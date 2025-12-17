//! Virtual filesystem implementation with FUSE bindings.

use std::ffi::OsStr;
use std::sync::Arc;
use std::time::Duration;

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen,
    ReplyWrite, Request,
};
use libc;
use lux_core::{DagRef, ObjectId};
use lux_store::BlobStore;
use parking_lot::RwLock;
use thiserror::Error;
use tracing::{debug, error, warn};

use crate::inode::{Inode, InodeId, InodeTable, InodeType};
use crate::mount::MountConfig;

/// VFS errors.
#[derive(Debug, Error)]
pub enum VfsError {
    /// Inode not found
    #[error("Inode not found: {0}")]
    InodeNotFound(u64),

    /// Not a directory
    #[error("Not a directory")]
    NotDirectory,

    /// Not a file
    #[error("Not a file")]
    NotFile,

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),
}

/// TTL for cached attributes.
const TTL: Duration = Duration::from_secs(1);

/// Lux FUSE filesystem implementation.
pub struct LuxFilesystem {
    /// Inode table
    inodes: InodeTable,
    /// Blob store for content
    store: Option<Arc<BlobStore>>,
    /// Mount configuration
    config: MountConfig,
    /// Open file handles
    handles: RwLock<std::collections::HashMap<u64, OpenHandle>>,
    /// Next file handle
    next_handle: std::sync::atomic::AtomicU64,
}

/// An open file handle.
struct OpenHandle {
    inode: InodeId,
    read: bool,
    write: bool,
    buffer: Vec<u8>,
}

impl LuxFilesystem {
    /// Creates a new filesystem.
    pub fn new(config: MountConfig) -> Self {
        Self {
            inodes: InodeTable::new(),
            store: None,
            config,
            handles: RwLock::new(std::collections::HashMap::new()),
            next_handle: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Sets the blob store.
    pub fn with_store(mut self, store: Arc<BlobStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Returns the inode table.
    pub fn inodes(&self) -> &InodeTable {
        &self.inodes
    }

    /// Creates a file in a directory.
    pub fn create_file(&self, parent: InodeId, name: &str) -> Result<InodeId, VfsError> {
        let parent_inode = self
            .inodes
            .get(parent)
            .ok_or(VfsError::InodeNotFound(parent.0))?;

        if !parent_inode.is_dir() {
            return Err(VfsError::NotDirectory);
        }

        let file = Inode::file(InodeId::new(), parent, name.to_string());
        let id = file.id;
        self.inodes.insert(file);

        debug!(parent = parent.0, name = name, id = id.0, "Created file");
        Ok(id)
    }

    /// Creates a directory.
    pub fn create_directory(&self, parent: InodeId, name: &str) -> Result<InodeId, VfsError> {
        let parent_inode = self
            .inodes
            .get(parent)
            .ok_or(VfsError::InodeNotFound(parent.0))?;

        if !parent_inode.is_dir() {
            return Err(VfsError::NotDirectory);
        }

        let dir = Inode::directory(InodeId::new(), parent, name.to_string());
        let id = dir.id;
        self.inodes.insert(dir);

        debug!(parent = parent.0, name = name, id = id.0, "Created directory");
        Ok(id)
    }

    fn allocate_handle(&self, inode: InodeId, read: bool, write: bool) -> u64 {
        let fh = self
            .next_handle
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.handles.write().insert(
            fh,
            OpenHandle {
                inode,
                read,
                write,
                buffer: Vec::new(),
            },
        );
        fh
    }

    fn release_handle(&self, fh: u64) {
        self.handles.write().remove(&fh);
    }
}

impl Filesystem for LuxFilesystem {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name = name.to_string_lossy();
        debug!(parent = parent, name = %name, "lookup");

        if let Some(inode_id) = self.inodes.lookup(InodeId(parent), &name) {
            if let Some(inode) = self.inodes.get(inode_id) {
                reply.entry(&TTL, &inode.to_file_attr(), 0);
                return;
            }
        }

        reply.error(libc::ENOENT);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        debug!(ino = ino, "getattr");

        if let Some(inode) = self.inodes.get(InodeId(ino)) {
            reply.attr(&TTL, &inode.to_file_attr());
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        debug!(ino = ino, offset = offset, "readdir");

        let inode = match self.inodes.get(InodeId(ino)) {
            Some(i) if i.is_dir() => i,
            Some(_) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let parent_ino = inode.parent.0;
        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ino, FileType::Directory, ".".to_string()),
            (parent_ino, FileType::Directory, "..".to_string()),
        ];

        for child in self.inodes.list_children(InodeId(ino)) {
            let kind = match child.inode_type {
                InodeType::File => FileType::RegularFile,
                InodeType::Directory => FileType::Directory,
                InodeType::Symlink => FileType::Symlink,
            };
            entries.push((child.id.0, kind, child.name.clone()));
        }

        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(ino, (i + 1) as i64, kind, &name) {
                break;
            }
        }

        reply.ok();
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        debug!(ino = ino, flags = flags, "open");

        let inode = match self.inodes.get(InodeId(ino)) {
            Some(i) if i.is_file() => i,
            Some(_) => {
                reply.error(libc::EISDIR);
                return;
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let read = (flags & libc::O_ACCMODE) != libc::O_WRONLY;
        let write = (flags & libc::O_ACCMODE) != libc::O_RDONLY;

        let fh = self.allocate_handle(InodeId(ino), read, write);
        reply.opened(fh, 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        debug!(ino = ino, fh = fh, offset = offset, size = size, "read");

        let handles = self.handles.read();
        if let Some(handle) = handles.get(&fh) {
            let offset = offset as usize;
            let size = size as usize;

            if offset >= handle.buffer.len() {
                reply.data(&[]);
            } else {
                let end = std::cmp::min(offset + size, handle.buffer.len());
                reply.data(&handle.buffer[offset..end]);
            }
        } else {
            reply.error(libc::EBADF);
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        debug!(
            ino = ino,
            fh = fh,
            offset = offset,
            size = data.len(),
            "write"
        );

        // Buffer the write
        if let Some(handle) = self.handles.write().get_mut(&fh) {
            let new_len = (offset as usize) + data.len();
            if handle.buffer.len() < new_len {
                handle.buffer.resize(new_len, 0);
            }
            handle.buffer[offset as usize..new_len].copy_from_slice(data);

            // Update inode size
            self.inodes.get_mut(handle.inode, |inode| {
                inode.size = handle.buffer.len() as u64;
                inode.touch();
            });

            reply.written(data.len() as u32);
        } else {
            reply.error(libc::EBADF);
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(ino = ino, fh = fh, "release");
        self.release_handle(fh);
        reply.ok();
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        let name = name.to_string_lossy();
        debug!(parent = parent, name = %name, mode = mode, "create");

        match self.create_file(InodeId(parent), &name) {
            Ok(id) => {
                if let Some(inode) = self.inodes.get(id) {
                    let fh = self.allocate_handle(id, true, true);
                    reply.created(&TTL, &inode.to_file_attr(), 0, fh, 0);
                } else {
                    reply.error(libc::EIO);
                }
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let name = name.to_string_lossy();
        debug!(parent = parent, name = %name, mode = mode, "mkdir");

        match self.create_directory(InodeId(parent), &name) {
            Ok(id) => {
                if let Some(inode) = self.inodes.get(id) {
                    reply.entry(&TTL, &inode.to_file_attr(), 0);
                } else {
                    reply.error(libc::EIO);
                }
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        let name = name.to_string_lossy();
        debug!(parent = parent, name = %name, "unlink");

        if let Some(inode_id) = self.inodes.lookup(InodeId(parent), &name) {
            self.inodes.remove(inode_id);
            reply.ok();
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        let name = name.to_string_lossy();
        debug!(parent = parent, name = %name, "rmdir");

        if let Some(inode_id) = self.inodes.lookup(InodeId(parent), &name) {
            if let Some(inode) = self.inodes.get(inode_id) {
                if !inode.children.is_empty() {
                    reply.error(libc::ENOTEMPTY);
                    return;
                }
            }
            self.inodes.remove(inode_id);
            reply.ok();
        } else {
            reply.error(libc::ENOENT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_file() {
        let fs = LuxFilesystem::new(MountConfig::default());

        let id = fs.create_file(InodeId::ROOT, "test.txt").unwrap();
        let inode = fs.inodes.get(id).unwrap();

        assert_eq!(inode.name, "test.txt");
        assert!(inode.is_file());
    }

    #[test]
    fn test_create_directory() {
        let fs = LuxFilesystem::new(MountConfig::default());

        let id = fs.create_directory(InodeId::ROOT, "subdir").unwrap();
        let inode = fs.inodes.get(id).unwrap();

        assert_eq!(inode.name, "subdir");
        assert!(inode.is_dir());
    }
}
