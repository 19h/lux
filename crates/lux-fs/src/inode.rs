//! Inode management for the virtual filesystem.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use lux_core::{DagRef, ObjectId, Timestamp};
use lux_proto::dag::EntryMetadata;
use parking_lot::RwLock;

/// Inode identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InodeId(pub u64);

impl InodeId {
    /// Root inode ID (FUSE convention).
    pub const ROOT: InodeId = InodeId(1);

    /// Generates a new unique inode ID.
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(2); // Start after root
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for InodeId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<u64> for InodeId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl From<InodeId> for u64 {
    fn from(id: InodeId) -> u64 {
        id.0
    }
}

/// Inode types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeType {
    /// Regular file
    File,
    /// Directory
    Directory,
    /// Symbolic link
    Symlink,
}

/// Inode representing a filesystem entry.
#[derive(Debug, Clone)]
pub struct Inode {
    /// Inode ID
    pub id: InodeId,
    /// Parent inode ID
    pub parent: InodeId,
    /// Entry name
    pub name: String,
    /// Inode type
    pub inode_type: InodeType,
    /// File mode (permissions)
    pub mode: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// File size
    pub size: u64,
    /// Access time
    pub atime: SystemTime,
    /// Modification time
    pub mtime: SystemTime,
    /// Change time
    pub ctime: SystemTime,
    /// Number of hard links
    pub nlink: u32,
    /// Reference to DAG content
    pub dag_ref: DagRef,
    /// Associated object ID (for mutable objects)
    pub object_id: Option<ObjectId>,
    /// Children (for directories)
    pub children: Vec<InodeId>,
}

impl Inode {
    /// Creates a new file inode.
    pub fn file(id: InodeId, parent: InodeId, name: String) -> Self {
        let now = SystemTime::now();
        Self {
            id,
            parent,
            name,
            inode_type: InodeType::File,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: 0,
            atime: now,
            mtime: now,
            ctime: now,
            nlink: 1,
            dag_ref: DagRef::empty(),
            object_id: None,
            children: Vec::new(),
        }
    }

    /// Creates a new directory inode.
    pub fn directory(id: InodeId, parent: InodeId, name: String) -> Self {
        let now = SystemTime::now();
        Self {
            id,
            parent,
            name,
            inode_type: InodeType::Directory,
            mode: 0o755,
            uid: 0,
            gid: 0,
            size: 0,
            atime: now,
            mtime: now,
            ctime: now,
            nlink: 2, // . and ..
            dag_ref: DagRef::empty(),
            object_id: None,
            children: Vec::new(),
        }
    }

    /// Creates the root inode.
    pub fn root() -> Self {
        Self::directory(InodeId::ROOT, InodeId::ROOT, String::new())
    }

    /// Returns true if this is a directory.
    pub fn is_dir(&self) -> bool {
        self.inode_type == InodeType::Directory
    }

    /// Returns true if this is a file.
    pub fn is_file(&self) -> bool {
        self.inode_type == InodeType::File
    }

    /// Updates modification time.
    pub fn touch(&mut self) {
        let now = SystemTime::now();
        self.mtime = now;
        self.ctime = now;
    }

    /// Adds a child inode.
    pub fn add_child(&mut self, child: InodeId) {
        if !self.children.contains(&child) {
            self.children.push(child);
            if self.is_dir() {
                self.nlink += 1;
            }
        }
    }

    /// Removes a child inode.
    pub fn remove_child(&mut self, child: InodeId) {
        if let Some(pos) = self.children.iter().position(|&c| c == child) {
            self.children.remove(pos);
            if self.is_dir() && self.nlink > 2 {
                self.nlink -= 1;
            }
        }
    }

    /// Converts to FUSE file attributes.
    pub fn to_file_attr(&self) -> fuser::FileAttr {
        use fuser::FileType;
        use std::time::UNIX_EPOCH;

        let kind = match self.inode_type {
            InodeType::File => FileType::RegularFile,
            InodeType::Directory => FileType::Directory,
            InodeType::Symlink => FileType::Symlink,
        };

        fuser::FileAttr {
            ino: self.id.0,
            size: self.size,
            blocks: (self.size + 511) / 512,
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
            crtime: self.ctime,
            kind,
            perm: self.mode as u16,
            nlink: self.nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }
}

/// Inode table managing all inodes.
pub struct InodeTable {
    /// All inodes by ID
    inodes: RwLock<HashMap<InodeId, Inode>>,
    /// Name to inode mapping per parent
    names: RwLock<HashMap<(InodeId, String), InodeId>>,
}

impl InodeTable {
    /// Creates a new inode table with a root directory.
    pub fn new() -> Self {
        let mut inodes = HashMap::new();
        let root = Inode::root();
        inodes.insert(InodeId::ROOT, root);

        Self {
            inodes: RwLock::new(inodes),
            names: RwLock::new(HashMap::new()),
        }
    }

    /// Gets an inode by ID.
    pub fn get(&self, id: InodeId) -> Option<Inode> {
        self.inodes.read().get(&id).cloned()
    }

    /// Gets a mutable reference to an inode.
    pub fn get_mut<F, R>(&self, id: InodeId, f: F) -> Option<R>
    where
        F: FnOnce(&mut Inode) -> R,
    {
        self.inodes.write().get_mut(&id).map(f)
    }

    /// Inserts an inode.
    pub fn insert(&self, inode: Inode) {
        let id = inode.id;
        let parent = inode.parent;
        let name = inode.name.clone();

        self.inodes.write().insert(id, inode);

        if !name.is_empty() {
            self.names.write().insert((parent, name), id);
        }

        // Update parent's children
        if parent != id {
            if let Some(parent_inode) = self.inodes.write().get_mut(&parent) {
                parent_inode.add_child(id);
            }
        }
    }

    /// Removes an inode.
    pub fn remove(&self, id: InodeId) -> Option<Inode> {
        let inode = self.inodes.write().remove(&id)?;

        // Remove from names
        self.names.write().remove(&(inode.parent, inode.name.clone()));

        // Remove from parent's children
        if let Some(parent) = self.inodes.write().get_mut(&inode.parent) {
            parent.remove_child(id);
        }

        Some(inode)
    }

    /// Looks up an inode by name in a parent directory.
    pub fn lookup(&self, parent: InodeId, name: &str) -> Option<InodeId> {
        self.names.read().get(&(parent, name.to_string())).copied()
    }

    /// Lists children of a directory.
    pub fn list_children(&self, parent: InodeId) -> Vec<Inode> {
        let inodes = self.inodes.read();
        if let Some(parent_inode) = inodes.get(&parent) {
            parent_inode
                .children
                .iter()
                .filter_map(|&id| inodes.get(&id).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }
}

impl Default for InodeTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inode_table() {
        let table = InodeTable::new();

        // Root should exist
        assert!(table.get(InodeId::ROOT).is_some());

        // Create a file
        let file = Inode::file(InodeId::new(), InodeId::ROOT, "test.txt".to_string());
        let file_id = file.id;
        table.insert(file);

        // Should be findable by lookup
        assert_eq!(table.lookup(InodeId::ROOT, "test.txt"), Some(file_id));

        // Should be in parent's children
        let root = table.get(InodeId::ROOT).unwrap();
        assert!(root.children.contains(&file_id));
    }

    #[test]
    fn test_inode_types() {
        let file = Inode::file(InodeId::new(), InodeId::ROOT, "file".to_string());
        assert!(file.is_file());
        assert!(!file.is_dir());

        let dir = Inode::directory(InodeId::new(), InodeId::ROOT, "dir".to_string());
        assert!(dir.is_dir());
        assert!(!dir.is_file());
    }
}
