//! Manifest storage implementation.
//!
//! Stores object manifests keyed by ObjectId.

use std::path::Path;
use std::sync::Arc;

use lux_core::encoding::{CanonicalDecode, CanonicalEncode};
use lux_core::{ObjectId, RevisionId};
use lux_proto::Manifest;
use rocksdb::{Options, DB};
use tracing::debug;

use crate::StoreError;

/// Column family for manifests.
const MANIFESTS_CF: &str = "manifests";
/// Column family for manifest history.
const MANIFEST_HISTORY_CF: &str = "manifest_history";

/// Manifest store for managing object manifests.
pub struct ManifestStore {
    db: Arc<DB>,
}

impl ManifestStore {
    /// Opens a manifest store at the given path.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let db = DB::open_cf(&opts, path, [MANIFESTS_CF, MANIFEST_HISTORY_CF])
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Opens with an existing DB instance.
    pub fn with_db(db: Arc<DB>) -> Self {
        Self { db }
    }

    /// Stores a manifest (latest version).
    ///
    /// Also stores in history keyed by (ObjectId, RevisionId).
    pub fn put(&self, manifest: &Manifest) -> Result<(), StoreError> {
        let object_id = &manifest.body.object_id;
        let revision = manifest.body.revision;
        let encoded = manifest.to_vec();

        // Store as latest
        let cf = self
            .db
            .cf_handle(MANIFESTS_CF)
            .ok_or_else(|| StoreError::Database("Missing manifests column family".to_string()))?;

        self.db
            .put_cf(&cf, object_id.as_bytes(), &encoded)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Store in history
        let history_cf = self
            .db
            .cf_handle(MANIFEST_HISTORY_CF)
            .ok_or_else(|| StoreError::Database("Missing manifest_history column family".to_string()))?;

        let history_key = Self::history_key(object_id, revision);
        self.db
            .put_cf(&history_cf, &history_key, &encoded)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        debug!(
            object_id = %object_id,
            revision = revision.value(),
            "Stored manifest"
        );

        Ok(())
    }

    /// Retrieves the latest manifest for an object.
    pub fn get(&self, object_id: &ObjectId) -> Result<Option<Manifest>, StoreError> {
        let cf = self
            .db
            .cf_handle(MANIFESTS_CF)
            .ok_or_else(|| StoreError::Database("Missing manifests column family".to_string()))?;

        match self
            .db
            .get_cf(&cf, object_id.as_bytes())
            .map_err(|e| StoreError::Database(e.to_string()))?
        {
            Some(bytes) => {
                let manifest = Manifest::from_bytes(&bytes)?;
                Ok(Some(manifest))
            }
            None => Ok(None),
        }
    }

    /// Retrieves a specific revision of a manifest.
    pub fn get_revision(
        &self,
        object_id: &ObjectId,
        revision: RevisionId,
    ) -> Result<Option<Manifest>, StoreError> {
        let history_cf = self
            .db
            .cf_handle(MANIFEST_HISTORY_CF)
            .ok_or_else(|| StoreError::Database("Missing manifest_history column family".to_string()))?;

        let history_key = Self::history_key(object_id, revision);

        match self
            .db
            .get_cf(&history_cf, &history_key)
            .map_err(|e| StoreError::Database(e.to_string()))?
        {
            Some(bytes) => {
                let manifest = Manifest::from_bytes(&bytes)?;
                Ok(Some(manifest))
            }
            None => Ok(None),
        }
    }

    /// Lists all revisions for an object.
    pub fn list_revisions(&self, object_id: &ObjectId) -> Result<Vec<RevisionId>, StoreError> {
        let history_cf = self
            .db
            .cf_handle(MANIFEST_HISTORY_CF)
            .ok_or_else(|| StoreError::Database("Missing manifest_history column family".to_string()))?;

        let prefix = object_id.as_bytes();
        let mut revisions = Vec::new();

        let iter = self.db.prefix_iterator_cf(&history_cf, prefix);
        for item in iter {
            let (key, _) = item.map_err(|e| StoreError::Database(e.to_string()))?;
            if key.len() == 40 && key.starts_with(prefix) {
                let rev_bytes: [u8; 8] = key[32..40].try_into().unwrap();
                let rev = RevisionId::new(u64::from_le_bytes(rev_bytes));
                revisions.push(rev);
            } else {
                break;
            }
        }

        revisions.sort();
        Ok(revisions)
    }

    /// Deletes a manifest (all revisions).
    pub fn delete(&self, object_id: &ObjectId) -> Result<(), StoreError> {
        // Delete latest
        let cf = self
            .db
            .cf_handle(MANIFESTS_CF)
            .ok_or_else(|| StoreError::Database("Missing manifests column family".to_string()))?;

        self.db
            .delete_cf(&cf, object_id.as_bytes())
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Delete history
        let revisions = self.list_revisions(object_id)?;
        let history_cf = self
            .db
            .cf_handle(MANIFEST_HISTORY_CF)
            .ok_or_else(|| StoreError::Database("Missing manifest_history column family".to_string()))?;

        for rev in revisions {
            let key = Self::history_key(object_id, rev);
            self.db
                .delete_cf(&history_cf, &key)
                .map_err(|e| StoreError::Database(e.to_string()))?;
        }

        debug!(object_id = %object_id, "Deleted manifest");
        Ok(())
    }

    /// Lists all object IDs in the store.
    pub fn list_objects(&self) -> Result<Vec<ObjectId>, StoreError> {
        let cf = self
            .db
            .cf_handle(MANIFESTS_CF)
            .ok_or_else(|| StoreError::Database("Missing manifests column family".to_string()))?;

        let mut objects = Vec::new();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (key, _) = item.map_err(|e| StoreError::Database(e.to_string()))?;
            if key.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key);
                objects.push(ObjectId::new(arr));
            }
        }

        Ok(objects)
    }

    fn history_key(object_id: &ObjectId, revision: RevisionId) -> [u8; 40] {
        let mut key = [0u8; 40];
        key[..32].copy_from_slice(object_id.as_bytes());
        key[32..].copy_from_slice(&revision.value().to_le_bytes());
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lux_core::{DagRef, SigningKey};
    use lux_proto::manifest::{IdentityBinding, ManifestBody};
    use tempfile::TempDir;

    fn create_test_manifest(object_id: ObjectId, revision: u64) -> Manifest {
        let signing_key = SigningKey::random();
        let public_key = signing_key.public_key();
        let origin = IdentityBinding::from_public_key(public_key);

        let body = ManifestBody::new(object_id, RevisionId::new(revision), DagRef::empty(), origin);

        Manifest::new(body, &signing_key).unwrap()
    }

    #[test]
    fn test_manifest_store_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = ManifestStore::open(dir.path()).unwrap();

        let object_id = ObjectId::random();
        let manifest = create_test_manifest(object_id, 0);

        store.put(&manifest).unwrap();

        let retrieved = store.get(&object_id).unwrap().unwrap();
        assert_eq!(manifest.body.object_id, retrieved.body.object_id);
        assert_eq!(manifest.body.revision, retrieved.body.revision);
    }

    #[test]
    fn test_manifest_store_revisions() {
        let dir = TempDir::new().unwrap();
        let store = ManifestStore::open(dir.path()).unwrap();

        let object_id = ObjectId::random();

        // Store multiple revisions
        for rev in 0..5 {
            let manifest = create_test_manifest(object_id, rev);
            store.put(&manifest).unwrap();
        }

        // List revisions
        let revisions = store.list_revisions(&object_id).unwrap();
        assert_eq!(revisions.len(), 5);
        assert_eq!(revisions[0].value(), 0);
        assert_eq!(revisions[4].value(), 4);

        // Get specific revision
        let manifest = store
            .get_revision(&object_id, RevisionId::new(2))
            .unwrap()
            .unwrap();
        assert_eq!(manifest.body.revision.value(), 2);
    }

    #[test]
    fn test_manifest_store_delete() {
        let dir = TempDir::new().unwrap();
        let store = ManifestStore::open(dir.path()).unwrap();

        let object_id = ObjectId::random();
        let manifest = create_test_manifest(object_id, 0);

        store.put(&manifest).unwrap();
        assert!(store.get(&object_id).unwrap().is_some());

        store.delete(&object_id).unwrap();
        assert!(store.get(&object_id).unwrap().is_none());
    }
}
