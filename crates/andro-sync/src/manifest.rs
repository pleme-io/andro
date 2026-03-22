//! Re-export fudajiku as the sync manifest implementation.
//!
//! This module existed before fudajiku was extracted. Now it just
//! re-exports the library for backward compatibility.

pub use fudajiku::{Manifest as SyncManifest, ManifestEntry, hash_bytes, hash_file};
