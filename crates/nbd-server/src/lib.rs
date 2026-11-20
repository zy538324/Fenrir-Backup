//! NBD export of images straight from the chunk store (Phase 3).
//!
//! Not implemented yet. Phase 3 serves any image as a read-only NBD block
//! device, fetching and caching chunks on demand; see the spec section
//! "Boot from backup as a VM". The fixed 4 MiB chunk alignment chosen in
//! Phase 1 makes each NBD read a single manifest lookup per chunk.
