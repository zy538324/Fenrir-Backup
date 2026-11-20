//! Backup, restore and verify on top of `core-format`.
//!
//! Platform code (VSS, LVM, ...) lives in the snapshot crates and reaches
//! the engine only through the `DiskSource` trait.

#![forbid(unsafe_code)]

pub mod backup;
pub mod control;
pub mod layout;
pub mod restore;
pub mod source;
pub mod target;
pub mod verify;

pub use backup::{backup, BackupOptions, BackupReport, ImageMeta, Progress};
pub use control::JobControl;
pub use restore::{restore_disk, RestoreOptions, RestoreReport};
pub use source::{CapturePlan, DiskInfo, DiskSource, PartitionPlan, ReadAtSource};
pub use target::{DestructiveConfirmation, FileTarget, WriteTarget};
pub use verify::{verify, VerifyLevel, VerifyReport};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Format(#[from] core_format::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A safety rule refused the operation. Nothing was written.
    #[error("refused for safety: {0}")]
    Safety(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, EngineError>;
