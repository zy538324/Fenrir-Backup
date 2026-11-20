//! Wire protocol between `fenrir-server` and `fenrir-agent`, plus the
//! sealing scheme the browser uses to hand repository secrets to agents
//! without the server being able to read them.
//!
//! All messages are JSON over HTTPS. Agents always initiate.

#![forbid(unsafe_code)]

pub mod seal;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    /// Desktop or laptop.
    Workstation,
    /// Physical or virtual server backing itself up.
    Server,
    /// Hyper-V host backing up its VMs.
    Hyperv,
}

impl AgentRole {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "workstation" => Some(Self::Workstation),
            "server" => Some(Self::Server),
            "hyperv" => Some(Self::Hyperv),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Workstation => "workstation",
            Self::Server => "server",
            Self::Hyperv => "hyperv",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsSummary {
    /// "windows", "linux", "macos".
    pub family: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub protocol: u32,
    pub token: String,
    pub hostname: String,
    pub machine_id: String,
    pub os: OsSummary,
    pub role: AgentRole,
    pub agent_version: String,
    /// X25519 public key, base64. Repository secrets are sealed to it.
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub agent_id: Uuid,
    /// Bearer token for all later requests. Shown once; the server keeps
    /// only its hash.
    pub agent_token: String,
    pub poll_seconds: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DiskSummary {
    pub path: String,
    pub size: u64,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub system: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VmSummary {
    pub id: String,
    pub name: String,
    /// "running", "off", "saved", "paused", ...
    pub state: String,
    #[serde(default)]
    pub generation: u32,
    #[serde(default)]
    pub disk_bytes: u64,
    #[serde(default)]
    pub disks: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    pub hostname: String,
    pub os: OsSummary,
    pub agent_version: String,
    /// What this agent can do: "backup_system", "backup_disks",
    /// "backup_hyperv", "verify".
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub disks: Vec<DiskSummary>,
    #[serde(default)]
    pub vms: Vec<VmSummary>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub inventory: Inventory,
    /// Job the agent is executing now, if any.
    #[serde(default)]
    pub running_job: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub jobs: Vec<JobSpec>,
    pub poll_seconds: u32,
    /// Jobs the administrator cancelled while they were running.
    #[serde(default)]
    pub cancel: Vec<Uuid>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BackupSettings {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub rate_limit_mib: u64,
    /// Windows: VSS FULL instead of COPY.
    #[serde(default)]
    pub vss_full: bool,
    /// Verify a sample of the new image's chunks afterwards.
    #[serde(default)]
    pub verify_sample_percent: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JobKind {
    /// Create the repository at `repository.path`.
    InitRepository,
    /// Whole running system (Windows VSS).
    BackupSystem {
        #[serde(default)]
        settings: BackupSettings,
    },
    /// Listed devices or image files.
    BackupDisks {
        paths: Vec<String>,
        #[serde(default)]
        settings: BackupSettings,
    },
    /// Hyper-V VMs by ID; empty = every VM on the host.
    BackupHyperv {
        #[serde(default)]
        vm_ids: Vec<String>,
        #[serde(default)]
        settings: BackupSettings,
    },
    Verify {
        /// "quick", "sample", "full".
        level: String,
        #[serde(default)]
        sample_percent: Option<f64>,
    },
    /// Report the repository's images to the server.
    ListImages,
}

impl JobKind {
    pub fn label(&self) -> &'static str {
        match self {
            JobKind::InitRepository => "Create repository",
            JobKind::BackupSystem { .. } => "System backup",
            JobKind::BackupDisks { .. } => "Disk backup",
            JobKind::BackupHyperv { .. } => "Hyper-V backup",
            JobKind::Verify { .. } => "Verify",
            JobKind::ListImages => "Refresh images",
        }
    }
}

/// Where the repository is and the secret to open it, sealed to this agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoAccess {
    pub repository_id: Uuid,
    pub path: String,
    pub sealed_secret: seal::Sealed,
}

/// Plaintext inside `RepoAccess::sealed_secret`.
#[derive(Clone, Serialize, Deserialize)]
pub struct RepoSecret {
    pub passphrase: String,
    /// Recovery key file contents; only sent to the agent that creates
    /// the repository.
    #[serde(default)]
    pub recovery_key: Option<String>,
}

impl std::fmt::Debug for RepoSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RepoSecret(..)")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSpec {
    pub id: Uuid,
    pub kind: JobKind,
    #[serde(default)]
    pub repository: Option<RepoAccess>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Dispatched,
    Running,
    Succeeded,
    /// Completed, with warnings worth a look.
    Warning,
    Failed,
    Cancelled,
}

impl JobState {
    pub fn as_str(&self) -> &'static str {
        match self {
            JobState::Queued => "queued",
            JobState::Dispatched => "dispatched",
            JobState::Running => "running",
            JobState::Succeeded => "succeeded",
            JobState::Warning => "warning",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "queued" => JobState::Queued,
            "dispatched" => JobState::Dispatched,
            "running" => JobState::Running,
            "succeeded" => JobState::Succeeded,
            "warning" => JobState::Warning,
            "failed" => JobState::Failed,
            "cancelled" => JobState::Cancelled,
            _ => return None,
        })
    }
    pub fn is_final(&self) -> bool {
        matches!(
            self,
            JobState::Succeeded | JobState::Warning | JobState::Failed | JobState::Cancelled
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct JobProgress {
    /// Short phase name: "snapshot", "reading", "verifying", ...
    pub phase: String,
    pub done: u64,
    pub total: u64,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobUpdate {
    pub state: JobState,
    #[serde(default)]
    pub progress: Option<JobProgress>,
    /// Kind-specific result (e.g. backup report).
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Images now in the repository (after backup or ListImages).
    #[serde(default)]
    pub images: Option<Vec<ImageReport>>,
    /// Repository UUID (after InitRepository).
    #[serde(default)]
    pub repo_uuid: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageReport {
    pub image_id: Uuid,
    pub machine_id: String,
    pub hostname: String,
    pub created: String,
    pub created_unix: i64,
    pub kind: String,
    pub consistency: String,
    pub captured_bytes: u64,
    pub stored_new_bytes: u64,
    pub disks: Vec<u64>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub vm_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}
