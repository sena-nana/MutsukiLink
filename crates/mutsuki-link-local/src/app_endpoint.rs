//! Stable local App endpoint identity.
//!
//! Derives a deterministic namespaced local IPC address from `AppId` and the
//! current user/session identity so business code never concatenates pipe or
//! socket paths. Platform mapping (Named Pipe vs Unix Domain Socket) remains
//! inside `interprocess` / `LocalAddress`.

use mutsuki_link_core::EndpointId;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::LocalAddress;

/// Stable application identity shared by desktop hosts.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AppId(String);

impl AppId {
    pub fn new(value: impl Into<String>) -> Result<Self, AppEndpointError> {
        let value = value.into();
        if value.is_empty()
            || !value
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_')
        {
            return Err(AppEndpointError::InvalidAppId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AppId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// User/session identity used to isolate local endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIdentity {
    pub user_key: String,
    pub session_key: String,
}

impl SessionIdentity {
    pub fn current() -> Self {
        let user_key = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "local-user".into());
        let session_key = std::env::var("XDG_SESSION_ID")
            .or_else(|_| std::env::var("SESSIONNAME"))
            .unwrap_or_else(|_| format!("pid-{}", std::process::id()));
        Self {
            user_key,
            session_key,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppEndpointError {
    InvalidAppId,
    InvalidCapability,
    LeaseIo,
}

impl fmt::Display for AppEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAppId => formatter.write_str("app id is invalid"),
            Self::InvalidCapability => formatter.write_str("capability descriptor is invalid"),
            Self::LeaseIo => formatter.write_str("endpoint lease io failed"),
        }
    }
}

impl std::error::Error for AppEndpointError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityOffer {
    pub name: String,
    pub protocol_version: u32,
    pub schema_version: u32,
    pub ready: bool,
}

impl CapabilityOffer {
    pub fn new(
        name: impl Into<String>,
        protocol_version: u32,
        schema_version: u32,
        ready: bool,
    ) -> Result<Self, AppEndpointError> {
        let name = name.into();
        if name.is_empty() {
            return Err(AppEndpointError::InvalidCapability);
        }
        Ok(Self {
            name,
            protocol_version,
            schema_version,
            ready,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppEndpointDescriptor {
    pub app_id: AppId,
    pub instance_id: String,
    pub host_protocol_version: u32,
    pub endpoint_id: EndpointId,
    pub address: LocalAddress,
    pub capabilities: Vec<CapabilityOffer>,
}

impl AppEndpointDescriptor {
    pub fn capability_ready(&self, name: &str, protocol_version: u32, schema_version: u32) -> bool {
        self.capabilities.iter().any(|capability| {
            capability.name == name
                && capability.protocol_version == protocol_version
                && capability.schema_version == schema_version
                && capability.ready
        })
    }
}

/// Derive the stable local IPC address for an app in the current user session.
pub fn local_address_for_app(app_id: &AppId, session: &SessionIdentity) -> LocalAddress {
    let digest = Sha256::digest(format!(
        "mutsuki.link.app.v1\0{}\0{}\0{}",
        app_id.as_str(),
        session.user_key,
        session.session_key
    ));
    let short = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let sanitized = app_id
        .as_str()
        .chars()
        .map(|ch| if ch == '.' { '-' } else { ch })
        .collect::<String>();
    LocalAddress(format!("mutsuki.app.{sanitized}.{short}"))
}

/// Derive a stable EndpointId from AppId + session so owners do not invent paths.
pub fn endpoint_id_for_app(app_id: &AppId, session: &SessionIdentity) -> EndpointId {
    let digest = Sha256::digest(format!(
        "mutsuki.link.endpoint.v1\0{}\0{}\0{}",
        app_id.as_str(),
        session.user_key,
        session.session_key
    ));
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    EndpointId::from_bytes(bytes)
}

#[derive(Clone, Debug)]
pub struct EndpointLease {
    path: PathBuf,
    pub app_id: AppId,
    pub instance_id: String,
    pub pid: u32,
    pub created_unix_ms: u64,
}

impl EndpointLease {
    pub fn create(
        directory: impl AsRef<Path>,
        app_id: &AppId,
        instance_id: impl Into<String>,
    ) -> Result<Self, AppEndpointError> {
        let directory = directory.as_ref();
        fs::create_dir_all(directory).map_err(|_| AppEndpointError::LeaseIo)?;
        let path = lease_path(directory, app_id);
        let created_unix_ms = now_unix_ms();
        let lease = Self {
            path: path.clone(),
            app_id: app_id.clone(),
            instance_id: instance_id.into(),
            pid: std::process::id(),
            created_unix_ms,
        };
        let payload = format!(
            "{}\n{}\n{}\n{}\n",
            lease.app_id.as_str(),
            lease.instance_id,
            lease.pid,
            lease.created_unix_ms
        );
        let pending = path.with_extension("lease.pending");
        fs::write(&pending, payload).map_err(|_| AppEndpointError::LeaseIo)?;
        fs::rename(pending, path).map_err(|_| AppEndpointError::LeaseIo)?;
        Ok(lease)
    }

    pub fn read(
        directory: impl AsRef<Path>,
        app_id: &AppId,
    ) -> Result<Option<Self>, AppEndpointError> {
        let path = lease_path(directory.as_ref(), app_id);
        if !path.is_file() {
            return Ok(None);
        }
        let payload = fs::read_to_string(&path).map_err(|_| AppEndpointError::LeaseIo)?;
        let mut lines = payload.lines();
        let Some(app) = lines.next() else {
            return Ok(None);
        };
        let Some(instance_id) = lines.next() else {
            return Ok(None);
        };
        let Some(pid) = lines.next().and_then(|value| value.parse().ok()) else {
            return Ok(None);
        };
        let Some(created_unix_ms) = lines.next().and_then(|value| value.parse().ok()) else {
            return Ok(None);
        };
        if app != app_id.as_str() {
            return Ok(None);
        }
        Ok(Some(Self {
            path,
            app_id: app_id.clone(),
            instance_id: instance_id.into(),
            pid,
            created_unix_ms,
        }))
    }

    pub fn is_stale(&self, _max_age: Duration) -> bool {
        !process_exists(self.pid)
    }

    pub fn clear(self) -> Result<(), AppEndpointError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(AppEndpointError::LeaseIo),
        }
    }
}

/// Clear a stale lease so a new endpoint owner can take over.
pub fn reclaim_stale_lease(
    directory: impl AsRef<Path>,
    app_id: &AppId,
    max_age: Duration,
) -> Result<bool, AppEndpointError> {
    let Some(lease) = EndpointLease::read(directory.as_ref(), app_id)? else {
        return Ok(false);
    };
    if lease.is_stale(max_age) {
        lease.clear()?;
        return Ok(true);
    }
    Ok(false)
}

fn lease_path(directory: &Path, app_id: &AppId) -> PathBuf {
    let sanitized = app_id
        .as_str()
        .chars()
        .map(|ch| if ch == '.' { '-' } else { ch })
        .collect::<String>();
    directory.join(format!("{sanitized}.lease"))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn process_exists(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("ps")
            .args(["-p", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(windows)]
    {
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .map(|output| {
                let text = String::from_utf8_lossy(&output.stdout);
                text.contains(&pid.to_string())
            })
            .unwrap_or(false)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = pid;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn app_address_is_stable_for_same_session() {
        let app = AppId::new("lilia.code").unwrap();
        let session = SessionIdentity {
            user_key: "alice".into(),
            session_key: "desktop-1".into(),
        };
        let first = local_address_for_app(&app, &session);
        let second = local_address_for_app(&app, &session);
        assert_eq!(first, second);
        assert!(first.0.starts_with("mutsuki.app.lilia-code."));
        assert_ne!(
            local_address_for_app(
                &app,
                &SessionIdentity {
                    user_key: "bob".into(),
                    session_key: "desktop-1".into(),
                }
            ),
            first
        );
    }

    #[test]
    fn endpoint_id_differs_from_address_digest_domain() {
        let app = AppId::new("lilia.github").unwrap();
        let session = SessionIdentity {
            user_key: "alice".into(),
            session_key: "s1".into(),
        };
        let endpoint = endpoint_id_for_app(&app, &session);
        let other = endpoint_id_for_app(&AppId::new("lilia.code").unwrap(), &session);
        assert_ne!(endpoint.as_bytes(), other.as_bytes());
    }

    #[test]
    fn lease_round_trip_and_reclaim() {
        let dir = std::env::temp_dir().join(format!(
            "mutsuki-link-lease-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let app = AppId::new("demo.app").unwrap();
        let lease = EndpointLease::create(&dir, &app, "instance-1").unwrap();
        let loaded = EndpointLease::read(&dir, &app).unwrap().unwrap();
        assert_eq!(loaded.instance_id, "instance-1");
        assert_eq!(loaded.pid, lease.pid);
        assert!(!reclaim_stale_lease(&dir, &app, Duration::from_secs(3600)).unwrap());
        // Force stale by writing a dead pid.
        let path = lease_path(&dir, &app);
        fs::write(&path, format!("{}\ndead\n4294967294\n0\n", app.as_str())).unwrap();
        assert!(reclaim_stale_lease(&dir, &app, Duration::from_secs(0)).unwrap());
        assert!(EndpointLease::read(&dir, &app).unwrap().is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn capability_ready_requires_exact_match() {
        let descriptor = AppEndpointDescriptor {
            app_id: AppId::new("demo.app").unwrap(),
            instance_id: "i1".into(),
            host_protocol_version: 1,
            endpoint_id: EndpointId::from_bytes([1; 16]),
            address: LocalAddress("x".into()),
            capabilities: vec![CapabilityOffer::new("cap.a", 1, 2, true).unwrap()],
        };
        assert!(descriptor.capability_ready("cap.a", 1, 2));
        assert!(!descriptor.capability_ready("cap.a", 1, 1));
        assert!(!descriptor.capability_ready("cap.b", 1, 2));
    }
}
