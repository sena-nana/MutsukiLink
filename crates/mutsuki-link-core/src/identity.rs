use core::fmt;

macro_rules! opaque_id {
    ($name:ident, $size:expr) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $size]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in &self.0[..4] {
                    write!(formatter, "{byte:02x}")?;
                }
                formatter.write_str("…")
            }
        }
    };
}

// A peer is a long-lived cryptographic/device identity. Endpoint and connection
// identifiers deliberately have different types so callers cannot conflate them.
opaque_id!(PeerId, 32);
opaque_id!(EndpointId, 16);
opaque_id!(ConnectionId, 16);
opaque_id!(SessionId, 16);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionRange {
    pub minimum: ProtocolVersion,
    pub maximum: ProtocolVersion,
}

impl VersionRange {
    pub const fn new(minimum: ProtocolVersion, maximum: ProtocolVersion) -> Self {
        Self { minimum, maximum }
    }

    pub const fn is_valid(self) -> bool {
        self.minimum.major == self.maximum.major && self.minimum.minor <= self.maximum.minor
    }

    pub fn negotiate(self, other: Self) -> Option<ProtocolVersion> {
        if !self.is_valid() || !other.is_valid() || self.minimum.major != other.minimum.major {
            return None;
        }
        let minimum = self.minimum.minor.max(other.minimum.minor);
        let maximum = self.maximum.minor.min(other.maximum.minor);
        (minimum <= maximum).then(|| ProtocolVersion::new(self.minimum.major, maximum))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub peer_id: PeerId,
    pub endpoint_id: EndpointId,
    pub connection_id: ConnectionId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_negotiation_selects_highest_shared_minor() {
        let local = VersionRange::new(ProtocolVersion::new(1, 1), ProtocolVersion::new(1, 4));
        let remote = VersionRange::new(ProtocolVersion::new(1, 2), ProtocolVersion::new(1, 3));
        assert_eq!(local.negotiate(remote), Some(ProtocolVersion::new(1, 3)));
    }

    #[test]
    fn different_major_versions_are_incompatible() {
        let one = VersionRange::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 4));
        let two = VersionRange::new(ProtocolVersion::new(2, 0), ProtocolVersion::new(2, 4));
        assert_eq!(one.negotiate(two), None);
    }
}
