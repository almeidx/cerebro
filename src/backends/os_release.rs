//! Parser for `/etc/os-release`.

use crate::model::{Distro, OsRelease};

fn unquote(value: &str) -> String {
    let trimmed = value.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| {
            trimmed
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
        })
        .unwrap_or(trimmed)
        .to_string()
}

/// Parse the contents of `/etc/os-release` into an [`OsRelease`].
pub fn parse(content: &str) -> OsRelease {
    let mut id = String::new();
    let mut version_id = None;
    let mut pretty_name = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = unquote(value);
        match key.trim() {
            "ID" => id = value,
            "VERSION_ID" => version_id = Some(value),
            "PRETTY_NAME" => pretty_name = Some(value),
            _ => {}
        }
    }

    let distro = Distro::from_id(&id);
    OsRelease {
        id,
        version_id,
        pretty_name,
        distro,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROCKY_10: &str = r#"NAME="Rocky Linux"
VERSION="10.0 (Red Quartz)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="10.0"
PLATFORM_ID="platform:el10"
PRETTY_NAME="Rocky Linux 10.0 (Red Quartz)"
"#;

    const CENTOS_STREAM_10: &str = r#"NAME="CentOS Stream"
VERSION="10"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="10"
PRETTY_NAME="CentOS Stream 10"
"#;

    #[test]
    fn parses_rocky() {
        let os = parse(ROCKY_10);
        assert_eq!(os.id, "rocky");
        assert_eq!(os.version_id.as_deref(), Some("10.0"));
        assert_eq!(
            os.pretty_name.as_deref(),
            Some("Rocky Linux 10.0 (Red Quartz)")
        );
        assert_eq!(os.distro, Distro::Rocky);
        assert!(os.distro.is_rpm());
    }

    #[test]
    fn parses_centos_stream() {
        let os = parse(CENTOS_STREAM_10);
        assert_eq!(os.distro, Distro::CentosStream);
        assert_eq!(os.version_id.as_deref(), Some("10"));
    }

    #[test]
    fn unknown_distro_is_preserved() {
        let os = parse("ID=arch\n");
        assert_eq!(os.distro, Distro::Other("arch".to_string()));
        assert!(!os.distro.is_rpm());
    }
}
