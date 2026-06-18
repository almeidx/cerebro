//! Parsers for `dnf` update output on RHEL-family systems.
//!
//! Two independent text sources are folded into the shared [`OsUpdate`] model:
//! `dnf --quiet check-update` for the pending package list and
//! `dnf updateinfo list --available` for the matching security advisories.

use std::collections::HashMap;

use crate::model::{Errata, ErrataKind, OsUpdate, Severity};

/// Parse `dnf --quiet check-update` output into a list of [`OsUpdate`].
///
/// A leading `Last metadata expiration check` line, blank lines, and a trailing
/// `Obsoleting Packages` section are all ignored. The remaining rows are
/// `NAME.ARCH  EVR  REPO`. When a package's `NAME.ARCH` is wide, dnf wraps the
/// row across two physical lines (the bare `NAME.ARCH`, then an indented
/// `EVR  REPO`) — which it does whenever stdout is a pipe, as it is over SSH. To
/// stay correct under wrapping we flatten every data line into a single token
/// stream and group it into `(NAME.ARCH, EVR, REPO)` triples; wrapping changes
/// line boundaries but never the token sequence. `NAME` and `ARCH` are split on
/// the last dot of the first token.
pub fn parse_check_update(raw: &str) -> Vec<OsUpdate> {
    let mut tokens: Vec<&str> = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Last metadata") {
            continue;
        }
        if line.starts_with("Obsoleting Packages") {
            break;
        }
        tokens.extend(line.split_whitespace());
    }

    tokens
        .chunks_exact(3)
        .map(|chunk| {
            let (name, arch) = split_name_arch(chunk[0]);
            OsUpdate {
                name,
                arch,
                current_version: None,
                new_version: chunk[1].to_string(),
                repo: Some(chunk[2].to_string()),
                errata: None,
            }
        })
        .collect()
}

/// Parse `dnf updateinfo list --available` output into a map keyed by bare
/// package name.
///
/// Each line is `ADVISORY  TYPE  PACKAGE-NVRA`. The advisory type column drives
/// both [`ErrataKind`] and [`Severity`]: a `Severity/Sec.` value (e.g.
/// `Important/Sec.`) is a security advisory whose severity comes from the
/// prefix; `bugfix` and `enhancement` map to their respective kinds; anything
/// else is [`ErrataKind::Unknown`].
pub fn parse_security_updateinfo(raw: &str) -> HashMap<String, Errata> {
    let mut map: HashMap<String, Errata> = HashMap::new();

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut cols = line.split_whitespace();
        let (Some(advisory), Some(type_col), Some(nvra)) = (cols.next(), cols.next(), cols.next())
        else {
            continue;
        };

        let (kind, severity) = classify(type_col);
        let name = package_name_from_nvra(nvra);
        let errata = Errata {
            advisory: advisory.to_string(),
            severity,
            kind,
        };
        // A package can appear under more than one advisory; keep the most urgent.
        match map.get(&name) {
            Some(existing) if existing.severity >= severity => {}
            _ => {
                map.insert(name, errata);
            }
        }
    }

    map
}

/// Parse both `dnf` outputs and annotate each update with its errata.
///
/// The pending update list from [`parse_check_update`] is the source of truth;
/// any package that also appears in the advisory map from
/// [`parse_security_updateinfo`] gets its `errata` field populated.
pub fn parse(check_update: &str, updateinfo: &str) -> Vec<OsUpdate> {
    let errata = parse_security_updateinfo(updateinfo);
    let mut updates = parse_check_update(check_update);

    for update in &mut updates {
        if let Some(found) = errata.get(&update.name) {
            update.errata = Some(found.clone());
        }
    }

    updates
}

/// Split a `NAME.ARCH` token on its last dot.
///
/// dnf always suffixes the package name with an architecture (`bash.x86_64`,
/// `kernel.noarch`), so the final dot is the boundary. A token with no dot is
/// treated as a bare name with no architecture.
fn split_name_arch(pkg: &str) -> (String, Option<String>) {
    match pkg.rsplit_once('.') {
        Some((name, arch)) => (name.to_string(), Some(arch.to_string())),
        None => (pkg.to_string(), None),
    }
}

/// Map an `updateinfo` type column onto an [`ErrataKind`] and [`Severity`].
fn classify(type_col: &str) -> (ErrataKind, Severity) {
    if let Some(prefix) = type_col.strip_suffix("/Sec.") {
        return (ErrataKind::Security, severity_from_prefix(prefix));
    }
    match type_col.to_ascii_lowercase().as_str() {
        "bugfix" => (ErrataKind::BugFix, Severity::Unknown),
        "enhancement" => (ErrataKind::Enhancement, Severity::Unknown),
        _ => (ErrataKind::Unknown, Severity::Unknown),
    }
}

/// Map a security-advisory severity prefix onto a [`Severity`].
fn severity_from_prefix(prefix: &str) -> Severity {
    match prefix {
        "Critical" => Severity::Critical,
        "Important" => Severity::Important,
        "Moderate" => Severity::Moderate,
        "Low" => Severity::Low,
        _ => Severity::Unknown,
    }
}

/// Extract the bare package name from a `PACKAGE-NVRA` token.
///
/// An NVRA is `NAME-VERSION-RELEASE.ARCH`, so the name is everything before the
/// last two dash-separated segments (after stripping the trailing `.ARCH`). This
/// anchors on the version/release boundary rather than "first digit", so it
/// correctly handles hyphenated names (`glibc-common` => `glibc-common`) AND
/// names that themselves begin with a digit (`389-ds-base`, `389-ds-base-libs`).
fn package_name_from_nvra(nvra: &str) -> String {
    let without_arch = nvra.rsplit_once('.').map_or(nvra, |(rest, _arch)| rest);
    match without_arch
        .rsplit_once('-')
        .and_then(|(rest, _release)| rest.rsplit_once('-'))
    {
        Some((name, _version)) => name.to_string(),
        None => nvra.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECK_UPDATE: &str = "Last metadata expiration check: 0:12:33 ago on Mon 17 Jun 2026.

bash.x86_64                  5.2.26-3.el10           baseos
curl.x86_64                  8.9.1-5.el10_0          baseos
kernel.x86_64                6.12.0-55.el10          appstream
";

    const UPDATEINFO: &str = "RLSA-2024:1234 Important/Sec. curl-8.9.1-5.el10_0.x86_64
RLSA-2024:5678 Critical/Sec.  kernel-6.12.0-55.el10.x86_64
RLBA-2024:0001 bugfix         bash-5.2.26-3.el10.x86_64
";

    #[test]
    fn parses_three_updates_with_split_name_arch() {
        let updates = parse_check_update(CHECK_UPDATE);
        assert_eq!(updates.len(), 3);

        assert_eq!(updates[0].name, "bash");
        assert_eq!(updates[0].arch.as_deref(), Some("x86_64"));
        assert_eq!(updates[0].new_version, "5.2.26-3.el10");
        assert_eq!(updates[0].repo.as_deref(), Some("baseos"));
        assert_eq!(updates[0].current_version, None);
        assert_eq!(updates[0].errata, None);

        assert_eq!(updates[1].name, "curl");
        assert_eq!(updates[1].arch.as_deref(), Some("x86_64"));
        assert_eq!(updates[2].name, "kernel");
        assert_eq!(updates[2].repo.as_deref(), Some("appstream"));
    }

    #[test]
    fn ignores_obsoleting_packages_section() {
        let raw = "bash.x86_64   5.2.26-3.el10   baseos
Obsoleting Packages
oldpkg.x86_64   1.0-1.el10   baseos
";
        let updates = parse_check_update(raw);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].name, "bash");
    }

    #[test]
    fn empty_check_update_yields_no_updates() {
        assert!(parse_check_update("").is_empty());
        assert!(
            parse_check_update("Last metadata expiration check: 0:00:01 ago on Tue.\n\n")
                .is_empty()
        );
    }

    #[test]
    fn parses_updateinfo_kinds_and_severities() {
        let map = parse_security_updateinfo(UPDATEINFO);
        assert_eq!(map.len(), 3);

        let curl = &map["curl"];
        assert_eq!(curl.advisory, "RLSA-2024:1234");
        assert_eq!(curl.kind, ErrataKind::Security);
        assert_eq!(curl.severity, Severity::Important);

        let kernel = &map["kernel"];
        assert_eq!(kernel.advisory, "RLSA-2024:5678");
        assert_eq!(kernel.kind, ErrataKind::Security);
        assert_eq!(kernel.severity, Severity::Critical);

        let bash = &map["bash"];
        assert_eq!(bash.kind, ErrataKind::BugFix);
        assert_eq!(bash.severity, Severity::Unknown);
    }

    #[test]
    fn classifies_moderate_low_enhancement_and_unknown() {
        let raw = "RLSA-2024:0002 Moderate/Sec. openssl-3.2.2-6.el10.x86_64
RLSA-2024:0003 Low/Sec.       vim-9.1.083-1.el10.x86_64
RLEA-2024:0004 enhancement    podman-5.1.0-1.el10.x86_64
RLXA-2024:0005 newtype/Sec.   foo-1.0-1.el10.x86_64
";
        let map = parse_security_updateinfo(raw);
        assert_eq!(map["openssl"].severity, Severity::Moderate);
        assert_eq!(map["vim"].severity, Severity::Low);
        assert_eq!(map["podman"].kind, ErrataKind::Enhancement);
        assert_eq!(map["podman"].severity, Severity::Unknown);

        let foo = &map["foo"];
        assert_eq!(foo.kind, ErrataKind::Security);
        assert_eq!(foo.severity, Severity::Unknown);
    }

    #[test]
    fn extracts_hyphenated_package_names() {
        assert_eq!(
            package_name_from_nvra("kernel-6.12.0-55.el10.x86_64"),
            "kernel"
        );
        assert_eq!(package_name_from_nvra("curl-8.9.1-5.el10_0.x86_64"), "curl");
        assert_eq!(
            package_name_from_nvra("glibc-common-2.39-22.el10.x86_64"),
            "glibc-common"
        );
        assert_eq!(package_name_from_nvra("nofields"), "nofields");
    }

    #[test]
    fn merges_check_update_and_updateinfo() {
        let updates = parse(CHECK_UPDATE, UPDATEINFO);
        assert_eq!(updates.len(), 3);

        let curl = updates.iter().find(|u| u.name == "curl").unwrap();
        let curl_errata = curl.errata.as_ref().unwrap();
        assert_eq!(curl_errata.kind, ErrataKind::Security);
        assert_eq!(curl_errata.severity, Severity::Important);
        assert!(curl.is_security());

        let kernel = updates.iter().find(|u| u.name == "kernel").unwrap();
        let kernel_errata = kernel.errata.as_ref().unwrap();
        assert_eq!(kernel_errata.kind, ErrataKind::Security);
        assert_eq!(kernel_errata.severity, Severity::Critical);

        let bash = updates.iter().find(|u| u.name == "bash").unwrap();
        let bash_errata = bash.errata.as_ref().unwrap();
        assert_eq!(bash_errata.kind, ErrataKind::BugFix);
        assert!(!bash.is_security());
    }

    #[test]
    fn merge_leaves_errata_none_when_absent_from_updateinfo() {
        let updates = parse(CHECK_UPDATE, "");
        assert_eq!(updates.len(), 3);
        assert!(updates.iter().all(|u| u.errata.is_none()));
    }

    #[test]
    fn reassembles_wrapped_check_update_rows() {
        // A long NAME.ARCH wraps onto two lines; the indented continuation carries
        // the epoch-prefixed EVR and repo.
        let raw = "NetworkManager-config-server.noarch\n                              1:1.46.0-1.el10        baseos\ncurl.x86_64   8.9.1-5.el10_0   baseos\n";
        let updates = parse_check_update(raw);
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].name, "NetworkManager-config-server");
        assert_eq!(updates[0].arch.as_deref(), Some("noarch"));
        assert_eq!(updates[0].new_version, "1:1.46.0-1.el10");
        assert_eq!(updates[0].repo.as_deref(), Some("baseos"));
        assert_eq!(updates[1].name, "curl");
    }

    #[test]
    fn extracts_name_that_starts_with_a_digit() {
        assert_eq!(
            package_name_from_nvra("389-ds-base-2.6.1-1.el10.x86_64"),
            "389-ds-base"
        );
        assert_eq!(
            package_name_from_nvra("389-ds-base-libs-2.6.1-1.el10.x86_64"),
            "389-ds-base-libs"
        );
    }

    #[test]
    fn merges_security_errata_for_digit_leading_name() {
        let check = "389-ds-base.x86_64  2.6.1-1.el10  appstream\n";
        let info = "RLSA-2024:9999 Critical/Sec. 389-ds-base-2.6.1-1.el10.x86_64\n";
        let updates = parse(check, info);
        assert_eq!(updates.len(), 1);
        assert!(updates[0].is_security());
        assert_eq!(
            updates[0].errata.as_ref().unwrap().severity,
            Severity::Critical
        );
    }

    #[test]
    fn duplicate_advisory_keeps_most_urgent_severity() {
        let raw =
            "RLSA-1 Low/Sec. curl-1-1.el10.x86_64\nRLSA-2 Critical/Sec. curl-1-1.el10.x86_64\n";
        assert_eq!(
            parse_security_updateinfo(raw)["curl"].severity,
            Severity::Critical
        );
        // …regardless of advisory order.
        let reversed =
            "RLSA-2 Critical/Sec. curl-1-1.el10.x86_64\nRLSA-1 Low/Sec. curl-1-1.el10.x86_64\n";
        assert_eq!(
            parse_security_updateinfo(reversed)["curl"].severity,
            Severity::Critical
        );
    }
}
