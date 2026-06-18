//! Snapshot drift detection via unified diff.
//!
//! Compares the previously captured payload of a [`SnapshotKind`] against the
//! current one and, when they differ, produces a [`Drift`] carrying a unified
//! diff and a terse `added/removed` line summary.

use similar::{ChangeTag, TextDiff};

use crate::model::{Drift, SnapshotKind};

/// Compute the drift between two snapshot payloads of the same `kind`.
///
/// Returns `None` when the payloads are byte-for-byte identical, otherwise a
/// [`Drift`] whose `diff` is a unified diff (`previous` -> `current`) and whose
/// `summary` counts inserted and deleted lines.
pub fn diff_snapshots(kind: SnapshotKind, host: &str, old: &str, new: &str) -> Option<Drift> {
    if old == new {
        return None;
    }

    let diff = TextDiff::from_lines(old, new);
    let unified = diff
        .unified_diff()
        .context_radius(3)
        .header("previous", "current")
        .to_string();

    let mut added = 0usize;
    let mut removed = 0usize;
    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Insert => added += 1,
            ChangeTag::Delete => removed += 1,
            ChangeTag::Equal => {}
        }
    }

    Some(Drift {
        host: host.to_string(),
        kind,
        summary: format!("{added} added, {removed} removed"),
        diff: unified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_payloads_report_no_drift() {
        let payload = "a\nb\nc\n";
        assert!(diff_snapshots(SnapshotKind::Firewall, "web-01", payload, payload).is_none());
    }

    #[test]
    fn empty_payloads_report_no_drift() {
        assert!(diff_snapshots(SnapshotKind::Firewall, "web-01", "", "").is_none());
    }

    #[test]
    fn single_line_change_counts_one_added_one_removed() {
        let old = "a\nb\nc\n";
        let new = "a\nB\nc\n";
        let drift = diff_snapshots(SnapshotKind::Firewall, "web-01", old, new)
            .expect("payloads differ, expected drift");

        assert_eq!(drift.host, "web-01");
        assert_eq!(drift.kind, SnapshotKind::Firewall);
        assert_eq!(drift.summary, "1 added, 1 removed");
        assert!(!drift.diff.is_empty());
        assert!(drift.diff.contains('B'));
    }

    #[test]
    fn pure_additions_report_only_added() {
        let old = "a\nb\n";
        let new = "a\nb\nc\nd\n";
        let drift = diff_snapshots(SnapshotKind::Firewall, "web-01", old, new)
            .expect("payloads differ, expected drift");

        assert_eq!(drift.summary, "2 added, 0 removed");
        assert!(drift.diff.contains('c'));
        assert!(drift.diff.contains('d'));
    }

    #[test]
    fn pure_removals_report_only_removed() {
        let old = "a\nb\nc\nd\n";
        let new = "a\nd\n";
        let drift = diff_snapshots(SnapshotKind::Firewall, "web-01", old, new)
            .expect("payloads differ, expected drift");

        assert_eq!(drift.summary, "0 added, 2 removed");
        assert!(drift.diff.contains('b'));
        assert!(drift.diff.contains('c'));
    }

    #[test]
    fn unified_diff_carries_headers() {
        let old = "rule one\n";
        let new = "rule two\n";
        let drift = diff_snapshots(SnapshotKind::Firewall, "fw-1", old, new)
            .expect("payloads differ, expected drift");

        assert!(drift.diff.contains("previous"));
        assert!(drift.diff.contains("current"));
        assert!(drift.diff.contains("rule one"));
        assert!(drift.diff.contains("rule two"));
    }
}
