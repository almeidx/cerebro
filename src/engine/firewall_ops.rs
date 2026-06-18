//! Firewall change application with the diff + auto-rollback-timer safety model.
//!
//! A change is computed as a [`crate::model::ZoneDiff`], applied to the **runtime**
//! ruleset only (so a `firewall-cmd --reload` reverts it), and guarded by a host-side
//! timer that reloads — undoing the change — unless the operator confirms in time. This
//! is the backstop against locking yourself out over SSH.

use crate::backends::firewalld::{self, DesiredZone};
use crate::engine::safety::{Disposition, SafetyGate};
use crate::error::{Error, Result};
use crate::model::{ActionTier, FirewallZone, ZoneDiff};
use crate::ssh::{CommandRunner, SshTarget};

/// Default host-side marker file proving the operator confirmed the change.
pub const DEFAULT_MARKER: &str = "/run/cerebro-fw-confirm";

/// A reviewed firewall change for a single zone, ready to apply.
pub struct FirewallPlan {
    pub zone: String,
    pub diff: ZoneDiff,
}

impl FirewallPlan {
    pub fn new(current: &FirewallZone, zone: &str, desired: &DesiredZone) -> Self {
        Self {
            zone: zone.to_string(),
            diff: firewalld::diff_zone(current, desired),
        }
    }

    pub fn is_noop(&self) -> bool {
        self.diff.is_empty()
    }

    /// A change that only *removes* openings (or deletes rules) is destructive.
    pub fn tier(&self) -> ActionTier {
        let removes_only_or_any = !self.diff.removed_services.is_empty()
            || !self.diff.removed_ports.is_empty()
            || !self.diff.removed_rich_rules.is_empty();
        if removes_only_or_any {
            ActionTier::Destructive
        } else {
            ActionTier::SafeWrite
        }
    }

    /// `firewall-cmd` argvs mutating only the runtime ruleset (revertible via reload).
    pub fn runtime_argv(&self) -> Vec<Vec<String>> {
        firewalld::apply_argv(&self.zone, &self.diff, false)
    }
}

/// Host-side guard argv: after `secs`, reload firewalld (reverting runtime to the
/// permanent ruleset) unless the confirmation `marker` exists. The guard is launched
/// detached so it survives the SSH session ending — which is exactly the lockout case.
///
/// Returned as a full `["sh", "-c", body]` argv: the body carries its own `nohup … &`
/// backgrounding and must be delivered as a single argument to an outer shell, which is
/// what dispatching it through [`CommandRunner`] (whose [`crate::ssh::join_remote`] quotes
/// each element) achieves. `marker` is shell-escaped before interpolation.
pub fn arm_rollback_command(secs: u64, marker: &str) -> Vec<String> {
    let m = crate::ssh::posix_quote(marker);
    let body = format!(
        "nohup sh -c 'rm -f {m}; sleep {secs}; if [ -f {m} ]; then rm -f {m}; else firewall-cmd --reload; fi' >/dev/null 2>&1 &"
    );
    vec!["sh".to_string(), "-c".to_string(), body]
}

/// Commands that keep the change: drop the marker (so the guard skips its reload) and
/// persist the runtime ruleset to permanent.
pub fn confirm_commands(marker: &str) -> Vec<Vec<String>> {
    vec![
        vec!["touch".to_string(), marker.to_string()],
        vec![
            "firewall-cmd".to_string(),
            "--runtime-to-permanent".to_string(),
        ],
    ]
}

async fn run_argv(runner: &dyn CommandRunner, target: &SshTarget, argv: &[String]) -> Result<()> {
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let out = runner.run(target, &refs).await?;
    if out.success() {
        Ok(())
    } else {
        Err(Error::RemoteCommand {
            host: target.host.clone(),
            code: out.status,
            stderr: out.stderr,
        })
    }
}

/// Arm the host-side rollback timer **first**, then apply the change to the runtime
/// ruleset, after passing the safety gate. On [`Disposition::DryRun`] nothing executes.
///
/// On success the caller MUST re-verify connectivity out of band and call
/// [`confirm_change`] before `rollback_secs` elapses — otherwise the host reloads
/// firewalld and reverts to the (known-good) permanent ruleset. Arming before mutating
/// is what makes a lockout self-heal even if this SSH session dies mid-apply.
pub async fn arm_and_apply(
    runner: &dyn CommandRunner,
    target: &SshTarget,
    plan: &FirewallPlan,
    gate: SafetyGate,
    rollback_secs: u64,
    marker: &str,
) -> Result<Disposition> {
    let disposition = gate.authorize(plan.tier())?;
    if disposition == Disposition::DryRun {
        return Ok(disposition);
    }
    run_argv(runner, target, &arm_rollback_command(rollback_secs, marker)).await?;
    for argv in plan.runtime_argv() {
        run_argv(runner, target, &argv).await?;
    }
    Ok(disposition)
}

/// Persist the change only after the operator has re-verified connectivity: drop the
/// confirmation marker (so the armed guard skips its reload) and write runtime to
/// permanent. Note: a reload reverts runtime to *permanent*, which is the prior ruleset
/// — it is only "known good" insofar as permanent was good before this change.
pub async fn confirm_change(
    runner: &dyn CommandRunner,
    target: &SshTarget,
    marker: &str,
) -> Result<()> {
    for argv in confirm_commands(marker) {
        run_argv(runner, target, &argv).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PortRule, Protocol};
    use crate::ssh::{ok_output, MockRunner};

    fn current_zone() -> FirewallZone {
        FirewallZone {
            name: "public".to_string(),
            interfaces: vec!["eth0".to_string()],
            services: vec!["ssh".to_string()],
            ..FirewallZone::default()
        }
    }

    #[test]
    fn adding_a_service_is_safe_write() {
        let desired = DesiredZone {
            services: vec!["ssh".to_string(), "https".to_string()],
            ports: vec![],
            rich_rules: vec![],
        };
        let plan = FirewallPlan::new(&current_zone(), "public", &desired);
        assert!(!plan.is_noop());
        assert_eq!(plan.tier(), ActionTier::SafeWrite);
        assert_eq!(plan.diff.added_services, vec!["https".to_string()]);
    }

    #[test]
    fn removing_a_service_is_destructive() {
        let desired = DesiredZone::default();
        let plan = FirewallPlan::new(&current_zone(), "public", &desired);
        assert_eq!(plan.tier(), ActionTier::Destructive);
    }

    fn add_https() -> DesiredZone {
        DesiredZone {
            services: vec!["ssh".to_string(), "https".to_string()],
            ports: vec![PortRule {
                port: "8443".to_string(),
                protocol: Protocol::Tcp,
            }],
            rich_rules: vec![],
        }
    }

    #[test]
    fn rollback_and_confirm_commands_are_well_formed() {
        let armed = arm_rollback_command(60, DEFAULT_MARKER);
        assert_eq!(armed[0], "sh");
        assert_eq!(armed[1], "-c");
        assert!(armed[2].contains("sleep 60"));
        assert!(armed[2].contains("firewall-cmd --reload"));
        assert!(armed[2].contains(DEFAULT_MARKER));

        let confirm = confirm_commands(DEFAULT_MARKER);
        assert_eq!(confirm[0][0], "touch");
        assert_eq!(confirm[1], vec!["firewall-cmd", "--runtime-to-permanent"]);
    }

    #[test]
    fn armed_rollback_survives_remote_quoting() {
        // Dispatching the argv through the runner re-quotes each element; the body must
        // arrive at an outer `sh -c` intact rather than being torn apart.
        let armed = arm_rollback_command(60, DEFAULT_MARKER);
        let refs: Vec<&str> = armed.iter().map(String::as_str).collect();
        let line = crate::ssh::join_remote(&refs);
        assert!(line.starts_with("sh -c '"));
        assert!(line.contains("firewall-cmd --reload"));
        assert!(line.trim_end().ends_with("&'"));
    }

    #[tokio::test]
    async fn dry_run_executes_nothing() {
        let plan = FirewallPlan::new(&current_zone(), "public", &add_https());
        let runner = MockRunner::new().fallback(ok_output(""));
        let target = SshTarget::new("web", "web");
        let gate = SafetyGate::new(false, true);
        let disposition = arm_and_apply(&runner, &target, &plan, gate, 60, DEFAULT_MARKER)
            .await
            .unwrap();
        assert_eq!(disposition, Disposition::DryRun);
    }

    #[tokio::test]
    async fn read_only_blocks_apply() {
        let plan = FirewallPlan::new(&current_zone(), "public", &add_https());
        let runner = MockRunner::new().fallback(ok_output(""));
        let target = SshTarget::new("web", "web");
        let gate = SafetyGate::new(true, false);
        let err = arm_and_apply(&runner, &target, &plan, gate, 60, DEFAULT_MARKER)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Blocked(_)));
    }

    #[tokio::test]
    async fn arm_and_apply_arms_before_mutating() {
        use std::sync::{Arc, Mutex};

        #[derive(Default)]
        struct RecordingRunner {
            calls: Mutex<Vec<String>>,
        }
        #[async_trait::async_trait]
        impl CommandRunner for RecordingRunner {
            async fn run(&self, _t: &SshTarget, argv: &[&str]) -> Result<crate::ssh::CmdOutput> {
                self.calls.lock().unwrap().push(argv.join(" "));
                Ok(ok_output(""))
            }
        }

        let plan = FirewallPlan::new(&current_zone(), "public", &add_https());
        let runner = Arc::new(RecordingRunner::default());
        let target = SshTarget::new("web", "web");
        let gate = SafetyGate::new(false, false);
        let disposition = arm_and_apply(runner.as_ref(), &target, &plan, gate, 60, DEFAULT_MARKER)
            .await
            .unwrap();
        assert_eq!(disposition, Disposition::Proceed);

        let calls = runner.calls.lock().unwrap();
        assert!(
            calls[0].contains("firewall-cmd --reload"),
            "rollback must be armed first"
        );
        assert!(
            calls
                .iter()
                .skip(1)
                .any(|c| c.contains("--add-service=https")),
            "the change must be applied after arming"
        );
    }
}
