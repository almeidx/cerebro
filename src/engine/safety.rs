//! The safety gate: tiered actions, dry-run, and a global read-only switch.
//!
//! Every mutating operation the engine performs is classified by an
//! [`ActionTier`] and passed through a [`SafetyGate`] first. The gate is the
//! single place that decides whether a command may actually run, must be turned
//! into a dry-run preview, or has to be refused outright.

use crate::error::{Error, Result};
use crate::model::ActionTier;

/// What the safety gate decided an authorized action should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Execute the action for real.
    Proceed,
    /// Compute and show the change, but do not apply it.
    DryRun,
}

/// Global mutation policy applied to every tiered action.
#[derive(Debug, Clone, Copy)]
pub struct SafetyGate {
    /// When set, no write of any tier is allowed; reads still pass.
    pub read_only: bool,
    /// When set, allowed writes are previewed rather than applied.
    pub dry_run: bool,
}

impl SafetyGate {
    /// Construct a gate from the two global flags.
    pub fn new(read_only: bool, dry_run: bool) -> Self {
        Self { read_only, dry_run }
    }

    /// Decide what should happen to an action of the given tier.
    ///
    /// Reads always proceed, even under read-only. Writes are refused with
    /// [`Error::Blocked`] in read-only mode (which takes precedence over
    /// dry-run), previewed when only dry-run is set, and otherwise proceed.
    pub fn authorize(&self, tier: ActionTier) -> Result<Disposition> {
        match tier {
            ActionTier::Read => Ok(Disposition::Proceed),
            ActionTier::SafeWrite | ActionTier::Destructive => {
                if self.read_only {
                    Err(Error::Blocked(format!(
                        "{tier} action refused: Cerebro is running in read-only mode"
                    )))
                } else if self.dry_run {
                    Ok(Disposition::DryRun)
                } else {
                    Ok(Disposition::Proceed)
                }
            }
        }
    }
}

/// Whether an action of this tier warrants an explicit extra confirmation
/// before it is authorized. Only [`ActionTier::Destructive`] does.
pub fn requires_extra_confirmation(tier: ActionTier) -> bool {
    matches!(tier, ActionTier::Destructive)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODES: [(bool, bool); 4] = [(false, false), (false, true), (true, false), (true, true)];

    #[test]
    fn reads_always_proceed_in_every_mode() {
        for (read_only, dry_run) in MODES {
            let gate = SafetyGate::new(read_only, dry_run);
            assert_eq!(
                gate.authorize(ActionTier::Read).unwrap(),
                Disposition::Proceed,
                "read should proceed with read_only={read_only}, dry_run={dry_run}"
            );
        }
    }

    #[test]
    fn safe_write_blocked_in_read_only() {
        let gate = SafetyGate::new(true, false);
        let err = gate.authorize(ActionTier::SafeWrite).unwrap_err();
        assert!(matches!(err, Error::Blocked(_)));
    }

    #[test]
    fn blocked_message_names_tier_and_mentions_read_only() {
        let gate = SafetyGate::new(true, false);
        let Error::Blocked(msg) = gate.authorize(ActionTier::Destructive).unwrap_err() else {
            panic!("expected Blocked");
        };
        assert!(msg.contains("destructive"));
        assert!(msg.contains("read-only"));
    }

    #[test]
    fn safe_write_is_dry_run_when_dry_run_and_not_read_only() {
        let gate = SafetyGate::new(false, true);
        assert_eq!(
            gate.authorize(ActionTier::SafeWrite).unwrap(),
            Disposition::DryRun
        );
    }

    #[test]
    fn safe_write_proceeds_when_neither_flag_set() {
        let gate = SafetyGate::new(false, false);
        assert_eq!(
            gate.authorize(ActionTier::SafeWrite).unwrap(),
            Disposition::Proceed
        );
    }

    #[test]
    fn read_only_takes_precedence_over_dry_run_for_writes() {
        let gate = SafetyGate::new(true, true);
        assert!(matches!(
            gate.authorize(ActionTier::SafeWrite).unwrap_err(),
            Error::Blocked(_)
        ));
        assert!(matches!(
            gate.authorize(ActionTier::Destructive).unwrap_err(),
            Error::Blocked(_)
        ));
    }

    #[test]
    fn destructive_proceeds_when_neither_flag_set() {
        let gate = SafetyGate::new(false, false);
        assert_eq!(
            gate.authorize(ActionTier::Destructive).unwrap(),
            Disposition::Proceed
        );
    }

    #[test]
    fn requires_extra_confirmation_only_for_destructive() {
        assert!(requires_extra_confirmation(ActionTier::Destructive));
        assert!(!requires_extra_confirmation(ActionTier::SafeWrite));
        assert!(!requires_extra_confirmation(ActionTier::Read));
    }
}
