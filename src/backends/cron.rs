//! Parsers for classic crontab formats.
//!
//! Three flavours are handled: per-user crontabs (5 schedule fields then the
//! command), `/etc/crontab` and `/etc/cron.d/*` (6 fields, with a `user` column
//! between the schedule and the command). Lines are parsed defensively: prose
//! comments and environment assignments are skipped, while a comment whose body
//! is itself a schedule is treated as a disabled job.

use crate::model::{CronJob, CronSource};

const AT_KEYWORDS: &[&str] = &[
    "@reboot",
    "@daily",
    "@hourly",
    "@weekly",
    "@monthly",
    "@yearly",
    "@annually",
    "@midnight",
];

/// Parse a per-user crontab: 5 schedule fields followed by the command.
///
/// Every produced [`CronJob`] has source [`CronSource::UserCrontab`] and
/// `user` set to `Some(user)`.
pub fn parse_user_crontab(user: &str, content: &str) -> Vec<CronJob> {
    parse_lines(content, &CronSource::UserCrontab, |line| {
        let (schedule, command) = split_schedule_command(line)?;
        Some((schedule, Some(user.to_string()), command))
    })
}

/// Parse `/etc/crontab`: 6 fields, with a `user` column between the schedule and
/// the command.
///
/// Every produced [`CronJob`] has source [`CronSource::EtcCrontab`].
pub fn parse_etc_crontab(content: &str) -> Vec<CronJob> {
    parse_lines(content, &CronSource::EtcCrontab, parse_system_line)
}

/// Parse a drop-in under `/etc/cron.d`: same 6-field format as `/etc/crontab`.
///
/// Every produced [`CronJob`] has source [`CronSource::CronD(path)`].
pub fn parse_cron_d(path: &str, content: &str) -> Vec<CronJob> {
    parse_lines(
        content,
        &CronSource::CronD(path.to_string()),
        parse_system_line,
    )
}

fn parse_system_line(line: &str) -> Option<(String, Option<String>, String)> {
    let (schedule, rest) = split_schedule_command(line)?;
    let (user, command) = rest.split_once(char::is_whitespace)?;
    if user.is_empty() || command.trim().is_empty() {
        return None;
    }
    Some((
        schedule,
        Some(user.to_string()),
        command.trim_start().to_string(),
    ))
}

fn parse_lines<F>(content: &str, source: &CronSource, parse_body: F) -> Vec<CronJob>
where
    F: Fn(&str) -> Option<(String, Option<String>, String)>,
{
    let mut jobs = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let (body, enabled) = match classify(line) {
            LineKind::Skip => continue,
            LineKind::Active => (line, true),
            LineKind::Disabled(body) => (body, false),
        };

        if let Some((schedule, user, command)) = parse_body(body) {
            jobs.push(CronJob {
                source: source.clone(),
                user,
                schedule,
                command,
                raw: body.to_string(),
                enabled,
            });
        }
    }
    jobs
}

enum LineKind<'a> {
    Skip,
    Active,
    Disabled(&'a str),
}

fn classify(line: &str) -> LineKind<'_> {
    if let Some(rest) = line.strip_prefix('#') {
        let body = rest.trim_start();
        if looks_like_schedule(body) {
            return LineKind::Disabled(body);
        }
        return LineKind::Skip;
    }
    if is_env_assignment(line) {
        return LineKind::Skip;
    }
    LineKind::Active
}

/// Whether a comment body is a real (commented-out) cron entry rather than prose.
///
/// A bare "first char is a digit/star" test misfires on notes like "# 2024 was a
/// good year", so we require the candidate to actually split into a schedule whose
/// every field is valid cron syntax (or a known `@keyword`).
fn looks_like_schedule(body: &str) -> bool {
    let trimmed = body.trim_start();
    if trimmed.starts_with('@') {
        let keyword = trimmed
            .split_once(char::is_whitespace)
            .map_or(trimmed, |(k, _)| k);
        return AT_KEYWORDS.contains(&keyword);
    }
    match split_schedule_command(trimmed) {
        Some((schedule, _command)) => schedule.split_whitespace().all(is_cron_field),
        None => false,
    }
}

fn is_cron_field(field: &str) -> bool {
    !field.is_empty()
        && field
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '*' | ',' | '-' | '/'))
}

fn is_env_assignment(line: &str) -> bool {
    let Some((ident, _)) = line.split_once('=') else {
        return false;
    };
    let mut chars = ident.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn split_schedule_command(line: &str) -> Option<(String, String)> {
    let mut rest = line.trim_start();
    if rest.starts_with('@') {
        let (keyword, tail) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        if !AT_KEYWORDS.contains(&keyword) {
            return None;
        }
        let command = tail.trim_start();
        if command.is_empty() {
            return None;
        }
        return Some((keyword.to_string(), command.to_string()));
    }

    let mut fields = Vec::with_capacity(5);
    for _ in 0..5 {
        let trimmed = rest.trim_start();
        if trimmed.is_empty() {
            return None;
        }
        let (field, tail) = trimmed
            .split_once(char::is_whitespace)
            .unwrap_or((trimmed, ""));
        fields.push(field);
        rest = tail;
    }

    let command = rest.trim_start();
    if command.is_empty() {
        return None;
    }
    Some((fields.join(" "), command.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_CRONTAB: &str = "\
# m h dom mon dow command
SHELL=/bin/bash
*/5 * * * * /usr/bin/check.sh
@daily /usr/local/bin/backup.sh
#0 3 * * * /x.sh
";

    #[test]
    fn parses_user_crontab() {
        let jobs = parse_user_crontab("deploy", USER_CRONTAB);
        assert_eq!(jobs.len(), 3);

        assert_eq!(jobs[0].schedule, "*/5 * * * *");
        assert_eq!(jobs[0].command, "/usr/bin/check.sh");
        assert!(jobs[0].enabled);

        assert_eq!(jobs[1].schedule, "@daily");
        assert_eq!(jobs[1].command, "/usr/local/bin/backup.sh");
        assert!(jobs[1].enabled);

        assert_eq!(jobs[2].schedule, "0 3 * * *");
        assert_eq!(jobs[2].command, "/x.sh");
        assert!(!jobs[2].enabled);

        for job in &jobs {
            assert_eq!(job.source, CronSource::UserCrontab);
            assert_eq!(job.user.as_deref(), Some("deploy"));
        }
    }

    #[test]
    fn disabled_job_strips_leading_hash_from_raw() {
        let jobs = parse_user_crontab("deploy", "#0 3 * * * /x.sh\n");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].raw, "0 3 * * * /x.sh");
        assert!(!jobs[0].enabled);
    }

    #[test]
    fn prose_comment_is_skipped() {
        let jobs = parse_user_crontab("deploy", "# some note about the box\n");
        assert!(jobs.is_empty());
    }

    #[test]
    fn prose_comment_starting_with_digit_is_not_a_job() {
        assert!(parse_user_crontab("deploy", "# 2024 was a good year for us\n").is_empty());
        assert!(parse_user_crontab("deploy", "# 5 reasons to upgrade now please\n").is_empty());
        // A genuine disabled job is still recognised.
        let jobs = parse_user_crontab("deploy", "#0 3 * * * /x.sh\n");
        assert_eq!(jobs.len(), 1);
        assert!(!jobs[0].enabled);
    }

    #[test]
    fn env_assignments_are_skipped() {
        let content = "SHELL=/bin/bash\nPATH=/usr/bin:/bin\nMAILTO=ops@example.com\n";
        let jobs = parse_user_crontab("deploy", content);
        assert!(jobs.is_empty());
    }

    #[test]
    fn parses_etc_crontab() {
        let content = "0 3 * * * root /sbin/logrotate\n";
        let jobs = parse_etc_crontab(content);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].schedule, "0 3 * * *");
        assert_eq!(jobs[0].user.as_deref(), Some("root"));
        assert_eq!(jobs[0].command, "/sbin/logrotate");
        assert_eq!(jobs[0].source, CronSource::EtcCrontab);
        assert!(jobs[0].enabled);
    }

    #[test]
    fn etc_crontab_at_keyword_takes_user_column() {
        let content = "@daily backup /usr/local/bin/dump.sh --all\n";
        let jobs = parse_etc_crontab(content);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].schedule, "@daily");
        assert_eq!(jobs[0].user.as_deref(), Some("backup"));
        assert_eq!(jobs[0].command, "/usr/local/bin/dump.sh --all");
    }

    #[test]
    fn parse_cron_d_sets_source_with_path() {
        let path = "/etc/cron.d/certbot";
        let content = "0 */12 * * * root /usr/bin/certbot renew --quiet\n";
        let jobs = parse_cron_d(path, content);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].source, CronSource::CronD(path.to_string()));
        assert_eq!(jobs[0].user.as_deref(), Some("root"));
        assert_eq!(jobs[0].schedule, "0 */12 * * *");
        assert_eq!(jobs[0].command, "/usr/bin/certbot renew --quiet");
    }

    #[test]
    fn realistic_cron_d_fixture() {
        let content = "\
# /etc/cron.d/sysstat: run system activity accounting tool every 10 minutes
SHELL=/bin/sh
PATH=/usr/lib/sysstat:/usr/sbin:/usr/sbin:/usr/bin:/sbin:/bin
*/10 * * * * root command -v debian-sa1 > /dev/null && debian-sa1 1 1
53 23 * * * root command -v debian-sa1 > /dev/null && debian-sa1 60 2
";
        let jobs = parse_cron_d("/etc/cron.d/sysstat", content);
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].schedule, "*/10 * * * *");
        assert_eq!(jobs[0].user.as_deref(), Some("root"));
        assert_eq!(
            jobs[0].command,
            "command -v debian-sa1 > /dev/null && debian-sa1 1 1"
        );
        assert_eq!(jobs[1].schedule, "53 23 * * *");
    }

    #[test]
    fn disabled_system_job_keeps_user_column() {
        let content = "#30 2 * * * root /usr/bin/maint.sh\n";
        let jobs = parse_etc_crontab(content);
        assert_eq!(jobs.len(), 1);
        assert!(!jobs[0].enabled);
        assert_eq!(jobs[0].user.as_deref(), Some("root"));
        assert_eq!(jobs[0].schedule, "30 2 * * *");
        assert_eq!(jobs[0].command, "/usr/bin/maint.sh");
        assert_eq!(jobs[0].raw, "30 2 * * * root /usr/bin/maint.sh");
    }

    #[test]
    fn unknown_at_keyword_is_dropped() {
        let jobs = parse_user_crontab("deploy", "@never /usr/bin/never.sh\n");
        assert!(jobs.is_empty());
    }

    #[test]
    fn schedule_with_no_command_is_dropped() {
        let jobs = parse_user_crontab("deploy", "* * * * *\n");
        assert!(jobs.is_empty());
    }

    #[test]
    fn extra_whitespace_in_schedule_is_normalised() {
        let jobs = parse_user_crontab("deploy", "  0   4   *   *   1   /run.sh  \n");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].schedule, "0 4 * * 1");
        assert_eq!(jobs[0].command, "/run.sh");
    }

    #[test]
    fn command_preserves_internal_spacing() {
        let jobs = parse_user_crontab("deploy", "0 0 * * * /bin/sh -c 'echo  hi'\n");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].command, "/bin/sh -c 'echo  hi'");
    }
}
