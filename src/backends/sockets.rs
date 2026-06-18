//! Parser for `ss -H -tulpn` (listening sockets).
//!
//! The `-H` flag suppresses the header row, so every line is a socket. Columns are
//! whitespace-separated: `Netid State Recv-Q Send-Q LocalAddr:Port PeerAddr:Port [Process]`.

use crate::model::{ListeningSocket, Protocol};

fn protocol_of(netid: &str) -> Option<Protocol> {
    if netid.starts_with("tcp") {
        Some(Protocol::Tcp)
    } else if netid.starts_with("udp") {
        Some(Protocol::Udp)
    } else {
        None
    }
}

fn split_endpoint(endpoint: &str) -> Option<(&str, u16)> {
    let (addr, port) = endpoint.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    Some((addr, port))
}

fn parse_process(column: &str) -> (Option<String>, Option<u32>) {
    let name = column
        .split_once('"')
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(name, _)| name.to_string());

    let pid = column.split_once("pid=").and_then(|(_, rest)| {
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        digits.parse::<u32>().ok()
    });

    (name, pid)
}

fn parse_line(line: &str) -> Option<ListeningSocket> {
    let mut columns = line.split_whitespace();
    let protocol = protocol_of(columns.next()?)?;

    // State, Recv-Q, Send-Q, then the local endpoint (the 4th remaining column).
    let local = columns.nth(3)?;
    let (addr, port) = split_endpoint(local)?;

    // The process blob (`users:(("name",pid=N,fd=M))`) can contain spaces in the
    // process comm, so take it from the marker to end-of-line rather than as a
    // positional whitespace column.
    let (process, pid) = match line.find("users:((") {
        Some(idx) => parse_process(&line[idx..]),
        None => (None, None),
    };

    Some(ListeningSocket {
        protocol,
        local_addr: addr.to_string(),
        local_port: port,
        process,
        pid,
    })
}

/// Parse `ss -H -tulpn` output into the listening sockets it describes.
///
/// Lines whose protocol is neither tcp nor udp, or whose local port is not a valid
/// `u16` (for example a wildcard `*`), are skipped.
pub fn parse_ss(raw: &str) -> Vec<ListeningSocket> {
    raw.lines().filter_map(parse_line).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SS_OUTPUT: &str = concat!(
        "tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:((\"sshd\",pid=1234,fd=3))\n",
        "tcp   LISTEN 0      4096      127.0.0.1:5432       0.0.0.0:*    users:((\"postgres\",pid=2345,fd=5))\n",
        "udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*    users:((\"NetworkManager\",pid=900,fd=21))\n",
        "tcp   LISTEN 0      128             [::]:80            [::]:*    users:((\"nginx\",pid=3456,fd=6))\n",
        "tcp   LISTEN 0      128       127.0.0.1:9090        0.0.0.0:*\n",
    );

    fn parsed() -> Vec<ListeningSocket> {
        parse_ss(SS_OUTPUT)
    }

    #[test]
    fn parses_all_five_lines() {
        assert_eq!(parsed().len(), 5);
    }

    #[test]
    fn parses_sshd_wildcard() {
        let sockets = parsed();
        let sshd = &sockets[0];
        assert_eq!(sshd.protocol, Protocol::Tcp);
        assert_eq!(sshd.local_addr, "0.0.0.0");
        assert_eq!(sshd.local_port, 22);
        assert_eq!(sshd.process.as_deref(), Some("sshd"));
        assert_eq!(sshd.pid, Some(1234));
        assert!(sshd.is_wildcard());
    }

    #[test]
    fn parses_postgres_loopback() {
        let sockets = parsed();
        let postgres = &sockets[1];
        assert_eq!(postgres.protocol, Protocol::Tcp);
        assert_eq!(postgres.local_addr, "127.0.0.1");
        assert_eq!(postgres.local_port, 5432);
        assert_eq!(postgres.process.as_deref(), Some("postgres"));
        assert_eq!(postgres.pid, Some(2345));
        assert!(!postgres.is_wildcard());
    }

    #[test]
    fn parses_udp_socket() {
        let sockets = parsed();
        let nm = &sockets[2];
        assert_eq!(nm.protocol, Protocol::Udp);
        assert_eq!(nm.local_addr, "0.0.0.0");
        assert_eq!(nm.local_port, 68);
        assert_eq!(nm.process.as_deref(), Some("NetworkManager"));
        assert_eq!(nm.pid, Some(900));
    }

    #[test]
    fn parses_ipv6_wildcard() {
        let sockets = parsed();
        let nginx = &sockets[3];
        assert_eq!(nginx.protocol, Protocol::Tcp);
        assert_eq!(nginx.local_addr, "[::]");
        assert_eq!(nginx.local_port, 80);
        assert_eq!(nginx.process.as_deref(), Some("nginx"));
        assert_eq!(nginx.pid, Some(3456));
        assert!(nginx.is_wildcard());
    }

    #[test]
    fn parses_line_without_process() {
        let sockets = parsed();
        let bare = &sockets[4];
        assert_eq!(bare.local_addr, "127.0.0.1");
        assert_eq!(bare.local_port, 9090);
        assert_eq!(bare.process, None);
        assert_eq!(bare.pid, None);
    }

    #[test]
    fn parses_process_name_with_space() {
        let raw = "tcp   LISTEN 0      128          0.0.0.0:32400      0.0.0.0:*    users:((\"Plex Media Serv\",pid=999,fd=30))\n";
        let sockets = parse_ss(raw);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].local_port, 32400);
        assert_eq!(sockets[0].process.as_deref(), Some("Plex Media Serv"));
        assert_eq!(sockets[0].pid, Some(999));
    }

    #[test]
    fn parses_concrete_ipv6_address() {
        let raw = "tcp   LISTEN 0      128       [2001:db8::1]:443      [::]:*    users:((\"nginx\",pid=7,fd=8))\n";
        let sockets = parse_ss(raw);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].local_addr, "[2001:db8::1]");
        assert_eq!(sockets[0].local_port, 443);
        assert!(!sockets[0].is_wildcard());
    }

    #[test]
    fn skips_non_tcp_udp_lines() {
        let raw = "nl    UNCONN 0      0            *:* \n\
                   tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*\n";
        let sockets = parse_ss(raw);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].local_port, 22);
    }

    #[test]
    fn skips_wildcard_port() {
        let raw = "tcp   LISTEN 0      128          0.0.0.0:*         0.0.0.0:*\n";
        assert!(parse_ss(raw).is_empty());
    }

    #[test]
    fn skips_blank_and_garbage_lines() {
        let raw = "\n   \nnot a socket line\n";
        assert!(parse_ss(raw).is_empty());
    }

    #[test]
    fn is_wildcard_for_known_addresses() {
        for addr in ["0.0.0.0", "[::]", "*", "::", "::0"] {
            let socket = ListeningSocket {
                protocol: Protocol::Tcp,
                local_addr: addr.to_string(),
                local_port: 80,
                process: None,
                pid: None,
            };
            assert!(socket.is_wildcard(), "expected {addr} to be wildcard");
        }
    }
}
