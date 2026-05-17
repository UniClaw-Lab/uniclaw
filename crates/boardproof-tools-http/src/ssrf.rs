//! Server-Side Request Forgery defense.
//!
//! When `HttpFetchConfig::allow_private_ips` is `false` (the default), a
//! request whose host parses as a literal IP in any of the ranges below
//! is refused **before** the HTTP client opens a connection.
//!
//! ## Disallowed IPv4 ranges (RFC-cited where applicable)
//!
//! | Range | RFC | Reason |
//! |---|---|---|
//! | `0.0.0.0/8` | RFC 1122 | "this network" |
//! | `10.0.0.0/8` | RFC 1918 | private |
//! | `100.64.0.0/10` | RFC 6598 | shared / carrier-grade NAT |
//! | `127.0.0.0/8` | RFC 1122 | loopback |
//! | `169.254.0.0/16` | RFC 3927 | link-local |
//! | `172.16.0.0/12` | RFC 1918 | private |
//! | `192.0.0.0/24` | RFC 6890 | IETF protocol assignments |
//! | `192.168.0.0/16` | RFC 1918 | private |
//! | `198.18.0.0/15` | RFC 2544 | benchmark |
//! | `224.0.0.0/4` | RFC 5771 | multicast |
//! | `240.0.0.0/4` | RFC 1112 | reserved / future |
//! | `255.255.255.255/32` | RFC 919 | limited broadcast |
//!
//! ## Disallowed IPv6 ranges
//!
//! | Range | RFC | Reason |
//! |---|---|---|
//! | `::/128` | RFC 4291 | unspecified |
//! | `::1/128` | RFC 4291 | loopback |
//! | `fc00::/7` | RFC 4193 | unique local (private) |
//! | `fe80::/10` | RFC 4291 | link-local |
//! | `ff00::/8` | RFC 4291 | multicast |
//! | `2001:db8::/32` | RFC 3849 | documentation |
//! | `::ffff:x.x.x.x` | RFC 4291 | IPv4-mapped (recurse on the embedded v4) |
//!
//! ## What this does NOT defend against
//!
//! - **DNS rebinding.** A hostname that resolves to a public IP at parse
//!   time but a private IP at connect time slips through. A future step
//!   pins the resolved IP; v0 documents this as a known limitation.
//! - **Hostname allowlist correctness.** This module only catches *literal*
//!   IPs in the request. Hostname-based requests rely on the
//!   `Capability::NetConnect` glob to restrict targets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Is this host string a literal IP address that we should refuse for
/// SSRF reasons? Returns `true` if the host parses as an IP address in
/// any disallowed range, `false` otherwise (including: not an IP at
/// all — hostnames pass through and are gated by capability glob).
///
/// `host` should be the unbracketed host, exactly as `url::Url::host_str`
/// returns: `"127.0.0.1"`, `"::1"`, `"api.example.com"`. Not
/// `"[::1]"`, not `"https://..."`.
#[must_use]
pub fn is_disallowed_ip(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => is_disallowed_v4(v4),
        Ok(IpAddr::V6(v6)) => is_disallowed_v6(v6),
        Err(_) => false,
    }
}

fn is_disallowed_v4(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    let [a, b, _, _] = octets;

    if addr.is_loopback() || addr.is_private() || addr.is_link_local() || addr.is_multicast() {
        return true;
    }
    if addr.is_unspecified() || addr.is_broadcast() {
        return true;
    }
    // `0.0.0.0/8`: the leading-zero "this network" range. is_unspecified
    // covers only 0.0.0.0/32.
    if a == 0 {
        return true;
    }
    // `100.64.0.0/10`: carrier-grade NAT.
    if a == 100 && (64..=127).contains(&b) {
        return true;
    }
    // `192.0.0.0/24`: IETF protocol assignments.
    if octets[0..3] == [192, 0, 0] {
        return true;
    }
    // `198.18.0.0/15`: benchmark range.
    if a == 198 && (b == 18 || b == 19) {
        return true;
    }
    // `240.0.0.0/4`: reserved / future. (`is_multicast` is `224.0.0.0/4`,
    // so this catches the rest.)
    if a >= 240 {
        return true;
    }
    false
}

fn is_disallowed_v6(addr: Ipv6Addr) -> bool {
    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return true;
    }

    let segs = addr.segments();
    let high = segs[0];

    // `fe80::/10` — link-local. `is_unicast_link_local` is unstable in
    // std; check manually: top 10 bits are `1111111010` = `0xfe80..0xfebf`.
    if (high & 0xffc0) == 0xfe80 {
        return true;
    }
    // `fc00::/7` — unique local addresses (private equivalent).
    if (high & 0xfe00) == 0xfc00 {
        return true;
    }
    // `2001:db8::/32` — RFC 3849 documentation range.
    if high == 0x2001 && segs[1] == 0x0db8 {
        return true;
    }
    // IPv4-mapped IPv6 (`::ffff:x.x.x.x`): the bottom 32 bits are an
    // IPv4 address; recurse on it.
    if let Some(v4) = addr.to_ipv4_mapped() {
        return is_disallowed_v4(v4);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- IPv4 ---

    #[test]
    fn loopback_is_refused() {
        assert!(is_disallowed_ip("127.0.0.1"));
        assert!(is_disallowed_ip("127.255.255.254"));
    }

    #[test]
    fn rfc1918_private_ranges_refused() {
        assert!(is_disallowed_ip("10.0.0.1"));
        assert!(is_disallowed_ip("172.16.0.1"));
        assert!(is_disallowed_ip("172.31.255.255"));
        assert!(is_disallowed_ip("192.168.0.1"));
    }

    #[test]
    fn link_local_169_254_refused() {
        assert!(is_disallowed_ip("169.254.169.254")); // AWS metadata
        assert!(is_disallowed_ip("169.254.0.1"));
    }

    #[test]
    fn cgn_100_64_refused() {
        assert!(is_disallowed_ip("100.64.0.1"));
        assert!(is_disallowed_ip("100.127.255.255"));
        // Just outside the range: 100.63.x and 100.128.x — these are
        // public allocations.
        assert!(!is_disallowed_ip("100.63.0.1"));
        assert!(!is_disallowed_ip("100.128.0.1"));
    }

    #[test]
    fn this_network_zero_slash_eight_refused() {
        assert!(is_disallowed_ip("0.0.0.0"));
        assert!(is_disallowed_ip("0.255.255.255"));
    }

    #[test]
    fn ietf_protocol_192_0_0_refused() {
        assert!(is_disallowed_ip("192.0.0.1"));
        assert!(is_disallowed_ip("192.0.0.255"));
        // Just outside: 192.0.1.x is documentation but currently
        // routable as a hole punching target — we don't refuse the
        // wider 192.0.0.0/16 because not everything in there is
        // sensitive, but 192.0.0.0/24 is.
        assert!(!is_disallowed_ip("192.0.1.1"));
    }

    #[test]
    fn benchmark_198_18_refused() {
        assert!(is_disallowed_ip("198.18.0.1"));
        assert!(is_disallowed_ip("198.19.255.255"));
        assert!(!is_disallowed_ip("198.20.0.1"));
    }

    #[test]
    fn multicast_and_reserved_refused() {
        assert!(is_disallowed_ip("224.0.0.1"));
        assert!(is_disallowed_ip("239.255.255.250")); // SSDP
        assert!(is_disallowed_ip("240.0.0.1"));
        assert!(is_disallowed_ip("255.255.255.255")); // broadcast
    }

    #[test]
    fn public_ipv4_passes() {
        assert!(!is_disallowed_ip("8.8.8.8"));
        assert!(!is_disallowed_ip("1.1.1.1"));
        assert!(!is_disallowed_ip("142.250.190.78")); // google.com
    }

    // --- IPv6 ---

    #[test]
    fn ipv6_loopback_refused() {
        assert!(is_disallowed_ip("::1"));
    }

    #[test]
    fn ipv6_unspecified_refused() {
        assert!(is_disallowed_ip("::"));
    }

    #[test]
    fn ipv6_link_local_refused() {
        assert!(is_disallowed_ip("fe80::1"));
        assert!(is_disallowed_ip("febf:1234::1"));
        // Just outside fe80::/10:
        assert!(!is_disallowed_ip("fec0::1"));
    }

    #[test]
    fn ipv6_unique_local_refused() {
        assert!(is_disallowed_ip("fc00::1"));
        assert!(is_disallowed_ip("fd12:3456::1"));
        // Just outside fc00::/7:
        assert!(!is_disallowed_ip("fe00::1"));
    }

    #[test]
    fn ipv6_multicast_refused() {
        assert!(is_disallowed_ip("ff00::1"));
        assert!(is_disallowed_ip("ff02::1")); // all-nodes
    }

    #[test]
    fn ipv6_documentation_2001_db8_refused() {
        assert!(is_disallowed_ip("2001:db8::1"));
        assert!(is_disallowed_ip("2001:db8:dead:beef::1"));
        // Just outside 2001:db8::/32:
        assert!(!is_disallowed_ip("2001:db9::1"));
    }

    #[test]
    fn ipv6_mapped_ipv4_recursively_checked() {
        // ::ffff:127.0.0.1 — should be refused because it's loopback.
        assert!(is_disallowed_ip("::ffff:127.0.0.1"));
        assert!(is_disallowed_ip("::ffff:10.0.0.1"));
        // ::ffff:8.8.8.8 — public, should pass.
        assert!(!is_disallowed_ip("::ffff:8.8.8.8"));
    }

    #[test]
    fn public_ipv6_passes() {
        assert!(!is_disallowed_ip("2606:4700:4700::1111")); // cloudflare
        assert!(!is_disallowed_ip("2001:4860:4860::8888")); // google
    }

    // --- Non-IP hostnames pass through ---

    #[test]
    fn hostnames_are_not_disallowed_by_this_check() {
        // Hostnames are gated by the capability glob, not by this
        // module. A hostname like "localhost" would resolve to
        // 127.0.0.1 at connect time — DNS rebinding is documented
        // as a known limitation; this module catches *literal* IPs.
        assert!(!is_disallowed_ip("localhost"));
        assert!(!is_disallowed_ip("api.example.com"));
        assert!(!is_disallowed_ip(""));
    }
}
