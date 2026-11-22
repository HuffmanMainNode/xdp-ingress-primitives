# Security Model

## Intended behavior

This prototype is an ingress-only XDP primitive. It performs a narrow exact-match lookup of an IPv4 source address in a BPF hash map and returns `XDP_DROP` only when the map contains the explicit drop value.

All other paths return `XDP_PASS`, which passes the packet to the normal networking stack. It is not fail-closed and must never be described as such.

## Explicit boundaries

- No outbound scanning, remote exploitation, brute force, counter-attack, or retaliation.
- No loader, program pinning, map updater, interface attach/detach, or automatic network mutation.
- The Python rule compiler is preview-only and never invokes bpftool or another host-control utility.
- No privilege escalation or network retrieval.
- Only exact IPv4 source addresses are supported by the current map format.
- IPv6, VLAN-tagged frames, non-IPv4 frames, malformed/truncated headers, missing rules, and unsupported map values pass to the normal stack.
- No claim of protection is made until a compatible program has been loaded, verified, attached, and observed.

## Failure behavior

Compilation failure means no object was produced. Missing or unavailable XDP support must be reported as unavailable by any future loader; it must not trigger silent fallback or connectivity disruption. XDP_PASS is pass-through, not a fail-closed substitute.

## Verification limits

- CI compilation and unit tests do not prove kernel verifier acceptance.
- No TIER-3 privileged verifier or attach test has been performed.
- No supported kernel minimum, NIC, driver mode, or hardware compatibility is claimed.
- No live packet capture or operational event is claimed.
- The BPF map is limited to 4,096 exact IPv4 entries.
- The current program does not implement VLAN parsing, IPv6, CIDR matching, transport-layer matching, or counters.
- Toolchain and kernel header versions must be pinned and recorded before a reproducible release is claimed.
