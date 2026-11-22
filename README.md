# xdp-ingress-primitives

Small Linux XDP ingress-only IPv4 source-address filtering primitive.

## Current prototype

The repository contains:
- `xdp_ingress.c`: a minimal XDP program with a 4,096-entry IPv4 source-address deny map.
- `xdp_rules.py`: standard-library rule validation and deterministic map-update preview.
- `schemas/ingress-rules.schema.json`: versioned v1.0 rule document.
- A local build target and CI compile check.

The program drops a packet only when it is an Ethernet IPv4 frame and its exact source IPv4 address is present in `deny_src_ipv4` with action value `1`. All other traffic returns `XDP_PASS`.

**`XDP_PASS` passes the packet to the normal networking stack. It is not fail-closed.**

## Rule document

Example `rules.json` using a documentation-only TEST-NET address:

```json
{
  "schema_version": "1.0",
  "rules": [
    {
      "id": "deny-documentation-address",
      "source_ipv4": "198.51.100.10",
      "action": "drop"
    }
  ]
}
```

Validate and preview exact map key/value bytes:

```sh
python3 xdp_rules.py validate rules.json
python3 xdp_rules.py compile rules.json
```

The compiler emits the four source-address bytes in network byte order and value byte `01`. It does not update a BPF map, load an object, attach to an interface, or change host networking.

## Build

Requires Clang with the BPF target and Linux UAPI headers:

```sh
make
```

This produces `xdp_ingress.o`. The repository does not include an operator-facing loader, map updater, approval/rollback controller, or production interface manager. CI separately loads the object into an ephemeral runner, tests it with synthetic packets, and attaches/detaches it in driver mode on an isolated veth pair in separate network namespaces. That CI test is not a production deployment workflow.

## Packet behavior and limits

- Ethernet IPv4 frames are parsed with bounds checks.
- Exact source IPv4 matches with map value `1` return `XDP_DROP`.
- IPv6, VLAN-tagged frames, non-IPv4 frames, malformed or truncated headers, missing map entries, and unrecognized map values return `XDP_PASS`.
- No CIDR matching, port matching, connection tracking, rate limiting, counters, loader, map updater, or automatic interface attachment is implemented.
- No unsupported-state fallback is described as protection.

## Verification

```sh
python3 -m pip install -r requirements-test.txt
python3 -m unittest discover -v
```

CI validates the shared contract, rule schema, 12 deterministic tests across Python 3.9 through 3.13, and BPF object compilation with Clang 18.1.3. An ephemeral Ubuntu 24.04 job loads the object into the kernel verifier, tests synthetic packets with bpftool 7.7.0, then attaches/detaches it on an isolated veth pair and checks actual ICMP pass/drop/restore behavior. No physical NIC or production interface is used.

See [SECURITY.md](SECURITY.md) and [CONTRACT.md](CONTRACT.md).

## Prototype release record

See [PROTOTYPE-RELEASE.md](PROTOTYPE-RELEASE.md) for the verified source commit, evidence ceiling, supported prototype scope, limitations, and next milestone. This document stages a prototype handoff; it does not create a GitHub Release or claim production readiness.
