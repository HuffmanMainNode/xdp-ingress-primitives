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

This produces `xdp_ingress.o`. Compilation does not load or attach the program. Loading, map updates, interface attachment, detach, and live enforcement are intentionally not implemented in this prototype.

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

CI validates the shared contract, rule schema, deterministic tests, and BPF object compilation. CI compilation is not kernel verifier or live attach evidence.

See [SECURITY.md](SECURITY.md) and [CONTRACT.md](CONTRACT.md).
