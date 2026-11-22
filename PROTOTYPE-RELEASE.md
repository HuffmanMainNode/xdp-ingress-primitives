# Prototype Release Record

**Release stage:** Prototype candidate documentation complete  
**Lifecycle:** Prototype  
**Verified source commit:** `667a1fbda825a057a02c5f3ae92c4df01b11894d`  
**Evidence ceiling:** TIER-3  
**GitHub Release/tag:** Not published by this record

## Purpose

A small Linux XDP ingress-only IPv4 source-address filtering primitive, paired with an offline rule validator and deterministic map-update preview.

## Included capabilities

- Bounds-checked Ethernet IPv4 parsing.
- 4,096-entry exact-source IPv4 hash map.
- Only an exact configured source match with action value `1` returns `XDP_DROP`.
- Unsupported, malformed, non-IPv4, VLAN-tagged, unmatched, and other paths return `XDP_PASS`.
- Offline rule validation and map preview; no operator-facing loader or map updater.

## Verify locally

```sh
python3 -m pip install -r requirements-test.txt
python3 -m unittest discover -v
make
python3 xdp_rules.py validate rules.json
python3 xdp_rules.py compile rules.json
```

The BPF build requires Clang with the BPF target and Linux UAPI headers.

## Evidence

The recorded CI run passed 12 deterministic Python tests, BPF compilation, kernel verifier acceptance, synthetic program tests, and native driver-mode attach/detach with actual ICMP pass/drop/restore observations on an isolated veth pair: [workflow run](https://github.com/HuffmanMainNode/xdp-ingress-primitives/actions/runs/44978554223).

## Explicit limitations

`XDP_PASS` passes traffic to the normal networking stack. It is not fail-closed. The recorded datapath test used an isolated veth pair in a CI runner, not a physical NIC or production interface. No production loader, map updater, approval/rollback controller, broad kernel/driver matrix, IPv6, VLAN parsing, CIDR matching, port matching, counters, or rate limiting is included.

## Next milestone

Design a separately reviewed operator loader and map-update transaction with explicit pre-change state, approval, rollback, and post-change verification. Test across supported kernel and driver combinations before making deployment claims.

## Ecosystem context

Related public components:
- [cas-xdp-supervisor](https://github.com/HuffmanMainNode/cas-xdp-supervisor)
- [cas-threat-index](https://github.com/HuffmanMainNode/cas-threat-index)
- [posix-containment-kit](https://github.com/HuffmanMainNode/posix-containment-kit)
- [canary-labyrinth-httpd](https://github.com/HuffmanMainNode/canary-labyrinth-httpd)

This repository does not provide production interface management or integrated end-to-end enforcement.
