# xdp-ingress-primitives

Linux XDP ingress filtering primitives for defensive packet handling.

## Responsibility

This repository is intended to provide small, auditable ingress-only packet parsing and filtering primitives, with explicit kernel, driver, verifier, and capability checks.

## Safety and failure behavior

- Scope is ingress packet handling only. No outbound scanning, exploitation, brute force, or counter-attack.
- `XDP_PASS` is pass-through to the normal networking stack. It is not fail-closed.
- Report enforcement as active only after successful attach and verification.
- Unsupported kernels, drivers, or capabilities must produce an explicit unavailable state without claiming protection.
- No silent fallback. Any alternate path requires explicit operator selection and independent tests.

## Current status

**Lifecycle: planned.** No eBPF program, loader, verifier result, kernel compatibility matrix, or test suite has yet been verified. See [COMPATIBILITY.json](COMPATIBILITY.json).
