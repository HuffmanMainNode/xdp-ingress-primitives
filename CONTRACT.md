# CAS-XDP Shared Engineering Contract

**Canonical owner:** Private repository `HuffmanMainNode/HuffmanPlan-CASXDP-Master-Repo`  
**Contract version:** 1.0  
**Status:** Baseline adopted for Phase 0; implementation validation pending.

Every public repository in this ecosystem must carry a byte-identical copy of this contract at its root as `CONTRACT.md`, plus a root `COMPATIBILITY.json` instance validated against the shared schema at `schemas/compatibility.schema.json`. The master copy is authoritative. CI must detect drift.

## 1. Capability and negative-scope declaration

Each repository must declare exact supported operations and explicit non-goals. Supported capability categories may include read-only local audit, ingress packet filtering, local containment, HTTP canary observation, and artifact indexing.

The enforcement plane is ingress-only. Host inspection and containment are local-host operations. No repository may implement remote exploitation, outbound scanning, brute-force routines, counter-attack, retaliation, or unauthorized state changes.

**Narrow registry exception:** The artifact trust registry may retrieve a specifically identified artifact or metadata from an explicitly configured upstream source when an operator or consuming workflow authorizes that retrieval. This is not scanning. Retrieval must be bounded to declared URLs and immutable identifiers, must not execute retrieved content, and must be disabled unless explicitly configured. This exception does not grant outbound network capability to enforcement components.

## 2. Trust, provenance, and cryptographic pinning

A SHA-256 digest establishes byte integrity, not publisher identity or trust.

An externally sourced artifact record must include, where applicable:
- canonical upstream repository or publisher URL;
- immutable 40-character Git commit SHA for Git-sourced material;
- SPDX license identifier;
- SHA-256 digest of the exact artifact bytes;
- publisher signature using Ed25519 or a supported Sigstore/cosign verification flow;
- signer identity and verification result;
- revocation and trust status, including the source and observation time.

Mutable references such as `main`, `master`, and `latest` are not acceptable as artifact identity or release pins. Missing provenance must be represented as missing, never inferred or fabricated. Trust decisions must distinguish verified, unverified, rejected, revoked, and unknown.

## 3. Permission boundaries and staged containment

Read-only inspection must run unprivileged wherever technically possible and must not modify system state.

Every state-changing operation (including permissions, firewall rules, sockets, routes, interfaces, or processes) must use this seven-stage gate:

1. Inspect the current state.
2. Generate a change plan **and prepare a rollback snapshot**.
3. Display the proposed impact, affected resources, and rollback method.
4. Require explicit operator approval tied to the displayed plan.
5. Apply only the approved change.
6. Verify the resulting state against the intended state.
7. Record the outcome, evidence, and rollback snapshot reference.

Rollback material must be prepared before mutation. `--confirm` must never bypass inspection, plan display, or approval binding. Any plan change invalidates prior approval. Failures must stop further mutation and report partial application clearly.

## 4. Explicit failure and fallback behavior

Components must detect unsupported kernel features, capabilities, drivers, operating systems, and runtime facilities. They must report a precise unavailable or unsupported state without claiming protection.

`XDP_PASS` passes a packet onward to the normal networking stack. It is not a fail-closed action. No implementation may describe it as fail-closed.

The system must distinguish:
- enforcement active and verified;
- enforcement unavailable, with explicit diagnostic and no protection claim;
- an alternate fallback explicitly enabled by the operator and independently tested with documented security properties.

There must be no silent fallback and no disruption to existing connectivity merely because a capability check failed.

## 5. Evidence tier classification

All test reports, CI records, and operational claims must identify their evidence tier:

- `TIER-1`: Static build, lint, type, and schema validation.
- `TIER-2`: Deterministic unit tests.
- `TIER-3`: Kernel verifier or privileged subsystem tests (for example, a real `bpftool prog load` on a compatible test host).
- `TIER-4`: Cross-repository integration tests.
- `TIER-5`: Live operational observations from real events only.

Tests using fixtures or synthetic inputs must be labelled as tests. They must never be presented as live events. A test tier is not automatically a security certification.

## 6. Interoperability and schema contract

Cross-repository interfaces, including CLI arguments, JSON documents, MCP stdio JSON-RPC 2.0 tools, and STIX 2.1 exports, must be versioned and schema-validated.

The shared compatibility JSON Schema defines the shape of a manifest; each root `COMPATIBILITY.json` is an instance, not a schema. Agents and integrations must not infer undocumented flags, fields, tool names, or behavior.

## 7. Reproducible releases and dependency hygiene

- C/eBPF enforcement components must minimize runtime dependencies and pin or otherwise reproducibly identify build headers and toolchains.
- Python control-plane core must use the standard library for offline core operation. Optional protocol, schema, crypto, or platform dependencies must be explicit and pinned.
- Build dependencies, runtime dependencies, and optional dependencies must be listed separately.
- CI must be reproducible and must not silently fetch mutable dependencies during security-sensitive release steps.
- Releases must identify source commit, build inputs, test evidence, artifact digests, and signatures where supported.

## Implementation clarifications

- Platform and kernel support is **unverified until tested**. Manifests must use `planned`, `verified`, or `unsupported` states and cite evidence for verified claims.
- Linux `memfd_create`, file sealing, executable-memory policy, libc behavior, and crypto-library availability must be tested independently. Documentation must not promise physical-RAM exclusivity or complete erasure; memory wiping is best-effort and must describe its limits.
- A license choice is repository-specific. Existing licenses must not be silently changed. The current ecosystem has both MIT and Apache-2.0 initializations; this mixed baseline is recorded for owner review.
- A public repository must not claim completion merely because its documentation or manifest exists.
