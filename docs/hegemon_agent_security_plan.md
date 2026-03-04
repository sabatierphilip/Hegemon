# Hegemon Agent Security Plan (Phases 1-9)

## Implemented baseline (strengthened Phase 1-7 + concrete Phase 9)

Hegemon Agent now implements an integrated security baseline: robust userland telemetry/signing (Phase 1-2), signed WASM admission and policy gating (Phase 3), kernel-adjacent safe telemetry vectors (Phase 4), secure update verification scaffolding (Phase 5), quorum/causality/transparency control-plane checks (Phase 6), capability-matrix based containment governance (Phase 7), and adaptive persistent runtime capabilities with dual approval + revocation lifecycle (Phase 9).

## Threat model
- Local privilege escalation.
- Network MITM.
- Supply-chain compromise of modules/updates.
- Insider misuse of operator credentials.
- Physical access to endpoint storage.

## Assets
- Agent private key + control trust roots.
- Human approval secret/HMAC material.
- Containment orders and quorum signatures.
- WASM manifest signatures and capability registry.
- Signed append-only local ledger and transparency decisions.

## Security assumptions
- TPM may be absent (software fallback used with explicit risk signaling).
- Clock skew bounded for freshness checks.
- Quorum and trust roots are correctly provisioned.
- BCC/ETW collectors may degrade to safe fallback mode.

## Goals
- Fail-closed cryptographic verification for control actions.
- Persistent, auditable, revocable runtime capability growth.
- Safe kernel-adjacent visibility without custom kernel driver attack surface.
- Update integrity verification before binary replacement.

## Non-goals
- Offensive behavior.
- Custom kernel driver development.
- Guaranteeing integrity under fully compromised firmware/kernel.

## Architecture (text)
```
[Control Plane]
  |- signed orders (N-of-M quorum)
  |- signed module/update approvals
  |- dashboard settings + transparency service
      |
      v
[Hegemon Agent]
  |- Phase 1-2 telemetry/signing/key storage baseline
  |- Phase 3 signed WASM admission
  |- Phase 4 kernel-adjacent telemetry manager
  |- Phase 5 secure update verifier/scaffold
  |- Phase 6 order verifier + transparency publisher
  |- Phase 7 containment capability matrix
  |- Phase 9 persistent capability registry + revocation
  |- Signed append-only local ledger
```

## Minimum security requirements (implemented)
- Signed telemetry envelopes and signed containment verification.
- Quorum validation with unique signer counting.
- Human HMAC binding and freshness checks.
- Checkpoint causality checks against ledger continuity.
- Signed module and signed kernel-program admission checks.
- Signed update manifest/checksum/fingerprint verification scaffold.
- Phase 9 dual-approval module install, persistent registry, revocation + broadcast logging.

## Validation strategy
- Unit tests for phase 4/5/6/7/9 failure and success paths.
- Syntax compilation checks for all security modules.
- Red-team style assertions for replay/stale/quorum bypass/unauthorized capability paths.
