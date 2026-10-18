# CashNova Protocol: Patent Claim-to-Code Mapping & Verification Record

**Tag**: v0.1.0-alpha
**Commit**: a77eef56a2f8fa1b43c3dd53345313e7338f09d5
**Timestamp**: 2026-10-18T19:39:07.381Z

## 1. Machine Verification Summary
- **Protocol State**: ALL 5 SCHEMAS MACHINE-VALIDATED ACROSS 3 SERVICES
- **Binary Schemas**: 5 Canonical Records (42B Manifest, 192B Envelope, 56B Source Prepare, 80B Dest Prepare, 90B Decision Cert)
- **State Guarantee**: Zero Double-Spend across autonomous domain authorities

## 2. Claim Dependency Matrix

| Patent Claim Element | Specification & Code File | Machine Invariant / Test Verification |
| :--- | :--- | :--- |
| **Deterministic Record Canonicalization** | `shared/records.js` (`serialize*` & `deserialize*`) | Enforces fixed-byte offsets and deterministic Big-Endian scalar packing without JSON overhead. |
| **Authority Firewall (Predecessor Invalidation)** | `source-domain/server.js` (`/finalize`) | Confirmed on disk: Predecessor `CPT-ROOT-001` transitions irreversibly to `CONSUMED`. |
| **Anti-Branching Guarantee** | `dest-domain/server.js` (`/finalize`) & `shared/storage.js` | Enforced by SQLite `finalized_successor_index` unique index. Adversarial duplicate attempt trapped with HTTP `409 ERR_PARENT_CERT_ALREADY_FINALIZED`. |
| **Asymmetric Multi-Domain Handshake** | `tests/verify_protocol.js` & `shared/protocol.js` | Ed25519 signing across independent service instances (`source:8001`, `dest:8002`, `decision:8003`). |

## 3. Verified Ledger Invariant Snapshot
```json
{
  "timestamp": "2026-10-18T19:34:41.657Z",
  "source_ledger": [
    {
      "id": "CPT-ROOT-001",
      "state": "CONSUMED",
      "denom": 100000,
      "generation": 1,
      "locked_tx_id": null
    }
  ],
  "destination_ledger": [
    {
      "id": "CPT-SUCC-001",
      "state": "FINAL",
      "denom": 25000,
      "generation": 2,
      "parent_cert_hash": "7777777777777777777777777777777777777777777777777777777777777777"
    }
  ],
  "successor_index": [
    {
      "parent_cert_hash": "7777777777777777777777777777777777777777777777777777777777777777",
      "successor_id": "CPT-SUCC-001",
      "transition_id": "01010101010101010101010101010101"
    }
  ]
}
```
