# CashNova Protocol Core

Machine-verified, cross-domain digital currency settlement protocol featuring strict cryptographic state handoffs, predecessor consumption via Authority Firewall, and deterministic anti-branching guarantees.

## Verification Status
- **Current Milestone**: v0.1.0-alpha
- **Specification Engine**: 5-record canonical binary schema (42B Manifest, 192B Envelope, 56B Source Prepare, 80B Dest Prepare, 90B Decision Cert)
- **Multi-Service Verification**: PASS across source-domain, dest-domain, and decision-svc
- **Authority Firewall**: Predecessors irreversibly transitioned to CONSUMED
- **Double-Spend Protection**: Duplicate parent certificate finalization blocked via SQLite unique indexing (409 ERR_PARENT_CERT_ALREADY_FINALIZED)

## Running the Multi-Process Verification Suite
```bash
rm -f db/*.sqlite* && node tests/verify_protocol.js
```

## Diligence & Patent Mapping
Formal claim-to-code alignments and ledger invariant snapshots are tracked in cashnova-diligence/CLAIM_TO_CODE_MAPPING.md.
