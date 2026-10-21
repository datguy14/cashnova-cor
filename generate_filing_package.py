import os
import hashlib

md_content = """# UNITED STATES UTILITY NON-PROVISIONAL PATENT APPLICATION FILING PACKAGE

**Docket Number:** CN-2026-001-UTIL  
**Application Type:** Utility Non-Provisional Patent Application under 35 U.S.C. § 111(a)  
**Domestic Priority Claim:** 35 U.S.C. § 119(e) to U.S. Provisional Application No. 64/164,630  
**Title:** System and Method for Certificate-Gated Transformation of Authoritative Monetary State Across Independent Consensus Jurisdictions Using Denomination-Driven Successor Mapping  
**Inventor:** Charles Ronald Locklear Jr.  
**Execution Date:** October 19, 2026  

---

## COMPONENT 1: PATENT ASSIGNMENT & TRANSFER OF RIGHTS

**PATENT ASSIGNMENT AGREEMENT**

**WHEREAS**, I, **Charles Ronald Locklear Jr.**, residing in Laurinburg, North Carolina (hereinafter referred to as the "ASSIGNOR"), have invented certain new and useful improvements in:

> **SYSTEM AND METHOD FOR CERTIFICATE-GATED TRANSFORMATION OF AUTHORITATIVE MONETARY STATE ACROSS INDEPENDENT CONSENSUS JURISDICTIONS USING DENOMINATION-DRIVEN SUCCESSOR MAPPING**

for which an application for United States Non-Provisional Letters Patent is being executed concurrently herewith, claiming benefit of U.S. Provisional Application Serial No. **64/164,630**; and

**WHEREAS**, **[ASSIGNOR / LEGAL ENTITY NAME]**, having an address at **[BUSINESS ADDRESS]** (hereinafter referred to as the "ASSIGNEE"), is desirous of acquiring the entire right, title, and interest in and to said inventions and patent applications;

**NOW, THEREFORE**, for good and valuable consideration, the receipt and sufficiency of which are hereby acknowledged, ASSIGNOR does hereby sell, assign, transfer, and convey unto ASSIGNEE, its successors, and assigns, the entire right, title, and interest throughout the United States and all foreign countries in and to:
1. Said inventions and improvements as disclosed in U.S. Provisional Application No. 64/164,630 and the non-provisional application executed concurrently herewith;
2. All Letters Patent that may be granted thereon, and all divisions, continuations, continuations-in-part, reissues, reexaminations, and extensions thereof;
3. The right to invoke and claim the benefit of priority under the Paris Convention, the Patent Cooperation Treaty (PCT), and 35 U.S.C. § 119 and § 120; and
4. All causes of action and rights to sue and recover for past, present, and future infringements thereof.

**ASSIGNOR COVENANTS** to execute, acknowledge, and deliver any further instruments, oaths, declarations, or documents necessary to enable ASSIGNEE to secure and protect all rights conveyed herein.

**IN WITNESS WHEREOF**, ASSIGNOR has executed this Assignment on the date set forth below.


___________________________________________  
**Charles Ronald Locklear Jr.** (Inventor / Assignor)  
Date: October 19, 2026  

**STATE OF NORTH CAROLINA**  
**COUNTY OF SCOTLAND**  

On this 19th day of October, 2026, before me, the undersigned notary public, personally appeared Charles Ronald Locklear Jr., known to me to be the person described in and who executed the foregoing assignment, and acknowledged that he executed the same as his free act and deed.


___________________________________________  
Notary Public, State of North Carolina  
My Commission Expires: ____________________  

---

## COMPONENT 2: UNIFIED CLAIM MATRIX & EXAMINATION CHART

| Claim # | Claim Type & Hierarchy | Subject Matter Limitation | Provisional Support (64/164,630) | Prior Art Differentiation & Rebuttal Scope |
| :--- | :--- | :--- | :--- | :--- |
| **Claim 1** | **Independent System** | Distributed state machine for cross-jurisdiction token migration; dual validators; denomination engine ($D_s = D_p - R$); authenticated mapping manifest; predecessor lock; conditional successor reservation; certificate processor; independent local finality. | **¶¶ 243–286, 310–326, 346–362** (Processor, mapping, successor generation, lock/consume states, cross-jurisdiction certificate). | Distinguishes **Guardtime** and **HSBC** by routing across independent consensus regimes using denomination intervals rather than internal shard IDs. Distinguishes **Ripple** by barring the coordinator from ledger authority. |
| **Claim 2** | **Independent Method** | Method for migrating redeemability authority: lock predecessor, verify mapping manifest, issue atomicity certificate upon dual prepare evidence, terminal consumption at source, conditional activation at destination. | **¶¶ 243–286, 346–362, 364–378** (Method steps, state transitions, prepare/decision phases). | Defeats § 101 rejections via concrete state-machine transformations (`ACTIVE` -> `LOCKED` -> terminal `CONSUMED`) that prevent delayed rollback reactivation. |
| **Claim 3** | **Independent Apparatus** | Standalone certificate verification apparatus: receives certificate, validates transcript bindings, checks mapping manifest against denomination, validates consensus evidence, outputs local authorization. | **¶¶ 274–279, 346–362** (Independent verification without holding native ledger authority). | Protects validator-node implementations and HSMs running local verification logic independently of coordinating nodes. |
| **Claim 4** | **Independent Method (Lineage)** | Non-branching cryptographic lineage: successor creation requires parent atomicity certificate, generation counter ($G + 1$), and rejects duplicate finalized successors for parent/transition. | **¶¶ 380–415** (Hash-linked multi-generation lineage and anti-branching structures). | Standalone patentability independent of denomination routing; prevents double-issue branches in off-chain or asynchronous environments. |
| **Claim 5** | **Independent Method (Recovery)** | Crash and expiry recovery: detecting time past `expiryEpoch`, selecting exactly one of abort or completion, mutually exclusive terminal finalization. | **¶¶ 364–378** (In-flight transition tracking and rollback/completion branches). | Solves liveness boundaries without leaving dangling unreserved commitments. |
| **Claims 6–10** | Dependent (Claim 1) | Ledger formats (channels, rollups, clearing networks), canonical manifest hashing, Merkle proofs, threshold/governance signatures, canonical precision parameters. | **¶¶ 346–362, 380–415** | Establishes fallback positions for cryptographic transcript integrity. |
| **Claims 11–17** | Dependent (Claim 1) | Lock sequence numbers, dual-evidence conditions, domain-separated canonical serialization, authority rejection rules. | **¶¶ 346–362** | Secures implementation details against replay and cross-type message attacks. |
| **Claims 18–28** | Dependent (Claim 1) | Three-state source/dest machines (`CONSUMED`, `CONDITIONALLY_AUTHORIZED`), conservation verification ($D_p = R + D_s$), zero-knowledge interval proofs. | **¶¶ 310–326, 380–415** | Explicit technical barriers to Alice/Mayo abstract-idea assertions. |
| **Claims 57–60** | Dependent (Claims 1 & 2) | Append-only WAL persistence, synchronous `fsync` flush prior to in-memory mutation, deterministic restart replay of `MINT`, `LOCK`, `CONSUME`, `UNLOCK`. | Narrow fallback (New matter analysis required per § 10.5). | Provides direct literal infringement capture for database engine and node implementations. |
| **Claims 61–62** | Dependent (Claim 1) | Fixed-width 192-byte binary envelope layout, exact byte offsets (`0x00` through `0xC0`), big-endian integers, zero-padded ASCII domain tags. | Narrow fallback (New matter analysis required per § 10.5). | Exact hardware/firmware execution lock-in. |

---

## COMPONENT 3: INFORMATION DISCLOSURE STATEMENT (IDS)

1. **U.S. Patent Application Publication No. 2022/0284129 A1**  
   * Applicant: Guardtime SA  
   * Pub. Date: September 8, 2022  
   * Title: *Verifiable Splitting of Single-Instance Data Using Sharded Blockchain*  
   * Relevance: Discloses logical data unit splitting and transfer across sharded ledgers.
2. **International Publication No. WO 2024/011707 A1**  
   * Applicant: HSBC Group  
   * Pub. Date: January 18, 2024  
   * Title: *Blockchain Transaction Sharding for Improved Transaction Throughput*  
   * Relevance: Discloses token routing to shard controllers via lookup mapping.
3. **U.S. Patent No. 10,878,410 B2**  
   * Assignee: Ripple Labs Inc.  
   * Pub. Date: December 29, 2020  
   * Title: *Inter-Ledger Protocol (ILP) and Cross-Chain Clearing*  
   * Relevance: Discloses escrow-backed cross-ledger transfers using cryptographic conditions.
4. **U.S. Patent Application Publication No. 2021/0027294 A1**  
   * Applicant: nChain Holdings Ltd.  
   * Pub. Date: January 28, 2021  
   * Title: *Computer-Implemented System and Method for Atomic Swaps*  
   * Relevance: Discloses cross-chain asset atomic exchange mechanisms.

---

## COMPONENT 4: EXHIBIT C – ACTUAL REDUCTION TO PRACTICE MANIFEST

* **Artifact Description:** Cryptographic checksum ledger and state invariant dump demonstrating multi-process protocol verification.
* **Local Package Path:** `/sdcard/Download/cashnova-v0.1.0-diligence-package.tar.gz`
* **Verified SHA-256 Digest:** `2ee52b93c5caf5b07d8d2cdcd927e9a33a54fb02583614a6191e52979224ee0f`
* **Repository Origin & Tag:** `https://github.com/datguy14/cashnova-cor.git` at tag `v0.1.0-alpha` (Commit: `631569b`)
* **Formal Verification Correspondence:**
  * TLA+ Safety Invariant Model: `formal/CashNova.tla` (18 distinct states, depth 6, verified deadlock-free).
  * Prototype Integration Test: 9 passed automated invariant tests (`tests/verify_protocol.js`, `tests/cluster.test.cjs`).
"""

out_dir = "/sdcard/Download"
md_path = os.path.join(out_dir, "CashNova_NonProvisional_Filing_Package.md")
html_path = os.path.join(out_dir, "CashNova_NonProvisional_Filing_Package.html")

with open(md_path, "w", encoding="utf-8") as f:
    f.write(md_content)

html_template = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>CashNova Patent Filing Package</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; padding: 30px; max-width: 900px; margin: auto; color: #24292e; }}
  table {{ border-collapse: collapse; width: 100%; margin: 20px 0; font-size: 13px; }}
  th, td {{ border: 1px solid #dfe2e5; padding: 8px 12px; text-align: left; }}
  th {{ background-color: #f6f8fa; font-weight: 600; }}
  tr:nth-child(even) {{ background-color: #fafbfc; }}
  blockquote {{ border-left: 4px solid #dfe2e5; color: #6a737d; padding: 0 1em; margin: 15px 0; }}
  h1, h2, h3 {{ border-bottom: 1px solid #eaecef; padding-bottom: .3em; }}
  code {{ background-color: #f6f8fa; padding: 0.2em 0.4em; border-radius: 3px; font-family: monospace; font-size: 85%; }}
</style>
</head>
<body>
<pre style="white-space: pre-wrap; font-family: inherit;">{md_content}</pre>
</body>
</html>"""

with open(html_path, "w", encoding="utf-8") as f:
    f.write(html_template)

print(f"Successfully generated downloadable files:")
print(f"1. Markdown: {md_path}")
print(f"2. HTML Document: {html_path}")
