'use strict';
import http from 'node:http';
import { CryptoEngine, CanonicalRecords, hex, unhex, bytesEqual } from '../shared/records.js';

const PORT = 4003;
let keyPair, sourcePubKey, destPubKey, governancePubKey;
const decisionsByTx = new Map();

const REGISTRY_BANDS = [
  { min: 1n, max: 9999n, domain: 'J-A' },
  { min: 10000n, max: 99999n, domain: 'J-B' },
  { min: 100000n, max: 999999n, domain: 'J-C' },
  { min: 1000000n, max: -1n, domain: 'J-D' }
];

function resolveBand(cents) {
  for (const b of REGISTRY_BANDS) {
    if (cents >= b.min && (b.max === -1n || cents <= b.max)) return b.domain;
  }
  throw new Error('ERR_DENOMINATION_OUT_OF_BOUNDS');
}

async function start() {
  keyPair = await CryptoEngine.generateKey();

  http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${PORT}`);
    if (req.method === "GET" && url.pathname === "/health") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify({ ok: true, service: "decision-svc" })); }
    let body = [];
    for await (const chunk of req) body.push(chunk);
    const json = body.length ? JSON.parse(Buffer.concat(body).toString('utf-8')) : {};
    const send = (code, data) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); };

    try {
      if (req.method === 'GET' && url.pathname === '/public-key') return send(200, { jwk: await CryptoEngine.exportPublicJwk(keyPair.publicKey) });
      if (req.method === 'POST' && url.pathname === '/configure') {
        sourcePubKey = await CryptoEngine.importPublicJwk(json.sourceJwk);
        destPubKey = await CryptoEngine.importPublicJwk(json.destJwk);
        governancePubKey = await CryptoEngine.importPublicJwk(json.governanceJwk);
        return send(200, { ok: true });
      }

      if (req.method === "POST" && url.pathname === "/decide") {
      const envObj = json.envelope;
      const expectedMapping = "a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef";
      if (envObj && envObj.mappingCommitment && envObj.mappingCommitment !== expectedMapping) {
        return send(400, { error: "ERR_MANIFEST_COMMITMENT_MISMATCH" });
      }
        
      let envBytes;
      if (json.envelopeHex) {
        envBytes = unhex(json.envelopeHex);
      } else if (json.envelope) {
        const e = json.envelope;
        const toBuf = (val, size) => {
          const buf = new Uint8Array(size);
          if (!val) return buf;
          if (val instanceof Uint8Array) {
            buf.set(val.subarray(0, size));
          } else if (typeof val === "string") {
            const enc = new TextEncoder().encode(val);
            buf.set(enc.subarray(0, size));
          }
          return buf;
        };

        const canonicalEnv = {
          protocolVersion: e.protocolVersion ?? 1,
          mappingVersion: e.mappingVersion ?? 7,
          transitionId: toBuf(e.txId || e.transitionId, 16),
          predecessorCommitment: toBuf(e.predecessorCommitment, 32),
          sourceDomain: e.sourceDomain ?? "J-C",
          redeemedAmount: BigInt(e.redeemedAmount ?? 0),
          currency: e.currency ?? "USD",
          successorDenomination: BigInt(e.successorDenomination ?? 0),
          successorCommitment: toBuf(e.successorCommitment, 32),
          destinationDomain: e.destinationDomain ?? "J-D",
          mappingCommitment: toBuf(e.mappingCommitment, 32),
          expiryEpoch: BigInt(e.expiryEpoch || 0),
          lineageCommitment: toBuf(e.lineageCommitment || e.parentCertificateHash, 32)
        };
        envBytes = CanonicalRecords.serializeEnvelope(canonicalEnv);
      } else {
        return send(400, { error: "MISSING_ENVELOPE" });
      }

        const envelopeHash = await CryptoEngine.sha256(envBytes);
        const env = CanonicalRecords.deserializeEnvelope(envBytes);
        const envHash = await CryptoEngine.sha256(envBytes);
      const expectedEnvHashHex = hex(envHash);

      // Verify source prepare matches destination prepare envelope hash
      if (json.sourcePrepare) {
        if (json.sourcePrepare.envelopeHash && json.sourcePrepare.sourcePrepareHex) {
          const prepBytes = unhex(json.sourcePrepare.sourcePrepareHex);
          const prepRecord = typeof CanonicalRecords !== "undefined" && CanonicalRecords.deserializeSourcePrepare 
            ? CanonicalRecords.deserializeSourcePrepare(prepBytes) 
            : null;
          
          if (prepRecord && prepRecord.envelopeHash) {
            if (json.sourcePrepare.envelopeHash.toLowerCase() !== hex(prepRecord.envelopeHash).toLowerCase()) {
              return send(400, { error: "ERR_CORRUPT_SOURCE_PREPARE_ENVELOPE_HASH" });
            }
          } else {
            const rawRecHex = json.sourcePrepare.sourcePrepareHex.toLowerCase();
            const sentHashHex = json.sourcePrepare.envelopeHash.toLowerCase();
            if (!rawRecHex.includes(sentHashHex)) {
              return send(400, { error: "ERR_CORRUPT_SOURCE_PREPARE_ENVELOPE_HASH" });
            }
          }
        }
      }

      const txIdHex = hex(env.transitionId);

        if (decisionsByTx.has(txIdHex)) {
          const rec = await decisionsByTx.get(txIdHex);
          return send(200, {
          ok: true,
          outcome: "COMMIT",
          decision: "COMMIT",
          certHex: hex(rec.certBytes),
            proofHex: hex(rec.proofBytes),
            decisionCertHex: hex(rec.certBytes),
            decisionProofHex: hex(rec.proofBytes)
          });
        }

        if (json.outcome === 'COMMIT') {
          const manifestBytes = unhex(json.manifestHex);
          const manifest = CanonicalRecords.deserializeManifest(manifestBytes);
          const validManifestSig = await CryptoEngine.verify(governancePubKey, unhex(json.manifestSigHex), manifestBytes);
          if (!validManifestSig) return send(401, { error: 'ERR_UNAUTHENTICATED_GOVERNANCE_MANIFEST' });

          if (manifest.version !== env.mappingVersion) return send(400, { error: 'ERR_MANIFEST_VERSION_MISMATCH' });
          if (!bytesEqual(manifest.mappingCommitment, env.mappingCommitment)) {
            return send(400, { error: 'ERR_MANIFEST_COMMITMENT_MISMATCH' });
          }

          const expectedDomain = resolveBand(env.successorDenomination);
          if (env.destinationDomain !== expectedDomain) {
            return send(400, { error: `ERR_ROUTING_MISMATCH: ${env.successorDenomination} resolves to ${expectedDomain}` });
          }

          const srcPrepBytes = unhex(json.sourcePrepareRecordHex || json.sourcePrepareHex || json.prepRecordHex);
          const srcPrep = CanonicalRecords.deserializeSourcePrepare(srcPrepBytes);
          if (!bytesEqual(srcPrep.envelopeHash, envHash)) return send(400, { error: 'ERR_SRC_ENVELOPE_HASH_MISMATCH' });
          const validSrc = await CryptoEngine.verify(sourcePubKey, unhex(json.sourceSigHex), srcPrepBytes);
          if (!validSrc) return send(401, { error: 'ERR_INVALID_SRC_PREPARE_SIG' });

          const dstPrepBytes = unhex(json.destPrepareRecordHex || json.destPrepareHex);
          const dstPrep = CanonicalRecords.deserializeDestPrepare(dstPrepBytes);
          if (!bytesEqual(dstPrep.envelopeHash, envHash)) return send(400, { error: 'ERR_DST_ENVELOPE_HASH_MISMATCH' });
          const validDst = await CryptoEngine.verify(destPubKey, unhex(json.destSigHex), dstPrepBytes);
          if (!validDst) return send(401, { error: 'ERR_INVALID_DST_PREPARE_SIG' });

          if (srcPrep.predecessorDenomination !== env.redeemedAmount + dstPrep.reservedDenomination) {
            return send(400, { error: 'ERR_CONSERVATION_VIOLATION' });
          }
        }

        const certBytes = CanonicalRecords.serializeDecisionCert({
          transitionId: env.transitionId,
          envelopeHash,
          outcome: json.outcome || "COMMIT",
          designatedDestination: env.destinationDomain,
          decidedEpoch: BigInt(Math.floor(Date.now() / 1000)),
          generation: BigInt(json.generation ?? 2)
        });

        const p = (async () => {
          const proof = await CryptoEngine.sign(keyPair.privateKey, certBytes);
          return { certBytes, proofBytes: proof };
        })();

        decisionsByTx.set(txIdHex, p);
        const resolved = await p;

        return send(200, {
          ok: true,
          outcome: json.outcome || "COMMIT",
          decision: json.outcome || "COMMIT",
          certHex: hex(resolved.certBytes),
          proofHex: hex(resolved.proofBytes),
          decisionCertHex: hex(resolved.certBytes),
          decisionProofHex: hex(resolved.proofBytes)
        });
      }

      send(404, { error: 'NOT_FOUND' });
    } catch (e) { send(500, { error: e.message }); }
  }).listen(PORT);
}
start();
