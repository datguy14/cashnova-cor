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

      if (req.method === 'POST' && url.pathname === '/decide') {
        const envBytes = unhex(json.envelopeHex);
        const envelopeHash = await CryptoEngine.sha256(envBytes);
        const env = CanonicalRecords.deserializeEnvelope(envBytes);
        const envHash = await CryptoEngine.sha256(envBytes);
        const txIdHex = hex(env.transitionId);

        if (decisionsByTx.has(txIdHex)) {
          const rec = await decisionsByTx.get(txIdHex);
          return send(200, {
            ok: true,
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
          outcome: json.outcome,
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
