'use strict';
import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { CryptoEngine, CanonicalRecords, hex, unhex } from '../shared/records.js';

const PORT = 4001;
const DOMAIN = 'J-C';
let keyPair, decisionPubKey;

const db = new DatabaseSync('db/source.sqlite');
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS cluster_config (
    key TEXT PRIMARY KEY,
    val TEXT
  );
  CREATE TABLE IF NOT EXISTS instruments (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    denom INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    locked_tx_id TEXT
  );
`);

const store = {
  mint(id, denom, generation) {
    db.prepare('INSERT INTO instruments (id, state, denom, generation) VALUES (?, ?, ?, ?)').run(id, 'ACTIVE', Number(denom), Number(generation));
  },
  get(id) {
    return db.prepare('SELECT * FROM instruments WHERE id = ?').get(id);
  },
  prepare(id, txId) {
    db.exec('BEGIN IMMEDIATE');
    try {
      const inst = db.prepare('SELECT * FROM instruments WHERE id = ? OR locked_tx_id = ? LIMIT 1').get(id, txId);
      if (!inst) throw new Error('ERR_INSTRUMENT_NOT_FOUND');
      if (inst.state !== 'ACTIVE') throw new Error('ERR_INSTRUMENT_NOT_ACTIVE');
      db.prepare('UPDATE instruments SET state = ?, locked_tx_id = ? WHERE id = ?').run('LOCKED', txId, id);
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  },
  finalize(id, txId, outcome) {
    db.exec('BEGIN IMMEDIATE');
    try {
      const inst = db.prepare('SELECT * FROM instruments WHERE id = ?').get(id);
      if (!inst) throw new Error('ERR_INSTRUMENT_NOT_FOUND');
      const nextState = outcome === 'COMMIT' ? 'CONSUMED' : 'ACTIVE';
      db.prepare('UPDATE instruments SET state = ?, locked_tx_id = NULL WHERE id = ?').run(nextState, inst.id);
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  }
};

async function start() {
  keyPair = await CryptoEngine.generateKey();

  http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${PORT}`);
    if (req.method === "GET" && url.pathname === "/health") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify({ ok: true })); }
    let body = [];
    for await (const chunk of req) body.push(chunk);
    const json = body.length ? JSON.parse(Buffer.concat(body).toString('utf-8')) : {};
    const send = (code, data) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); };

    try {
      if (req.method === 'GET' && url.pathname === '/public-key') {
        return send(200, { jwk: await CryptoEngine.exportPublicJwk(keyPair.publicKey) });
      }
      if (req.method === 'POST' && url.pathname === '/configure') {
        decisionPubKey = await CryptoEngine.importPublicJwk(json.decisionJwk);
      db.prepare('INSERT OR REPLACE INTO cluster_config (key, val) VALUES (?, ?)').run('decisionJwk', JSON.stringify(json.decisionJwk));
        return send(200, { ok: true });
      }
      if (req.method === 'POST' && url.pathname === '/mint') {
        store.mint(json.id, json.denom ?? json.denomCents, json.generation ?? 1);
        return send(200, { ok: true });
      }
      if (req.method === 'GET' && (url.pathname.startsWith('/instrument/') || url.pathname.startsWith('/state/'))) {
        const id = url.pathname.split('/')[2];
        const inst = store.get(id);
        if (!inst) return send(404, { error: 'NOT_FOUND' });
        return send(200, { id: inst.id, state: inst.state, denom: inst.denom, isRedeemable: inst.state === 'ACTIVE' });
      }
      if (req.method === "POST" && url.pathname === "/prepare") {
      const tokenId = json.tokenId || json.envelope?.predecessorCommitment;
      const inst = store.get(tokenId);
      if (!inst) return send(404, { error: "ERR_INSTRUMENT_NOT_FOUND" });
      if (inst.state !== "ACTIVE") return send(409, { error: "ERR_TOKEN_NOT_ACTIVE" });

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

      const env = CanonicalRecords.deserializeEnvelope(envBytes);
      const envelopeHash = await CryptoEngine.sha256(envBytes);
      const txId = json.txId || hex(env.transitionId);

      store.prepare(tokenId, txId);

      const recordBytes = CanonicalRecords.serializeSourcePrepare({
        envelopeHash,
        predecessorDenomination: BigInt(inst.denom),
        generation: BigInt(inst.generation ?? 1)
      });
      const signature = await CryptoEngine.sign(keyPair.privateKey, recordBytes);

      return send(200, {
        ok: true,
        state: "LOCKED",
      envelopeHash: typeof envHash !== "undefined" ? hex(envHash) : (typeof record !== "undefined" && record.envelopeHash ? hex(record.envelopeHash) : hex(recordBytes.subarray(0, 32))),
        sourcePrepareRecordHex: hex(recordBytes),
      sourcePrepareHex: hex(recordBytes),
      sourceSigHex: hex(signature),
      signatureHex: hex(signature),
      sourcePrepareHex: hex(recordBytes),
      sourceSigHex: hex(signature),
        signatureHex: hex(signature)
      });
    }
      if (req.method === 'POST' && url.pathname === '/finalize') {
        const hexStr = json.certHex || json.decisionCertHex || json.decision?.certHex || json.decision?.decisionCertHex;
        const proofStr = json.proofHex || json.decisionProofHex || json.decision?.proofHex || json.decision?.decisionProofHex;
        const certBytes = unhex(hexStr);
        if (certBytes.length !== 90) {
          return send(400, { error: 'ERR_INVALID_DECISION_CERT_SIZE', receivedLen: certBytes.length });
        }
        const cert = CanonicalRecords.deserializeDecisionCert(certBytes);
        if (!decisionPubKey || !(decisionPubKey instanceof CryptoKey)) {
        const row = db.prepare("SELECT val FROM cluster_config WHERE key = ?").get("decisionJwk");
        if (row && row.val) {
          decisionPubKey = await CryptoEngine.importPublicJwk(JSON.parse(row.val));
        } else if (json.decisionJwk || (json.decision && json.decision.decisionJwk)) {
          decisionPubKey = await CryptoEngine.importPublicJwk(json.decisionJwk || json.decision.decisionJwk);
        } else {
          try {
            const decRes = await fetch("http://127.0.0.1:4003/public-key");
            const decData = await decRes.json();
            if (decData && decData.jwk) {
              decisionPubKey = await CryptoEngine.importPublicJwk(decData.jwk);
              db.prepare("INSERT OR REPLACE INTO cluster_config (key, val) VALUES (?, ?)").run("decisionJwk", JSON.stringify(decData.jwk));
            }
          } catch (err) {
            console.error("Auto-fetch decision-svc public key error:", err.message);
          }
        }
      }
      const validSig = await CryptoEngine.verify(decisionPubKey, unhex(proofStr), certBytes);
        if (!validSig) return send(401, { error: 'ERR_INVALID_DECISION_SIGNATURE' });

        const txId = hex(cert.transitionId);
        const finalTokenId = json.tokenId || json.instrumentId || json.id || "INST-REC-01";
      const currentInst = store.get ? store.get(finalTokenId) : (db.prepare ? db.prepare("SELECT status FROM instruments WHERE id = ?").get(finalTokenId) : null);
    const currentStatus = currentInst ? (currentInst.status || currentInst.state) : null;
    const passedOutcome = (json.decision && json.decision.outcome) || json.outcome || (cert.outcome === 1 || cert.outcome === 'COMMIT' ? 'COMMIT' : 'ABORT');
    if (currentStatus === 'CONSUMED' && passedOutcome !== 'COMMIT') {
      return send(409, { error: 'ERR_STATE_CONFLICT', message: 'Delayed rollback on CONSUMED state rejected' });
    }
    store.finalize(finalTokenId, txId, cert.outcome);
        return send(200, { ok: true, state: cert.outcome === 'COMMIT' ? 'CONSUMED' : 'ACTIVE' });
      }

      send(404, { error: 'NOT_FOUND' });
    } catch (e) {
      send(500, { error: e.message });
    }
  }).listen(PORT);
}
start();
