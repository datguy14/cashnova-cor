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
      const inst = db.prepare('SELECT * FROM instruments WHERE id = ?').get(id);
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
      db.prepare('UPDATE instruments SET state = ?, locked_tx_id = NULL WHERE id = ?').run(nextState, id);
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
        return send(200, { ok: true });
      }
      if (req.method === 'POST' && url.pathname === '/mint') {
        store.mint(json.id, json.denomCents, json.generation);
        return send(201, { ok: true });
      }
      if (req.method === 'GET' && url.pathname.startsWith('/instrument/')) {
        const id = url.pathname.split('/')[2];
        const inst = store.get(id);
        if (!inst) return send(404, { error: 'NOT_FOUND' });
        return send(200, { id: inst.id, state: inst.state, denom: inst.denom, isRedeemable: inst.state === 'ACTIVE' });
      }
      if (req.method === 'POST' && url.pathname === '/prepare') {
        const inst = store.get(json.tokenId);
        if (!inst) return send(404, { error: 'ERR_INSTRUMENT_NOT_FOUND' });
        if (inst.state !== 'ACTIVE') return send(409, { error: 'ERR_TOKEN_NOT_ACTIVE' });

        const envBytes = unhex(json.envelopeHex);
        const env = CanonicalRecords.deserializeEnvelope(envBytes);
        const envelopeHash = await CryptoEngine.sha256(envBytes);
        const txId = hex(env.transitionId);

        store.prepare(json.tokenId, txId);

        const recordBytes = CanonicalRecords.serializeSourcePrepare({
          envelopeHash,
          predecessorDenomination: BigInt(inst.denom),
          generation: BigInt(inst.generation)
        });
        const signature = await CryptoEngine.sign(keyPair.privateKey, recordBytes);

        return send(200, {
          ok: true,
          sourcePrepareRecordHex: hex(recordBytes),
          signatureHex: hex(signature)
        });
      }
      if (req.method === 'POST' && url.pathname === '/finalize') {
        const hexStr = json.certHex || json.decisionCertHex;
        const proofStr = json.proofHex || json.decisionProofHex;
        const certBytes = unhex(hexStr);
        if (certBytes.length !== 90) {
          return send(400, { error: 'ERR_INVALID_DECISION_CERT_SIZE', receivedLen: certBytes.length });
        }
        const cert = CanonicalRecords.deserializeDecisionCert(certBytes);
        const validSig = await CryptoEngine.verify(decisionPubKey, unhex(proofStr), certBytes);
        if (!validSig) return send(401, { error: 'ERR_INVALID_DECISION_SIGNATURE' });

        const txId = hex(cert.transitionId);
        store.finalize(json.tokenId, txId, cert.outcome);
        return send(200, { ok: true, state: cert.outcome === 'COMMIT' ? 'CONSUMED' : 'ACTIVE' });
      }

      send(404, { error: 'NOT_FOUND' });
    } catch (e) {
      send(500, { error: e.message });
    }
  }).listen(PORT);
}
start();
