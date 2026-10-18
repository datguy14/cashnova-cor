import http from "node:http";
import { DatabaseSync } from "node:sqlite";
import { CryptoEngine, CanonicalRecords, hex, unhex } from "../shared/records.js";

const PORT = 4002, DOMAIN = "J-B";
let keyPair, decisionPubKey;

const db = new DatabaseSync("db/dest.sqlite");
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS instruments (id TEXT PRIMARY KEY, state TEXT NOT NULL, denom INTEGER NOT NULL, generation INTEGER NOT NULL, parent_cert_hash TEXT);
  CREATE TABLE IF NOT EXISTS registered_parent_certs (parent_cert_hash TEXT PRIMARY KEY);
  CREATE TABLE IF NOT EXISTS finalized_successor_index (parent_cert_hash TEXT PRIMARY KEY, successor_id TEXT NOT NULL, transition_id TEXT NOT NULL);
`);

const store = {
  registerParentCert(h) { db.prepare("INSERT OR IGNORE INTO registered_parent_certs VALUES (?)").run(h); },
  prepareSuccessor(id, denom, gen, parentH) {
    db.exec("BEGIN IMMEDIATE");
    try {
      if (!db.prepare("SELECT 1 FROM registered_parent_certs WHERE parent_cert_hash = ?").get(parentH)) throw new Error("ERR_UNKNOWN_PARENT_CERT");
      if (db.prepare("SELECT 1 FROM finalized_successor_index WHERE parent_cert_hash = ?").get(parentH)) { const e = new Error("ERR_PARENT_CERT_ALREADY_FINALIZED"); e.code = 409; throw e; }
      db.prepare("INSERT INTO instruments VALUES (?, ?, ?, ?, ?)").run(id, "PREPARED", Number(denom), Number(gen), parentH);
      db.exec("COMMIT");
    } catch(e) { db.exec("ROLLBACK"); throw e; }
  },
  finalize(id, txId, outcome, parentH) {
    db.exec("BEGIN IMMEDIATE");
    try {
      if (!db.prepare("SELECT * FROM instruments WHERE id = ?").get(id)) throw new Error("ERR_INSTRUMENT_NOT_FOUND");
      if (outcome === "COMMIT") {
        if (db.prepare("SELECT 1 FROM finalized_successor_index WHERE parent_cert_hash = ?").get(parentH)) { const e = new Error("ERR_PARENT_CERT_ALREADY_FINALIZED"); e.code = 409; throw e; }
        db.prepare("UPDATE instruments SET state = ? WHERE id = ?").run("FINAL", id);
        db.prepare("INSERT INTO finalized_successor_index VALUES (?, ?, ?)").run(parentH, id, txId);
      } else { db.prepare("UPDATE instruments SET state = ? WHERE id = ?").run("ABORTED", id); }
      db.exec("COMMIT");
    } catch(e) { db.exec("ROLLBACK"); throw e; }
  },
  get(id) { return db.prepare("SELECT * FROM instruments WHERE id = ?").get(id); }
};

async function start() {
  keyPair = await CryptoEngine.generateKey();
  http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost:" + PORT);
    let body = [];
    for await (const chunk of req) body.push(chunk);
    const json = body.length ? JSON.parse(Buffer.concat(body).toString("utf-8")) : {};
    const send = (code, data) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(data)); };

    try {
      if (req.method === "GET" && url.pathname === "/public-key") return send(200, { jwk: await CryptoEngine.exportPublicJwk(keyPair.publicKey) });
      if (req.method === "POST" && url.pathname === "/configure") { decisionPubKey = await CryptoEngine.importPublicJwk(json.decisionJwk); return send(200, { ok: true }); }
      if (req.method === "POST" && url.pathname === "/register-parent-cert") { store.registerParentCert(json.parentCertHashHex); return send(200, { ok: true }); }
      if (req.method === "GET" && url.pathname.startsWith("/instrument/")) {
        const inst = store.get(url.pathname.split("/")[2]);
        return inst ? send(200, { id: inst.id, state: inst.state, denom: inst.denom, isRedeemable: inst.state === "FINAL" }) : send(404, { error: "NOT_FOUND" });
      }
      if (req.method === "POST" && url.pathname === "/prepare") {
        const envBytes = unhex(json.envelopeHex);
        const env = CanonicalRecords.deserializeEnvelope(envBytes);
        const envelopeHash = await CryptoEngine.sha256(envBytes);
        try { const pHash = json.parentCertHashHex || json.parentCertHash || ""; store.prepareSuccessor(json.successorId, env.successorDenomination, json.generation, pHash); }
        catch (err) { if (err.code === 409) return send(409, { error: err.message }); throw err; }
        const recordBytes = CanonicalRecords.serializeDestPrepare({
          envelopeHash,
          reservedDenomination: env.successorDenomination,
          generation: BigInt(json.generation),
          parentCertificateHash: unhex(json.parentCertHashHex || json.parentCertHash || json.parent_cert_hash || "")
        });
        const signature = await CryptoEngine.sign(keyPair.privateKey, recordBytes);
        return send(200, { ok: true, destPrepareRecordHex: hex(recordBytes), signatureHex: hex(signature) });
      }
      if (req.method === "POST" && url.pathname === "/finalize") {
        const hexStr = json.certHex || json.decisionCertHex;
        const proofStr = json.proofHex || json.decisionProofHex;
        const certBytes = unhex(hexStr);
        if (certBytes.length !== 90) return send(400, { error: "ERR_INVALID_DECISION_CERT_SIZE", receivedLen: certBytes.length });
        const cert = CanonicalRecords.deserializeDecisionCert(certBytes);
        if (!await CryptoEngine.verify(decisionPubKey, unhex(proofStr), certBytes)) return send(401, { error: "ERR_INVALID_DECISION_SIGNATURE" });
        if (cert.outcome === "COMMIT" && cert.designatedDestination !== DOMAIN) return send(403, { error: "ERR_NOT_DESIGNATED_AUTHORITY" });
        try {
          store.finalize(json.successorId, hex(cert.transitionId), cert.outcome, json.parentCertHashHex);
          return send(200, { ok: true, state: cert.outcome === "COMMIT" ? "FINAL" : "ABORTED" });
        } catch (err) { if (err.code === 409) return send(409, { error: err.message }); throw err; }
      }
      send(404, { error: "NOT_FOUND" });
    } catch (e) { console.error("DEST_ERROR_STACK:", e); send(500, { error: e.message, stack: e.stack }); }
  }).listen(PORT);
}
start();
