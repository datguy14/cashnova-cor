'use strict';
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';

export class SourceStore {
  constructor(dbPath = 'db/source.sqlite') {
    this.db = new DatabaseSync(path.resolve(dbPath));
    this.init();
  }

  init() {
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      CREATE TABLE IF NOT EXISTS instruments (
        id TEXT PRIMARY KEY,
        denom TEXT NOT NULL,
        currency TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('ACTIVE', 'LOCKED', 'CONSUMED')),
        generation INTEGER NOT NULL,
        locked_tx TEXT,
        locked_envelope_hash TEXT
      );
    `);
  }

  mint(id, denom, currency, generation = 1) {
    const stmt = this.db.prepare(`
      INSERT INTO instruments (id, denom, currency, state, generation, locked_tx, locked_envelope_hash)
      VALUES (?, ?, ?, 'ACTIVE', ?, NULL, NULL)
    `);
    stmt.run(id, denom.toString(), currency, Number(generation));
  }

  get(id) {
    const stmt = this.db.prepare('SELECT * FROM instruments WHERE id = ?');
    const row = stmt.get(id);
    if (!row) return null;
    return {
      id: row.id,
      denom: BigInt(row.denom),
      currency: row.currency,
      state: row.state,
      generation: BigInt(row.generation),
      lockedTx: row.locked_tx,
      lockedEnvelopeHash: row.locked_envelope_hash,
      isRedeemable: row.state === 'ACTIVE'
    };
  }

  lock(id, txId, envelopeHash) {
    const stmt = this.db.prepare(`
      UPDATE instruments
      SET state = 'LOCKED', locked_tx = ?, locked_envelope_hash = ?
      WHERE id = ? AND state = 'ACTIVE'
    `);
    const res = stmt.run(txId, envelopeHash, id);
    if (res.changes === 0) throw new Error('ERR_LOCK_REJECTED_STATE_NOT_ACTIVE');
  }

  finalize(id, txId, outcome) {
    if (outcome === 'COMMIT') {
      const stmt = this.db.prepare(`
        UPDATE instruments
        SET state = 'CONSUMED', locked_tx = NULL, locked_envelope_hash = NULL
        WHERE id = ? AND state = 'LOCKED' AND locked_tx = ?
      `);
      const res = stmt.run(id, txId);
      if (res.changes === 0) throw new Error('ERR_FINALIZE_COMMIT_PRECONDITION_FAILED');
    } else if (outcome === 'ABORT') {
      const stmt = this.db.prepare(`
        UPDATE instruments
        SET state = 'ACTIVE', locked_tx = NULL, locked_envelope_hash = NULL
        WHERE id = ? AND state = 'LOCKED' AND locked_tx = ?
      `);
      const res = stmt.run(id, txId);
      if (res.changes === 0) throw new Error('ERR_FINALIZE_ABORT_PRECONDITION_FAILED');
    }
  }
}

export class DestStore {
  constructor(dbPath = 'db/dest.sqlite') {
    this.db = new DatabaseSync(path.resolve(dbPath));
    this.init();
  }

  init() {
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      CREATE TABLE IF NOT EXISTS parent_certs (
        parent_cert_hash TEXT PRIMARY KEY,
        verified_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS successors (
        id TEXT PRIMARY KEY,
        denom TEXT NOT NULL,
        currency TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('PREPARED', 'FINAL', 'ABORTED')),
        generation INTEGER NOT NULL,
        tx_id TEXT NOT NULL,
        parent_cert_hash TEXT NOT NULL,
        FOREIGN KEY(parent_cert_hash) REFERENCES parent_certs(parent_cert_hash)
      );
      CREATE TABLE IF NOT EXISTS finalized_successor_index (
        parent_cert_hash TEXT PRIMARY KEY,
        transition_id TEXT NOT NULL,
        finalized_at INTEGER NOT NULL
      );
    `);
  }

  registerParentCert(hashHex) {
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO parent_certs (parent_cert_hash, verified_at)
      VALUES (?, ?)
    `);
    stmt.run(hashHex, Date.now());
  }

  reserve(id, denom, currency, generation, txId, parentCertHashHex) {
    const pCheck = this.db.prepare('SELECT 1 FROM parent_certs WHERE parent_cert_hash = ?').get(parentCertHashHex);
    if (!pCheck) throw new Error('ERR_LINEAGE_PARENT_NOT_FINAL');

    const branchCheck = this.db.prepare('SELECT 1 FROM finalized_successor_index WHERE parent_cert_hash = ?').get(parentCertHashHex);
    if (branchCheck) throw new Error('ERR_LINEAGE_BRANCHING_PARENT_ALREADY_FINALIZED');

    const stmt = this.db.prepare(`
      INSERT INTO successors (id, denom, currency, state, generation, tx_id, parent_cert_hash)
      VALUES (?, ?, ?, 'PREPARED', ?, ?, ?)
    `);
    stmt.run(id, denom.toString(), currency, Number(generation), txId, parentCertHashHex);
  }

  get(id) {
    const stmt = this.db.prepare('SELECT * FROM successors WHERE id = ?');
    const row = stmt.get(id);
    if (!row) return null;
    return {
      id: row.id,
      denom: BigInt(row.denom),
      currency: row.currency,
      state: row.state,
      generation: BigInt(row.generation),
      txId: row.tx_id,
      parentCertHash: row.parent_cert_hash,
      isRedeemable: row.state === 'FINAL'
    };
  }

  finalize(id, txId, outcome, parentCertHashHex) {
    if (outcome === 'COMMIT') {
      const idxStmt = this.db.prepare(`
        INSERT INTO finalized_successor_index (parent_cert_hash, transition_id, finalized_at)
        VALUES (?, ?, ?)
      `);
      idxStmt.run(parentCertHashHex, txId, Date.now());

      const stmt = this.db.prepare(`
        UPDATE successors
        SET state = 'FINAL'
        WHERE id = ? AND state = 'PREPARED' AND tx_id = ?
      `);
      const res = stmt.run(id, txId);
      if (res.changes === 0) throw new Error('ERR_FINALIZE_DEST_PRECONDITION_FAILED');
    } else if (outcome === 'ABORT') {
      const stmt = this.db.prepare(`
        UPDATE successors
        SET state = 'ABORTED'
        WHERE id = ? AND state = 'PREPARED' AND tx_id = ?
      `);
      stmt.run(id, txId);
    }
  }
}
