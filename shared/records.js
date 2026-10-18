'use strict';
import crypto from 'node:crypto';

export const WC = crypto.webcrypto;
export const enc = s => new TextEncoder().encode(s);
export const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
export const unhex = h => {
  if (!h || typeof h !== 'string') return new Uint8Array(0);
  const clean = h.startsWith('0x') ? h.slice(2) : h;
  if (clean.length % 2 !== 0) throw new Error('ERR_INVALID_HEX_STRING');
  const arr = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) arr[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  return arr;
};
export const bytesEqual = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

export class CryptoEngine {
  static async generateKey() {
    return await WC.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  }
  static async exportPublicJwk(key) {
    return await WC.subtle.exportKey('jwk', key);
  }
  static async importPublicJwk(jwk) {
    return await WC.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  }
  static async sign(privateKey, dataBytes) {
    return new Uint8Array(await WC.subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, privateKey, dataBytes));
  }
  static async verify(publicKey, signatureBytes, dataBytes) {
    return await WC.subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-256' } }, publicKey, signatureBytes, dataBytes);
  }
  static async sha256(dataBytes) {
    return new Uint8Array(await WC.subtle.digest('SHA-256', dataBytes));
  }
}

function writeAsciiPadded(buf, offset, maxBytes, str, fieldName) {
  if (typeof str !== 'string' || str.length === 0 || str.length > maxBytes) {
    throw new Error(`ERR_${fieldName}_LENGTH: must be 1 to ${maxBytes} characters`);
  }
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code < 0x20 || code > 0x7E) throw new Error(`ERR_${fieldName}_NON_PRINTABLE_ASCII`);
    buf[offset + i] = code;
  }
  for (let i = str.length; i < maxBytes; i++) buf[offset + i] = 0;
}

function readAsciiPadded(buf, offset, maxBytes, fieldName) {
  let end = 0;
  while (end < maxBytes && buf[offset + end] !== 0) end++;
  if (end === 0) throw new Error(`ERR_${fieldName}_EMPTY`);
  for (let i = end; i < maxBytes; i++) {
    if (buf[offset + i] !== 0) throw new Error(`ERR_${fieldName}_NON_CANONICAL_NUL_PADDING`);
  }
  let s = '';
  for (let i = 0; i < end; i++) {
    const c = buf[offset + i];
    if (c < 0x20 || c > 0x7E) throw new Error(`ERR_${fieldName}_NON_PRINTABLE`);
    s += String.fromCharCode(c);
  }
  return s;
}

export class CanonicalRecords {
  static serializeManifest(d) {
    const buf = new Uint8Array(42);
    const view = new DataView(buf.buffer);
    view.setUint16(0x00, d.version, false);
    buf.set(d.mappingCommitment, 0x02);
    view.setBigUint64(0x22, d.effectiveEpoch, false);
    return buf;
  }
  static deserializeManifest(buf) {
    if (!(buf instanceof Uint8Array) || buf.length !== 42) throw new Error('ERR_INVALID_MANIFEST_SIZE');
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    return {
      version: view.getUint16(0x00, false),
      mappingCommitment: buf.slice(0x02, 0x22),
      effectiveEpoch: view.getBigUint64(0x22, false)
    };
  }
  static serializeEnvelope(d) {
    const buf = new Uint8Array(192);
    const view = new DataView(buf.buffer);
    view.setUint16(0x00, d.protocolVersion, false);
    view.setUint16(0x02, d.mappingVersion, false);
    buf.set(d.transitionId.subarray(0, 16), 0x04);
    buf.set(d.predecessorCommitment.subarray(0, 32), 0x14);
    writeAsciiPadded(buf, 0x34, 8, d.sourceDomain, 'SOURCE_DOMAIN');
    view.setBigUint64(0x3C, d.redeemedAmount, false);
    writeAsciiPadded(buf, 0x44, 4, d.currency, 'CURRENCY');
    view.setBigUint64(0x48, d.successorDenomination, false);
    buf.set(d.successorCommitment.subarray(0, 32), 0x50);
    writeAsciiPadded(buf, 0x70, 8, d.destinationDomain, 'DESTINATION_DOMAIN');
    buf.set(d.mappingCommitment.subarray(0, 32), 0x78);
    view.setBigUint64(0x98, d.expiryEpoch, false);
    buf.set(d.lineageCommitment.subarray(0, 32), 0xA0);
    return buf;
  }
  static deserializeEnvelope(buf) {
    if (!(buf instanceof Uint8Array) || buf.length !== 192) throw new Error('ERR_INVALID_ENVELOPE_SIZE');
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    return {
      protocolVersion: view.getUint16(0x00, false),
      mappingVersion: view.getUint16(0x02, false),
      transitionId: buf.slice(0x04, 0x14),
      predecessorCommitment: buf.slice(0x14, 0x34),
      sourceDomain: readAsciiPadded(buf, 0x34, 8, 'SOURCE_DOMAIN'),
      redeemedAmount: view.getBigUint64(0x3C, false),
      currency: readAsciiPadded(buf, 0x44, 4, 'CURRENCY'),
      successorDenomination: view.getBigUint64(0x48, false),
      successorCommitment: buf.slice(0x50, 0x70),
      destinationDomain: readAsciiPadded(buf, 0x70, 8, 'DESTINATION_DOMAIN'),
      mappingCommitment: buf.slice(0x78, 0x98),
      expiryEpoch: view.getBigUint64(0x98, false),
      lineageCommitment: buf.slice(0xA0, 0xC0)
    };
  }
  static serializeSourcePrepare(d) {
    const buf = new Uint8Array(56);
    const view = new DataView(buf.buffer);
    buf.set(enc('SRC_PREP'), 0x00);
    buf.set(d.envelopeHash, 0x08);
    view.setBigUint64(0x28, d.predecessorDenomination, false);
    view.setBigUint64(0x30, d.generation, false);
    return buf;
  }
  static deserializeSourcePrepare(buf) {
    if (!(buf instanceof Uint8Array) || buf.length !== 56) throw new Error('ERR_INVALID_SOURCE_PREPARE_SIZE');
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    return {
      envelopeHash: buf.slice(0x08, 0x28),
      predecessorDenomination: view.getBigUint64(0x28, false),
      generation: view.getBigUint64(0x30, false)
    };
  }
  static serializeDestPrepare(d) {
    const buf = new Uint8Array(80);
    const view = new DataView(buf.buffer);
    buf.set(enc("DST_PREP"), 0x00);
    const envH = d.envelopeHash instanceof Uint8Array ? d.envelopeHash : unhex(d.envelopeHash || "");
    buf.set(envH, 0x08);
    view.setBigUint64(0x28, BigInt(d.reservedDenomination ?? d.successorDenomination ?? 0n), false);
    let pCert = d.parentCertificateHash || d.parentCertHash;
    if (typeof pCert === "string") pCert = unhex(pCert);
    if (!pCert || !(pCert instanceof Uint8Array)) pCert = new Uint8Array(32);
    buf.set(pCert.subarray(0, 32), 0x30);
    return buf;
  }
  static deserializeDestPrepare(buf) {
    if (!(buf instanceof Uint8Array) || buf.length !== 80) throw new Error('ERR_INVALID_DEST_PREPARE_SIZE');
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    return {
      envelopeHash: buf.slice(0x08, 0x28),
      reservedDenomination: view.getBigUint64(0x28, false),
      parentCertHash: buf.slice(0x30, 0x50)
    };
  }
  static serializeDecisionCert(d) {
    const outcomeCode = d.outcome === 'COMMIT' ? 0x01 : 0x02;
    const buf = new Uint8Array(90);
    const view = new DataView(buf.buffer);
    buf.set(enc('DECISION'), 0x00);
    buf.set(d.transitionId, 0x08);
    buf.set(d.envelopeHash, 0x18);
    buf[0x38] = outcomeCode;
    writeAsciiPadded(buf, 0x39, 8, d.designatedDestination, 'DESIGNATED_DESTINATION');
    view.setBigUint64(0x41, d.decidedEpoch, false);
    view.setBigUint64(0x49, d.generation, false);
    return buf;
  }
  static deserializeDecisionCert(buf) {
    if (!(buf instanceof Uint8Array) || buf.length !== 90) throw new Error('ERR_INVALID_DECISION_CERT_SIZE');
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    return {
      transitionId: buf.slice(0x08, 0x18),
      envelopeHash: buf.slice(0x18, 0x38),
      outcome: buf[0x38] === 0x01 ? 'COMMIT' : 'ABORT',
      designatedDestination: readAsciiPadded(buf, 0x39, 8, 'DESIGNATED_DESTINATION'),
      decidedEpoch: view.getBigUint64(0x41, false),
      generation: view.getBigUint64(0x49, false)
    };
  }
}
