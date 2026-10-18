'use strict';
import crypto from 'node:crypto';

export const WC = crypto.webcrypto;
export const enc = s => new TextEncoder().encode(s);
export const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');

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

export class CanonicalEnvelope {
  static serialize(d) {
    const buf = new Uint8Array(192);
    const view = new DataView(buf.buffer);
    view.setUint16(0x00, d.protocolVersion, false);
    view.setUint16(0x02, d.mappingVersion, false);
    buf.set(d.transitionId, 0x04);
    buf.set(d.predecessorCommitment, 0x14);
    for (let i = 0; i < d.sourceDomain.length; i++) buf[0x34 + i] = d.sourceDomain.charCodeAt(i);
    view.setBigUint64(0x3C, d.redeemedAmount, false);
    for (let i = 0; i < d.currency.length; i++) buf[0x44 + i] = d.currency.charCodeAt(i);
    view.setBigUint64(0x48, d.successorDenomination, false);
    buf.set(d.successorCommitment, 0x50);
    for (let i = 0; i < d.destinationDomain.length; i++) buf[0x70 + i] = d.destinationDomain.charCodeAt(i);
    buf.set(d.mappingCommitment, 0x78);
    view.setBigUint64(0x98, d.expiryEpoch, false);
    buf.set(d.lineageCommitment, 0xA0);
    return buf;
  }
  static deserialize(buf) {
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const readAscii = (off, max) => {
      let n = 0;
      while (n < max && buf[off + n] !== 0) n++;
      return String.fromCharCode(...buf.slice(off, off + n));
    };
    return {
      protocolVersion: view.getUint16(0x00, false),
      mappingVersion: view.getUint16(0x02, false),
      transitionId: buf.slice(0x04, 0x14),
      predecessorCommitment: buf.slice(0x14, 0x34),
      sourceDomain: readAscii(0x34, 8),
      redeemedAmount: view.getBigUint64(0x3C, false),
      currency: readAscii(0x44, 4),
      successorDenomination: view.getBigUint64(0x48, false),
      successorCommitment: buf.slice(0x50, 0x70),
      destinationDomain: readAscii(0x70, 8),
      mappingCommitment: buf.slice(0x78, 0x98),
      expiryEpoch: view.getBigUint64(0x98, false),
      lineageCommitment: buf.slice(0xA0, 0xC0)
    };
  }
}

export const PrepareMessages = {
  source(envHash, predecessorDenomination) {
    const tag = enc('PREPARE_SOURCE:');
    const out = new Uint8Array(tag.length + envHash.length + 8);
    out.set(tag, 0);
    out.set(envHash, tag.length);
    new DataView(out.buffer).setBigUint64(tag.length + envHash.length, predecessorDenomination, false);
    return out;
  },
  destination(envHash) {
    const tag = enc('PREPARE_DESTINATION:');
    const out = new Uint8Array(tag.length + envHash.length);
    out.set(tag, 0);
    out.set(envHash, tag.length);
    return out;
  }
};

export const DecisionMessage = {
  build(txId, envHashHex, outcome) { return enc(`DECISION|${txId}|${envHashHex}|${outcome}`); }
};

export const txIdFromEnvelope = bytes => hex(bytes.subarray(0x04, 0x14));
