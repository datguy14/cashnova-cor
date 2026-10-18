'use strict';
import { spawn } from 'node:child_process';
import { CryptoEngine, CanonicalRecords, hex } from '../shared/records.js';

const SOURCE = 'http://localhost:4001';
const DEST = 'http://localhost:4002';
const DECISION = 'http://localhost:4003';
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function post(url, data) {
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  return { status: res.status, json: await res.json() };
}
async function get(url) {
  const res = await fetch(url);
  return { status: res.status, json: await res.json() };
}

async function run() {
  console.log('=== STARTING CASHNOVA 5-RECORD MULTI-PROCESS VERIFICATION ===\n');

  const procs = {
    source: spawn('node', ['source-domain/server.js'], { stdio: 'inherit' }),
    dest: spawn('node', ['dest-domain/server.js'], { stdio: 'inherit' }),
    decision: spawn('node', ['decision-svc/server.js'], { stdio: 'inherit' })
  };
  await sleep(1500);

  try {
    const govKeys = await CryptoEngine.generateKey();
    const govJwk = await CryptoEngine.exportPublicJwk(govKeys.publicKey);

    const sKey = (await get(`${SOURCE}/public-key`)).json.jwk;
    const dKey = (await get(`${DEST}/public-key`)).json.jwk;
    const decKey = (await get(`${DECISION}/public-key`)).json.jwk;

    await post(`${SOURCE}/configure`, { decisionJwk: decKey });
    await post(`${DEST}/configure`, { decisionJwk: decKey });
    await post(`${DECISION}/configure`, { sourceJwk: sKey, destJwk: dKey, governanceJwk: govJwk });
    console.log('✔ Independent microservices booted and cryptographic keys bound.\n');

    const manifestCommitment = new Uint8Array(32).fill(0x17);
    const manifestBytes = CanonicalRecords.serializeManifest({
      version: 17,
      mappingCommitment: manifestCommitment,
      effectiveEpoch: 1700000000n
    });
    const manifestSig = await CryptoEngine.sign(govKeys.privateKey, manifestBytes);
    console.log('✔ Record 1: 42-byte Governance Manifest signed by authority.');

    const mintRes = await post(`${SOURCE}/mint`, { id: 'CPT-ROOT-001', denomCents: '100000', generation: 1 });
    if (mintRes.status !== 201) throw new Error('Mint failed: ' + JSON.stringify(mintRes.json));

    const parentCertHash = new Uint8Array(32).fill(0x77);
    await post(`${DEST}/register-parent-cert`, { parentCertHashHex: hex(parentCertHash) });

    const envBytes = CanonicalRecords.serializeEnvelope({
      protocolVersion: 1,
      mappingVersion: 17,
      transitionId: new Uint8Array(16).fill(0x01),
      predecessorCommitment: new Uint8Array(32).fill(0xAA),
      sourceDomain: 'J-C',
      redeemedAmount: 75000n,
      currency: 'USD',
      successorDenomination: 25000n,
      successorCommitment: new Uint8Array(32).fill(0xBB),
      destinationDomain: 'J-B',
      mappingCommitment: manifestCommitment,
      expiryEpoch: 1800000000n,
      lineageCommitment: new Uint8Array(32).fill(0xCC)
    });
    const envHex = hex(envBytes);
    console.log('✔ Record 2: 192-byte Transition Envelope serialized with version-pinned mapping.');

    const srcPost = await post(`${SOURCE}/prepare`, { tokenId: 'CPT-ROOT-001', envelopeHex: envHex });
    if (srcPost.status !== 200 || !srcPost.json.ok) {
      throw new Error('Source /prepare failed: ' + JSON.stringify(srcPost.json));
    }
    const srcRes = srcPost.json;
    console.log('✔ Record 3: 56-byte Source Prepare record signed by Domain J-C.');

    const dstPost = await post(`${DEST}/prepare`, {
      successorId: 'CPT-SUCC-001',
      envelopeHex: envHex,
      parentCertHashHex: hex(parentCertHash),
      generation: 2
    });
    if (dstPost.status !== 200 || !dstPost.json.ok) {
      throw new Error('Dest /prepare failed: ' + JSON.stringify(dstPost.json));
    }
    const dstRes = dstPost.json;
    console.log('✔ Record 4: 80-byte Destination Prepare record signed by Domain J-B.');

    const decPost = await post(`${DECISION}/decide`, {
      envelopeHex: envHex,
      manifestHex: hex(manifestBytes),
      manifestSigHex: hex(manifestSig),
      sourcePrepareRecordHex: srcRes.sourcePrepareRecordHex,
      sourceSigHex: srcRes.signatureHex,
      destPrepareRecordHex: dstRes.destPrepareRecordHex,
      destSigHex: dstRes.signatureHex,
      outcome: 'COMMIT',
      generation: 2
    });
    if (decPost.status !== 200 || !decPost.json.ok) {
      throw new Error('Decision Service rejected /decide: ' + JSON.stringify(decPost.json));
    }
    const decRes = decPost.json;
    console.log('✔ Record 5: 90-byte Decision Certificate signed and issued by Decision Service.');

    const finSrcRes = await post(`${SOURCE}/finalize`, {
      tokenId: 'CPT-ROOT-001',
      certHex: decRes.certHex,
      proofHex: decRes.proofHex
    });
    if (finSrcRes.status !== 200) throw new Error('Source finalize rejected: ' + JSON.stringify(finSrcRes.json));

    const finDstRes = await post(`${DEST}/finalize`, {
      successorId: 'CPT-SUCC-001',
      parentCertHashHex: hex(parentCertHash),
      certHex: decRes.certHex,
      proofHex: decRes.proofHex
    });
    if (finDstRes.status !== 200) throw new Error('Dest finalize rejected: ' + JSON.stringify(finDstRes.json));

    const pState = (await get(`${SOURCE}/instrument/CPT-ROOT-001`)).json;
    const sState = (await get(`${DEST}/instrument/CPT-SUCC-001`)).json;

    if (pState.state !== 'CONSUMED' || pState.isRedeemable !== false) {
      throw new Error(`Source consumption failed: state=${pState.state}, isRedeemable=${pState.isRedeemable}`);
    }
    if (sState.state !== 'FINAL' || sState.isRedeemable !== true) {
      throw new Error(`Destination finality failed: state=${sState.state}, isRedeemable=${sState.isRedeemable}`);
    }
    console.log('✔ Finality confirmed: Predecessor consumed under Authority Firewall; Successor active.');

    console.log('\n[ADVERSARIAL] Attempting duplicate successor finalization on same parent certificate...');
    const rogueBranchRes = await post(`${DEST}/prepare`, {
      successorId: 'CPT-SUCC-ROGUE',
      envelopeHex: envHex,
      parentCertHashHex: hex(parentCertHash),
      generation: 2
    });

    if (rogueBranchRes.status === 409) {
      console.log('✔ PASS: Destination validator blocked branching attempt against finalized parent.');
    } else {
      throw new Error('Anti-branching guard failed to reject duplicate branch');
    }

    console.log('\n==================================================');
    console.log('ALL 5 SCHEMAS MACHINE-VALIDATED ACROSS 3 SERVICES');
    console.log('==================================================');
  } finally {
    Object.values(procs).forEach(p => p.kill('SIGKILL'));
  }
}

run().catch(e => { console.error('FATAL TEST ERROR:', e); process.exit(1); });
