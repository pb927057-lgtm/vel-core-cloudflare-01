import assert from 'node:assert/strict';
import {
  clearFirebaseJwksCacheForTests,
  clearOAuthTokenCacheForTests,
  FirestoreRestClient,
  normalizePemPrivateKey,
  verifyUserTokenStrict
} from '../cloudflare/shared/firebaseRest';
import {
  createFirestoreRestDeviceStore,
  DeviceTransactionStore
} from '../cloudflare/shared/deviceAuthService';
import { createFirestoreRestPaymentStore } from '../cloudflare/shared/paymentRenewalService';
import { verifyMpWebhookSignature } from '../cloudflare/shared/mercadopago';
import {
  createSubscriptionPass,
  verifySubscriptionPass
} from '../cloudflare/shared/subscriptionAccess';
import type {
  AuthorizationRecord,
  CloudflareEnv,
  DeviceLinkRecord,
  DeviceRecord,
  PagoProcesadoRecord,
  PricingConfig,
  SuscriptorAdminRecord
} from '../cloudflare/shared/types';
import {
  bytesToBase64,
  bytesToBase64Url,
  bytesToHex,
  hmacSha256Bytes,
  sha256Bytes,
  toExactArrayBuffer,
  utf8ToBytes
} from '../cloudflare/shared/webCrypto';

import { handleRelayConfig } from '../functions/api/relay-config';
import { handleRegisterDevice } from '../functions/api/register-device';
import { handleDeviceSession } from '../functions/api/device-session';
import { handlePairingConfirm } from '../functions/api/pairing-confirm';
import { handleRevokeDevice } from '../functions/api/revoke-device';
import { handleVerifyDeviceToken } from '../functions/api/verify-device-token';
import { handleGetPricing } from '../functions/api/get-pricing';
import { handleAdminPricing } from '../functions/api/admin-pricing';
import { handleCreatePreference } from '../functions/api/create-preference';
import { handlePaymentWebhook } from '../functions/api/payment-webhook';
import { handleCreateSubscription } from '../functions/api/create-subscription';
import { handleLegacyPreapprovalWebhook } from '../functions/api/mercadopago-webhook';
import { handleCancelSubscription } from '../functions/api/cancel-subscription';
import { handleDownloadPackage } from '../functions/api/download-package';
import { handleAccountRequest } from '../functions/api/account';

let passed = 0;
let total = 0;

async function runCheck(name: string, fn: () => Promise<void> | void): Promise<void> {
  total++;
  try {
    await fn();
    passed++;
    console.log(`✓ [PASS] ${name}`);
  } catch (err: any) {
    console.error(`✗ [FAIL] ${name}: ${err?.stack || err?.message || err}`);
    process.exitCode = 1;
  }
}

function createMemoryDeviceStore(initialSub?: SuscriptorAdminRecord): DeviceTransactionStore {
  const devices = new Map<string, DeviceRecord>();
  const links = new Map<string, DeviceLinkRecord>();
  const auths = new Map<string, AuthorizationRecord>();
  const subs = new Map<string, SuscriptorAdminRecord>();
  if (initialSub) subs.set(initialSub.uid, { ...initialSub });

  return {
    async runTransaction(fn) {
      return fn({
        async getDevice(id) {
          const d = devices.get(id);
          return d ? { ...d } : null;
        },
        createDevice(record) {
          devices.set(record.deviceId, { ...record });
        },
        updateDevice(id, patch) {
          const cur = devices.get(id);
          if (cur) devices.set(id, { ...cur, ...patch });
        },
        async getLink(linkId) {
          const l = links.get(linkId);
          return l ? { ...l } : null;
        },
        createLink(record) {
          links.set(record.linkId, { ...record });
        },
        updateLink(linkId, patch) {
          const cur = links.get(linkId);
          if (cur) links.set(linkId, { ...cur, ...patch });
        },
        async getAuthorizationByLink(linkId) {
          const a = auths.get(linkId);
          return a ? { ...a } : null;
        },
        createAuthorization(record) {
          auths.set(record.authorizationId, { ...record });
        },
        updateAuthorization(authId, patch) {
          const cur = auths.get(authId);
          if (cur) auths.set(authId, { ...cur, ...patch });
        },
        async getSubscriberInTx(uid) {
          const s = subs.get(uid);
          return s ? { ...s } : null;
        },
        async findSubscribersByEmailInTx(email) {
          const norm = email.trim().toLowerCase();
          return Array.from(subs.values())
            .filter((s) => s.email.trim().toLowerCase() === norm)
            .map((s) => ({ ...s }));
        },
        setSubscriberInTx(uid, record, merge) {
          const cur = subs.get(uid);
          subs.set(uid, merge && cur ? ({ ...cur, ...record } as SuscriptorAdminRecord) : ({ ...record } as SuscriptorAdminRecord));
        },
        async findDevicesBySubscriptionUidInTx(subscriptionUid) {
          return Array.from(devices.values())
            .filter((d) => d.subscriptionUid === subscriptionUid)
            .map((d) => ({ ...d }));
        }
      });
    },
    async getSubscriber(uid) {
      const s = subs.get(uid);
      return s ? { ...s } : null;
    },
    async updateSubscriberStatus(uid, patch) {
      const s = subs.get(uid);
      if (s) subs.set(uid, { ...s, ...patch });
    },
    async listDevicesBySubscriptionUid(subscriptionUid) {
      return Array.from(devices.values())
        .filter((d) => d.subscriptionUid === subscriptionUid)
        .map((d) => ({ ...d }));
    },
    async hasAcceptedContract() {
      return false;
    }
  };
}

async function makeSignedFirebaseToken(
  privateKey: CryptoKey,
  kid: string,
  payloadOverrides: Record<string, any> = {},
  nowSec: number = Math.floor(Date.now() / 1000)
): Promise<string> {
  const header = { alg: 'RS256', kid, typ: 'JWT' };
  const payload = {
    aud: 'proyecto-vel',
    iss: 'https://securetoken.google.com/proyecto-vel',
    sub: 'USR_CF_TEST_01',
    email: 'suscriptor@vel.test',
    iat: nowSec - 10,
    auth_time: nowSec - 10,
    exp: nowSec + 3600,
    ...payloadOverrides
  };
  const hB64 = bytesToBase64Url(utf8ToBytes(JSON.stringify(header)));
  const pB64 = bytesToBase64Url(utf8ToBytes(JSON.stringify(payload)));
  const unsigned = `${hB64}.${pB64}`;
  const sig = await globalThis.crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    toExactArrayBuffer(utf8ToBytes(unsigned))
  );
  return `${unsigned}.${bytesToBase64Url(new Uint8Array(sig))}`;
}

async function generateDeviceSpkiAndFingerprint(): Promise<{
  spkiBase64: string;
  signingSpkiBase64: string;
  fingerprint: string;
}> {
  const kp1 = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  const kp2 = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const spki1 = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', kp1.publicKey));
  const spki2 = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', kp2.publicKey));
  const digest = await sha256Bytes(spki1);
  const fingerprint = Array.from(digest)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(':');
  return {
    spkiBase64: bytesToBase64(spki1),
    signingSpkiBase64: bytesToBase64(spki2),
    fingerprint
  };
}

function derPkcs8ToPem(pkcs8Bytes: Uint8Array): string {
  const b64 = bytesToBase64(pkcs8Bytes);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----\n`;
}

async function main() {
  console.log('====================================================');
  console.log('PRUEBAS DE MIGRACIÓN CLOUDFLARE PAGES + FUNCTIONS (VEL 0.1)');
  console.log('====================================================\n');

  const rsaPair = await globalThis.crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  );
  const pubJwk = (await globalThis.crypto.subtle.exportKey('jwk', rsaPair.publicKey)) as JsonWebKey & {
    kid?: string;
  };
  pubJwk.kid = 'vel-test-kid-1';
  const pkcs8ServiceBytes = new Uint8Array(
    await globalThis.crypto.subtle.exportKey('pkcs8', rsaPair.privateKey)
  );
  const servicePem = derPkcs8ToPem(pkcs8ServiceBytes);

  const mockJwksFetch: typeof fetch = async (input) => {
    const url = String(input);
    if (url.includes('securetoken@system.gserviceaccount.com')) {
      return new Response(JSON.stringify({ keys: [pubJwk] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600' }
      });
    }
    throw new Error(`Fetch inesperado en mockJwksFetch: ${url}`);
  };

  await runCheck('1. verifyUserTokenStrict con RS256 Web Crypto + JWKS valida token legítimo y rechaza alterados/expirados', async () => {
    clearFirebaseJwksCacheForTests();
    const nowSec = Math.floor(Date.now() / 1000);
    const validJwt = await makeSignedFirebaseToken(rsaPair.privateKey, 'vel-test-kid-1', { admin: true }, nowSec);
    const okRes = await verifyUserTokenStrict(`Bearer ${validJwt}`, { FIREBASE_PROJECT_ID: 'proyecto-vel' }, {
      nowMs: nowSec * 1000,
      fetchFn: mockJwksFetch
    });
    assert.equal(okRes.authenticated, true);
    if (okRes.authenticated) {
      assert.equal(okRes.uid, 'USR_CF_TEST_01');
      assert.equal(okRes.email, 'suscriptor@vel.test');
      assert.equal(okRes.claims.admin, true);
    }

    const expiredJwt = await makeSignedFirebaseToken(
      rsaPair.privateKey,
      'vel-test-kid-1',
      { exp: nowSec - 60 },
      nowSec
    );
    const expRes = await verifyUserTokenStrict(`Bearer ${expiredJwt}`, { FIREBASE_PROJECT_ID: 'proyecto-vel' }, {
      nowMs: nowSec * 1000,
      fetchFn: mockJwksFetch
    });
    assert.equal(expRes.authenticated, false);

    const wrongAudJwt = await makeSignedFirebaseToken(
      rsaPair.privateKey,
      'vel-test-kid-1',
      { aud: 'otro-proyecto' },
      nowSec
    );
    const audRes = await verifyUserTokenStrict(`Bearer ${wrongAudJwt}`, { FIREBASE_PROJECT_ID: 'proyecto-vel' }, {
      nowMs: nowSec * 1000,
      fetchFn: mockJwksFetch
    });
    assert.equal(audRes.authenticated, false);

    const parts = validJwt.split('.');
    const tampered = `${parts[0]}.${parts[1]}.${parts[2].slice(0, -4)}AAAA`;
    const tamperedRes = await verifyUserTokenStrict(`Bearer ${tampered}`, { FIREBASE_PROJECT_ID: 'proyecto-vel' }, {
      nowMs: nowSec * 1000,
      fetchFn: mockJwksFetch
    });
    assert.equal(tamperedRes.authenticated, false);
  });

  await runCheck('2. normalizePemPrivateKey + FirestoreRestClient ejecuta transacción atómica (beginTransaction, read, query, commit, rollback y retry 409)', async () => {
    clearOAuthTokenCacheForTests();
    const canonical = normalizePemPrivateKey(servicePem.replace(/\n/g, '\\n'));
    assert.ok(canonical.startsWith('-----BEGIN PRIVATE KEY-----\n'));

    let commitCalls = 0;
    let rollbackCalls = 0;
    let lastCommitBody: any = null;
    const mockFirestoreFetch: typeof fetch = async (input, init) => {
      const url = String(input);
      if (url === 'https://oauth2.googleapis.com/token') {
        return new Response(JSON.stringify({ access_token: 'mock-oauth-token', expires_in: 3600 }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      if (url.endsWith(':beginTransaction')) {
        return new Response(JSON.stringify({ transaction: `tx_${commitCalls + 1}` }), { status: 200 });
      }
      if (url.includes('/documents/suscriptores/USR_TX?transaction=')) {
        return new Response(
          JSON.stringify({
            name: 'projects/proyecto-vel/databases/(default)/documents/suscriptores/USR_TX',
            fields: {
              uid: { stringValue: 'USR_TX' },
              estado: { stringValue: 'activo' },
              venceEl: { stringValue: '2026-12-20T00:00:00.000Z' }
            }
          }),
          { status: 200 }
        );
      }
      if (url.endsWith(':runQuery')) {
        return new Response(
          JSON.stringify([
            {
              document: {
                name: 'projects/proyecto-vel/databases/(default)/documents/pagos_procesados/PAY_1',
                fields: {
                  paymentId: { stringValue: 'PAY_1' },
                  uid: { stringValue: 'USR_TX' },
                  status: { stringValue: 'approved' },
                  grantedDays: { integerValue: '30' }
                }
              }
            }
          ]),
          { status: 200 }
        );
      }
      if (url.endsWith(':commit')) {
        commitCalls++;
        lastCommitBody = JSON.parse(String(init?.body || '{}'));
        if (commitCalls === 1) {
          return new Response(JSON.stringify({ error: { message: 'ABORTED' } }), { status: 409 });
        }
        return new Response(JSON.stringify({ writeResults: [] }), { status: 200 });
      }
      if (url.endsWith(':rollback')) {
        rollbackCalls++;
        return new Response(JSON.stringify({}), { status: 200 });
      }
      return new Response(JSON.stringify({ error: { message: `Not mocked: ${url}` } }), { status: 404 });
    };

    const client = new FirestoreRestClient(
      {
        projectId: 'proyecto-vel',
        clientEmail: 'firebase-adminsdk@proyecto-vel.iam.gserviceaccount.com',
        privateKey: canonical
      },
      mockFirestoreFetch
    );

    const paymentStore = createFirestoreRestPaymentStore(client);
    const txOut = await paymentStore.runTransaction(async (ctx) => {
      const sub = await ctx.getSubscriber('USR_TX');
      const pays = await ctx.getSubscriberPayments('USR_TX');
      ctx.updateSubscriber('USR_TX', { ultimaActualizacion: '2026-11-24T12:00:00.000Z' });
      return { sub, pays };
    });
    assert.equal(commitCalls, 2); // reintentó una vez ante HTTP 409
    assert.equal(txOut.sub?.estado, 'activo');
    assert.equal(txOut.pays.length, 1);
    assert.equal(txOut.pays[0].grantedDays, 30);
    assert.ok(Array.isArray(lastCommitBody.writes) && lastCommitBody.writes.length === 1);

    const deviceStore = createFirestoreRestDeviceStore(client);
    assert.ok(deviceStore);

    await assert.rejects(
      () =>
        client.runTransaction(async () => {
          throw new Error('Falla controlada');
        }),
      /Falla controlada/
    );
    assert.equal(rollbackCalls, 1);
  });

  await runCheck('3. Web Crypto HMAC-SHA256 para Mercado Pago x-signature y pase vel_pass', async () => {
    const env: CloudflareEnv = {
      MP_WEBHOOK_SECRET: 'cf_mp_secret_1234567890',
      VEL_ACTIVATION_SECRET: 'cf_vel_activation_secret_01'
    };
    const nowMs = Date.UTC(2026, 10, 24, 10, 0, 0);
    const tsSec = Math.floor(nowMs / 1000).toString();
    const manifest = `id:pay_9988;request-id:req-cf-1;ts:${tsSec};`;
    const sigHex = bytesToHex(await hmacSha256Bytes(env.MP_WEBHOOK_SECRET!, manifest));

    const valid = await verifyMpWebhookSignature(`ts=${tsSec},v1=${sigHex}`, 'req-cf-1', 'PAY_9988', env, { nowMs });
    assert.equal(valid.isValid, true);

    const invalid = await verifyMpWebhookSignature(`ts=${tsSec},v1=${'0'.repeat(64)}`, 'req-cf-1', 'PAY_9988', env, { nowMs });
    assert.equal(invalid.isValid, false);

    const pass = await createSubscriptionPass('USR_SUB_1', new Date(nowMs), undefined, undefined, env);
    assert.ok(pass);
    const verifiedPass = await verifySubscriptionPass(pass!, new Date(nowMs + 1000), undefined, env);
    assert.equal(verifiedPass.valid, true);
    assert.equal(verifiedPass.uid, 'USR_SUB_1');
  });

  await runCheck('4. /api/relay-config (handleRelayConfig)', async () => {
    const unconf = await handleRelayConfig({
      request: new Request('https://proyecto-vel.pages.dev/api/relay-config', { method: 'GET' }),
      env: {}
    });
    assert.equal(unconf.status, 200);
    assert.equal((await unconf.json()).configured, false);

    const conf = await handleRelayConfig({
      request: new Request('https://proyecto-vel.pages.dev/api/relay-config', { method: 'GET' }),
      env: { VEL_RELAY_WSS_URL: 'wss://server-vel.onrender.com/' }
    });
    const confBody = await conf.json();
    assert.equal(conf.status, 200);
    assert.equal(confBody.configured, true);
    assert.equal(confBody.wssUrl, 'wss://server-vel.onrender.com');

    const badMethod = await handleRelayConfig({
      request: new Request('https://proyecto-vel.pages.dev/api/relay-config', { method: 'POST' }),
      env: {}
    });
    assert.equal(badMethod.status, 405);
  });

  await runCheck('5. /api/register-device, /api/device-session, /api/pairing-confirm, /api/verify-device-token, /api/revoke-device', async () => {
    const env: CloudflareEnv = { VEL_ACTIVATION_SECRET: 'cf_vel_activation_secret_01' };
    const now = new Date('2026-11-24T12:00:00.000Z');
    const subPass = await createSubscriptionPass('USR_OWNER_1', now, undefined, undefined, env);
    const store = createMemoryDeviceStore({
      uid: 'USR_OWNER_1',
      email: 'owner@vel.test',
      estado: 'activo',
      plan: 'Suscripción mensual VEL',
      fechaAlta: '2026-11-01T00:00:00.000Z',
      venceEl: '2026-12-20T00:00:00.000Z'
    });

    const coreKeys = await generateDeviceSpkiAndFingerprint();
    const movKeys = await generateDeviceSpkiAndFingerprint();

    const regCore = await handleRegisterDevice(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/register-device', {
          method: 'POST',
          headers: { Authorization: 'Bearer tok', 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deviceId: 'VEL-CORE-AABBCCDDEEFF',
            role: 'CORE',
            publicKeySpkiBase64: coreKeys.spkiBase64,
            signingPublicKeySpkiBase64: coreKeys.signingSpkiBase64,
            fingerprint: coreKeys.fingerprint,
            subscriptionPass: subPass
          })
        }),
        env
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'AUTH_CORE_UID', email: '', claims: {} }),
        hasDbCredentials: () => true,
        getDeviceStore: () => store,
        nowProvider: () => now
      }
    );
    assert.equal(regCore.status, 201);
    const regCoreBody = await regCore.json();
    assert.equal(regCoreBody.device.subscriptionUid, 'USR_OWNER_1');

    // Intento duplicado debe dar 409
    const dupCore = await handleRegisterDevice(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/register-device', {
          method: 'POST',
          headers: { Authorization: 'Bearer tok', 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deviceId: 'VEL-CORE-AABBCCDDEEFF',
            role: 'CORE',
            publicKeySpkiBase64: coreKeys.spkiBase64,
            signingPublicKeySpkiBase64: coreKeys.signingSpkiBase64,
            fingerprint: coreKeys.fingerprint
          })
        }),
        env
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'AUTH_CORE_UID', email: '', claims: {} }),
        hasDbCredentials: () => true,
        getDeviceStore: () => store
      }
    );
    assert.equal(dupCore.status, 409);

    // Registro TERMINAL
    const regMov = await handleRegisterDevice(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/register-device', {
          method: 'POST',
          headers: { Authorization: 'Bearer tok2', 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deviceId: 'VEL-MOV-112233445566',
            role: 'TERMINAL',
            publicKeySpkiBase64: movKeys.spkiBase64,
            signingPublicKeySpkiBase64: movKeys.signingSpkiBase64,
            fingerprint: movKeys.fingerprint
          })
        }),
        env
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'AUTH_MOV_UID', email: '', claims: {} }),
        hasDbCredentials: () => true,
        getDeviceStore: () => store,
        nowProvider: () => now
      }
    );
    assert.equal(regMov.status, 201);

    // Emparejamiento atómico con SAS verificado
    const pairRes = await handlePairingConfirm(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/pairing-confirm', {
          method: 'POST',
          headers: { Authorization: 'Bearer tok', 'Content-Type': 'application/json' },
          body: JSON.stringify({
            linkId: 'LNK-CF-01',
            coreDeviceId: 'VEL-CORE-AABBCCDDEEFF',
            terminalDeviceId: 'VEL-MOV-112233445566',
            corePublicKeySpkiBase64: coreKeys.spkiBase64,
            terminalPublicKeySpkiBase64: movKeys.spkiBase64,
            sasVerified: true
          })
        }),
        env
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'AUTH_CORE_UID', email: '', claims: {} }),
        hasDbCredentials: () => true,
        getDeviceStore: () => store,
        nowProvider: () => now
      }
    );
    assert.equal(pairRes.status, 200);
    const pairBody = await pairRes.json();
    assert.equal(pairBody.authorization.status, 'active');

    // device-session GET con estado de suscripción
    const sessRes = await handleDeviceSession(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/device-session?deviceId=VEL-CORE-AABBCCDDEEFF', {
          method: 'GET',
          headers: { Authorization: 'Bearer tok' }
        }),
        env
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'AUTH_CORE_UID', email: '', claims: {} }),
        hasDbCredentials: () => true,
        getDeviceStore: () => store,
        nowProvider: () => now
      }
    );
    assert.equal(sessRes.status, 200);
    const sessBody = await sessRes.json();
    assert.equal(sessBody.subscriptionStatus.active, true);

    // verify-device-token para Relay
    const verRes = await handleVerifyDeviceToken(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/verify-device-token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            firebaseIdToken: 'tok',
            deviceId: 'VEL-CORE-AABBCCDDEEFF',
            peerDeviceId: 'VEL-MOV-112233445566'
          })
        }),
        env
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'AUTH_CORE_UID', email: '', claims: {} }),
        hasDbCredentials: () => true,
        getDeviceStore: () => store,
        nowProvider: () => now
      }
    );
    assert.equal(verRes.status, 200);
    assert.equal((await verRes.json()).valid, true);

    // revoke-device revoca TERMINAL pero preserva CORE
    const revRes = await handleRevokeDevice(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/revoke-device', {
          method: 'POST',
          headers: { Authorization: 'Bearer tok', 'Content-Type': 'application/json' },
          body: JSON.stringify({
            coreDeviceId: 'VEL-CORE-AABBCCDDEEFF',
            targetTerminalId: 'VEL-MOV-112233445566'
          })
        }),
        env
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'AUTH_CORE_UID', email: '', claims: {} }),
        hasDbCredentials: () => true,
        getDeviceStore: () => store,
        nowProvider: () => now
      }
    );
    assert.equal(revRes.status, 200);
    const revBody = await revRes.json();
    assert.equal(revBody.coreDevice.status, 'registered');

    // TERMINAL revocado es rechazado por verify-device-token
    const verMovAfterRevoke = await handleVerifyDeviceToken(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/verify-device-token', {
          method: 'POST',
          headers: { Authorization: 'Bearer tok2', 'Content-Type': 'application/json' },
          body: JSON.stringify({ deviceId: 'VEL-MOV-112233445566' })
        }),
        env
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'AUTH_MOV_UID', email: '', claims: {} }),
        hasDbCredentials: () => true,
        getDeviceStore: () => store,
        nowProvider: () => now
      }
    );
    assert.equal(verMovAfterRevoke.status, 403);
    assert.equal((await verMovAfterRevoke.json()).code, 'DEVICE_REVOKED');
  });

  await runCheck('6. /api/get-pricing y /api/admin-pricing', async () => {
    const pricing: PricingConfig = {
      monto: 4500,
      moneda: 'ARS',
      periodicidad: 'mensual',
      actualizadoEl: '2026-11-24T00:00:00.000Z'
    };
    const pubPrice = await handleGetPricing(
      { request: new Request('https://proyecto-vel.pages.dev/api/get-pricing'), env: {} },
      { getPricing: async () => pricing }
    );
    assert.equal(pubPrice.status, 200);
    assert.equal((await pubPrice.json()).pricing.monto, 4500);

    const noCredsPrice = await handleGetPricing({
      request: new Request('https://proyecto-vel.pages.dev/api/get-pricing'),
      env: {}
    });
    assert.equal(noCredsPrice.status, 503);

    const deniedAdmin = await handleAdminPricing(
      { request: new Request('https://proyecto-vel.pages.dev/api/admin-pricing'), env: {} },
      { verifyToken: async () => ({ uid: 'u1', email: 'normal@user.com', claims: {} }) }
    );
    assert.equal(deniedAdmin.status, 403);

    const initAdmin = await handleAdminPricing(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/admin-pricing', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'initialize', monto: 5000, moneda: 'ARS' })
        }),
        env: {}
      },
      {
        verifyToken: async () => ({ uid: 'adm1', email: 'admin@vel.com', claims: { admin: true } }),
        initPricing: async (monto, moneda, adminEmail) => ({
          created: true,
          alreadyInitialized: false,
          pricing: { monto, moneda, periodicidad: 'mensual', actualizadoEl: '2026-11-24T00:00:00.000Z', actualizadoPor: adminEmail }
        })
      }
    );
    assert.equal(initAdmin.status, 201);
  });

  await runCheck('7. /api/create-preference usa /api/payment-webhook en Cloudflare y CORS estricto de Blogger', async () => {
    let capturedNotificationUrl = '';
    let capturedSuccessUrl = '';
    const env: CloudflareEnv = {
      VEL_ACTIVATION_SECRET: 'cf_vel_activation_secret_01',
      APP_BASE_URL: 'https://proyecto-vel.pages.dev'
    };

    const badOrigin = await handleCreatePreference({
      request: new Request('https://proyecto-vel.pages.dev/api/create-preference', {
        method: 'POST',
        headers: { Origin: 'https://sitio-no-autorizado.com' }
      }),
      env
    });
    assert.equal(badOrigin.status, 403);

    const okPref = await handleCreatePreference(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/create-preference', {
          method: 'POST',
          headers: {
            Origin: 'https://proyecto-vel.blogspot.com',
            Authorization: 'Bearer tok',
            'Content-Type': 'application/json'
          },
          body: '{}'
        }),
        env
      },
      {
        verifyToken: async () => ({
          authenticated: true,
          uid: 'USR_MP_1',
          email: 'cliente@vel.test',
          claims: {}
        }),
        getPricing: async () => ({
          monto: 4500,
          moneda: 'ARS',
          periodicidad: 'mensual',
          actualizadoEl: '2026-11-24T00:00:00.000Z'
        }),
        getSubscriber: async () => null,
        createPreference: async (params) => {
          capturedNotificationUrl = params.notificationUrl;
          capturedSuccessUrl = params.backUrls.success;
          return {
            success: true,
            data: { id: 'PREF_CF_01', init_point: 'https://www.mercadopago.com.ar/checkout/v1/redirect?pref_id=PREF_CF_01' }
          };
        },
        recordPreferenceIntent: async () => {}
      }
    );

    assert.equal(okPref.status, 200);
    assert.equal(okPref.headers.get('access-control-allow-origin'), 'https://proyecto-vel.blogspot.com');
    assert.equal(capturedNotificationUrl, 'https://proyecto-vel.pages.dev/api/payment-webhook?source_news=webhooks');
    assert.ok(!capturedNotificationUrl.includes('netlify'));
    assert.ok(capturedSuccessUrl.includes('vel_pass='));
  });

  await runCheck('8. /api/payment-webhook acredita 30 días atómicamente, aplica idempotencia y recalcula reembolsos', async () => {
    const env: CloudflareEnv = { MP_WEBHOOK_SECRET: 'cf_mp_secret_1234567890' };
    const now = new Date('2026-11-24T12:00:00.000Z');
    const ts = Math.floor(now.getTime() / 1000).toString();

    const paymentsMap = new Map<string, PagoProcesadoRecord>();
    const subsMap = new Map<string, SuscriptorAdminRecord>([
      [
        'USR_PAY_1',
        {
          uid: 'USR_PAY_1',
          email: 'payer@vel.test',
          estado: 'pendiente_pago',
          plan: 'Suscripción mensual VEL',
          fechaAlta: '2026-11-24T11:00:00.000Z',
          venceEl: null,
          modalidadComercial: 'manual_30d',
          mpPreferenceId: 'PREF_1'
        }
      ]
    ]);
    const store = {
      async runTransaction<T>(fn: any): Promise<T> {
        return fn({
          getProcessedPayment: async (id: string) => paymentsMap.get(id) || null,
          getSubscriber: async (uid: string) => subsMap.get(uid) || null,
          getSubscriberPayments: async (uid: string) =>
            Array.from(paymentsMap.values()).filter((p) => p.uid === uid),
          saveProcessedPayment: (rec: PagoProcesadoRecord) => paymentsMap.set(rec.paymentId, { ...rec }),
          updateProcessedPayment: (id: string, patch: any) => {
            const cur = paymentsMap.get(id);
            if (cur) paymentsMap.set(id, { ...cur, ...patch });
          },
          updateSubscriber: (uid: string, patch: any) => {
            const cur = subsMap.get(uid);
            if (cur) subsMap.set(uid, { ...cur, ...patch });
          }
        });
      }
    };

    const payId = '99112233';
    const manifest = `id:${payId};request-id:req-wh-1;ts:${ts};`;
    const sigHex = bytesToHex(await hmacSha256Bytes(env.MP_WEBHOOK_SECRET!, manifest));

    const makeReq = () =>
      new Request(`https://proyecto-vel.pages.dev/api/payment-webhook?data.id=${payId}&type=payment`, {
        method: 'POST',
        headers: {
          'x-signature': `ts=${ts},v1=${sigHex}`,
          'x-request-id': 'req-wh-1',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ type: 'payment', data: { id: payId } })
      });

    let mpPayStatus = 'approved';
    const deps = {
      hasDbCredentials: () => true,
      getPricing: async () => ({
        monto: 4500,
        moneda: 'ARS',
        periodicidad: 'mensual' as const,
        actualizadoEl: '2026-11-01T00:00:00.000Z'
      }),
      getPaymentStore: () => store,
      nowProvider: () => now,
      fetchPayment: async () => ({
        success: true,
        data: {
          id: payId,
          status: mpPayStatus,
          external_reference: 'USR_PAY_1',
          transaction_amount: 4500,
          currency_id: 'ARS',
          metadata: { circuito: 'checkout_pro', preference_id: 'PREF_1' }
        }
      })
    };

    const first = await handlePaymentWebhook({ request: makeReq(), env }, deps);
    assert.equal(first.status, 200);
    const firstBody = await first.json();
    assert.equal(firstBody.grantedDays, 30);
    assert.equal(firstBody.estado, 'activo');

    const dup = await handlePaymentWebhook({ request: makeReq(), env }, deps);
    assert.equal(dup.status, 200);
    const dupBody = await dup.json();
    assert.equal(dupBody.duplicate, true);
    assert.equal(dupBody.grantedDays, 0);

    mpPayStatus = 'refunded';
    const rev = await handlePaymentWebhook({ request: makeReq(), env }, deps);
    assert.equal(rev.status, 200);
    const revBody = await rev.json();
    assert.equal(revBody.reverted, true);
    assert.equal(revBody.estado, 'suspendido');
  });

  await runCheck('9. /api/create-subscription (410), /api/mercadopago-webhook, /api/cancel-subscription, /api/download-package', async () => {
    const depSub = await handleCreateSubscription({
      request: new Request('https://proyecto-vel.pages.dev/api/create-subscription', { method: 'POST' }),
      env: {}
    });
    assert.equal(depSub.status, 410);
    assert.equal((await depSub.json()).officialEndpoint, '/api/create-preference');

    // mercadopago-webhook ignora pagos de Checkout Pro
    const env: CloudflareEnv = {
      VEL_ACTIVATION_SECRET: 'cf_vel_activation_secret_01',
      APP_BASE_URL: 'https://proyecto-vel.pages.dev'
    };
    const fakeClient = {
      getDocument: async (path: string) => (path.startsWith('pagos_procesados/') ? { paymentId: '1' } : null),
      setDocument: async () => {},
      updateDocument: async () => {}
    } as any;
    const legWh = await handleLegacyPreapprovalWebhook(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/mercadopago-webhook?data.id=1&type=payment', {
          method: 'POST',
          body: JSON.stringify({ type: 'payment', data: { id: '1' } })
        }),
        env
      },
      {
        verifySignature: async () => ({ isValid: true }),
        hasDbCredentials: () => true,
        getClient: () => fakeClient
      }
    );
    assert.equal(legWh.status, 200);
    assert.equal((await legWh.json()).ignored, true);

    // cancel-subscription bloquea cuentas manual_30d
    const cancelManual = await handleCancelSubscription(
      { request: new Request('https://proyecto-vel.pages.dev/api/cancel-subscription', { method: 'POST' }), env },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'USR_1', email: 'a@b.c', claims: {} }),
        hasDbCredentials: () => true,
        getSubscriber: async () => ({
          uid: 'USR_1',
          email: 'a@b.c',
          estado: 'activo',
          plan: 'Suscripción mensual VEL',
          fechaAlta: '2026-11-01T00:00:00.000Z',
          venceEl: '2026-12-10T00:00:00.000Z',
          modalidadComercial: 'manual_30d'
        })
      }
    );
    assert.equal(cancelManual.status, 400);

    // download-package redirige con vel_pass al sitio Cloudflare
    const dlRes = await handleDownloadPackage(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/download-package', {
          method: 'GET',
          headers: { Origin: 'https://proyecto-vel.blogspot.com', Authorization: 'Bearer tok' }
        }),
        env
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'USR_ACTIVE', email: 'a@b.c', claims: {} }),
        nowProvider: () => new Date('2026-11-24T12:00:00.000Z'),
        getSubscriber: async () => ({
          uid: 'USR_ACTIVE',
          email: 'a@b.c',
          estado: 'activo',
          plan: 'Suscripción mensual VEL',
          fechaAlta: '2026-11-01T00:00:00.000Z',
          venceEl: '2026-12-20T00:00:00.000Z'
        })
      }
    );
    assert.equal(dlRes.status, 302);
    const location = dlRes.headers.get('location') || '';
    assert.ok(location.startsWith('https://proyecto-vel.pages.dev/?vel_pass='));
  });

  await runCheck('10. /api/account (Alta, bloqueo anónimo, vinculación con commercialIdToken y Baja con propagación)', async () => {
    const store = createMemoryDeviceStore();
    const coreKeys = await generateDeviceSpkiAndFingerprint();
    const now = new Date('2026-11-25T10:00:00.000Z');

    const anonDenied = await handleAccountRequest(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/account', {
          method: 'POST',
          headers: { Origin: 'https://proyecto-vel.blogspot.com', Authorization: 'Bearer anon', 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'register' })
        }),
        env: {}
      },
      {
        verifyToken: async () => ({
          authenticated: true,
          uid: 'ANON_UID',
          email: '',
          claims: { firebase: { sign_in_provider: 'anonymous' } }
        }),
        hasDbCredentials: () => true,
        getDeviceStore: () => store
      }
    );
    assert.equal(anonDenied.status, 403);
    assert.equal((await anonDenied.json()).code, 'ANONYMOUS_NOT_ALLOWED');

    const altaRes = await handleAccountRequest(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/account', {
          method: 'POST',
          headers: { Origin: 'https://proyecto-vel.blogspot.com', Authorization: 'Bearer email-tok', 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'register' })
        }),
        env: {}
      },
      {
        verifyToken: async () => ({
          authenticated: true,
          uid: 'USR_UNICO_1',
          email: 'unico@vel.test',
          claims: { firebase: { sign_in_provider: 'emailLink' } }
        }),
        hasDbCredentials: () => true,
        getDeviceStore: () => store,
        nowProvider: () => now
      }
    );
    assert.equal(altaRes.status, 201);
    assert.equal(altaRes.headers.get('access-control-allow-origin'), 'https://proyecto-vel.blogspot.com');

    await handleRegisterDevice(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/register-device', {
          method: 'POST',
          headers: { Authorization: 'Bearer dev-tok', 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deviceId: 'VEL-CORE-AABBCCDDEEFF',
            role: 'CORE',
            publicKeySpkiBase64: coreKeys.spkiBase64,
            signingPublicKeySpkiBase64: coreKeys.signingSpkiBase64,
            fingerprint: coreKeys.fingerprint
          })
        }),
        env: {}
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'ANON_DEV_1', email: '', claims: {} }),
        hasDbCredentials: () => true,
        getDeviceStore: () => store,
        nowProvider: () => now
      }
    );

    const bindRes = await handleDeviceSession(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/device-session', {
          method: 'POST',
          headers: { Authorization: 'Bearer dev-tok', 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'bind_subscription',
            deviceId: 'VEL-CORE-AABBCCDDEEFF',
            commercialIdToken: 'commercial-email-tok'
          })
        }),
        env: {}
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'ANON_DEV_1', email: '', claims: {} }),
        verifyCommercialToken: async () => ({
          authenticated: true,
          uid: 'USR_UNICO_1',
          email: 'unico@vel.test',
          claims: { firebase: { sign_in_provider: 'emailLink' } }
        }),
        hasDbCredentials: () => true,
        getDeviceStore: () => store,
        nowProvider: () => now
      }
    );
    assert.equal(bindRes.status, 200);
    assert.equal((await bindRes.json()).device.subscriptionUid, 'USR_UNICO_1');

    const bajaRes = await handleAccountRequest(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/account', {
          method: 'DELETE',
          headers: { Origin: 'https://proyecto-vel.pages.dev', Authorization: 'Bearer email-tok', 'Content-Type': 'application/json' },
          body: JSON.stringify({ confirmText: 'ELIMINAR CUENTA' })
        }),
        env: {}
      },
      {
        verifyToken: async () => ({
          authenticated: true,
          uid: 'USR_UNICO_1',
          email: 'unico@vel.test',
          claims: { firebase: { sign_in_provider: 'emailLink' } }
        }),
        hasDbCredentials: () => true,
        getDeviceStore: () => store,
        deleteAuthUser: async () => ({ deleted: true }),
        nowProvider: () => now
      }
    );
    assert.equal(bajaRes.status, 200);
    const bajaBody = await bajaRes.json();
    assert.equal(bajaBody.accountDeactivated, true);
    assert.deepEqual(bajaBody.revokedDeviceIds, ['VEL-CORE-AABBCCDDEEFF']);
    assert.equal(bajaBody.authAccountDeleted, true);
  });

  console.log(`\n====================================================`);
  console.log(`RESULTADO CLOUDFLARE: ${passed}/${total} pruebas superadas.`);
  console.log(`====================================================`);
}

main();
