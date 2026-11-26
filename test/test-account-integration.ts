import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import WebSocket from 'ws';
import {
  AuthorizationRecord,
  DeviceLinkRecord,
  DeviceRecord,
  LocalDeviceIdentityRecord,
  VelIncomingChunkRecord,
  VelVaultItemRecord
} from '../src/contracts/velContracts';
import { VelUnifiedStorageAdapter } from '../src/db/db';
import { VelLocalStore } from '../src/db/velLocalStore';
import {
  bindCommercialAccountToDevice,
  fetchCommercialAccountStatus,
  registerCommercialAccount,
  requestAccountDeactivation,
  setupNewDeviceIdentity
} from '../src/services/deviceIdentityService';
import { VelRelayClient } from '../src/services/relayClient';
import { VelTransferManager } from '../src/services/transferManager';
import { handleAccountRequest } from '../functions/api/account';
import { handleRegisterDevice } from '../functions/api/register-device';
import { handleDeviceSession } from '../functions/api/device-session';
import { handleCreatePreference } from '../functions/api/create-preference';
import {
  DeviceTransactionContext,
  DeviceTransactionStore
} from '../cloudflare/shared/deviceAuthService';
import {
  clearOAuthTokenCacheForTests,
  deleteFirebaseAuthUser
} from '../cloudflare/shared/firebaseRest';
import type { CloudflareEnv, SuscriptorAdminRecord } from '../cloudflare/shared/types';
import { VelRelayServer } from '../server-vel/relay-server';

let passed = 0;
let total = 0;

async function check(name: string, fn: () => Promise<void> | void) {
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

async function waitFor(predicate: () => boolean, timeoutMs = 4000, label = 'condición') {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error(`Timeout (${timeoutMs}ms): ${label}`);
}

function createStorageStub(): VelUnifiedStorageAdapter & { items: Map<string, VelVaultItemRecord> } {
  let identity: LocalDeviceIdentityRecord | null = null;
  const config = new Map<string, any>();
  const auths = new Map<string, AuthorizationRecord>();
  const links = new Map<string, DeviceLinkRecord>();
  const items = new Map<string, VelVaultItemRecord>();
  const chunks = new Map<string, VelIncomingChunkRecord>();

  return {
    items,
    async getIdentity() {
      return identity;
    },
    async saveIdentity(record) {
      identity = { ...record };
    },
    async clearIdentity() {
      identity = null;
    },
    async getConfig<T>(key: string) {
      return config.has(key) ? (config.get(key) as T) : null;
    },
    async setConfig(key: string, value: unknown) {
      config.set(key, value);
    },
    async deleteConfig(key: string) {
      config.delete(key);
    },
    async getAuthorization(id: string) {
      return auths.get(id) || null;
    },
    async saveAuthorization(record: AuthorizationRecord) {
      auths.set(record.authorizationId, { ...record });
    },
    async getLink(id: string) {
      return links.get(id) || null;
    },
    async saveLink(record: DeviceLinkRecord) {
      links.set(record.linkId, { ...record });
    },
    async putItem(record) {
      items.set(record.id, { ...record });
    },
    async getItem(id) {
      return items.get(id) || null;
    },
    async getAllItems() {
      return Array.from(items.values());
    },
    async deleteItem(id) {
      items.delete(id);
    },
    async putIncomingChunk(record) {
      chunks.set(record.chunkKey, { ...record });
    },
    async getIncomingChunksByItemId(itemId) {
      return Array.from(chunks.values())
        .filter((c) => c.itemId === itemId)
        .sort((a, b) => a.chunkIndex - b.chunkIndex);
    },
    async deleteIncomingChunksByItemId(itemId) {
      let n = 0;
      for (const [k, c] of chunks.entries()) {
        if (c.itemId === itemId) {
          chunks.delete(k);
          n++;
        }
      }
      return n;
    },
    async close() {}
  };
}

function createUnifiedMemoryDb() {
  const devices = new Map<string, DeviceRecord>();
  const links = new Map<string, DeviceLinkRecord>();
  const authorizations = new Map<string, AuthorizationRecord>();
  const subscribers = new Map<string, SuscriptorAdminRecord>();
  const acceptedContracts = new Set<string>();

  const store: DeviceTransactionStore = {
    async runTransaction<T>(fn: (ctx: DeviceTransactionContext) => Promise<T>): Promise<T> {
      const ctx: DeviceTransactionContext = {
        async getDevice(id) {
          const d = devices.get(id);
          return d ? { ...d } : null;
        },
        createDevice(rec) {
          devices.set(rec.deviceId, { ...rec });
        },
        updateDevice(id, patch) {
          const cur = devices.get(id);
          if (cur) devices.set(id, { ...cur, ...patch });
        },
        async getLink(id) {
          const l = links.get(id);
          return l ? { ...l } : null;
        },
        createLink(rec) {
          links.set(rec.linkId, { ...rec });
        },
        updateLink(id, patch) {
          const cur = links.get(id);
          if (cur) links.set(id, { ...cur, ...patch });
        },
        async getAuthorizationByLink(id) {
          const a = authorizations.get(id);
          return a ? { ...a } : null;
        },
        createAuthorization(rec) {
          authorizations.set(rec.authorizationId, { ...rec });
        },
        updateAuthorization(id, patch) {
          const cur = authorizations.get(id);
          if (cur) authorizations.set(id, { ...cur, ...patch });
        },
        async getSubscriberInTx(uid) {
          const s = subscribers.get(uid);
          return s ? { ...s } : null;
        },
        async findSubscribersByEmailInTx(email) {
          const norm = email.trim().toLowerCase();
          return Array.from(subscribers.values())
            .filter((s) => s.email.trim().toLowerCase() === norm)
            .map((s) => ({ ...s }));
        },
        setSubscriberInTx(uid, record, merge) {
          const cur = subscribers.get(uid);
          subscribers.set(uid, merge && cur ? ({ ...cur, ...record } as SuscriptorAdminRecord) : ({ ...record } as SuscriptorAdminRecord));
        },
        async findDevicesBySubscriptionUidInTx(subscriptionUid) {
          return Array.from(devices.values())
            .filter((d) => d.subscriptionUid === subscriptionUid)
            .map((d) => ({ ...d }));
        }
      };
      return fn(ctx);
    },
    async getSubscriber(uid) {
      const s = subscribers.get(uid);
      return s ? { ...s } : null;
    },
    async updateSubscriberStatus(uid, patch) {
      const cur = subscribers.get(uid);
      if (cur) subscribers.set(uid, { ...cur, ...patch });
    },
    async listDevicesBySubscriptionUid(subscriptionUid) {
      return Array.from(devices.values())
        .filter((d) => d.subscriptionUid === subscriptionUid)
        .map((d) => ({ ...d }));
    },
    async hasAcceptedContract(uid, version) {
      return acceptedContracts.has(`${uid}:${version}`);
    }
  };

  return { store, devices, links, authorizations, subscribers, acceptedContracts };
}

async function main() {
  console.log('====================================================================');
  console.log('VEL 0.1 — INTEGRACIÓN DE CUENTAS, ALTA/BAJA Y PROPAGACIÓN COMPLETA');
  console.log('====================================================================\n');

  const env: CloudflareEnv = {
    APP_BASE_URL: 'https://proyecto-vel.pages.dev',
    VEL_ACTIVATION_SECRET: 'vel_account_integration_secret_01'
  };

  const verifyUnifiedToken = async (authHeader?: string) => {
    const raw = String(authHeader || '').replace(/^Bearer\s+/i, '').trim();
    if (raw === 'commercial-user-1') {
      return {
        authenticated: true as const,
        uid: 'USR_UNICO_A',
        email: 'titular@vel.test',
        claims: { firebase: { sign_in_provider: 'emailLink' } }
      };
    }
    if (raw === 'commercial-user-dup-email') {
      return {
        authenticated: true as const,
        uid: 'USR_DUPLICADO_B',
        email: 'TITULAR@vel.test',
        claims: { firebase: { sign_in_provider: 'password' } }
      };
    }
    if (raw.startsWith('device-')) {
      const uid = raw.replace('device-', '');
      return {
        authenticated: true as const,
        uid,
        email: '',
        claims: { firebase: { sign_in_provider: 'anonymous' } }
      };
    }
    return {
      authenticated: false as const,
      reason: 'invalid_token' as const,
      message: 'Token inválido.'
    };
  };

  let mpCancelCalls: string[] = [];
  let mpCancelShouldFail = false;
  let deletedAuthUids: string[] = [];
  let deleteAuthShouldFail = false;

  const db = createUnifiedMemoryDb();

  const makeFetchAdapter = () => {
    return (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method || 'GET').toUpperCase();
      const headers = (init?.headers || {}) as Record<string, string>;
      const body = typeof init?.body === 'string' ? init.body : undefined;

      if (url.startsWith('/api/account')) {
        return handleAccountRequest(
          {
            request: new Request(`https://proyecto-vel.pages.dev${url}`, { method, headers, body }),
            env
          },
          {
            verifyToken: verifyUnifiedToken,
            hasDbCredentials: () => true,
            getDeviceStore: () => db.store,
            cancelMpPreapproval: async (preId) => {
              mpCancelCalls.push(preId);
              if (mpCancelShouldFail) {
                return { success: false, error: 'MP gateway unreachable' };
              }
              return { success: true };
            },
            deleteAuthUser: async (uid) => {
              if (deleteAuthShouldFail) {
                return { deleted: false, error: 'IdentityToolkit permission denied' };
              }
              deletedAuthUids.push(uid);
              return { deleted: true };
            }
          }
        );
      }
      if (url.startsWith('/api/register-device')) {
        return handleRegisterDevice(
          {
            request: new Request(`https://proyecto-vel.pages.dev${url}`, { method, headers, body }),
            env
          },
          {
            verifyToken: verifyUnifiedToken,
            hasDbCredentials: () => true,
            getDeviceStore: () => db.store
          }
        );
      }
      if (url.startsWith('/api/device-session')) {
        return handleDeviceSession(
          {
            request: new Request(`https://proyecto-vel.pages.dev${url}`, { method, headers, body }),
            env
          },
          {
            verifyToken: verifyUnifiedToken,
            verifyCommercialToken: verifyUnifiedToken,
            hasDbCredentials: () => true,
            getDeviceStore: () => db.store
          }
        );
      }
      throw new Error(`Endpoint inesperado: ${url}`);
    }) as typeof fetch;
  };

  const fetchAdapter = makeFetchAdapter();

  await check('1. Misma identidad Firebase (Blogger <-> VEL): Alta idempotente y bloqueo estricto de correo duplicado / anónimo', async () => {
    const anonRes = await registerCommercialAccount('device-anon_only', { fetchFn: fetchAdapter });
    assert.equal(anonRes.success, false);
    assert.equal(anonRes.code, 'ANONYMOUS_NOT_ALLOWED');

    const alta1 = await registerCommercialAccount('commercial-user-1', { fetchFn: fetchAdapter });
    assert.equal(alta1.success, true);
    assert.equal(alta1.account?.uid, 'USR_UNICO_A');
    assert.equal(alta1.account?.email, 'titular@vel.test');
    assert.equal(alta1.account?.estado, 'pendiente_pago');

    const alta2 = await registerCommercialAccount('commercial-user-1', { fetchFn: fetchAdapter });
    assert.equal(alta2.success, true);
    assert.equal(db.subscribers.size, 1);

    const dupEmailRes = await registerCommercialAccount('commercial-user-dup-email', { fetchFn: fetchAdapter });
    assert.equal(dupEmailRes.success, false);
    assert.equal(dupEmailRes.code, 'DUPLICATE_ACCOUNT_EMAIL');
    assert.equal(db.subscribers.size, 1);
  });

  const coreStorage = createStorageStub();
  const movStorage = createStorageStub();

  await check('2. Vinculación de dispositivos CORE + MÓVIL con la cuenta única Firebase + transferencia E2EE en bóveda local', async () => {
    db.subscribers.set('USR_UNICO_A', {
      ...db.subscribers.get('USR_UNICO_A')!,
      estado: 'activo',
      plan: 'Suscripción mensual VEL',
      venceEl: new Date(Date.now() + 20 * 86_400_000).toISOString(),
      mpPreapprovalId: 'PREAPP_REAL_999'
    });
    db.acceptedContracts.add('USR_UNICO_A:1.2');

    await setupNewDeviceIdentity('CORE', undefined, {
      storage: coreStorage,
      ensureAnonymousAuth: async () => ({ success: true, uid: 'anon_core_acc', idToken: 'device-anon_core_acc' }),
      fetchFn: fetchAdapter
    });
    await setupNewDeviceIdentity('TERMINAL', undefined, {
      storage: movStorage,
      ensureAnonymousAuth: async () => ({ success: true, uid: 'anon_mov_acc', idToken: 'device-anon_mov_acc' }),
      fetchFn: fetchAdapter
    });

    const bindCore = await bindCommercialAccountToDevice('commercial-user-1', {
      storage: coreStorage,
      getFreshToken: async () => 'device-anon_core_acc',
      fetchFn: fetchAdapter
    });
    assert.equal(bindCore.success, true);
    assert.equal(bindCore.identity?.subscriptionUid, 'USR_UNICO_A');
    assert.equal(bindCore.subscriptionStatus?.active, true);

    const status = await fetchCommercialAccountStatus('commercial-user-1', { fetchFn: fetchAdapter });
    assert.equal(status.success, true);
    assert.equal(status.account?.contratoV12Aceptado, true);
    assert.equal(status.devices?.length, 1);
  });

  const testStorageDir = path.join(process.cwd(), 'server-vel', 'test-data-account');
  if (fs.existsSync(testStorageDir)) fs.rmSync(testStorageDir, { recursive: true, force: true });

  const server = new VelRelayServer({
    port: 0,
    storageDir: testStorageDir,
    deviceStore: db.store as any,
    verifyToken: verifyUnifiedToken as any,
    hasDbCredentials: () => true,
    heartbeatIntervalMs: 60_000,
    authTimeoutMs: 5_000
  });
  const port = await server.start();
  const wssUrl = `ws://127.0.0.1:${port}`;

  const coreClient = new VelRelayClient({
    storage: coreStorage,
    getFirebaseIdToken: async () => 'device-anon_core_acc',
    fetchFn: fetchAdapter,
    WebSocketImpl: WebSocket
  });
  const movClient = new VelRelayClient({
    storage: movStorage,
    getFirebaseIdToken: async () => 'device-anon_mov_acc',
    fetchFn: fetchAdapter,
    WebSocketImpl: WebSocket
  });
  const coreMgr = new VelTransferManager({
    relayClient: coreClient,
    role: 'CORE',
    store: new VelLocalStore(coreStorage)
  });
  const movMgr = new VelTransferManager({
    relayClient: movClient,
    role: 'TERMINAL',
    store: new VelLocalStore(movStorage)
  });

  await check('3. Emparejamiento y envío real antes de la Baja conserva copia en VEL CORE', async () => {
    coreClient.connect(wssUrl);
    movClient.connect(wssUrl);
    await waitFor(
      () => coreClient.getState() === 'AUTHENTICATED' && movClient.getState() === 'AUTHENTICATED',
      3500,
      'Relay auth'
    );

    const offer = coreClient.startCorePairingOffer()!;
    movClient.claimPairingCode(offer.code);
    await waitFor(
      () => coreClient.getState() === 'LINKED' && movClient.getState() === 'LINKED',
      3500,
      'Relay link'
    );

    await movMgr.addNote('Respaldo previo a baja', 'Este archivo es estrictamente local del usuario');
    await waitFor(
      () => coreMgr.getSnapshot().items.length === 1 && movMgr.getSnapshot().items[0].syncStatus === 'synced',
      4000,
      'Transferencia a CORE'
    );
  });

  await check('4. Baja exige confirmación textual y NO comete baja parcial si falla cancelación en Mercado Pago', async () => {
    const missingConfirm = await requestAccountDeactivation('commercial-user-1', 'SI', {
      storage: coreStorage,
      fetchFn: fetchAdapter
    });
    assert.equal(missingConfirm.success, false);
    assert.equal(missingConfirm.code, 'CONFIRMATION_REQUIRED');

    mpCancelShouldFail = true;
    const mpFailRes = await requestAccountDeactivation('commercial-user-1', 'ELIMINAR CUENTA', {
      storage: coreStorage,
      fetchFn: fetchAdapter
    });
    assert.equal(mpFailRes.success, false);
    assert.equal(mpFailRes.code, 'MP_CANCELLATION_FAILED');
    assert.equal(db.subscribers.get('USR_UNICO_A')?.estado, 'activo');
    mpCancelShouldFail = false;
  });

  await check('5. Baja reporta honestamente si falla eliminación en Firebase Auth sin ocultar error ni borrar bóveda local', async () => {
    deleteAuthShouldFail = true;
    const res = await requestAccountDeactivation('commercial-user-1', 'ELIMINAR CUENTA', {
      storage: coreStorage,
      fetchFn: fetchAdapter
    });
    assert.equal(res.success, true);
    assert.equal(res.accountDeactivated, true);
    assert.equal(res.mpSubscriptionCancelled, true);
    assert.equal(mpCancelCalls.includes('PREAPP_REAL_999'), true);
    assert.equal(res.authAccountDeleted, false);
    assert.ok(res.authPropagationError?.includes('IdentityToolkit'));

    assert.equal(db.subscribers.get('USR_UNICO_A')?.estado, 'cancelado');
    assert.ok(db.subscribers.get('USR_UNICO_A')?.bajaSolicitadaEl);

    const coreDevId = (await coreStorage.getIdentity())!.deviceId;
    const movDevId = (await movStorage.getIdentity())!.deviceId;
    assert.equal(db.devices.get(coreDevId)?.status, 'revoked');
    assert.equal(db.devices.get(movDevId)?.status, 'revoked');
    assert.equal(coreMgr.getSnapshot().items.length, 1);
  });

  await check('6. Relay bloquea dispositivos tras Baja y /api/create-preference rechaza cuenta dada de baja', async () => {
    coreClient.disconnect();
    movClient.disconnect();

    const blockedRecon = await new Promise<boolean>((resolve) => {
      const c = new VelRelayClient({
        storage: movStorage,
        getFirebaseIdToken: async () => 'device-anon_mov_acc',
        fetchFn: fetchAdapter,
        WebSocketImpl: WebSocket
      });
      const unsub = c.onStateChange((st) => {
        if (st === 'REVOKED') {
          unsub();
          c.disconnect();
          resolve(true);
        }
      });
      c.connect(wssUrl);
      setTimeout(() => resolve(false), 3000);
    });
    assert.equal(blockedRecon, true);

    const prefBlocked = await handleCreatePreference(
      {
        request: new Request('https://proyecto-vel.pages.dev/api/create-preference', {
          method: 'POST',
          headers: {
            Origin: 'https://proyecto-vel.blogspot.com',
            Authorization: 'Bearer commercial-user-1',
            'Content-Type': 'application/json'
          },
          body: '{}'
        }),
        env
      },
      {
        verifyToken: verifyUnifiedToken,
        getPricing: async () => ({
          monto: 4500,
          moneda: 'ARS',
          periodicidad: 'mensual',
          actualizadoEl: '2026-11-01T00:00:00.000Z'
        }),
        getSubscriber: async (uid) => db.subscribers.get(uid) || null
      }
    );
    assert.equal(prefBlocked.status, 403);
    assert.equal((await prefBlocked.json()).code, 'ACCOUNT_DEACTIVATED');
  });

  await check('7. Eliminación real en Firebase Auth (handleAccountRequest -> deleteFirebaseAuthUser -> OAuth2 JWT + accounts:delete)', async () => {
    clearOAuthTokenCacheForTests();
    const { privateKey: rsaPrivatePem } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' }
    });

    const realAuthEnv: CloudflareEnv = {
      ...env,
      FIREBASE_PROJECT_ID: 'proyecto-vel',
      FIREBASE_SERVICE_ACCOUNT: JSON.stringify({
        type: 'service_account',
        project_id: 'proyecto-vel',
        client_email: 'firebase-adminsdk-vel@proyecto-vel.iam.gserviceaccount.com',
        private_key: rsaPrivatePem
      })
    };

    db.subscribers.set('USR_REAL_AUTH_DEL', {
      uid: 'USR_REAL_AUTH_DEL',
      email: 'real-delete@vel.test',
      estado: 'activo',
      plan: 'Suscripción mensual VEL',
      fechaAlta: new Date().toISOString(),
      venceEl: new Date(Date.now() + 15 * 86_400_000).toISOString()
    });

    const capturedCalls: Array<{ url: string; method: string; headers: Record<string, string>; body: string }> = [];
    const originalFetch = globalThis.fetch;

    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method || 'GET').toUpperCase();
        const hdrsObj: Record<string, string> = {};
        if (init?.headers instanceof Headers) {
          init.headers.forEach((v, k) => {
            hdrsObj[k.toLowerCase()] = v;
          });
        } else if (init?.headers && typeof init.headers === 'object') {
          for (const [k, v] of Object.entries(init.headers as Record<string, string>)) {
            hdrsObj[k.toLowerCase()] = String(v);
          }
        }
        const bodyStr = typeof init?.body === 'string' ? init.body : '';
        capturedCalls.push({ url, method, headers: hdrsObj, body: bodyStr });

        if (url === 'https://oauth2.googleapis.com/token') {
          return new Response(
            JSON.stringify({ access_token: 'ya29.real_oauth_service_token', expires_in: 3600, token_type: 'Bearer' }),
            { status: 200, headers: { 'Content-Type': 'application/json' } }
          );
        }

        if (url === 'https://identitytoolkit.googleapis.com/v1/projects/proyecto-vel/accounts:delete') {
          return new Response(JSON.stringify({ kind: 'identitytoolkit#DeleteAccountResponse' }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          });
        }

        return new Response(JSON.stringify({ error: { message: `URL inesperada: ${url}` } }), { status: 404 });
      }) as typeof fetch;

      // Invoca handleAccountRequest SIN stub de deleteAuthUser para recorrer el camino real completo
      const resp = await handleAccountRequest(
        {
          request: new Request('https://proyecto-vel.pages.dev/api/account', {
            method: 'DELETE',
            headers: {
              Origin: 'https://proyecto-vel.blogspot.com',
              Authorization: 'Bearer commercial-real-del-user',
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ confirmText: 'ELIMINAR CUENTA' })
          }),
          env: realAuthEnv
        },
        {
          verifyToken: async (hdr) => {
            assert.equal(hdr, 'Bearer commercial-real-del-user');
            return {
              authenticated: true as const,
              uid: 'USR_REAL_AUTH_DEL',
              email: 'real-delete@vel.test',
              claims: { firebase: { sign_in_provider: 'emailLink' } }
            };
          },
          getDeviceStore: () => db.store
        }
      );

      assert.equal(resp.status, 200);
      const payload = await resp.json();
      assert.equal(payload.success, true);
      assert.equal(payload.accountDeactivated, true);
      assert.equal(payload.authAccountDeleted, true);
      assert.equal(payload.authPropagationError, null);

      assert.equal(capturedCalls.length, 2);

      // 1. Validar intercambio OAuth2 de cuenta de servicio y scopes
      const oauthCall = capturedCalls[0];
      assert.equal(oauthCall.url, 'https://oauth2.googleapis.com/token');
      assert.equal(oauthCall.method, 'POST');
      const formParams = new URLSearchParams(oauthCall.body);
      assert.equal(formParams.get('grant_type'), 'urn:ietf:params:oauth:grant-type:jwt-bearer');
      const jwtParts = String(formParams.get('assertion') || '').split('.');
      assert.equal(jwtParts.length, 3);
      const jwtClaims = JSON.parse(Buffer.from(jwtParts[1], 'base64url').toString('utf8'));
      assert.equal(jwtClaims.iss, 'firebase-adminsdk-vel@proyecto-vel.iam.gserviceaccount.com');
      assert.equal(jwtClaims.aud, 'https://oauth2.googleapis.com/token');
      const grantedScopes = String(jwtClaims.scope || '').split(/\s+/);
      assert.equal(grantedScopes.includes('https://www.googleapis.com/auth/cloud-platform'), true);
      assert.equal(grantedScopes.includes('https://www.googleapis.com/auth/identitytoolkit'), true);

      // 2. Validar endpoint REST oficial accounts:delete, token OAuth2 Bearer (no ID token) y body localId
      const deleteCall = capturedCalls[1];
      assert.equal(
        deleteCall.url,
        'https://identitytoolkit.googleapis.com/v1/projects/proyecto-vel/accounts:delete'
      );
      assert.equal(deleteCall.method, 'POST');
      assert.equal(deleteCall.headers['authorization'], 'Bearer ya29.real_oauth_service_token');
      assert.notEqual(deleteCall.headers['authorization'], 'Bearer commercial-real-del-user');
      assert.equal(deleteCall.headers['content-type'], 'application/json');
      assert.deepEqual(JSON.parse(deleteCall.body), { localId: 'USR_REAL_AUTH_DEL' });

      // 3. Validar idempotencia ante USER_NOT_FOUND y reporte honesto ante error de permisos
      const notFoundRes = await deleteFirebaseAuthUser(
        realAuthEnv,
        'USR_YA_ELIMINADO',
        (async () =>
          new Response(
            JSON.stringify({
              error: { code: 400, message: 'USER_NOT_FOUND', errors: [{ message: 'USER_NOT_FOUND' }] }
            }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          )) as typeof fetch
      );
      assert.equal(notFoundRes.deleted, true);

      const deniedRes = await deleteFirebaseAuthUser(
        realAuthEnv,
        'USR_PERM_ERR',
        (async () =>
          new Response(
            JSON.stringify({
              error: { code: 403, message: 'PERMISSION_DENIED: Caller does not have permission firebaseauth.users.delete' }
            }),
            { status: 403, headers: { 'Content-Type': 'application/json' } }
          )) as typeof fetch
      );
      assert.equal(deniedRes.deleted, false);
      assert.ok(deniedRes.error?.includes('PERMISSION_DENIED'));
    } finally {
      globalThis.fetch = originalFetch;
      clearOAuthTokenCacheForTests();
    }
  });

  coreMgr.dispose();
  movMgr.dispose();
  coreClient.disconnect();
  movClient.disconnect();
  await server.stop();
  if (fs.existsSync(testStorageDir)) fs.rmSync(testStorageDir, { recursive: true, force: true });

  console.log(`\n====================================================================`);
  console.log(`RESULTADO CUENTAS Y PROPAGACIÓN: ${passed}/${total} pruebas superadas.`);
  console.log(`====================================================================`);
}

main().catch((err) => {
  console.error('Error fatal en test-account-integration:', err);
  process.exit(1);
});
