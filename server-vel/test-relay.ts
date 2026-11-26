import WebSocket from 'ws';
import fs from 'fs';
import path from 'path';
import { VelRelayServer } from './relay-server';
import {
  AuthorizationRecord,
  DeviceLinkRecord,
  DeviceRecord,
  SuscriptorAdminRecord
} from '../netlify/functions/shared/types';
import {
  DeviceTransactionContext,
  DeviceTransactionStore
} from '../netlify/functions/shared/deviceAuthService';
import {
  generateDeviceCryptoMaterial,
  generateRandomDeviceId
} from '../src/crypto/deviceCrypto';

function withTimeout<T>(promise: Promise<T>, ms: number, errorMsg: string): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Timeout (${ms}ms): ${errorMsg}`)), ms);
  });
  return Promise.race([promise, timeoutPromise]).finally(() => clearTimeout(timer));
}

function createMemoryDeviceStore() {
  const devices = new Map<string, DeviceRecord>();
  const links = new Map<string, DeviceLinkRecord>();
  const authorizations = new Map<string, AuthorizationRecord>();
  const subscribers = new Map<string, SuscriptorAdminRecord>();

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
        }
      };
      return fn(ctx);
    },
    async getSubscriber(uid) {
      const sub = subscribers.get(uid);
      return sub ? { ...sub } : null;
    },
    async updateSubscriberStatus(uid, patch) {
      const sub = subscribers.get(uid);
      if (sub) subscribers.set(uid, { ...sub, ...patch });
    }
  };

  return { store, devices, links, authorizations, subscribers };
}

async function authenticateDirectSocket(
  serverUrl: string,
  device: DeviceRecord,
  token: string,
  pairedCoreId?: string | null,
  headers?: Record<string, string>
): Promise<WebSocket> {
  const ws = new WebSocket(serverUrl, headers ? { headers } : undefined);
  await withTimeout(
    new Promise<void>((resolve, reject) => {
      ws.on('message', (raw) => {
        const msg = JSON.parse(raw.toString());
        if (msg.type === 'AUTH_CHALLENGE') {
          ws.send(
            JSON.stringify({
              type: 'AUTH',
              deviceId: device.deviceId,
              role: device.role,
              pairedCoreId: pairedCoreId ?? null,
              firebaseIdToken: token,
              timestamp: Date.now()
            })
          );
        } else if (msg.type === 'AUTH_SUCCESS') {
          resolve();
        } else if (msg.type === 'AUTH_ERROR') {
          reject(new Error(`AUTH_ERROR: ${msg.error}`));
        }
      });
      ws.on('error', reject);
    }),
    3000,
    `Autenticación directa de ${device.deviceId}`
  );
  return ws;
}

async function runAllRelayTests() {
  console.log('=== PRUEBAS UNITARIAS DEL SERVIDOR RELAY SIMPLIFICADO (VEL 0.1) ===\n');

  const testDataDir = path.join(process.cwd(), 'server-vel', 'test-data');
  if (fs.existsSync(testDataDir)) {
    fs.rmSync(testDataDir, { recursive: true, force: true });
  }

  const db = createMemoryDeviceStore();
  const verifyToken = async (authHeader?: string) => {
    if (!authHeader?.startsWith('Bearer tok-')) {
      return { authenticated: false as const, reason: 'invalid_token' as const, message: 'Token inválido' };
    }
    return { authenticated: true as const, uid: authHeader.replace('Bearer tok-', '').trim(), email: '' };
  };

  const server = new VelRelayServer({
    port: 0,
    storageDir: testDataDir,
    deviceStore: db.store,
    verifyToken,
    hasDbCredentials: () => true,
    allowedOrigins: ['https://proyecto-vel.netlify.app'],
    heartbeatIntervalMs: 60_000
  });
  const port = await server.start();
  const serverUrl = `ws://127.0.0.1:${port}`;
  const validHeaders = { Origin: 'https://proyecto-vel.netlify.app' };

  const coreMat = await generateDeviceCryptoMaterial('CORE');
  const termMat = await generateDeviceCryptoMaterial('TERMINAL');
  const nowIso = new Date().toISOString();

  const coreRec: DeviceRecord = {
    deviceId: coreMat.deviceId,
    role: 'CORE',
    authUid: 'uid-core-1',
    publicKeySpkiBase64: coreMat.publicKeySpkiBase64,
    signingPublicKeySpkiBase64: coreMat.signingPublicKeySpkiBase64,
    fingerprint: coreMat.fingerprint,
    status: 'registered',
    activeLinkId: null,
    pairedPeerDeviceId: null,
    createdAt: nowIso,
    lastSeenAt: nowIso,
    updatedAt: nowIso,
    revokedAt: null,
    revokedReason: null
  };
  const termRec: DeviceRecord = {
    deviceId: termMat.deviceId,
    role: 'TERMINAL',
    authUid: 'uid-term-1',
    publicKeySpkiBase64: termMat.publicKeySpkiBase64,
    signingPublicKeySpkiBase64: termMat.signingPublicKeySpkiBase64,
    fingerprint: termMat.fingerprint,
    status: 'registered',
    activeLinkId: null,
    pairedPeerDeviceId: null,
    createdAt: nowIso,
    lastSeenAt: nowIso,
    updatedAt: nowIso,
    revokedAt: null,
    revokedReason: null
  };
  db.devices.set(coreRec.deviceId, coreRec);
  db.devices.set(termRec.deviceId, termRec);

  let coreWs: WebSocket | null = null;
  let termWs: WebSocket | null = null;

  try {
    console.log('[PRUEBA 1] Rechazo de origen no autorizado...');
    const badOriginRejected = await new Promise<boolean>((resolve) => {
      const s = new WebSocket(serverUrl, { headers: { Origin: 'https://evil.example.com' } });
      s.on('unexpected-response', (_req, res) => {
        resolve(res.statusCode === 403);
      });
      s.on('error', () => resolve(true));
      s.on('open', () => {
        s.close();
        resolve(false);
      });
    });
    if (!badOriginRejected) throw new Error('Origen no autorizado debió ser rechazado');
    console.log(' -> PASÓ: Origen no autorizado rechazado.');

    console.log('\n[PRUEBA 2] Autenticación directa con Firebase Token y emparejamiento 1-paso de 6 dígitos...');
    coreWs = await authenticateDirectSocket(serverUrl, coreRec, 'tok-uid-core-1', null, validHeaders);
    termWs = await authenticateDirectSocket(serverUrl, termRec, 'tok-uid-term-1', null, validHeaders);

    coreWs.send(
      JSON.stringify({
        type: 'PAIRING_OFFER',
        code: '482910',
        initiatorDeviceId: coreRec.deviceId
      })
    );
    await withTimeout(
      new Promise<void>((resolve) => {
        coreWs!.on('message', (raw) => {
          const d = JSON.parse(raw.toString());
          if (d.type === 'PAIRING_OFFER_REGISTERED') resolve();
        });
      }),
      2000,
      'PAIRING_OFFER_REGISTERED'
    );

    const coreConfirmedPromise = withTimeout(
      new Promise<string>((resolve) => {
        coreWs!.on('message', (raw) => {
          const d = JSON.parse(raw.toString());
          if (d.type === 'PAIRING_CONFIRMED') resolve(d.link.linkId);
        });
      }),
      2000,
      'PAIRING_CONFIRMED en CORE'
    );

    const termConfirmedPromise = withTimeout(
      new Promise<string>((resolve) => {
        termWs!.on('message', (raw) => {
          const d = JSON.parse(raw.toString());
          if (d.type === 'PAIRING_CONFIRMED') resolve(d.link.linkId);
        });
      }),
      2000,
      'PAIRING_CONFIRMED en MÓVIL'
    );

    termWs.send(
      JSON.stringify({
        type: 'PAIRING_CLAIM',
        code: '482910',
        claimerDeviceId: termRec.deviceId
      })
    );

    const [coreLinkId, termLinkId] = await Promise.all([coreConfirmedPromise, termConfirmedPromise]);
    if (!coreLinkId || coreLinkId !== termLinkId || !db.links.has(coreLinkId)) {
      throw new Error('La vinculación en 1 paso no se confirmó o no persistió en Firestore');
    }
    console.log(' -> PASÓ: Código de 6 dígitos conectó CORE y MÓVIL en 1 paso.');

    console.log('\n[PRUEBA 3] Paso directo RELAY_DATA en memoria RAM (cero disco/nube)...');
    const receivedPromise = withTimeout(
      new Promise<any>((resolve) => {
        coreWs!.on('message', (raw) => {
          const d = JSON.parse(raw.toString());
          if (d.type === 'RELAY_DATA') resolve(d);
        });
      }),
      2000,
      'RELAY_DATA en CORE'
    );

    const routedPromise = withTimeout(
      new Promise<any>((resolve) => {
        termWs!.on('message', (raw) => {
          const d = JSON.parse(raw.toString());
          if (d.type === 'MESSAGE_ROUTED' && d.operationId === 'op-note-001') resolve(d);
        });
      }),
      2000,
      'MESSAGE_ROUTED en MÓVIL'
    );

    termWs.send(
      JSON.stringify({
        type: 'RELAY_DATA',
        senderId: termRec.deviceId,
        recipientId: coreRec.deviceId,
        linkId: coreLinkId,
        operationId: 'op-note-001',
        payload: {
          kind: 'note',
          itemId: 'NOTE-123',
          title: 'Nota de prueba',
          textContent: 'Contenido privado entre teléfonos',
          createdAt: Date.now()
        },
        timestamp: Date.now()
      })
    );

    const [relayed, routed] = await Promise.all([receivedPromise, routedPromise]);
    if (
      relayed.payload?.textContent !== 'Contenido privado entre teléfonos' ||
      routed.operationId !== 'op-note-001'
    ) {
      throw new Error('RELAY_DATA no se entregó correctamente');
    }

    if (fs.existsSync(testDataDir)) {
      throw new Error('El servidor Relay no debe crear archivos con contenido de usuario en disco');
    }
    console.log(' -> PASÓ: RELAY_DATA reenviado en memoria sin guardar copias en disco o nube.');

    console.log('\n[PRUEBA 4] Rechazo de /ws/{deviceId} y manejo honesto de RECIPIENT_OFFLINE...');
    const rogueId = generateRandomDeviceId('TERMINAL');
    const pathRejected = await new Promise<boolean>((resolve) => {
      const s = new WebSocket(`${serverUrl}/ws/${rogueId}`, { headers: validHeaders });
      s.on('close', (c) => resolve(c === 4001));
    });
    if (!pathRejected) throw new Error('/ws/{deviceId} debe rechazarse');

    coreWs.close();
    await new Promise((r) => setTimeout(r, 80));

    const offlineResult = await withTimeout(
      new Promise<any>((resolve) => {
        termWs!.on('message', (raw) => {
          const d = JSON.parse(raw.toString());
          if (d.type === 'DELIVERY_FAILED' && d.operationId === 'op-offline-002') resolve(d);
        });
        termWs!.send(
          JSON.stringify({
            type: 'RELAY_DATA',
            senderId: termRec.deviceId,
            recipientId: coreRec.deviceId,
            linkId: coreLinkId,
            operationId: 'op-offline-002',
            payload: {
              kind: 'note',
              itemId: 'NOTE-OFFLINE',
              title: 'Sin CORE',
              textContent: 'No se debe encolar en servidor',
              createdAt: Date.now()
            },
            timestamp: Date.now()
          })
        );
      }),
      2000,
      'DELIVERY_FAILED RECIPIENT_OFFLINE'
    );
    if (offlineResult.reason !== 'RECIPIENT_OFFLINE') {
      throw new Error(`Se esperaba RECIPIENT_OFFLINE, llegó ${offlineResult.reason}`);
    }
    console.log(' -> PASÓ: Ruta heredada rechazada y modo offline reportado sin cola en nube.');

    console.log('\n[PRUEBA 5] Revocación remota y bloqueo persistente tras reinicio...');
    coreWs = await authenticateDirectSocket(serverUrl, coreRec, 'tok-uid-core-1', null, validHeaders);
    coreWs.send(
      JSON.stringify({
        type: 'REVOKE_DEVICE',
        coreId: coreRec.deviceId,
        targetTerminalId: termRec.deviceId,
        reason: 'Prueba revocación'
      })
    );
    await withTimeout(
      new Promise<void>((resolve) => {
        coreWs!.on('message', (raw) => {
          const d = JSON.parse(raw.toString());
          if (d.type === 'REVOCATION_CONFIRMED') resolve();
        });
      }),
      2000,
      'REVOCATION_CONFIRMED'
    );

    coreWs.close();
    termWs.close();
    await server.stop();

    const server2 = new VelRelayServer({
      port: 0,
      storageDir: testDataDir,
      deviceStore: db.store,
      verifyToken,
      hasDbCredentials: () => true,
      allowedOrigins: ['https://proyecto-vel.netlify.app'],
      heartbeatIntervalMs: 60_000
    });
    const port2 = await server2.start();
    const blockedAfterRestart = await new Promise<boolean>((resolve) => {
      const s = new WebSocket(`ws://127.0.0.1:${port2}`, { headers: validHeaders });
      s.on('message', (raw) => {
        const m = JSON.parse(raw.toString());
        if (m.type === 'AUTH_CHALLENGE') {
          s.send(
            JSON.stringify({
              type: 'AUTH',
              deviceId: termRec.deviceId,
              role: 'TERMINAL',
              firebaseIdToken: 'tok-uid-term-1',
              timestamp: Date.now()
            })
          );
        }
      });
      s.on('close', (c) => resolve(c === 4003));
    });
    if (!blockedAfterRestart) throw new Error('Terminal revocado no fue bloqueado tras reinicio');
    await server2.stop();

    console.log('\n[PRUEBA 6] Pausa automática al vencer suscripción mensual y reactivación sin re-emparejar...');
    const subDb = createMemoryDeviceStore();
    const subUid = 'sub-relay-life-1';
    subDb.subscribers.set(subUid, {
      uid: subUid,
      email: 'suscriptor@vel.com',
      estado: 'vencido',
      plan: 'Suscripción mensual VEL',
      modalidadComercial: 'manual_30d',
      fechaAlta: new Date(Date.now() - 31 * 86_400_000).toISOString(),
      venceEl: new Date(Date.now() - 86_400_000).toISOString()
    });

    const coreSubMat = await generateDeviceCryptoMaterial('CORE');
    const termSubMat = await generateDeviceCryptoMaterial('TERMINAL');
    const linkSubId = 'LNK-SUB-TEST-01';
    const subNowIso = new Date().toISOString();

    const subCoreRec: DeviceRecord = {
      deviceId: coreSubMat.deviceId,
      role: 'CORE',
      authUid: 'uid-sub-core',
      publicKeySpkiBase64: coreSubMat.publicKeySpkiBase64,
      signingPublicKeySpkiBase64: coreSubMat.signingPublicKeySpkiBase64,
      fingerprint: coreSubMat.fingerprint,
      status: 'paired',
      activeLinkId: linkSubId,
      pairedPeerDeviceId: termSubMat.deviceId,
      subscriptionUid: subUid,
      createdAt: subNowIso,
      lastSeenAt: subNowIso,
      updatedAt: subNowIso,
      revokedAt: null,
      revokedReason: null
    };
    const subTermRec: DeviceRecord = {
      deviceId: termSubMat.deviceId,
      role: 'TERMINAL',
      authUid: 'uid-sub-term',
      publicKeySpkiBase64: termSubMat.publicKeySpkiBase64,
      signingPublicKeySpkiBase64: termSubMat.signingPublicKeySpkiBase64,
      fingerprint: termSubMat.fingerprint,
      status: 'paired',
      activeLinkId: linkSubId,
      pairedPeerDeviceId: coreSubMat.deviceId,
      subscriptionUid: subUid,
      createdAt: subNowIso,
      lastSeenAt: subNowIso,
      updatedAt: subNowIso,
      revokedAt: null,
      revokedReason: null
    };
    subDb.devices.set(subCoreRec.deviceId, subCoreRec);
    subDb.devices.set(subTermRec.deviceId, subTermRec);
    subDb.links.set(linkSubId, {
      linkId: linkSubId,
      coreDeviceId: subCoreRec.deviceId,
      terminalDeviceId: subTermRec.deviceId,
      coreAuthUid: 'uid-sub-core',
      terminalAuthUid: 'uid-sub-term',
      coreFingerprint: subCoreRec.fingerprint,
      terminalFingerprint: subTermRec.fingerprint,
      subscriptionUid: subUid,
      status: 'active',
      sasVerified: true,
      createdAt: subNowIso,
      activatedAt: subNowIso,
      revokedAt: null,
      revokedByDeviceId: null,
      revocationReason: null
    });
    subDb.authorizations.set(linkSubId, {
      authorizationId: linkSubId,
      linkId: linkSubId,
      coreDeviceId: subCoreRec.deviceId,
      terminalDeviceId: subTermRec.deviceId,
      coreAuthUid: 'uid-sub-core',
      terminalAuthUid: 'uid-sub-term',
      subscriptionUid: subUid,
      status: 'active',
      permissions: ['RELAY_CONNECT', 'E2EE_SESSION', 'SYNC_STATUS', 'REVOKE_PEER'],
      grantedAt: subNowIso,
      revokedAt: null,
      revokedByDeviceId: null,
      lastActivityAt: subNowIso
    });

    const server3 = new VelRelayServer({
      port: 0,
      storageDir: testDataDir,
      deviceStore: subDb.store,
      verifyToken,
      hasDbCredentials: () => true,
      allowedOrigins: ['https://proyecto-vel.netlify.app'],
      heartbeatIntervalMs: 60_000
    });
    const port3 = await server3.start();
    const url3 = `ws://127.0.0.1:${port3}`;

    const sCore = await authenticateDirectSocket(url3, subCoreRec, 'tok-uid-sub-core', null, validHeaders);
    const sTerm = await authenticateDirectSocket(url3, subTermRec, 'tok-uid-sub-term', subCoreRec.deviceId, validHeaders);

    const blockedRes = await withTimeout(
      new Promise<any>((resolve) => {
        sTerm.on('message', (raw) => {
          const d = JSON.parse(raw.toString());
          if (d.type === 'DELIVERY_FAILED' && d.operationId === 'op-sub-expired-1') resolve(d);
        });
        sTerm.send(
          JSON.stringify({
            type: 'RELAY_DATA',
            senderId: subTermRec.deviceId,
            recipientId: subCoreRec.deviceId,
            linkId: linkSubId,
            operationId: 'op-sub-expired-1',
            payload: {
              kind: 'note',
              itemId: 'NOTE-EXP-1',
              title: 'Bloqueada por vencimiento',
              textContent: 'Debe esperar a la renovación',
              createdAt: Date.now()
            },
            timestamp: Date.now()
          })
        );
      }),
      2000,
      'DELIVERY_FAILED SUBSCRIPTION_EXPIRED'
    );
    if (blockedRes.reason !== 'SUBSCRIPTION_EXPIRED') {
      throw new Error(`Se esperaba SUBSCRIPTION_EXPIRED, llegó ${blockedRes.reason}`);
    }

    // Renovar suscripción en el store y reconectar sin re-emparejar
    subDb.subscribers.set(subUid, {
      uid: subUid,
      email: 'suscriptor@vel.com',
      estado: 'activo',
      plan: 'Suscripción mensual VEL',
      modalidadComercial: 'manual_30d',
      fechaAlta: new Date(Date.now() - 31 * 86_400_000).toISOString(),
      venceEl: new Date(Date.now() + 30 * 86_400_000).toISOString()
    });
    sTerm.close();
    const sTermRenewed = await authenticateDirectSocket(url3, subTermRec, 'tok-uid-sub-term', subCoreRec.deviceId, validHeaders);

    const deliveredAfterRenew = await withTimeout(
      new Promise<boolean>((resolve) => {
        sCore.on('message', (raw) => {
          const d = JSON.parse(raw.toString());
          if (d.type === 'RELAY_DATA' && d.operationId === 'op-sub-renewed-2') resolve(true);
        });
        sTermRenewed.send(
          JSON.stringify({
            type: 'RELAY_DATA',
            senderId: subTermRec.deviceId,
            recipientId: subCoreRec.deviceId,
            linkId: linkSubId,
            operationId: 'op-sub-renewed-2',
            payload: {
              kind: 'note',
              itemId: 'NOTE-REN-2',
              title: 'Reactivada',
              textContent: 'Nota entregada tras renovar',
              createdAt: Date.now()
            },
            timestamp: Date.now()
          })
        );
      }),
      2000,
      'Entrega automática tras renovar suscripción'
    );
    if (!deliveredAfterRenew) throw new Error('Relay no reactivó el envío tras renovar suscripción');

    sCore.close();
    sTermRenewed.close();
    await server3.stop();

    if (fs.existsSync(testDataDir)) {
      fs.rmSync(testDataDir, { recursive: true, force: true });
    }
    console.log(' -> PASÓ: Suscripción vencida pausa Relay sin revocar y se reactiva automáticamente al pagar.');
    console.log('\n=== RESULTADO FINAL: TODAS LAS PRUEBAS DE server-vel/test-relay.ts PASARON ===\n');
  } finally {
    try {
      coreWs?.close();
      termWs?.close();
      await server.stop();
    } catch {}
  }
}

runAllRelayTests().catch((err) => {
  console.error('\n[FALLO EN PRUEBA]:', err);
  process.exit(1);
});
