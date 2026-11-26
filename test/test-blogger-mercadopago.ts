import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
  createPreferenceHandler,
  defaultRecordPreferenceIntent
} from '../netlify/functions/create-preference';
import { paymentWebhookHandler } from '../netlify/functions/payment-webhook';
import { downloadPackageHandler } from '../netlify/functions/download-package';
import { createSubscriptionHandler } from '../netlify/functions/create-subscription';
import { legacyPreapprovalWebhookHandler } from '../netlify/functions/mercadopago-webhook';
import { adminPricingHandler } from '../netlify/functions/admin-pricing';
import { registerDeviceHandler } from '../netlify/functions/register-device';
import { deviceSessionHandler } from '../netlify/functions/device-session';
import { verifyMpWebhookSignature } from '../netlify/functions/shared/mercadopago';
import {
  getCurrentPricing,
  initializePricing,
  PricingUnavailableError
} from '../netlify/functions/shared/pricingService';
import {
  AtomicRenewalContext,
  calculateThirtyDayRenewal,
  PaymentTransactionStore,
  THIRTY_DAYS_MS
} from '../netlify/functions/shared/paymentRenewalService';
import {
  createSubscriptionPass,
  evaluateSubscriberAccess,
  verifySubscriptionPass
} from '../netlify/functions/shared/subscriptionAccess';
import {
  DeviceTransactionContext,
  DeviceTransactionStore
} from '../netlify/functions/shared/deviceAuthService';
import {
  AuthorizationRecord,
  DeviceLinkRecord,
  DeviceRecord,
  PagoProcesadoRecord,
  PricingConfig,
  SuscriptorAdminRecord
} from '../netlify/functions/shared/types';
import { generateDeviceCryptoMaterial } from '../src/crypto/deviceCrypto';

let passedTests = 0;
let totalTests = 0;

function assert(condition: boolean, name: string, detail?: string) {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`✓ [PASS] ${name}`);
  } else {
    console.error(`✗ [FAIL] ${name}${detail ? ` -> ${detail}` : ''}`);
  }
}

function createInMemoryPaymentStore(
  initialSubscribers: Record<string, SuscriptorAdminRecord>,
  options: { asyncYieldMs?: number } = {}
): {
  store: PaymentTransactionStore;
  subscribers: Record<string, SuscriptorAdminRecord>;
  processedPayments: Record<string, PagoProcesadoRecord>;
  preferenceStatuses: Record<string, { status: string; paymentId: string }>;
} {
  const subscribers: Record<string, SuscriptorAdminRecord> = JSON.parse(
    JSON.stringify(initialSubscribers)
  );
  const processedPayments: Record<string, PagoProcesadoRecord> = {};
  const preferenceStatuses: Record<string, { status: string; paymentId: string }> = {};

  // Cola secuencial para simular aislamiento serializable de db.runTransaction ante ejecuciones concurrentes
  let txQueue: Promise<void> = Promise.resolve();

  const store: PaymentTransactionStore = {
    async runTransaction<T>(fn: (ctx: AtomicRenewalContext) => Promise<T>): Promise<T> {
      let release!: () => void;
      const previous = txQueue;
      txQueue = new Promise<void>((resolve) => {
        release = resolve;
      });
      await previous;

      try {
        const stagedNewPayments: Record<string, PagoProcesadoRecord> = {};
        const stagedPaymentPatches: Record<string, Partial<PagoProcesadoRecord>> = {};
        const stagedSubPatches: Record<string, Partial<SuscriptorAdminRecord>> = {};
        const stagedPrefMarks: Record<string, { status: string; paymentId: string }> = {};

        const ctx: AtomicRenewalContext = {
          async getProcessedPayment(paymentId: string) {
            if (options.asyncYieldMs) {
              await new Promise((r) => setTimeout(r, options.asyncYieldMs));
            }
            return processedPayments[paymentId] ? { ...processedPayments[paymentId] } : null;
          },
          async getSubscriber(uid: string) {
            return subscribers[uid] ? { ...subscribers[uid] } : null;
          },
          async getSubscriberPayments(uid: string) {
            return Object.values(processedPayments)
              .filter((p) => p.uid === uid)
              .map((p) => ({ ...p }));
          },
          saveProcessedPayment(record: PagoProcesadoRecord) {
            stagedNewPayments[record.paymentId] = { ...record };
          },
          updateProcessedPayment(paymentId: string, patch: Partial<PagoProcesadoRecord>) {
            stagedPaymentPatches[paymentId] = {
              ...(stagedPaymentPatches[paymentId] || {}),
              ...patch
            };
          },
          updateSubscriber(uid: string, patch: Partial<SuscriptorAdminRecord>) {
            stagedSubPatches[uid] = { ...(stagedSubPatches[uid] || {}), ...patch };
          },
          markPreferenceStatus(preferenceId: string, status: 'paid' | 'reverted', paymentId: string) {
            stagedPrefMarks[preferenceId] = { status, paymentId };
          }
        };

        const result = await fn(ctx);

        // Commit atómico en memoria
        for (const [pid, rec] of Object.entries(stagedNewPayments)) {
          processedPayments[pid] = rec;
        }
        for (const [pid, patch] of Object.entries(stagedPaymentPatches)) {
          processedPayments[pid] = { ...processedPayments[pid], ...patch };
        }
        for (const [uid, patch] of Object.entries(stagedSubPatches)) {
          subscribers[uid] = { ...subscribers[uid], ...patch };
        }
        for (const [prefId, info] of Object.entries(stagedPrefMarks)) {
          preferenceStatuses[prefId] = info;
        }

        return result;
      } finally {
        release();
      }
    }
  };

  return { store, subscribers, processedPayments, preferenceStatuses };
}

function signWebhook(secret: string, dataId: string, requestId: string, ts: string): string {
  const manifest = `id:${dataId.toLowerCase()};request-id:${requestId};ts:${ts};`;
  const v1 = crypto.createHmac('sha256', secret).update(manifest).digest('hex');
  return `ts=${ts},v1=${v1}`;
}

async function runTests() {
  console.log('==================================================================');
  console.log('PRUEBAS INTEGRALES VEL 0.1 — CHECKOUT PRO + BLOGGER + FIREBASE');
  console.log('(Ejecutadas con dobles/mocks deterministas; sin cobros reales)');
  console.log('==================================================================\n');

  const currentPricing: PricingConfig = {
    monto: 6500,
    moneda: 'ARS',
    periodicidad: 'mensual',
    actualizadoEl: '2026-11-01T00:00:00.000Z',
    actualizadoPor: 'admin@vel.com'
  };

  const OFFICIAL_ORIGIN = 'https://proyecto-vel.blogspot.com';
  const secret = 'vel_webhook_secret_pruebas_unitarias_001';
  process.env.MP_WEBHOOK_SECRET = secret;
  const fixedNow = new Date('2026-11-10T12:00:00.000Z');
  const fixedTs = String(Math.floor(fixedNow.getTime() / 1000));

  // ------------------------------------------------------------------
  // 1. Alta de un nuevo suscriptor (tarifa vigente + activación)
  // ------------------------------------------------------------------
  {
    const mem = createInMemoryPaymentStore({});
    let capturedParams: any = null;

    const prefRes = await createPreferenceHandler(
      {
        httpMethod: 'POST',
        headers: {
          origin: OFFICIAL_ORIGIN,
          authorization: 'Bearer valid_token_new_user',
          host: 'legendary-pasca-bf280b.netlify.app'
        },
        body: JSON.stringify({
          uid: 'UID_FALSO_MANIPULADO',
          precio: 1,
          estado: 'activo'
        })
      },
      {
        verifyToken: async () => ({
          authenticated: true,
          uid: 'UID_NUEVO_01',
          email: 'nuevo@vel.com'
        }),
        getPricing: async () => currentPricing,
        getSubscriber: async () => null,
        createPreference: async (params) => {
          capturedParams = params;
          return {
            success: true,
            data: {
              id: 'pref_nuevo_01',
              init_point: 'https://www.mercadopago.com.ar/checkout/v1/redirect?pref_id=pref_nuevo_01'
            }
          };
        },
        recordPreferenceIntent: async (uid, email, prefId, eff) => {
          mem.subscribers[uid] = {
            uid,
            email,
            estado: 'pendiente_pago',
            plan: 'Suscripción mensual VEL',
            modalidadComercial: 'manual_30d',
            mpPreferenceId: prefId,
            mpExternalReference: uid,
            ultimaTarifaConsultada: eff.monto,
            moneda: eff.moneda,
            fechaAlta: fixedNow.toISOString(),
            venceEl: null
          };
        }
      }
    );

    const prefBody = JSON.parse(prefRes.body);
    assert(
      prefRes.statusCode === 200 &&
        prefBody.success === true &&
        prefBody.tarifaHistoricaConservada === false &&
        capturedParams?.amount === 6500 &&
        capturedParams?.externalReference === 'UID_NUEVO_01' &&
        mem.subscribers['UID_NUEVO_01'].estado === 'pendiente_pago',
      '1. Alta de nuevo suscriptor crea preferencia a tarifa vigente (6500 ARS), ignora body manipulado y deja estado pendiente_pago'
    );

    const pid = 'pay_alta_01';
    const sig = signWebhook(secret, pid, 'req-alta-1', fixedTs);
    const payRes = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-alta-1' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'approved',
            external_reference: 'UID_NUEVO_01',
            transaction_amount: 6500,
            currency_id: 'ARS',
            date_approved: fixedNow.toISOString(),
            metadata: { circuito: 'checkout_pro', preference_id: 'pref_nuevo_01' }
          }
        })
      }
    );

    const payBody = JSON.parse(payRes.body);
    assert(
      payRes.statusCode === 200 &&
        payBody.grantedDays === 30 &&
        mem.subscribers['UID_NUEVO_01'].estado === 'activo' &&
        mem.subscribers['UID_NUEVO_01'].precioContratado === 6500,
      '1b. Al aprobarse el primer pago, el suscriptor pasa a activo y fija su precioContratado'
    );
  }

  // ------------------------------------------------------------------
  // 2. Conservación de tarifa histórica (no se sobrescribe por tarifa vigente)
  // ------------------------------------------------------------------
  {
    const historicalSub: SuscriptorAdminRecord = {
      uid: 'UID_HISTORICO',
      email: 'historico@vel.com',
      estado: 'activo',
      plan: 'Suscripción mensual VEL',
      modalidadComercial: 'manual_30d',
      fechaAlta: '2026-06-01T00:00:00.000Z',
      fechaUltimoPago: '2026-10-15T12:00:00.000Z',
      venceEl: '2026-11-14T12:00:00.000Z',
      precioContratado: 4500,
      moneda: 'ARS'
    };

    const mem = createInMemoryPaymentStore({ UID_HISTORICO: historicalSub });
    let capturedAmount = 0;

    const prefRes = await createPreferenceHandler(
      {
        httpMethod: 'POST',
        headers: { origin: OFFICIAL_ORIGIN, authorization: 'Bearer valid_hist_token' },
        body: '{}'
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'UID_HISTORICO', email: 'historico@vel.com' }),
        getPricing: async () => currentPricing, // Tarifa global vigente = 6500 ARS
        getSubscriber: async () => mem.subscribers['UID_HISTORICO'],
        createPreference: async (params) => {
          capturedAmount = params.amount;
          return {
            success: true,
            data: { id: 'pref_hist_1', init_point: 'https://www.mercadopago.com.ar/checkout/v1/redirect?pref_id=pref_hist_1' }
          };
        },
        recordPreferenceIntent: async () => {}
      }
    );

    const prefBody = JSON.parse(prefRes.body);
    assert(
      prefRes.statusCode === 200 &&
        capturedAmount === 4500 &&
        prefBody.monto === 4500 &&
        prefBody.tarifaHistoricaConservada === true,
      '2a. Suscriptor existente conserva su tarifa original (4500 ARS) aunque la tarifa vigente haya subido a 6500 ARS'
    );

    const pid = 'pay_hist_renew_1';
    const sig = signWebhook(secret, pid, 'req-hist-1', fixedTs);
    const payRes = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-hist-1' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'approved',
            external_reference: 'UID_HISTORICO',
            transaction_amount: 4500,
            currency_id: 'ARS',
            date_approved: fixedNow.toISOString(),
            metadata: { circuito: 'checkout_pro', preference_id: 'pref_hist_1' }
          }
        })
      }
    );

    assert(
      payRes.statusCode === 200 &&
        mem.subscribers['UID_HISTORICO'].precioContratado === 4500 &&
        mem.subscribers['UID_HISTORICO'].moneda === 'ARS',
      '2b. Webhook aprueba la renovación a tarifa histórica (4500 ARS) y no la reemplaza por la vigente'
    );
  }

  // ------------------------------------------------------------------
  // 3. Renovación anticipada (venceEl > now -> venceEl + 30 días)
  // ------------------------------------------------------------------
  {
    const currentVenceEl = '2026-11-25T12:00:00.000Z';
    const mem = createInMemoryPaymentStore({
      UID_ACTIVA: {
        uid: 'UID_ACTIVA',
        email: 'activa@vel.com',
        estado: 'activo',
        plan: 'Suscripción mensual VEL',
        modalidadComercial: 'manual_30d',
        fechaAlta: '2026-10-25T12:00:00.000Z',
        fechaUltimoPago: '2026-10-26T12:00:00.000Z',
        precioContratado: 6500,
        moneda: 'ARS',
        venceEl: currentVenceEl
      }
    });

    const pid = 'pay_anticipada_1';
    const sig = signWebhook(secret, pid, 'req-ant-1', fixedTs);
    const res = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-ant-1' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'approved',
            external_reference: 'UID_ACTIVA',
            transaction_amount: 6500,
            currency_id: 'ARS',
            date_approved: fixedNow.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    const expected = new Date(Date.parse(currentVenceEl) + THIRTY_DAYS_MS).toISOString();
    assert(
      res.statusCode === 200 && mem.subscribers['UID_ACTIVA'].venceEl === expected,
      '3. Renovación anticipada sobre cuenta activa suma 30 días desde venceEl vigente'
    );
  }

  // ------------------------------------------------------------------
  // 4. Renovación después del vencimiento (venceEl < now -> now + 30 días)
  // ------------------------------------------------------------------
  {
    const expiredVenceEl = '2026-10-01T12:00:00.000Z';
    const mem = createInMemoryPaymentStore({
      UID_VENCIDA: {
        uid: 'UID_VENCIDA',
        email: 'vencida@vel.com',
        estado: 'vencido',
        plan: 'Suscripción mensual VEL',
        modalidadComercial: 'manual_30d',
        fechaAlta: '2026-09-01T12:00:00.000Z',
        fechaUltimoPago: '2026-09-01T12:00:00.000Z',
        precioContratado: 6500,
        moneda: 'ARS',
        venceEl: expiredVenceEl
      }
    });

    const pid = 'pay_vencida_1';
    const sig = signWebhook(secret, pid, 'req-ven-1', fixedTs);
    const res = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-ven-1' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'approved',
            external_reference: 'UID_VENCIDA',
            transaction_amount: 6500,
            currency_id: 'ARS',
            date_approved: fixedNow.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    const expected = new Date(fixedNow.getTime() + THIRTY_DAYS_MS).toISOString();
    assert(
      res.statusCode === 200 &&
        mem.subscribers['UID_VENCIDA'].estado === 'activo' &&
        mem.subscribers['UID_VENCIDA'].venceEl === expected,
      '4. Renovación tras vencimiento suma 30 días desde la fecha actual y reactiva a activo'
    );
  }

  // ------------------------------------------------------------------
  // 5. Pago pendiente (incluyendo Rapipago/Pago Fácil ticket)
  // ------------------------------------------------------------------
  {
    const mem = createInMemoryPaymentStore({
      UID_PENDING: {
        uid: 'UID_PENDING',
        email: 'pending@vel.com',
        estado: 'pendiente_pago',
        plan: 'Suscripción mensual VEL',
        modalidadComercial: 'manual_30d',
        fechaAlta: '2026-11-01T00:00:00.000Z',
        venceEl: null
      }
    });

    const pid = 'pay_pending_1';
    const sig = signWebhook(secret, pid, 'req-pend-1', fixedTs);
    const res = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-pend-1' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'pending',
            payment_method_id: 'rapipago',
            payment_type_id: 'ticket',
            external_reference: 'UID_PENDING',
            transaction_amount: 6500,
            currency_id: 'ARS'
          }
        })
      }
    );

    const body = JSON.parse(res.body);
    assert(
      res.statusCode === 200 &&
        body.grantedDays === 0 &&
        mem.subscribers['UID_PENDING'].estado === 'pendiente_pago' &&
        mem.subscribers['UID_PENDING'].venceEl === null,
      '5. Pago pendiente concede 0 días y no activa ni extiende vigencia'
    );
  }

  // ------------------------------------------------------------------
  // 6. Pago rechazado
  // ------------------------------------------------------------------
  {
    const mem = createInMemoryPaymentStore({
      UID_REJ: {
        uid: 'UID_REJ',
        email: 'rej@vel.com',
        estado: 'pendiente_pago',
        plan: 'Suscripción mensual VEL',
        modalidadComercial: 'manual_30d',
        fechaAlta: '2026-11-01T00:00:00.000Z',
        venceEl: null
      }
    });

    const pid = 'pay_rej_1';
    const sig = signWebhook(secret, pid, 'req-rej-1', fixedTs);
    const res = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-rej-1' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'rejected',
            external_reference: 'UID_REJ',
            transaction_amount: 6500,
            currency_id: 'ARS'
          }
        })
      }
    );

    const body = JSON.parse(res.body);
    assert(
      res.statusCode === 200 &&
        body.grantedDays === 0 &&
        mem.subscribers['UID_REJ'].estado === 'pendiente_pago',
      '6. Pago rechazado concede 0 días y deja intacto al suscriptor'
    );
  }

  // ------------------------------------------------------------------
  // 7. Pago aprobado (Rapipago acreditado tras estar pendiente)
  // ------------------------------------------------------------------
  {
    const mem = createInMemoryPaymentStore({
      UID_RP: {
        uid: 'UID_RP',
        email: 'rp@vel.com',
        estado: 'pendiente_pago',
        plan: 'Suscripción mensual VEL',
        modalidadComercial: 'manual_30d',
        fechaAlta: '2026-11-01T00:00:00.000Z',
        venceEl: null
      }
    });

    const pid = 'pay_rp_1';
    const sig = signWebhook(secret, pid, 'req-rp-1', fixedTs);
    const res = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-rp-1' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'approved',
            payment_method_id: 'rapipago',
            payment_type_id: 'ticket',
            external_reference: 'UID_RP',
            transaction_amount: 6500,
            currency_id: 'ARS',
            date_approved: fixedNow.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    const body = JSON.parse(res.body);
    assert(
      res.statusCode === 200 &&
        body.grantedDays === 30 &&
        mem.subscribers['UID_RP'].estado === 'activo',
      '7. Pago aprobado (Rapipago/Pago Fácil) acredita 30 días y activa la suscripción'
    );
  }

  // ------------------------------------------------------------------
  // 8. Notificación duplicada del mismo pago (idempotencia)
  // ------------------------------------------------------------------
  {
    const mem = createInMemoryPaymentStore({
      UID_DUP: {
        uid: 'UID_DUP',
        email: 'dup@vel.com',
        estado: 'pendiente_pago',
        plan: 'Suscripción mensual VEL',
        modalidadComercial: 'manual_30d',
        fechaAlta: '2026-11-01T00:00:00.000Z',
        venceEl: null
      }
    });

    const pid = 'pay_dup_1';
    const sig = signWebhook(secret, pid, 'req-dup-1', fixedTs);
    const fetchMock = async () => ({
      success: true,
      data: {
        id: pid,
        status: 'approved',
        external_reference: 'UID_DUP',
        transaction_amount: 6500,
        currency_id: 'ARS',
        date_approved: fixedNow.toISOString(),
        metadata: { circuito: 'checkout_pro' }
      }
    });

    await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-dup-1' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => fixedNow,
        fetchPayment: fetchMock
      }
    );
    const firstVence = mem.subscribers['UID_DUP'].venceEl;

    const dupRes = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-dup-1' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => new Date(fixedNow.getTime() + 60_000),
        fetchPayment: fetchMock
      }
    );

    const dupBody = JSON.parse(dupRes.body);
    assert(
      dupRes.statusCode === 200 &&
        dupBody.duplicate === true &&
        dupBody.grantedDays === 0 &&
        mem.subscribers['UID_DUP'].venceEl === firstVence,
      '8. Notificación duplicada del mismo paymentId devuelve duplicate=true y grantedDays=0 sin extender dos veces'
    );
  }

  // ------------------------------------------------------------------
  // 9. Dos pagos diferentes consecutivos (acumulan 60 días exactos)
  // ------------------------------------------------------------------
  {
    const mem = createInMemoryPaymentStore({
      UID_DOS: {
        uid: 'UID_DOS',
        email: 'dos@vel.com',
        estado: 'pendiente_pago',
        plan: 'Suscripción mensual VEL',
        modalidadComercial: 'manual_30d',
        fechaAlta: '2026-10-01T00:00:00.000Z',
        venceEl: null
      }
    });

    const t1 = new Date('2026-10-01T12:00:00.000Z');
    const t2 = new Date('2026-10-16T12:00:00.000Z');
    const t1Ts = String(Math.floor(t1.getTime() / 1000));
    const t2Ts = String(Math.floor(t2.getTime() / 1000));

    await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': signWebhook(secret, 'pay_1', 'r1', t1Ts), 'x-request-id': 'r1' },
        queryStringParameters: { 'data.id': 'pay_1' },
        body: JSON.stringify({ type: 'payment', data: { id: 'pay_1' } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => t1,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: 'pay_1',
            status: 'approved',
            external_reference: 'UID_DOS',
            transaction_amount: 6500,
            currency_id: 'ARS',
            date_approved: t1.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': signWebhook(secret, 'pay_2', 'r2', t2Ts), 'x-request-id': 'r2' },
        queryStringParameters: { 'data.id': 'pay_2' },
        body: JSON.stringify({ type: 'payment', data: { id: 'pay_2' } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => t2,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: 'pay_2',
            status: 'approved',
            external_reference: 'UID_DOS',
            transaction_amount: 6500,
            currency_id: 'ARS',
            date_approved: t2.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    const expected60d = new Date(t1.getTime() + 2 * THIRTY_DAYS_MS).toISOString();
    assert(
      mem.subscribers['UID_DOS'].venceEl === expected60d &&
        Object.keys(mem.processedPayments).length === 2,
      '9. Dos pagos diferentes consecutivos acumulan exactamente 60 días desde el inicio'
    );
  }

  // ------------------------------------------------------------------
  // 10. Reembolso parcial (status='approved' con status_detail='partially_refunded')
  // ------------------------------------------------------------------
  {
    const mem = createInMemoryPaymentStore({
      UID_PARTIAL: {
        uid: 'UID_PARTIAL',
        email: 'partial@vel.com',
        estado: 'pendiente_pago',
        plan: 'Suscripción mensual VEL',
        modalidadComercial: 'manual_30d',
        fechaAlta: '2026-11-01T00:00:00.000Z',
        venceEl: null
      }
    });

    const pid = 'pay_partial_1';
    const sig = signWebhook(secret, pid, 'req-part-1', fixedTs);

    // Primero se aprueba
    await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-part-1' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'approved',
            external_reference: 'UID_PARTIAL',
            transaction_amount: 6500,
            transaction_amount_refunded: 0,
            currency_id: 'ARS',
            date_approved: fixedNow.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    // Luego llega notificación con reembolso parcial aunque status siga en 'approved'
    const partialRes = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-part-1' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => new Date(fixedNow.getTime() + 86_400_000),
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'approved',
            status_detail: 'partially_refunded',
            external_reference: 'UID_PARTIAL',
            transaction_amount: 6500,
            transaction_amount_refunded: 2000,
            currency_id: 'ARS',
            date_approved: fixedNow.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    const partialBody = JSON.parse(partialRes.body);
    assert(
      partialRes.statusCode === 200 &&
        partialBody.reverted === true &&
        partialBody.grantedDays === 0 &&
        mem.subscribers['UID_PARTIAL'].estado === 'suspendido' &&
        mem.subscribers['UID_PARTIAL'].venceEl === null &&
        mem.processedPayments[pid].reverted === true,
      '10. Reembolso parcial (status=approved, partially_refunded) revierte la vigencia y suspende el acceso comercial'
    );
  }

  // ------------------------------------------------------------------
  // 11. Reembolso total (status='refunded')
  // ------------------------------------------------------------------
  {
    const mem = createInMemoryPaymentStore({
      UID_REFUND: {
        uid: 'UID_REFUND',
        email: 'refund@vel.com',
        estado: 'pendiente_pago',
        plan: 'Suscripción mensual VEL',
        modalidadComercial: 'manual_30d',
        fechaAlta: '2026-11-01T00:00:00.000Z',
        venceEl: null
      }
    });

    const pid = 'pay_refund_1';
    const sig = signWebhook(secret, pid, 'req-ref-1', fixedTs);

    await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-ref-1' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'approved',
            external_reference: 'UID_REFUND',
            transaction_amount: 6500,
            currency_id: 'ARS',
            date_approved: fixedNow.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    const refundNow = new Date(fixedNow.getTime() + 2 * 86_400_000);
    const refundSig = signWebhook(secret, pid, 'req-ref-2', String(Math.floor(refundNow.getTime() / 1000)));
    const refundRes = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': refundSig, 'x-request-id': 'req-ref-2' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => refundNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'refunded',
            external_reference: 'UID_REFUND',
            transaction_amount: 6500,
            transaction_amount_refunded: 6500,
            currency_id: 'ARS',
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    const refundBody = JSON.parse(refundRes.body);
    assert(
      refundRes.statusCode === 200 &&
        refundBody.reverted === true &&
        mem.subscribers['UID_REFUND'].estado === 'suspendido' &&
        mem.subscribers['UID_REFUND'].venceEl === null,
      '11. Reembolso total revierte los 30 días concedidos y suspende acceso comercial'
    );
  }

  // ------------------------------------------------------------------
  // 12. Contracargo (status='charged_back') + reintento idempotente
  // ------------------------------------------------------------------
  {
    const mem = createInMemoryPaymentStore({
      UID_CB: {
        uid: 'UID_CB',
        email: 'cb@vel.com',
        estado: 'pendiente_pago',
        plan: 'Suscripción mensual VEL',
        modalidadComercial: 'manual_30d',
        fechaAlta: '2026-11-01T00:00:00.000Z',
        venceEl: null
      }
    });

    const pid = 'pay_cb_1';
    const sig = signWebhook(secret, pid, 'req-cb-1', fixedTs);

    await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-cb-1' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'approved',
            external_reference: 'UID_CB',
            transaction_amount: 6500,
            currency_id: 'ARS',
            date_approved: fixedNow.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    const cbDay3Now = new Date(fixedNow.getTime() + 3 * 86_400_000);
    const cbSigDay3 = signWebhook(secret, pid, 'req-cb-2', String(Math.floor(cbDay3Now.getTime() / 1000)));
    const cbRes = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': cbSigDay3, 'x-request-id': 'req-cb-2' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => cbDay3Now,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'charged_back',
            external_reference: 'UID_CB',
            transaction_amount: 6500,
            currency_id: 'ARS',
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    const cbDay4Now = new Date(fixedNow.getTime() + 4 * 86_400_000);
    const cbDupRes = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': cbSigDay3, 'x-request-id': 'req-cb-2' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => cbDay4Now,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'charged_back',
            external_reference: 'UID_CB',
            transaction_amount: 6500,
            currency_id: 'ARS',
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    const cbBody = JSON.parse(cbRes.body);
    const cbDupBody = JSON.parse(cbDupRes.body);
    assert(
      cbBody.reverted === true &&
        mem.subscribers['UID_CB'].estado === 'suspendido' &&
        mem.subscribers['UID_CB'].ultimoMotivoReversion === 'charged_back' &&
        cbDupBody.duplicate === true,
      '12. Contracargo (charged_back) suspende el acceso comercial y sus reintentos son idempotentes'
    );
  }

  // ------------------------------------------------------------------
  // 13. Reversión de un pago con renovaciones posteriores (conserva días legítimos)
  // ------------------------------------------------------------------
  {
    const mem = createInMemoryPaymentStore({
      UID_CHAIN: {
        uid: 'UID_CHAIN',
        email: 'chain@vel.com',
        estado: 'pendiente_pago',
        plan: 'Suscripción mensual VEL',
        modalidadComercial: 'manual_30d',
        fechaAlta: '2026-10-01T00:00:00.000Z',
        venceEl: null
      }
    });

    const t1 = new Date('2026-10-01T12:00:00.000Z');
    const t2 = new Date('2026-10-16T12:00:00.000Z');
    const tRev = new Date('2026-10-21T12:00:00.000Z');
    const t1Ts = String(Math.floor(t1.getTime() / 1000));
    const t2Ts = String(Math.floor(t2.getTime() / 1000));
    const tRevTs = String(Math.floor(tRev.getTime() / 1000));

    // Pago 1 (día 0 -> vence 31 oct)
    await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': signWebhook(secret, 'pay_c1', 'rc1', t1Ts), 'x-request-id': 'rc1' },
        queryStringParameters: { 'data.id': 'pay_c1' },
        body: JSON.stringify({ type: 'payment', data: { id: 'pay_c1' } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => t1,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: 'pay_c1',
            status: 'approved',
            external_reference: 'UID_CHAIN',
            transaction_amount: 6500,
            currency_id: 'ARS',
            date_approved: t1.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    // Pago 2 anticipado (día 15 -> suma 30 días sobre 31 oct = 30 nov)
    await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': signWebhook(secret, 'pay_c2', 'rc2', t2Ts), 'x-request-id': 'rc2' },
        queryStringParameters: { 'data.id': 'pay_c2' },
        body: JSON.stringify({ type: 'payment', data: { id: 'pay_c2' } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => t2,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: 'pay_c2',
            status: 'approved',
            external_reference: 'UID_CHAIN',
            transaction_amount: 6500,
            currency_id: 'ARS',
            date_approved: t2.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    // Contracargo de Pago 1 el día 20 (tRev): Pago 2 sigue siendo válido (30 días desde t2)
    const revRes = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': signWebhook(secret, 'pay_c1', 'rc3', tRevTs), 'x-request-id': 'rc3' },
        queryStringParameters: { 'data.id': 'pay_c1' },
        body: JSON.stringify({ type: 'payment', data: { id: 'pay_c1' } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => tRev,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: 'pay_c1',
            status: 'charged_back',
            external_reference: 'UID_CHAIN',
            transaction_amount: 6500,
            currency_id: 'ARS',
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    const expectedFromP2Only = new Date(t2.getTime() + THIRTY_DAYS_MS).toISOString();
    const revBody = JSON.parse(revRes.body);
    assert(
      revRes.statusCode === 200 &&
        revBody.reverted === true &&
        mem.subscribers['UID_CHAIN'].estado === 'activo' &&
        mem.subscribers['UID_CHAIN'].venceEl === expectedFromP2Only,
      '13. Reversión de un pago con renovación posterior conserva íntegros los 30 días legítimos del pago válido (activo hasta t2 + 30d)'
    );
  }

  // ------------------------------------------------------------------
  // 14. Descarga con suscripción vencida (aunque estado figure 'activo')
  // ------------------------------------------------------------------
  {
    let updatedStatus: string | undefined;
    const expiredActiveSub: SuscriptorAdminRecord = {
      uid: 'UID_DL_EXP',
      email: 'dlexp@vel.com',
      estado: 'activo', // Estado desactualizado en BD aunque venceEl ya expiró
      plan: 'Suscripción mensual VEL',
      modalidadComercial: 'manual_30d',
      fechaAlta: '2026-09-01T00:00:00.000Z',
      venceEl: '2026-10-15T12:00:00.000Z'
    };

    const resExpiredDl = await downloadPackageHandler(
      {
        httpMethod: 'GET',
        headers: { authorization: 'Bearer valid_dl_token', accept: 'application/json' },
        queryStringParameters: { format: 'json' }
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'UID_DL_EXP', email: 'dlexp@vel.com' }),
        getSubscriber: async () => expiredActiveSub,
        updateSubscriberStatus: async (_uid, patch) => {
          updatedStatus = patch.estado;
        },
        nowProvider: () => fixedNow
      }
    );

    const dlExpiredBody = JSON.parse(resExpiredDl.body);
    assert(
      resExpiredDl.statusCode === 403 &&
        dlExpiredBody.authorized === false &&
        updatedStatus === 'suspendido',
      '14a. Descarga bloqueada con 403 si venceEl ya expiró (incluso si estado en BD aún figuraba activo)'
    );

    const validActiveSub: SuscriptorAdminRecord = {
      ...expiredActiveSub,
      venceEl: '2026-11-25T12:00:00.000Z'
    };
    const resValidDl = await downloadPackageHandler(
      {
        httpMethod: 'GET',
        headers: {
          origin: OFFICIAL_ORIGIN,
          authorization: 'Bearer valid_dl_token',
          accept: 'application/json'
        },
        queryStringParameters: { format: 'json' }
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'UID_DL_EXP', email: 'dlexp@vel.com' }),
        getSubscriber: async () => validActiveSub,
        nowProvider: () => fixedNow
      }
    );
    const dlValidBody = JSON.parse(resValidDl.body);
    assert(
      resValidDl.statusCode === 200 &&
        dlValidBody.authorized === true &&
        typeof dlValidBody.downloadUrl === 'string' &&
        !dlValidBody.downloadUrl.endsWith('.zip') &&
        resValidDl.headers?.['Access-Control-Allow-Origin'] === OFFICIAL_ORIGIN,
      '14b. Descarga/acceso PWA autorizado con CORS para Blogger cuando estado es activo y venceEl está vigente (> ahora)'
    );
  }

  // ------------------------------------------------------------------
  // 15. Fallo al guardar una preferencia (no devuelve init_point exitoso)
  // ------------------------------------------------------------------
  {
    const resFailSave = await createPreferenceHandler(
      {
        httpMethod: 'POST',
        headers: { origin: OFFICIAL_ORIGIN, authorization: 'Bearer valid_token' },
        body: '{}'
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'UID_SAVE_ERR', email: 'err@vel.com' }),
        getPricing: async () => currentPricing,
        getSubscriber: async () => null,
        createPreference: async () => ({
          success: true,
          data: {
            id: 'pref_fail_db',
            init_point: 'https://www.mercadopago.com.ar/checkout/v1/redirect?pref_id=pref_fail_db'
          }
        }),
        recordPreferenceIntent: async () => {
          throw new Error('Error de escritura en Firestore');
        }
      }
    );

    const bodyFailSave = JSON.parse(resFailSave.body);
    assert(
      resFailSave.statusCode === 500 &&
        bodyFailSave.success === false &&
        !bodyFailSave.init_point,
      '15. Si falla el registro en Firestore, create-preference devuelve HTTP 500 y nunca entrega init_point'
    );
  }

  // ------------------------------------------------------------------
  // 16. Fallos de autenticación y credenciales faltantes
  // ------------------------------------------------------------------
  {
    const noHeader = await createPreferenceHandler({
      httpMethod: 'POST',
      headers: { origin: OFFICIAL_ORIGIN },
      body: '{}'
    });
    assert(noHeader.statusCode === 401, '16a. Solicitud sin Authorization es rechazada con 401');

    const badToken = await createPreferenceHandler(
      {
        httpMethod: 'POST',
        headers: { origin: OFFICIAL_ORIGIN, authorization: 'Bearer invalid.jwt.token' },
        body: '{}'
      },
      {
        verifyToken: async () => ({
          authenticated: false,
          reason: 'invalid_token',
          message: 'Token inválido'
        })
      }
    );
    assert(badToken.statusCode === 401, '16b. Token Firebase inválido es rechazado con 401');

    const prevFb = process.env.FIREBASE_SERVICE_ACCOUNT;
    const prevMp = process.env.MP_ACCESS_TOKEN;
    const prevSec = process.env.MP_WEBHOOK_SECRET;
    delete process.env.FIREBASE_SERVICE_ACCOUNT;
    delete process.env.MP_ACCESS_TOKEN;
    delete process.env.MP_WEBHOOK_SECRET;

    const pendingFb = await createPreferenceHandler({
      httpMethod: 'POST',
      headers: { origin: OFFICIAL_ORIGIN, authorization: 'Bearer some.jwt.token' },
      body: '{}'
    });
    const pendingSec = verifyMpWebhookSignature('ts=1,v1=aa', 'req-1', '123');
    assert(
      pendingFb.statusCode === 503 &&
        JSON.parse(pendingFb.body).pendingConfig === true &&
        pendingSec.isValid === false &&
        pendingSec.pendingConfig === true,
      '16c. Sin FIREBASE_SERVICE_ACCOUNT / MP_WEBHOOK_SECRET informa pendingConfig (503) sin simular éxito'
    );

    if (prevFb !== undefined) process.env.FIREBASE_SERVICE_ACCOUNT = prevFb;
    if (prevMp !== undefined) process.env.MP_ACCESS_TOKEN = prevMp;
    if (prevSec !== undefined) process.env.MP_WEBHOOK_SECRET = prevSec;
  }

  // ------------------------------------------------------------------
  // 17. Separación estricta entre Preapproval y Checkout Pro
  // ------------------------------------------------------------------
  {
    const legacyCreateRes = await createSubscriptionHandler({ httpMethod: 'POST', headers: {} });
    assert(
      legacyCreateRes.statusCode === 410 && JSON.parse(legacyCreateRes.body).deprecated === true,
      '17a. create-subscription (Preapproval) devuelve 410 deshabilitado para nuevas operaciones'
    );

    const mem = createInMemoryPaymentStore({
      UID_PREAPP: {
        uid: 'UID_PREAPP',
        email: 'preapp@vel.com',
        estado: 'activo',
        plan: 'VEL Oficial (CORE + MÓVIL)',
        modalidadComercial: 'preapproval',
        mpPreapprovalId: 'preapp_hist_99',
        fechaAlta: '2026-08-01T00:00:00.000Z',
        venceEl: '2026-11-20T00:00:00.000Z'
      }
    });

    const sig = signWebhook(secret, 'pay_preapp_99', 'req-sep-1', fixedTs);
    const cpResOnPreapp = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-sep-1' },
        queryStringParameters: { 'data.id': 'pay_preapp_99' },
        body: JSON.stringify({ type: 'payment', data: { id: 'pay_preapp_99' } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => mem.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: 'pay_preapp_99',
            status: 'approved',
            preapproval_id: 'preapp_hist_99',
            external_reference: 'UID_PREAPP',
            transaction_amount: 6500,
            currency_id: 'ARS'
          }
        })
      }
    );

    const cpBody = JSON.parse(cpResOnPreapp.body);
    assert(
      cpResOnPreapp.statusCode === 200 &&
        cpBody.ignored === true &&
        cpBody.grantedDays === 0 &&
        mem.subscribers['UID_PREAPP'].venceEl === '2026-11-20T00:00:00.000Z',
      '17b. payment-webhook (Checkout Pro) ignora pagos con preapproval_id sin alterar cuentas Preapproval'
    );

    const legacyWebhookSrc = fs.readFileSync(
      path.resolve(process.cwd(), 'netlify/functions/mercadopago-webhook.ts'),
      'utf8'
    );
    assert(
      legacyWebhookSrc.includes('pagos_procesados') &&
        legacyWebhookSrc.includes("payData.metadata?.circuito === 'checkout_pro'") &&
        typeof legacyPreapprovalWebhookHandler === 'function',
      '17c. mercadopago-webhook (Preapproval) verifica pagos_procesados y circuito checkout_pro para no modificar pagos Checkout Pro'
    );
  }

  // ------------------------------------------------------------------
  // 18. Renovación desde Blogger con sesión Firebase existente y CORS estricto
  // ------------------------------------------------------------------
  {
    const optRes = await createPreferenceHandler({
      httpMethod: 'OPTIONS',
      headers: { origin: OFFICIAL_ORIGIN, host: 'legendary-pasca-bf280b.netlify.app' }
    });
    const allowOrigin: string = optRes.headers['Access-Control-Allow-Origin'] || '';
    const hasWildcard = Object.values(optRes.headers).some((v) => String(v).trim() === '*');

    const evilRes = await createPreferenceHandler({
      httpMethod: 'POST',
      headers: { origin: 'https://otro-dominio-no-autorizado.com', authorization: 'Bearer x' },
      body: '{}'
    });

    const bloggerHtml = fs.readFileSync(
      path.resolve(process.cwd(), 'blogger/vel-contratacion-mercadopago.html'),
      'utf8'
    );

    assert(
      optRes.statusCode === 204 &&
        allowOrigin === OFFICIAL_ORIGIN &&
        !hasWildcard &&
        evilRes.statusCode === 403,
      '18a. CORS habilita exclusivamente https://proyecto-vel.blogspot.com y rechaza orígenes externos con 403'
    );

    assert(
      bloggerHtml.includes('https://proyecto-vel.pages.dev/') &&
        bloggerHtml.includes('ACEPTO Y CONTINUAR') &&
        bloggerHtml.includes("var CONTRACT_VERSION = '1.2'") &&
        !bloggerHtml.toLowerCase().includes('netlify') &&
        bloggerHtml.includes('resolveExistingFirebaseAuth()') &&
        bloggerHtml.includes("projectId: 'proyecto-vel'") &&
        !bloggerHtml.includes('MP_ACCESS_TOKEN') &&
        bloggerHtml.includes('getIdToken(true)') &&
        bloggerHtml.includes("'Authorization': 'Bearer ' + idToken") &&
        bloggerHtml.includes('if (!isSubmitting)'),
      '18b. Bloque Blogger prioriza sesión existente, inicializa proyecto-vel si falta, llama getIdToken(true), exige contrato v1.2, apunta a proyecto-vel.pages.dev y no expone secretos'
    );
  }

  // ------------------------------------------------------------------
  // 19. Validación temporal de ts en firma HMAC (reciente, antigua y retrasada)
  // ------------------------------------------------------------------
  {
    const nowMs = fixedNow.getTime();
    const recentTs = String(Math.floor((nowMs - 60_000) / 1000)); // Hace 1 minuto
    const delayed18hTs = String(Math.floor((nowMs - 18 * 60 * 60 * 1000) / 1000)); // Retraso de 18h (reintento MP)
    const delayed47hTs = String(Math.floor((nowMs - 47 * 60 * 60 * 1000) / 1000)); // Retraso de 47h (dentro de 48h)
    const old49hTs = String(Math.floor((nowMs - 49 * 60 * 60 * 1000) / 1000)); // Hace 49h (expirada > 48h)

    const recentCheck = verifyMpWebhookSignature(
      signWebhook(secret, 'pay_ts_recent', 'req-ts-1', recentTs),
      'req-ts-1',
      'pay_ts_recent',
      { nowMs }
    );
    assert(
      recentCheck.isValid === true,
      '19a. Firma válida reciente (hace 60s) es aceptada correctamente'
    );

    const oldCheck = verifyMpWebhookSignature(
      signWebhook(secret, 'pay_ts_old', 'req-ts-2', old49hTs),
      'req-ts-2',
      'pay_ts_old',
      { nowMs }
    );
    let fetchCalledOnExpired = false;
    const oldWebhookRes = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: {
          'x-signature': signWebhook(secret, 'pay_ts_old', 'req-ts-2', old49hTs),
          'x-request-id': 'req-ts-2'
        },
        queryStringParameters: { 'data.id': 'pay_ts_old' },
        body: JSON.stringify({ type: 'payment', data: { id: 'pay_ts_old' } })
      },
      {
        nowProvider: () => fixedNow,
        fetchPayment: async () => {
          fetchCalledOnExpired = true;
          return { success: true, data: {} };
        }
      }
    );
    assert(
      oldCheck.isValid === false &&
        oldWebhookRes.statusCode === 401 &&
        !fetchCalledOnExpired,
      '19b. Firma antigua (> 48h) es rechazada con 401 antes de consultar Mercado Pago o Firestore'
    );

    const memDelayed = createInMemoryPaymentStore({
      UID_DELAY: {
        uid: 'UID_DELAY',
        email: 'delay@vel.com',
        estado: 'pendiente_pago',
        plan: 'Suscripción mensual VEL',
        modalidadComercial: 'manual_30d',
        fechaAlta: '2026-11-01T00:00:00.000Z',
        venceEl: null
      }
    });
    const delayed18hCheck = verifyMpWebhookSignature(
      signWebhook(secret, 'pay_ts_delay18', 'req-ts-3', delayed18hTs),
      'req-ts-3',
      'pay_ts_delay18',
      { nowMs }
    );
    const delayed47hRes = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: {
          'x-signature': signWebhook(secret, 'pay_ts_delay47', 'req-ts-4', delayed47hTs),
          'x-request-id': 'req-ts-4'
        },
        queryStringParameters: { 'data.id': 'pay_ts_delay47' },
        body: JSON.stringify({ type: 'payment', data: { id: 'pay_ts_delay47' } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => memDelayed.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: 'pay_ts_delay47',
            status: 'approved',
            external_reference: 'UID_DELAY',
            transaction_amount: 6500,
            currency_id: 'ARS',
            date_approved: new Date(nowMs - 47 * 60 * 60 * 1000).toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );
    const delayedBody = JSON.parse(delayed47hRes.body);
    assert(
      delayed18hCheck.isValid === true &&
        delayed47hRes.statusCode === 200 &&
        delayedBody.grantedDays === 30 &&
        memDelayed.subscribers['UID_DELAY'].estado === 'activo',
      '19c. Notificación legítima retrasada por reintento de Mercado Pago (18h y 47h) es aceptada y procesada'
    );
  }

  // ------------------------------------------------------------------
  // 20. Error temporal al consultar la tarifa (sin fallback silencioso)
  // ------------------------------------------------------------------
  {
    const failingMockDb = {
      doc: () => ({
        get: async () => {
          throw new Error('DEADLINE_EXCEEDED: Firestore temporalmente inaccesible');
        }
      })
    } as any;

    let threwOnDbError = false;
    try {
      await getCurrentPricing(failingMockDb);
    } catch (err: any) {
      threwOnDbError = err instanceof PricingUnavailableError && err.retryable === true;
    }

    const missingDocMockDb = {
      doc: () => ({
        get: async () => ({ exists: false, data: () => undefined })
      })
    } as any;

    let threwOnMissingDoc = false;
    try {
      await getCurrentPricing(missingDocMockDb);
    } catch (err: any) {
      threwOnMissingDoc = err instanceof PricingUnavailableError;
    }

    assert(
      threwOnDbError && threwOnMissingDoc,
      '20a. getCurrentPricing() lanza PricingUnavailableError ante fallo de lectura o ausencia de documento, sin fallback a DEFAULT_PRICING'
    );

    const existingHistSub: SuscriptorAdminRecord = {
      uid: 'UID_PRICING_ERR',
      email: 'pricingerr@vel.com',
      estado: 'activo',
      plan: 'Suscripción mensual VEL',
      modalidadComercial: 'manual_30d',
      fechaAlta: '2026-08-01T00:00:00.000Z',
      fechaUltimoPago: '2026-10-15T12:00:00.000Z',
      venceEl: '2026-11-14T12:00:00.000Z',
      precioContratado: 4500,
      moneda: 'ARS'
    };
    const memPricingErr = createInMemoryPaymentStore({ UID_PRICING_ERR: existingHistSub });
    const pid = 'pay_pricing_err_1';
    const sig = signWebhook(secret, pid, 'req-pr-err', fixedTs);

    const pricingErrRes = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-pr-err' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: () => getCurrentPricing(failingMockDb),
        getPaymentStore: () => memPricingErr.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'approved',
            external_reference: 'UID_PRICING_ERR',
            transaction_amount: 4500,
            currency_id: 'ARS',
            date_approved: fixedNow.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    const pricingErrBody = JSON.parse(pricingErrRes.body);
    assert(
      pricingErrRes.statusCode === 503 &&
        pricingErrBody.retryable === true &&
        pricingErrBody.grantedDays === 0 &&
        Object.keys(memPricingErr.processedPayments).length === 0 &&
        memPricingErr.subscribers['UID_PRICING_ERR'].precioContratado === 4500 &&
        memPricingErr.subscribers['UID_PRICING_ERR'].venceEl === '2026-11-14T12:00:00.000Z',
      '20b. Ante error al consultar tarifa, webhook devuelve 503 reintentable, concede 0 días y conserva intacto el precio histórico'
    );
  }

  // ------------------------------------------------------------------
  // 21. Suscriptor inexistente (create-preference crea ficha; webhook rechaza seguro)
  // ------------------------------------------------------------------
  {
    const mockFirestoreDocs: Record<string, any> = {};
    const mockDbForPref = {
      collection: (colName: string) => ({
        doc: (docId: string) => ({ __path: `${colName}/${docId}` })
      }),
      runTransaction: async (fn: (tx: any) => Promise<any>) => {
        const tx = {
          get: async (ref: { __path: string }) => ({
            exists: Boolean(mockFirestoreDocs[ref.__path]),
            data: () => mockFirestoreDocs[ref.__path]
          }),
          set: (ref: { __path: string }, data: any, opts?: { merge?: boolean }) => {
            mockFirestoreDocs[ref.__path] = opts?.merge
              ? { ...(mockFirestoreDocs[ref.__path] || {}), ...data }
              : { ...data };
          }
        };
        return fn(tx);
      }
    } as any;

    const prefResNew = await createPreferenceHandler(
      {
        httpMethod: 'POST',
        headers: { origin: OFFICIAL_ORIGIN, authorization: 'Bearer tok_new_sub' },
        body: '{}'
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'UID_PREF_AUTOCREATE', email: 'auto@vel.com' }),
        getPricing: async () => currentPricing,
        getSubscriber: async () => null,
        createPreference: async () => ({
          success: true,
          data: {
            id: 'pref_auto_01',
            init_point: 'https://www.mercadopago.com.ar/checkout/v1/redirect?pref_id=pref_auto_01'
          }
        }),
        recordPreferenceIntent: (uid, email, prefId, eff) =>
          defaultRecordPreferenceIntent(uid, email, prefId, eff, mockDbForPref)
      }
    );

    const subCreated = mockFirestoreDocs['suscriptores/UID_PREF_AUTOCREATE'];
    const prefCreated = mockFirestoreDocs['preferencias_pago/pref_auto_01'];
    assert(
      prefResNew.statusCode === 200 &&
        Boolean(JSON.parse(prefResNew.body).init_point) &&
        subCreated?.estado === 'pendiente_pago' &&
        subCreated?.mpPreferenceId === 'pref_auto_01' &&
        prefCreated?.uid === 'UID_PREF_AUTOCREATE',
      '21a. create-preference registra atómicamente suscriptores/{uid} y preferencias_pago/{prefId} antes de entregar init_point'
    );

    const memNoSub = createInMemoryPaymentStore({});
    const pidNoSub = 'pay_no_sub_1';
    const resNoSub = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: {
          'x-signature': signWebhook(secret, pidNoSub, 'req-nosub-1', fixedTs),
          'x-request-id': 'req-nosub-1'
        },
        queryStringParameters: { 'data.id': pidNoSub },
        body: JSON.stringify({ type: 'payment', data: { id: pidNoSub } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => memNoSub.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pidNoSub,
            status: 'approved',
            external_reference: 'UID_INEXISTENTE_999',
            transaction_amount: 6500,
            currency_id: 'ARS',
            date_approved: fixedNow.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    const bodyNoSub = JSON.parse(resNoSub.body);
    assert(
      resNoSub.statusCode === 422 &&
        bodyNoSub.processed === false &&
        bodyNoSub.grantedDays === 0 &&
        Object.keys(memNoSub.processedPayments).length === 0 &&
        !memNoSub.subscribers['UID_INEXISTENTE_999'],
      '21b. Webhook rechaza con 422 y 0 días si no existe suscriptores/{uid} en Firestore'
    );
  }

  // ------------------------------------------------------------------
  // 22. Reembolso parcial cuyo importe neto restante sigue siendo suficiente
  // ------------------------------------------------------------------
  {
    const memPartialSufficient = createInMemoryPaymentStore({
      UID_PARTIAL_NET_OK: {
        uid: 'UID_PARTIAL_NET_OK',
        email: 'partialnetok@vel.com',
        estado: 'pendiente_pago',
        plan: 'Suscripción mensual VEL',
        modalidadComercial: 'manual_30d',
        fechaAlta: '2026-10-01T00:00:00.000Z',
        precioContratado: 4500,
        moneda: 'ARS',
        venceEl: null
      }
    });

    const pid = 'pay_partial_net_ok';
    const sig = signWebhook(secret, pid, 'req-part-net-ok', fixedTs);

    // Pago inicial aprobado por 6500 ARS (tarifa del suscriptor = 4500 ARS)
    await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-part-net-ok' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => memPartialSufficient.store,
        nowProvider: () => fixedNow,
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'approved',
            external_reference: 'UID_PARTIAL_NET_OK',
            transaction_amount: 6500,
            transaction_amount_refunded: 0,
            currency_id: 'ARS',
            date_approved: fixedNow.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    // Reembolso parcial de 1500 ARS: neto restante = 5000 ARS (>= 4500 ARS contratados)
    const partialSuffRes = await paymentWebhookHandler(
      {
        httpMethod: 'POST',
        headers: { 'x-signature': sig, 'x-request-id': 'req-part-net-ok' },
        queryStringParameters: { 'data.id': pid },
        body: JSON.stringify({ type: 'payment', data: { id: pid } })
      },
      {
        hasDbCredentials: () => true,
        getPricing: async () => currentPricing,
        getPaymentStore: () => memPartialSufficient.store,
        nowProvider: () => new Date(fixedNow.getTime() + 3_600_000),
        fetchPayment: async () => ({
          success: true,
          data: {
            id: pid,
            status: 'approved',
            status_detail: 'partially_refunded',
            external_reference: 'UID_PARTIAL_NET_OK',
            transaction_amount: 6500,
            transaction_amount_refunded: 1500, // Neto restante = 5000 >= 4500
            currency_id: 'ARS',
            date_approved: fixedNow.toISOString(),
            metadata: { circuito: 'checkout_pro' }
          }
        })
      }
    );

    const partialSuffBody = JSON.parse(partialSuffRes.body);
    assert(
      partialSuffRes.statusCode === 200 &&
        partialSuffBody.reverted === true &&
        partialSuffBody.grantedDays === 0 &&
        memPartialSufficient.subscribers['UID_PARTIAL_NET_OK'].estado === 'suspendido' &&
        memPartialSufficient.subscribers['UID_PARTIAL_NET_OK'].venceEl === null &&
        memPartialSufficient.processedPayments[pid].netAmount === 5000,
      '22. Política actual documentada: reembolso parcial con neto suficiente (5000 >= 4500) igualmente revierte los 30 días y suspende acceso'
    );
  }

  // ------------------------------------------------------------------
  // 23. Notificaciones duplicadas y simultáneas (Promise.all concurrente)
  // ------------------------------------------------------------------
  {
    const memConcurrent = createInMemoryPaymentStore(
      {
        UID_CONCURRENT: {
          uid: 'UID_CONCURRENT',
          email: 'concurrent@vel.com',
          estado: 'pendiente_pago',
          plan: 'Suscripción mensual VEL',
          modalidadComercial: 'manual_30d',
          fechaAlta: '2026-11-01T00:00:00.000Z',
          venceEl: null
        }
      },
      { asyncYieldMs: 15 }
    );

    const pid = 'pay_concurrent_1';
    const sig = signWebhook(secret, pid, 'req-conc-1', fixedTs);

    const makeEvent = () => ({
      httpMethod: 'POST',
      headers: { 'x-signature': sig, 'x-request-id': 'req-conc-1' },
      queryStringParameters: { 'data.id': pid },
      body: JSON.stringify({ type: 'payment', data: { id: pid } })
    });

    const deps = {
      hasDbCredentials: () => true,
      getPricing: async () => currentPricing,
      getPaymentStore: () => memConcurrent.store,
      nowProvider: () => fixedNow,
      fetchPayment: async () => ({
        success: true,
        data: {
          id: pid,
          status: 'approved',
          external_reference: 'UID_CONCURRENT',
          transaction_amount: 6500,
          currency_id: 'ARS',
          date_approved: fixedNow.toISOString(),
          metadata: { circuito: 'checkout_pro' }
        }
      })
    };

    const responses = await Promise.all([
      paymentWebhookHandler(makeEvent(), deps),
      paymentWebhookHandler(makeEvent(), deps),
      paymentWebhookHandler(makeEvent(), deps)
    ]);

    const parsed = responses.map((r) => JSON.parse(r.body));
    const grantedCount = parsed.filter((b) => b.grantedDays === 30 && b.duplicate === false).length;
    const duplicateCount = parsed.filter((b) => b.grantedDays === 0 && b.duplicate === true).length;
    const expectedExact30d = new Date(fixedNow.getTime() + THIRTY_DAYS_MS).toISOString();

    assert(
      responses.every((r) => r.statusCode === 200) &&
        grantedCount === 1 &&
        duplicateCount === 2 &&
        Object.keys(memConcurrent.processedPayments).length === 1 &&
        memConcurrent.subscribers['UID_CONCURRENT'].venceEl === expectedExact30d,
      '23. Tres notificaciones duplicadas y simultáneas (Promise.all) acreditan exactamente una sola vez (30 días, 2 duplicadas)'
    );
  }

  // ------------------------------------------------------------------
  // 24. Variable MP_WEBHOOK_MAX_AGE_SECONDS (ausente, válida e inválida)
  // ------------------------------------------------------------------
  {
    const nowMs = fixedNow.getTime();
    const prevMaxAgeEnv = process.env.MP_WEBHOOK_MAX_AGE_SECONDS;
    const ts30mAgo = String(Math.floor((nowMs - 30 * 60 * 1000) / 1000));
    const ts2hAgo = String(Math.floor((nowMs - 2 * 60 * 60 * 1000) / 1000));
    const ts47hAgo = String(Math.floor((nowMs - 47 * 60 * 60 * 1000) / 1000));
    const ts49hAgo = String(Math.floor((nowMs - 49 * 60 * 60 * 1000) / 1000));
    const ts6mFuture = String(Math.floor((nowMs + 6 * 60 * 1000) / 1000));

    delete process.env.MP_WEBHOOK_MAX_AGE_SECONDS;
    const default47h = verifyMpWebhookSignature(
      signWebhook(secret, 'pay_env_1', 'req-env-1', ts47hAgo),
      'req-env-1',
      'pay_env_1',
      { nowMs }
    );
    const default49h = verifyMpWebhookSignature(
      signWebhook(secret, 'pay_env_2', 'req-env-2', ts49hAgo),
      'req-env-2',
      'pay_env_2',
      { nowMs }
    );
    const defaultFuture = verifyMpWebhookSignature(
      signWebhook(secret, 'pay_env_3', 'req-env-3', ts6mFuture),
      'req-env-3',
      'pay_env_3',
      { nowMs }
    );

    process.env.MP_WEBHOOK_MAX_AGE_SECONDS = '3600'; // 1 hora
    const custom30m = verifyMpWebhookSignature(
      signWebhook(secret, 'pay_env_4', 'req-env-4', ts30mAgo),
      'req-env-4',
      'pay_env_4',
      { nowMs }
    );
    const custom2h = verifyMpWebhookSignature(
      signWebhook(secret, 'pay_env_5', 'req-env-5', ts2hAgo),
      'req-env-5',
      'pay_env_5',
      { nowMs }
    );

    process.env.MP_WEBHOOK_MAX_AGE_SECONDS = 'valor_invalido';
    const invalidEnv47h = verifyMpWebhookSignature(
      signWebhook(secret, 'pay_env_6', 'req-env-6', ts47hAgo),
      'req-env-6',
      'pay_env_6',
      { nowMs }
    );

    if (prevMaxAgeEnv !== undefined) {
      process.env.MP_WEBHOOK_MAX_AGE_SECONDS = prevMaxAgeEnv;
    } else {
      delete process.env.MP_WEBHOOK_MAX_AGE_SECONDS;
    }

    const envExampleSrc = fs.readFileSync(path.resolve(process.cwd(), '.env.example'), 'utf8');
    const mpSrc = fs.readFileSync(
      path.resolve(process.cwd(), 'netlify/functions/shared/mercadopago.ts'),
      'utf8'
    );

    assert(
      default47h.isValid === true &&
        default49h.isValid === false &&
        defaultFuture.isValid === false &&
        custom30m.isValid === true &&
        custom2h.isValid === false &&
        invalidEnv47h.isValid === true &&
        envExampleSrc.includes('MP_WEBHOOK_MAX_AGE_SECONDS') &&
        mpSrc.includes('MP_WEBHOOK_MAX_AGE_SECONDS') &&
        !mpSrc.includes('EDAD_M'),
      '24. MP_WEBHOOK_MAX_AGE_SECONDS usa 48h/5m por defecto si falta o es inválida, y ajusta la ventana temporal si tiene valor válido'
    );
  }

  // ------------------------------------------------------------------
  // 25. Inicialización segura de configuracion_comercial/precios
  // ------------------------------------------------------------------
  {
    const mockPricingDocs: Record<string, any> = {};
    let autoId = 0;
    const mockPricingDb = {
      doc: (docPath: string) => ({
        __path: docPath,
        get: async () => ({
          exists: Boolean(mockPricingDocs[docPath]),
          data: () => mockPricingDocs[docPath]
        })
      }),
      collection: (colPath: string) => ({
        doc: (id?: string) => ({ __path: `${colPath}/${id || `hist_${++autoId}`}` }),
        orderBy: () => ({
          limit: () => ({
            get: async () => ({
              docs: Object.entries(mockPricingDocs)
                .filter(([k]) => k.startsWith('configuracion_comercial/precios/historial/'))
                .map(([k, v]) => ({ id: k.split('/').pop(), data: () => v }))
            })
          })
        })
      }),
      runTransaction: async (fn: (tx: any) => Promise<any>) => {
        const staged: Record<string, any> = {};
        const tx = {
          get: async (ref: { __path: string }) => ({
            exists: Boolean(mockPricingDocs[ref.__path]),
            data: () => mockPricingDocs[ref.__path]
          }),
          set: (ref: { __path: string }, data: any) => {
            staged[ref.__path] = { ...data };
          }
        };
        const out = await fn(tx);
        Object.assign(mockPricingDocs, staged);
        return out;
      }
    } as any;

    // 25a. Sin inicializar, GET /admin-pricing informa requiresInitialization=true sin devolver DEFAULT_PRICING
    const getBeforeInit = await adminPricingHandler(
      { httpMethod: 'GET', headers: { authorization: 'Bearer admin_tok' } },
      {
        verifyToken: async () => ({ uid: 'ADMIN_1', email: 'admin@vel.com' }),
        isAdmin: () => true,
        getHistory: async () => [],
        getPricing: () => getCurrentPricing(mockPricingDb)
      }
    );
    const getBeforeBody = JSON.parse(getBeforeInit.body);
    assert(
      getBeforeInit.statusCode === 200 &&
        getBeforeBody.initialized === false &&
        getBeforeBody.requiresInitialization === true &&
        getBeforeBody.current === null,
      '25a. GET /admin-pricing detecta configuracion_comercial/precios sin inicializar sin inventar DEFAULT_PRICING'
    );

    // 25b. Usuario no autorizado no puede inicializar precios (403)
    const unauthInit = await adminPricingHandler(
      {
        httpMethod: 'POST',
        headers: { authorization: 'Bearer client_tok' },
        body: JSON.stringify({ action: 'initialize', monto: 7200, moneda: 'ARS' })
      },
      {
        verifyToken: async () => ({ uid: 'CLIENT_1', email: 'cliente@externo.com' })
      }
    );
    assert(
      unauthInit.statusCode === 403 && !mockPricingDocs['configuracion_comercial/precios'],
      '25b. Usuario sin privilegios administrativos no puede inicializar ni modificar configuracion_comercial/precios (403)'
    );

    // 25c. Administrador inicializa correctamente y un segundo initialize no sobrescribe (409)
    const firstInitRes = await adminPricingHandler(
      {
        httpMethod: 'POST',
        headers: { authorization: 'Bearer admin_tok' },
        body: JSON.stringify({ action: 'initialize', monto: 7200, moneda: 'ARS' })
      },
      {
        verifyToken: async () => ({ uid: 'ADMIN_1', email: 'admin@vel.com' }),
        isAdmin: () => true,
        initPricing: (m, cur, em, mot) => initializePricing(m, cur, em, mot, mockPricingDb)
      }
    );
    const secondInitRes = await adminPricingHandler(
      {
        httpMethod: 'POST',
        headers: { authorization: 'Bearer admin_tok' },
        body: JSON.stringify({ action: 'initialize', monto: 9999, moneda: 'USD' })
      },
      {
        verifyToken: async () => ({ uid: 'ADMIN_1', email: 'admin@vel.com' }),
        isAdmin: () => true,
        initPricing: (m, cur, em, mot) => initializePricing(m, cur, em, mot, mockPricingDb)
      }
    );
    const readAfterInit = await getCurrentPricing(mockPricingDb);
    assert(
      firstInitRes.statusCode === 201 &&
        secondInitRes.statusCode === 409 &&
        readAfterInit.monto === 7200 &&
        readAfterInit.moneda === 'ARS',
      '25c. initializePricing crea configuracion_comercial/precios una sola vez y rechaza sobrescritura con 409'
    );
  }

  // ------------------------------------------------------------------
  // 26. Circuito automático vel_pass -> register-device -> device-session -> vencimiento y reactivación
  // ------------------------------------------------------------------
  {
    const subUid = 'UID_SUB_AUTO_26';
    const subDocs: Record<string, SuscriptorAdminRecord> = {
      [subUid]: {
        uid: subUid,
        email: 'auto26@vel.com',
        estado: 'activo',
        plan: 'Suscripción mensual VEL',
        modalidadComercial: 'manual_30d',
        fechaAlta: '2026-11-01T00:00:00.000Z',
        venceEl: new Date(fixedNow.getTime() + 15 * 86_400_000).toISOString(),
        precioContratado: 6500,
        moneda: 'ARS'
      }
    };

    const dlActiveRes = await downloadPackageHandler(
      {
        httpMethod: 'GET',
        headers: { authorization: 'Bearer tok_dl_26', accept: 'application/json' },
        queryStringParameters: { format: 'json' }
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: subUid, email: 'auto26@vel.com' }),
        getSubscriber: async (u) => subDocs[u] || null,
        nowProvider: () => fixedNow
      }
    );
    const dlActiveBody = JSON.parse(dlActiveRes.body);
    const issuedUrl = new URL(dlActiveBody.downloadUrl, 'https://legendary-pasca-bf280b.netlify.app');
    const velPass = issuedUrl.searchParams.get('vel_pass') || '';
    const verifiedPass = verifySubscriptionPass(velPass, fixedNow);
    const tamperedPass = verifySubscriptionPass(`${velPass}tamper`, fixedNow);

    assert(
      dlActiveRes.statusCode === 200 &&
        Boolean(velPass) &&
        verifiedPass.valid === true &&
        verifiedPass.uid === subUid &&
        tamperedPass.valid === false,
      '26a. download-package emite vel_pass firmado válido para entrar a VEL y rechaza pases manipulados'
    );

    const devicesMap = new Map<string, DeviceRecord>();
    const linksMap = new Map<string, DeviceLinkRecord>();
    const authsMap = new Map<string, AuthorizationRecord>();
    const memDevStore: DeviceTransactionStore = {
      async runTransaction<T>(fn: (ctx: DeviceTransactionContext) => Promise<T>): Promise<T> {
        const ctx: DeviceTransactionContext = {
          async getDevice(id) {
            const d = devicesMap.get(id);
            return d ? { ...d } : null;
          },
          createDevice(rec) {
            devicesMap.set(rec.deviceId, { ...rec });
          },
          updateDevice(id, patch) {
            const c = devicesMap.get(id);
            if (c) devicesMap.set(id, { ...c, ...patch });
          },
          async getLink(id) {
            const l = linksMap.get(id);
            return l ? { ...l } : null;
          },
          async getAuthorizationByLink(id) {
            const a = authsMap.get(id);
            return a ? { ...a } : null;
          }
        };
        return fn(ctx);
      },
      async getSubscriber(u) {
        return subDocs[u] ? { ...subDocs[u] } : null;
      },
      async updateSubscriberStatus(u, patch) {
        if (subDocs[u]) subDocs[u] = { ...subDocs[u], ...patch };
      }
    };

    const matCore = await generateDeviceCryptoMaterial('CORE');
    const regRes = await registerDeviceHandler(
      {
        httpMethod: 'POST',
        headers: { authorization: 'Bearer dev_core_tok' },
        body: JSON.stringify({
          deviceId: matCore.deviceId,
          role: 'CORE',
          publicKeySpkiBase64: matCore.publicKeySpkiBase64,
          signingPublicKeySpkiBase64: matCore.signingPublicKeySpkiBase64,
          fingerprint: matCore.fingerprint,
          subscriptionUid: 'UID_FALSO_IGNORADO',
          subscriptionPass: velPass
        })
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'anon_core_26', email: '' }),
        hasDbCredentials: () => true,
        getDeviceStore: () => memDevStore,
        nowProvider: () => fixedNow
      }
    );
    const regBody = JSON.parse(regRes.body);
    assert(
      regRes.statusCode === 201 && regBody.device?.subscriptionUid === subUid,
      '26b. register-device asocia únicamente el subscriptionUid verificado dentro de vel_pass e ignora spoofing en el body'
    );

    // Simular vencimiento de los 30 días en Firestore (sin revocar el dispositivo)
    subDocs[subUid].venceEl = new Date(Date.now() - 2 * 86_400_000).toISOString();
    const sessExpiredRes = await deviceSessionHandler(
      {
        httpMethod: 'GET',
        headers: { authorization: 'Bearer dev_core_tok' },
        queryStringParameters: { deviceId: matCore.deviceId }
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'anon_core_26', email: '' }),
        hasDbCredentials: () => true,
        getDeviceStore: () => memDevStore
      }
    );
    const sessExpiredBody = JSON.parse(sessExpiredRes.body);
    assert(
      sessExpiredRes.statusCode === 200 &&
        sessExpiredBody.device?.status === 'registered' &&
        sessExpiredBody.subscriptionStatus?.linked === true &&
        sessExpiredBody.subscriptionStatus?.active === false &&
        subDocs[subUid].estado === 'vencido',
      '26c. Al vencer la fecha, device-session marca activo=false y estado=vencido SIN revocar el dispositivo'
    );

    // Simular renovación en Blogger/Mercado Pago -> vuelve a estar activo automáticamente
    subDocs[subUid].estado = 'activo';
    subDocs[subUid].venceEl = new Date(Date.now() + 30 * 86_400_000).toISOString();
    const sessRenewedRes = await deviceSessionHandler(
      {
        httpMethod: 'GET',
        headers: { authorization: 'Bearer dev_core_tok' },
        queryStringParameters: { deviceId: matCore.deviceId }
      },
      {
        verifyToken: async () => ({ authenticated: true, uid: 'anon_core_26', email: '' }),
        hasDbCredentials: () => true,
        getDeviceStore: () => memDevStore
      }
    );
    const sessRenewedBody = JSON.parse(sessRenewedRes.body);
    const expiredEval = evaluateSubscriberAccess({ ...subDocs[subUid], estado: 'activo', venceEl: '2020-01-01T00:00:00.000Z' }, fixedNow);
    const createdPass = createSubscriptionPass(subUid, fixedNow);
    assert(
      sessRenewedBody.subscriptionStatus?.active === true &&
        expiredEval.active === false &&
        Boolean(createdPass),
      '26d. Al renovarse el pago, device-session reporta active=true automáticamente para los mismos teléfonos'
    );
  }

  console.log('\n==================================================================');
  console.log(`RESUMEN PRUEBAS CHECKOUT PRO / BLOGGER: ${passedTests} de ${totalTests} aprobadas.`);
  console.log('==================================================================');

  if (passedTests !== totalTests) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Error fatal ejecutando pruebas:', err);
  process.exit(1);
});
