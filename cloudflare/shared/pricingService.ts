import {
  createFirestoreRestClient,
  FirestoreRestClient,
  hasFirebaseAdminCredentials
} from './firebaseRest';
import type { CloudflareEnv, PricingConfig, PricingHistoryEntry } from './types';

const PRICING_DOC_PATH = 'configuracion_comercial/precios';
const PRICING_PARENT_DOC_PATH = 'configuracion_comercial/precios';
const PRICING_HISTORY_COLLECTION = 'configuracion_comercial/precios/historial';

export const DEFAULT_PRICING: PricingConfig = {
  monto: 4500,
  moneda: 'ARS',
  periodicidad: 'mensual',
  actualizadoEl: '2026-11-12T00:00:00.000Z',
  actualizadoPor: 'sistema_inicial'
};

export type PricingUnavailableReason = 'firestore_error' | 'not_configured' | 'invalid_config';

export class PricingUnavailableError extends Error {
  public readonly code = 'PRICING_UNAVAILABLE';
  public readonly retryable = true;

  constructor(
    message: string,
    public readonly reason: PricingUnavailableReason = 'firestore_error',
    public readonly causeError?: unknown
  ) {
    super(message);
    this.name = 'PricingUnavailableError';
  }
}

export function isValidCurrencyCode(currency: string): boolean {
  return /^[A-Z]{3}$/.test(currency.trim().toUpperCase());
}

export async function getCurrentPricing(
  env: CloudflareEnv = {},
  clientOverride?: FirestoreRestClient
): Promise<PricingConfig> {
  if (!clientOverride && !hasFirebaseAdminCredentials(env)) {
    throw new PricingUnavailableError(
      'Credenciales de servidor Firebase no configuradas en Cloudflare para consultar la tarifa vigente.',
      'not_configured'
    );
  }

  let data: Partial<PricingConfig> | null;
  try {
    const client = clientOverride || createFirestoreRestClient(env);
    data = await client.getDocument<Partial<PricingConfig>>(PRICING_DOC_PATH);
  } catch (err: any) {
    throw new PricingUnavailableError(
      `No se pudo consultar la tarifa vigente en Firestore (${PRICING_DOC_PATH}): ${err?.message || err}`,
      'firestore_error',
      err
    );
  }

  if (!data) {
    throw new PricingUnavailableError(
      `No existe configuración de tarifa vigente en Firestore (${PRICING_DOC_PATH}).`,
      'not_configured'
    );
  }

  const monto = Number(data?.monto);
  const moneda = typeof data?.moneda === 'string' ? data.moneda.trim().toUpperCase() : '';

  if (!Number.isFinite(monto) || monto <= 0 || !isValidCurrencyCode(moneda)) {
    throw new PricingUnavailableError(
      `La tarifa vigente registrada en Firestore (${PRICING_DOC_PATH}) es inválida o está incompleta.`,
      'invalid_config'
    );
  }

  return {
    monto,
    moneda,
    periodicidad: 'mensual',
    actualizadoEl: data?.actualizadoEl || new Date().toISOString(),
    actualizadoPor: data?.actualizadoPor || 'administrador',
    motivoCambio: data?.motivoCambio
  };
}

export async function initializePricing(
  montoInicial: number,
  monedaInicial: string,
  adminEmail: string,
  motivoCambio?: string,
  env: CloudflareEnv = {},
  clientOverride?: FirestoreRestClient
): Promise<{ created: boolean; alreadyInitialized: boolean; pricing: PricingConfig }> {
  const monto = Number(montoInicial);
  const moneda = String(monedaInicial || '').toUpperCase().trim();

  if (!Number.isFinite(monto) || monto <= 0) {
    throw new Error('El monto inicial debe ser un número finito mayor a 0.');
  }
  if (!isValidCurrencyCode(moneda)) {
    throw new Error('La moneda inicial debe ser un código ISO de 3 letras válido (ej. ARS).');
  }

  const client = clientOverride || createFirestoreRestClient(env);
  const nowIso = new Date().toISOString();

  return client.runTransaction(async (tx) => {
    const existing = await tx.getDocument<Partial<PricingConfig>>(PRICING_DOC_PATH);

    if (existing) {
      const existingMonto = Number(existing.monto);
      const existingMoneda =
        typeof existing.moneda === 'string' ? existing.moneda.trim().toUpperCase() : '';

      if (Number.isFinite(existingMonto) && existingMonto > 0 && isValidCurrencyCode(existingMoneda)) {
        return {
          created: false,
          alreadyInitialized: true,
          pricing: {
            monto: existingMonto,
            moneda: existingMoneda,
            periodicidad: 'mensual',
            actualizadoEl: existing.actualizadoEl || nowIso,
            actualizadoPor: existing.actualizadoPor || 'administrador',
            motivoCambio: existing.motivoCambio
          }
        };
      }
    }

    const initialConfig: PricingConfig = {
      monto,
      moneda,
      periodicidad: 'mensual',
      actualizadoEl: nowIso,
      actualizadoPor: adminEmail,
      motivoCambio: motivoCambio || 'Inicialización comercial de tarifa vigente'
    };

    const historyId = globalThis.crypto.randomUUID().replace(/-/g, '').slice(0, 20);
    tx.setDocument(PRICING_DOC_PATH, initialConfig, false);
    tx.createDocument(`${PRICING_HISTORY_COLLECTION}/${historyId}`, {
      ...initialConfig,
      timestamp: nowIso
    });

    return {
      created: true,
      alreadyInitialized: false,
      pricing: initialConfig
    };
  });
}

export async function updatePricing(
  nuevoMonto: number,
  nuevaMoneda: string,
  adminEmail: string,
  motivoCambio?: string,
  env: CloudflareEnv = {},
  clientOverride?: FirestoreRestClient
): Promise<PricingConfig> {
  const monto = Number(nuevoMonto);
  const moneda = String(nuevaMoneda || '').toUpperCase().trim();
  if (!Number.isFinite(monto) || monto <= 0) {
    throw new Error('El monto mensual debe ser un número finito mayor a 0.');
  }
  if (!isValidCurrencyCode(moneda)) {
    throw new Error('La moneda debe ser un código ISO de 3 letras válido (ej. ARS).');
  }

  const client = clientOverride || createFirestoreRestClient(env);
  const nowIso = new Date().toISOString();

  const newConfig: PricingConfig = {
    monto,
    moneda,
    periodicidad: 'mensual',
    actualizadoEl: nowIso,
    actualizadoPor: adminEmail,
    motivoCambio: motivoCambio || 'Actualización comercial de tarifa'
  };

  await client.setDocument(PRICING_DOC_PATH, newConfig, true);
  await client.addDocument(PRICING_HISTORY_COLLECTION, {
    ...newConfig,
    timestamp: nowIso
  });

  return newConfig;
}

export async function getPricingHistory(
  limitCount: number = 20,
  env: CloudflareEnv = {},
  clientOverride?: FirestoreRestClient
): Promise<PricingHistoryEntry[]> {
  try {
    if (!clientOverride && !hasFirebaseAdminCredentials(env)) {
      return [];
    }
    const client = clientOverride || createFirestoreRestClient(env);
    const rows = await client.runQuery<PricingConfig>(PRICING_PARENT_DOC_PATH, {
      from: [{ collectionId: 'historial' }],
      orderBy: [{ field: { fieldPath: 'actualizadoEl' }, direction: 'DESCENDING' }],
      limit: limitCount
    });

    return rows.map((row) => ({
      id: row.id,
      ...row.data
    }));
  } catch (err) {
    console.warn('Error al leer historial de precios:', err);
    return [];
  }
}
