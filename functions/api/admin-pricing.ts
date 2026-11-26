import {
  isUserAdmin,
  verifyUserToken
} from '../../cloudflare/shared/firebaseRest';
import { jsonResponse, parseJsonBody } from '../../cloudflare/shared/http';
import {
  getCurrentPricing,
  getPricingHistory,
  initializePricing,
  isValidCurrencyCode,
  PricingUnavailableError,
  updatePricing
} from '../../cloudflare/shared/pricingService';
import type {
  CloudflareEnv,
  CloudflarePagesContext,
  PricingConfig,
  PricingHistoryEntry
} from '../../cloudflare/shared/types';

export interface AdminPricingDeps {
  verifyToken?: (
    authHeader?: string,
    env?: CloudflareEnv
  ) => Promise<{ uid: string; email?: string; claims?: Record<string, any> } | null>;
  getUserClaims?: (uid: string) => Promise<any>;
  isAdmin?: (email?: string, claims?: any) => boolean;
  getPricing?: (env?: CloudflareEnv) => Promise<PricingConfig>;
  getHistory?: (limitCount?: number, env?: CloudflareEnv) => Promise<PricingHistoryEntry[]>;
  initPricing?: (
    monto: number,
    moneda: string,
    adminEmail: string,
    motivo?: string,
    env?: CloudflareEnv
  ) => Promise<{ created: boolean; alreadyInitialized: boolean; pricing: PricingConfig }>;
  savePricing?: (
    monto: number,
    moneda: string,
    adminEmail: string,
    motivo?: string,
    env?: CloudflareEnv
  ) => Promise<PricingConfig>;
}

export async function handleAdminPricing(
  context: CloudflarePagesContext,
  deps: AdminPricingDeps = {}
): Promise<Response> {
  const { request, env = {} } = context;

  const authHeader = request.headers.get('authorization') ?? undefined;
  const verifyTokenFn = deps.verifyToken || ((hdr?: string) => verifyUserToken(hdr, env));
  const verifiedUser = await verifyTokenFn(authHeader, env);

  if (!verifiedUser) {
    return jsonResponse(401, {
      error: 'No autorizado. Se requiere inicio de sesión administrativo.'
    });
  }

  let userClaims: any = verifiedUser.claims ?? null;
  if (deps.getUserClaims) {
    try {
      userClaims = await deps.getUserClaims(verifiedUser.uid);
    } catch {
      // Si no se pueden obtener claims adicionales, se evalúa por claims del JWT y email
    }
  }

  const isAdminFn = deps.isAdmin || isUserAdmin;
  if (!isAdminFn(verifiedUser.email, userClaims)) {
    return jsonResponse(403, {
      error: 'Acceso denegado. Tu cuenta no cuenta con permisos para modificar precios del servicio.'
    });
  }

  if (request.method === 'GET') {
    const getHistoryFn = deps.getHistory || ((limitCount = 25) => getPricingHistory(limitCount, env));
    const getPricingFn = deps.getPricing || (() => getCurrentPricing(env));
    const history = await getHistoryFn(25, env);

    try {
      const current = await getPricingFn(env);
      return jsonResponse(200, {
        success: true,
        initialized: true,
        current,
        history
      });
    } catch (err: any) {
      if (
        (err instanceof PricingUnavailableError || err?.code === 'PRICING_UNAVAILABLE') &&
        (err.reason === 'not_configured' || err.reason === 'invalid_config')
      ) {
        return jsonResponse(200, {
          success: true,
          initialized: false,
          requiresInitialization: true,
          current: null,
          history,
          mensaje:
            'La configuración comercial (configuracion_comercial/precios) aún no ha sido inicializada por un administrador.'
        });
      }

      return jsonResponse(503, {
        success: false,
        error: err?.message || 'Error consultando la configuración comercial vigente en Firestore.'
      });
    }
  }

  if (request.method === 'POST') {
    const parsed = await parseJsonBody(request);
    if (!parsed.ok) {
      return jsonResponse(400, {
        error: 'Cuerpo de solicitud JSON inválido.'
      });
    }

    const body = parsed.data;
    const action = String(body.action || 'update').toLowerCase().trim();
    const nuevoMonto = Number(body.monto);
    const nuevaMoneda =
      body.moneda !== undefined && body.moneda !== null
        ? String(body.moneda).toUpperCase().trim()
        : action === 'initialize'
        ? ''
        : 'ARS';
    const motivo = body.motivoCambio
      ? String(body.motivoCambio).trim()
      : action === 'initialize'
      ? 'Inicialización comercial de tarifa vigente'
      : 'Actualización de tarifa comercial';

    if (!Number.isFinite(nuevoMonto) || nuevoMonto <= 0) {
      return jsonResponse(400, {
        error: 'El monto mensual debe ser un número positivo mayor a 0.'
      });
    }

    if (!isValidCurrencyCode(nuevaMoneda)) {
      return jsonResponse(400, {
        error: 'Debes indicar un código de moneda ISO válido de 3 letras (por ejemplo, ARS).'
      });
    }

    try {
      if (action === 'initialize') {
        const initFn =
          deps.initPricing ||
          ((monto: number, moneda: string, adminEmail: string, m?: string) =>
            initializePricing(monto, moneda, adminEmail, m, env));

        const initResult = await initFn(
          nuevoMonto,
          nuevaMoneda,
          verifiedUser.email || verifiedUser.uid,
          motivo,
          env
        );

        if (initResult.alreadyInitialized) {
          return jsonResponse(409, {
            success: false,
            alreadyInitialized: true,
            error:
              'La configuración comercial (configuracion_comercial/precios) ya fue inicializada y no se sobrescribe mediante inicialización.',
            pricing: initResult.pricing
          });
        }

        return jsonResponse(201, {
          success: true,
          initialized: true,
          mensaje: 'Configuración comercial inicializada exitosamente.',
          pricing: initResult.pricing
        });
      }

      const saveFn =
        deps.savePricing ||
        ((monto: number, moneda: string, adminEmail: string, m?: string) =>
          updatePricing(monto, moneda, adminEmail, m, env));

      const updated = await saveFn(
        nuevoMonto,
        nuevaMoneda,
        verifiedUser.email || verifiedUser.uid,
        motivo,
        env
      );

      return jsonResponse(200, {
        success: true,
        mensaje: 'Precio comercial actualizado exitosamente.',
        reglaComercial:
          'Los nuevos suscriptores contratarán a este nuevo valor. Los suscriptores existentes conservan su precio de contratación original.',
        pricing: updated
      });
    } catch (err: any) {
      return jsonResponse(500, {
        error: `Fallo al guardar nuevo precio: ${err?.message || err}`
      });
    }
  }

  return jsonResponse(405, {
    error: 'Método no permitido. Utilizar GET o POST.'
  });
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handleAdminPricing(context);
};
