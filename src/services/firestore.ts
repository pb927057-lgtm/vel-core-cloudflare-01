import {
  getFirestore,
  doc,
  getDoc,
  setDoc,
  serverTimestamp,
  Timestamp
} from 'firebase/firestore';
import { app } from './firebase';

export const db = getFirestore(app);

export interface SuscriptorDocument {
  uid: string;
  email: string;
  estado: 'pendiente_pago' | 'activo' | 'en_gracia' | 'suspendido' | 'vencido' | 'cancelado';
  plan: string | null;
  fechaAlta: Timestamp | any;
  venceEl: string | null;
  // Campos comerciales Mercado Pago y Período de Gracia
  modalidadComercial?: 'manual_30d' | 'preapproval' | null;
  mpPreapprovalId?: string | null;
  mpPreferenceId?: string | null;
  mpExternalReference?: string | null;
  ultimoPagoId?: string | null;
  ultimaTarifaConsultada?: number | null;
  ultimaSolicitudPagoEl?: string | null;
  fechaUltimoPago?: string | null;
  fechaProximoPago?: string | null;
  fechaInicioGracia?: string | null;
  precioContratado?: number | null;
  moneda?: string | null;
  canceladoEl?: string | null;
  ultimoReembolsoEl?: string | null;
  ultimoMotivoReversion?: string | null;
}

export interface AceptacionContratoDocument {
  uid: string;
  versionContrato: string;
  urlContrato: string;
  aceptado: boolean;
  fechaAceptacion: Timestamp | any;
}

export interface AceptacionResult {
  success: boolean;
  doc: AceptacionContratoDocument | null;
  error?: string;
  isPermissionError?: boolean;
}

export interface SyncResult {
  success: boolean;
  doc: SuscriptorDocument | null;
  alreadyExisted: boolean;
  error?: string;
  isPermissionError?: boolean;
}

/**
 * Traduce errores técnicos de Firestore a explicaciones claras en español.
 */
export function getFirestoreErrorMessage(error: any): { message: string; isPermissionError: boolean } {
  const code = error?.code || '';
  if (code === 'permission-denied') {
    return {
      message: 'Acceso denegado por las reglas de seguridad de Firestore. Debes aplicar las reglas de acceso en Firebase Console.',
      isPermissionError: true
    };
  }
  if (code === 'unavailable') {
    return {
      message: 'Servicio de base de datos no disponible temporalmente. Comprueba tu conexión.',
      isPermissionError: false
    };
  }
  return {
    message: error?.message || 'Error al comunicar con Cloud Firestore.',
    isPermissionError: false
  };
}

/**
 * Obtiene el documento administrativo de un suscriptor a partir de su UID.
 */
export async function getSubscriberDocument(uid: string): Promise<SuscriptorDocument | null> {
  const docRef = doc(db, 'suscriptores', uid);
  const snap = await getDoc(docRef);
  if (snap.exists()) {
    return snap.data() as SuscriptorDocument;
  }
  return null;
}

/**
 * Asegura la existencia de la ficha administrativa del suscriptor en Firestore:
 * 1. Verifica si ya existe el documento suscriptores/{uid}.
 * 2. Si existe, no lo duplica ni sobreescribe sus campos, retornando los datos actuales.
 * 3. Si no existe, crea la ficha inicial:
 *    - uid: UID de Firebase Auth
 *    - email: Correo autenticado
 *    - estado: "pendiente_pago"
 *    - plan: null
 *    - fechaAlta: serverTimestamp()
 *    - venceEl: null
 */
export async function ensureSubscriberDocument(uid: string, email: string): Promise<SyncResult> {
  const docRef = doc(db, 'suscriptores', uid);

  try {
    // 1. Comprobación previa para evitar duplicados y preservar estado
    const snap = await getDoc(docRef);
    if (snap.exists()) {
      return {
        success: true,
        doc: snap.data() as SuscriptorDocument,
        alreadyExisted: true
      };
    }

    // 2. Creación del documento inicial con campos estrictos
    const newDocData: SuscriptorDocument = {
      uid,
      email: email.trim(),
      estado: 'pendiente_pago',
      plan: null,
      fechaAlta: serverTimestamp(),
      venceEl: null
    };

    await setDoc(docRef, newDocData);

    return {
      success: true,
      doc: newDocData,
      alreadyExisted: false
    };
  } catch (error: any) {
    const parsed = getFirestoreErrorMessage(error);
    return {
      success: false,
      doc: null,
      alreadyExisted: false,
      error: parsed.message,
      isPermissionError: parsed.isPermissionError
    };
  }
}

/**
 * Constantes oficiales del contrato de VEL.
 */
export const OFFICIAL_CONTRACT_URL = 'https://proyecto-vel.blogspot.com/2026/11/terminos-y-condiciones-y-contrato-de-uso.html';
export const CURRENT_CONTRACT_VERSION = '1.2';

/**
 * Identifica si la versión actual es un borrador previo no apto para contratación comercial definitiva.
 */
export function isDraftContractVersion(version: string = CURRENT_CONTRACT_VERSION): boolean {
  return version.toLowerCase().includes('draft') || version.toLowerCase().includes('borrador');
}

/**
 * Consulta el registro de aceptación del contrato para una versión específica (por defecto la versión vigente).
 * 1. Primero busca en la subcolección de historial 'suscriptores/{uid}/historial_contratos/{versionContrato}'
 *    para permitir conservar todas las versiones firmadas a lo largo del tiempo.
 * 2. Si no existe, consulta como compatibilidad directa 'aceptaciones_contrato/{uid}'.
 * 3. Valida estrictamente que el documento encontrado corresponda a la versión requerida.
 */
export async function getContractAcceptance(
  uid: string,
  targetVersion: string = CURRENT_CONTRACT_VERSION
): Promise<AceptacionContratoDocument | null> {
  if (!uid) return null;

  // 1. Consulta en subcolección inmutable de historial
  const historyRef = doc(db, 'suscriptores', uid, 'historial_contratos', targetVersion);
  const historySnap = await getDoc(historyRef);
  if (historySnap.exists()) {
    const data = historySnap.data() as AceptacionContratoDocument;
    if (data.versionContrato === targetVersion && data.aceptado === true) {
      return data;
    }
  }

  // 2. Consulta en la colección raíz de aceptación
  const legacyRef = doc(db, 'aceptaciones_contrato', uid);
  const legacySnap = await getDoc(legacyRef);
  if (legacySnap.exists()) {
    const data = legacySnap.data() as AceptacionContratoDocument;
    // Comprobación estricta de versión vigente: una versión draft nunca se equipara a final
    if (data.versionContrato === targetVersion && data.aceptado === true) {
      return data;
    }
  }

  return null;
}

/**
 * Registra formalmente la aceptación del contrato preservando el historial completo.
 * 
 * ARQUITECTURA DE ALMACENAMIENTO:
 * 1. REGISTRO PRINCIPAL (Historial Inmutable):
 *    Se almacena en 'suscriptores/{uid}/historial_contratos/{versionContrato}'.
 *    Al usar la versión como ID de documento dentro de la subcolección del suscriptor,
 *    se garantiza que la aceptación de una versión (ej: '1.0-draft') NO sobrescribe
 *    ni colisiona con la futura aceptación de otra versión (ej: '1.0-final').
 * 
 * 2. REGISTRO DE COMPATIBILIDAD / ESTADO ACTUAL:
 *    Se intenta registrar en 'aceptaciones_contrato/{uid}'. Si ya existe porque las reglas
 *    impiden actualizar documentos (inmutabilidad), la operación principal no falla,
 *    asegurando que el historial del cliente siempre quede acreditado legalmente.
 * 
 * - NO altera el documento administrativo en 'suscriptores/{uid}'.
 */
// Lista de identificadores de cuentas técnicas reservadas (identificadas por correo electrónico)
// NOTA: El UID alfanumérico generado por Firebase Auth para la cuenta técnica no está hardcodeado
// en el código local para no inventar datos. Si se conoce el UID real de la cuenta técnica,
// puede agregarse a la lista 'uids'. Mientras tanto, la exclusión opera por email verificado.
export const TECHNICAL_ACCOUNTS = {
  emails: ['soporte@vel.com', 'admin@vel.com', 'pb927057@gmail.com'],
  uids: [] as string[]
};

/**
 * Comprueba si una cuenta corresponde a la cuenta técnica de prueba de VEL.
 */
export function isTechnicalAccount(uid?: string | null, email?: string | null): boolean {
  if (uid && TECHNICAL_ACCOUNTS.uids.includes(uid)) {
    return true;
  }
  if (email) {
    const em = email.toLowerCase().trim();
    if (TECHNICAL_ACCOUNTS.emails.includes(em) || em.includes('soporte@vel') || em.includes('admin@vel')) {
      return true;
    }
  }
  return false;
}

/**
 * Registra formalmente la aceptación del contrato preservando el historial completo.
 * 
 * ARQUITECTURA DE ALMACENAMIENTO Y GARANTÍAS:
 * 1. PROTECCIÓN DE CUENTA TÉCNICA:
 *    Comprueba la cuenta antes de cualquier mutación para evitar registros simulados.
 * 
 * 2. COMPROBACIÓN EXCLUSIVA EN EL HISTORIAL PRINCIPAL:
 *    Comprueba directamente 'suscriptores/{uid}/historial_contratos/{versionContrato}'.
 *    NO devuelve éxito basándose en el documento raíz secundario 'aceptaciones_contrato/{uid}'.
 * 
 * 3. DISTINCIÓN CLARA DE FECHA DEL SERVIDOR:
 *    Tras setDoc(), recupera el documento para obtener el Timestamp real del servidor.
 *    Si la lectura posterior no logra recuperar el Timestamp, retorna el registro confirmado
 *    con fechaAceptacion: null y dateNotRecovered: true, evitando presentar el centinela local
 *    serverTimestamp() como si fuera una fecha resuelta.
 * 
 * 4. CONCURRENCIA ESTRICTA (Carrera de creación):
 *    Solo si el error recibido corresponde específicamente a una denegación por documento existente
 *    ('permission-denied' o 'already-exists'), consulta el historial y retorna éxito si y solo si
 *    el documento existente coincide con UID, versión, URL oficial y aceptación afirmativa.
 *    No enmascara errores reales de red ni desconexiones.
 * 
 * - NO altera el documento administrativo en 'suscriptores/{uid}'.
 */
export async function recordContractAcceptance(
  uid: string,
  versionContrato: string = CURRENT_CONTRACT_VERSION,
  urlContrato: string = OFFICIAL_CONTRACT_URL,
  userEmail?: string | null
): Promise<AceptacionResult & { dateNotRecovered?: boolean }> {
  // 1. Protección de cuenta técnica
  if (isTechnicalAccount(uid, userEmail)) {
    return {
      success: false,
      doc: null,
      error: 'Operación bloqueada: La cuenta técnica reservada no puede registrarse como un cliente particular.'
    };
  }

  const historyRef = doc(db, 'suscriptores', uid, 'historial_contratos', versionContrato);

  try {
    // 2. Comprobación directa y exclusiva en el historial principal
    const existingSnap = await getDoc(historyRef);
    if (existingSnap.exists()) {
      const existingData = existingSnap.data() as AceptacionContratoDocument;
      if (
        existingData.uid === uid &&
        existingData.versionContrato === versionContrato &&
        existingData.urlContrato === urlContrato &&
        existingData.aceptado === true
      ) {
        return {
          success: true,
          doc: existingData
        };
      }
    }

    // 3. Payload estricto con timestamp de servidor
    const payloadParaGuardar = {
      uid,
      versionContrato,
      urlContrato,
      aceptado: true,
      fechaAceptacion: serverTimestamp()
    };

    // 4. Destino Principal: Subcolección inmutable de historial
    await setDoc(historyRef, payloadParaGuardar);

    // 5. Destino Secundario: Documento de compatibilidad en la raíz (aislado)
    try {
      const legacyRef = doc(db, 'aceptaciones_contrato', uid);
      await setDoc(legacyRef, payloadParaGuardar);
    } catch {
      // Si el documento raíz ya existía con otra versión y las reglas bloquean update,
      // el registro oficial en historial persiste de forma independiente
    }

    // 6. Recuperación posterior para confirmar la fecha real generada por el servidor
    try {
      const snapConfirmado = await getDoc(historyRef);
      if (snapConfirmado.exists()) {
        const docConfirmado = snapConfirmado.data() as AceptacionContratoDocument;
        return {
          success: true,
          doc: docConfirmado
        };
      }
    } catch {
      // La lectura posterior no pudo completarse transitoriamente.
      // Se informa registro confirmado pero con fecha pendiente de recuperación (null).
      return {
        success: true,
        doc: {
          uid,
          versionContrato,
          urlContrato,
          aceptado: true,
          fechaAceptacion: null
        },
        dateNotRecovered: true
      };
    }

    // En caso de que el snap no existiera inmediatamente por latencia de replicación:
    return {
      success: true,
      doc: {
        uid,
        versionContrato,
        urlContrato,
        aceptado: true,
        fechaAceptacion: null
      },
      dateNotRecovered: true
    };
  } catch (error: any) {
    const errorCode = error?.code || '';

    // 7. Manejo específico de concurrencia:
    // Solo cuando el error sea denegación por documento ya existente ('permission-denied')
    // se comprueba si la solicitud paralela ya creó el documento en el historial principal.
    if (errorCode === 'permission-denied' || errorCode === 'already-exists') {
      try {
        const verifySnap = await getDoc(historyRef);
        if (verifySnap.exists()) {
          const verifyData = verifySnap.data() as AceptacionContratoDocument;
          // Solo devolver éxito si verifica coincidencia exacta en todos los parámetros requeridos
          if (
            verifyData.uid === uid &&
            verifyData.versionContrato === versionContrato &&
            verifyData.urlContrato === urlContrato &&
            verifyData.aceptado === true
          ) {
            return {
              success: true,
              doc: verifyData
            };
          }
        }
      } catch {
        // Si no se puede verificar, se mantiene el error original sin silenciarlo
      }
    }

    const parsed = getFirestoreErrorMessage(error);
    return {
      success: false,
      doc: null,
      error: parsed.message,
      isPermissionError: parsed.isPermissionError
    };
  }
}


