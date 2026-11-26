import { initializeApp, getApps, getApp, FirebaseApp } from 'firebase/app';
import {
  getAuth,
  signInAnonymously,
  sendSignInLinkToEmail,
  isSignInWithEmailLink,
  signInWithEmailLink,
  signOut,
  onAuthStateChanged,
  User,
  Auth
} from 'firebase/auth';
import { velDb } from '../db/db';

const firebaseConfig = {
  apiKey: "AIzaSyAHtyvXUF6gfv1kpOwdDkMrorJlq5pw26A",
  authDomain: "proyecto-vel.firebaseapp.com",
  projectId: "proyecto-vel",
  messagingSenderId: "606785327115",
  appId: "1:606785327115:web:22e0f143078f6dbdd9f70e"
};

const DEVICE_APP_NAME = 'vel-device-auth';
const PENDING_EMAIL_LINK_KEY = 'pending_commercial_email_link';

// 1. Instancia principal (Portal comercial, suscripciones y administración sin contraseña)
export const app: FirebaseApp = getApps().some((a) => a.name === '[DEFAULT]')
  ? getApp()
  : initializeApp(firebaseConfig);
export const auth: Auth = getAuth(app);

// 2. Instancia técnica aislada (Autenticación anónima del dispositivo CORE / MÓVIL)
// Garantiza que la sesión técnica del dispositivo nunca sobrescriba ni mezcle UIDs con el suscriptor comercial.
export const deviceApp: FirebaseApp = getApps().some((a) => a.name === DEVICE_APP_NAME)
  ? getApp(DEVICE_APP_NAME)
  : initializeApp(firebaseConfig, DEVICE_APP_NAME);
export const deviceAuth: Auth = getAuth(deviceApp);

/**
 * Traduce códigos de error técnicos de Firebase Auth a mensajes comprensibles en español.
 */
export function getAuthErrorMessage(errorCode: string): string {
  switch (errorCode) {
    case 'auth/invalid-email':
      return 'El formato del correo electrónico no es válido.';
    case 'auth/user-disabled':
      return 'Esta cuenta ha sido inhabilitada. Contacta al soporte.';
    case 'auth/too-many-requests':
      return 'Demasiados intentos recientes. Por seguridad, espera unos minutos antes de volver a intentar.';
    case 'auth/network-request-failed':
      return 'Problema de conexión con los servidores de Firebase. Comprueba tu acceso a internet.';
    case 'auth/missing-email':
      return 'Por favor ingresa tu correo electrónico.';
    case 'auth/operation-not-allowed':
    case 'auth/admin-restricted-operation':
    case 'auth/configuration-not-found':
      return 'El proveedor de acceso técnico (Anonymous Authentication) no está habilitado o configurado en Firebase Console.';
    case 'auth/unauthorized-continue-uri':
    case 'auth/invalid-continue-uri':
    case 'auth/unauthorized-domain':
      return 'El dominio actual no está autorizado en Firebase Authentication (Authorized domains).';
    case 'auth/api-key-not-valid':
    case 'auth/invalid-api-key':
    case 'auth/app-not-authorized':
      return 'La configuración de Firebase Web App (API key / proyecto) no es válida o no está autorizada.';
    case 'auth/expired-action-code':
      return 'El enlace de verificación de un solo uso ha expirado. Solicita un nuevo enlace.';
    case 'auth/invalid-action-code':
      return 'El enlace de verificación ya fue utilizado o no es válido. Solicita uno nuevo.';
    default:
      return errorCode
        ? `Ocurrió un error al validar la identidad en Firebase Authentication (${errorCode}).`
        : 'Ocurrió un error al validar la identidad en Firebase Authentication.';
  }
}

export interface DeviceAnonymousAuthResult {
  success: boolean;
  uid?: string;
  idToken?: string;
  providerDisabled?: boolean;
  errorCode?: string;
  errorMessage?: string;
}

/**
 * Inicia o recupera la sesión técnica anónima del dispositivo (sin correo ni contraseña).
 * No sustituye ni modifica la sesión comercial del suscriptor.
 */
export async function ensureDeviceAnonymousSession(): Promise<DeviceAnonymousAuthResult> {
  try {
    if (typeof (deviceAuth as any).authStateReady === 'function') {
      try {
        await (deviceAuth as any).authStateReady();
      } catch {
        // Continuar evaluando currentUser si authStateReady falla transitoriamente
      }
    }
    let user = deviceAuth.currentUser;
    if (!user) {
      const credential = await signInAnonymously(deviceAuth);
      user = credential.user;
    }
    const idToken = await user.getIdToken(true);
    return {
      success: true,
      uid: user.uid,
      idToken
    };
  } catch (err: any) {
    const code = String(err?.code || '');
    const providerDisabled =
      code === 'auth/operation-not-allowed' ||
      code === 'auth/admin-restricted-operation' ||
      code === 'auth/configuration-not-found';
    return {
      success: false,
      providerDisabled,
      errorCode: code || 'unknown',
      errorMessage: providerDisabled
        ? `Firebase Anonymous Authentication no está habilitado en Firebase Console para proyecto-vel (${code}).`
        : getAuthErrorMessage(code)
    };
  }
}

export async function getFreshDeviceAuthToken(): Promise<string | null> {
  if (typeof (deviceAuth as any).authStateReady === 'function') {
    try {
      await (deviceAuth as any).authStateReady();
    } catch {
      // Continuar con currentUser si authStateReady falla
    }
  }
  let user = deviceAuth.currentUser;
  if (!user) {
    const recovered = await ensureDeviceAnonymousSession();
    if (recovered.success && recovered.idToken) {
      return recovered.idToken;
    }
    return null;
  }
  try {
    return await user.getIdToken(true);
  } catch {
    const recovered = await ensureDeviceAnonymousSession();
    return recovered.success && recovered.idToken ? recovered.idToken : null;
  }
}

export async function signOutDeviceAuth(): Promise<void> {
  if (deviceAuth.currentUser) {
    await signOut(deviceAuth);
  }
}

export function subscribeToDeviceAuthChanges(callback: (user: User | null) => void) {
  return onAuthStateChanged(deviceAuth, callback);
}

/**
 * Envía un enlace de verificación de un solo uso sin contraseña (Email Link)
 * para nuevos suscriptores o suscriptores históricos existentes (conserva su mismo UID).
 * Guarda el correo pendiente temporalmente en IndexedDB (nunca en localStorage).
 */
export async function sendPasswordlessSignInLink(email: string, continueUrl?: string): Promise<void> {
  const cleanEmail = email.trim();
  const targetUrl =
    continueUrl ||
    (typeof window !== 'undefined'
      ? `${window.location.origin}${window.location.pathname}`
      : (typeof import.meta !== 'undefined' && (import.meta as any).env?.VITE_APP_BASE_URL) || '/');

  await sendSignInLinkToEmail(auth, cleanEmail, {
    url: targetUrl,
    handleCodeInApp: true
  });

  try {
    await velDb.setConfig(PENDING_EMAIL_LINK_KEY, cleanEmail);
  } catch {
    // Si IndexedDB no está disponible transitoriamente, el usuario podrá confirmar su correo al regresar
  }
}

export function isIncomingPasswordlessSignInLink(href?: string): boolean {
  const target = href || (typeof window !== 'undefined' ? window.location.href : '');
  if (!target) return false;
  return isSignInWithEmailLink(auth, target);
}

export async function getPendingEmailForLink(): Promise<string | null> {
  try {
    const stored = await velDb.getConfig<string>(PENDING_EMAIL_LINK_KEY);
    return stored || null;
  } catch {
    return null;
  }
}

export async function clearPendingEmailForLink(): Promise<void> {
  try {
    await velDb.deleteConfig(PENDING_EMAIL_LINK_KEY);
  } catch {
    // Silencioso
  }
}

/**
 * Completa la verificación de un solo uso desde el enlace recibido por correo.
 * Preserva el UID histórico si la cuenta ya existía con contraseña anteriormente.
 */
export async function completePasswordlessSignInLink(
  emailOverride?: string,
  href?: string
): Promise<{
  completed: boolean;
  needsEmailConfirmation?: boolean;
  user?: User;
  error?: string;
}> {
  const targetHref = href || (typeof window !== 'undefined' ? window.location.href : '');
  if (!targetHref || !isSignInWithEmailLink(auth, targetHref)) {
    return { completed: false };
  }

  const email = (emailOverride || (await getPendingEmailForLink()) || '').trim();
  if (!email) {
    return {
      completed: false,
      needsEmailConfirmation: true,
      error: 'Confirma el correo electrónico en el que recibiste el enlace de acceso para completar la verificación.'
    };
  }

  try {
    const credential = await signInWithEmailLink(auth, email, targetHref);
    await clearPendingEmailForLink();
    return {
      completed: true,
      user: credential.user
    };
  } catch (err: any) {
    return {
      completed: false,
      error: getAuthErrorMessage(String(err?.code || ''))
    };
  }
}

/**
 * Cierra la sesión comercial activa en Firebase Authentication.
 */
export async function logoutUser(): Promise<void> {
  await signOut(auth);
}

/**
 * Suscriptor al estado de autenticación comercial (onAuthStateChanged).
 */
export function subscribeToAuthChanges(callback: (user: User | null) => void) {
  return onAuthStateChanged(auth, callback);
}

export type { User };
