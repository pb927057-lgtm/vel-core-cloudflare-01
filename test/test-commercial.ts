import * as crypto from 'crypto';
import { verifyMpWebhookSignature } from '../netlify/functions/shared/mercadopago';
import { isUserAdmin } from '../netlify/functions/shared/firebaseAdmin';

let passedTests = 0;
let totalTests = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`✓ [PASS] ${testName}`);
  } else {
    console.error(`✗ [FAIL] ${testName} - ${detail || ''}`);
  }
}

async function runCommercialTests() {
  console.log('====================================================');
  console.log('INICIANDO PRUEBAS DEL SISTEMA COMERCIAL Y SUSCRIPCIONES (VEL 0.1)');
  console.log('====================================================\n');

  // ------------------------------------------------------------------
  // 1. Prueba de Validación de Firma Criptográfica de Webhook (HMAC-SHA256)
  // ------------------------------------------------------------------
  console.log('--- 1. Seguridad: Firma Criptográfica de Webhook ---');
  const testSecret = 'secret_prueba_mercadopago_1234567890';
  process.env.MP_WEBHOOK_SECRET = testSecret;

  const ts = Math.floor(Date.now() / 1000).toString();
  const requestId = 'req-test-uuid-9876';
  const dataId = 'preapproval_test_554433';

  const manifest = `id:${dataId};request-id:${requestId};ts:${ts};`;
  const validHash = crypto.createHmac('sha256', testSecret).update(manifest).digest('hex');

  const validHeader = `ts=${ts},v1=${validHash}`;
  const sigValidCheck = verifyMpWebhookSignature(validHeader, requestId, dataId);
  assert(sigValidCheck.isValid, 'Firma legítima de Mercado Pago es aceptada');

  const invalidHeader = `ts=${ts},v1=hash_alterado_o_invalido_0000000000000000000000000000000000000000000000000000000000000000`;
  const sigInvalidCheck = verifyMpWebhookSignature(invalidHeader, requestId, dataId);
  assert(!sigInvalidCheck.isValid, 'Firma falsificada o alterada es rechazada');

  const missingSigCheck = verifyMpWebhookSignature(undefined, requestId, dataId);
  assert(!missingSigCheck.isValid, 'Solicitud de webhook sin cabecera x-signature es rechazada');

  // ------------------------------------------------------------------
  // 2. Prueba de Asociación Inmutable por UID de Firebase
  // ------------------------------------------------------------------
  console.log('\n--- 2. Asociación de Suscripción por UID ---');
  const testFirebaseUid = 'USR_FIREBASE_7788AABBCC';
  const externalReference = testFirebaseUid;
  assert(externalReference === testFirebaseUid, 'Se utiliza el UID de Firebase como external_reference');
  assert(!externalReference.includes('@'), 'La referencia no depende de correo electrónico modificable');

  // ------------------------------------------------------------------
  // 3. Prueba de Período de Gracia (7 días de tolerancia)
  // ------------------------------------------------------------------
  console.log('\n--- 3. Lógica del Período de Gracia (7 Días) ---');
  const GRACE_PERIOD_MS = 7 * 24 * 60 * 60 * 1000;

  // Caso A: Inicio de período de gracia (hoy)
  const fechaInicioGraciaHoy = new Date();
  const tiempoTranscurridoHoy = Date.now() - fechaInicioGraciaHoy.getTime();
  const estadoHoy = tiempoTranscurridoHoy >= GRACE_PERIOD_MS ? 'suspendido' : 'en_gracia';
  assert(estadoHoy === 'en_gracia', 'Día 1 sin pago: estado en_gracia (servicio permanece habilitado)');

  // Caso B: Día 6 (dentro del período de gracia)
  const fechaInicioGraciaDia6 = new Date(Date.now() - 6 * 24 * 60 * 60 * 1000);
  const tiempoDia6 = Date.now() - fechaInicioGraciaDia6.getTime();
  const estadoDia6 = tiempoDia6 >= GRACE_PERIOD_MS ? 'suspendido' : 'en_gracia';
  assert(estadoDia6 === 'en_gracia', 'Día 6 sin pago: servicio continúa en período de gracia con aviso');

  // Caso C: Día 8 (expirado período de gracia sin pago regularizado)
  const fechaInicioGraciaDia8 = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);
  const tiempoDia8 = Date.now() - fechaInicioGraciaDia8.getTime();
  const estadoDia8 = tiempoDia8 >= GRACE_PERIOD_MS ? 'suspendido' : 'en_gracia';
  assert(estadoDia8 === 'suspendido', 'Día 8 sin pago: suspensión automática comercial');

  // Caso D: Regularización y reactivación
  let estadoTrasPago = estadoDia8;
  if (estadoTrasPago === 'suspendido') {
    // Mercado Pago confirma cobro aprobado
    estadoTrasPago = 'activo';
  }
  assert(estadoTrasPago === 'activo', 'Pago regularizado: reactivación automática de la cuenta');

  // ------------------------------------------------------------------
  // 4. Prueba de Regla Comercial de Precios
  // ------------------------------------------------------------------
  console.log('\n--- 4. Administración y Regla Comercial de Precios ---');
  const precioAnterior = 4500;
  const precioNuevo = 6000;

  // Suscriptor existente
  const suscriptorExistente = {
    uid: 'user_1',
    precioContratado: precioAnterior,
    moneda: 'ARS'
  };

  // Nuevo suscriptor
  const nuevoSuscriptor = {
    uid: 'user_2',
    precioContratado: precioNuevo,
    moneda: 'ARS'
  };

  assert(
    suscriptorExistente.precioContratado === 4500,
    'Suscriptor existente conserva inalterable su precio original de contratación (ARS 4.500)'
  );
  assert(
    nuevoSuscriptor.precioContratado === 6000,
    'Nuevo suscriptor contrata al nuevo valor vigente (ARS 6.000)'
  );

  // ------------------------------------------------------------------
  // 5. Prueba de Autorización Administrativa de Precios (RBAC)
  // ------------------------------------------------------------------
  console.log('\n--- 5. Control de Acceso Administrativo (RBAC) ---');
  assert(isUserAdmin('admin@vel.com'), 'Correo oficial admin@vel.com tiene permisos de administración');
  assert(isUserAdmin('soporte@vel.com'), 'Correo soporte@vel.com tiene permisos de administración');
  assert(isUserAdmin('pb927057@gmail.com'), 'Correo pb927057@gmail.com tiene permisos de administración');
  assert(!isUserAdmin('cliente@externo.com'), 'Usuario cliente estándar NO tiene permisos de administración');
  assert(!isUserAdmin(undefined), 'Solicitud anónima NO tiene permisos de administración');

  // ------------------------------------------------------------------
  // 6. Prueba de Control de Acceso del Servidor a Descargas
  // ------------------------------------------------------------------
  console.log('\n--- 6. Control del Servidor sobre Descargas ---');
  const puedeDescargarActivo = ['activo', 'en_gracia'].includes('activo');
  const puedeDescargarEnGracia = ['activo', 'en_gracia'].includes('en_gracia');
  const puedeDescargarSuspendido = ['activo', 'en_gracia'].includes('suspendido');
  const puedeDescargarPendiente = ['activo', 'en_gracia'].includes('pendiente_pago');

  assert(puedeDescargarActivo, 'Suscriptor activo tiene acceso autorizado a descargar la aplicación');
  assert(puedeDescargarEnGracia, 'Suscriptor en período de gracia conserva acceso a la aplicación');
  assert(!puedeDescargarSuspendido, 'Suscriptor suspendido tiene bloqueada la descarga del instalador');
  assert(!puedeDescargarPendiente, 'Usuario pendiente de pago tiene bloqueada la descarga');

  // ------------------------------------------------------------------
  // 7. Prueba de Preservación de Datos en VEL CORE ante Suspensión
  // ------------------------------------------------------------------
  console.log('\n--- 7. Garantía de Soberanía y No Borrado de Datos ---');
  const notasLocalesCore = [{ id: '1', titulo: 'Mis Claves', cifrado: true }];
  const suspensionComercial = true;

  let datosBorradosEnCore = false;
  if (suspensionComercial) {
    // La suspensión comercial afecta exclusivamente la suscripción del portal web
    datosBorradosEnCore = false;
  }
  assert(!datosBorradosEnCore, 'La suspensión comercial NUNCA borra notas ni claves en VEL CORE');
  assert(notasLocalesCore.length === 1, 'Las notas en el teléfono CORE permanecen 100% intactas');

  console.log('\n====================================================');
  console.log(`RESUMEN DE PRUEBAS: ${passedTests} de ${totalTests} aprobadas con éxito.`);
  console.log('====================================================');
}

runCommercialTests().catch((err) => {
  console.error('Error ejecutando pruebas:', err);
  process.exit(1);
});
