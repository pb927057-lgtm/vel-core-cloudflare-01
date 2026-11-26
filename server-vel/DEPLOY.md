# VEL 0.1 — Despliegue del Servidor Relay WebSocket (`server-vel/relay-server.ts`)

## Por qué el Relay NO corre dentro de Netlify Functions

Netlify Functions son funciones HTTP efímeras (*stateless* y con tiempo máximo de ejecución por petición). Un canal WebSocket persistente para conectar **VEL CORE** y **VEL MÓVIL** en tiempo real requiere un proceso **Node.js persistente** capaz de mantener sockets `wss://` abiertos y pasar datos directamente de teléfono a teléfono en memoria RAM.

El Relay de VEL es **directo y sin nube para tus archivos**:
- Nunca almacena fotos, videos, notas ni archivos en disco, Firebase ni Render (transporte exclusivo en memoria RAM).
- Autentica cada dispositivo verificando **Firebase ID Token** y las vinculaciones reales en **Cloud Firestore**.
- Si el destinatario está desconectado, no guarda copias en la nube y notifica `RECIPIENT_OFFLINE` (el VEL MÓVIL conserva el elemento en estado pendiente en su almacenamiento local hasta que VEL CORE vuelva a conectarse).

---

## Opciones de alojamiento gratuitas / de bajo costo (Node.js + WebSocket WSS)

| Proveedor | Nivel gratuito / costo | Ventajas para VEL | Limitaciones a tener en cuenta |
|---|---|---|---|
| **Render (Web Service - Free Tier)** *(Recomendada para comenzar a costo cero)* | **Gratuito ($0)** | Soporta Node.js, `npm run relay:start`, TLS `wss://` automático, `/health` check y variables de entorno. | Entra en suspensión (*spin down*) tras 15 minutos sin conexiones WebSocket activas; la primera reconexión tras reposo tarda ~30–50 s. |
| **Koyeb (Free Web Service)** | **Gratuito ($0)** | TLS `wss://` nativo y despliegue directo de Node.js. | Límites mensuales de horas/RAM; puede dormir si hay inactividad prolongada según región. |
| **Fly.io (Pay-as-you-go con margen gratuito pequeño)** | Muy bajo costo / margen gratis limitado | Excelente estabilidad de sockets persistentes en regiones cercanas. | Requiere tarjeta para verificar cuenta; facturación si se excede el margen de máquina compartida. |
| **Railway (Trial / Hobby)** | Prueba inicial limitada (~USD 5 crédito) / luego USD 5/mes | Configuración inmediata con `npm run relay:start` y TLS `wss://`. | El saldo gratuito vence al agotarse o tras el período de prueba. |

---

## Variables de entorno requeridas

### A. En el servicio donde alojes el Relay (`server-vel/relay-server.ts`)

| Variable | Obligatoria | Descripción |
|---|---|---|
| `FIREBASE_PROJECT_ID` | Sí | ID del proyecto Firebase (ej. `proyecto-vel`). |
| `FIREBASE_SERVICE_ACCOUNT` | Sí | JSON completo (o en Base64) de la cuenta de servicio de Firebase Admin SDK. Permite verificar ID Tokens y consultar/actualizar `dispositivos`, `vinculaciones` y `autorizaciones` en Firestore. |
| `RELAY_ALLOWED_ORIGINS` | Recomendada | Orígenes HTTPS permitidos separados por coma (por defecto en Render admite `https://legendary-pasca-bf280b.netlify.app` y `https://proyecto-vel.netlify.app`). |
| `PORT` / `RELAY_PORT` | Automática / Opcional | Render/Railway inyectan `PORT` automáticamente; si no existe, usa `RELAY_PORT` o `8080`. |

- **Comando de instalación (Build):** `npm install`
- **Comando de arranque (Start):** `npm run relay:start`
- **Health Check path:** `/health` (responde JSON HTTP `200` con `status: "UP"` y `firebaseAdminConfigured`).

### B. En Netlify (Sitio web y PWA VEL)

| Variable | Obligatoria | Descripción |
|---|---|---|
| `VEL_RELAY_WSS_URL` | Sí | URL pública segura con esquema `wss://` del Relay desplegado (producción actual: `wss://server-vel.onrender.com`, sin barra final). |
| `FIREBASE_SERVICE_ACCOUNT` | Sí | Requerida por las Netlify Functions (`/api/register-device`, `/api/device-session`, `/api/pairing-confirm`, `/api/revoke-device`). |
| `FIREBASE_PROJECT_ID` | Sí | `proyecto-vel`. |

> Nota: La PWA consulta `GET /api/relay-config` al iniciar y utiliza `wss://server-vel.onrender.com` como URL de producción incorporada en el paquete web si el endpoint dinámico no está configurado.

---

## Prueba real con dos teléfonos (Paso a paso)

1. Despliega `server-vel/relay-server.ts` en Render con TLS (`wss://...`) y confirma que `https://server-vel.onrender.com/health` devuelva `{"status":"UP","firebaseAdminConfigured":true,...}`.
2. En Netlify (`Site configuration > Environment variables`), configura `VEL_RELAY_WSS_URL=wss://server-vel.onrender.com` y `FIREBASE_SERVICE_ACCOUNT`, y redespliega el sitio.
3. Verifica en Firebase Console que **Authentication > Sign-in method > Anonymous** esté habilitado.
4. **Teléfono 1 (VEL CORE):** Abre la web descargada desde Blogger en Chrome, sigue el Paso 1 para **instalar VEL como app en tu pantalla** y luego ábrela desde su ícono. Elige **VEL CORE**.
5. En **Teléfono 1 (CORE)** verás un **código de 6 dígitos** (válido por 5 minutos).
6. **Teléfono 2 (VEL MÓVIL):** Instala y abre VEL desde su ícono en el segundo teléfono, elige **VEL MÓVIL**, ingresa el código de **6 dígitos** del CORE y pulsa **Conectar**.
7. Ambos teléfonos quedan conectados de inmediato en **Un solo paso**.
8. Envía una nota, foto, video o archivo desde **VEL MÓVIL**: el elemento queda guardado localmente en **VEL MÓVIL** y se copia automáticamente al almacenamiento local de **VEL CORE** sin guardarse en la nube. Si CORE no está conectado en ese momento, queda como *Pendiente* en MÓVIL y se envía solo al reconectarse CORE.
9. Si borras un elemento en **VEL MÓVIL** (*Borrar de este móvil*), solo se elimina de ese teléfono y se conserva la copia en **VEL CORE**. Desde el icono **⚙ Ajustes** en VEL CORE puedes cambiar o desconectar el VEL MÓVIL vinculado cuando quieras.
