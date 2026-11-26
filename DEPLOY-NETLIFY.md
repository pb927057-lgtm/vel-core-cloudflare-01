# VEL 0.1 — Despliegue Completo en Netlify (Frontend `dist/` + `netlify/functions/`)

Este procedimiento publica **VEL 0.1 completa** (PWA + las 14 funciones serverless `/api/*`) sobre **tu sitio actual de Netlify**, **sin crear un sitio nuevo**, **sin cambiar la URL pública** y **sin necesidad de usar GitHub**.

> **Por qué no usar Netlify Drop:** Netlify Drop únicamente sube archivos estáticos (`dist/`) y **no despliega** `netlify/functions/`. Al usar **Netlify CLI** (gratuito en el plan Starter de Netlify), subes en un solo paso `dist/`, `netlify/functions/` y las reglas de `netlify.toml`.

---

## 1. Requisitos en tu computadora (gratuitos)

1. **Node.js 20 LTS** (o superior) con `npm`.
2. Tener a mano:
   - Tu cuenta de **Netlify** (donde ya existe tu sitio actual, por ejemplo `proyecto-vel.netlify.app`).
   - Las variables de entorno secretas configuradas en el panel de Netlify (ver sección 3).

---

## 2. Paso a paso para publicar en tu sitio actual (sin GitHub)

Si descargaste y descomprimiste el paquete `vel-0.1-netlify-completo.zip` en una carpeta (por ejemplo `vel-deploy/`), abre una terminal **dentro de esa carpeta** y ejecuta en orden:

### Paso 1 — Instalar dependencias de servidor para empaquetar las funciones
```bash
npm install
```
*(Necesario para que `firebase-admin` y las dependencias de empaquetado existan localmente al construir el ZIP de cada Netlify Function.)*

### Paso 2 — Iniciar sesión en tu cuenta de Netlify (solo la primera vez)
```bash
npx netlify-cli login
```
Se abrirá tu navegador para autorizar el acceso a tu cuenta de Netlify. Una vez autorizado, vuelve a la terminal.

### Paso 3 — Vincular esta carpeta con tu sitio actual de Netlify (solo la primera vez)
```bash
npx netlify-cli link
```
Elige:
1. **`Use current git remote origin` no** → selecciona **`Choose from a list of your recently updated sites`** o **`Enter a site ID`** (o **`Search by full or partial site name`**).
2. Selecciona **tu sitio existente de Netlify** (el que ya tiene tu dominio público actual).
3. Esto crea la carpeta local oculta `.netlify/state.json` apuntando a tu sitio existente; **no crea un sitio nuevo ni altera tu dominio**.

### Paso 4 — Verificar las variables de entorno en Netlify (antes o inmediatamente después)
Puedes cargarlas en **Netlify UI → Site configuration → Environment variables** o desde la terminal con `npx netlify-cli env:set NOMBRE "valor"` (ver tabla en la sección 3).

### Paso 5 — Desplegar en producción la app completa (`dist/` + `netlify/functions/`)
```bash
npx netlify-cli deploy --prod --dir=dist --functions=netlify/functions
```
*(Si realizaste cambios en `src/` antes de desplegar, ejecuta primero `npm run build` para regenerar `dist/`.)*

Al finalizar, la terminal mostrará:
- **Website URL** (tu dominio actual de Netlify intacto).
- Confirmación de las **14 funciones** desplegadas bajo `/.netlify/functions/*` y enrutadas por `/api/*`.

---

## 3. Separación exacta de variables de entorno (Netlify vs. Render)

**Ninguna clave privada ni token secreto se incluye en `dist/` ni en el JavaScript público.**

### A. Variables en Netlify (`Site configuration > Environment variables`)

| Variable | Obligatoria | Uso en VEL |
|---|---|---|
| `FIREBASE_PROJECT_ID` | Sí | ID del proyecto Firebase (`proyecto-vel`). |
| `FIREBASE_SERVICE_ACCOUNT` | Sí | JSON completo (o en Base64) de la cuenta de servicio Firebase Admin SDK. Usada por `register-device`, `device-session`, `pairing-confirm`, `revoke-device`, `verify-device-token`, `create-preference`, `payment-webhook`, `admin-pricing`, `download-package`, etc. |
| `VEL_RELAY_WSS_URL` | Sí | `wss://server-vel.onrender.com` (sin barra final). Entregada por `GET /api/relay-config`. |
| `MP_ACCESS_TOKEN` | Sí (para cobros) | Access Token privado de Mercado Pago (`APP_USR-...` en producción). |
| `MP_WEBHOOK_SECRET` | Sí (para webhooks) | Secreto HMAC-SHA256 de notificaciones Mercado Pago (`x-signature`). |
| `APP_BASE_URL` | Recomendada | URL pública de tu sitio en Netlify (ej. `https://proyecto-vel.netlify.app`), sin barra final. Usada para `notification_url` de Mercado Pago y CORS. |
| `VEL_PORTAL_RETURN_URL` | Opcional | URL de retorno tras el checkout (por defecto igual a `APP_BASE_URL`). |
| `BLOGGER_ORIGIN` | Opcional | Origen adicional permitido por CORS además de `https://proyecto-vel.blogspot.com`. |
| `MP_WEBHOOK_MAX_AGE_SECONDS` | Opcional | Tolerancia máxima de firma webhook en segundos (por defecto `172800` = 48 h). |

### B. Variables públicas de compilación Vite (ya incluidas en `.env.production`, sin secretos)

| Variable | Valor | Dónde vive |
|---|---|---|
| `VITE_VEL_RELAY_WSS_URL` | `wss://server-vel.onrender.com` | `.env.production` (compilado en `dist/` como respaldo público de `GET /api/relay-config`). |

### C. Variables en Render (`server-vel/relay-server.ts`)

| Variable | Obligatoria | Uso en Render |
|---|---|---|
| `FIREBASE_PROJECT_ID` | Sí | `proyecto-vel`. |
| `FIREBASE_SERVICE_ACCOUNT` | Sí | JSON completo (o Base64) de Firebase Admin SDK para autenticar sockets y validar `dispositivos`, `vinculaciones` y `autorizaciones` en Firestore. |
| `RELAY_ALLOWED_ORIGINS` | Sí en producción | Lista separada por comas de orígenes HTTPS permitidos para WebSocket (ej. `https://proyecto-vel.netlify.app`). |
| `PORT` / `RELAY_PORT` | Automática en Render | Puerto HTTP/WS (`Render` inyecta `PORT` automáticamente). |

> **Importante:** Las credenciales de Mercado Pago (`MP_ACCESS_TOKEN`, `MP_WEBHOOK_SECRET`) van **únicamente en Netlify**, **no en Render**. El Relay de Render solo necesita Firebase Admin y `RELAY_ALLOWED_ORIGINS`.

---

## 4. Endpoints verificados incluidos en `netlify/functions/` (14 funciones)

- **Identidad y dispositivos**: `/api/register-device`, `/api/device-session`, `/api/verify-device-token`, `/api/pairing-confirm`, `/api/revoke-device`.
- **Configuración Relay**: `/api/relay-config`.
- **Comercial y Mercado Pago**: `/api/get-pricing`, `/api/admin-pricing`, `/api/create-preference`, `/api/payment-webhook`, `/api/download-package`, `/api/cancel-subscription`, más compatibilidad heredada `/api/create-subscription` y `/api/mercadopago-webhook`.

---

## 5. Verificación rápida posterior al despliegue

1. `https://<tu-sitio>.netlify.app/api/relay-config` → debe devolver JSON `{"configured":true,"wssUrl":"wss://server-vel.onrender.com",...}` (no HTML).
2. `https://<tu-sitio>.netlify.app/api/get-pricing` → debe devolver JSON con la tarifa vigente en Firestore (o HTTP `503` controlado si `configuracion_comercial/precios` aún no fue inicializada).
3. `https://server-vel.onrender.com/health` → debe devolver `{"status":"UP","firebaseAdminConfigured":true,...}`.
