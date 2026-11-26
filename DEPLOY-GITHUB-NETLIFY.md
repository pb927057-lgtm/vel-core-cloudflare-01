# VEL 0.1 — Guía de Publicación vía GitHub → Netlify (`legendary-pasca-bf280b.netlify.app`)

Esta guía está pensada para subir el proyecto completo desde **cualquier navegador** (incluida una PC antigua con Windows 7, sin instalar Node.js ni usar terminal) a un **repositorio privado de GitHub** y conectarlo con tu sitio actual de Netlify.

---

## 1. Subir el código fuente a un repositorio privado de GitHub

1. Reúne los archivos del proyecto limpio en una carpeta local (sin `node_modules`, `dist`, `.netlify` ni archivos `.env` con secretos).
2. Entra a `https://github.com` con tu cuenta e inicia **New repository**:
   - **Repository name:** por ejemplo `proyectovel`
   - **Visibility:** **Private** (recomendado)
   - Pulsa **Create repository**.
3. En la pantalla del repositorio recién creado, haz clic en **uploading an existing file** (o usa `git push`).
4. Selecciona **todo el contenido limpio del proyecto** (`src`, `public`, `netlify`, `blogger`, `server-vel`, `test`, `index.html`, `package.json`, `netlify.toml`, `tsconfig.json`, `vite.config.ts`, `.gitignore`, `.env.example`, etc.) y súbelo al repositorio.
   - *(Verifica que `src/`, `public/`, `netlify/functions/`, `index.html`, `package.json`, `vite.config.ts`, `tsconfig.json` y `netlify.toml` queden incluidos).*
5. Pulsa **Commit changes**.

---

## 2. Conectar el repositorio a tu sitio actual de Netlify

1. Entra a **Netlify** → selecciona tu sitio actual **`legendary-pasca-bf280b`** (`https://legendary-pasca-bf280b.netlify.app`).
2. Ve a **Site configuration → Build & deploy → Continuous deployment → Link repository**.
3. Elige **GitHub**, autoriza acceso a tu repositorio y selecciónalo.
4. Netlify detectará automáticamente `netlify.toml`:
   - **Build command:** `npm run build`
   - **Publish directory:** `dist`
   - **Functions directory:** `netlify/functions`
   - **Node version:** `22`
5. Antes o inmediatamente después del primer build, configura las variables de entorno (sección 3).

---

## 3. Variables de entorno requeridas en Netlify

En **Site configuration → Environment variables**:

| Variable | Obligatoria | Valor / Descripción |
|---|---|---|
| `FIREBASE_PROJECT_ID` | Sí | `proyecto-vel` |
| `FIREBASE_SERVICE_ACCOUNT` | Sí | JSON completo (o en Base64) de la cuenta de servicio Firebase Admin SDK |
| `VEL_RELAY_WSS_URL` | Sí | `wss://server-vel.onrender.com` |
| `APP_BASE_URL` | Recomendada | `https://legendary-pasca-bf280b.netlify.app` |
| `AWS_LAMBDA_JS_RUNTIME` | Recomendada | `nodejs22.x` *(para alinear el runtime de Functions con `firebase-admin@14.5.1`)* |
| `MP_ACCESS_TOKEN` | Sí (para cobros) | Token privado de Mercado Pago (`APP_USR-...` en producción) |
| `MP_WEBHOOK_SECRET` | Sí (para webhooks) | Secreto HMAC-SHA256 de notificaciones Mercado Pago |
| `VEL_PORTAL_RETURN_URL` | Opcional | `https://legendary-pasca-bf280b.netlify.app` |
| `BLOGGER_ORIGIN` | Opcional | Origen adicional CORS si aplica |
| `MP_WEBHOOK_MAX_AGE_SECONDS` | Opcional | Por defecto `172800` (48 h) |

> **Importante:** No agregues `NODE_ENV=production` como variable de build en Netlify, porque `tailwindcss` está en `devDependencies` y `npm install` necesita instalarla para `vite build`.

---

## 4. Variables en Render (`server-vel`) y Firebase

- **Render (`https://server-vel.onrender.com`):**
  - `FIREBASE_PROJECT_ID` = `proyecto-vel`
  - `FIREBASE_SERVICE_ACCOUNT` = JSON / Base64 de Firebase Admin SDK
  - `RELAY_ALLOWED_ORIGINS` = `https://legendary-pasca-bf280b.netlify.app,https://proyecto-vel.netlify.app`
- **Firebase Console:**
  - **Authentication → Sign-in method:** habilitar **Anonymous** y **Email link (sin contraseña)**.
  - **Authentication → Settings → Authorized domains:** agregar `legendary-pasca-bf280b.netlify.app` y `proyecto-vel.netlify.app`.

---

## 5. Verificación posterior al despliegue

1. `https://legendary-pasca-bf280b.netlify.app/api/relay-config` → debe devolver JSON `{"configured":true,"wssUrl":"wss://server-vel.onrender.com",...}` (no HTML).
2. `https://legendary-pasca-bf280b.netlify.app/api/get-pricing` → debe responder JSON con la tarifa vigente en Firestore (o HTTP `503` controlado si `configuracion_comercial/precios` no ha sido inicializada).
3. `https://server-vel.onrender.com/health` → debe responder `{"status":"UP","firebaseAdminConfigured":true,...}`.
