import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig, Plugin } from 'vite';

function cloudflareFunctionsDevPlugin(): Plugin {
  return {
    name: 'cloudflare-pages-functions-dev-middleware',
    apply: 'serve', // Solo se ejecuta durante 'vite dev', no en 'vite build'
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (!req.url?.startsWith('/api/')) {
          return next();
        }

        const protocol = req.headers['x-forwarded-proto']
          ? String(req.headers['x-forwarded-proto']).split(',')[0].trim()
          : 'http';
        const host = req.headers.host || 'localhost:3000';
        const url = new URL(req.url, `${protocol}://${host}`);
        const endpoint = url.pathname.replace('/api/', '').split('/')[0];

        const allowedEndpoints: Record<string, string> = {
          'get-pricing': './functions/api/get-pricing.ts',
          'create-preference': './functions/api/create-preference.ts',
          'payment-webhook': './functions/api/payment-webhook.ts',
          'create-subscription': './functions/api/create-subscription.ts',
          'mercadopago-webhook': './functions/api/mercadopago-webhook.ts',
          'cancel-subscription': './functions/api/cancel-subscription.ts',
          'admin-pricing': './functions/api/admin-pricing.ts',
          'download-package': './functions/api/download-package.ts',
          'register-device': './functions/api/register-device.ts',
          'device-session': './functions/api/device-session.ts',
          'verify-device-token': './functions/api/verify-device-token.ts',
          'pairing-confirm': './functions/api/pairing-confirm.ts',
          'revoke-device': './functions/api/revoke-device.ts',
          'relay-config': './functions/api/relay-config.ts',
          'account': './functions/api/account.ts'
        };

        const targetFile = allowedEndpoints[endpoint];
        if (!targetFile) {
          res.statusCode = 404;
          res.setHeader('Content-Type', 'application/json');
          return res.end(JSON.stringify({ error: `Función /api/${endpoint} no encontrada.` }));
        }

        try {
          const headers = new Headers();
          for (const [key, value] of Object.entries(req.headers)) {
            if (typeof value === 'string') {
              headers.set(key, value);
            } else if (Array.isArray(value)) {
              headers.set(key, value.join(', '));
            }
          }

          let bodyStr: string | undefined;
          if (req.method && req.method !== 'GET' && req.method !== 'HEAD') {
            const chunks: Buffer[] = [];
            for await (const chunk of req) {
              chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
            }
            if (chunks.length > 0) {
              bodyStr = Buffer.concat(chunks).toString('utf8');
            }
          }

          const webRequest = new Request(url.toString(), {
            method: req.method || 'GET',
            headers,
            body: bodyStr
          });

          const mod = await server.ssrLoadModule(targetFile);
          const webResponse: Response = await mod.onRequest({
            request: webRequest,
            env: process.env,
            params: {}
          });

          res.statusCode = webResponse.status || 200;
          webResponse.headers.forEach((value, key) => {
            res.setHeader(key, value);
          });
          const resBody = await webResponse.text();
          return res.end(resBody);
        } catch (err: any) {
          res.statusCode = 500;
          res.setHeader('Content-Type', 'application/json');
          return res.end(
            JSON.stringify({
              error: `Error ejecutando /api/${endpoint} en desarrollo: ${err?.message || err}`
            })
          );
        }
      });
    }
  };
}

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss(), cloudflareFunctionsDevPlugin()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.')
      }
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: process.env.DISABLE_HMR === 'true' ? null : {}
    }
  };
});
