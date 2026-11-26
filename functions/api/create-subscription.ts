import { jsonResponse } from '../../cloudflare/shared/http';
import type { CloudflarePagesContext } from '../../cloudflare/shared/types';

export async function handleCreateSubscription(context: CloudflarePagesContext): Promise<Response> {
  const { request } = context;

  if (request.method !== 'POST') {
    return jsonResponse(405, {
      error: 'Método no permitido. Utilizar POST.'
    });
  }

  return jsonResponse(410, {
    success: false,
    deprecated: true,
    officialCircuit: 'checkout_pro',
    officialEndpoint: '/api/create-preference',
    error:
      'El circuito anterior de suscripciones recurrentes (Preapproval) está deshabilitado para nuevas operaciones. Utiliza Checkout Pro mediante create-preference.'
  });
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handleCreateSubscription(context);
};
