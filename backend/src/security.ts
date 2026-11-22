/**
 * Response headers and request limits, for every route.
 *
 * Done in two hooks rather than per route so a new route cannot forget them.
 */
import type { FastifyInstance } from 'fastify';
import type { AppContext } from './context.ts';

/**
 * What the console is allowed to load. Everything comes from this origin: the
 * bundle, the bundled fonts and the API. `data:` and `blob:` cover the app icon
 * embedded in a report, a generated download and the report preview frame.
 * Inline styles are allowed because the UI sets some at runtime; inline script is not.
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "frame-src 'self' blob:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

const STATIC_HEADERS: Record<string, string> = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
};

export function registerSecurity(server: FastifyInstance, ctx: AppContext): void {
  // Refuse a client that is hammering the API before doing any work for it.
  // Health checks are exempt: a probe that gets rate-limited looks like an outage.
  server.addHook('onRequest', async (request, reply) => {
    if (request.url === '/healthz') return;
    const result = ctx.limits.requests.hit(request.ip);
    if (!result.allowed) {
      reply.header('retry-after', String(result.retryAfterSec));
      return reply.code(429).send({ error: 'too many requests; slow down and try again shortly' });
    }
  });

  server.addHook('onSend', async (request, reply, payload) => {
    for (const [name, value] of Object.entries(STATIC_HEADERS)) reply.header(name, value);

    const type = String(reply.getHeader('content-type') ?? '');
    if (type.startsWith('text/html')) reply.header('content-security-policy', CONTENT_SECURITY_POLICY);

    // API answers are about one signed-in user and must not be kept by a shared cache.
    if ((request.url.startsWith('/v1') || request.url === '/healthz') && !reply.hasHeader('cache-control')) {
      reply.header('cache-control', 'no-store');
    }

    // Only meaningful over HTTPS, and harmful to send over plain HTTP in development.
    if (ctx.config.hsts || request.protocol === 'https') {
      reply.header('strict-transport-security', 'max-age=31536000; includeSubDomains');
    }
    return payload;
  });
}
