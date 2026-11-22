/**
 * Thin API client.
 *
 * Adapted from the API client of the author's earlier Kavach project, trimmed to the
 * shapes this product's screens actually import — no Policy/PolicyAnalysis/
 * ProtectCapability/BuildResult/device types, none of which this product has
 * routes or screens for.
 *
 * The bearer token is a local-development credential typed into the UI and kept
 * in localStorage. That is fine for a console that runs on your own machine
 * against your own backend; in a hosted deployment this is where an OIDC flow
 * goes, and nothing else in the console changes because everything below only
 * sees `request`.
 */
const TOKEN_KEY = 'kavach-sast-token';

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? '';
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(status: number, message: string, body: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

export async function request<T>(
  path: string,
  options: { method?: string; body?: unknown } = {},
): Promise<T> {
  const headers: Record<string, string> = { authorization: `Bearer ${getToken()}` };
  // Only declare a JSON body when there is one. Sending this header with an
  // empty body makes the JSON body parser reject the request outright.
  if (options.body !== undefined) headers['content-type'] = 'application/json';

  const response = await fetch(path, {
    method: options.method ?? 'GET',
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });

  const text = await response.text();
  const parsed = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const message =
      (parsed && typeof parsed === 'object' && 'error' in parsed
        ? String((parsed as { error: unknown }).error)
        : null) ?? `${response.status} ${response.statusText}`;
    throw new ApiError(response.status, message, parsed);
  }
  return parsed as T;
}

export type App = {
  appId: string;
  displayName: string;
  platform: 'android' | 'ios' | 'universal';
  bundleId: string;
  owner: string;
  createdAt: string;
};
