import type { AuthResult } from './types';

const JWT_HEADER = 'x-wippa-jwt';
const API_KEY_HEADER = 'x-wippa-api-key';

function decodeBase64(str: string): string {
  return Buffer.from(str, 'base64').toString('utf-8');
}

export function verifyApiKey(apiKey: string, expectedPrefix: string = 'wip_ent_'): boolean {
  if (!apiKey.startsWith(expectedPrefix)) return false;
  try {
    const payload = apiKey.slice(expectedPrefix.length);
    const decoded = decodeBase64(payload);
    const parts = decoded.split(':');
    return parts.length === 2 && parts[0].length > 0 && parts[1].length > 0;
  } catch {
    return false;
  }
}

export function verifyJwt(token: string): { valid: boolean; userId?: string } {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return { valid: false };
    const payload = JSON.parse(decodeBase64(parts[1]));
    if (payload.exp && Date.now() / 1000 > payload.exp) return { valid: false };
    return { valid: true, userId: payload.sub || payload.userId };
  } catch {
    return { valid: false };
  }
}

export function authHeaders(config: { enterpriseApiKey?: string; org?: string }): Record<string, string> {
  const headers: Record<string, string> = {};
  if (config.enterpriseApiKey) {
    headers[API_KEY_HEADER] = config.enterpriseApiKey;
  }
  if (config.org) {
    headers[JWT_HEADER] = config.org;
  }
  return headers;
}

export async function authenticate(
  enterpriseUrl: string,
  config: { enterpriseApiKey?: string; org?: string }
): Promise<AuthResult> {
  if (!config.enterpriseApiKey) {
    return { authenticated: false, error: 'No enterprise API key configured' };
  }
  if (!verifyApiKey(config.enterpriseApiKey)) {
    return { authenticated: false, error: 'Invalid enterprise API key format' };
  }
  try {
    const res = await fetch(`${enterpriseUrl}/api/v1/auth/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...authHeaders(config),
      },
    });
    if (!res.ok) {
      return { authenticated: false, error: `Auth failed: ${res.status}` };
    }
      const data = await res.json() as { userId?: string; roles?: string[] };
      return {
        authenticated: true,
        userId: data.userId,
        roles: data.roles || [],
      };
  } catch (err: any) {
    return { authenticated: false, error: err?.message || 'Auth request failed' };
  }
}

export function createApiKey(orgId: string, secret: string): string {
  const payload = Buffer.from(`${orgId}:${secret}`).toString('base64');
  return `wip_ent_${payload}`;
}
