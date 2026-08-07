import { createServer, IncomingMessage, ServerResponse } from 'http';
import type { OrgPolicy, RegistryCatalog } from './types';

export interface ServerOptions {
  port: number;
  policy?: OrgPolicy;
  catalog?: RegistryCatalog;
}

const DEFAULT_POLICY: OrgPolicy = {
  allowedDomains: ['api.openai.com', 'api.anthropic.com', 'api.groq.com'],
  blockedDomains: [],
  enforceGVisor: false,
  enforceScan: true,
  scanThreshold: 'high',
  auditAllRuns: true,
  policyVersion: '0.1.0',
};

const DEFAULT_CATALOG: RegistryCatalog = {
  entries: [],
};

function jsonResponse(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function parseBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk: string) => { body += chunk; });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : null);
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

export function startPolicyServer(options: ServerOptions): Promise<{ close: () => void; port: number }> {
  return new Promise((resolve, reject) => {
    const policy = options.policy || DEFAULT_POLICY;
    const catalog = options.catalog || DEFAULT_CATALOG;

    const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      res.setHeader('X-Wippa-Version', '0.1.0');

      if (req.method === 'OPTIONS') {
        res.writeHead(204, {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, x-wippa-jwt, x-wippa-api-key',
        });
        res.end();
        return;
      }

      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      const path = url.pathname;

      try {
        if (path === '/api/v1/health') {
          jsonResponse(res, 200, { status: 'ok', version: '0.1.0' });
          return;
        }

        if (path === '/api/v1/policy') {
          jsonResponse(res, 200, policy);
          return;
        }

        if (path === '/api/v1/registry/catalog') {
          jsonResponse(res, 200, catalog);
          return;
        }

        if (path === '/api/v1/registry/verify' && req.method === 'POST') {
          const body = await parseBody(req) as any;
          const { imageName, imageSha256 } = body || {};
          if (!imageName || !imageSha256) {
            jsonResponse(res, 400, { error: 'imageName and imageSha256 required' });
            return;
          }
          const entry = catalog.entries.find(
            e => e.name === imageName && e.imageSha256 === imageSha256
          );
          jsonResponse(res, 200, { approved: !!entry, entry: entry || null });
          return;
        }

        if (path === '/api/v1/auth/verify' && req.method === 'POST') {
          const apiKey = req.headers['x-wippa-api-key'] as string;
          if (!apiKey || !apiKey.startsWith('wip_ent_')) {
            jsonResponse(res, 401, { error: 'Invalid API key' });
            return;
          }
          const payload = Buffer.from(apiKey.slice(8), 'base64').toString('utf-8');
          const parts = payload.split(':');
          jsonResponse(res, 200, {
            userId: parts[0] || 'unknown',
            roles: ['admin', 'user'],
          });
          return;
        }

        jsonResponse(res, 404, { error: 'Not found' });
      } catch (err: any) {
        jsonResponse(res, 500, { error: err?.message || 'Internal server error' });
      }
    });

    server.listen(options.port, () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : options.port;
      resolve({
        close: () => server.close(),
        port,
      });
    });

    server.on('error', reject);
  });
}
