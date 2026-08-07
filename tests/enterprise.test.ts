import {
  defaultPolicy,
  mergePolicyWithConfig,
  verifyApiKey,
  createApiKey,
  verifyJwt,
  configureAuditLog,
  isAuditEnabled,
  startPolicyServer,
} from '../src/enterprise';

describe('enterprise / policy', () => {
  test('defaultPolicy returns baseline policy', () => {
    const policy = defaultPolicy();
    expect(policy.enforceGVisor).toBe(false);
    expect(policy.enforceScan).toBe(true);
    expect(policy.scanThreshold).toBe('high');
    expect(policy.auditAllRuns).toBe(false);
    expect(policy.policyVersion).toBe('0.1.0');
  });

  test('mergePolicyWithConfig enforces gVisor when policy requires it', () => {
    const result = mergePolicyWithConfig(
      { gVisor: false, skipScan: false, allowDomains: [], port: 8080 },
      { ...defaultPolicy(), enforceGVisor: true }
    );
    expect(result.gVisor).toBe(true);
    expect(result.violations).toContain('gVisor enforced by org policy');
  });

  test('mergePolicyWithConfig overrides skip-scan when policy requires scan', () => {
    const result = mergePolicyWithConfig(
      { gVisor: false, skipScan: true, allowDomains: [], port: 8080 },
      { ...defaultPolicy(), enforceScan: true }
    );
    expect(result.skipScan).toBe(false);
    expect(result.violations).toContain('--skip-scan overridden by org policy (scan is required)');
  });

  test('mergePolicyWithConfig caps port to policy max', () => {
    const result = mergePolicyWithConfig(
      { gVisor: false, skipScan: false, allowDomains: [], port: 9999 },
      { ...defaultPolicy(), maxPort: 3000 }
    );
    expect(result.port).toBe(3000);
    expect(result.violations).toContain('Port capped to 3000 by org policy');
  });

  test('mergePolicyWithConfig removes blocked domains', () => {
    const result = mergePolicyWithConfig(
      { gVisor: false, skipScan: false, allowDomains: ['evil.com'], port: 8080 },
      { ...defaultPolicy(), blockedDomains: ['evil.com'] }
    );
    expect(result.allowDomains).not.toContain('evil.com');
  });

  test('mergePolicyWithConfig uses policy allowlist when none provided', () => {
    const result = mergePolicyWithConfig(
      { gVisor: false, skipScan: false, allowDomains: [], port: 8080 },
      { ...defaultPolicy(), allowedDomains: ['api.openai.com'] }
    );
    expect(result.allowDomains).toContain('api.openai.com');
  });

  test('mergePolicyWithConfig returns empty violations when policy is null', () => {
    const result = mergePolicyWithConfig(
      { gVisor: false, skipScan: false, allowDomains: [], port: 8080 },
      null
    );
    expect(result.violations).toEqual([]);
    expect(result.gVisor).toBe(false);
  });
});

describe('enterprise / auth', () => {
  test('verifyApiKey validates key format', () => {
    const key = createApiKey('org-foo', 'secret123');
    expect(key.startsWith('wip_ent_')).toBe(true);
    expect(verifyApiKey(key)).toBe(true);
  });

  test('verifyApiKey rejects bad prefix', () => {
    expect(verifyApiKey('bad-key')).toBe(false);
  });

  test('verifyApiKey rejects empty payload', () => {
    expect(verifyApiKey('wip_ent_')).toBe(false);
  });

  test('verifyJwt parses valid token', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'user-1', exp: Date.now() / 1000 + 3600 })).toString('base64url');
    const token = `${header}.${payload}.signature`;
    const result = verifyJwt(token);
    expect(result.valid).toBe(true);
    expect(result.userId).toBe('user-1');
  });

  test('verifyJwt rejects expired token', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'user-1', exp: Date.now() / 1000 - 3600 })).toString('base64url');
    const token = `${header}.${payload}.signature`;
    const result = verifyJwt(token);
    expect(result.valid).toBe(false);
  });

  test('verifyJwt rejects malformed token', () => {
    expect(verifyJwt('bad.token').valid).toBe(false);
  });

  test('createApiKey produces consistent format', () => {
    const key = createApiKey('org-acme', 'sec');
    expect(key).toMatch(/^wip_ent_[A-Za-z0-9+/=]+$/);
  });
});

describe('enterprise / audit', () => {
  test('configureAuditLog enables audit', () => {
    configureAuditLog('/tmp/wippa-test-audit.jsonl');
    expect(isAuditEnabled()).toBe(true);
    configureAuditLog('');
  });

  test('isAuditEnabled returns false when not configured', () => {
    configureAuditLog('');
    expect(isAuditEnabled()).toBe(false);
  });
});

describe('enterprise / server', () => {
  test('startPolicyServer starts and responds to health', async () => {
    const server = await startPolicyServer({ port: 0 });
    try {
      const res = await fetch(`http://localhost:${server.port}/api/v1/health`);
      expect(res.status).toBe(200);
      const body: any = await res.json();
      expect(body.status).toBe('ok');
    } finally {
      server.close();
    }
  });

  test('startPolicyServer returns policy on /api/v1/policy', async () => {
    const server = await startPolicyServer({ port: 0, policy: { ...defaultPolicy(), allowedDomains: ['example.com'] } });
    try {
      const res = await fetch(`http://localhost:${server.port}/api/v1/policy`);
      expect(res.status).toBe(200);
      const body: any = await res.json();
      expect(body.allowedDomains).toContain('example.com');
      expect(body.policyVersion).toBe('0.1.0');
    } finally {
      server.close();
    }
  });

  test('startPolicyServer returns catalog on /api/v1/registry/catalog', async () => {
    const server = await startPolicyServer({ port: 0 });
    try {
      const res = await fetch(`http://localhost:${server.port}/api/v1/registry/catalog`);
      expect(res.status).toBe(200);
      const body: any = await res.json();
      expect(body.entries).toEqual([]);
    } finally {
      server.close();
    }
  });

  test('startPolicyServer verifies registry image via POST', async () => {
    const server = await startPolicyServer({
      port: 0,
      catalog: {
        entries: [{ name: 'safe-agent', imageSha256: 'abc123', framework: 'CrewAI', version: '1.0', approved: true }],
      },
    });
    try {
      const res = await fetch(`http://localhost:${server.port}/api/v1/registry/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ imageName: 'safe-agent', imageSha256: 'abc123' }),
      });
      expect(res.status).toBe(200);
      const body: any = await res.json();
      expect(body.approved).toBe(true);
    } finally {
      server.close();
    }
  });

  test('startPolicyServer rejects unknown registry image', async () => {
    const server = await startPolicyServer({ port: 0 });
    try {
      const res = await fetch(`http://localhost:${server.port}/api/v1/registry/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ imageName: 'unknown', imageSha256: 'xxx' }),
      });
      const body: any = await res.json();
      expect(body.approved).toBe(false);
    } finally {
      server.close();
    }
  });

  test('startPolicyServer returns 404 for unknown routes', async () => {
    const server = await startPolicyServer({ port: 0 });
    try {
      const res = await fetch(`http://localhost:${server.port}/api/v1/unknown`);
      expect(res.status).toBe(404);
    } finally {
      server.close();
    }
  });
});
