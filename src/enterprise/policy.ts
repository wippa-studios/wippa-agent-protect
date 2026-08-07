import type { OrgPolicy, PolicyFetchResult } from './types';
import { authHeaders } from './auth';
import { writeAuditEntry } from './audit';

const LOCAL_POLICY_FILE = 'wippa.policy.json';

export function defaultPolicy(): OrgPolicy {
  return {
    enforceGVisor: false,
    enforceScan: true,
    scanThreshold: 'high',
    auditAllRuns: false,
    policyVersion: '0.1.0',
  };
}

export async function fetchPolicy(
  enterpriseUrl: string,
  config: { enterpriseApiKey?: string; org?: string }
): Promise<PolicyFetchResult> {
  if (!enterpriseUrl) {
    return { policy: null, error: 'No enterprise URL configured' };
  }

  const url = `${enterpriseUrl}/api/v1/policy`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...authHeaders(config),
  };

  try {
    const res = await fetch(url, { headers });
    if (!res.ok) {
      const error = `Policy fetch failed: ${res.status} ${res.statusText}`;
      await writeAuditEntry('policy_fetch', {
        metadata: { error, url },
      });
      return { policy: null, error };
    }
    const policy: OrgPolicy = await res.json() as OrgPolicy;
    await writeAuditEntry('policy_fetch', {
      metadata: { policyVersion: policy.policyVersion, url },
    });
    return { policy };
  } catch (err: any) {
    const error = `Policy fetch error: ${err?.message || 'Unknown'}`;
    await writeAuditEntry('policy_fetch', {
      metadata: { error, url },
    });
    return { policy: null, error };
  }
}

export function mergePolicyWithConfig(
  cliConfig: {
    gVisor: boolean;
    skipScan: boolean;
    allowDomains: string[];
    port: number;
  },
  policy: OrgPolicy | null
): {
  gVisor: boolean;
  skipScan: boolean;
  allowDomains: string[];
  port: number;
  violations: string[];
} {
  const violations: string[] = [];

  if (!policy) {
    return { ...cliConfig, violations };
  }

  let { gVisor, skipScan, allowDomains, port } = cliConfig;

  if (policy.enforceGVisor && !cliConfig.gVisor) {
    gVisor = true;
    violations.push('gVisor enforced by org policy');
  }

  if (policy.enforceScan && cliConfig.skipScan) {
    skipScan = false;
    violations.push('--skip-scan overridden by org policy (scan is required)');
  }

  if (policy.allowedDomains && policy.allowedDomains.length > 0) {
    const blocked = cliConfig.allowDomains.filter(
      d => !policy.allowedDomains!.includes(d)
    );
    if (blocked.length > 0) {
      violations.push(`Domains not in org allowlist: ${blocked.join(', ')}`);
    }
    if (allowDomains.length === 0) {
      allowDomains = [...policy.allowedDomains];
    }
  }

  if (policy.blockedDomains) {
    const overridden = allowDomains.filter(d => policy.blockedDomains!.includes(d));
    if (overridden.length > 0) {
      violations.push(`Blocked domains removed: ${overridden.join(', ')}`);
      allowDomains = allowDomains.filter(d => !policy.blockedDomains!.includes(d));
    }
  }

  if (policy.maxPort && cliConfig.port > policy.maxPort) {
    port = policy.maxPort;
    violations.push(`Port capped to ${policy.maxPort} by org policy`);
  }

  return { gVisor, skipScan, allowDomains, port, violations };
}
