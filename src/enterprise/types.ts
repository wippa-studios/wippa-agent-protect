export interface EnterpriseConfig {
  enterpriseUrl?: string;
  enterpriseApiKey?: string;
  org?: string;
  registry?: string;
  auditLog?: string;
}

export interface OrgPolicy {
  allowedDomains?: string[];
  blockedDomains?: string[];
  enforceGVisor: boolean;
  enforceScan: boolean;
  scanThreshold: 'low' | 'medium' | 'high';
  maxPort?: number;
  allowedFrameworks?: string[];
  auditAllRuns: boolean;
  policyVersion: string;
}

export interface AuditEntry {
  event: string;
  timestamp: string;
  org?: string;
  userId?: string;
  repoUrl?: string;
  imageTag?: string;
  containerId?: string;
  framework?: string;
  scanPassed?: boolean;
  scanFindings?: number;
  policyViolation?: string;
  durationMs?: number;
  metadata?: Record<string, unknown>;
}

export type AuditEvent =
  | 'run_start'
  | 'run_stop'
  | 'scan_result'
  | 'policy_fetch'
  | 'policy_violation'
  | 'registry_check'
  | 'registry_block'
  | 'auth_failure'
  | 'auth_success';

export interface RegistryEntry {
  name: string;
  imageSha256: string;
  framework: string;
  version: string;
  approved: boolean;
  signedBy?: string;
}

export interface RegistryCatalog {
  entries: RegistryEntry[];
}

export interface PolicyFetchResult {
  policy: OrgPolicy | null;
  error?: string;
}

export interface AuthResult {
  authenticated: boolean;
  userId?: string;
  roles?: string[];
  error?: string;
}
