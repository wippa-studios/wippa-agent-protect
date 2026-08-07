export interface ScanFinding {
  file: string;
  severity: string;
  description: string;
  match: string;
}

export interface ScanResult {
  passed: boolean;
  findings: ScanFinding[];
}

export interface DetectionResult {
  framework: string;
  confidence: 'high' | 'medium' | 'low';
}

export interface EntrypointResult {
  entrypoint: string | null;
  hasDockerfile: boolean;
  originalCommand: string | null;
}

export interface BuildResult {
  success: boolean;
  logs: string;
  imageTag?: string;
  error?: string;
}

export interface RunResult {
  success: boolean;
  url?: string;
  containerId?: string;
  logs: string;
  error?: string;
}

export interface RunnerOptions {
  imageTag: string;
  containerName?: string;
  hostPort?: number;
  containerPort?: number;
  env?: Record<string, string>;
  gVisor?: boolean;
  memory?: string;
  cpus?: number;
  interactive?: boolean;
}

export interface RunConfig {
  port: number;
  apiKey?: string;
  gVisor: boolean;
  allowDomains: string[];
  skipScan: boolean;
  interactive: boolean;
  enterpriseUrl?: string;
  enterpriseApiKey?: string;
  org?: string;
  registry?: string;
  auditLog?: string;
}

export interface ProjectConfig {
  port?: number;
  api_key?: string;
  apiKey?: string;
  allow_domains?: string[];
  allowDomains?: string[];
  gvisor?: boolean;
  gVisor?: boolean;
  skip_scan?: boolean;
  skipScan?: boolean;
  interactive?: boolean;
  enterprise_url?: string;
  enterpriseUrl?: string;
  enterprise_api_key?: string;
  enterpriseApiKey?: string;
  org?: string;
  registry?: string;
  audit_log?: string;
  auditLog?: string;
}
