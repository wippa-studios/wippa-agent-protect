export { scanRepo } from './scan';
export type { ScanResult, ScanFinding } from './types';

export { detectFramework } from './detection';
export type { DetectionResult } from './types';

export {
  buildImage,
  detectEntrypoint,
  generateDockerfile,
  isPythonFramework,
  isJsFramework,
} from './build';
export type { BuildResult } from './types';

export {
  runContainer,
  stopContainer,
  containerLogs,
  waitForHealth,
} from './runner';
export type { RunResult, RunnerOptions } from './types';

export { encrypt, decrypt } from './encryption';
export { cloneRepo } from './clone';
export { dockerBuild } from './docker';
export { loadProjectConfig, mergeConfig } from './config';
export type { ProjectConfig } from './types';
export { analyzePythonAST, analyzeJS, shannonEntropy, findHighEntropyStrings } from './analyzer';

// Enterprise
export {
  startPolicyServer,
  fetchPolicy,
  mergePolicyWithConfig,
  defaultPolicy,
  configureAuditLog,
  writeAuditEntry,
  isAuditEnabled,
  createAuditMeta,
  verifyApiKey,
  verifyJwt,
  authenticate,
  createApiKey,
  authHeaders,
  fetchCatalog,
  lookupImage,
  verifyImage,
  fetchApprovedImages,
} from './enterprise';
export type {
  ServerOptions,
  EnterpriseConfig,
  OrgPolicy,
  AuditEntry,
  AuditEvent,
  RegistryEntry,
  RegistryCatalog,
  PolicyFetchResult,
  AuthResult,
} from './enterprise';
export type { RunConfig } from './types';
