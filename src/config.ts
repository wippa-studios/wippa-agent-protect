import { readFile, access } from 'fs/promises';
import { join } from 'path';
import type { ProjectConfig, RunConfig } from './types';

function parseToml(text: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('[')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    let value: unknown = trimmed.slice(eqIdx + 1).trim();
    if (value === 'true') value = true;
    else if (value === 'false') value = false;
    else if (/^\d+$/.test(value as string)) value = parseInt(value as string, 10);
    else if (value === '[' || (value as string).startsWith('[')) {
      const arrMatch = text.match(new RegExp(`${key}\\s*=\\s*\\[([^\\]]*)\\]`));
      if (arrMatch) {
        value = arrMatch[1].split(',').map((s: string) => s.trim().replace(/['"]/g, '')).filter(Boolean);
      }
    } else if ((value as string).startsWith('"') || (value as string).startsWith("'")) {
      value = (value as string).replace(/^['"]|['"]$/g, '');
    }
    result[key] = value;
  }
  return result;
}

function camelize(str: string): string {
  return str.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
}

function normalizeConfig(raw: Record<string, unknown>): ProjectConfig {
  const result: ProjectConfig = {};
  for (const [key, value] of Object.entries(raw)) {
    const camelKey = camelize(key);
    (result as any)[camelKey] = value;
  }
  return result;
}

export async function loadProjectConfig(cloneDir: string): Promise<ProjectConfig | null> {
  for (const filename of ['wippa.json', 'wippa.toml']) {
    const filePath = join(cloneDir, filename);
    try {
      await access(filePath);
      const content = await readFile(filePath, 'utf-8');
      if (filename.endsWith('.json')) {
        return normalizeConfig(JSON.parse(content));
      }
      return normalizeConfig(parseToml(content));
    } catch {
      continue;
    }
  }
  return null;
}

export function mergeConfig(
  cliConfig: RunConfig,
  projectConfig: ProjectConfig | null
): RunConfig {
  if (!projectConfig) return cliConfig;

  return {
    port: cliConfig.port !== 8080 ? cliConfig.port : (projectConfig.port ?? 8080),
    apiKey: cliConfig.apiKey ?? projectConfig.apiKey ?? projectConfig.api_key,
    gVisor: cliConfig.gVisor || (projectConfig.gVisor ?? projectConfig.gvisor ?? false),
    allowDomains: cliConfig.allowDomains.length > 0 ? cliConfig.allowDomains : (projectConfig.allowDomains ?? projectConfig.allow_domains ?? []),
    skipScan: cliConfig.skipScan || (projectConfig.skipScan ?? projectConfig.skip_scan ?? false),
    interactive: cliConfig.interactive || (projectConfig.interactive ?? false),
    enterpriseUrl: cliConfig.enterpriseUrl ?? projectConfig.enterpriseUrl ?? projectConfig.enterprise_url,
    enterpriseApiKey: cliConfig.enterpriseApiKey ?? projectConfig.enterpriseApiKey ?? projectConfig.enterprise_api_key,
    org: cliConfig.org ?? projectConfig.org,
    registry: cliConfig.registry ?? projectConfig.registry,
    auditLog: cliConfig.auditLog ?? projectConfig.auditLog ?? projectConfig.audit_log,
  };
}
