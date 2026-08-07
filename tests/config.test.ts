import { loadProjectConfig, mergeConfig } from '../src/config';
import { mkdtemp, writeFile, rm, mkdir } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

async function withTempDir(files: Record<string, string>, fn: (dir: string) => Promise<void>) {
  const dir = await mkdtemp(join(tmpdir(), 'wippa-config-test-'));
  try {
    for (const [path, content] of Object.entries(files)) {
      const fullPath = join(dir, path);
      const parent = fullPath.substring(0, fullPath.lastIndexOf('/'));
      if (parent) await mkdir(parent, { recursive: true }).catch(() => {});
      await writeFile(fullPath, content);
    }
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe('loadProjectConfig', () => {
  it('loads wippa.json', async () => {
    await withTempDir({
      'wippa.json': JSON.stringify({ port: 3000, interactive: true }),
    }, async (dir) => {
      const config = await loadProjectConfig(dir);
      expect(config).not.toBeNull();
      expect(config!.port).toBe(3000);
      expect(config!.interactive).toBe(true);
    });
  });

  it('loads wippa.toml', async () => {
    await withTempDir({
      'wippa.toml': 'port = 4000\ninteractive = true\nskip_scan = true\n',
    }, async (dir) => {
      const config = await loadProjectConfig(dir);
      expect(config).not.toBeNull();
      expect(config!.port).toBe(4000);
      expect(config!.interactive).toBe(true);
      expect(config!.skipScan).toBe(true);
    });
  });

  it('loads allow_domains from toml', async () => {
    await withTempDir({
      'wippa.toml': 'allow_domains = ["api.slack.com", "api.stripe.com"]\n',
    }, async (dir) => {
      const config = await loadProjectConfig(dir);
      expect(config).not.toBeNull();
      expect(config!.allowDomains).toEqual(['api.slack.com', 'api.stripe.com']);
    });
  });

  it('returns null when no config file exists', async () => {
    await withTempDir({
      'README.md': '# hello\n',
    }, async (dir) => {
      const config = await loadProjectConfig(dir);
      expect(config).toBeNull();
    });
  });

  it('wippa.json takes priority over wippa.toml', async () => {
    await withTempDir({
      'wippa.json': JSON.stringify({ port: 5000 }),
      'wippa.toml': 'port = 6000\n',
    }, async (dir) => {
      const config = await loadProjectConfig(dir);
      expect(config).not.toBeNull();
      expect(config!.port).toBe(5000);
    });
  });
});

describe('mergeConfig', () => {
  const defaults = { port: 8080, apiKey: undefined, gVisor: false, allowDomains: [], skipScan: false, interactive: false };

  it('uses CLI defaults when no project config', () => {
    const result = mergeConfig(defaults, null);
    expect(result.port).toBe(8080);
    expect(result.interactive).toBe(false);
  });

  it('merges project config values when CLI uses defaults', () => {
    const result = mergeConfig(defaults, { port: 3000, interactive: true });
    expect(result.port).toBe(3000);
    expect(result.interactive).toBe(true);
  });

  it('CLI flags override project config', () => {
    const cliConfig = { ...defaults, port: 9000 };
    const result = mergeConfig(cliConfig, { port: 3000 });
    expect(result.port).toBe(9000);
  });

  it('merges allowDomains from project config', () => {
    const result = mergeConfig(defaults, { allowDomains: ['api.slack.com'] });
    expect(result.allowDomains).toEqual(['api.slack.com']);
  });

  it('CLI allowDomains overrides project config', () => {
    const cliConfig = { ...defaults, allowDomains: ['api.custom.com'] };
    const result = mergeConfig(cliConfig, { allowDomains: ['api.slack.com'] });
    expect(result.allowDomains).toEqual(['api.custom.com']);
  });
});
