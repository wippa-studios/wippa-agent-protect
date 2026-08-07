import { mkdtemp, writeFile, rm, mkdir, readFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

jest.mock('../src/docker', () => ({
  dockerBuild: jest.fn().mockResolvedValue({ exitCode: 0, stdout: 'Build complete', stderr: '' }),
}));

import { buildImage, detectEntrypoint, generateDockerfile, isPythonFramework, isJsFramework } from '../src/build';
import type { BuildResult } from '../src/types';

async function withTempDir(files: Record<string, string>, fn: (dir: string) => Promise<void>) {
  const dir = await mkdtemp(join(tmpdir(), 'wippa-build-test-'));
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

describe('detectEntrypoint', () => {
  it('returns existing Dockerfile with extracted CMD', async () => {
    await withTempDir({
      'Dockerfile': 'FROM node:20\nCMD ["node", "index.js"]\n',
    }, async (dir) => {
      const result = await detectEntrypoint(dir, 'Vercel AI SDK');
      expect(result.hasDockerfile).toBe(true);
      expect(result.entrypoint).toBeNull();
      expect(result.originalCommand).toBeTruthy();
    });
  });

  it('detects Python entrypoint', async () => {
    await withTempDir({
      'main.py': 'print("hello")',
    }, async (dir) => {
      const result = await detectEntrypoint(dir, 'CrewAI');
      expect(result.hasDockerfile).toBe(false);
      expect(result.entrypoint).toBe('main.py');
      expect(result.originalCommand).toBeNull();
    });
  });

  it('detects JS entrypoint', async () => {
    await withTempDir({
      'index.js': 'console.log("hello")',
    }, async (dir) => {
      const result = await detectEntrypoint(dir, 'LangChain.js');
      expect(result.hasDockerfile).toBe(false);
      expect(result.entrypoint).toBe('index.js');
    });
  });

  it('returns null for unrecognized entrypoint', async () => {
    await withTempDir({
      'random.py': 'print("hello")',
    }, async (dir) => {
      const result = await detectEntrypoint(dir, 'CrewAI');
      expect(result.entrypoint).toBeNull();
    });
  });
});

describe('generateDockerfile', () => {
  it('generates Python Dockerfile with proxy', async () => {
    await withTempDir({}, async (dir) => {
      const gen = generateDockerfile(dir, 'CrewAI', 'main.py');
      expect(gen.dockerfile).toContain('python:3.11-slim');
      expect(gen.dockerfile).toContain('_eap_proxy.py');
      expect(gen.proxyFilename).toBe('_eap_proxy.py');
      expect(gen.proxyScript).toContain("ENTRYPOINT = 'main.py'");
      expect(gen.logs.length).toBeGreaterThan(0);
    });
  });

  it('generates Node Dockerfile with proxy', async () => {
    await withTempDir({}, async (dir) => {
      const gen = generateDockerfile(dir, 'Vercel AI SDK', 'index.js');
      expect(gen.dockerfile).toContain('node:20-slim');
      expect(gen.dockerfile).toContain('_eap_proxy.mjs');
      expect(gen.proxyFilename).toBe('_eap_proxy.mjs');
      expect(gen.proxyScript).toContain('index.js');
    });
  });

  it('generates Python proxy with ENTRYPOINT_CMD when originalCommand provided', async () => {
    await withTempDir({}, async (dir) => {
      const gen = generateDockerfile(dir, 'CrewAI', 'main.py', 'gunicorn app:app -b 0.0.0.0:8080');
      expect(gen.proxyScript).toContain("ENTRYPOINT_CMD = 'gunicorn app:app -b 0.0.0.0:8080'");
      expect(gen.proxyScript).toContain("ENTRYPOINT = 'main.py'");
    });
  });

  it('generates Node proxy with ENTRYPOINT_CMD when originalCommand provided', async () => {
    await withTempDir({}, async (dir) => {
      const gen = generateDockerfile(dir, 'Vercel AI SDK', 'index.js', 'node server.js');
      expect(gen.proxyScript).toContain("ENTRYPOINT_CMD = 'node server.js'");
    });
  });
});

describe('buildImage — entrypoint detection & Dockerfile generation', () => {
  it('returns failure with clear message when no entrypoint or Dockerfile exists (Python)', async () => {
    await withTempDir({
      'requirements.txt': 'crewai\n',
      'README.md': '# test\n',
    }, async (dir) => {
      const result = await buildImage(dir, 'CrewAI', 'test-1');
      expect(result.success).toBe(false);
      expect(result.error).toContain('No Dockerfile found');
      expect(result.error).toContain('main.py');
    });
  });

  it('returns failure with clear message when no entrypoint or Dockerfile exists (JS)', async () => {
    await withTempDir({
      'package.json': JSON.stringify({ dependencies: { ai: '^4.0.0' } }),
    }, async (dir) => {
      const result = await buildImage(dir, 'Vercel AI SDK', 'test-2');
      expect(result.success).toBe(false);
      expect(result.error).toContain('No Dockerfile found');
      expect(result.error).toContain('index.js');
    });
  });

  it('generates Dockerfile when Python entrypoint exists', async () => {
    await withTempDir({
      'requirements.txt': 'crewai\n',
      'main.py': 'print("hello")',
    }, async (dir) => {
      const result = await buildImage(dir, 'CrewAI', 'test-3');
      expect(result.logs).toContain('Generated Dockerfile');
      expect(result.logs).toContain('main.py');
    });
  });

  it('generates Dockerfile when JS entrypoint exists', async () => {
    await withTempDir({
      'package.json': JSON.stringify({ dependencies: { ai: '^4.0.0' } }),
      'index.js': 'console.log("hello")',
    }, async (dir) => {
      const result = await buildImage(dir, 'Vercel AI SDK', 'test-4');
      expect(result.logs).toContain('Generated Dockerfile');
      expect(result.logs).toContain('index.js');
    });
  });

  it('injects proxy into existing Dockerfile with CMD', async () => {
    await withTempDir({
      'Dockerfile': 'FROM node:20\nCOPY . /app\nCMD ["node", "index.js"]',
      'package.json': JSON.stringify({ dependencies: { ai: '^4.0.0' } }),
    }, async (dir) => {
      const result = await buildImage(dir, 'Vercel AI SDK', 'test-5');
      expect(result.logs).toContain('Injected Wippa proxy');
      expect(result.logs).toContain('node index.js');
      // Verify Dockerfile was modified
      const df = await readFile(join(dir, 'Dockerfile'), 'utf-8');
      expect(df).toContain('_eap_proxy.mjs');
      expect(df).toContain('COPY _eap_proxy.mjs');
      // Verify original CMD was stripped
      expect(df).not.toContain('CMD ["node", "index.js"]');
    });
  });

  it('injects proxy into existing Dockerfile with ENTRYPOINT', async () => {
    await withTempDir({
      'Dockerfile': 'FROM python:3.11-slim\nCOPY . /app\nENTRYPOINT ["python", "app.py"]',
      'app.py': 'print("hello")',
    }, async (dir) => {
      const result = await buildImage(dir, 'CrewAI', 'test-6');
      expect(result.logs).toContain('Injected Wippa proxy');
      const df = await readFile(join(dir, 'Dockerfile'), 'utf-8');
      expect(df).toContain('_eap_proxy.py');
      expect(df).toContain('COPY _eap_proxy.py');
      expect(df).not.toContain('ENTRYPOINT');
    });
  });

  it('injects proxy into existing Dockerfile with shell-form CMD', async () => {
    await withTempDir({
      'Dockerfile': 'FROM python:3.11-slim\nCMD gunicorn app:app -b 0.0.0.0:8080\n',
    }, async (dir) => {
      const result = await buildImage(dir, 'CrewAI', 'test-7');
      expect(result.logs).toContain('Injected Wippa proxy');
      expect(result.logs).toContain('gunicorn');
    });
  });

  it('generated Dockerfile references correct Python entrypoint (app.py)', async () => {
    await withTempDir({
      'app.py': 'print("hello")',
    }, async (dir) => {
      await buildImage(dir, 'LangChain', 'test-8');
      const df = await readFile(join(dir, 'Dockerfile'), 'utf-8');
      expect(df).toContain('_eap_proxy.py');
      expect(df).toContain('python:3.11-slim');
      const proxy = await readFile(join(dir, '_eap_proxy.py'), 'utf-8');
      expect(proxy).toContain('app.py');
    });
  });

  it('generated Dockerfile references correct JS entrypoint (server.js)', async () => {
    await withTempDir({
      'server.js': 'console.log("hi")',
    }, async (dir) => {
      await buildImage(dir, 'LangChain.js', 'test-9');
      const df = await readFile(join(dir, 'Dockerfile'), 'utf-8');
      expect(df).toContain('_eap_proxy.mjs');
      expect(df).toContain('node:20-slim');
      const proxy = await readFile(join(dir, '_eap_proxy.mjs'), 'utf-8');
      expect(proxy).toContain('server.js');
    });
  });
});
