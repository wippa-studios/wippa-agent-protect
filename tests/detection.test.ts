import { detectFramework } from '../src/detection';
import { mkdtemp, writeFile, rm, mkdir } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

async function withTempDir(files: Record<string, string>, fn: (dir: string) => Promise<void>) {
  const dir = await mkdtemp(join(tmpdir(), 'wippa-detect-test-'));
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

describe('detectFramework', () => {
  it('detects CrewAI from requirements.txt', async () => {
    await withTempDir({
      'requirements.txt': 'crewai\nlangchain\n',
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('CrewAI');
    });
  });

  it('detects CrewAI from pyproject.toml', async () => {
    await withTempDir({
      'pyproject.toml': '[project]\ndependencies = ["crewai"]\n',
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('CrewAI');
    });
  });

  it('detects LangGraph from requirements.txt', async () => {
    await withTempDir({
      'requirements.txt': 'langgraph\nlangchain\n',
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('LangGraph');
    });
  });

  it('detects LangChain from requirements.txt', async () => {
    await withTempDir({
      'requirements.txt': 'langchain\nopenai\n',
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('LangChain');
    });
  });

  it('detects AutoGen from requirements.txt (pyautogen)', async () => {
    await withTempDir({
      'requirements.txt': 'pyautogen\n',
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('AutoGen');
    });
  });

  it('detects Vercel AI SDK from package.json', async () => {
    await withTempDir({
      'package.json': JSON.stringify({ dependencies: { ai: '^4.0.0' } }),
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('Vercel AI SDK');
    });
  });

  it('detects LangChain.js from package.json', async () => {
    await withTempDir({
      'package.json': JSON.stringify({ dependencies: { langchain: '^0.3.0' } }),
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('LangChain.js');
    });
  });

  it('returns unknown for unsupported repo', async () => {
    await withTempDir({
      'requirements.txt': 'flask\ndjango\n',
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('unknown');
    });
  });

  it('returns unknown when no dependency files exist', async () => {
    await withTempDir({
      'README.md': '# hello\n',
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('unknown');
    });
  });

  it('gives higher score to the more specific match when multiple match', async () => {
    await withTempDir({
      'requirements.txt': 'langgraph\nlangchain\ncrewai\n',
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(['LangGraph', 'CrewAI']).toContain(result.framework);
    });
  });

  it('detects Semantic Kernel from requirements.txt', async () => {
    await withTempDir({
      'requirements.txt': 'semantic-kernel\n',
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('Semantic Kernel');
    });
  });

  it('detects DSPy from requirements.txt', async () => {
    await withTempDir({
      'requirements.txt': 'dspy\n',
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('DSPy');
    });
  });

  it('detects Haystack from requirements.txt', async () => {
    await withTempDir({
      'requirements.txt': 'haystack-ai\n',
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('Haystack');
    });
  });

  it('detects Smolagents from requirements.txt', async () => {
    await withTempDir({
      'requirements.txt': 'smolagents\n',
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('Smolagents');
    });
  });

  it('detects Agno from requirements.txt', async () => {
    await withTempDir({
      'requirements.txt': 'agno\n',
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('Agno');
    });
  });

  it('detects Mastra from package.json', async () => {
    await withTempDir({
      'package.json': JSON.stringify({ dependencies: { mastra: '^0.1.0' } }),
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('Mastra');
    });
  });

  it('detects OpenAI Assistants from requirements.txt', async () => {
    await withTempDir({
      'requirements.txt': 'openai\n',
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('OpenAI Assistants');
    });
  });

  it('detects CopilotKit from package.json', async () => {
    await withTempDir({
      'package.json': JSON.stringify({ dependencies: { '@copilotkit/runtime': '^1.0.0' } }),
    }, async (dir) => {
      const result = await detectFramework(dir);
      expect(result.framework).toBe('CopilotKit');
    });
  });
});
