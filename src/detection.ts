import { readFile, access } from 'fs/promises';
import { join } from 'path';
import type { DetectionResult } from './types';

interface FrameworkSignature {
  name: string;
  patterns: { file: string; packages: string[] }[];
}

const FRAMEWORKS: FrameworkSignature[] = [
  {
    name: 'CrewAI',
    patterns: [
      { file: 'requirements.txt', packages: ['crewai'] },
      { file: 'pyproject.toml', packages: ['crewai'] },
      { file: 'poetry.lock', packages: ['crewai'] },
      { file: 'uv.lock', packages: ['crewai'] },
    ],
  },
  {
    name: 'LangGraph',
    patterns: [
      { file: 'requirements.txt', packages: ['langgraph'] },
      { file: 'pyproject.toml', packages: ['langgraph'] },
      { file: 'poetry.lock', packages: ['langgraph'] },
      { file: 'uv.lock', packages: ['langgraph'] },
    ],
  },
  {
    name: 'LangChain',
    patterns: [
      { file: 'requirements.txt', packages: ['langchain'] },
      { file: 'pyproject.toml', packages: ['langchain'] },
      { file: 'poetry.lock', packages: ['langchain'] },
      { file: 'uv.lock', packages: ['langchain'] },
    ],
  },
  {
    name: 'AutoGen',
    patterns: [
      { file: 'requirements.txt', packages: ['pyautogen', 'autogen-agentchat', 'autogen'] },
      { file: 'pyproject.toml', packages: ['pyautogen', 'autogen-agentchat', 'autogen'] },
      { file: 'poetry.lock', packages: ['pyautogen', 'autogen-agentchat', 'autogen'] },
      { file: 'uv.lock', packages: ['pyautogen', 'autogen-agentchat', 'autogen'] },
    ],
  },
  {
    name: 'Pydantic AI',
    patterns: [
      { file: 'requirements.txt', packages: ['pydantic-ai'] },
      { file: 'pyproject.toml', packages: ['pydantic-ai'] },
      { file: 'poetry.lock', packages: ['pydantic-ai'] },
      { file: 'uv.lock', packages: ['pydantic-ai'] },
    ],
  },
  {
    name: 'Vercel AI SDK',
    patterns: [
      { file: 'package.json', packages: ['ai', '@ai-sdk/openai', '@ai-sdk/anthropic', '@ai-sdk/core'] },
    ],
  },
  {
    name: 'LangChain.js',
    patterns: [
      { file: 'package.json', packages: ['langchain'] },
    ],
  },
  {
    name: 'OpenAI Agents SDK',
    patterns: [
      { file: 'requirements.txt', packages: ['openai-agents', 'agents-sdk'] },
      { file: 'pyproject.toml', packages: ['openai-agents', 'agents-sdk'] },
      { file: 'poetry.lock', packages: ['openai-agents', 'agents-sdk'] },
      { file: 'uv.lock', packages: ['openai-agents', 'agents-sdk'] },
    ],
  },
  {
    name: 'Semantic Kernel',
    patterns: [
      { file: 'requirements.txt', packages: ['semantic-kernel'] },
      { file: 'pyproject.toml', packages: ['semantic-kernel'] },
      { file: 'poetry.lock', packages: ['semantic-kernel'] },
      { file: 'uv.lock', packages: ['semantic-kernel'] },
    ],
  },
  {
    name: 'DSPy',
    patterns: [
      { file: 'requirements.txt', packages: ['dspy', 'dspy-ai'] },
      { file: 'pyproject.toml', packages: ['dspy', 'dspy-ai'] },
      { file: 'poetry.lock', packages: ['dspy', 'dspy-ai'] },
      { file: 'uv.lock', packages: ['dspy', 'dspy-ai'] },
    ],
  },
  {
    name: 'Haystack',
    patterns: [
      { file: 'requirements.txt', packages: ['haystack-ai', 'farm-haystack'] },
      { file: 'pyproject.toml', packages: ['haystack-ai', 'farm-haystack'] },
      { file: 'poetry.lock', packages: ['haystack-ai', 'farm-haystack'] },
      { file: 'uv.lock', packages: ['haystack-ai', 'farm-haystack'] },
    ],
  },
  {
    name: 'Smolagents',
    patterns: [
      { file: 'requirements.txt', packages: ['smolagents'] },
      { file: 'pyproject.toml', packages: ['smolagents'] },
      { file: 'poetry.lock', packages: ['smolagents'] },
      { file: 'uv.lock', packages: ['smolagents'] },
    ],
  },
  {
    name: 'Agno',
    patterns: [
      { file: 'requirements.txt', packages: ['agno', 'phidata'] },
      { file: 'pyproject.toml', packages: ['agno', 'phidata'] },
      { file: 'poetry.lock', packages: ['agno', 'phidata'] },
      { file: 'uv.lock', packages: ['agno', 'phidata'] },
    ],
  },
  {
    name: 'Mastra',
    patterns: [
      { file: 'package.json', packages: ['mastra'] },
    ],
  },
  {
    name: 'Genkit',
    patterns: [
      { file: 'package.json', packages: ['genkit', '@genkit-ai/ai'] },
    ],
  },
  {
    name: 'AI.JSX',
    patterns: [
      { file: 'package.json', packages: ['ai-jsx', 'ai-jsx-react'] },
    ],
  },
  {
    name: 'CopilotKit',
    patterns: [
      { file: 'package.json', packages: ['@copilotkit/runtime', '@copilotkit/core'] },
    ],
  },
  {
    name: 'OpenAI Assistants',
    patterns: [
      { file: 'requirements.txt', packages: ['openai'] },
      { file: 'pyproject.toml', packages: ['openai'] },
      { file: 'poetry.lock', packages: ['openai'] },
      { file: 'uv.lock', packages: ['openai'] },
      { file: 'package.json', packages: ['openai'] },
    ],
  },
];

async function fileExists(dir: string, file: string): Promise<boolean> {
  try {
    await access(join(dir, file));
    return true;
  } catch {
    return false;
  }
}

async function readFileSafe(dir: string, file: string): Promise<string | null> {
  try {
    return await readFile(join(dir, file), 'utf-8');
  } catch {
    return null;
  }
}

function getDependencyPackages(content: string): Set<string> {
  try {
    const json = JSON.parse(content);
    const deps = { ...json.dependencies, ...json.devDependencies, ...json.peerDependencies };
    return new Set(Object.keys(deps).filter(Boolean));
  } catch {
    return new Set();
  }
}

function getRequirementPackages(content: string): Set<string> {
  const packages = new Set<string>();
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
    const parts = trimmed.split(/[=~<>!@;]/);
    const pkg = parts[0].trim().toLowerCase();
    if (pkg) packages.add(pkg);
  }
  return packages;
}

function getPyprojectPackages(content: string): Set<string> {
  const packages = new Set<string>();
  try {
    const parsed = JSON.parse(content);
    const deps = parsed.project?.dependencies || parsed.poetry?.dependencies || parsed.tool?.poetry?.dependencies || {};
    if (Array.isArray(deps)) {
      for (const dep of deps) {
        const pkg = dep.split(/[=~<>!@[;]/)[0].trim().toLowerCase();
        if (pkg) packages.add(pkg);
      }
    } else {
      for (const key of Object.keys(deps)) {
        packages.add(key.toLowerCase());
      }
    }
  } catch {
    const depsMatch = content.match(/dependencies\s*=\s*\[([^\]]*)\]/);
    if (depsMatch) {
      const items = depsMatch[1].split(',');
      for (const item of items) {
        const clean = item.trim().replace(/['"]/g, '');
        const pkg = clean.split(/[=~<>!@[;]/)[0].trim().toLowerCase();
        if (pkg) packages.add(pkg);
      }
    }
  }
  return packages;
}

function getPackages(dir: string, file: string, content: string): Set<string> {
  if (file === 'package.json') return getDependencyPackages(content);
  if (file === 'requirements.txt') return getRequirementPackages(content);
  if (file === 'pyproject.toml') return getPyprojectPackages(content);
  // Lock files: search for package name mentions as text
  if (file === 'poetry.lock' || file === 'uv.lock' || file === 'pixi.toml') {
    const packages = new Set<string>();
    const lower = content.toLowerCase();
    // Check for known framework package names in lockfile content
    for (const fw of FRAMEWORKS) {
      for (const pat of fw.patterns) {
        if (pat.file === file) {
          for (const pkg of pat.packages) {
            if (lower.includes(pkg.toLowerCase())) {
              packages.add(pkg.toLowerCase());
            }
          }
        }
      }
    }
    return packages;
  }
  return new Set();
}

export async function detectFramework(cloneDir: string): Promise<DetectionResult> {
  const candidates: { name: string; score: number; confidence: 'high' | 'medium' | 'low' }[] = [];

  for (const framework of FRAMEWORKS) {
    let score = 0;
    for (const pattern of framework.patterns) {
      const exists = await fileExists(cloneDir, pattern.file);
      if (!exists) continue;

      const content = await readFileSafe(cloneDir, pattern.file);
      if (!content) continue;

      const installedPackages = getPackages(cloneDir, pattern.file, content);

      for (const pkg of pattern.packages) {
        if (installedPackages.has(pkg.toLowerCase())) {
          score += 1;
        }
      }
    }

    if (score > 0) {
      const confidence = score >= 2 ? 'high' : 'medium';
      candidates.push({ name: framework.name, score, confidence });
    }
  }

  candidates.sort((a, b) => b.score - a.score);

  if (candidates.length === 0) {
    return { framework: 'unknown', confidence: 'low' };
  }

  return {
    framework: candidates[0].name,
    confidence: candidates[0].confidence,
  };
}
