<div align="center">

# wippa-agent-protect

### Sandboxed AI Agent Execution

**Run untrusted agent code safely.** Clone, scan, build, and run any AI agent repo in an isolated Docker container with egress filtering and secret masking.

[![npm](https://img.shields.io/badge/npm-@wippa%2Fcore-blue.svg)](https://www.npmjs.com/package/@wippa/core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Stage](https://img.shields.io/badge/stage-early%20release-orange.svg)](#security-model)

[How it works](#how-it-works) · [Security model](#security-model) · [Quick start](#quick-start) · [Configuration](#configuration)

</div>

---

## Why this exists

AI agent repositories are becoming a supply chain risk. You `git clone` someone's CrewAI agent and run it — it has access to your filesystem, your API keys, your network. Agent-protect solves this by running every agent in a sandboxed Docker container with controlled permissions.

```
$ npx @wippa/core run https://github.com/user/crewai-agent

  Cloning repository...
  Scanning for security issues...     PASSED
  Detecting framework...              CrewAI (high confidence)
  Building Docker image...
  Starting container on port 8080...

  Agent ready at http://localhost:8080
```

## How it works

1. **Clone** — Fetches the repository from any Git URL
2. **Scan** — Static analysis for security issues (secret leaks, malicious patterns)
3. **Detect** — Identifies the AI framework (LangChain, CrewAI, AutoGen, custom)
4. **Build** — Creates a Docker image with the agent's dependencies
5. **Run** — Starts the container with egress filtering, resource limits, and secret masking

## Security model

| Layer | What it does |
|---|---|
| **Docker isolation** | Agent runs in its own container with no access to host filesystem |
| **Egress filtering** | Only allows outbound connections to approved endpoints |
| **Secret masking** | Environment variables are injected but never logged or exposed |
| **Resource limits** | CPU, memory, and disk quotas prevent runaway processes |
| **Static scanning** | Regex-based scan for obvious malicious patterns |
| **Read-only root** | Container filesystem is read-only except for explicit volumes |

> **Honest guarantee:** The scanning is regex-based and immature (v0.1.0). Docker isolation is the real security boundary. The scan catches low-hanging fruit; Docker catches everything else.

## Quick start

```bash
# Run any agent repo
npx @wippa/core run https://github.com/user/crewai-agent

# Or install globally
npm install -g @wippa/core
wippa run https://github.com/user/crewai-agent
```

### Prerequisites

- Docker installed and running
- Node.js 18+

## Configuration

```bash
# Custom port
wippa run https://github.com/user/agent --port 9090

# Dry run (scan only, don't execute)
wippa run https://github.com/user/agent --dry-run

# Skip security scan (not recommended)
wippa run https://github.com/user/agent --skip-scan

# Custom resource limits
wippa run https://github.com/user/agent --memory 2g --cpus 2
```

### Environment variables

```bash
BETFAIR_USERNAME=...    # Injected into container (masked in logs)
BETFAIR_PASSWORD=...
BETFAIR_APP_KEY=...
```

Secrets are injected via environment variables and automatically masked in container output.

## Framework detection

Agent-protect auto-detects the AI framework used in the repository:

| Framework | Detection signals |
|---|---|
| CrewAI | `crewai` in requirements, `Crew` class usage |
| LangChain | `langchain` in requirements, `AgentExecutor` usage |
| AutoGen | `autogen` in requirements, `ConversableAgent` usage |
| OpenAI | `openai` in requirements, `Assistant` usage |
| Custom | Fallback — runs with generic Python/Node detection |

## Testing

```bash
npm test
npm run typecheck
```

## Project layout

```
wippa-agent-protect/
├── src/
│   ├── clone.ts          Git repository cloning
│   ├── scan.ts           Static security scanning
│   ├── detect.ts         Framework detection
│   ├── build.ts          Docker image building
│   ├── run.ts            Container execution
│   └── types.ts          Shared types
├── tests/                Test suite
├── readme-styles.svg     Banner asset
└── package.json
```

## License

MIT
