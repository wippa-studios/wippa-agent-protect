<p align="center">
  <img src="./readme-styles.svg" alt="Wippa Banner" width="100%">
</p>

<p align="center"><b>⚠ Early stage:</b> v0.1.0 — core pipeline works, scanning heuristics are regex-based and immature. See <a href="#security-model">Security Model</a> for honest guarantees.</p>

```
$ wippa run https://github.com/user/crewai-agent

  ╔══════════════════════════════════════╗
  ║          Wippa v0.1.0                ║
  ║  Sandboxed AI Agent Execution        ║
  ╚══════════════════════════════════════╝

  Cloning https://github.com/user/crewai-agent...
  Scanning repository for security issues...
  Security scan: PASSED (no issues found)
  Detecting AI framework...
  Framework: CrewAI (confidence: high)
  Building Docker image (wippa-1712345678)...
  Image built: wippa-1712345678
  Starting container on port 8080...
  Container started: a1b2c3d4e5f6
  URL: http://localhost:8080

  Agent is ready!
  ────────────────────────────────────
  Access your agent at:
  http://localhost:8080
  ────────────────────────────────────

  Streaming container logs (Ctrl+C to stop)...
```

```bash
npx @wippa/core run https://github.com/user/crewai-agent
```

---

## Security Model

Wippa runs untrusted agent code on your machine. The guarantees below describe what it controls — and what it doesn't.

### What Wippa Controls

- **🔒 OS-level isolation with gVisor** — optional `--gvisor` flag wraps the container in a sandboxed kernel (runsc). Blocks container escape at the syscall layer. _Note: gVisor is Linux-only. On macOS/Windows, Wippa falls back to standard Docker isolation with a warning._
- **⛓️ Resource-capped containers** — 2 GB RAM limit, 1 CPU hard cap. No fork bombs, no memory exhaustion.
- **🚦 Egress filtering proxy** — built-in transparent proxy inside the container blocks all outbound traffic except an allowlist. Default list covers common AI API providers (OpenAI, Anthropic, Groq, DeepSeek, Mistral, Cohere, Together, Fireworks, GitHub). **Because agent code needs to call LLM APIs to function, the default allowlist permits those calls.** This means API requests **do leave your machine** — but only to the domains you (or the repo maintainer) choose. Use `--allow-domain` to add more, or set `WIPPA_ALLOWED_DOMAINS` env var to override entirely. Set to an empty value for full network isolation (no outbound calls allowed at all).
- **🛡️ Multi-layer security scan** — three scanning engines run before any code executes:
  - **Regex scan**: 19 pattern families for cryptominers, reverse shells, hardcoded credentials, Docker socket access, firewall manipulation, and more
  - **AST analysis**: Python files parsed via `ast` module — detects `os.system()`/`subprocess.Popen()` with dynamic arguments, `eval()`/`exec()` with untrusted input, `__import__()` obfuscation, and dangerous imports. JS/TS files scanned structurally for `child_process.exec()`, `eval()`, `new Function()`, `vm` sandbox escape surfaces
  - **Entropy detection**: Shannon entropy analysis of quoted strings — flags high-entropy tokens (≥4.5 bits/char) that may be secrets or API keys
  - **What it does NOT catch:** obfuscated/minified payloads, compiled binaries, or zero-day patterns. Not a full commercial SAST tool. High-severity findings block execution. Use `--skip-scan` to bypass.
- **⚡ Zero privileges** — `--cap-drop ALL`, no-new-privileges, isolated bridge network.
- **🔑 Secret masking** — container logs are sanitized in real time: API keys (`sk-...`, `sk-ant-...`), cloud credentials (`AKIA...`, `AIza...`), tokens (`ghp_...`, `xox[bpras]-...`) are replaced with `***` before display.
- **🔧 Existing Dockerfile wrapping** — if a repo ships its own Dockerfile, Wippa strips the original `CMD`/`ENTRYPOINT`, copies in the egress proxy, and wraps the original command as a subprocess under it. This ensures runtime egress filtering and the health-check endpoint work regardless. If no `CMD`/`ENTRYPOINT` is found, a framework-default entrypoint is used. _Note: this addresses **runtime** CMD/ENTRYPOINT only. Build-time `RUN` instructions execute before the proxy exists (see below)._

### What Wippa Does NOT Control

- **Docker socket access** — Wippa itself needs the Docker socket (`/var/run/docker.sock`) to build images and run containers on your host. This is standard for Docker-based tooling but means **Wippa has effective root access** to your Docker daemon. The containers it spawns do NOT have socket access (`--cap-drop ALL`, no bind-mount of `/var/run`), but Wippa the CLI does. If you're concerned, run Wippa inside a dedicated VM or CI runner.
- **Build-time `RUN` instructions in Dockerfiles** — `RUN` commands in a Dockerfile execute during `docker build`, on the host's Docker daemon, **before any runtime sandboxing applies**. A malicious Dockerfile could exfiltrate data or install packages during the build phase — the egress proxy, cap-drop, and gVisor isolation only apply at container runtime. The static scan checks for suspicious patterns (including `curl`/`wget` payload downloads, base64 decode, and remote `ADD`), but this is a regex smoke test, not a guarantee. **We recommend auditing any Dockerfile before building, or running Wippa in a disposable CI runner.**
- **Static scan evasion** — the scan runs on plaintext files up to 512 KB and skips common vendored directories. While Wippa now combines regex, AST analysis (Python's `ast` module / JS structural scanning), and entropy-based secret detection, compiled binaries, encrypted payloads, or runtime-generated attacks remain invisible. `--skip-scan` disables all scanning entirely — use with caution.

## How It Works

| Step | What happens |
|------|-------------|
| **0. Config** | `wippa.toml` / `wippa.json` loaded if present, merged with CLI flags |
| **1. Clone** | Shallow clone into a temp directory |
| **2. Scan** | Regex (19 families) + AST analysis (Python/JS) + entropy-based secret detection |
| **3. Detect** | Dependency files read, framework identified (18 supported) |
| **4. Build** | Dockerfile auto-generated with injected proxy. Existing Dockerfiles are also patched — original CMD/ENTRYPOINT extracted, proxy injected |
| **5. Run** | Container starts with resource limits, cap drops, egress proxy, and secret-masked logs |

## Installation

```bash
npm install -g @wippa/core
```

Or run directly:

```bash
npx @wippa/core run <repo-url>
```

**Prerequisites:** Node.js 20+, Docker, git.

## Usage

```bash
wippa run <repo-url> [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--port, -p` | `8080` | Host port to expose |
| `--api-key, -k` | — | API key to inject (e.g. `OPENAI_API_KEY`) |
| `--allow-domain` | — | Add domain to egress allowlist (repeatable) |
| `--interactive, -i` | off | Run in interactive TTY mode (stdin/stdout passthrough) |
| `--skip-scan` | off | Skip the static malicious-code security scan |
| `--gvisor` | off | Use gVisor runtime for kernel-level isolation (Linux only) |
| `--enterprise-url` | — | Enterprise policy server URL for org-wide config |
| `--enterprise-api-key` | — | API key for enterprise authentication |
| `--org` | — | Organization ID for enterprise policy |
| `--registry` | — | Private agent image registry URL for image verification |
| `--audit-log` | — | Path for structured audit log (JSONL format) |
| `--help, -h` | — | Show help |

### Project Config (wippa.toml / wippa.json)

Commit a config file to your repo so anyone can run it with zero flags:

```json
{
  "port": 3000,
  "allowDomains": ["api.slack.com", "api.stripe.com"],
  "interactive": true,
  "gVisor": false,
  "enterpriseUrl": "https://wippa.acme.com",
  "org": "acme-corp",
  "auditLog": "/var/log/wippa/audit.jsonl"
}
```

Or TOML:

```toml
port = 3000
allow_domains = ["api.slack.com", "api.stripe.com"]
interactive = true
gvisor = false
enterprise_url = "https://wippa.acme.com"
org = "acme-corp"
audit_log = "/var/log/wippa/audit.jsonl"
```

Wippa auto-detects the file in the cloned repo and merges it with CLI flags. **CLI flags always override** the config file.

### Secret Masking

Container logs are automatically sanitized — API keys, tokens, and credentials (`sk-...`, `ghp_...`, `AKIA...`, `OPENAI_API_KEY=...`, etc.) are replaced with `***` before display.

### Proxy Audit Stream

When the egress proxy blocks or allows a domain, live audit messages appear in your terminal:

```
[PROXY] Blocked outbound call to api.stripe.com. Use --allow-domain api.stripe.com to allow.
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `WIPPA_ALLOWED_DOMAINS` | Comma-separated list of domains allowed through the egress proxy (default: OpenAI, Anthropic, Groq, DeepSeek, Mistral, Cohere, Together, Fireworks, GitHub) |

### Examples

```bash
# Run a CrewAI agent
wippa run https://github.com/user/crewai-agent

# Run with a custom port
wippa run https://github.com/user/langgraph-agent --port 3000

# Run with an API key and gVisor isolation
wippa run https://github.com/user/autogen-agent -k $OPENAI_API_KEY --gvisor

# Run a tool-heavy agent with additional egress domains
wippa run https://github.com/user/tool-agent --allow-domain api.slack.com --allow-domain api.github.com

# Skip the static security scan (e.g., for local development)
wippa run https://github.com/user/my-agent --skip-scan

# Run an interactive terminal agent with stdin/stdout passthrough
wippa run https://github.com/user/cli-agent --interactive

# Run with a project config file from the repo (zero flags needed)
wippa run https://github.com/user/configured-agent
```

## Supported Frameworks

<details>
<summary><b>18 frameworks detected automatically — click to expand</b></summary>

| Framework | Language | Package detection |
|-----------|----------|-------------------|
| CrewAI | Python | requirements.txt, pyproject.toml, poetry.lock, uv.lock |
| LangGraph | Python | requirements.txt, pyproject.toml, poetry.lock, uv.lock |
| LangChain | Python | requirements.txt, pyproject.toml, poetry.lock, uv.lock |
| AutoGen | Python | requirements.txt, pyproject.toml, poetry.lock, uv.lock |
| Pydantic AI | Python | requirements.txt, pyproject.toml, poetry.lock, uv.lock |
| OpenAI Agents SDK | Python | requirements.txt, pyproject.toml, poetry.lock, uv.lock |
| Semantic Kernel | Python | requirements.txt, pyproject.toml, poetry.lock, uv.lock |
| DSPy | Python | requirements.txt, pyproject.toml, poetry.lock, uv.lock |
| Haystack | Python | requirements.txt, pyproject.toml, poetry.lock, uv.lock |
| Vercel AI SDK | TypeScript/JS | package.json |
| LangChain.js | TypeScript/JS | package.json |
| Smolagents | Python | requirements.txt, pyproject.toml, poetry.lock, uv.lock |
| Agno (Phidata) | Python | requirements.txt, pyproject.toml, poetry.lock, uv.lock |
| Mastra | TypeScript/JS | package.json |
| Genkit | TypeScript/JS | package.json |
| AI.JSX | TypeScript/JS | package.json |
| CopilotKit | TypeScript/JS | package.json |
| OpenAI Assistants | Python / TypeScript | requirements.txt, pyproject.toml, package.json |

</details>

Don't see yours? [Open an issue](https://github.com/wippa-studios/wippa/issues/1) — we're watching.

## Examples

Minimal working agents in `examples/`. Each is a single file + `requirements.txt` — no hidden config, no local paths.

```bash
wippa run examples/crewai
wippa run examples/langgraph
wippa run examples/autogen
```

## Programmatic API

```typescript
import {
  scanRepo,
  detectFramework,
  buildImage,
  runContainer,
  stopContainer,
  generateDockerfile,
  cloneRepo,
} from '@wippa/core';

// Security scan
const scan = await scanRepo('/tmp/cloned-repo');
console.log(scan.passed, scan.findings);

// Framework detection
const detection = await detectFramework('/tmp/cloned-repo');
console.log(detection.framework, detection.confidence);

// Dockerfile generation
const { dockerfile, proxyScript } = generateDockerfile(
  '/tmp/cloned-repo', 'CrewAI', 'main.py'
);

// Full build
const build = await buildImage('/tmp/cloned-repo', 'CrewAI', 'my-image');
if (build.success) {
  const run = await runContainer('my-image', { hostPort: 8080 });
  console.log(`Agent running at ${run.url}`);
}
```

## Open Core

The CLI is MIT — always free, always local. Wippa Cloud is the hosted version: runs the sandboxing infra so you don't have to manage Docker, gVisor, registries, or proxy updates yourself.

**Caveat:** we're v0.1.0. Wippa Cloud doesn't exist yet. The table below is honest about what's shipped vs. planned.

| Feature | Free CLI | Wippa Cloud (planned) |
|---------|----------|----------------------|
| **Local sandbox** | ✅ `wippa run` | — |
| **Egress filtering** | ✅ `--allow-domain` | — |
| **Static security scan** | ✅ regex + AST + entropy | — |
| **gVisor isolation** | ✅ opt-in (Linux only) | — |
| **Secret masking** | ✅ | — |
| **Interactive TTY mode** | ✅ | — |
| **Project config** | ✅ `wippa.toml` / `wippa.json` | — |
| **Audit logging** | ✅ `--audit-log` (JSONL) | ✅ managed dashboard |
| **Policy server** | ✅ `wippa server` | ✅ built-in |
| **Private registry** | ✅ `--registry` | ✅ hosted catalog |
| **Cloud sandbox execution** | — | ✅ no local Docker needed |
| **Team management** | — | ✅ multi-user |
| **SSO / SAML** | — | ✅ |
| **Compliance reporting** | — | ✅ SOC 2 |
| **Hosted scanning API** | — | ✅ deeper analysis |

The CLI stays free. The cloud handles the parts that are annoying to self-host: keeping gVisor images current, scaling sandboxes, managing team access. [Open an issue](https://github.com/wippa-studios/wippa/issues) if you'd use this.

### Getting Started

```bash
npx @wippa/core run https://github.com/user/crewai-agent
```

That's it. No signup, no cloud, no account. When Wippa Cloud ships, adding `--cloud` will be the only difference.

The CLI will always be free. [Open an issue](https://github.com/wippa-studios/wippa/issues) if something's missing.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). We're v0.1.0 — the CLI pipeline is functional, but the security scanning is regex-based and the heuristics are rudimentary. Issues, honest feedback, and PRs all welcome. The main gaps we know about: [build-time Dockerfile `RUN` scanning](https://github.com/wippa-studios/wippa/issues), [entropy threshold tuning for low-FP secret detection](https://github.com/wippa-studios/wippa/issues), and [gVisor on non-Linux hosts](https://github.com/wippa-studios/wippa/issues).

## License

MIT — see [LICENSE](LICENSE).
