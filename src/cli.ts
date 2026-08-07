#!/usr/bin/env node
import { scanRepo } from './scan';
import { detectFramework } from './detection';
import { buildImage } from './build';
import { runContainer, containerLogs, waitForHealth, stopContainer } from './runner';
import { cloneRepo } from './clone';
import { loadProjectConfig, mergeConfig } from './config';
import { maskSecrets, formatProxyAudit } from './sanitize';
import {
  fetchPolicy,
  mergePolicyWithConfig,
  configureAuditLog,
  writeAuditEntry,
  isAuditEnabled,
  createAuditMeta,
  verifyImage,
  authenticate,
  startPolicyServer,
} from './enterprise';
import type { RunConfig } from './types';
import type { OrgPolicy } from './enterprise/types';

const DEFAULT_ALLOWED_DOMAINS = [
  'api.openai.com', 'api.anthropic.com', 'api.groq.com', 'api.deepseek.com',
  'api.mistral.ai', 'api.cohere.com', 'api.together.xyz', 'api.fireworks.ai',
  'github.com', 'api.github.com',
];

async function printBanner() {
  console.log('');
  console.log('  ╔══════════════════════════════════════╗');
  console.log('  ║          Wippa v0.1.0                ║');
  console.log('  ║  Sandboxed AI Agent Execution        ║');
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');
}

function getPlatform(): string {
  return process.platform;
}

function warnGVisor(platform: string): void {
  console.log(`  ⚠ gVisor isolation requested on ${platform}.`);
  console.log('     gVisor (runsc) requires a Linux host with runsc installed.');
  if (platform === 'darwin') {
    console.log('     On macOS, this only works inside a Linux VM (e.g. Docker Desktop VM).');
    console.log('     Falling back to standard Docker isolation.\n');
  } else if (platform === 'win32') {
    console.log('     On Windows, this only works inside a Linux VM (e.g. Docker Desktop VM).');
    console.log('     Falling back to standard Docker isolation.\n');
  }
}

async function cmdRun(repoUrl: string, options: RunConfig) {
  await printBanner();

  if (options.auditLog) {
    configureAuditLog(options.auditLog);
  }

  const auditMeta = createAuditMeta({
    org: options.org,
    repoUrl,
  });

  await writeAuditEntry('run_start', auditMeta);

  const platform = getPlatform();

  if (options.enterpriseUrl) {
    const authResult = await authenticate(options.enterpriseUrl, {
      enterpriseApiKey: options.enterpriseApiKey,
      org: options.org,
    });
    if (!authResult.authenticated) {
      await writeAuditEntry('auth_failure', {
        ...auditMeta,
        metadata: { error: authResult.error },
      });
      console.log(`  Enterprise auth failed: ${authResult.error}\n`);
      return;
    }
    await writeAuditEntry('auth_success', {
      ...auditMeta,
      metadata: { userId: authResult.userId, roles: authResult.roles },
    });

    const { policy } = await fetchPolicy(options.enterpriseUrl, {
      enterpriseApiKey: options.enterpriseApiKey,
      org: options.org,
    });

    if (policy) {
      const merged = mergePolicyWithConfig(
        { gVisor: options.gVisor, skipScan: options.skipScan, allowDomains: options.allowDomains, port: options.port },
        policy
      );
      options.gVisor = merged.gVisor;
      options.skipScan = merged.skipScan;
      options.allowDomains = merged.allowDomains;
      options.port = merged.port;

      if (merged.violations.length > 0) {
        for (const v of merged.violations) {
          console.log(`  ⚠ Policy: ${v}`);
        }
        await writeAuditEntry('policy_violation', {
          ...auditMeta,
          metadata: { violations: merged.violations },
        });
      }
    }
  }

  if (options.gVisor && platform !== 'linux') {
    warnGVisor(platform);
    options.gVisor = false;
  }

  const allowedDomains = options.allowDomains.length > 0
    ? options.allowDomains
    : (process.env.WIPPA_ALLOWED_DOMAINS
        ? process.env.WIPPA_ALLOWED_DOMAINS.split(',').map(d => d.trim()).filter(Boolean)
        : DEFAULT_ALLOWED_DOMAINS);

  if (options.allowDomains.length > 0) {
    console.log(`  Allowed domains: ${allowedDomains.join(', ')}\n`);
  }

  console.log(`  Cloning ${repoUrl}...`);
  const { dir, cleanup } = await cloneRepo(repoUrl);
  let containerId: string | undefined;

  try {
    // Load project config from cloned repo and merge with CLI flags
    const projectConfig = await loadProjectConfig(dir);
    if (projectConfig) {
      const configSource = projectConfig.port !== undefined ? 'wippa.toml/wippa.json' : 'project config';
      console.log(`  Found ${configSource} in repository.\n`);
      options = mergeConfig(options, projectConfig);
    }

    if (!options.skipScan) {
      console.log('  Scanning repository for security issues...');
      const scanResult = await scanRepo(dir);

      if (scanResult.findings.length > 0) {
        console.log(`\n  Security scan: ${scanResult.passed ? 'PASSED' : 'BLOCKED'}`);
        for (const f of scanResult.findings) {
          const icon = f.severity === 'high' ? '  ⚠' : '  ·';
          console.log(`  ${icon} [${f.severity}] ${f.file}: ${f.description}`);
        }
        console.log('');
      } else {
        console.log('  Security scan: PASSED (no issues found)\n');
      }

      await writeAuditEntry('scan_result', {
        ...auditMeta,
        scanPassed: scanResult.passed,
        scanFindings: scanResult.findings.length,
        metadata: { findings: scanResult.findings },
      });

      if (!scanResult.passed) {
        console.log('  ERROR: Repository blocked by security policy.');
        console.log('  Resolve high-severity findings before proceeding.');
        console.log('  Note: Static scans have limits — see docs for details.');
        return;
      }
    } else {
      console.log('  Skipping security scan (--skip-scan).\n');
    }

    console.log('  Detecting AI framework...');
    const detection = await detectFramework(dir);

    if (detection.framework !== 'unknown') {
      console.log(`  Framework: ${detection.framework} (confidence: ${detection.confidence})\n`);
    } else {
      console.log('  Framework: unknown — falling back to generic Python build.\n');
    }

    const imageTag = `wippa-${Date.now()}`;
    console.log(`  Building Docker image (${imageTag})...`);
    const buildResult = await buildImage(dir, detection.framework, imageTag);

    if (!buildResult.success) {
      console.log(`  ERROR: Build failed — ${buildResult.error}`);
      console.log('\n  Build logs:');
      console.log(buildResult.logs);
      return;
    }
    console.log(`  Image built: ${imageTag}\n`);

    if (options.registry) {
      await writeAuditEntry('registry_check', {
        ...auditMeta,
        imageTag,
        metadata: { registryUrl: options.registry },
      });
    }

    const env: Record<string, string> = {};
    if (options.apiKey) {
      env.OPENAI_API_KEY = options.apiKey;
    }
    env.WIPPA_ALLOWED_DOMAINS = allowedDomains.join(',');

    if (options.interactive) {
      console.log('  Starting container in interactive mode...\n');
      const runResult = await runContainer(imageTag, {
        env: Object.keys(env).length > 0 ? env : undefined,
        gVisor: options.gVisor,
        interactive: true,
      });

      if (!runResult.success) {
        console.log(`  ERROR: ${runResult.error}`);
        return;
      }
      console.log('\n  Container exited.');
      return;
    }

    console.log(`  Starting container on port ${options.port || 8080}...`);
    const runResult = await runContainer(imageTag, {
      hostPort: options.port || 8080,
      containerPort: 8080,
      env: Object.keys(env).length > 0 ? env : undefined,
      gVisor: options.gVisor,
    });

    if (!runResult.success) {
      console.log(`  ERROR: ${runResult.error}`);
      return;
    }

    containerId = runResult.containerId;
    console.log(`  Container started: ${containerId}`);
    console.log(`  URL: ${runResult.url}\n`);

    console.log('  Waiting for agent to become healthy...');
    const healthy = await waitForHealth(`${runResult.url}/_eap/health`, 15, 2000);

    if (healthy) {
      console.log('  Agent is ready!\n');
      console.log(`  ────────────────────────────────────`);
      console.log(`  Access your agent at:`);
      console.log(`  ${runResult.url}`);
      console.log(`  ────────────────────────────────────\n`);
    } else {
      console.log('  Warning: Agent health check did not pass.');
      console.log('  The container may still be starting up.\n');
    }

    console.log('  Streaming container logs (Ctrl+C to stop)...\n');

    const logInterval = setInterval(async () => {
      if (containerId) {
        const logs = await containerLogs(containerId);
        if (logs.trim()) {
          const lines = logs.split('\n');
          for (const line of lines) {
            const sanitized = maskSecrets(line);
            const proxyLine = formatProxyAudit(sanitized);
            if (proxyLine) {
              process.stdout.write(proxyLine + '\n');
            } else {
              process.stdout.write(sanitized + '\n');
            }
          }
        }
      }
    }, 3000);

    process.on('SIGINT', async () => {
      clearInterval(logInterval);
      console.log('\n  Shutting down...');
      if (containerId) {
        await stopContainer(containerId);
        await writeAuditEntry('run_stop', {
          ...auditMeta,
          containerId,
          imageTag,
        });
      }
      await cleanup();
      process.exit(0);
    });

    // Keep alive until SIGINT
    await new Promise(() => {});
  } catch (err: any) {
    console.error(`  ERROR: ${err?.message || 'Unknown error'}`);

    if (containerId) {
      await stopContainer(containerId).catch(() => {});
    }

    await cleanup();
    process.exit(1);
  }
}

async function cmdHelp() {
  await printBanner();
  console.log('  Usage:');
  console.log('    wippa run <repo-url>          Clone, scan, build, and run an AI agent');
  console.log('    wippa server [--port <n>]     Start the enterprise policy server');
  console.log('');
  console.log('  Run Options:');
  console.log('    --port, -p <number>           Host port to expose (default: 8080)');
  console.log('    --api-key, -k <key>           API key to inject (e.g. OPENAI_API_KEY)');
  console.log('    --allow-domain <domain>       Add domain to egress allowlist (repeatable)');
  console.log('    --interactive, -i             Run in interactive TTY mode (stdin/stdout)');
  console.log('    --skip-scan                   Skip malicious-code security scan');
  console.log('    --gvisor                      Use gVisor runtime for extra isolation (Linux only)');
  console.log('');
  console.log('  Enterprise Options:');
  console.log('    --enterprise-url <url>        Enterprise policy server URL');
  console.log('    --enterprise-api-key <key>    Enterprise API key for authentication');
  console.log('    --org <id>                    Organization ID');
  console.log('    --registry <url>              Private agent image registry URL');
  console.log('    --audit-log <path>            Path for structured audit log (JSONL)');
  console.log('');
  console.log('  Server Options:');
  console.log('    --port, -p <number>           Server listen port (default: 9099)');
  console.log('');
  console.log('  Project Config (wippa.toml / wippa.json):');
  console.log('    Commit a config file to your repo for zero-flag runs:');
  console.log('    { "port": 3000, "allowDomains": ["api.slack.com"], "interactive": true }');
  console.log('    Enterprise fields: enterpriseUrl, enterpriseApiKey, org, registry, auditLog');
  console.log('');
  console.log('  Environment:');
  console.log('    WIPPA_ALLOWED_DOMAINS         Comma-separated list of allowed egress domains');
  console.log('');
  console.log('  Examples:');
  console.log('    wippa run https://github.com/user/crewai-agent');
  console.log('    wippa run https://github.com/user/langgraph-agent --port 3000');
  console.log('    wippa run https://github.com/user/autogen-agent -k $OPENAI_API_KEY --gvisor');
  console.log('    wippa run https://github.com/user/tool-agent --allow-domain api.slack.com');
  console.log('    wippa run https://github.com/user/cli-agent -i');
  console.log('    wippa run https://github.com/user/enterprise-agent --enterprise-url https://wippa.acme.com');
  console.log('');
}

function parseEnterpriseArgs(args: string[]): {
  enterpriseUrl?: string;
  enterpriseApiKey?: string;
  org?: string;
  registry?: string;
  auditLog?: string;
} {
  const getVal = (flag: string): string | undefined => {
    const idx = args.findIndex(a => a === flag);
    return idx !== -1 && args[idx + 1] ? args[idx + 1] : undefined;
  };
  return {
    enterpriseUrl: getVal('--enterprise-url'),
    enterpriseApiKey: getVal('--enterprise-api-key'),
    org: getVal('--org'),
    registry: getVal('--registry'),
    auditLog: getVal('--audit-log'),
  };
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    await cmdHelp();
    return;
  }

  const command = args[0];

  if (command === 'run') {
    const repoUrl = args[1];
    if (!repoUrl) {
      console.error('Error: <repo-url> is required');
      console.error('Usage: wippa run <repo-url> [options]');
      process.exit(1);
    }

    const portIndex = args.findIndex(a => a === '--port' || a === '-p');
    const port = portIndex !== -1 ? parseInt(args[portIndex + 1], 10) : 8080;

    const keyIndex = args.findIndex(a => a === '--api-key' || a === '-k');
    const apiKey = keyIndex !== -1 ? args[keyIndex + 1] : undefined;

    const gVisor = args.includes('--gvisor');
    const skipScan = args.includes('--skip-scan');
    const interactive = args.includes('--interactive') || args.includes('-i');

    const allowDomains: string[] = [];
    args.forEach((a, i) => {
      if (a === '--allow-domain' && args[i + 1]) {
        allowDomains.push(args[i + 1]);
      }
    });

    const enterpriseConfig = parseEnterpriseArgs(args);

    await cmdRun(repoUrl, {
      port, apiKey, gVisor, allowDomains, skipScan, interactive,
      ...enterpriseConfig,
    });
  } else if (command === 'server') {
    const portIndex = args.findIndex(a => a === '--port' || a === '-p');
    const port = portIndex !== -1 ? parseInt(args[portIndex + 1], 10) : 9099;

    console.log(`  Starting Wippa Enterprise policy server on port ${port}...\n`);
    try {
      const server = await startPolicyServer({ port });
      console.log(`  Policy server running at http://localhost:${server.port}`);
      console.log('  Endpoints:');
      console.log('    GET /api/v1/health');
      console.log('    GET /api/v1/policy');
      console.log('    GET /api/v1/registry/catalog');
      console.log('    POST /api/v1/registry/verify');
      console.log('    POST /api/v1/auth/verify');
      console.log('');
      console.log('  Press Ctrl+C to stop.\n');
      await new Promise(() => {});
    } catch (err: any) {
      console.error(`  Failed to start server: ${err?.message || 'Unknown'}`);
      process.exit(1);
    }
  } else {
    console.error(`Unknown command: ${command}`);
    console.error('Usage: wippa run <repo-url> [options]');
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err?.message || err);
  process.exit(1);
});
