import { execa } from 'execa';
import type { RunResult, RunnerOptions } from './types';

function buildRunArgs(options: RunnerOptions): string[] {
  const args = options.interactive ? ['run', '--rm'] : ['run', '-d', '--rm'];

  if (options.containerName) {
    args.push('--name', options.containerName);
  }

  if (options.hostPort && options.containerPort && !options.interactive) {
    args.push('-p', `${options.hostPort}:${options.containerPort}`);
  }

  if (options.memory) {
    args.push('--memory', options.memory);
  }

  if (options.cpus) {
    args.push('--cpus', String(options.cpus));
  }

  if (options.gVisor) {
    args.push('--runtime', 'runsc');
  }

  if (options.env) {
    for (const [key, value] of Object.entries(options.env)) {
      args.push('-e', `${key}=${value}`);
    }
  }

  if (options.interactive) {
    args.push('-i', '-t');
  }

  // Network isolation: no host network, no docker-in-docker
  args.push('--network', 'bridge');
  args.push('--security-opt', 'no-new-privileges:true');
  args.push('--cap-drop', 'ALL');

  args.push(options.imageTag);

  return args;
}

export async function runContainer(
  imageTag: string,
  options: Partial<RunnerOptions> = {}
): Promise<RunResult> {
  const opts: RunnerOptions = {
    imageTag,
    hostPort: options.hostPort ?? 8080,
    containerPort: options.containerPort ?? 8080,
    containerName: options.containerName,
    env: options.env,
    gVisor: options.gVisor ?? false,
    memory: options.memory ?? '2g',
    cpus: options.cpus ?? 1.0,
    interactive: options.interactive ?? false,
  };

  if (opts.interactive) {
    return runContainerInteractive(opts);
  }

  const args = buildRunArgs(opts);

  try {
    const result = await execa('docker', args, { timeout: 30_000, reject: false });

    if (result.exitCode !== 0) {
      return {
        success: false,
        logs: result.stderr || result.stdout || 'Unknown error',
        error: `Failed to start container: ${result.stderr?.trim() || 'unknown error'}`,
      };
    }

    const containerId = result.stdout?.trim();

    return {
      success: true,
      url: `http://localhost:${opts.hostPort}`,
      containerId,
      logs: `Container started: ${containerId}`,
    };
  } catch (err: any) {
    return {
      success: false,
      logs: err?.message || 'Unknown error',
      error: `Failed to start container: ${err?.message || 'unknown error'}`,
    };
  }
}

async function runContainerInteractive(opts: RunnerOptions): Promise<RunResult> {
  const args = buildRunArgs(opts);

  try {
    const subprocess = execa('docker', args, {
      stdio: 'inherit',
      reject: false,
      timeout: 0,
    });

    const exitCode = await subprocess;

    return {
      success: exitCode.exitCode === 0,
      logs: exitCode.exitCode === 0 ? 'Container exited successfully' : `Container exited with code ${exitCode.exitCode}`,
      error: exitCode.exitCode !== 0 ? `Container exited with code ${exitCode.exitCode}` : undefined,
    };
  } catch (err: any) {
    return {
      success: false,
      logs: err?.message || 'Unknown error',
      error: `Failed to run container: ${err?.message || 'unknown error'}`,
    };
  }
}

export async function stopContainer(containerId: string): Promise<{ success: boolean; logs: string }> {
  try {
    await execa('docker', ['stop', containerId], { timeout: 30_000 });
    return { success: true, logs: `Container stopped: ${containerId}` };
  } catch (err: any) {
    return { success: false, logs: `Failed to stop container: ${err?.message}` };
  }
}

export async function containerLogs(containerId: string): Promise<string> {
  try {
    const result = await execa('docker', ['logs', containerId], { timeout: 10_000 });
    return (result.stdout || '') + (result.stderr || '');
  } catch {
    return 'No logs available';
  }
}

export async function waitForHealth(url: string, maxRetries = 15, intervalMs = 2000): Promise<boolean> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(3000) });
      if (response.ok) return true;
    } catch {
      // not ready yet
    }
    await new Promise(r => setTimeout(r, intervalMs));
  }
  return false;
}
