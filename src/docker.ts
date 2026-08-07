import { execa } from 'execa';

const BUILD_TIMEOUT_MS = 300_000;

export async function dockerBuild(
  imageTag: string,
  contextDir: string
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const result = await execa(
    'docker',
    [
      'build',
      '--memory', '2g',
      '--memory-swap', '2g',
      '--cpus', '1.0',
      '-t', imageTag,
      contextDir,
    ],
    {
      timeout: BUILD_TIMEOUT_MS,
      reject: false,
    }
  );

  return {
    exitCode: result.exitCode || 0,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
  };
}
