import { execa } from 'execa';
import { tmpdir } from 'os';
import { join } from 'path';
import { mkdtemp, rm } from 'fs/promises';

export async function cloneRepo(repoUrl: string, ref?: string): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), 'wippa-clone-'));
  const args = ['clone', '--depth', '1'];
  if (ref) args.push('--branch', ref);
  args.push(repoUrl, dir);
  await execa('git', args, { timeout: 120_000 });
  return {
    dir,
    cleanup: async () => {
      await rm(dir, { recursive: true, force: true });
    },
  };
}
