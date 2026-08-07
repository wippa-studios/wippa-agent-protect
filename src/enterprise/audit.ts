import { appendFile, mkdir } from 'fs/promises';
import { join, dirname } from 'path';
import type { AuditEntry, AuditEvent } from './types';

const MAX_LOG_SIZE = 100 * 1024 * 1024;
let auditLogPath: string | null = null;
let logStreamActive = false;

export function configureAuditLog(filePath: string): void {
  auditLogPath = filePath || null;
  logStreamActive = !!filePath;
}

export function isAuditEnabled(): boolean {
  return logStreamActive;
}

export async function writeAuditEntry(
  event: AuditEvent,
  meta: Partial<AuditEntry>
): Promise<void> {
  if (!logStreamActive || !auditLogPath) return;

  const entry: AuditEntry = {
    event,
    timestamp: new Date().toISOString(),
    ...meta,
  };

  const line = JSON.stringify(entry) + '\n';

  try {
    const logPath = auditLogPath;
    if (!logPath) return;
    await mkdir(dirname(logPath), { recursive: true });
    const stat = await import('fs/promises').then(fs => fs.stat(logPath).catch(() => null));
    if (stat && stat.size > MAX_LOG_SIZE) {
      await rotateLog(auditLogPath);
    }
    await appendFile(auditLogPath, line, 'utf-8');
  } catch (err) {
    console.error(`[wippa:audit] Failed to write audit log: ${err}`);
  }
}

async function rotateLog(filePath: string): Promise<void> {
  const { rename } = await import('fs/promises');
  const rotated = filePath.replace(/\.jsonl$/, '') + `.${Date.now()}.jsonl`;
  try {
    await rename(filePath, rotated);
    console.error(`[wippa:audit] Rotated audit log to ${rotated}`);
  } catch {
    // If rename fails, just overwrite
  }
}

export function createAuditMeta(options: {
  org?: string;
  repoUrl?: string;
  imageTag?: string;
  containerId?: string;
  framework?: string;
}): Partial<AuditEntry> {
  return {
    org: options.org,
    repoUrl: options.repoUrl,
    imageTag: options.imageTag,
    containerId: options.containerId,
    framework: options.framework,
  };
}
