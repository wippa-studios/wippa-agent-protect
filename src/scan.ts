import { readdir, readFile } from 'fs/promises';
import { join, relative, extname } from 'path';
import type { ScanResult } from './types';
import { analyzePythonAST, analyzeJS, findHighEntropyStrings, shannonEntropy } from './analyzer';

const SUSPICIOUS_PATTERNS: { pattern: RegExp; severity: 'high' | 'medium'; description: string }[] = [
  { pattern: /(stratum\+tcp|minerd|xmrig|cgminer|bfgminer|ethminer)/i, severity: 'high', description: 'Cryptominer reference detected' },
  { pattern: /(reverse.?shell|bind.?shell|mkfifo|nc\s+-e|bash\s+-i\s+[&>].*\/dev\/tcp)/i, severity: 'high', description: 'Reverse shell or backdoor pattern' },
  { pattern: /(chmod\s+777|chmod\s+-R\s+777|chmod\s+0{4}7{3})/i, severity: 'medium', description: 'Overly permissive file permissions' },
  { pattern: /(wget|curl)\s+.*(\||-O\s|>)/i, severity: 'medium', description: 'Remote payload download' },
  { pattern: /(base64\s+-d|base64\s+--decode)\s*[A-Za-z0-9+/]{50,}/i, severity: 'medium', description: 'Large base64 decode (possible encoded payload)' },
  { pattern: /(eval\s*\(\s*(exec|system|passthru|shell_exec|`|file_get_contents))/i, severity: 'medium', description: 'Dangerous eval with execution function' },
  { pattern: /(DOCKER_HOST|\$DOCKER|\/var\/run\/docker\.sock)/i, severity: 'high', description: 'Docker socket or host access attempt' },
  { pattern: /(AWS_ACCESS_KEY|AWS_SECRET_ACCESS_KEY|AZURE_|GOOGLE_APPLICATION)/i, severity: 'high', description: 'Hardcoded cloud credentials' },
  { pattern: /(ssh-rsa\s+AAA|BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE\s+KEY)/i, severity: 'high', description: 'Embedded SSH key' },
  { pattern: /(iptables|ufw\s+disable|systemctl\s+stop\s+(firewalld|ufw))/i, severity: 'high', description: 'Firewall manipulation' },
  { pattern: /(os\.environ|os\.getenv|process\.env)\s*[\[(].*?(send|post|get|put|delete|request|http|https)\s*[\(]/i, severity: 'high', description: 'Environment access followed by network I/O' },
  { pattern: /(subprocess\.\w+\s*\(|os\.system\s*\(|os\.popen\s*\()[^)]*(env|environ|token|secret|key|password).*(send|post|get|put|delete|request|http|https)/i, severity: 'high', description: 'Command execution with environment/sensitive data + network I/O' },
  { pattern: /(__import__\s*\(\s*["']os["']\s*\)|__import__\s*\(\s*["']subprocess["']\s*\))/i, severity: 'medium', description: 'Dynamic import of os/subprocess (possible obfuscation)' },
  { pattern: /(compile\s*\(|exec\s*\(|eval\s*\()\s*[^)]*(request|url|open|fetch|get|post)/i, severity: 'medium', description: 'Dynamic code execution with network input' },
  { pattern: /(pty\.spawn|os\.execv|os\.execve)/i, severity: 'medium', description: 'Process spawning via pty/os.exec' },
  { pattern: /(import\s+.*\bcodecs\b|import\s+.*\bencodings\b).*\b(bytes.decode|base64|hex)\b/i, severity: 'medium', description: 'Codec/encoding abuse for payload obfuscation' },
  // Dockerfile-specific patterns
  { pattern: /(ADD\s+(https?|ftp):\/\/)/i, severity: 'medium', description: 'Dockerfile ADD from remote URL — downloads code at build time, bypasses source scan' },
  { pattern: /(COPY\s+--chmod\s*=\s*0{4}7{3}|RUN\s+chmod\s+(777|0{4}7{3}|-R\s+777))/i, severity: 'medium', description: 'Dockerfile sets world-writable permissions' },
  { pattern: /(USER\s+root|USER\s+0\s)/i, severity: 'medium', description: 'Dockerfile runs as root user' },
];

const SCAN_EXCLUDE_DIRS = new Set(['.git', 'node_modules', '__pycache__', '.venv', 'venv', 'env']);
const MAX_FILE_SIZE = 1024 * 512;

async function walkDir(dir: string, baseDir: string): Promise<string[]> {
  const files: string[] = [];
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SCAN_EXCLUDE_DIRS.has(entry.name)) {
          files.push(...await walkDir(fullPath, baseDir));
        }
      } else if (entry.isFile()) {
        files.push(fullPath);
      }
    }
  } catch {
    // skip inaccessible directories
  }
  return files;
}

export async function scanRepo(cloneDir: string): Promise<ScanResult> {
  const findings: ScanResult['findings'] = [];
  const files = await walkDir(cloneDir, cloneDir);

  const pythonFiles: string[] = [];
  const jsFiles: { filePath: string; relPath: string; content: string }[] = [];

  for (const filePath of files) {
    const relPath = relative(cloneDir, filePath);
    const ext = extname(filePath).toLowerCase();

    try {
      const stat = await (await import('fs/promises')).stat(filePath);
      if (stat.size > MAX_FILE_SIZE) continue;

      const content = await readFile(filePath, 'utf-8');

      // Regex-based scan (applies to all files)
      for (const { pattern, severity, description } of SUSPICIOUS_PATTERNS) {
        const match = content.match(pattern);
        if (match) {
          const line = content.substring(0, content.indexOf('\n', match.index!)).trim().substring(0, 120);
          findings.push({
            file: relPath,
            severity,
            description,
            match: line,
          });
        }
      }

      // Entropy-based secret detection (all file types)
      const highEntropy = findHighEntropyStrings(content);
      for (const hit of highEntropy) {
        findings.push({
          file: relPath,
          severity: 'medium',
          description: `High-entropy string (${hit.entropy.toFixed(1)} bits/char) — possible secret or token: "${hit.value}..."`,
          match: `line ${hit.line}`,
        });
      }

      // Collect files for AST analysis
      if (ext === '.py') {
        pythonFiles.push(filePath);
      } else if (['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'].includes(ext)) {
        jsFiles.push({ filePath, relPath, content });
      }
    } catch {
      continue;
    }
  }

  // AST analysis for Python files (batched via python3)
  if (pythonFiles.length > 0) {
    const batchSize = 20;
    for (let i = 0; i < pythonFiles.length; i += batchSize) {
      const batch = pythonFiles.slice(i, i + batchSize);
      const result = await analyzePythonAST(batch);
      if (result) {
        for (const finding of result) {
          findings.push(finding);
        }
      }
    }
  }

  // Structural analysis for JS/TS files
  for (const { relPath, content } of jsFiles) {
    const jsFindings = analyzeJS(relPath, content);
    findings.push(...jsFindings);
  }

  const highSeverityFindings = findings.filter(f => f.severity === 'high');

  return {
    passed: highSeverityFindings.length === 0,
    findings,
  };
}
