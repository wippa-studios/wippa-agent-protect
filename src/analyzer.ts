import { execa } from 'execa';
import type { ScanFinding } from './types';

const AST_SCAN_SCRIPT = `
import ast, sys, json

files = sys.argv[1:]
results = {}
for filepath in files:
    try:
        with open(filepath) as f:
            source = f.read()
    except Exception:
        continue
    try:
        tree = ast.parse(source)
    except SyntaxError:
        continue
    findings = []
    for node in ast.walk(tree):
        loc = getattr(node, 'lineno', 0)
        if isinstance(node, ast.Call):
            func = node.func
            name_chain = []
            n = func
            while isinstance(n, ast.Attribute):
                name_chain.insert(0, n.attr)
                n = n.value
            if isinstance(n, ast.Name):
                name_chain.insert(0, n.id)
            call_name = '.'.join(name_chain)

            has_nonconst_args = any(
                not isinstance(a, (ast.Constant, ast.Str, ast.Num)) and
                not (isinstance(a, ast.List) and all(isinstance(e, ast.Constant) for e in a.elts))
                for a in node.args
            )

            is_suspicious_call = False
            desc = ''

            if call_name in ('os.system', 'os.popen', 'os.execv', 'os.execve', 'pty.spawn'):
                if has_nonconst_args:
                    is_suspicious_call = True
                    desc = f'AST: {call_name}() called with dynamic argument — possible command injection'
            elif call_name in ('subprocess.call', 'subprocess.run', 'subprocess.Popen', 'subprocess.check_output', 'subprocess.check_call'):
                kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
                has_shell_true = any(
                    isinstance(kw, ast.keyword) and kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                if has_shell_true and has_nonconst_args:
                    is_suspicious_call = True
                    desc = f'AST: {call_name}() with shell=True and dynamic command — possible command injection'
                elif has_shell_true:
                    is_suspicious_call = True
                    desc = f'AST: {call_name}() with shell=True — potential risk'
            elif call_name in ('eval', 'exec', 'execfile'):
                if has_nonconst_args:
                    is_suspicious_call = True
                    desc = f'AST: {call_name}() with dynamic input — possible code injection'
                elif node.args:
                    is_suspicious_call = True
                    desc = f'AST: {call_name}() used — verify input is trusted'
            elif call_name in ('compile',):
                if has_nonconst_args:
                    is_suspicious_call = True
                    desc = f'AST: compile() with dynamic source — possible code injection'
            elif call_name == '__import__':
                if has_nonconst_args:
                    is_suspicious_call = True
                    desc = f'AST: __import__() with dynamic argument — possible obfuscation'
            elif 'base64' in call_name.lower() and has_nonconst_args:
                is_suspicious_call = True
                desc = f'AST: base64 decode with dynamic input — possible obfuscation'

            if is_suspicious_call:
                findings.append({
                    'line': loc,
                    'description': desc,
                    'match': source.split(chr(10))[loc - 1].strip()[:120] if 0 < loc <= len(source.split(chr(10))) else ''
                })

        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in ('os', 'subprocess', 'shutil', 'pty', 'ctypes'):
                    findings.append({
                        'line': loc,
                        'description': f'AST: imports module "{alias.name}" — monitor for dangerous usage',
                        'match': f'import {alias.name}'
                    })
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module in ('os', 'subprocess', 'shutil', 'pty'):
                for alias in node.names:
                    if alias.name in ('system', 'popen', 'run', 'Popen', 'call', 'execv', 'execve', 'spawn'):
                        findings.append({
                            'line': loc,
                            'description': f'AST: imports dangerous function "{alias.name}" from {node.module}',
                            'match': f'from {node.module} import {alias.name}'
                        })

    if findings:
        results[filepath] = findings

print(json.dumps(results))
`;

const JS_DANGEROUS_PATTERNS: { check: (line: string, lines: string[], idx: number) => { severity: string; description: string; match: string } | null }[] = [
  {
    check: (line, lines, idx) => {
      const m = line.match(/\b(exec|execSync|execFile|spawn|fork)\s*\(/);
      if (m) {
        const hasDynamic = !line.includes("'") && !line.includes('"') && line.match(/,\s*[^"')\s]/);
        if (hasDynamic) {
          return { severity: 'high', description: 'AST: child_process.' + m[1] + '() with dynamic command — possible command injection', match: line.trim().substring(0, 120) };
        }
        return { severity: 'medium', description: 'AST: child_process.' + m[1] + '() used — verify input is trusted', match: line.trim().substring(0, 120) };
      }
      return null;
    }
  },
  {
    check: (line, lines, idx) => {
      const m = line.match(/\beval\s*\(/);
      if (m) {
        const hasDynamic = !line.includes("'") && !line.includes('"') && !line.match(/\[\d+\]/);
        return { severity: hasDynamic ? 'high' : 'medium', description: 'AST: eval() used' + (hasDynamic ? ' with dynamic input — possible code injection' : ''), match: line.trim().substring(0, 120) };
      }
      return null;
    }
  },
  {
    check: (line, lines, idx) => {
      const m = line.match(/new\s+Function\s*\(/);
      if (m) return { severity: 'medium', description: 'AST: new Function() used — possible dynamic code execution', match: line.trim().substring(0, 120) };
      return null;
    }
  },
  {
    check: (line, lines, idx) => {
      if ((line.match(/require\s*\(\s*['"]child_process['"]\s*\)/) || line.match(/from\s+['"]child_process['"]/)) && !line.trim().startsWith('//')) {
        return { severity: 'low', description: 'AST: imports child_process module — monitor for dangerous usage', match: line.trim().substring(0, 120) };
      }
      return null;
    }
  },
  {
    check: (line, lines, idx) => {
      if (line.match(/vm\.(runInThisContext|runInNewContext|Script|compileFunction)\s*\(/)) {
        const hasDynamic = !line.includes("'") && !line.includes('"');
        return { severity: hasDynamic ? 'high' : 'medium', description: 'AST: vm sandbox escape surface with' + (hasDynamic ? ' dynamic' : '') + ' code', match: line.trim().substring(0, 120) };
      }
      return null;
    }
  },
  {
    check: (line, lines, idx) => {
      if (line.match(/\bfs\.(chmod|chown)\s*\(/)) {
        return { severity: 'medium', description: 'AST: filesystem permission change', match: line.trim().substring(0, 120) };
      }
      return null;
    }
  },
];

export function shannonEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function findHighEntropyStrings(content: string): { value: string; entropy: number; line: number; column: number }[] {
  const results: { value: string; entropy: number; line: number; column: number }[] = [];
  const lines = content.split('\n');

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];

    const strMatches = line.matchAll(/['"]([A-Za-z0-9+/=_\-:.~]{20,})['"]/g);
    for (const m of strMatches) {
      const value = m[1];
      if (/^\d+$/.test(value)) continue;
      if (value.startsWith('http')) continue;
      if (value.startsWith('sha') && value.length === 40) continue;
      const entropy = shannonEntropy(value);
      if (entropy > 4.5) {
        results.push({ value: value.substring(0, 40), entropy, line: lineIdx + 1, column: (m.index || 0) + 1 });
      }
    }
  }

  return results;
}

export async function analyzePythonAST(filePaths: string[]): Promise<{ file: string; severity: string; description: string; match: string }[] | null> {
  if (filePaths.length === 0) return null;
  try {
    const result = await execa('python3', ['-c', AST_SCAN_SCRIPT, ...filePaths], { timeout: 30_000, reject: false });
    if (result.exitCode !== 0 || !result.stdout.trim()) return null;
    const parsed = JSON.parse(result.stdout.trim());
    const findings: { file: string; severity: string; description: string; match: string }[] = [];
    for (const [filePath, fileFindings] of Object.entries(parsed)) {
      for (const f of fileFindings as any[]) {
        findings.push({
          file: filePath,
          severity: (f.description as string).includes('injection') || (f.description as string).includes('dynamic') || (f.description as string).includes('obfuscation') ? 'high' : 'medium',
          description: f.description as string,
          match: (f.match as string) || '',
        });
      }
    }
    return findings;
  } catch {
    return null;
  }
}

export function analyzeJS(relPath: string, content: string): { file: string; severity: string; description: string; match: string }[] {
  const findings: { file: string; severity: string; description: string; match: string }[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of JS_DANGEROUS_PATTERNS) {
      const result = pattern.check(line, lines, i);
      if (result) {
        findings.push({
          file: relPath,
          severity: result.severity === 'high' ? 'high' : 'medium',
          description: result.description,
          match: result.match,
        });
      }
    }
  }

  return findings;
}
