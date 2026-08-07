import { join } from 'path';
import { access, readFile, writeFile } from 'fs/promises';
import { dockerBuild } from './docker';
import type { BuildResult } from './types';

const PYTHON_ENTRYPOINTS = ['main.py', 'app.py', 'run.py', 'agent.py', 'src/main.py', 'src/app.py', 'src/agent.py'];
const JS_ENTRYPOINTS = ['index.js', 'server.js', 'app.js', 'src/index.js', 'dist/index.js', 'main.js'];

const PYTHON_PROXY_TEMPLATE = `import http.server, urllib.request, sys, os, subprocess, threading, json, socket, shlex

ENTRYPOINT = 'ENTRYPOINT_PLACEHOLDER'
ENTRYPOINT_CMD = 'ENTRYPOINT_CMD_PLACEHOLDER'

APP_PORT = int(os.environ.get('APP_PORT', '9090'))
PROXY_PORT = int(os.environ.get('PROXY_PORT', os.environ.get('PORT', '8080')))
EGRESS_PORT = 9091
ALLOWED_DOMAINS = set(h.strip() for h in os.environ.get('WIPPA_ALLOWED_DOMAINS',
    'api.openai.com,api.anthropic.com,api.groq.com,api.deepseek.com,api.mistral.ai,api.cohere.com,api.together.xyz,api.fireworks.ai,github.com,api.github.com').split(','))

BADGE = '<div style="position:fixed;bottom:8px;right:8px;z-index:9999;background:rgba(0,0,0,0.7);color:#fff;padding:4px 10px;border-radius:12px;font-size:11px;font-family:sans-serif;pointer-events:none;opacity:0.7">Powered by Wippa</div>'
CLI_HTML = '''<!DOCTYPE html><html><head><meta charset="utf-8"><title>Agent Preview</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:720px;margin:0 auto;padding:2rem}
h1{font-size:1.5rem}pre{background:#f4f4f4;padding:1rem;border-radius:4px;overflow:auto;max-height:60vh}
form{margin:1rem 0}label{display:block;margin-bottom:0.25rem;font-weight:600}
input,textarea,button{width:100%;padding:0.5rem;box-sizing:border-box;margin-bottom:0.5rem;font-size:1rem}
button{background:#000;color:#fff;border:none;padding:0.75rem;cursor:pointer}
button:disabled{opacity:0.5}
.badge{position:fixed;bottom:8px;right:8px;z-index:9999;background:rgba(0,0,0,0.7);color:#fff;padding:4px 10px;border-radius:12px;font-size:11px;pointer-events:none;opacity:0.7}
</style></head><body>
<h1>Agent Preview</h1><p>This agent runs as a CLI script. Enter input below to run it.</p>
<form onsubmit="event.preventDefault();runAgent()">
<label for="input">Input (optional)</label>
<textarea id="input" rows="3" placeholder="Enter input for the agent..."></textarea>
<button id="runBtn" type="submit">Run Agent</button>
</form>
<div id="output" style="display:none"><h3>Output</h3><pre id="result"></pre></div>
<script>
async function runAgent(){const b=document.getElementById('runBtn');const i=document.getElementById('input').value;b.disabled=true;b.textContent='Running...';const r=await fetch('/_eap/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({input:i})});const d=await r.json();document.getElementById('output').style.display='block';document.getElementById('result').textContent=d.output||d.error;b.disabled=false;b.textContent='Run Agent';}
</script></body></html>'''

cli_mode = [False]

def probe_app():
    try:
        urllib.request.urlopen(f'http://127.0.0.1:{APP_PORT}/', timeout=3)
        cli_mode[0] = False
    except: cli_mode[0] = True

def start_app():
    env = {**os.environ, 'PORT': str(APP_PORT),
           'HTTP_PROXY': f'http://127.0.0.1:{EGRESS_PORT}',
           'HTTPS_PROXY': f'http://127.0.0.1:{EGRESS_PORT}',
           'http_proxy': f'http://127.0.0.1:{EGRESS_PORT}',
           'https_proxy': f'http://127.0.0.1:{EGRESS_PORT}'}
    if ENTRYPOINT_CMD:
        subprocess.run(ENTRYPOINT_CMD, shell=True, env=env)
    else:
        subprocess.run([sys.executable, ENTRYPOINT], env=env)

def audit_log(action, domain, detail=''):
    print(f'[WIPPA_PROXY] {action} {domain} {detail}', flush=True, file=sys.stderr)

class EgressHandler(http.server.BaseHTTPRequestHandler):
    def do_CONNECT(self):
        host = self.path.split(':')[0]
        if host not in ALLOWED_DOMAINS:
            audit_log('BLOCKED', host, '(not in allowlist)')
            self.send_response(403)
            self.end_headers()
            return
        audit_log('ALLOWED', host)
        try:
            port = int(self.path.split(':')[1]) if ':' in self.path else 443
            s = socket.create_connection((host, port))
            self.send_response(200)
            self.end_headers()
            t1 = threading.Thread(target=self._tunnel, args=(s,), daemon=True)
            t1.start()
            while True:
                d = self.rfile.read(65536)
                if not d: break
                s.sendall(d)
        except: pass
    def _tunnel(self, s):
        try:
            while True:
                d = s.recv(65536)
                if not d: break
                self.wfile.write(d)
                self.wfile.flush()
        except: pass
    def do_GET(self): self._forward()
    def do_POST(self): self._forward()
    def do_PUT(self): self._forward()
    def do_DELETE(self): self._forward()
    def do_PATCH(self): self._forward()
    def _forward(self):
        host = self.headers.get('Host', '')
        if self.path.startswith('http'):
            from urllib.parse import urlparse
            parsed = urlparse(self.path)
            host = parsed.hostname or host
        if host not in ALLOWED_DOMAINS:
            audit_log('BLOCKED', host, '(not in allowlist)')
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'Blocked by network policy')
            return
        audit_log('ALLOWED', host)
        try:
            url = self.path if self.path.startswith('http') else f'http://{host}{self.path}'
            u = urllib.request.Request(url, method=self.command)
            if 'Content-Length' in self.headers:
                u.data = self.rfile.read(int(self.headers['Content-Length']))
            for k, v in self.headers.items():
                if k.lower() not in ('proxy-host', 'proxy-connection'):
                    u.add_header(k, v)
            s = urllib.request.urlopen(u, timeout=30)
            self.send_response(s.status)
            c = s.read()
            for k, v in s.headers.items():
                if k.lower() not in ('transfer-encoding','content-encoding'):
                    self.send_header(k, v)
            self.send_header('Content-Length', str(len(c)))
            self.end_headers()
            self.wfile.write(c)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            c = e.read()
            self.send_header('Content-Length',str(len(c)))
            self.end_headers()
            self.wfile.write(c)
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f'Egress proxy error: {e}'.encode())
    def log_message(self, *a): pass

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/_eap/health':
            self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
            return
        if cli_mode[0]:
            self.send_response(200); self.send_header('Content-Type','text/html;charset=utf-8')
            self.send_header('Content-Length',str(len(CLI_HTML)+len(BADGE)))
            self.end_headers(); self.wfile.write((CLI_HTML + BADGE).encode())
            return
        self._proxy()
    def do_POST(self):
        if self.path == '/_eap/run' and cli_mode[0]:
            length = int(self.headers.get('Content-Length',0))
            body = json.loads(self.rfile.read(length)) if length else {}
            inp = body.get('input','')
            env = {**os.environ, 'PORT': str(APP_PORT),
                   'HTTP_PROXY': f'http://127.0.0.1:{EGRESS_PORT}',
                   'HTTPS_PROXY': f'http://127.0.0.1:{EGRESS_PORT}',
                   'http_proxy': f'http://127.0.0.1:{EGRESS_PORT}',
                   'https_proxy': f'http://127.0.0.1:{EGRESS_PORT}'}
            try:
                if ENTRYPOINT_CMD:
                    p = subprocess.run(ENTRYPOINT_CMD, input=inp, capture_output=True, text=True, timeout=60, env=env, shell=True) if inp else subprocess.run(ENTRYPOINT_CMD, capture_output=True, text=True, timeout=60, env=env, shell=True)
                else:
                    p = subprocess.run([sys.executable, ENTRYPOINT], input=inp, capture_output=True, text=True, timeout=60, env=env) if inp else subprocess.run([sys.executable, ENTRYPOINT], capture_output=True, text=True, timeout=60, env=env)
                out = (p.stdout or '') + (p.stderr or '')
                if p.returncode != 0: out = f'Exit code {p.returncode}\\n' + out
            except subprocess.TimeoutExpired: out = 'Agent timed out (60s limit)'
            except Exception as e: out = f'Error: {e}'
            r = json.dumps({'output':out}).encode()
            self.send_response(200); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(r))); self.end_headers(); self.wfile.write(r)
            return
        if not cli_mode[0]: self._proxy(); return
        self.send_response(404); self.end_headers()
    def do_PUT(self): self._proxy()
    def do_DELETE(self): self._proxy()
    def do_PATCH(self): self._proxy()
    def do_HEAD(self): self._proxy()
    def _proxy(self):
        u = f'http://127.0.0.1:{APP_PORT}{self.path}'
        try:
            r = urllib.request.Request(u, method=self.command)
            if 'Content-Length' in self.headers:
                r.data = self.rfile.read(int(self.headers['Content-Length']))
            s = urllib.request.urlopen(r, timeout=30)
            self.send_response(s.status)
            c = s.read()
            for k, v in s.headers.items():
                if k.lower() not in ('transfer-encoding','content-encoding','content-length'):
                    self.send_header(k, v)
            if 'text/html' in s.headers.get('Content-Type',''):
                c = c.replace(b'</body>', BADGE + b'</body>')
                if b'</body>' not in c: c = c + BADGE
            self.send_header('Content-Length', str(len(c)))
            self.end_headers()
            self.wfile.write(c)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            c = e.read()
            self.send_header('Content-Length',str(len(c)))
            self.end_headers()
            self.wfile.write(c)
        except: self.send_response(502); self.end_headers(); self.wfile.write(b'error')
    def log_message(self, *a): pass

egress_server = http.server.HTTPServer(('127.0.0.1', EGRESS_PORT), EgressHandler)
threading.Thread(target=egress_server.serve_forever, daemon=True).start()

t = threading.Thread(target=start_app, daemon=True)
t.start()
threading.Thread(target=lambda: [__import__('time').sleep(3), probe_app()], daemon=True).start()
http.server.HTTPServer(('0.0.0.0', PROXY_PORT), H).serve_forever()
`;

const NODE_PROXY = (entrypoint: string, entrypointCmd?: string) => [
'import http from \'http\';',
'import { spawn, execSync } from \'child_process\';',
'',
'function auditLog(action, domain, detail = \'\') {',
'  process.stderr.write(`[WIPPA_PROXY] ${action} ${domain} ${detail}\\n`);',
'}',
'',
'const APP_PORT = parseInt(process.env.APP_PORT || \'9090\');',
'const PROXY_PORT = parseInt(process.env.PROXY_PORT || process.env.PORT || \'8080\');',
`const ENTRYPOINT = '${entrypoint}';`,
`const ENTRYPOINT_CMD = ${entrypointCmd ? `'${entrypointCmd.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'` : 'null'};`,
'',
'const BADGE = \'<div style="position:fixed;bottom:8px;right:8px;z-index:9999;background:rgba(0,0,0,0.7);color:#fff;padding:4px 10px;border-radius:12px;font-size:11px;font-family:sans-serif;pointer-events:none;opacity:0.7">Powered by Wippa</div>\';',
'const CLI_HTML = \'<!DOCTYPE html><html><head><meta charset="utf-8"><title>Agent Preview</title><meta name="viewport" content="width=device-width,initial-scale=1">\' +',
'\'<style>body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:720px;margin:0 auto;padding:2rem}\' +',
'\'h1{font-size:1.5rem}pre{background:#f4f4f4;padding:1rem;border-radius:4px;overflow:auto;max-height:60vh}\' +',
'\'form{margin:1rem 0}label{display:block;margin-bottom:0.25rem;font-weight:600}\' +',
'\'input,textarea,button{width:100%;padding:0.5rem;box-sizing:border-box;margin-bottom:0.5rem;font-size:1rem}\' +',
'\'button{background:#000;color:#fff;border:none;padding:0.75rem;cursor:pointer}\' +',
'\'button:disabled{opacity:0.5}\' +',
'\'.badge{position:fixed;bottom:8px;right:8px;z-index:9999;background:rgba(0,0,0,0.7);color:#fff;padding:4px 10px;border-radius:12px;font-size:11px;pointer-events:none;opacity:0.7}\' +',
'\'</style></head><body><h1>Agent Preview</h1>\' +',
'\'<p>This agent runs as a CLI script. Enter input below to run it.</p>\' +',
'\'<form onsubmit="event.preventDefault();runAgent()"><label for="input">Input (optional)</label>\' +',
'\'<textarea id="input" rows="3" placeholder="Enter input for the agent..."></textarea>\' +',
'\'<button id="runBtn" type="submit">Run Agent</button></form>\' +',
'\'<div id="output" style="display:none"><h3>Output</h3><pre id="result"></pre></div>\' +',
'\'<script>async function runAgent(){const b=document.getElementById(\\\'runBtn\\\');const i=document.getElementById(\\\'input\\\').value;b.disabled=true;b.textContent=\\\'Running...\\\';\' +',
'\'const r=await fetch(\\\'/_eap/run\\\',{method:\\\'POST\\\',headers:{\\\'Content-Type\\\':\\\'application/json\\\'},body:JSON.stringify({input:i})});\' +',
'\'const d=await r.json();document.getElementById(\\\'output\\\').style.display=\\\'block\\\';document.getElementById(\\\'result\\\').textContent=d.output||d.error;b.disabled=false;b.textContent=\\\'Run Agent\\\';}\' +',
'\'</script></body></html>\';',
'',
'let cliMode = false;',
'',
'function probeApp() {',
'  const r = http.get(\'http://127.0.0.1:\' + APP_PORT + \'/\', (res) => { cliMode = false; });',
'  r.on(\'error\', () => { cliMode = true; });',
'  r.setTimeout(3000, () => { r.destroy(); cliMode = true; });',
'}',
'',
'const app = http.createServer((req, res) => {',
'  if (req.url === \'/_eap/health\') { res.writeHead(200); res.end(\'ok\'); return; }',
'  if (cliMode) {',
'    if (req.url === \'/_eap/run\' && req.method === \'POST\') {',
'      let body = Buffer.alloc(0);',
'      req.on(\'data\', (c) => body = Buffer.concat([body, c]));',
'      req.on(\'end\', () => {',
'        const input = JSON.parse(body.toString()).input || \'\';',
'        try {',
'          const cmd = ENTRYPOINT_CMD ? ENTRYPOINT_CMD : \'node \' + ENTRYPOINT;',
'          const out = execSync(cmd, { timeout: 60000, input, encoding: \'utf-8\', env: { ...process.env, PORT: String(APP_PORT) }, shell: !!ENTRYPOINT_CMD });',
'          const r = JSON.stringify({ output: out });',
'          res.writeHead(200, { \'Content-Type\': \'application/json\', \'Content-Length\': Buffer.byteLength(r) });',
'          res.end(r);',
'        } catch(e) {',
'          const r = JSON.stringify({ output: e.stderr ? e.stderr.toString() : e.message });',
'          res.writeHead(200, { \'Content-Type\': \'application/json\', \'Content-Length\': Buffer.byteLength(r) });',
'          res.end(r);',
'        }',
'      });',
'      return;',
'    }',
'    if (req.method === \'GET\') {',
'      res.writeHead(200, { \'Content-Type\': \'text/html;charset=utf-8\' });',
'      res.end(CLI_HTML + BADGE);',
'      return;',
'    }',
'    res.writeHead(404); res.end();',
'    return;',
'  }',
'  const opts = { hostname: \'127.0.0.1\', port: APP_PORT, path: req.url, method: req.method, headers: req.headers };',
'  const proxy = http.request(opts, (proxyRes) => {',
'    let body = Buffer.alloc(0);',
'    proxyRes.on(\'data\', (chunk) => body = Buffer.concat([body, chunk]));',
'    proxyRes.on(\'end\', () => {',
'      const ct = proxyRes.headers[\'content-type\'] || \'\';',
'      res.writeHead(proxyRes.statusCode, proxyRes.statusMessage, proxyRes.headers);',
'      if (ct.includes(\'text/html\')) {',
'        let html = body.toString(\'utf-8\');',
'        html = html.replace(\'</body>\', BADGE + \'</body>\');',
'        if (!html.includes(\'</body>\')) html += BADGE;',
'        res.end(html);',
'      } else res.end(body);',
'    });',
'  });',
'  proxy.on(\'error\', () => { res.writeHead(502); res.end(\'error\'); });',
'  req.pipe(proxy);',
'});',
'',
'setTimeout(probeApp, 3000);',
'if (ENTRYPOINT_CMD) {',
'  spawn(\'sh\', [\' -c\', ENTRYPOINT_CMD], { stdio: \'inherit\', env: { ...process.env, PORT: String(APP_PORT) } });',
'} else {',
'  spawn(\'node\', [ENTRYPOINT], { stdio: \'inherit\', env: { ...process.env, PORT: String(APP_PORT) } });',
'}',
'app.listen(PROXY_PORT, () => console.log(\'EAP proxy listening on\', PROXY_PORT));',
].join('\n');

const DOCKERFILE_PYTHON = (entrypoint: string, badgeScript: string) => `
FROM python:3.11-slim

WORKDIR /app

COPY . /app

RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt 2>/dev/null || true; fi
RUN if [ -f pyproject.toml ]; then pip install --no-cache-dir . 2>/dev/null || true; fi

ENV PYTHONUNBUFFERED=1

${badgeScript}
`;

const DOCKERFILE_NODE = (entrypoint: string, badgeScript: string) => `
FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json* yarn.lock* pnpm-lock.yaml* /app/
RUN npm install 2>/dev/null; exit 0

COPY . /app

${badgeScript}
`;

export function isPythonFramework(framework: string): boolean {
  return ['CrewAI', 'LangGraph', 'LangChain', 'AutoGen', 'Pydantic AI', 'OpenAI Agents SDK', 'Semantic Kernel', 'DSPy', 'Haystack'].includes(framework);
}

export function isJsFramework(framework: string): boolean {
  return ['Vercel AI SDK', 'LangChain.js'].includes(framework);
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function parseDockerfileCommand(dir: string): Promise<string | null> {
  const dfPath = join(dir, 'Dockerfile');
  try {
    const content = await readFile(dfPath, 'utf-8');
    const lines = content.split('\n');

    let entrypoint: string[] | null = null;
    let cmd: string[] | null = null;

    for (const line of lines) {
      const trimmed = line.trim();

      const epMatch = trimmed.match(/^ENTRYPOINT\s+(.+)/);
      if (epMatch) {
        const val = epMatch[1].trim();
        if (val.startsWith('[')) {
          try {
            entrypoint = JSON.parse(val);
          } catch {
            entrypoint = [val.replace(/^\[|\]$/g, '').split(',').map((s: string) => s.trim().replace(/["']/g, '')).filter(Boolean)].flat();
          }
        } else {
          entrypoint = ['/bin/sh', '-c', val];
        }
      }

      const cmdMatch = trimmed.match(/^CMD\s+(.+)/);
      if (cmdMatch && !trimmed.startsWith('#')) {
        const val = cmdMatch[1].trim();
        if (val.startsWith('[')) {
          try {
            cmd = JSON.parse(val);
          } catch {
            cmd = [val.replace(/^\[|\]$/g, '').split(',').map((s: string) => s.trim().replace(/["']/g, '')).filter(Boolean)].flat();
          }
        } else {
          cmd = ['/bin/sh', '-c', val];
        }
      }
    }

    const combined = entrypoint || cmd;
    if (!combined) return null;

    return combined.map(s => {
      if (s.includes(' ') || s.includes('(') || s.includes(')') || s.includes('$')) {
        const escaped = s.replace(/'/g, "'\\''");
        return `'${escaped}'`;
      }
      return s;
    }).join(' ');
  } catch {
    return null;
  }
}

export async function detectEntrypoint(
  dir: string,
  framework: string
): Promise<{ entrypoint: string | null; hasDockerfile: boolean; originalCommand: string | null }> {
  const dockerfilePath = join(dir, 'Dockerfile');
  const hasDockerfile = await fileExists(dockerfilePath);

  if (hasDockerfile) {
    const originalCommand = await parseDockerfileCommand(dir);
    return { entrypoint: null, hasDockerfile: true, originalCommand };
  }

  const candidates = isPythonFramework(framework)
    ? PYTHON_ENTRYPOINTS
    : isJsFramework(framework)
      ? JS_ENTRYPOINTS
      : [];

  for (const ep of candidates) {
    if (await fileExists(join(dir, ep))) {
      return { entrypoint: ep, hasDockerfile: false, originalCommand: null };
    }
  }

  return { entrypoint: null, hasDockerfile: false, originalCommand: null };
}

export function generateDockerfile(
  cloneDir: string,
  framework: string,
  entrypoint: string,
  originalCommand?: string | null
): { dockerfile: string; proxyScript: string; proxyFilename: string; logs: string[] } {
  const isPy = isPythonFramework(framework);
  const logs: string[] = [];

  const hasExistingDf = originalCommand !== undefined;

  const badgeScript = isPy
    ? `COPY _eap_proxy.py /app/_eap_proxy.py\nCMD ["python", "_eap_proxy.py"]`
    : `COPY _eap_proxy.mjs /app/_eap_proxy.mjs\nCMD ["node", "_eap_proxy.mjs"]`;

  const dockerfileContent = hasExistingDf
    ? DOCKERFILE_PYTHON(entrypoint, badgeScript)
    : (isPy
        ? DOCKERFILE_PYTHON(entrypoint, badgeScript)
        : DOCKERFILE_NODE(entrypoint, badgeScript));

  let proxyScript: string;
  if (isPy) {
    proxyScript = PYTHON_PROXY_TEMPLATE
      .replace('ENTRYPOINT_PLACEHOLDER', entrypoint)
      .replace("ENTRYPOINT_CMD = 'ENTRYPOINT_CMD_PLACEHOLDER'", originalCommand
        ? `ENTRYPOINT_CMD = '${originalCommand.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`
        : "ENTRYPOINT_CMD = ''");
  } else {
    proxyScript = NODE_PROXY(entrypoint, originalCommand || undefined);
  }
  const proxyFilename = isPy ? '_eap_proxy.py' : '_eap_proxy.mjs';

  logs.push(`Generated Dockerfile for ${framework} (entrypoint: ${entrypoint})`);
  logs.push('Added Wippa proxy');

  return { dockerfile: dockerfileContent.trimStart(), proxyScript, proxyFilename, logs };
}

export async function buildImage(
  cloneDir: string,
  framework: string,
  imageTag: string
): Promise<BuildResult> {
  const { entrypoint, hasDockerfile, originalCommand } = await detectEntrypoint(cloneDir, framework);
  const logs: string[] = [];

  if (!hasDockerfile && !entrypoint) {
    const supported = isPythonFramework(framework)
      ? PYTHON_ENTRYPOINTS.join(', ')
      : JS_ENTRYPOINTS.join(', ');
    const msg = `No Dockerfile found and no recognized entrypoint detected. Looked for: ${supported}`;
    return { success: false, logs: msg, error: msg };
  }

  if (hasDockerfile && originalCommand) {
    const effectiveEntrypoint = isPythonFramework(framework) ? (entrypoint || 'main.py') : (entrypoint || 'index.js');
    const { dockerfile: _df, proxyScript, proxyFilename } = generateDockerfile(cloneDir, framework, effectiveEntrypoint, originalCommand);

    // Read the existing Dockerfile, strip any existing CMD/ENTRYPOINT, inject proxy
    const existingDf = await readFile(join(cloneDir, 'Dockerfile'), 'utf-8');
    const lines = existingDf.split('\n');
    const cleaned = lines.filter(l => {
      const t = l.trim();
      return !t.startsWith('CMD ') && !t.startsWith('ENTRYPOINT ') && !t.startsWith('CMD\t') && !t.startsWith('ENTRYPOINT\t');
    });
    const proxyCmd = isPythonFramework(framework) ? 'python' : 'node';
    const proxyArgs = isPythonFramework(framework) ? '_eap_proxy.py' : '_eap_proxy.mjs';
    const injection = `\nCOPY ${proxyFilename} /app/${proxyFilename}\nCMD ["${proxyCmd}", "${proxyArgs}"]\n`;
    const modifiedDf = cleaned.join('\n') + injection;

    await writeFile(join(cloneDir, 'Dockerfile'), modifiedDf);
    await writeFile(join(cloneDir, proxyFilename), proxyScript);

    logs.push(`Injected Wippa proxy into existing Dockerfile (original command: ${originalCommand.substring(0, 80)}${originalCommand.length > 80 ? '...' : ''})`);
  } else if (hasDockerfile) {
    // Dockerfile exists but no CMD/ENTRYPOINT found — inject proxy with a generic fallback
    const effectiveEntrypoint = isPythonFramework(framework) ? (entrypoint || 'main.py') : (entrypoint || 'index.js');
    const { proxyScript, proxyFilename } = generateDockerfile(cloneDir, framework, effectiveEntrypoint);

    const proxyCmd = isPythonFramework(framework) ? 'python' : 'node';
    const proxyArgs = isPythonFramework(framework) ? '_eap_proxy.py' : '_eap_proxy.mjs';
    const existingDf = await readFile(join(cloneDir, 'Dockerfile'), 'utf-8');
    const injection = `\nCOPY ${proxyFilename} /app/${proxyFilename}\nCMD ["${proxyCmd}", "${proxyArgs}"]\n`;
    const modifiedDf = existingDf + injection;

    await writeFile(join(cloneDir, 'Dockerfile'), modifiedDf);
    await writeFile(join(cloneDir, proxyFilename), proxyScript);

    logs.push('Injected Wippa proxy into existing Dockerfile (no CMD/ENTRYPOINT found, using framework default)');
  } else if (entrypoint) {
    const { dockerfile, proxyScript, proxyFilename } = generateDockerfile(cloneDir, framework, entrypoint);

    await writeFile(join(cloneDir, 'Dockerfile'), dockerfile);
    await writeFile(join(cloneDir, proxyFilename), proxyScript);

    logs.push(`Generated Dockerfile for ${framework} (entrypoint: ${entrypoint})`);
    logs.push('Added Wippa proxy');
  }

  try {
    const buildResult = await dockerBuild(imageTag, cloneDir);

    const output = buildResult.stdout + '\n' + buildResult.stderr;
    logs.push(output);

    if (buildResult.exitCode === 0) {
      return { success: true, logs: logs.join('\n'), imageTag };
    }

    let errorMsg = 'Build failed.';
    const stderr = buildResult.stderr.toLowerCase();
    if (stderr.includes('timeout') || stderr.includes('timed out')) {
      errorMsg = 'Build timed out (5 minute limit exceeded).';
    } else if (stderr.includes('not found') || stderr.includes('no such file')) {
      errorMsg = 'Build failed: missing file or dependency not found. Check build logs.';
    }

    return { success: false, logs: logs.join('\n'), error: errorMsg };
  } catch (err: any) {
    const msg = err?.message || 'Unknown build error';
    logs.push(msg);
    return { success: false, logs: logs.join('\n'), error: `Build failed: ${msg}` };
  }
}
