const SECRET_PATTERNS = [
  /sk-[A-Za-z0-9_-]{20,}/g,
  /sk-ant-[A-Za-z0-9]{20,}/g,
  /AIza[0-9A-Za-z_-]{35}/g,
  /AKIA[0-9A-Z]{16}/g,
  /SG\.[A-Za-z0-9]{20,}\.[A-Za-z0-9]{20,}/g,
  /ghp_[A-Za-z0-9]{36}/g,
  /gho_[A-Za-z0-9]{36}/g,
  /github_pat_[A-Za-z0-9]{22,}/g,
  /xox[bpras]-\d+-[A-Za-z0-9]{10,}/g,
];

export function maskSecrets(text: string): string {
  let masked = text;
  for (const pattern of SECRET_PATTERNS) {
    masked = masked.replace(pattern, '***');
  }
  masked = masked.replace(/(OPENAI_API_KEY|ANTHROPIC_API_KEY|OPENAI_ORG_ID|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)=[^\s"'\\]+/g, '$1=***');
  return masked;
}

export function formatProxyAudit(line: string): string | null {
  const match = line.match(/\[WIPPA_PROXY\]\s+(BLOCKED|ALLOWED)\s+(\S+)\s*(.*)/);
  if (!match) return null;
  const action = match[1];
  const domain = match[2];
  const detail = match[3] || '';
  if (action === 'BLOCKED') {
    return `  [PROXY] Blocked outbound call to ${domain}. Use --allow-domain ${domain} to allow.`;
  }
  if (action === 'ALLOWED' && detail) {
    return `  [PROXY] ${domain} (${detail.trim()})`;
  }
  return `  [PROXY] ${action === 'ALLOWED' ? 'Allowed' : 'Blocked'} ${domain}`;
}
