import { maskSecrets } from '../src/sanitize';

describe('maskSecrets', () => {
  it('masks OpenAI API keys (sk-...)', () => {
    const result = maskSecrets('key=sk-proj-ABCDEF1234567890abcdef1234567890abcdef12');
    expect(result).toContain('***');
    expect(result).not.toContain('sk-proj');
  });

  it('masks Anthropic API keys (sk-ant-...)', () => {
    const result = maskSecrets('key=sk-ant-ABCDEF1234567890abcdef1234567890');
    expect(result).toContain('***');
  });

  it('masks environment variable assignments', () => {
    const result = maskSecrets('export OPENAI_API_KEY=sk-secret123');
    expect(result).toBe('export OPENAI_API_KEY=***');
  });

  it('masks AWS access keys', () => {
    const result = maskSecrets('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE');
    expect(result).toContain('***');
  });

  it('does not modify text without secrets', () => {
    const text = 'print("hello world")\n';
    expect(maskSecrets(text)).toBe(text);
  });

  it('masks multiple secrets in same line', () => {
    const result = maskSecrets('OPENAI_API_KEY=sk-key1 ANTHROPIC_API_KEY=sk-ant-key2');
    expect(result).toBe('OPENAI_API_KEY=*** ANTHROPIC_API_KEY=***');
  });

  it('masks GitHub tokens', () => {
    const result = maskSecrets('token=ghp_abcdefghijklmnopqrstuvwxyz0123456789');
    expect(result).toContain('***');
  });

  it('masks Google API keys', () => {
    const result = maskSecrets('key=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
    expect(result).toContain('***');
  });
});
