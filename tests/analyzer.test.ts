// execa is used by the analyzer module, but we only test pure functions here
jest.mock('execa', () => ({
  execa: jest.fn(),
}));

import { shannonEntropy, findHighEntropyStrings, analyzeJS } from '../src/analyzer';

describe('shannonEntropy', () => {
  it('returns 0 for empty string', () => {
    expect(shannonEntropy('')).toBe(0);
  });

  it('returns 0 for single character', () => {
    expect(shannonEntropy('a')).toBe(0);
  });

  it('returns higher entropy for diverse character sets', () => {
    const low = shannonEntropy('aaaaaa');
    const high = shannonEntropy('aB3$xyz');
    expect(high).toBeGreaterThan(low);
  });

  it('returns ~4.7 for random alphanumeric', () => {
    const e = shannonEntropy('k8Hs92mR4vXpLwN7qTf');
    expect(e).toBeGreaterThan(4);
  });
});

describe('findHighEntropyStrings', () => {
  it('finds high-entropy strings in quotes', () => {
    const content = 'key = "k8Hs92mR4vXpLwN7qTfZb3Gc"';
    const results = findHighEntropyStrings(content);
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].entropy).toBeGreaterThan(4.5);
  });

  it('ignores short strings', () => {
    const content = 'name = "abc"';
    expect(findHighEntropyStrings(content)).toHaveLength(0);
  });

  it('ignores URLs', () => {
    const content = 'url = "https://api.openai.com/v1/chat/completions"';
    expect(findHighEntropyStrings(content)).toHaveLength(0);
  });

  it('ignores numeric strings', () => {
    const content = 'count = "12345678901234567890"';
    expect(findHighEntropyStrings(content)).toHaveLength(0);
  });

  it('ignores SHA hashes', () => {
    const content = 'hash = "sha256:abcdef1234567890abcdef1234567890abcdef12"';
    expect(findHighEntropyStrings(content)).toHaveLength(0);
  });
});

describe('analyzeJS', () => {
  it('detects child_process exec with dynamic command', () => {
    const content = `
const { exec } = require('child_process');
exec(cmd, (err, out) => {});
`;
    const findings = analyzeJS('test.js', content);
    expect(findings.some(f => f.description.includes('dynamic command'))).toBe(true);
  });

  it('flags eval usage', () => {
    const content = `eval(userInput);`;
    const findings = analyzeJS('test.js', content);
    expect(findings.some(f => f.description.includes('eval'))).toBe(true);
  });

  it('flags new Function()', () => {
    const content = `const fn = new Function('return ' + code);`;
    const findings = analyzeJS('test.js', content);
    expect(findings.some(f => f.description.includes('new Function'))).toBe(true);
  });

  it('flags vm sandbox usage', () => {
    const content = `vm.runInNewContext(code, sandbox);`;
    const findings = analyzeJS('test.js', content);
    expect(findings.some(f => f.description.includes('vm sandbox'))).toBe(true);
  });
});
