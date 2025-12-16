import { Sandbox, SandboxError, run } from '../src';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('Sandbox', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bubbleproc-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('blocks network by default', async () => {
    const sb = new Sandbox();
    const result = await sb.run('curl -s --connect-timeout 2 https://example.com || echo "blocked"');
    expect(result.stdout).toContain('blocked');
  });

  test('allows network when enabled', async () => {
    const sb = new Sandbox({ network: true });
    const result = await sb.run('curl -s --connect-timeout 5 https://example.com | head -c 50');
    expect(result.stdout.length).toBeGreaterThan(0);
  });

  test('allows read-write to specified paths', async () => {
    const testFile = path.join(tmpDir, 'test.txt');
    const sb = new Sandbox({ rw: [tmpDir] });
    
    await sb.run(`echo "hello" > ${testFile}`);
    
    expect(fs.existsSync(testFile)).toBe(true);
    expect(fs.readFileSync(testFile, 'utf-8').trim()).toBe('hello');
  });

  test('blocks write to system paths', () => {
    expect(() => new Sandbox({ rw: ['/usr/bin'] }))
      .toThrow(SandboxError);
  });

  test('convenience run function works', async () => {
    const result = await run('echo "test"', { ro: [tmpDir] });
    expect(result.stdout.trim()).toBe('test');
  });
});
