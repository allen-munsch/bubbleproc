/**
 * bubbleproc - Bubblewrap sandboxing for Node.js
 * 
 * A secure subprocess execution library that uses bubblewrap
 * to isolate commands from sensitive data and system resources.
 * 
 * @examples.py
 * ```typescript
 * import { run, Sandbox } from ' @bubbleproc/node';
 * 
 * // Simple usage
 * const result = await run('ls -la', { rw: ['~/project'] });
 * 
 * // Reusable sandbox
 * const sb = new Sandbox({ rw: ['~/project'], network: true });
 * await sb.run('npm install');
 * await sb.run('npm test');
 * ```
 */

export { Sandbox, SandboxOptions, SandboxError } from './sandbox';
export { run, checkOutput, patchChildProcess, unpatchChildProcess } from './sandbox';
