import { spawn, SpawnOptions, ChildProcess } from 'child_process';
import { existsSync, accessSync, constants } from 'fs';
import { resolve, join } from 'path';
import { homedir } from 'os';
import { promisify } from 'util';
import { exec as execCallback } from 'child_process';

const exec = promisify(execCallback);

/**
 * Error thrown when sandbox configuration or execution fails.
 */
export class SandboxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SandboxError';
  }
}

/**
 * Paths that are always blocked (overlaid with empty tmpfs)
 */
const SECRET_PATHS = [
  '.ssh', '.gnupg', '.pki',
  '.aws', '.azure', '.gcloud', '.config/gcloud',
  '.kube', '.docker', '.helm',
  '.npmrc', '.yarnrc', '.pypirc', '.netrc',
  '.gem/credentials', '.cargo/credentials', '.cargo/credentials.toml',
  '.composer/auth.json',
  '.password-store', '.local/share/keyrings',
  '.config/op', '.config/keybase',
  '.config/gh', '.config/hub', '.config/netlify',
  '.config/heroku', '.config/doctl',
  '.mozilla', '.config/google-chrome', '.config/chromium',
  '.config/BraveSoftware', '.config/vivaldi',
  '.secrets', '.credentials', '.private',
  '.bash_history', '.zsh_history', '.node_repl_history',
];

/**
 * System paths that cannot be written to
 */
const FORBIDDEN_WRITE = [
  '/', '/bin', '/boot', '/etc', '/lib', '/lib64', '/lib32',
  '/opt', '/root', '/sbin', '/sys', '/usr', '/var',
];

/**
 * Configuration options for the Sandbox.
 */
export interface SandboxOptions {
  /** Paths to mount read-only */
  ro?: string[];
  /** Paths to mount read-write */
  rw?: string[];
  /** Allow network access (default: false) */
  network?: boolean;
  /** Allow GPU access (default: false) */
  gpu?: boolean;
  /** Mount $HOME read-only with secrets blocked (default: false) */
  shareHome?: boolean;
  /** Additional environment variables */
  env?: Record<string, string>;
  /** Environment variables to pass from host */
  envPassthrough?: string[];
  /** Secret paths to allow (e.g., ['.gnupg'] for signing) */
  allowSecrets?: string[];
  /** Command timeout in milliseconds */
  timeout?: number;
  /** Working directory for commands */
  cwd?: string;
}

/**
 * Result of a sandboxed command execution.
 */
export interface RunResult {
  /** Exit code of the command */
  code: number;
  /** Standard output */
  stdout: string;
  /** Standard error */
  stderr: string;
}

/**
 * Resolve path with home directory expansion.
 */
function resolvePath(path: string): string {
  if (path.startsWith('~')) {
    return resolve(homedir(), path.slice(2));
  }
  return resolve(path);
}

/**
 * Validate that a path can be mounted read-write.
 */
function validateRwPath(path: string): string {
  const resolved = resolvePath(path);
  for (const forbidden of FORBIDDEN_WRITE) {
    if (resolved === forbidden || resolved.startsWith(forbidden + '/')) {
      throw new SandboxError(`Write access to '${resolved}' is forbidden (system path)`);
    }
  }
  return resolved;
}

/**
 * Check if bwrap is available.
 */
async function findBwrap(): Promise<string> {
  try {
    const { stdout } = await exec('which bwrap');
    return stdout.trim();
  } catch {
    throw new SandboxError(
      'bubblewrap (bwrap) not found. Install with: apt install bubblewrap'
    );
  }
}

/**
 * Configurable bubblewrap sandbox for subprocess execution.
 * 
 * @examples.py
 * ```typescript
 * const sb = new Sandbox({ rw: ['~/project'], network: true });
 * const result = await sb.run('make test');
 * console.log(result.stdout);
 * ```
 */
export class Sandbox {
  private options: Required<SandboxOptions>;
  private bwrapPath: string | null = null;

  constructor(options: SandboxOptions = {}) {
    // Validate rw paths
    for (const path of options.rw || []) {
      validateRwPath(path);
    }

    this.options = {
      ro: options.ro || [],
      rw: options.rw || [],
      network: options.network || false,
      gpu: options.gpu || false,
      shareHome: options.shareHome || false,
      env: options.env || {},
      envPassthrough: options.envPassthrough || [],
      allowSecrets: options.allowSecrets || [],
      timeout: options.timeout || 0,
      cwd: options.cwd || '',
    };
  }

  /**
   * Build bwrap command arguments.
   */
  private buildBwrapArgs(command: string, cwd?: string): string[] {
    const args: string[] = [];
    const home = homedir();

    // Namespace isolation
    args.push(
      '--unshare-user', '--unshare-pid', '--unshare-uts',
      '--unshare-ipc', '--unshare-cgroup'
    );
    if (!this.options.network) {
      args.push('--unshare-net');
    }

    // Security
    args.push(
      '--cap-drop', 'ALL',
      '--no-new-privs',
      '--new-session',
      '--die-with-parent',
      '--hostname', 'sandbox'
    );

    // /proc and /dev
    args.push('--proc', '/proc', '--dev', '/dev');
    for (const dev of ['/dev/null', '/dev/zero', '/dev/random', '/dev/urandom', '/dev/tty']) {
      if (existsSync(dev)) {
        args.push('--dev-bind-try', dev, dev);
      }
    }

    // Base system (read-only)
    for (const dir of ['/usr', '/bin', '/sbin', '/lib', '/lib64', '/lib32']) {
      if (existsSync(dir)) {
        args.push('--ro-bind', dir, dir);
      }
    }

    // Essential /etc files
    const etcFiles = [
      '/etc/ld.so.cache', '/etc/ld.so.conf', '/etc/passwd', '/etc/group',
      '/etc/hosts', '/etc/resolv.conf', '/etc/localtime',
      '/etc/ssl', '/etc/ca-certificates', '/etc/terminfo', '/etc/alternatives',
    ];
    for (const f of etcFiles) {
      if (existsSync(f)) {
        args.push('--ro-bind-try', f, f);
      }
    }

    // Ephemeral mounts
    args.push('--tmpfs', '/tmp', '--tmpfs', '/var/tmp', '--tmpfs', '/run');

    // Home directory
    if (this.options.shareHome) {
      args.push('--ro-bind', home, home);
      for (const secret of SECRET_PATHS) {
        if (this.options.allowSecrets.includes(secret)) continue;
        const secretPath = join(home, secret);
        if (existsSync(secretPath)) {
          args.push('--tmpfs', secretPath);
        }
      }
    } else {
      args.push(
        '--tmpfs', home,
        '--dir', join(home, '.cache'),
        '--dir', join(home, '.config'),
        '--dir', join(home, '.local/share')
      );
    }

    // User-specified mounts
    for (const path of this.options.ro) {
      const resolved = resolvePath(path);
      if (existsSync(resolved)) {
        args.push('--ro-bind', resolved, resolved);
      }
    }

    for (const path of this.options.rw) {
      const resolved = resolvePath(path);
      if (existsSync(resolved)) {
        args.push('--bind', resolved, resolved);
      }
    }

    // GPU access
    if (this.options.gpu) {
      if (existsSync('/dev/dri')) {
        args.push('--dev-bind', '/dev/dri', '/dev/dri');
      }
      // Note: glob for nvidia devices would need additional implementation
    }

    // Environment
    const user = process.env.USER || 'sandbox';
    const envVars: Record<string, string> = {
      HOME: home,
      USER: user,
      LOGNAME: user,
      PATH: '/usr/local/bin:/usr/bin:/bin',
      TERM: process.env.TERM || 'xterm-256color',
      LANG: process.env.LANG || 'C.UTF-8',
      TMPDIR: '/tmp',
    };

    for (const varName of this.options.envPassthrough) {
      if (process.env[varName]) {
        envVars[varName] = process.env[varName]!;
      }
    }

    Object.assign(envVars, this.options.env);

    for (const [key, value] of Object.entries(envVars)) {
      args.push('--setenv', key, value);
    }

    // Working directory
    let workdir = cwd || this.options.cwd;
    if (!workdir) {
      if (this.options.rw.length > 0) {
        workdir = resolvePath(this.options.rw[0]);
      } else if (this.options.ro.length > 0) {
        workdir = resolvePath(this.options.ro[0]);
      } else {
        workdir = '/tmp';
      }
    } else {
      workdir = resolvePath(workdir);
    }
    args.push('--chdir', workdir);

    // Command
    args.push('--', 'sh', '-c', command);

    return args;
  }

  /**
   * Run a command in the sandbox.
   */
  async run(command: string, options: { cwd?: string } = {}): Promise<RunResult> {
    if (!this.bwrapPath) {
      this.bwrapPath = await findBwrap();
    }

    const args = this.buildBwrapArgs(command, options.cwd);

    return new Promise((resolve, reject) => {
      const proc = spawn(this.bwrapPath!, args, {
        stdio: ['inherit', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';

      proc.stdout?.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr?.on('data', (data) => {
        stderr += data.toString();
      });

      let timeoutId: NodeJS.Timeout | undefined;
      if (this.options.timeout > 0) {
        timeoutId = setTimeout(() => {
          proc.kill('SIGTERM');
          reject(new SandboxError(`Command timed out after ${this.options.timeout}ms`));
        }, this.options.timeout);
      }

      proc.on('close', (code) => {
        if (timeoutId) clearTimeout(timeoutId);
        resolve({
          code: code ?? -1,
          stdout,
          stderr,
        });
      });

      proc.on('error', (err) => {
        if (timeoutId) clearTimeout(timeoutId);
        reject(new SandboxError(`Failed to spawn process: ${err.message}`));
      });
    });
  }

  /**
   * Run command and return its output. Throws on non-zero exit.
   */
  async checkOutput(command: string, options: { cwd?: string } = {}): Promise<string> {
    const result = await this.run(command, options);
    if (result.code !== 0) {
      throw new SandboxError(`Command failed with code ${result.code}: ${result.stderr}`);
    }
    return result.stdout;
  }
}

// === Convenience functions ===

/**
 * Run a command in a sandbox.
 */
export async function run(
  command: string,
  options: SandboxOptions & { cwd?: string } = {}
): Promise<RunResult> {
  const { cwd, ...sandboxOptions } = options;
  const sb = new Sandbox(sandboxOptions);
  return sb.run(command, { cwd });
}

/**
 * Run a sandboxed command and return its output.
 */
export async function checkOutput(
  command: string,
  options: SandboxOptions & { cwd?: string } = {}
): Promise<string> {
  const { cwd, ...sandboxOptions } = options;
  const sb = new Sandbox(sandboxOptions);
  return sb.checkOutput(command, { cwd });
}

// === child_process patching ===

let _originalExec: typeof execCallback | null = null;
let _patched = false;
let _patchConfig: SandboxOptions = {};

/**
 * Monkey-patch child_process.exec to use sandboxing.
 */
export function patchChildProcess(options: SandboxOptions = {}): void {
  if (_patched) return;

  const childProcess = require('child_process');
  _originalExec = childProcess.exec;
  _patchConfig = {
    network: false,
    shareHome: true,
    envPassthrough: [
      'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'OPENROUTER_API_KEY',
      'GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL',
      'TERM', 'COLORTERM',
    ],
    ...options,
  };

  childProcess.exec = (
    command: string,
    execOptions: any,
    callback?: Function
  ) => {
    if (typeof execOptions === 'function') {
      callback = execOptions;
      execOptions = {};
    }

    const sb = new Sandbox(_patchConfig);
    sb.run(command, { cwd: execOptions?.cwd })
      .then((result) => {
        if (callback) {
          const error = result.code !== 0
            ? Object.assign(new Error(`Command failed: ${command}`), { code: result.code })
            : null;
          callback(error, result.stdout, result.stderr);
        }
      })
      .catch((err) => {
        if (callback) callback(err, '', '');
      });
  };

  _patched = true;
}

/**
 * Remove the child_process monkey-patch.
 */
export function unpatchChildProcess(): void {
  if (!_patched || !_originalExec) return;
  
  const childProcess = require('child_process');
  childProcess.exec = _originalExec;
  _patched = false;
}
