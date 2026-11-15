/**
 * Binary and Runtime Resolver for OSINT Tools
 * Centralized resolution hierarchy and execution environment isolation.
 */

import os from 'node:os';
import path from 'node:path';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { SupportedTool } from './types.js';

export interface SpiderfootResolution {
  spiderfootDir: string;
  pythonBinary: string;
  binaryPath: string;
}

export interface BinaryResolutionResult {
  tool: string;
  binaryPath: string;
  isEmbedded: boolean;
  source: 'explicit' | 'packaged' | 'staged' | 'system' | 'fallback';
}

export class BinaryResolver {
  /**
   * Resolve project root relative to current file URL.
   */
  private static getProjectRoot(): string {
    try {
      const currentFilePath = fileURLToPath(import.meta.url);
      const currentDir = path.dirname(currentFilePath);
      // Works both from src/core and dist/src/core
      if (currentDir.includes(path.join('dist', 'src', 'core'))) {
        return path.resolve(currentDir, '..', '..', '..');
      }
      if (currentDir.includes(path.join('src', 'core'))) {
        return path.resolve(currentDir, '..', '..');
      }
      return process.cwd();
    } catch {
      return process.cwd();
    }
  }

  /**
   * Determine if an embedded Python runtime is available.
   */
  public static isEmbeddedAvailable(): boolean {
    return BinaryResolver.getEmbeddedPythonRoot() !== null;
  }

  /**
   * Find the root directory of the embedded Python runtime if present.
   */
  public static getEmbeddedPythonRoot(): string | null {
    // 1. Packaged Electron resources (Tier 2)
    const resourcesPath = (process as any).resourcesPath;
    if (resourcesPath) {
      const candidatePackaged = path.join(resourcesPath, 'python');
      if (
        existsSync(path.join(candidatePackaged, 'bin', 'python3')) ||
        existsSync(path.join(candidatePackaged, 'bin', 'python'))
      ) {
        return candidatePackaged;
      }
    }

    // 2. Development staged directory from cwd (Tier 3)
    const cwdStaged = path.join(process.cwd(), 'resources', 'python');
    if (
      existsSync(path.join(cwdStaged, 'bin', 'python3')) ||
      existsSync(path.join(cwdStaged, 'bin', 'python'))
    ) {
      return cwdStaged;
    }

    // 3. Staged directory from project root
    const rootStaged = path.join(BinaryResolver.getProjectRoot(), 'resources', 'python');
    if (
      existsSync(path.join(rootStaged, 'bin', 'python3')) ||
      existsSync(path.join(rootStaged, 'bin', 'python'))
    ) {
      return rootStaged;
    }

    return null;
  }

  /**
   * Return path to the embedded Python interpreter executable, or null if absent.
   */
  public static getEmbeddedPythonPath(): string | null {
    const root = BinaryResolver.getEmbeddedPythonRoot();
    if (!root) {
      return null;
    }
    const py3 = path.join(root, 'bin', 'python3');
    if (existsSync(py3)) {
      return py3;
    }
    const py = path.join(root, 'bin', 'python');
    if (existsSync(py)) {
      return py;
    }
    return null;
  }

  /**
   * Check whether a given binary path is located inside the embedded runtime.
   */
  public static isEmbeddedBinary(binaryPath: string): boolean {
    if (!binaryPath) return false;
    const root = BinaryResolver.getEmbeddedPythonRoot();
    if (root && binaryPath.startsWith(root)) {
      return true;
    }
    return (
      binaryPath.includes(path.join('resources', 'python')) ||
      binaryPath.includes(path.join('Contents', 'Resources', 'python'))
    );
  }

  /**
   * Resolve bundled Root CA certificate (certifi/cacert.pem).
   */
  public static resolveCertFilePath(pythonRoot?: string): string | null {
    const root = pythonRoot || BinaryResolver.getEmbeddedPythonRoot();
    if (!root) {
      return null;
    }

    const candidatePaths = [
      path.join(root, 'lib', 'python3.11', 'site-packages', 'certifi', 'cacert.pem'),
      path.join(root, 'lib', 'python3.12', 'site-packages', 'certifi', 'cacert.pem'),
      path.join(root, 'lib', 'python3.10', 'site-packages', 'certifi', 'cacert.pem'),
      path.join(root, 'ssl', 'cert.pem'),
      path.join(root, 'ssl', 'cacert.pem'),
    ];

    for (const certPath of candidatePaths) {
      if (existsSync(certPath)) {
        return certPath;
      }
    }

    return null;
  }

  /**
   * Resolve tool binary path according to 4-tier resolution hierarchy.
   * Safe fallback for adapter constructors (does not throw on missing files).
   */
  public static resolveToolBinary(tool: SupportedTool | string, explicitPath?: string): string {
    const result = BinaryResolver.resolveToolBinaryDetails(tool, explicitPath);
    return result.binaryPath;
  }

  /**
   * Detailed resolution returning source and embedded status.
   */
  public static resolveToolBinaryDetails(
    tool: SupportedTool | string,
    explicitPath?: string
  ): BinaryResolutionResult {
    // Tier 1: Explicit path override
    if (explicitPath && explicitPath.trim().length > 0) {
      return {
        tool,
        binaryPath: explicitPath.trim(),
        isEmbedded: BinaryResolver.isEmbeddedBinary(explicitPath.trim()),
        source: 'explicit',
      };
    }

    // Tier 2: Packaged embedded path (Contents/Resources/python/bin/<tool>)
    const resourcesPath = (process as any).resourcesPath;
    if (resourcesPath) {
      const packagedBinary = path.join(resourcesPath, 'python', 'bin', tool);
      if (existsSync(packagedBinary)) {
        return {
          tool,
          binaryPath: packagedBinary,
          isEmbedded: true,
          source: 'packaged',
        };
      }
    }

    // Tier 3: Development staged path (resources/python/bin/<tool>)
    const stagedCwd = path.join(process.cwd(), 'resources', 'python', 'bin', tool);
    if (existsSync(stagedCwd)) {
      return {
        tool,
        binaryPath: stagedCwd,
        isEmbedded: true,
        source: 'staged',
      };
    }

    const stagedRoot = path.join(BinaryResolver.getProjectRoot(), 'resources', 'python', 'bin', tool);
    if (existsSync(stagedRoot)) {
      return {
        tool,
        binaryPath: stagedRoot,
        isEmbedded: true,
        source: 'staged',
      };
    }

    // Tier 4: System PATH and user directories fallback
    const systemCandidates = [
      path.join(os.homedir(), '.local', 'bin', tool),
      `/opt/homebrew/bin/${tool}`,
      `/usr/local/bin/${tool}`,
      `/usr/bin/${tool}`,
    ];

    for (const candidate of systemCandidates) {
      if (existsSync(candidate)) {
        return {
          tool,
          binaryPath: candidate,
          isEmbedded: false,
          source: 'system',
        };
      }
    }

    const pathDirs = (process.env.PATH || '').split(path.delimiter);
    for (const pDir of pathDirs) {
      if (pDir) {
        const candidate = path.join(pDir, tool);
        if (existsSync(candidate)) {
          return {
            tool,
            binaryPath: candidate,
            isEmbedded: false,
            source: 'system',
          };
        }
      }
    }

    // Default fallback (local user bin)
    return {
      tool,
      binaryPath: path.join(os.homedir(), '.local', 'bin', tool),
      isEmbedded: false,
      source: 'fallback',
    };
  }

  /**
   * Strict binary resolver: returns verified path or throws if binary does not exist.
   */
  public static getBinaryPath(tool: SupportedTool | string, explicitPath?: string): string {
    const resolvedPath = BinaryResolver.resolveToolBinary(tool, explicitPath);
    if (!existsSync(resolvedPath)) {
      throw new Error(`Binary for tool "${tool}" not found at ${resolvedPath}`);
    }
    return resolvedPath;
  }

  /**
   * Resolve directory for SpiderFoot engine.
   */
  public static resolveSpiderfootDir(explicitDir?: string): string {
    // Tier 1: Explicit override
    if (explicitDir && explicitDir.trim().length > 0) {
      return explicitDir.trim();
    }

    // Tier 2: Packaged app (Contents/Resources/spiderfoot)
    const resourcesPath = (process as any).resourcesPath;
    if (resourcesPath) {
      const packagedDir = path.join(resourcesPath, 'spiderfoot');
      if (existsSync(path.join(packagedDir, 'sf.py'))) {
        return packagedDir;
      }
    }

    // Tier 3: Staged development (resources/spiderfoot)
    const stagedCwd = path.join(process.cwd(), 'resources', 'spiderfoot');
    if (existsSync(path.join(stagedCwd, 'sf.py'))) {
      return stagedCwd;
    }

    const stagedRoot = path.join(BinaryResolver.getProjectRoot(), 'resources', 'spiderfoot');
    if (existsSync(path.join(stagedRoot, 'sf.py'))) {
      return stagedRoot;
    }

    // Tier 4: Host fallback locations
    const hostCandidates = [
      path.join(os.homedir(), 'osint-perso', 'spiderfoot'),
      path.join(os.homedir(), 'spiderfoot'),
      path.join(os.homedir(), '.local', 'share', 'spiderfoot'),
    ];

    for (const candidate of hostCandidates) {
      if (existsSync(path.join(candidate, 'sf.py'))) {
        return candidate;
      }
    }

    // Default fallback
    const defaultStaged = path.join(process.cwd(), 'resources', 'spiderfoot');
    if (existsSync(defaultStaged)) {
      return defaultStaged;
    }
    return path.join(os.homedir(), 'osint-perso', 'spiderfoot');
  }

  /**
   * Resolve Python binary for SpiderFoot execution.
   */
  public static resolveSpiderfootPython(explicitPy?: string, spiderfootDir?: string): string {
    // Tier 1: Explicit override
    if (explicitPy && explicitPy.trim().length > 0) {
      return explicitPy.trim();
    }

    // Tier 2: Embedded Python if available
    const embeddedPy = BinaryResolver.getEmbeddedPythonPath();
    if (embeddedPy && existsSync(embeddedPy)) {
      return embeddedPy;
    }

    // Tier 3: venv inside spiderfootDir
    const baseDir = spiderfootDir || BinaryResolver.resolveSpiderfootDir();
    const venvPy = path.join(baseDir, 'venv', 'bin', 'python');
    if (existsSync(venvPy)) {
      return venvPy;
    }
    const venvPy3 = path.join(baseDir, 'venv', 'bin', 'python3');
    if (existsSync(venvPy3)) {
      return venvPy3;
    }

    // Tier 4: System Python candidates
    const sysPyCandidates = [
      '/opt/homebrew/bin/python3',
      '/usr/local/bin/python3',
      '/usr/bin/python3',
    ];
    for (const sysPy of sysPyCandidates) {
      if (existsSync(sysPy)) {
        return sysPy;
      }
    }

    // Fallback
    return path.join(baseDir, 'venv', 'bin', 'python');
  }

  /**
   * Convenience resolver returning both spiderfoot directory and python interpreter.
   */
  public static resolveSpiderfoot(
    explicitDir?: string,
    explicitPy?: string
  ): SpiderfootResolution {
    const dir = BinaryResolver.resolveSpiderfootDir(explicitDir);
    const py = BinaryResolver.resolveSpiderfootPython(explicitPy, dir);
    return {
      spiderfootDir: dir,
      pythonBinary: py,
      binaryPath: py,
    };
  }

  /**
   * Return execution environment with isolated Python environment variables.
   */
  public static getExecutionEnvironment(
    toolBinaryPath?: string,
    customEnv?: Record<string, string | undefined>,
    cwd?: string
  ): NodeJS.ProcessEnv;
  public static getExecutionEnvironment(
    tool: SupportedTool | string,
    command: string,
    customEnv?: Record<string, string | undefined>,
    cwd?: string
  ): NodeJS.ProcessEnv;
  public static getExecutionEnvironment(
    toolOrBinaryPath?: string,
    commandOrEnv?: string | Record<string, string | undefined>,
    customEnvOrCwd?: Record<string, string | undefined> | string,
    cwd?: string
  ): NodeJS.ProcessEnv {
    let targetTool: string | undefined;
    let binaryPath: string | undefined;
    let envOverrides: Record<string, string | undefined> | undefined;
    let workingDir: string | undefined;

    if (typeof commandOrEnv === 'object' && commandOrEnv !== null) {
      binaryPath = toolOrBinaryPath;
      envOverrides = commandOrEnv as Record<string, string | undefined>;
      if (typeof customEnvOrCwd === 'string') {
        workingDir = customEnvOrCwd;
      } else {
        workingDir = cwd;
      }
    } else if (typeof commandOrEnv === 'string') {
      targetTool = toolOrBinaryPath;
      binaryPath = commandOrEnv;
      if (typeof customEnvOrCwd === 'object' && customEnvOrCwd !== null) {
        envOverrides = customEnvOrCwd;
      }
      workingDir = cwd;
    } else {
      binaryPath = toolOrBinaryPath;
      if (typeof customEnvOrCwd === 'object' && customEnvOrCwd !== null) {
        envOverrides = customEnvOrCwd;
      } else if (typeof customEnvOrCwd === 'string') {
        workingDir = customEnvOrCwd;
      }
      workingDir = workingDir || cwd;
    }

    const baseEnv: NodeJS.ProcessEnv = { ...process.env };
    const pythonRoot = BinaryResolver.getEmbeddedPythonRoot();
    const isEmbedded =
      (binaryPath && BinaryResolver.isEmbeddedBinary(binaryPath)) ||
      (pythonRoot !== null && binaryPath && binaryPath.includes(pythonRoot));

    const toolDir = binaryPath && binaryPath.includes(path.sep) ? path.dirname(binaryPath) : '';

    if (isEmbedded && pythonRoot) {
      baseEnv.PYTHONHOME = pythonRoot;
      baseEnv.PYTHONNOUSERSITE = '1';
      baseEnv.PYTHONDONTWRITEBYTECODE = '1';

      const embeddedBin = path.join(pythonRoot, 'bin');
      const standardPath = `/opt/homebrew/bin:/usr/local/bin:${os.homedir()}/.local/bin:${process.env.PATH || ''}`;
      baseEnv.PATH = toolDir && toolDir !== embeddedBin
        ? `${toolDir}:${embeddedBin}:${standardPath}`
        : `${embeddedBin}:${standardPath}`;

      const certFile = BinaryResolver.resolveCertFilePath(pythonRoot);
      if (certFile) {
        baseEnv.SSL_CERT_FILE = certFile;
        baseEnv.REQUESTS_CA_BUNDLE = certFile;
      }
    } else {
      const standardPath = `/opt/homebrew/bin:/usr/local/bin:${os.homedir()}/.local/bin:${process.env.PATH || ''}`;
      baseEnv.PATH = toolDir ? `${toolDir}:${standardPath}` : standardPath;
    }

    if (
      targetTool === 'spiderfoot' ||
      (binaryPath && binaryPath.includes('spiderfoot')) ||
      (workingDir && workingDir.includes('spiderfoot'))
    ) {
      if (workingDir) {
        baseEnv.PYTHONPATH = pythonRoot
          ? `${workingDir}:${path.join(pythonRoot, 'lib', 'python3.11', 'site-packages')}`
          : workingDir;
      }
    }

    if (envOverrides) {
      for (const [key, value] of Object.entries(envOverrides)) {
        if (value !== undefined) {
          baseEnv[key] = value;
        }
      }
    }

    return baseEnv;
  }

  // Instance methods for dependency injection
  public resolveToolBinary(tool: SupportedTool | string, explicitPath?: string): string {
    return BinaryResolver.resolveToolBinary(tool, explicitPath);
  }

  public getBinaryPath(tool: SupportedTool | string, explicitPath?: string): string {
    return BinaryResolver.getBinaryPath(tool, explicitPath);
  }

  public isEmbeddedAvailable(): boolean {
    return BinaryResolver.isEmbeddedAvailable();
  }

  public getEmbeddedPythonPath(): string | null {
    return BinaryResolver.getEmbeddedPythonPath();
  }

  public resolveSpiderfootDir(explicitDir?: string): string {
    return BinaryResolver.resolveSpiderfootDir(explicitDir);
  }

  public resolveSpiderfootPython(explicitPy?: string, spiderfootDir?: string): string {
    return BinaryResolver.resolveSpiderfootPython(explicitPy, spiderfootDir);
  }

  public resolveSpiderfoot(explicitDir?: string, explicitPy?: string): SpiderfootResolution {
    return BinaryResolver.resolveSpiderfoot(explicitDir, explicitPy);
  }

  public getExecutionEnvironment(
    toolBinaryPath?: string,
    customEnv?: Record<string, string | undefined>,
    cwd?: string
  ): NodeJS.ProcessEnv;
  public getExecutionEnvironment(
    tool: SupportedTool | string,
    command: string,
    customEnv?: Record<string, string | undefined>,
    cwd?: string
  ): NodeJS.ProcessEnv;
  public getExecutionEnvironment(
    toolOrBinaryPath?: string,
    commandOrEnv?: string | Record<string, string | undefined>,
    customEnvOrCwd?: Record<string, string | undefined> | string,
    cwd?: string
  ): NodeJS.ProcessEnv {
    return BinaryResolver.getExecutionEnvironment(
      toolOrBinaryPath as any,
      commandOrEnv as any,
      customEnvOrCwd as any,
      cwd
    );
  }
}

// Exported standalone functions matching dispatch interface
export const resolveToolBinary = BinaryResolver.resolveToolBinary.bind(BinaryResolver);
export const getBinaryPath = BinaryResolver.getBinaryPath.bind(BinaryResolver);
export const isEmbeddedAvailable = BinaryResolver.isEmbeddedAvailable.bind(BinaryResolver);
export const getExecutionEnvironment = BinaryResolver.getExecutionEnvironment.bind(BinaryResolver);
export const resolveSpiderfoot = BinaryResolver.resolveSpiderfoot.bind(BinaryResolver);
export const resolveSpiderfootDir = BinaryResolver.resolveSpiderfootDir.bind(BinaryResolver);
export const resolveSpiderfootPython = BinaryResolver.resolveSpiderfootPython.bind(BinaryResolver);
export const getEmbeddedPythonPath = BinaryResolver.getEmbeddedPythonPath.bind(BinaryResolver);
export const getEmbeddedPythonRoot = BinaryResolver.getEmbeddedPythonRoot.bind(BinaryResolver);
