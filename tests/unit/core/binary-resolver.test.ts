/**
 * Unit Tests for BinaryResolver
 * Tests 4-tier resolution hierarchy, environment isolation, and SpiderFoot resolution.
 */

import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { existsSync } from 'node:fs';
import {
  BinaryResolver,
  resolveToolBinary,
  getBinaryPath,
  isEmbeddedAvailable,
  getExecutionEnvironment,
  resolveSpiderfoot,
  resolveSpiderfootDir,
  resolveSpiderfootPython,
  getEmbeddedPythonPath,
  getEmbeddedPythonRoot,
} from '../../../src/core/binary-resolver.js';

describe('BinaryResolver Unit Tests', () => {
  describe('Tier 1: Explicit Override Invariant', () => {
    it('returns explicit binary path verbatim without checking file existence', () => {
      const explicit = '/opt/mock/nonexistent/bin/holehe';
      const resolved = BinaryResolver.resolveToolBinary('holehe', explicit);
      expect(resolved).toBe(explicit);
    });

    it('trims whitespace on explicit path', () => {
      const explicit = '  /custom/bin/maigret  ';
      const resolved = BinaryResolver.resolveToolBinary('maigret', explicit);
      expect(resolved).toBe('/custom/bin/maigret');
    });

    it('returns explicit SpiderFoot directory without checking disk existence', () => {
      const explicit = '/custom/sf/directory';
      expect(BinaryResolver.resolveSpiderfootDir(explicit)).toBe(explicit);
    });

    it('returns explicit SpiderFoot Python without checking disk existence', () => {
      const explicit = '/custom/python3/binary';
      expect(BinaryResolver.resolveSpiderfootPython(explicit)).toBe(explicit);
    });

    it('returns explicit SpiderFoot pair in resolveSpiderfoot', () => {
      const sf = BinaryResolver.resolveSpiderfoot('/custom/sf/dir', '/custom/py/bin');
      expect(sf.spiderfootDir).toBe('/custom/sf/dir');
      expect(sf.pythonBinary).toBe('/custom/py/bin');
      expect(sf.binaryPath).toBe('/custom/py/bin');
    });
  });

  describe('Tier 2 / Tier 3: Staged Embedded Runtime Detection', () => {
    it('detects embedded runtime availability when resources/python is present', () => {
      const available = isEmbeddedAvailable();
      expect(typeof available).toBe('boolean');
      expect(available).toBe(true);
    });

    it('locates embedded Python root and executable path', () => {
      const root = getEmbeddedPythonRoot();
      expect(root).not.toBeNull();
      expect(existsSync(root!)).toBe(true);

      const pyPath = getEmbeddedPythonPath();
      expect(pyPath).not.toBeNull();
      expect(existsSync(pyPath!)).toBe(true);
      expect(pyPath!.endsWith('python3') || pyPath!.endsWith('python')).toBe(true);
    });

    it('resolves staged tools in resources/python/bin', () => {
      const tools = ['holehe', 'maigret', 'ignorant', 'h8mail', 'ghunt', 'spiderfoot'] as const;
      for (const tool of tools) {
        const toolBin = resolveToolBinary(tool);
        expect(existsSync(toolBin)).toBe(true);
        expect(toolBin).toContain(path.join('resources', 'python', 'bin', tool));
      }
    });

    it('locates staged SpiderFoot directory containing sf.py', () => {
      const sfDir = resolveSpiderfootDir();
      expect(existsSync(sfDir)).toBe(true);
      expect(existsSync(path.join(sfDir, 'sf.py'))).toBe(true);
    });

    it('resolves bundled certifi cacert.pem', () => {
      const certFile = BinaryResolver.resolveCertFilePath();
      expect(certFile).not.toBeNull();
      expect(existsSync(certFile!)).toBe(true);
      expect(certFile!.endsWith('cacert.pem')).toBe(true);
    });
  });

  describe('Strict getBinaryPath', () => {
    it('returns path when binary exists on disk', () => {
      const holehePath = getBinaryPath('holehe');
      expect(existsSync(holehePath)).toBe(true);
    });

    it('throws descriptive error when binary does not exist on disk', () => {
      const nonexistent = '/completely/fake/path/to/binary';
      expect(() => {
        getBinaryPath('ghunt', nonexistent);
      }).toThrowError(/Binary for tool "ghunt" not found at/);
    });
  });

  describe('Environment Isolation (getExecutionEnvironment)', () => {
    it('generates fully isolated environment for embedded tools', () => {
      const holehePath = resolveToolBinary('holehe');
      const env = getExecutionEnvironment(holehePath);

      expect(env.PYTHONHOME).toBeDefined();
      expect(existsSync(env.PYTHONHOME!)).toBe(true);
      expect(env.PYTHONNOUSERSITE).toBe('1');
      expect(env.PYTHONDONTWRITEBYTECODE).toBe('1');
      expect(env.SSL_CERT_FILE).toBeDefined();
      expect(existsSync(env.SSL_CERT_FILE!)).toBe(true);
      expect(env.REQUESTS_CA_BUNDLE).toBe(env.SSL_CERT_FILE);
      expect(env.PATH).toBeDefined();
      expect(env.PATH!.startsWith(path.dirname(holehePath))).toBe(true);
    });

    it('applies custom env overrides with priority', () => {
      const holehePath = resolveToolBinary('holehe');
      const env = getExecutionEnvironment(holehePath, {
        CUSTOM_TEST_VAR: 'test_value_123',
        PYTHONNOUSERSITE: '0',
      });

      expect(env.CUSTOM_TEST_VAR).toBe('test_value_123');
      expect(env.PYTHONNOUSERSITE).toBe('0');
    });

    it('configures PYTHONPATH for SpiderFoot execution when working dir is provided', () => {
      const sfDir = resolveSpiderfootDir();
      const sfPy = resolveSpiderfootPython();
      const env = getExecutionEnvironment('spiderfoot', sfPy, undefined, sfDir);

      expect(env.PYTHONPATH).toBeDefined();
      expect(env.PYTHONPATH!).toContain(sfDir);
    });
  });

  describe('Instance API Support', () => {
    it('allows instantiation and instance method calls', () => {
      const resolver = new BinaryResolver();
      expect(resolver.isEmbeddedAvailable()).toBe(true);
      expect(resolver.resolveToolBinary('holehe')).toBe(BinaryResolver.resolveToolBinary('holehe'));
      expect(resolver.getEmbeddedPythonPath()).toBe(BinaryResolver.getEmbeddedPythonPath());
      expect(resolver.resolveSpiderfootDir()).toBe(BinaryResolver.resolveSpiderfootDir());
    });
  });

  describe('Exported Standalone Functions', () => {
    it('verifies all dispatch exported functions are callable', () => {
      expect(typeof resolveToolBinary).toBe('function');
      expect(typeof getBinaryPath).toBe('function');
      expect(typeof isEmbeddedAvailable).toBe('function');
      expect(typeof getExecutionEnvironment).toBe('function');
      expect(typeof resolveSpiderfoot).toBe('function');
      expect(typeof resolveSpiderfootDir).toBe('function');
      expect(typeof resolveSpiderfootPython).toBe('function');
      expect(typeof getEmbeddedPythonPath).toBe('function');
      expect(typeof getEmbeddedPythonRoot).toBe('function');
    });
  });
});
