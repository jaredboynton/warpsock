/**
 * Specter - Node.js bindings for the Specter HTTP client.
 *
 * A high-performance async HTTP client with full TLS, HTTP/2, and HTTP/3
 * fingerprint control for browser impersonation.
 */

const { execSync } = require('node:child_process');
const { readFileSync } = require('node:fs');

const PACKAGE_VERSION = '2.2.0';

const targets = {
  'darwin-x64': {
    local: './specter.darwin-x64.node',
    package: 'specters-darwin-x64',
  },
  'darwin-arm64': {
    local: './specter.darwin-arm64.node',
    package: 'specters-darwin-arm64',
  },
  'linux-x64-gnu': {
    local: './specter.linux-x64-gnu.node',
    package: 'specters-linux-x64-gnu',
  },
  'linux-arm64-gnu': {
    local: './specter.linux-arm64-gnu.node',
    package: 'specters-linux-arm64-gnu',
  },
};

function isMusl() {
  if (process.platform !== 'linux') {
    return false;
  }

  const report = typeof process.report?.getReport === 'function'
    ? process.report.getReport()
    : null;

  if (report?.header?.glibcVersionRuntime) {
    return false;
  }

  if (Array.isArray(report?.sharedObjects)) {
    return report.sharedObjects.some((file) => file.includes('libc.musl-') || file.includes('ld-musl-'));
  }

  try {
    return readFileSync('/usr/bin/ldd', 'utf8').includes('musl');
  } catch {
    try {
      return execSync('ldd --version', { encoding: 'utf8' }).includes('musl');
    } catch {
      return false;
    }
  }
}

function targetKey() {
  if (process.platform === 'darwin') {
    return `darwin-${process.arch}`;
  }

  if (process.platform === 'linux') {
    return `linux-${process.arch}-${isMusl() ? 'musl' : 'gnu'}`;
  }

  return `${process.platform}-${process.arch}`;
}

function versionCheck(packageName) {
  if (!process.env.NAPI_RS_ENFORCE_VERSION_CHECK || process.env.NAPI_RS_ENFORCE_VERSION_CHECK === '0') {
    return;
  }

  const packageVersion = require(`${packageName}/package.json`).version;
  if (packageVersion !== PACKAGE_VERSION) {
    throw new Error(
      `Native binding package version mismatch for ${packageName}: expected ${PACKAGE_VERSION}, got ${packageVersion}. ` +
      'Reinstall dependencies to refresh optional native packages.'
    );
  }
}

function loadNativeBinding() {
  const loadErrors = [];

  if (process.env.NAPI_RS_NATIVE_LIBRARY_PATH) {
    try {
      return require(process.env.NAPI_RS_NATIVE_LIBRARY_PATH);
    } catch (error) {
      loadErrors.push(error);
    }
  }

  const key = targetKey();
  const target = targets[key];

  if (!target) {
    throw new Error(
      `Unsupported Specter native target: ${key}. ` +
      `Supported targets: ${Object.keys(targets).join(', ')}.`
    );
  }

  try {
    return require(target.local);
  } catch (error) {
    loadErrors.push(error);
  }

  try {
    versionCheck(target.package);
    return require(target.package);
  } catch (error) {
    loadErrors.push(error);
  }

  throw new Error(
    `Failed to load Specter native binding for ${key}. ` +
    `Expected optional package "${target.package}" or local binary "${target.local}".\n` +
    loadErrors.map((error) => `- ${error.message}`).join('\n')
  );
}

const binding = loadNativeBinding();

module.exports.Client = binding.Client;
module.exports.ClientBuilder = binding.ClientBuilder;
module.exports.RequestBuilder = binding.RequestBuilder;
module.exports.Response = binding.Response;
module.exports.CookieJar = binding.CookieJar;
module.exports.FingerprintProfile = binding.FingerprintProfile;
module.exports.HttpVersion = binding.HttpVersion;
module.exports.Timeouts = binding.Timeouts;
module.exports.clientBuilder = binding.clientBuilder;
module.exports.timeoutsApiDefaults = binding.timeoutsApiDefaults;
module.exports.timeoutsStreamingDefaults = binding.timeoutsStreamingDefaults;
