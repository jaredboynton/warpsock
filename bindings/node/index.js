/**
 * Specter - Node.js bindings for the Specter HTTP client.
 *
 * A high-performance async HTTP client with full TLS, HTTP/2, and HTTP/3
 * fingerprint control for browser impersonation.
 */

const { execSync } = require('node:child_process');
const { readFileSync } = require('node:fs');

const PACKAGE_VERSION = '4.2.0';

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
module.exports.BodyStreamBridge = binding.BodyStreamBridge;
module.exports.CookieJar = binding.CookieJar;
module.exports.WebSocketBuilder = binding.WebSocketBuilder;
module.exports.WebSocket = binding.WebSocket;
module.exports.WebSocketH2Builder = binding.WebSocketH2Builder;
module.exports.WebSocketH2Tunnel = binding.WebSocketH2Tunnel;
module.exports.WebSocketH3Builder = binding.WebSocketH3Builder;
module.exports.WebSocketH3Tunnel = binding.WebSocketH3Tunnel;
module.exports.WebSocketCloseFrame = binding.WebSocketCloseFrame;
module.exports.FingerprintProfile = binding.FingerprintProfile;
module.exports.HttpVersion = binding.HttpVersion;
module.exports.Timeouts = binding.Timeouts;
module.exports.CLOSE_NORMAL = binding.CLOSE_NORMAL;
module.exports.CLOSE_GOING_AWAY = binding.CLOSE_GOING_AWAY;
module.exports.CLOSE_PROTOCOL_ERROR = binding.CLOSE_PROTOCOL_ERROR;
module.exports.CLOSE_UNSUPPORTED = binding.CLOSE_UNSUPPORTED;
module.exports.CLOSE_NO_STATUS = binding.CLOSE_NO_STATUS;
module.exports.CLOSE_ABNORMAL = binding.CLOSE_ABNORMAL;
module.exports.CLOSE_INVALID_PAYLOAD = binding.CLOSE_INVALID_PAYLOAD;
module.exports.CLOSE_POLICY_VIOLATION = binding.CLOSE_POLICY_VIOLATION;
module.exports.CLOSE_MESSAGE_TOO_BIG = binding.CLOSE_MESSAGE_TOO_BIG;
module.exports.CLOSE_MANDATORY_EXTENSION = binding.CLOSE_MANDATORY_EXTENSION;
module.exports.CLOSE_INTERNAL_ERROR = binding.CLOSE_INTERNAL_ERROR;
module.exports.CLOSE_TLS_ERROR = binding.CLOSE_TLS_ERROR;
module.exports.isValidCloseCode = binding.isValidCloseCode;
module.exports.clientBuilder = binding.clientBuilder;
module.exports.timeoutsApiDefaults = binding.timeoutsApiDefaults;
module.exports.timeoutsStreamingDefaults = binding.timeoutsStreamingDefaults;
module.exports.GrpcEncoding = binding.GrpcEncoding;
module.exports.GrpcFramer = binding.GrpcFramer;
module.exports.encodeMessage = binding.encodeMessage;

const requestBuilderSend = binding.RequestBuilder.prototype.send;
const requestBuilderBodyStreamBridge = binding.RequestBuilder.prototype.bodyStreamBridge;

binding.RequestBuilder.prototype.bodyStream = function bodyStream(asyncIterable) {
  if (!asyncIterable || typeof asyncIterable[Symbol.asyncIterator] !== 'function') {
    throw new TypeError('bodyStream expects an AsyncIterable<Buffer | Uint8Array>');
  }

  const bridge = new binding.BodyStreamBridge();
  requestBuilderBodyStreamBridge.call(this, bridge);
  Object.defineProperty(this, '__specterBodyStream', {
    value: { asyncIterable, bridge },
    configurable: true,
  });
  return this;
};

binding.RequestBuilder.prototype.send = function send() {
  const streamState = this.__specterBodyStream;
  if (!streamState) {
    return requestBuilderSend.call(this);
  }

  const pump = (async () => {
    try {
      for await (const chunk of streamState.asyncIterable) {
        if (chunk == null) {
          throw new TypeError('bodyStream chunks must be Buffer or Uint8Array values');
        }
        await streamState.bridge.write(Buffer.from(chunk));
      }
      streamState.bridge.close();
    } catch (error) {
      await streamState.bridge.fail(error?.message || String(error));
    }
  })();

  pump.catch(() => {});
  return requestBuilderSend.call(this).finally(() => {
    streamState.bridge.close();
  });
};

Object.defineProperty(binding.Response.prototype, 'body', {
  configurable: true,
  enumerable: true,
  get() {
    const response = this;
    return {
      [Symbol.asyncIterator]() {
        return {
          async next() {
            const chunk = await response.nextBodyChunk();
            if (chunk === null || chunk === undefined) {
              return { done: true, value: undefined };
            }
            return { done: false, value: chunk };
          },
        };
      },
    };
  },
});
