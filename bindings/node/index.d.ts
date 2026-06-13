/**
 * Warpsock - Node.js bindings for the Warpsock HTTP client.
 *
 * Public Node.js binding surface.
 */

/** gRPC per-stream message encoding negotiated via the `grpc-encoding` header. */
export enum GrpcEncoding {
  /** No compression. */
  Identity = 0,
  /** gzip compression. */
  Gzip = 1,
}

/**
 * Frame a single gRPC message: prepend the compression flag and big-endian
 * length, gzip-compressing the payload when `compress` is set and `encoding`
 * is `Gzip`.
 */
export function encodeMessage(
  payload: Buffer,
  compress: boolean,
  encoding: GrpcEncoding,
): Buffer;

/**
 * Incremental decoder for gRPC length-prefixed messages. Push raw body chunks
 * with `push`, then call `nextMessage` repeatedly until it returns null to
 * drain every fully-available message.
 */
export class GrpcFramer {
  constructor(encoding: GrpcEncoding);
  /** The negotiated stream encoding. */
  get encoding(): GrpcEncoding;
  /** Append an incoming body chunk. */
  push(chunk: Buffer): void;
  /** Next fully-available message payload, or null if more bytes are needed. */
  nextMessage(): Buffer | null;
}

/** HTTP version preference. */
export enum HttpVersion {
  Http1_1 = 0,
  Http2 = 1,
  Http3 = 2,
  Http3Only = 3,
  Auto = 4,
}

/** Browser fingerprint profiles for impersonation. */
export enum FingerprintProfile {
  Chrome142 = 0,
  Chrome143 = 1,
  Chrome144 = 2,
  Chrome145 = 3,
  Chrome146 = 4,
  Chrome147 = 5,
  Chrome148 = 6,
  Firefox133 = 7,
  None = 8,
  Firefox134 = 9,
  Firefox135 = 10,
  Firefox136 = 11,
  Firefox137 = 12,
  Firefox138 = 13,
  Firefox139 = 14,
  Firefox140 = 15,
  Firefox141 = 16,
  Firefox142 = 17,
  Firefox143 = 18,
  Firefox144 = 19,
  Firefox145 = 20,
  Firefox146 = 21,
  Firefox147 = 22,
  Firefox148 = 23,
  Firefox149 = 24,
  Firefox150 = 25,
  Firefox151 = 26,
  FirefoxEsr115 = 27,
  FirefoxEsr128 = 28,
  FirefoxEsr140 = 29,
}

export interface Timeouts {
  connect?: number;
  ttfb?: number;
  readIdle?: number;
  writeIdle?: number;
  total?: number;
  poolAcquire?: number;
}

export function clientBuilder(): ClientBuilder;
export function timeoutsApiDefaults(): Timeouts;
export function timeoutsStreamingDefaults(): Timeouts;

export class CookieJar {
  constructor();
  length(): number;
  isEmpty(): boolean;
}

export class ClientBuilder {
  fingerprint(profile: FingerprintProfile): ClientBuilder;
  preferHttp2(prefer: boolean): ClientBuilder;
  http2PriorKnowledge(enabled: boolean): ClientBuilder;
  cookieStore(enabled: boolean): ClientBuilder;
  cookieJar(jar: CookieJar): ClientBuilder;
  h3Upgrade(enabled: boolean): ClientBuilder;
  timeouts(timeouts: Timeouts): ClientBuilder;
  apiTimeouts(): ClientBuilder;
  streamingTimeouts(): ClientBuilder;
  totalTimeout(timeoutSecs: number): ClientBuilder;
  connectTimeout(timeoutSecs: number): ClientBuilder;
  ttfbTimeout(timeoutSecs: number): ClientBuilder;
  readTimeout(timeoutSecs: number): ClientBuilder;
  dangerAcceptInvalidCerts(accept: boolean): ClientBuilder;
  localhostAllowsInvalidCerts(allow: boolean): ClientBuilder;
  withPlatformRoots(enabled: boolean): ClientBuilder;
  hickoryDns(enable: boolean): ClientBuilder;
  dnsCacheTtl(ttlSecs: number): ClientBuilder;
  httpTlsEarlyData(enabled: boolean): ClientBuilder;
  build(): Client;
}

export class Client {
  get(url: string): RequestBuilder;
  post(url: string): RequestBuilder;
  put(url: string): RequestBuilder;
  delete(url: string): RequestBuilder;
  patch(url: string): RequestBuilder;
  head(url: string): RequestBuilder;
  options(url: string): RequestBuilder;
  request(method: string, url: string): RequestBuilder;
  grpcRequest(url: string, encoding: GrpcEncoding): RequestBuilder;
}

export class RequestBuilder {
  header(key: string, value: string): RequestBuilder;
  headers(headers: string[][]): RequestBuilder;
  headersList(): string[][];
  readonly method: string;
  version(version: HttpVersion): RequestBuilder;
  body(body: Buffer | Uint8Array): RequestBuilder;
  json(jsonStr: string): RequestBuilder;
  form(formStr: string): RequestBuilder;
  bodyStream(asyncIterable: AsyncIterable<Buffer | Uint8Array>): RequestBuilder;
  send(): Promise<Response>;
}

export class Response {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly httpVersion: string;
  readonly effectiveUrl: string | null;
  readonly isSuccess: boolean;
  readonly isRedirect: boolean;
  readonly redirectUrl: string | null;
  readonly contentType: string | null;
  readonly body: AsyncIterable<Buffer>;
  headersList(): string[][];
  getHeader(name: string): string | null;
  text(): string;
  bytes(): Buffer;
  json(): string;
  nextBodyChunk(): Promise<Buffer | null>;
  trailers(): Promise<Record<string, string> | null>;
}

/**
 * gRPC additions to the request/response surface.
 *
 * `Client.grpcRequest` presets a POST with the gRPC headers in wire order
 * (`content-type: application/grpc+proto`, `te: trailers`, and `grpc-encoding:
 * gzip` only for Gzip), composing with the existing `.body()` / `.send()` path.
 * `Response.trailers` awaits HTTP/2 trailers (e.g. `grpc-status`).
 */
export interface GrpcClient {
  /** Build a gRPC unary/streaming POST request with the gRPC headers preset. */
  grpcRequest(url: string, encoding: GrpcEncoding): GrpcRequestBuilder;
}

export interface GrpcRequestBuilder {
  /** Set the request body as framed gRPC message bytes. */
  body(body: Buffer): GrpcRequestBuilder;
  /** Send the request and resolve with the response. */
  send(): Promise<GrpcResponse>;
  /** Staged headers as [key, value] pairs in wire (insertion) order. */
  headersList(): Array<Array<string>>;
  /** The HTTP method for this request. */
  get method(): string;
}

export interface GrpcResponse {
  /**
   * Await HTTP/2 response trailers (e.g. gRPC `grpc-status` / `grpc-message`).
   * Resolves with an object of header pairs when present, or null when the
   * stream ended cleanly without trailers; rejects when the stream was reset.
   */
  trailers(): Promise<Record<string, string> | null>;
}
