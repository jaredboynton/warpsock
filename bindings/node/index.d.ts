export enum FingerprintProfile {
  Chrome142,
  Chrome143,
  Chrome144,
  Chrome145,
  Chrome146,
  Chrome147,
  Chrome148,
  Firefox133,
  None,
  Firefox134,
  Firefox135,
  Firefox136,
  Firefox137,
  Firefox138,
  Firefox139,
  Firefox140,
  Firefox141,
  Firefox142,
  Firefox143,
  Firefox144,
  Firefox145,
  Firefox146,
  Firefox147,
  Firefox148,
  Firefox149,
  Firefox150,
  Firefox151,
  FirefoxEsr115,
  FirefoxEsr128,
  FirefoxEsr140,
}

export enum HttpVersion {
  Http1_1,
  Http2,
  Http3,
  Http3Only,
  Auto,
}

export interface Timeouts {
  connect?: number;
  ttfb?: number;
  readIdle?: number;
  writeIdle?: number;
  total?: number;
  poolAcquire?: number;
}

export interface WebSocketMessage {
  type: 'text' | 'binary' | 'ping' | 'pong' | 'close';
  text?: string;
  data?: Buffer;
  code?: number;
  reason?: string;
}

export interface WebSocketCloseFrame {
  code?: number;
  reason?: string;
}

export interface H2TunnelEvent {
  type: 'data' | 'endStream' | 'reset' | 'goAway';
  data?: Buffer;
  reason?: string;
  lastStreamId?: number;
}

export interface H3TunnelEvent {
  type: 'data' | 'endStream' | 'reset' | 'goAway';
  data?: Buffer;
  reason?: string;
  lastStreamId?: bigint;
}

export class RequestBuilder {
  header(key: string, value: string): this;
  headers(headers: string[][]): this;
  version(version: HttpVersion): this;
  body(body: Buffer): this;
  bodyStream(body: AsyncIterable<Buffer | Uint8Array>): this;
  json(jsonStr: string): this;
  form(formStr: string): this;
  send(): Promise<Response>;
}

export class Response {
  get status(): number;
  get headers(): Record<string, string>;
  get body(): AsyncIterable<Buffer>;
  headersList(): string[][];
  getHeader(name: string): string | null;
  text(): string;
  bytes(): Buffer;
  json(): string;
  get httpVersion(): string;
  get effectiveUrl(): string | null;
  get isSuccess(): boolean;
  get isRedirect(): boolean;
  get redirectUrl(): string | null;
  get contentType(): string | null;
}

export class ClientBuilder {
  fingerprint(profile: FingerprintProfile): this;
  preferHttp2(prefer: boolean): this;
  http2PriorKnowledge(enabled: boolean): this;
  h3Upgrade(enabled: boolean): this;
  cookieStore(enabled: boolean): this;
  cookieJar(jar: CookieJar): this;
  timeouts(timeouts: Timeouts): this;
  apiTimeouts(): this;
  streamingTimeouts(): this;
  totalTimeout(timeoutSecs: number): this;
  connectTimeout(timeoutSecs: number): this;
  ttfbTimeout(timeoutSecs: number): this;
  readTimeout(timeoutSecs: number): this;
  dangerAcceptInvalidCerts(accept: boolean): this;
  localhostAllowsInvalidCerts(allow: boolean): this;
  withPlatformRoots(enabled: boolean): this;
  build(): Client;
}

export class Client {
  websocket(url: string): WebSocketBuilder;
  websocketH2(url: string): WebSocketH2Builder;
  websocketH3(url: string): WebSocketH3Builder;
  get(url: string): RequestBuilder;
  post(url: string): RequestBuilder;
  put(url: string): RequestBuilder;
  delete(url: string): RequestBuilder;
  patch(url: string): RequestBuilder;
  head(url: string): RequestBuilder;
  options(url: string): RequestBuilder;
  request(method: string, url: string): RequestBuilder;
}

export class CookieJar {
  constructor();
  get length(): number;
  get isEmpty(): boolean;
}

export class WebSocketBuilder {
  header(key: string, value: string): this;
  headers(headers: Record<string, string>): this;
  subprotocol(value: string): this;
  subprotocols(values: string[]): this;
  maxMessageSize(bytes: number): this;
  maxFrameSize(bytes: number): this;
  connectTimeout(timeoutSecs: number): this;
  handshakeTimeout(timeoutSecs: number): this;
  readTimeout(timeoutSecs: number): this;
  writeTimeout(timeoutSecs: number): this;
  connect(): Promise<WebSocket>;
}

export class WebSocket {
  get url(): string;
  get protocol(): string | null;
  send(message: WebSocketMessage): Promise<void>;
  sendText(text: string): Promise<void>;
  sendBinary(data: Buffer): Promise<void>;
  sendPing(data?: Buffer): Promise<void>;
  sendPong(data?: Buffer): Promise<void>;
  next(): Promise<WebSocketMessage>;
  close(frame?: WebSocketCloseFrame): Promise<void>;
}

export class WebSocketH2Builder {
  header(key: string, value: string): this;
  headers(headers: string[][]): this;
  subprotocol(value: string): this;
  connectTimeout(timeoutSecs: number): this;
  readTimeout(timeoutSecs: number): this;
  writeTimeout(timeoutSecs: number): this;
  connect(): Promise<WebSocketH2Tunnel>;
}

export class WebSocketH2Tunnel {
  sendBytes(data: Buffer, endStream?: boolean): Promise<void>;
  recvBytes(): Promise<Buffer | null>;
  recvEvent(): Promise<H2TunnelEvent | null>;
  closeSend(): Promise<void>;
}

export class WebSocketH3Builder {
  header(key: string, value: string): this;
  headers(headers: string[][]): this;
  subprotocol(value: string): this;
  connectTimeout(timeoutSecs: number): this;
  readTimeout(timeoutSecs: number): this;
  writeTimeout(timeoutSecs: number): this;
  connect(): Promise<WebSocketH3Tunnel>;
}

export class WebSocketH3Tunnel {
  sendBytes(data: Buffer, fin?: boolean): Promise<void>;
  recvBytes(): Promise<Buffer | null>;
  recvEvent(): Promise<H3TunnelEvent | null>;
  closeSend(): Promise<void>;
}

export const CLOSE_NORMAL: number;
export const CLOSE_GOING_AWAY: number;
export const CLOSE_PROTOCOL_ERROR: number;
export const CLOSE_UNSUPPORTED: number;
export const CLOSE_NO_STATUS: number;
export const CLOSE_ABNORMAL: number;
export const CLOSE_INVALID_PAYLOAD: number;
export const CLOSE_POLICY_VIOLATION: number;
export const CLOSE_MESSAGE_TOO_BIG: number;
export const CLOSE_MANDATORY_EXTENSION: number;
export const CLOSE_INTERNAL_ERROR: number;
export const CLOSE_TLS_ERROR: number;

export function isValidCloseCode(code: number): boolean;
export function clientBuilder(): ClientBuilder;
export function timeoutsApiDefaults(): Timeouts;
export function timeoutsStreamingDefaults(): Timeouts;
