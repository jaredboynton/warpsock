"""RFC 8441 fixture note for Python binding tests.

The Python test environment has no HTTP/2 frame library dependency, and the
stdlib does not implement HTTP/2. Keep this lane dependency-free: use the Node
`createH2WebSocketFixture` helper for JS tests, or add a tiny Rust test binary
that starts a loopback h2 prior-knowledge server with ENABLE_CONNECT_PROTOCOL
and echoes DATA frames on accepted `:method = CONNECT`, `:protocol = websocket`
streams.
"""

from __future__ import annotations


RUST_H2_FIXTURE_FALLBACK = {
    "name": "specter-h2-ws-fixture",
    "transport": "h2c prior knowledge on 127.0.0.1:0",
    "accept": {
        ":method": "CONNECT",
        ":protocol": "websocket",
    },
    "behavior": "respond :status 200 and echo DATA frames until either side ends stream",
}


def create_h2_websocket_fixture(*_args: object, **_kwargs: object) -> None:
    raise RuntimeError(
        "Python has no dependency-free HTTP/2 server fixture. "
        "Use the documented Rust fallback in RUST_H2_FIXTURE_FALLBACK."
    )
