# Autobahn TestSuite conformance artifacts

Opt-in RFC 6455 / RFC 7692 conformance proof for the Warpsock WebSocket client,
using the industry-standard `crossbario/autobahn-testsuite` fuzzingserver (the
same suite fastwebsockets and tungstenite publish against).

## Run

```
just autobahn        # requires Docker; not part of `just test`
```

The recipe runs `scripts/autobahn.sh`, which builds the `autobahn_echo` example
(a client-mode echo driver on the public WebSocket API), starts the
fuzzingserver on `ws://127.0.0.1:9001`, runs every case, calls `updateReports`,
and copies the report (`index.json` + `summary.txt` + per-case HTML/JSON) into
`docs/benchmarks/autobahn/<YYYY-MM-DD>/`.

## Gate

The harness asserts **zero cases graded `FAILED`** (exit 1 otherwise).
`OK`, `NON-STRICT`, `INFORMATIONAL`, and `UNIMPLEMENTED` are allowed. The echo
driver does not request permessage-deflate, so RFC 7692 compression cases
(12.x/13.x) report `UNIMPLEMENTED`, which is permitted. Exit code 2 means Docker
was unavailable.
