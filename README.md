# jolt-lang/http-client

[clj-http-lite](https://github.com/clj-commons/clj-http-lite) running on
[Jolt](https://github.com/jolt-lang/jolt).

clj-http-lite is a small, dependency-light Clojure HTTP client built on the JVM's
`java.net.HttpURLConnection`. Jolt has no JVM, so this library supplies the host
APIs clj-http-lite needs as Jolt host shims — the same approach
[jolt-lang/router](https://github.com/jolt-lang/router) uses for reitit. None of
it lives in jolt core: requiring this library installs the shims at load.

```clojure
(require '[jolt.http-client :as http])

(http/get "https://example.com")
(http/get "https://api.example.com/things" {:query-params {"q" "jolt"} :as :json})
(http/post "https://example.com/x" {:body "{\"a\":1}" :content-type :json})
;; also: head, put, delete, and the lower-level request
```

The functions mirror `clj-http.lite.client` exactly — see its
[docs](https://github.com/clj-commons/clj-http-lite) for the full request/response
map.

## What it provides

| clj-http-lite uses | Jolt shim |
| --- | --- |
| `java.net.URL`, `HttpURLConnection` | hand-rolled HTTP/1.1 client over BSD sockets via `jolt.ffi` (`jolt.http.net` / `jolt.http.platform`) |
| `java.io.ByteArrayInput/OutputStream` | byte-stream tagged-tables wired into `io/copy` / `slurp` |
| `java.util.zip` (gzip/deflate) | the system **libz** via `jolt.ffi` (`jolt.http.zlib`) |
| `javax.net.ssl` (https, `insecure?`) | the system **OpenSSL** via `jolt.ffi`, memory-BIO TLS over the socket (`jolt.http.tls`) |

The native libraries (libc sockets, libz, OpenSSL) are declared in `deps.edn`
under `:jolt/native`; jolt loads them before the namespaces are required.

## Requirements

- System `libz` (always present) and OpenSSL (`libssl`/`libcrypto`) for https.
- A `jolt` build with the library-shim host hooks (`__register-class-methods!` /
  `__register-instance-check!`) and the FFI byte-buffer / charset support this
  library relies on.

## Tests

`joltc -M:test` runs clj-http-lite's own `client`, `links` and `integration`
suites under Jolt. The suites are vendored under `test/clj_http/lite`; their
`server-process` fixture is replaced with in-process plaintext + TLS servers
(`jolt.http.test-server`, over `jolt.ffi` sockets + OpenSSL) in place of the
suite's Jetty subprocess — no external checkout needed.

```
joltc -M:test
```

All 60 tests pass (116 assertions), including the self-signed-cert TLS test and
the gzip/deflate decompression tests.
