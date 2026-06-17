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
| `java.net.URL`, `HttpURLConnection` | hand-rolled HTTP/1.1 client over Janet `net/` sockets (`jolt.http.platform`) |
| `java.io.ByteArrayInput/OutputStream` | byte-stream tables wired into `io/copy` / `slurp` |
| `java.util.zip` (gzip/deflate) | the system **libz** via Janet FFI (`jolt.http.zlib`) |
| `javax.net.ssl` (https, `insecure?`) | the system **OpenSSL** via Janet FFI, memory-BIO so TLS rides the ev loop (`jolt.http.tls`) |

libz and OpenSSL are loaded lazily — nothing native is touched until a request
actually needs gzip or TLS.

## Requirements

- A `jolt` build new enough to expose `__register-instance-check!` and to unwrap
  the throw envelope in compiled `catch` (both landed alongside this library).
- System `libz` (always present) and OpenSSL (`libssl`/`libcrypto`) for https.

## Tests

`test/run-suite.janet` runs clj-http-lite's own `client`, `links` and
`integration` test suites under Jolt, standing up in-process plaintext and TLS
servers in place of the suite's Jetty subprocess:

```
JOLT_REPO=../jolt CLJ_HTTP_LITE=../clj-http-lite janet test/run-suite.janet
```

All of `links-test` and `integration-test` pass (including the self-signed-cert
TLS test); `client-test` passes except one assertion that depends on small-map
*insertion* order, which Jolt (Janet structs, key-sorted) does not preserve.
