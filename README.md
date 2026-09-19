# jolt-lang/http-client

HTTP for [Jolt](https://github.com/jolt-lang/jolt): the JVM networking APIs that
Clojure HTTP clients are written against, supplied as Jolt host shims over BSD
sockets and OpenSSL through `jolt.ffi`. Jolt has no JVM, so none of
`java.net.URL`, `java.net.http.HttpClient` or `javax.net.ssl` exists until this
library installs them — the same approach
[jolt-lang/router](https://github.com/jolt-lang/router) uses for reitit.

Two clients run on it unmodified:

```clojure
;; clj-http-lite, re-exported as jolt.http-client
(require '[jolt.http-client :as http])
(http/get "https://example.com")
(http/post "https://example.com/x" {:body "{\"a\":1}" :content-type :json})

;; babashka.http-client, straight from Maven
(require '[jolt.http.platform])            ;; installs the shims
(require '[babashka.http-client :as bb])
(bb/get "https://example.com" {:query-params {"q" "jolt"}})
(bb/post "https://example.com/upload" {:multipart [{:name "f" :content (io/file "x")}]})
(bb/get "https://example.com" {:async true})
```

An app that only reaches for the classes gets them without any require of ours:
`deps.edn` declares them under `:jolt/provides` (RFC 0014), so jolt autoloads the
namespace that installs them. That is also what makes a client compiled from a
jar work — a dependency namespace resolves its class references before any
require of ours could run.

## What it provides

| JVM API | Jolt shim |
| --- | --- |
| `java.net.URL`, `HttpURLConnection` | hand-rolled HTTP/1.1 over BSD sockets via `jolt.ffi` (`jolt.http.core` / `jolt.http.platform`) |
| `java.net.http.HttpClient` (JDK 11+) | `jolt.http.jdk` — client/request/response builders, `BodyPublishers`/`BodyHandlers`, `HttpHeaders`, over the same transport |
| `java.util.concurrent.CompletableFuture` | a real callback-driven future: `sendAsync` runs on jolt's future pool, `thenApply`/`exceptionally`/`thenCompose` chain off it, `@` derefs |
| `java.net.http.WebSocket` | `jolt.http.websocket` — RFC 6455 client (handshake, frame codec, listener callbacks) |
| `java.net.ProxySelector`, `Proxy`, `CookieManager`, `Authenticator` | real routing, not just constructors — see below |
| `javax.net.ssl` (`SSLContext`, `SSLParameters`, trust managers, `KeyStore`) | the system **OpenSSL** via `jolt.ffi`, memory-BIO TLS over the socket (`jolt.http.tls`), including PKCS#12 key and trust stores |
| `java.io` byte streams, `java.io.SequenceInputStream` | jolt's own streams where it has them, shims where it does not |

`java.util.zip` (gzip, deflate, raw deflate) is jolt's own, on the zlib every
jolt binary links. The native libraries (libc sockets, OpenSSL) are declared in `deps.edn`
under `:jolt/native`; jolt loads them before the namespaces are required.

## Client options

Everything `babashka.http-client`'s `client` accepts is honoured at send time,
not merely stored:

- **`:proxy`** — a map, or a function of the request URI, or a `ProxySelector`.
  Plain http goes through the proxy as an absolute-form request line; https
  tunnels with `CONNECT` and runs the TLS handshake inside the tunnel, so the
  proxy never sees plaintext.
- **`:cookie-handler`** — `:accept-all` / `:accept-none` / `:original-server`
  (RFC 6265 domain matching). Cookies are stored from `Set-Cookie` and sent back
  on later requests through the same client.
- **`:ssl-context`** — `{:insecure true}` to accept any certificate, or
  `:key-store` / `:trust-store` PKCS#12 files with their passwords. A trust store
  replaces the platform CA set, the way a `TrustManagerFactory` over a truststore
  does on the JVM.
- **`:authenticator`** — `{:user … :pass …}` answers a `401` by retrying once with
  Basic credentials.
- **`:follow-redirects`** — `:never` / `:normal` / `:always`, with `:normal`
  refusing an https→http downgrade like `java.net.http`.
- **`:connect-timeout`**, and per-request `:timeout`, which bounds the exchange
  up to the response. It does not cut a body that is already arriving, the same
  as `HttpRequest.timeout` on the JVM — see `:as :stream` below.

Not emulated: HTTP/2 (`:version :http2` is accepted and the exchange is
HTTP/1.1), request `:priority`, and a caller-supplied `:executor` — the async
send runs on jolt's own future pool. Each is recorded on the client and read
back, so a caller that sets and inspects one sees what it set. WebSocket
negotiates no extensions, so no `permessage-deflate`.

`:as :stream` (`BodyHandlers/ofInputStream`) is live **on jolt 0.8.8 and up**:
the response comes back as soon as the headers are in and the body is pulled off the socket as it is read,
so an SSE feed, an LLM token stream or a log tail works. The stream is framed by
the response — `Content-Length`, chunked, or the peer's close — so it ends where
the body ends. `slurp`, `io/copy`, `io/reader` and `mark`/`reset` all work on it.

What bounds a streamed body is inactivity, not total duration. On the
`clj-http-lite` side that is still the socket read timeout (`:socket-timeout`,
between reads). On the `babashka.http-client` side it is nothing at all by
default: `HttpRequest.timeout` is cancelled once the response headers arrive,
exactly as `java.net.http` behaves, so a body read that outlives it blocks on
rather than being cut (#26). For a hard total cap,
`jolt.http.platform/set-max-response-ms!` still applies to every response,
streamed or not.

The live stream is a reify `java.io.InputStream`, which needs the abstract-class
method inheritance jolt gained in 0.8.8. Below that — the declared floor is
0.8.1 — the transport probes for one, does not find it, and keeps reading bodies
to completion, so `:as :stream` is a stream over a finished body as it was
before. CI runs both.

Two things to know. The connection belongs to the stream until the body is read
to its end or the stream is closed, so a caller that abandons a stream should
`.close` it. And `line-seq` reads its reader to the end on jolt today, so read a
live stream with `.readLine` on a `BufferedReader` rather than through
`line-seq` until jolt's own `line-seq` is lazy.

Restricted request headers behave as `java.net.http` does: setting
`content-length`, `connection`, `host`, `upgrade` or `expect` on a request is an
`IllegalArgumentException`, because the client owns them.

## Connections

Connections are pooled and reused per origin. HTTP/1.1 is persistent by default,
so a request carries no `Connection: close` and the socket goes back to the pool
when the response framed itself with `Content-Length` or chunked encoding and the
server did not ask to close. Reuse is what makes a second request to the same
host cost a round trip instead of a connect plus, for https, a full TLS
handshake: ten sequential `https://example.com` GETs measured 308 ms pooled
against 1184 ms without.

A peer can retire a pooled connection between requests and nothing can rule that
out in advance. Two things cover it: a socket the peer has already closed is
detected and dropped before it is used, and a reused connection that answers with
no bytes at all is retried once on a fresh one — a peer that never sent a byte
never acted on the request, so even a `POST` is safe to retry there.

The knobs live in `jolt.http.core`, and apply process-wide:

```clojure
(reset! jolt.http.core/pool-enabled? false)   ;; one connection per request
(reset! jolt.http.core/pool-idle-ms 5000)     ;; how long an idle connection is kept
(reset! jolt.http.core/pool-max-per-key 8)    ;; idle connections kept per origin
(jolt.http.core/pool-clear!)                  ;; close and forget everything pooled
```

TLS contexts are shared too: an `SSL_CTX` is cached per client configuration
rather than built per request, which matters because a verifying one loads the
platform CA bundle (5.7 ms against 0.09 ms for `:insecure true`).

## Timeouts

`:conn-timeout` and `:socket-timeout` are milliseconds, and both are off unless
you pass them.

```clojure
(http/get "https://example.com" {:conn-timeout 2000 :socket-timeout 10000})
```

`:conn-timeout` bounds each connect attempt, the way `java.net.Socket`'s does —
a name resolving to a dead address and a live one still connects, and the dead
one costs at most the timeout instead of the kernel's SYN retry window (~75s on
macOS, ~130s on Linux). `:socket-timeout` bounds each individual read.

Neither bounds a peer that keeps trickling bytes: every read beats the read
timeout, so the response never ends. `(jolt.http.platform/set-max-response-ms!
ms)` caps the total wall-clock time of a response body across all reads. It
applies process-wide, and is nil (uncapped) by default. A per-request
`:timeout` on the `babashka.http-client` side does not do this: like
`HttpRequest.timeout`, it is cancelled once the response headers arrive and
leaves an arriving body alone.

## Requirements

- jolt 0.8.9 or newer, declared as `:jolt/min-version`. 0.8.9 is where
  `java.util.zip` entered the runtime, on the zlib every jolt binary links;
  this library's gzip and deflate decoding runs on those classes and no
  longer ships a libz shim of its own. (The earlier floor, 0.8.1, was
  `java.util.concurrent`'s executor interfaces, which
  `babashka.http-client`'s `->Executor` needs.)
- OpenSSL (`libssl`/`libcrypto`) for https.

## Namespaces

| | |
| --- | --- |
| `jolt.http-client` | the public clj-http-lite API |
| `jolt.http.core` | the HTTP/1.1 engine: transport, URL parser, request/response codec — shared, so the two client surfaces cannot drift |
| `jolt.http.net` | BSD sockets over `jolt.ffi` |
| `jolt.http.tls` | OpenSSL, including PKCS#12 stores and `CONNECT`-tunnel wrapping |
| `jolt.http.platform` | `java.net.URL` / `HttpURLConnection` / byte streams / `java.util.zip`; requiring it installs everything |
| `jolt.http.jdk` | `java.net.http` and the `java.net` / `javax.net.ssl` classes around it |
| `jolt.http.websocket` | RFC 6455 |

## Tests

Six suites, each its own process — they bind their own ports and stand up their
own servers. CI runs all of them except `:timeouttest`.

```
jolt -M:test          # the HTTP/1.1 engine itself (jolt.http.core-test: URL
                      # parsing, RFC 3986 reference resolution, request
                      # serialisation, response framing, connection reuse), plus
                      # clj-http-lite's own client, links and integration suites,
                      # vendored under test/clj_http/lite, with in-process
                      # plaintext + TLS servers in place of the Jetty subprocess
jolt -M:bhctest       # babashka.http-client, unmodified from Maven, over the
                      # java.net.http shim — request/response surface,
                      # interceptors, :async, multipart, proxy, cookies, auth
jolt -M:wstest        # RFC 6455: the frame codec both directions, plus
                      # babashka.http-client.websocket against an echo server
jolt -M:tlstest       # ssl-context, PKCS#12 key/trust stores, CONNECT
                      # tunnelling, wss — the server is self-signed, so the
                      # default client must refuse it
jolt -M:timeouttest   # timeout/deadline regressions; stalls connections on
                      # purpose. One case loads jolt.nrepl in a subprocess and
                      # fetches https://example.com, so it needs network egress.
```

Values the suites assert on — the bytes `java.net.http` puts on the wire, what
`java.net.URL`/`URI` getters return, what `java.net.URI/resolve` makes of a
relative `Location`, which request headers the JDK refuses, and when a cookie is
withheld — were measured against a real JDK rather than recalled.

The `:bhctest` multipart case parses the body the client built with
[jolt-lang/multipart](https://github.com/jolt-lang/multipart), so it asserts on
the parts rather than on a byte blob.
