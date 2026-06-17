# Runs clj-http-lite's own test suite under Jolt.
#
# clj-http-lite's integration tests spin up a Jetty server in a subprocess
# (clj-http.lite.test-util.server-process/launch). Jolt has no JVM, so this
# driver starts in-process servers (spork/http for plaintext, an OpenSSL-wrapped
# net server for https) serving the same routes, then redefines server-process to
# point the tests at them. The unit tests (client/links) need no server.
#
# Usage:  JOLT_REPO=<jolt> janet test/run-suite.janet
# Paths are resolved relative to this http-client repo and a sibling clj-http-lite
# checkout (override with CLJ_HTTP_LITE).

(import spork/http :as http)

(def repo (os/cwd))
(def jolt-repo (os/getenv "JOLT_REPO" "../jolt"))
(def lib (os/getenv "CLJ_HTTP_LITE" "../../clj-http-lite"))
(def cert (string repo "/test/resources/cert.pem"))
(def key (string repo "/test/resources/key.pem"))
(def http-port 18091)
(def https-port 18092)

# Make jolt importable from the checkout: point :syspath at a temp dir symlinking
# jolt/src/jolt -> <link-dir>/jolt (spork is already imported above from the
# default syspath). cwd must be the jolt repo root at import time — stdlib_embed
# reads sources relative to it.
(def cwd0 (os/cwd))
(def link-dir (string (os/getenv "TMPDIR" "/tmp") "/jolt-runsuite-syspath"))
(os/mkdir link-dir)
(def jolt-link (string link-dir "/jolt"))
(protect (os/rm jolt-link))
(protect (os/symlink (string jolt-repo "/src/jolt") jolt-link))
(setdyn :syspath link-dir)
(os/cd jolt-repo)
(import jolt/api :as api)
(os/cd cwd0)

(def c (api/init {:compile? true
                  :paths [(string repo "/src")
                          (string lib "/src")
                          (string lib "/test")]}))

# install the platform host shims (HttpURLConnection / URL / streams / TLS / gzip)
(api/eval-string c "(require '[jolt.http.platform])")

# --- routes (mirror clj-http.lite.test-util.http-server) --------------------
(def CREDS "Basic dXNlcm5hbWU6cGFzc3dvcmQ=")   # base64 username:password

(defn route [req]
  (def method (string/ascii-lower (req :method)))
  (def path (get req :route (req :path)))
  (def resp
    (cond
      (and (= method "get") (= path "/get")) {:status 200 :body "get"}
      (and (= method "head") (= path "/head")) {:status 200 :body ""}
      (and (= method "get") (= path "/content-type")) {:status 200 :body (or (get (req :headers) "content-type") "")}
      (and (= method "get") (= path "/header")) {:status 200 :body (or (get (req :headers) "x-my-header") "")}
      (and (= method "post") (= path "/post")) {:status 200 :body (string (or (http/read-body req) ""))}
      (and (= method "get") (= path "/redirect")) {:status 302 :body "" :headers {"Location" "/get"}}
      (and (= method "get") (= path "/error")) {:status 500 :body "o noes"}
      (and (= method "get") (= path "/timeout")) (do (ev/sleep 0.1) {:status 200 :body "timeout"})
      (and (= method "delete") (= path "/delete-with-body")) {:status 200 :body "delete-with-body"}
      (and (= method "get") (= path "/basic-auth"))
        (if (= CREDS (get (req :headers) "authorization"))
          {:status 200 :body "welcome"} {:status 401 :body "denied"})
      {:status 404 :body "not found"}))
  (def headers (merge {"Date" "Mon, 01 Jan 2026 00:00:00 GMT"} (or (get resp :headers) {})))
  (merge resp {:headers headers}))

# --- plaintext server ------------------------------------------------------
(http/server route "localhost" http-port)

# --- TLS server (OpenSSL-wrapped accepted connections) ---------------------
(api/eval-string c "(require '[jolt.http.tls :as tls])")
(def tls-wrap (api/eval-string c "jolt.http.tls/tls-wrap-server"))
(net/server "localhost" (string https-port)
  (fn [conn]
    # a client that rejects our self-signed cert aborts mid-handshake; that's an
    # expected case for the self-signed-ssl-get test, so swallow handler errors
    (try
      (let [tconn (tls-wrap conn cert key)]
        (http/server-handler tconn route))
      ([_] (protect (:close conn))))))

# Point the library's server-process fixture at our in-process servers. Each
# form is a SEPARATE eval so the in-ns takes effect before the defns compile.
(defn redef-server-process! []
  (api/eval-string c "(require '[clj-http.lite.test-util.server-process])")
  (api/eval-string c "(in-ns 'clj-http.lite.test-util.server-process)")
  (api/eval-string c (string "(defn launch [] {:http-port " http-port " :https-port " https-port "})"))
  (api/eval-string c "(defn kill [_] nil)")
  (api/eval-string c "(in-ns 'user)"))

# --- run ------------------------------------------------------------------
# deftest registers at load; run-tests runs the whole registry once (with the
# integration suite's :once with-server fixture wrapping everything).
(ev/spawn
  (ev/sleep 0.3)
  (api/eval-string c "(require '[clojure.test]) (clojure.test/reset-report!)")
  # Redirect server-process BEFORE integration-test is required, so its
  # (compiled, direct-linked) with-server binds our launch, not the JVM one.
  (redef-server-process!)
  (each ns ["clj-http.lite.links-test" "clj-http.lite.client-test" "clj-http.lite.integration-test"]
    (try (api/eval-string c (string "(require '[" ns "])"))
         ([e] (printf "%s LOAD ERROR: %s" ns e))))
  (def r (api/eval-string c "(clojure.test/run-tests)"))
  (printf "\n========== TOTAL ==========")
  (printf "tests=%d pass=%d fail=%d error=%d" (r :test) (r :pass) (r :fail) (r :error))
  (os/exit (if (and (= 0 (r :fail)) (= 0 (r :error))) 0 1)))

(ev/sleep 60)
(print "TIMED OUT")
(os/exit 2)
