(ns jolt.http.timeout-test
  "Regressions for two bugs that were only reachable over https.

  Both were invisible to the existing suite because it exercises the TLS path
  only against a server that answers promptly, in a process where nothing else
  had touched jolt.ffi first."
  (:require [clojure.test :refer [deftest is]]
            [clojure.string :as str]
            [jolt.ffi :as ffi]
            [jolt.process :as p]
            [jolt.http.net :as net]
            [jolt.http.tls :as tls]
            [jolt.http.platform :as platform]
            [jolt.http.test-server :as srv]
            [jolt.http-client :as http]))

;; --- a TLS server that answers the handshake and then goes silent -----------
;; The point is a peer that is reachable and healthy-looking at connect time and
;; then never sends a byte. That is what a wedged model provider looks like, and
;; it is the case a read timeout exists for.

(def ^:private cert (str (System/getProperty "user.dir") "/test/resources/cert.pem"))
(def ^:private key  (str (System/getProperty "user.dir") "/test/resources/key.pem"))

(defn- start-stalling-tls [port]
  (let [fd (srv/listen-socket port)
        running? (atom true)
        held (atom [])]
    (future
      (loop []
        (let [raw (srv/accept-raw fd)]
          (when @running?
            (when-not (neg? raw)
              ;; Complete the handshake, read the request, then hold the
              ;; connection open forever. Keep a reference so nothing closes it.
              (future (try (let [st (tls/tls-wrap-server raw cert key)]
                             ((jolt.host/ref-get st :read) st nil)
                             (swap! held conj st))
                           (catch Throwable _ nil))))
            (recur)))))
    {:fd fd :port port :running running? :held held}))

(deftest https-honours-socket-timeout
  ;; connect-stream dropped read-timeout on the https branch, so SO_RCVTIMEO was
  ;; never applied to the socket underneath OpenSSL and recv parked forever. A
  ;; timed deref cannot preempt a thread inside a blocking FFI call, so this was
  ;; unrecoverable from inside the process rather than merely slow.
  (let [port 18443
        srv (start-stalling-tls port)]
    (try
      (let [t0 (System/currentTimeMillis)
            outcome (try (http/get (str "https://127.0.0.1:" port "/get")
                                   {:insecure? true :socket-timeout 1500})
                         :returned
                         (catch Throwable e (class e)))
            elapsed (- (System/currentTimeMillis) t0)]
        (is (= java.net.SocketTimeoutException outcome)
            "a silent https peer must surface as a read timeout, not park the thread")
        (is (< elapsed 10000)
            (str "should give up near the 1500ms timeout, took " elapsed "ms")))
      (finally (reset! (:running srv) false) (net/close (:fd srv))))))

(deftest plain-http-still-honours-socket-timeout
  (let [port 18080
        srv (srv/start-plain port)]
    (try
      (is (= 200 (:status (http/get (str "http://127.0.0.1:" port "/get")
                                    {:socket-timeout 5000}))))
      (finally (srv/stop srv)))))

;; --- which OpenSSL wins the symbols -----------------------------------------
;; Chez resolves foreign symbols most-recently-loaded-first and defcfn resolves
;; when the def runs, so this can only be tested across a process boundary: the
;; damage is done at namespace-load time. In-process the bindings in jolt.http.tls
;; have already resolved correctly and no amount of later loading disturbs them.
;;
;; jolt.nrepl is the trigger in practice — it calls (ffi/load-library) with no
;; argument at ns load to bind sockets, which loads the running process's own
;; symbols. On macOS the process image transitively links LibreSSL, so without
;; the defensive load in jolt.http.tls the SSL_* symbols come from a mix of two
;; implementations and the first call faults with "invalid memory reference".

(defn- https-in-subprocess [requires]
  ;; p/process takes the command vector first and the options map second.
  (let [expr (str "(require " requires " '[jolt.http-client :as http])"
                  "(println :status (:status (http/get \"https://example.com\""
                  " {:socket-timeout 20000})))")
        proc (p/process ["jolt" "-e" expr] {:out :string :err :string})
        done (deref proc 120000 ::timeout)]
    (if (= ::timeout done)
      (do (try (p/destroy-tree proc) (catch Throwable _ nil))
          {:out "" :err "subprocess timed out"})
      {:exit (:exit done) :out (str (:out done)) :err (str (:err done))})))

(deftest tls-survives-nrepl-loading-first
  (let [{:keys [out err]} (https-in-subprocess "'[jolt.nrepl]")]
    (is (str/includes? out ":status 200")
        (str "https must work with jolt.nrepl loaded before it. out=" out " err=" err))
    (is (not (str/includes? err "invalid memory reference"))
        "an SSL_* symbol mix faults rather than failing cleanly")))

(deftest openssl-is-pinned-not-libressl
  ;; The concrete symptom to guard: macOS resolving to /usr/lib's LibreSSL. Both
  ;; entries must be non-nil, otherwise nothing was loaded and the process's own
  ;; symbols are all that is left.
  (let [{:keys [crypto ssl]} tls/loaded-openssl]
    (is (some? crypto) "libcrypto must be loaded by jolt.http.tls itself")
    (is (some? ssl) "libssl must be loaded by jolt.http.tls itself")))

;; --- a peer that trickles rather than stalls --------------------------------
;; SO_RCVTIMEO bounds inactivity, not total duration, so a peer sending one byte
;; every few seconds resets the read timer forever and the request never
;; returns. Measured before the fix: a 3000ms :socket-timeout against a
;; one-byte-per-second server ran past two minutes and was still going. That
;; leaks a socket and a parked thread per attempt, since nothing unwinds.

(defn- start-trickling-tls [port]
  (let [fd (srv/listen-socket port)
        running? (atom true)]
    (future
      (loop []
        (let [raw (srv/accept-raw fd)]
          (when @running?
            (when-not (neg? raw)
              (future
                (try
                  (let [st (tls/tls-wrap-server raw cert key)
                        write (jolt.host/ref-get st :write)]
                    ((jolt.host/ref-get st :read) st nil)
                    ;; Valid headers promising a body that never finishes...
                    (write st (byte-array (map int "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")))
                    ;; ...then one byte at a time, forever.
                    (while @running?
                      (write st (byte-array [(int \x)]))
                      (Thread/sleep 200)))
                  (catch Throwable _ nil))))
            (recur)))))
    {:fd fd :running running?}))

(deftest a-trickling-peer-is-bounded-by-the-total-deadline
  (let [port 18445
        srv (start-trickling-tls port)]
    (try
      (platform/set-max-response-ms! 4000)
      (let [t0 (System/currentTimeMillis)
            outcome (try (http/get (str "https://127.0.0.1:" port "/")
                                   {:insecure? true :socket-timeout 30000})
                         :returned
                         (catch Throwable e (class e)))
            elapsed (- (System/currentTimeMillis) t0)]
        (is (= java.net.SocketTimeoutException outcome)
            "a peer that keeps the read timer alive must still hit a total bound")
        (is (< elapsed 20000)
            (str "should give up near the 4000ms cap, took " elapsed "ms")))
      (finally
        (platform/set-max-response-ms! nil)
        (reset! (:running srv) false)
        (net/close (:fd srv))))))

(deftest no-cap-by-default
  ;; The historical behaviour is unbounded, and a cap applies process-wide, so a
  ;; library that quietly imposed one would change every consumer.
  (let [port 18446
        srv (srv/start-plain port)]
    (try
      (platform/set-max-response-ms! nil)
      (is (= 200 (:status (http/get (str "http://127.0.0.1:" port "/get")))))
      (finally (srv/stop srv)))))

;; --- :conn-timeout bounds the connect itself ---------------------------------
;; A connect to a blackholed address hangs in kernel SYN retries (~75s on macOS,
;; ~130s on Linux) with no read timeout able to interrupt it. 10.255.255.1 is
;; silently dropped by typical gateways, so before the fix this request parked
;; the thread for minutes; with :conn-timeout the non-blocking connect + poll
;; must give up in about the requested time and surface as a ConnectException.
(deftest conn-timeout-bounds-connect
  (let [t0 (System/currentTimeMillis)
        outcome (try
                  (http/get "http://10.255.255.1:81/" {:conn-timeout 500
                                                        :socket-timeout 1000})
                  :ok
                  (catch Throwable _ :threw))
        elapsed (- (System/currentTimeMillis) t0)]
    (is (= :threw outcome) "a blackholed address must fail rather than return")
    (is (< elapsed 10000)
        (str "connect must give up near the 500ms timeout, took " elapsed "ms"))))

;; getaddrinfo hands back every address for a name and connect walks them until
;; one answers. "localhost" resolves to ::1 and 127.0.0.1 on both macOS and the
;; CI runners, usually ::1 first, and the test server binds AF_INET only — so
;; the first address is refused and the request only works if the walk continues
;; to the second. Setting :conn-timeout puts that walk on the non-blocking
;; connect + poll path, which is the part that has to keep the loop going: a
;; per-address failure means "try the next one", never "give up on the host".
(deftest conn-timeout-still-walks-every-address
  (let [port 18447
        srv (srv/start-plain port)]
    (try
      (is (= 200 (:status (http/get (str "http://localhost:" port "/get")
                                    {:conn-timeout 2000 :socket-timeout 5000})))
          "a refused first address must not abort the whole connect")
      (finally (srv/stop srv)))))

;; --- a peer that resets: recv must not masquerade as a timeout ---------------
;; recv-bytes mapped EVERY negative recv to SocketTimeoutException("Read timed
;; out"). A peer that closes without reading what the client sent makes the
;; kernel answer the next recv with ECONNRESET, and reporting that as a read
;; timeout — with no timeout configured — is exactly what the self-signed-ssl-get
;; flake printed: "expected throw of javax.net.ssl.SSLException but got
;; java.net.SocketTimeoutException". The message misdirects debugging to
;; SO_RCVTIMEO, which was never set.

(defn- start-resetting-server [port]
  (let [fd (srv/listen-socket port)
        running? (atom true)]
    (future
      (loop []
        (let [raw (srv/accept-raw fd)]
          (when @running?
            (when-not (neg? raw)
              ;; give the client's bytes time to queue, then close UNREAD: the
              ;; close carries pending inbound data, so the kernel sends RST
              (future (try (Thread/sleep 100) (net/close raw) (catch Throwable _ nil))))
            (recur)))))
    {:fd fd :running running?}))

(deftest recv-classifies-reset-not-timeout
  (let [port 18448
        srv (start-resetting-server port)]
    (try
      (let [fd (net/connect "127.0.0.1" port nil)]
        (net/send-bytes fd (.getBytes "hello"))
        (let [e (try (net/recv-bytes fd) nil (catch Throwable e e))]
          (is (some? e) "a reset connection must throw, not return")
          (is (str/includes? (str (class e)) "SocketException")
              (str "ECONNRESET is a socket error, got " (class e)))
          (is (re-find #"[Rr]eset" (or (ex-message e) ""))
              (str "message must name the reset, got " (pr-str (ex-message e))))))
      (finally (reset! (:running srv) false) (net/close (:fd srv))))))

(deftest tls-handshake-transport-failure-is-ssl-exception
  ;; JVM parity: a transport failure during the TLS handshake surfaces as
  ;; SSLException, the way javax.net.ssl reports "Remote host terminated the
  ;; handshake". The raw SocketTimeoutException/SocketException of the transport
  ;; used to escape tls-connect untouched, so a mid-handshake reset read as a
  ;; read timeout to every caller — including clj-http-lite's
  ;; (is (thrown? SSLException ...)) in self-signed-ssl-get.
  (let [port 18449
        srv (start-resetting-server port)]
    (try
      (let [e (try (tls/tls-connect "127.0.0.1" port false) nil
                   (catch Throwable e e))]
        (is (some? e))
        (is (str/includes? (str (class e)) "SSLException")
            (str "a transport failure inside the handshake is an SSLException, got "
                 (class e)))
        (is (not (str/includes? (str (class e)) "SocketTimeoutException"))
            "the transport's own exception class must not leak through"))
      (finally (reset! (:running srv) false) (net/close (:fd srv))))))

;; --- a plain peer that accepts and never answers ---------------------------
;; What a cancelled provider call is parked on. Until reads were sliced, the
;; only way out was the socket timeout: a thread interrupted while parked in
;; recv ran the whole SO_RCVTIMEO before it noticed.

(defn- start-stalling-plain [port]
  (let [fd (srv/listen-socket port)
        running? (atom true)
        held (atom [])]
    (future
      (loop []
        (let [raw (srv/accept-raw fd)]
          (when @running?
            (when-not (neg? raw) (swap! held conj raw))
            (recur)))))
    {:fd fd :port port :running running? :held held}))

(deftest an-interrupt-unblocks-a-parked-read
  ;; jolt's Thread.interrupt does not reach a thread inside a blocking
  ;; syscall, so recv-bytes waits in interrupt-slice-ms slices and checks the
  ;; flag between them. A cancelled request comes back within one slice, as
  ;; an InterruptedException, with 10 s of socket timeout still to run.
  (let [port 18081
        srv (start-stalling-plain port)]
    (try
      (let [outcome (promise)
            t (Thread. (fn []
                         (let [t0 (System/currentTimeMillis)]
                           (deliver outcome
                                    (try (http/get (str "http://127.0.0.1:" port "/get")
                                                   {:socket-timeout 10000})
                                         [:returned 0]
                                         (catch Throwable e
                                           [(class e) (- (System/currentTimeMillis) t0)]))))))]
        (.start t)
        (Thread/sleep 300)
        (.interrupt t)
        (let [[cls elapsed] (deref outcome 5000 [:still-parked nil])]
          (is (= java.lang.InterruptedException cls)
              (str "the read came back as an interrupt, not a socket timeout: " cls))
          (is (and elapsed (< elapsed 2000))
              (str "within a slice of the interrupt, not the 10 s timeout; took " elapsed "ms"))))
      (finally (reset! (:running srv) false) (net/close (:fd srv))))))

(deftest a-sliced-read-still-honours-the-socket-timeout
  (let [port 18082
        srv (start-stalling-plain port)]
    (try
      (let [t0 (System/currentTimeMillis)
            outcome (try (http/get (str "http://127.0.0.1:" port "/get")
                                   {:socket-timeout 800})
                         :returned
                         (catch Throwable e (class e)))
            elapsed (- (System/currentTimeMillis) t0)]
        (is (= java.net.SocketTimeoutException outcome)
            "slicing the wait does not change what a silent peer surfaces as")
        (is (< 700 elapsed 4000)
            (str "and the bound is still the socket timeout, not a slice; took " elapsed "ms")))
      (finally (reset! (:running srv) false) (net/close (:fd srv))))))
