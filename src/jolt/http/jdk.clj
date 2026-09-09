(ns jolt.http.jdk
  "The java.net.http surface (JDK 11+ HttpClient) on Jolt, over the socket/TLS
  transport in jolt.http.core — plus the java.net and javax.net.ssl pieces a
  caller on that client reaches for on the way there.

  babashka.http-client drives all of it: `HttpClient.Builder` for the client
  options, `HttpRequest.Builder` for the request, `BodyPublishers`/`BodyHandlers`
  for the payload, `CompletableFuture` for `:async`, `ProxySelector`/
  `CookieHandler`/`SSLContext`/`SSLParameters`/`Authenticator` for the client
  options, and `SequenceInputStream` for multipart bodies. cognitect aws-api's
  java backend drives the same client. java.util.zip stays in jolt.http.platform,
  which owns the whole of it.

  What is NOT emulated: HTTP/2 (`:version :http2` is accepted and the exchange
  is HTTP/1.1), request priority, and a caller-supplied `:executor` (the async
  send runs on jolt's own future pool). Each is recorded on the client and read
  back, so a caller that sets and inspects one sees what it set."
  (:require [clojure.string :as str]
            [clojure.java.io]
            [jolt.crypto]                ;; java.security.SecureRandom (real, RAND_bytes)
            [jolt.http.core :as core]
            [jolt.http.net :as net]
            [jolt.http.tls :as tls]))

(def ^:private tt core/tt)
(def ^:private tget core/tget)
(def ^:private tput! core/tput!)
(def ^:private table? core/table?)
(def ^:private throw-typed core/throw-typed)

(defn- type-of [x] (and (table? x) (tget x :jolt/type)))

;; ---------------------------------------------------------------------------
;; CompletableFuture
;; ---------------------------------------------------------------------------
;; A future here is a reify, not a tagged table: `@f` is the whole point of the
;; class and jolt routes deref through clojure.lang.IDeref, which a tagged table
;; cannot implement.
;;
;; It is callback-driven rather than lazy, because on the JVM a stage RUNS when
;; its parent completes, whether or not anyone ever deref's it. Chaining off an
;; already-completed future runs the function right there on the calling thread —
;; which is exactly what babashka's WebSocket listener relies on:
;;
;;   (.thenApply (CompletableFuture/completedFuture nil)
;;               (reify Function (apply [_ _] (on-message ws data last?))))
;;
;; Nothing ever deref's that, so a lazy stage would silently drop every message.
;; It also keeps an async request to ONE thread: the root runs on jolt's future
;; pool and each derived stage settles on whichever thread completed its parent.
;;
;; A stage settles to {:v value} or {:e cause} — the CAUSE, not a wrapper. The
;; wrapping happens where the JVM wraps: get/join/deref raise ExecutionException
;; around it, while exceptionally and whenComplete see the cause itself.
;; babashka's :async-catch reads (ex-cause e) and falls back to e, so handing it
;; the cause is what makes both spellings work.
(defprotocol ^:private CF
  (cf-on-settle [_ cb] "Run cb with {:v x}/{:e t} when this stage settles, now if it already has.")
  (cf-settle! [_ r] "Settle this stage; the first call wins."))

(defn- completion-ex [t]
  (java.util.concurrent.ExecutionException. (str t) t))

(defn- cf-apply
  "Run f over a settled parent result, catching into the {:e t} shape. When the
  parent carries the other outcome it passes through untouched."
  [r want f]
  (if (contains? r want)
    (try {:v (.apply f (get r want))} (catch Throwable t {:e t}))
    r))

(declare cf-stage)

(defn- cf-derive
  "A stage that settles by running `f` over the parent's result."
  [parent f]
  (let [c (cf-stage)]
    (cf-on-settle parent (fn [r] (cf-settle! c (f r))))
    c))

(defn- cf-stage
  "An unsettled CompletableFuture."
  []
  (let [lock (Object.)
        state (atom {:done false :result nil :callbacks []})
        p (promise)
        out (fn [] (let [r @p] (if (contains? r :e) (throw (completion-ex (:e r))) (:v r))))]
    (reify
      clojure.lang.IDeref
      (deref [_] (out))
      CF
      (cf-on-settle [_ cb]
        ;; the lock is what makes "already settled?" and "queue me" one decision,
        ;; so a callback registered as the parent completes is neither dropped
        ;; nor run twice
        (let [now (locking lock
                    (if (:done @state)
                      (:result @state)
                      (do (swap! state update :callbacks conj cb) ::queued)))]
          (when-not (= ::queued now) (cb now))))
      (cf-settle! [_ r]
        (let [cbs (locking lock
                    (when-not (:done @state)
                      (let [cbs (:callbacks @state)]
                        (reset! state {:done true :result r :callbacks []})
                        (or cbs []))))]
          (when cbs
            (deliver p r)
            (doseq [cb cbs] (try (cb r) (catch Throwable _ nil))))
          nil))
      Object
      (get [_] (out))
      (join [_] (out))
      (getNow [_ fallback] (if (:done @state) (out) fallback))
      (isDone [_] (:done @state))
      (isCancelled [_] false)
      (cancel [_ _] false)
      (isCompletedExceptionally [_] (and (:done @state) (contains? (:result @state) :e)))
      (complete [this v] (cf-settle! this {:v v}) true)
      (completeExceptionally [this t] (cf-settle! this {:e t}) true)
      (thenApply [this f] (cf-derive this (fn [r] (cf-apply r :v f))))
      (thenApplyAsync [this f] (cf-derive this (fn [r] (cf-apply r :v f))))
      (thenAccept [this f] (cf-derive this (fn [r] (let [r' (cf-apply r :v f)]
                                                     (if (contains? r' :e) r' {:v nil})))))
      (thenRun [this f] (cf-derive this (fn [r] (if (contains? r :e) r
                                                    (try (.run f) {:v nil} (catch Throwable t {:e t}))))))
      ;; thenCompose's fn returns another stage; splice its result in
      (thenCompose [this f]
        (let [c (cf-stage)]
          (cf-on-settle this (fn [r]
                               (let [r' (cf-apply r :v f)]
                                 (if (contains? r' :e)
                                   (cf-settle! c r')
                                   (cf-on-settle (:v r') (fn [inner] (cf-settle! c inner)))))))
          c))
      (exceptionally [this f] (cf-derive this (fn [r] (cf-apply r :e f))))
      ;; whenComplete sees both arms and does not change the result
      (whenComplete [this f] (cf-derive this (fn [r]
                                               (try (.apply f (:v r) (:e r)) (catch Throwable _ nil))
                                               r)))
      (toCompletableFuture [this] this))))

(defn- cf-async
  "Run thunk on jolt's future pool; the stage settles when it finishes.

  One pool thread, not two. It used to run the thunk on one future and park a
  second on its deref purely to unwrap the ExecutionException jolt's own deref
  adds — but the inner future already catches Throwable and hands back a
  {:v}/{:e} map, so it never throws and there was nothing to unwrap. The second
  thread did nothing but wait, and halved how many :async requests a given pool
  could have in flight."
  [thunk]
  (let [c (cf-stage)]
    (future (cf-settle! c (try {:v (thunk)} (catch Throwable t {:e t}))))
    c))

(defn- cf-done [v] (doto (cf-stage) (cf-settle! {:v v})))
(defn- cf-failed [t] (doto (cf-stage) (cf-settle! {:e t})))

(defn- cf? [x] (satisfies? CF x))

;; The seam jolt.http.websocket builds its futures through — buildAsync and every
;; send return a CompletableFuture, and there is one implementation of that here.
(defn completed-future
  "An already-completed CompletableFuture holding `v`."
  [v]
  (cf-done v))

(defn async-future
  "A CompletableFuture over `thunk`, run on jolt's future pool."
  [thunk]
  (cf-async thunk))

;; ---------------------------------------------------------------------------
;; java.time.Duration <-> milliseconds
;; ---------------------------------------------------------------------------
(defn- duration-ms [d]
  (cond
    (nil? d) nil
    (number? d) d
    :else (try (.toMillis d) (catch Throwable _ nil))))

(defn duration->ms
  "A java.time.Duration (or a plain millisecond count) as milliseconds, nil for
  nothing. Public for jolt.http.websocket, which takes the same option."
  [d]
  (duration-ms d))

;; ---------------------------------------------------------------------------
;; SSL configuration carried on a client
;; ---------------------------------------------------------------------------
;; An SSLContext shim records what .init was handed. Whether it verifies peers is
;; not something we can read off a caller's TrustManager, so we ASK it: a manager
;; that accepts an empty certificate chain trusts everything, which is exactly
;; what babashka's `:insecure true` builds and what a real X509TrustManager
;; refuses. Default stays secure — only a manager that provably accepts nothing-
;; at-all flips verification off.
(defn- accepts-empty-chain? [tm]
  (try (.checkServerTrusted tm (into-array []) "RSA") true
       (catch Throwable _ false)))

(defn- ssl-context-insecure? [ctx]
  (boolean (and ctx (tget ctx :insecure))))

(defn- store-material [ks]
  (when (and ks (tget ks :bytes))
    {:bytes (tget ks :bytes) :pass (tget ks :pass)}))

(defn- ssl-material
  "The PKCS#12 material an SSLContext carries, in the shape jolt.http.tls wants."
  [ctx]
  (when ctx
    (let [key-store (store-material (tget ctx :key-store))
          trust-store (store-material (tget ctx :trust-store))]
      (when (or key-store trust-store)
        {:key-store key-store :trust-store trust-store}))))

;; A websocket is built off a client and inherits its TLS and connect settings;
;; these three read them without jolt.http.websocket knowing the client's shape.
(defn client-connect-timeout [client] (tget client :connect-timeout))
(defn client-ssl-material [client] (ssl-material (tget client :ssl-context)))
(defn client-insecure? [client] (ssl-context-insecure? (tget client :ssl-context)))

;; HttpClient.newWebSocketBuilder() belongs to the client, which lives here,
;; while the implementation lives in jolt.http.websocket — which requires this
;; namespace. The hook is what keeps that from being a cycle.
(def ^:private websocket-builder (atom nil))

(defn set-websocket-builder!
  "Register the fn HttpClient.newWebSocketBuilder() calls (of the client)."
  [f]
  (reset! websocket-builder f))

;; ---------------------------------------------------------------------------
;; Cookies
;; ---------------------------------------------------------------------------
(def ^:private policy-accept-all :java.net.CookiePolicy/ACCEPT_ALL)
(def ^:private policy-accept-none :java.net.CookiePolicy/ACCEPT_NONE)
(def ^:private policy-original :java.net.CookiePolicy/ACCEPT_ORIGINAL_SERVER)

(defn- host-of-uri [uri]
  (or (try (.getHost uri) (catch Throwable _ nil))
      (tget (core/parse-url (str uri)) :host)))

(defn- cookie-domain-matches?
  "RFC 6265 domain-match, which is what ACCEPT_ORIGINAL_SERVER gates on: no
  Domain attribute means host-only, otherwise the request host must be the
  domain or a subdomain of it."
  [host domain]
  (let [host (str/lower-case (or host ""))
        domain (str/lower-case (or domain ""))]
    (if (str/blank? domain)
      true
      (let [d (if (str/starts-with? domain ".") (subs domain 1) domain)]
        (or (= host d) (str/ends-with? host (str "." d)))))))

(def ^:private months
  {"jan" 1 "feb" 2 "mar" 3 "apr" 4 "may" 5 "jun" 6
   "jul" 7 "aug" 8 "sep" 9 "oct" 10 "nov" 11 "dec" 12})

(defn- days-from-civil
  "Days since the epoch for a proleptic-Gregorian y/m/d (Howard Hinnant's
  algorithm). java.time.format is not modelled here, and an Expires date is the
  only thing a cookie needs a calendar for."
  [y m d]
  (let [y (if (<= m 2) (dec y) y)
        era (quot (if (>= y 0) y (- y 399)) 400)
        yoe (- y (* era 400))
        doy (+ (quot (+ (* 153 (+ m (if (> m 2) -3 9))) 2) 5) (dec d))
        doe (+ (* yoe 365) (quot yoe 4) (- (quot yoe 100)) doy)]
    (+ (* era 146097) doe -719468)))

(defn- parse-http-date
  "An RFC 1123 / RFC 850 / asctime cookie Expires value as epoch milliseconds,
  nil when it cannot be read. Cookie dates are always GMT."
  [s]
  (try
    (let [toks (remove str/blank? (str/split (str s) #"[\s,]+"))
          ;; "Wed 21 Oct 2015 07:28:00 GMT" or "Wed 21-Oct-2015 07:28:00 GMT"
          toks (mapcat (fn [t] (str/split t #"-")) toks)
          nums (filter #(re-matches #"\d{1,4}" %) toks)
          time-tok (first (filter #(str/includes? % ":") toks))
          mon (some (fn [t] (get months (str/lower-case (subs t 0 (min 3 (count t)))))) toks)
          day (some (fn [t] (let [n (parse-long t)] (when (and n (<= 1 n 31)) n)))
                    (filter #(<= (count %) 2) nums))
          year (some (fn [t] (let [n (parse-long t)]
                               (when n (cond (>= n 1000) n
                                             (>= n 70) (+ 1900 n)
                                             :else (+ 2000 n)))))
                     (filter #(or (= 4 (count %)) (= 2 (count %))) nums))
          [hh mm ss] (when time-tok (map parse-long (str/split time-tok #":")))]
      (when (and mon day year hh)
        (+ (* (days-from-civil year mon day) 86400000)
           (* (or hh 0) 3600000) (* (or mm 0) 60000) (* (or ss 0) 1000))))
    (catch Throwable _ nil)))

(defn- parse-set-cookie [line]
  (let [parts (str/split (str line) #";")
        [nm v] (let [kv (first parts)
                     i (str/index-of (str kv) "=")]
                 (if i [(str/trim (subs kv 0 i)) (str/trim (subs kv (inc i)))] [(str/trim kv) ""]))
        attrs (reduce (fn [m part]
                        (let [part (str/trim part)
                              i (str/index-of part "=")]
                          (if i
                            (assoc m (str/lower-case (str/trim (subs part 0 i))) (str/trim (subs part (inc i))))
                            (assoc m (str/lower-case part) true))))
                      {} (rest parts))
        max-age (some-> (get attrs "max-age") parse-long)]
    (doto (tt :jolt.http/cookie)
      (tput! :name nm)
      (tput! :value v)
      (tput! :domain (get attrs "domain"))
      (tput! :path (or (get attrs "path") "/"))
      (tput! :secure (boolean (get attrs "secure")))
      (tput! :max-age max-age)
      ;; When a cookie stops being sent. RFC 6265 5.3: Max-Age wins over
      ;; Expires, and Max-Age=0 is how a server DELETES a cookie — parsed but
      ;; never read before, so a deleted cookie went on being sent forever.
      (tput! :expires-at (cond
                           max-age (+ (System/currentTimeMillis) (* 1000 max-age))
                           (get attrs "expires") (parse-http-date (get attrs "expires"))
                           :else nil)))))

(defn- cookie-expired? [c]
  (when-let [at (tget c :expires-at)]
    (<= at (System/currentTimeMillis))))

(defn- make-cookie-store []
  (doto (tt :jolt.http/cookie-store) (tput! :cookies (atom []))))

(defn- store-add! [store uri cookie]
  (let [host (host-of-uri uri)
        cookie (if (tget cookie :domain) cookie (doto cookie (tput! :domain host)))
        cookies (tget store :cookies)]
    (swap! cookies (fn [cs]
                     (conj (vec (remove (fn [c] (and (= (tget c :name) (tget cookie :name))
                                                     (= (tget c :domain) (tget cookie :domain))))
                                        cs))
                           cookie)))
    nil))

(defn- cookie-path-matches?
  "RFC 6265 path-match: the request path is the cookie's path, or sits under it."
  [request-path cookie-path]
  (let [cp (if (str/blank? (str cookie-path)) "/" cookie-path)
        rp (if (str/blank? (str request-path)) "/" request-path)]
    (or (= rp cp)
        (and (str/starts-with? rp cp)
             (or (str/ends-with? cp "/") (= \/ (get rp (count cp))))))))

(defn- store-matching
  "The cookies this store will send for `uri`. `secure?` is whether the request
  travels over TLS: java.net.CookieManager gates on `secureLink || !getSecure()`,
  so a Secure cookie is withheld from a plaintext request, and its CookieStore
  drops expired entries on the way out."
  [store uri secure?]
  (let [host (host-of-uri uri)
        path (tget (core/parse-url (str uri)) :path)]
    (filter (fn [c] (and (cookie-domain-matches? host (tget c :domain))
                         (cookie-path-matches? path (tget c :path))
                         (or secure? (not (tget c :secure)))
                         (not (cookie-expired? c))))
            @(tget store :cookies))))

(defn- make-cookie-manager [store policy]
  (doto (tt :jolt.http/cookie-manager)
    (tput! :store (or store (make-cookie-store)))
    (tput! :policy (or policy policy-accept-none))))

(defn- cookie-manager-put! [mgr uri headers]
  (let [store (tget mgr :store)
        policy (tget mgr :policy)
        host (host-of-uri uri)]
    (doseq [[k vs] headers
            :when (and k (contains? #{"set-cookie" "set-cookie2"} (str/lower-case (str k))))
            v (if (sequential? vs) vs [vs])]
      (let [c (parse-set-cookie v)]
        (when (cond
                (= policy policy-accept-all) true
                (= policy policy-accept-none) false
                (= policy policy-original) (cookie-domain-matches? host (tget c :domain))
                :else false)
          (store-add! store uri c))))
    nil))

(defn- cookie-manager-get [mgr uri _headers]
  (let [cs (store-matching (tget mgr :store) uri
                           (= "https" (tget (core/parse-url (str uri)) :protocol)))]
    (if (seq cs)
      {"Cookie" [(str/join "; " (map (fn [c] (str (tget c :name) "=" (tget c :value))) cs))]}
      {})))

;; ---------------------------------------------------------------------------
;; Proxies
;; ---------------------------------------------------------------------------
(def ^:private proxy-type-http :java.net.Proxy$Type/HTTP)
(def ^:private proxy-type-direct :java.net.Proxy$Type/DIRECT)
(def ^:private proxy-type-socks :java.net.Proxy$Type/SOCKS)

(defn- make-proxy-obj [type address]
  (doto (tt :jolt.http/proxy) (tput! :type type) (tput! :address address)))

(def ^:private no-proxy (make-proxy-obj proxy-type-direct nil))

(defn- select-proxy
  "Ask a ProxySelector for the proxy to use for `uri`, as {:host :port} or nil for
  a direct connection. An empty selection, or a DIRECT proxy, is a direct
  connection — the same reading java.net.http gives them. A selector that RAISES
  is not caught: a caller's proxy function failing is theirs to see, and
  swallowing it would silently send the request straight to the origin."
  [selector uri]
  (when selector
    (let [selected (.select selector uri)
          p (first (if (sequential? selected) selected (seq selected)))]
      (when (and p (not= proxy-type-direct (.type p)))
        (when-let [addr (.address p)]
          {:host (or (try (.getHostString addr) (catch Throwable _ nil))
                     (.getHostName addr))
           :port (.getPort addr)})))))

;; ---------------------------------------------------------------------------
;; Connect (direct, or through an HTTP proxy)
;; ---------------------------------------------------------------------------
;; java.net.http speaks to HTTP proxies only. Plain http goes through the proxy
;; as an absolute-form request line (RFC 7230 §5.3.2); https tunnels with
;; CONNECT and then runs the TLS handshake inside the tunnel, so the proxy never
;; sees the plaintext.
(defn- proxy-connect! [fd host port]
  (let [target (str host ":" port)
        req (str "CONNECT " target " HTTP/1.1\r\n"
                 "Host: " target "\r\n"
                 "Proxy-Connection: keep-alive\r\n\r\n")]
    (net/send-bytes fd (core/latin1->ba req))
    (loop [acc ""]
      (if-let [chunk (net/recv-bytes fd)]
        (let [acc (str acc (core/ba->latin1 chunk))]
          (if-let [end (str/index-of acc "\r\n\r\n")]
            (let [status-line (first (str/split (subs acc 0 end) #"\r\n"))
                  status (parse-long (or (nth (str/split status-line #" ") 1 nil) ""))]
              (when-not (= 200 status)
                (net/close fd)
                (throw-typed "java.io.IOException"
                             (str "proxy CONNECT to " target " failed: " status-line)))
              nil)
            (recur acc)))
        (do (net/close fd)
            (throw-typed "java.io.IOException"
                         (str "proxy closed the connection during CONNECT to " target)))))))

(defn- open-stream
  "Connect to the request's origin, honouring `prx` ({:host :port} or nil).
  Returns [stream absolute-form?] — absolute-form? is true when the request line
  must carry the full URI because we are talking to a plain-http proxy."
  [{:keys [host port https? insecure? read-timeout conn-timeout proxy ssl]}]
  (if (nil? proxy)
    [(core/connect-stream host port https? insecure? read-timeout conn-timeout ssl) false]
    (if https?
      (let [fd (net/connect (str (:host proxy)) (:port proxy) conn-timeout)]
        (net/set-read-timeout! fd read-timeout)
        (proxy-connect! fd host port)
        [(tls/tls-wrap-client fd host insecure? ssl) false])
      (let [fd (net/connect (str (:host proxy)) (:port proxy) conn-timeout)]
        (net/set-read-timeout! fd read-timeout)
        [fd true]))))

;; ---------------------------------------------------------------------------
;; The exchange
;; ---------------------------------------------------------------------------
(defn- header-value [pairs nm] (core/header-ci pairs nm))

(defn- drop-header [pairs nm]
  (let [low (str/lower-case nm)]
    (vec (remove (fn [p] (= low (str/lower-case (first p)))) pairs))))

;; java.net.http refuses to let a caller set a header the client itself owns —
;; measured against a JDK: content-length, connection, host, upgrade and expect
;; all raise IllegalArgumentException("restricted header name: ..."), while
;; date, via and anything custom go through. Without the check a caller's
;; Content-Length joined ours on the wire as "Content-Length: 4, 4", which
;; RFC 7230 3.3.3 makes an unrecoverable message framing error.
(def ^:private restricted-headers
  #{"connection" "content-length" "expect" "host" "upgrade"})

(defn- check-header! [k]
  (when (contains? restricted-headers (str/lower-case (str k)))
    (throw-typed "java.lang.IllegalArgumentException"
                 (str "restricted header name: \"" k "\"")))
  nil)

(defn- basic-auth-header [user pass]
  (str "Basic " (.encodeToString (java.util.Base64/getEncoder)
                                 (.getBytes (str user ":" pass) "UTF-8"))))

(defn- authenticator-header
  "Ask an Authenticator for credentials, as a Basic authorization value. Only
  Basic is emulated — the socket layer has no Digest/NTLM state machine."
  [auth]
  (when auth
    (when-let [pa (try (.getPasswordAuthentication auth) (catch Throwable _ nil))]
      (let [user (.getUserName pa)
            pass (apply str (seq (.getPassword pa)))]
        (basic-auth-header user pass)))))

(defn- follow?
  "java.net.http's redirect policies. NORMAL follows everything ALWAYS does
  except a redirect from https down to http."
  [policy from-url to-url]
  (cond
    (= policy :jolt.http.redirect/ALWAYS) true
    (= policy :jolt.http.redirect/NORMAL)
      (not (and (= "https" (tget from-url :protocol)) (= "http" (tget to-url :protocol))))
    :else false))

(defn- exchange-once
  "One request/response over `stream`. Releases the connection back to the pool
  when the response says it may be kept, and closes it otherwise — including on
  the way out of a failure, where the state of the connection is unknown."
  [stream absolute? key {:keys [url method headers body deadline]}]
  (let [ok (atom false)]
    (try
      (core/s-write stream (core/build-request method url headers body
                                               (when absolute? (core/spec-no-ref url))))
      (let [resp (core/read-response stream deadline method)]
        (reset! ok (:reusable? resp))
        resp)
      (finally
        (if @ok
          (core/pool-release! key stream)
          (try (core/s-close stream) (catch Throwable _ nil)))))))

(defn- exchange
  "One request/response, over a pooled connection when one is available.

  A pooled connection the peer retired between requests looks exactly like a
  live one until the read comes back with nothing at all; that is the single
  case retried on a fresh connection, and it is safe to retry even a POST there
  because a peer that never sent a byte never acted on the request."
  [{:keys [url method read-timeout conn-timeout insecure? proxy ssl] :as req}]
  (let [https? (= "https" (tget url :protocol))
        port (core/effective-port url)
        host (tget url :host)
        key (core/pool-key host port https? insecure? ssl proxy)
        open! (fn [] (open-stream {:host host :port port :https? https?
                                   :insecure? insecure? :read-timeout read-timeout
                                   :conn-timeout conn-timeout :proxy proxy :ssl ssl}))]
    (if-let [pooled (core/pool-acquire key)]
      (try
        (core/set-stream-timeout! pooled read-timeout)
        (exchange-once pooled (boolean (and proxy (not https?))) key req)
        (catch Throwable t
          (if (= "class java.io.EOFException" (str (class t)))
            (let [[stream absolute?] (open!)] (exchange-once stream absolute? key req))
            (throw t))))
      (let [[stream absolute?] (open!)]
        (exchange-once stream absolute? key req)))))

(defn- request-headers
  "The wire headers for one hop: what the caller set, plus a Cookie header from
  the cookie handler and an Authorization header from the authenticator."
  [pairs uri cookie-handler auth-header]
  (let [pairs (if cookie-handler
                (let [added (cookie-manager-get cookie-handler uri {})]
                  (reduce (fn [ps [k vs]]
                            (reduce (fn [ps v] (conj ps [k v])) ps vs))
                          pairs added))
                pairs)]
    (if (and auth-header (nil? (header-value pairs "authorization")))
      (conj pairs ["Authorization" auth-header])
      pairs)))

(defn- headers->map
  "java.net.http groups response headers to {lowercased-name [values]}."
  [pairs]
  (reduce (fn [m [k v]] (update m (str/lower-case k) (fnil conj []) v)) {} pairs))

(defn- net-http-send
  "Run a java.net.http request over the socket/TLS transport: proxy selection,
  cookies, redirects, authentication, then hand the body to the BodyHandler."
  [client request handler]
  (let [conn-timeout (duration-ms (tget client :connect-timeout))
        req-timeout (duration-ms (tget request :timeout))
        ssl-context (tget client :ssl-context)
        ssl (ssl-material ssl-context)
        insecure? (ssl-context-insecure? ssl-context)
        cookie-handler (tget client :cookie-handler)
        selector (tget client :proxy)
        policy (or (tget client :follow-redirects) :jolt.http.redirect/NEVER)
        deadline (when req-timeout (+ (System/currentTimeMillis) req-timeout))
        start-uri (tget request :uri)]
    (loop [uri start-uri
           url (core/parse-url (str start-uri))
           method (or (tget request :method) "GET")
           ;; An empty byte-array and nil are different requests: java.net.http
           ;; sends `Content-Length: 0` for a POST/PUT built with
           ;; BodyPublishers/noBody and nothing at all when there is no
           ;; publisher, so the distinction has to survive to build-request.
           body (when-let [bp (tget request :body)] (or (tget bp :bytes) (byte-array 0)))
           auth-header nil
           redirects 0
           retried-auth? false]
      (let [prx (select-proxy selector uri)
            hdrs (request-headers (or (tget request :headers) []) uri cookie-handler auth-header)
            resp (exchange {:url url :method method :headers hdrs :body body
                            :read-timeout req-timeout :conn-timeout conn-timeout
                            :insecure? insecure? :proxy prx :ssl ssl :deadline deadline})
            pairs (:header-pairs resp)]
        (when cookie-handler
          (cookie-manager-put! cookie-handler uri (headers->map pairs)))
        (let [loc (header-value pairs "location")
              status (:status resp)
              auth-retry (when (and (= 401 status) (not retried-auth?))
                           (authenticator-header (tget client :authenticator)))]
          (cond
            ;; 401 with an authenticator configured: retry the same request once
            ;; with credentials, which is what java.net.http's Authenticator does.
            (and (= 401 status) (not retried-auth?) auth-retry)
              (recur uri url method body auth-retry redirects true)

            (and loc (core/redirect-statuses status) (< redirects 20)
                 (let [to (core/resolve-location url loc)] (follow? policy url to)))
              (let [to (core/resolve-location url loc)
                    ;; 303 (and 301/302 on POST, matching java.net.http) rewrites
                    ;; to GET and drops the body.
                    to-get? (or (= 303 status)
                                (and (#{301 302} status) (not (#{"GET" "HEAD"} method))))]
                (recur (java.net.URI/create (tget to :spec)) to
                       (if to-get? "GET" method)
                       (if to-get? nil body)
                       auth-header (inc redirects) retried-auth?))

            :else
            (let [body-bytes (:body resp)
                  out-body (cond
                             (= handler :jolt.http/handler-string) (String. ^bytes body-bytes "UTF-8")
                             (= handler :jolt.http/handler-inputstream) (core/make-bais body-bytes)
                             (= handler :jolt.http/handler-discarding) nil
                             :else body-bytes)]
              (doto (tt :jolt.http/response)
                (tput! :status status)
                (tput! :body out-body)
                (tput! :uri uri)
                (tput! :version (or (tget client :version)
                                    (doto (tt :jolt.http/version-enum) (tput! :name "HTTP_1_1"))))
                (tput! :request request)
                (tput! :resp-headers pairs)))))))))

;; ---------------------------------------------------------------------------
;; install
;; ---------------------------------------------------------------------------
(defn- reg-ctor! [names f]
  (doseq [nm names] (__register-class-ctor! nm f)))

(defn- reg-statics! [names m]
  (doseq [nm names] (__register-class-statics! nm m)))

(defn- both
  "A JDK class is reached for by its simple name as often as its qualified one;
  register both spellings."
  [qualified]
  [qualified (last (str/split qualified #"\."))])

(defn install! []
  ;; --- java.net.URI: the multi-argument constructors ------------------------
  ;; jolt models URI natively with a one-argument ctor. babashka builds one from
  ;; a map of parts with the seven-argument ctor, so the ctor is replaced with
  ;; one that assembles the parts and hands the string back to URI/create — the
  ;; static, which the override leaves alone, so the object is still jolt's own
  ;; and every getter keeps working.
  (letfn [(auth [user host port]
            (str (when-not (str/blank? (str user)) (str user "@"))
                 host
                 (when (and port (number? port) (not (neg? port))) (str ":" port))))
          (assemble [scheme authority path query fragment]
            (str scheme ":"
                 (when-not (str/blank? (str authority)) (str "//" authority))
                 (or path "")
                 (when-not (str/blank? (str query)) (str "?" query))
                 (when-not (str/blank? (str fragment)) (str "#" fragment))))]
    (reg-ctor! (both "java.net.URI")
      (fn
        ([s] (java.net.URI/create (str s)))
        ;; (scheme, ssp, fragment)
        ([scheme ssp fragment]
         (java.net.URI/create (str scheme ":" ssp (when-not (str/blank? (str fragment)) (str "#" fragment)))))
        ;; (scheme, host, path, fragment)
        ([scheme host path fragment]
         (java.net.URI/create (assemble scheme host path nil fragment)))
        ;; (scheme, authority, path, query, fragment)
        ([scheme authority path query fragment]
         (java.net.URI/create (assemble scheme authority path query fragment)))
        ;; (scheme, userInfo, host, port, path, query, fragment)
        ([scheme user host port path query fragment]
         (java.net.URI/create (assemble scheme (auth user host port) path query fragment))))))

  ;; --- java.util.concurrent.CompletableFuture -------------------------------
  ;; An unsettled future the caller completes later with complete() /
  ;; completeExceptionally(); a deref before then parks.
  (reg-ctor! (both "java.util.concurrent.CompletableFuture") (fn [& _] (cf-stage)))
  (reg-statics! (both "java.util.concurrent.CompletableFuture")
    {"completedFuture" (fn [v] (cf-done v))
     "failedFuture"    (fn [t] (cf-failed t))
     "supplyAsync"     (fn [s & _] (cf-async (fn [] (.get s))))
     "runAsync"        (fn [r & _] (cf-async (fn [] (.run r) nil)))})

  ;; --- java.io.SequenceInputStream ------------------------------------------
  ;; Eager: the parts are drained and concatenated at construction. multipart
  ;; bodies are built this way and then read once, so nothing observes laziness —
  ;; and the socket layer needs the length up front to write Content-Length.
  (reg-ctor! (both "java.io.SequenceInputStream")
    (fn [a & more]
      (let [parts (if (and (empty? more) (not (instance? java.io.InputStream a)))
                    ;; the Enumeration<InputStream> ctor
                    (loop [acc []]
                      (if (.hasMoreElements a) (recur (conj acc (.nextElement a))) acc))
                    (cons a more))]
        ;; one pass, not a fresh copy of everything per part: a multipart body
        ;; is built out of a stream per field and re-concatenating each time is
        ;; quadratic in the size of the upload
        (core/make-bais (core/concat-bas (map core/->bytes parts))))))

  ;; --- java.nio.file.Files/probeContentType ---------------------------------
  ;; Content-type by extension. The JDK consults the platform's type database;
  ;; there is none to consult here, so a short table covers what multipart
  ;; uploads actually carry and everything else is the JDK's own fallback of
  ;; nil (the caller then uses application/octet-stream).
  (reg-statics! (both "java.nio.file.Files")
    {"probeContentType"
     (fn [path]
       (let [s (str/lower-case (str path))
             ext (when-let [i (str/last-index-of s ".")] (subs s (inc i)))]
         (get {"txt" "text/plain" "html" "text/html" "htm" "text/html"
               "css" "text/css" "csv" "text/csv" "json" "application/json"
               "xml" "application/xml" "edn" "application/edn"
               "js" "text/javascript" "pdf" "application/pdf"
               "png" "image/png" "jpg" "image/jpeg" "jpeg" "image/jpeg"
               "gif" "image/gif" "svg" "image/svg+xml" "webp" "image/webp"
               "zip" "application/zip" "gz" "application/gzip"
               "tar" "application/x-tar" "wasm" "application/wasm"}
              ext)))})

  ;; --- java.net.Proxy / Proxy$Type / ProxySelector --------------------------
  (reg-statics! (both "java.net.Proxy$Type")
    {"HTTP" proxy-type-http "DIRECT" proxy-type-direct "SOCKS" proxy-type-socks})
  (reg-ctor! (both "java.net.Proxy") (fn [type address] (make-proxy-obj type address)))
  (reg-statics! (both "java.net.Proxy") {"NO_PROXY" no-proxy})
  (__register-class-methods! :jolt.http/proxy
    {"type" (fn [self] (tget self :type))
     "address" (fn [self] (tget self :address))
     "toString" (fn [self] (str (name (tget self :type)) " @ " (tget self :address)))})
  ;; ProxySelector is only ever subclassed (babashka proxies over it to answer
  ;; select). Registering a ctor is what lets `proxy` build the base instance;
  ;; the base's own select selects nothing, i.e. a direct connection.
  (reg-ctor! (both "java.net.ProxySelector") (fn [& _] (tt :jolt.http/proxy-selector)))
  ;; ProxySelector.of(address) is the one-liner form — babashka 0.4.23 and hato
  ;; both build their proxy that way, where 0.4.24 subclasses instead.
  (reg-statics! (both "java.net.ProxySelector")
    {"of" (fn [addr] (doto (tt :jolt.http/proxy-selector)
                       (tput! :fixed (when addr (make-proxy-obj proxy-type-http addr)))))
     "getDefault" (fn [& _] (tt :jolt.http/proxy-selector))
     "setDefault" (fn [& _] nil)})
  (__register-class-methods! :jolt.http/proxy-selector
    {"select" (fn [self _uri] [(or (tget self :fixed) no-proxy)])
     "connectFailed" (fn [_self & _] nil)})

  ;; --- java.net cookies -----------------------------------------------------
  (reg-statics! (both "java.net.CookiePolicy")
    {"ACCEPT_ALL" policy-accept-all
     "ACCEPT_NONE" policy-accept-none
     "ACCEPT_ORIGINAL_SERVER" policy-original})
  (reg-ctor! (both "java.net.CookieManager")
    (fn ([] (make-cookie-manager nil nil))
        ([store] (make-cookie-manager store nil))
        ([store policy] (make-cookie-manager store policy))))
  (reg-ctor! (both "java.net.CookieHandler") (fn [& _] (make-cookie-manager nil nil)))
  (__register-class-methods! :jolt.http/cookie-manager
    {"put" (fn [self uri headers] (cookie-manager-put! self uri headers))
     "get" (fn [self uri headers] (cookie-manager-get self uri headers))
     "getCookieStore" (fn [self] (tget self :store))
     "setCookiePolicy" (fn [self p] (tput! self :policy p) nil)})
  (__register-class-methods! :jolt.http/cookie-store
    {"getCookies" (fn [self] (vec (remove cookie-expired? @(tget self :cookies))))
     "getURIs" (fn [_self] [])
     "add" (fn [self uri c] (store-add! self uri c))
     "removeAll" (fn [self] (reset! (tget self :cookies) []) true)})
  (reg-ctor! (both "java.net.HttpCookie")
    (fn [nm v] (doto (tt :jolt.http/cookie)
                 (tput! :name nm) (tput! :value v) (tput! :path "/"))))
  (reg-statics! (both "java.net.HttpCookie")
    {"parse" (fn [s] [(parse-set-cookie s)])})
  (__register-class-methods! :jolt.http/cookie
    {"getName" (fn [self] (tget self :name))
     "getValue" (fn [self] (tget self :value))
     "getDomain" (fn [self] (tget self :domain))
     "getPath" (fn [self] (tget self :path))
     "getSecure" (fn [self] (boolean (tget self :secure)))
     "getMaxAge" (fn [self] (or (tget self :max-age) -1))
     "setDomain" (fn [self d] (tput! self :domain d) nil)
     "setPath" (fn [self p] (tput! self :path p) nil)
     "toString" (fn [self] (str (tget self :name) "=" (tget self :value)))})

  ;; --- javax.net.ssl --------------------------------------------------------
  (reg-ctor! (both "javax.net.ssl.SSLParameters")
    (fn [& _] (doto (tt :jolt.http/ssl-parameters)
                (tput! :ciphers nil) (tput! :protocols nil))))
  (__register-class-methods! :jolt.http/ssl-parameters
    {"setCipherSuites" (fn [self arr] (tput! self :ciphers (vec arr)) nil)
     "getCipherSuites" (fn [self] (tget self :ciphers))
     "setProtocols" (fn [self arr] (tput! self :protocols (vec arr)) nil)
     "getProtocols" (fn [self] (tget self :protocols))})

  ;; The trust managers a caller can build. X509ExtendedTrustManager /
  ;; X509TrustManager exist so `proxy`/`reify` over them has a class to name; the
  ;; base implementations refuse an empty chain, so a subclass that does NOT
  ;; refuse it is one that trusts everything (see accepts-empty-chain?).
  (doseq [nm (concat (both "javax.net.ssl.X509ExtendedTrustManager")
                     (both "javax.net.ssl.X509TrustManager")
                     (both "javax.net.ssl.TrustManager")
                     (both "javax.net.ssl.KeyManager")
                     (both "java.security.cert.X509Certificate"))]
    (__register-class-ctor! nm (fn [& _] (tt :jolt.http/trust-manager))))
  (__register-class-methods! :jolt.http/trust-manager
    {"checkServerTrusted" (fn [_self chain & _]
                            (when (or (nil? chain) (zero? (count chain)))
                              (throw-typed "java.lang.IllegalArgumentException"
                                           "null or zero-length certificate chain"))
                            nil)
     "checkClientTrusted" (fn [_self chain & _]
                            (when (or (nil? chain) (zero? (count chain)))
                              (throw-typed "java.lang.IllegalArgumentException"
                                           "null or zero-length certificate chain"))
                            nil)
     "getAcceptedIssuers" (fn [_self] (into-array []))})

  ;; KeyStore / KeyManagerFactory / TrustManagerFactory: the PKCS#12 material a
  ;; caller loads is carried through to jolt.http.tls, which hands it to OpenSSL.
  (reg-statics! (both "java.security.KeyStore")
    {"getInstance" (fn [type & _] (doto (tt :jolt.http/keystore) (tput! :type (str type))))
     "getDefaultType" (fn [& _] "pkcs12")})
  (__register-class-methods! :jolt.http/keystore
    {"load" (fn [self stream pass]
              (tput! self :bytes (when stream (core/->bytes stream)))
              (tput! self :pass (when pass (apply str (seq pass))))
              nil)
     "size" (fn [self] (if (tget self :bytes) 1 0))})
  (doseq [[nm kind] [["javax.net.ssl.KeyManagerFactory" :key]
                     ["KeyManagerFactory" :key]
                     ["javax.net.ssl.TrustManagerFactory" :trust]
                     ["TrustManagerFactory" :trust]]]
    (__register-class-statics! nm
      {"getInstance" (fn [& _] (doto (tt :jolt.http/km-factory) (tput! :kind kind)))
       "getDefaultAlgorithm" (fn [& _] "PKIX")}))
  (__register-class-methods! :jolt.http/km-factory
    {"init" (fn [self ks & args]
              (tput! self :keystore ks)
              (tput! self :pass (when-let [p (first args)] (apply str (seq p))))
              nil)
     "getKeyManagers" (fn [self]
                        (into-array [(doto (tt :jolt.http/store-manager)
                                       (tput! :kind :key)
                                       (tput! :keystore (tget self :keystore)))]))
     "getTrustManagers" (fn [self]
                          (into-array [(doto (tt :jolt.http/store-manager)
                                         (tput! :kind :trust)
                                         (tput! :keystore (tget self :keystore)))]))})
  ;; A manager backed by a real keystore refuses an empty chain, so it never
  ;; trips the insecure probe.
  (__register-class-methods! :jolt.http/store-manager
    {"checkServerTrusted" (fn [_self & _] (throw-typed "java.lang.IllegalArgumentException"
                                                       "null or zero-length certificate chain"))
     "checkClientTrusted" (fn [_self & _] (throw-typed "java.lang.IllegalArgumentException"
                                                       "null or zero-length certificate chain"))
     "getAcceptedIssuers" (fn [_self] (into-array []))
     "keystore" (fn [self] (tget self :keystore))})

  (reg-statics! (both "javax.net.ssl.SSLContext")
    {"getInstance" (fn [& _] (tt :jolt/ssl-context))
     "getDefault" (fn [& _] (doto (tt :jolt/ssl-context) (tput! :default true)))})
  (__register-class-methods! :jolt/ssl-context
    {;; .init(keyManagers, trustManagers, secureRandom) — what a caller passes is
     ;; how the connection is configured: a key manager over a keystore becomes
     ;; the client certificate, a trust manager over a truststore becomes the
     ;; peer's CA set, and a trust manager that accepts an empty chain turns
     ;; verification off.
     "init" (fn [self kms tms & _]
              (let [kms (when kms (seq kms))
                    tms (when tms (seq tms))
                    store-of (fn [m] (when (= :jolt.http/store-manager (type-of m))
                                       (tget m :keystore)))]
                (tput! self :key-store (some store-of kms))
                (tput! self :trust-store (some store-of tms))
                (tput! self :insecure (boolean (some accepts-empty-chain? tms))))
              self)
     "getSocketFactory" (fn [_self] (tt :jolt/ssl-socket-factory))
     "getProtocol" (fn [_self] "TLS")})

  ;; --- java.net.Authenticator / PasswordAuthentication ----------------------
  (reg-ctor! (both "java.net.Authenticator") (fn [& _] (tt :jolt.http/authenticator)))
  (__register-class-methods! :jolt.http/authenticator
    {"getPasswordAuthentication" (fn [_self] nil)})
  (reg-ctor! (both "java.net.PasswordAuthentication")
    (fn [user pass] (doto (tt :jolt.http/password-auth)
                      (tput! :user user)
                      (tput! :pass (apply str (seq pass))))))
  (__register-class-methods! :jolt.http/password-auth
    {"getUserName" (fn [self] (tget self :user))
     "getPassword" (fn [self] (char-array (tget self :pass)))})

  ;; --- java.net.http --------------------------------------------------------
  (reg-statics! (both "java.net.http.HttpClient$Redirect")
    {"NEVER" :jolt.http.redirect/NEVER
     "ALWAYS" :jolt.http.redirect/ALWAYS
     "NORMAL" :jolt.http.redirect/NORMAL})
  ;; HttpClient.Version values carry their enum name: babashka's response->map
  ;; reads (.name (.version resp)) to recover the version keyword.
  (__register-class-methods! :jolt.http/version-enum
    {"name" (fn [self] (tget self :name))
     "toString" (fn [self] (tget self :name))})
  (let [v11 (doto (tt :jolt.http/version-enum) (tput! :name "HTTP_1_1"))
        v2  (doto (tt :jolt.http/version-enum) (tput! :name "HTTP_2"))]
    (reg-statics! (both "java.net.http.HttpClient$Version") {"HTTP_1_1" v11 "HTTP_2" v2}))

  (reg-statics! (both "java.net.http.HttpClient")
    {"newBuilder" (fn [& _] (tt :jolt.http/client-builder))
     "newHttpClient" (fn [& _] (tt :jolt.http/client))})
  (let [carry [:connect-timeout :follow-redirects :version :ssl-context :ssl-parameters
               :proxy :authenticator :cookie-handler :executor :priority]]
    (__register-class-methods! :jolt.http/client-builder
      {"connectTimeout"  (fn [self d] (tput! self :connect-timeout d) self)
       "followRedirects" (fn [self r] (tput! self :follow-redirects r) self)
       "version"         (fn [self v] (tput! self :version v) self)
       "sslContext"      (fn [self c] (tput! self :ssl-context c) self)
       "sslParameters"   (fn [self p] (tput! self :ssl-parameters p) self)
       "proxy"           (fn [self p] (tput! self :proxy p) self)
       "authenticator"   (fn [self a] (tput! self :authenticator a) self)
       "cookieHandler"   (fn [self h] (tput! self :cookie-handler h) self)
       "executor"        (fn [self e] (tput! self :executor e) self)
       "priority"        (fn [self n] (tput! self :priority n) self)
       "build"           (fn [self]
                           (let [c (tt :jolt.http/client)]
                             (doseq [k carry] (tput! c k (tget self k)))
                             c))}))
  (__register-class-methods! :jolt.http/client
    {"connectTimeout"  (fn [self] (let [d (tget self :connect-timeout)]
                                    (if d (java.util.Optional/of d) (java.util.Optional/empty))))
     "followRedirects" (fn [self] (or (tget self :follow-redirects) :jolt.http.redirect/NEVER))
     "version"         (fn [self] (or (tget self :version)
                                      (doto (tt :jolt.http/version-enum) (tput! :name "HTTP_1_1"))))
     "sslContext"      (fn [self] (or (tget self :ssl-context) (tt :jolt/ssl-context)))
     "sslParameters"   (fn [self] (or (tget self :ssl-parameters) (tt :jolt.http/ssl-parameters)))
     "cookieHandler"   (fn [self] (let [h (tget self :cookie-handler)]
                                    (if h (java.util.Optional/of h) (java.util.Optional/empty))))
     "authenticator"   (fn [self] (let [a (tget self :authenticator)]
                                    (if a (java.util.Optional/of a) (java.util.Optional/empty))))
     "proxy"           (fn [self] (let [p (tget self :proxy)]
                                    (if p (java.util.Optional/of p) (java.util.Optional/empty))))
     "executor"        (fn [self] (let [e (tget self :executor)]
                                    (if e (java.util.Optional/of e) (java.util.Optional/empty))))
     "send"            (fn [self req handler] (net-http-send self req handler))
     ;; sendAsync runs on jolt's future pool: a real thread, so the caller's
     ;; CompletableFuture is genuinely pending and thenApply/exceptionally chain
     ;; off it the way they do on the JVM.
     "sendAsync"       (fn [self req handler] (cf-async (fn [] (net-http-send self req handler))))
     "newWebSocketBuilder" (fn [self]
                             (if-let [f @websocket-builder]
                               (f self)
                               (throw-typed "java.lang.UnsupportedOperationException"
                                            "WebSocket support needs jolt.http.websocket to be loaded")))
     "close"           (fn [_self] nil)
     "shutdown"        (fn [_self] nil)})

  (reg-statics! (both "java.net.http.HttpRequest")
    {"newBuilder" (fn [& args]
                    (let [b (doto (tt :jolt.http/request-builder) (tput! :headers []))]
                      (when-let [uri (first args)] (tput! b :uri uri))
                      b))})
  (__register-class-methods! :jolt.http/request-builder
    {"uri"     (fn [self uri] (tput! self :uri uri) self)
     "method"  (fn [self m bp] (tput! self :method (str m)) (tput! self :body bp) self)
     "GET"     (fn [self] (tput! self :method "GET") self)
     "POST"    (fn [self bp] (tput! self :method "POST") (tput! self :body bp) self)
     "PUT"     (fn [self bp] (tput! self :method "PUT") (tput! self :body bp) self)
     "DELETE"  (fn [self] (tput! self :method "DELETE") self)
     "HEAD"    (fn [self] (tput! self :method "HEAD") self)
     "header"  (fn [self k v] (check-header! k)
                 (tput! self :headers (conj (tget self :headers) [(str k) (str v)])) self)
     ;; setHeader replaces every existing value for the name; header appends.
     "setHeader" (fn [self k v]
                   (check-header! k)
                   (tput! self :headers (conj (drop-header (tget self :headers) (str k)) [(str k) (str v)]))
                   self)
     ;; HttpRequest.Builder.headers(String...): a flat name/value array (babashka
     ;; passes (into-array String (coerce-headers headers))).
     "headers" (fn [self arr]
                 (let [pairs (map vec (partition 2 (vec arr)))]
                   (doseq [[k _] pairs] (check-header! k))
                   (tput! self :headers (into (tget self :headers) pairs)))
                 self)
     "expectContinue" (fn [self _] self)   ; no-op; the socket path doesn't 100-continue
     "version" (fn [self v] (tput! self :version v) self)
     "timeout" (fn [self d] (tput! self :timeout d) self)
     "copy"    (fn [self] (let [b (tt :jolt.http/request-builder)]
                            (doseq [k [:uri :method :body :timeout :headers :version]]
                              (tput! b k (tget self k)))
                            b))
     "build"   (fn [self] (doto (tt :jolt.http/request)
                            (tput! :uri (tget self :uri))
                            (tput! :method (or (tget self :method) "GET"))
                            (tput! :timeout (tget self :timeout))
                            (tput! :version (tget self :version))
                            (tput! :headers (tget self :headers))
                            (tput! :body (tget self :body))))})
  (__register-class-methods! :jolt.http/request
    {"uri"     (fn [self] (tget self :uri))
     "method"  (fn [self] (tget self :method))
     "version" (fn [self] (let [v (tget self :version)]
                            (if v (java.util.Optional/of v) (java.util.Optional/empty))))
     "timeout" (fn [self] (let [d (tget self :timeout)]
                            (if d (java.util.Optional/of d) (java.util.Optional/empty))))
     "bodyPublisher" (fn [self] (let [b (tget self :body)]
                                  (if b (java.util.Optional/of b) (java.util.Optional/empty))))
     "expectContinue" (fn [_self] false)
     "headers" (fn [self] (doto (tt :jolt.http/headers) (tput! :pairs (tget self :headers))))})
  ;; HttpHeaders.map() groups to {name [values]} (java.net.http always vectors
  ;; values) with LOWERCASED names, like java.net.http — babashka's response->map
  ;; and callers look keys up lower-case. firstValue matches case-insensitively.
  (__register-class-methods! :jolt.http/headers
    {"map" (fn [self] (headers->map (tget self :pairs)))
     "allValues" (fn [self k] (get (headers->map (tget self :pairs)) (str/lower-case k) []))
     "firstValue" (fn [self k] (let [low (str/lower-case k)]
                                 (if-let [p (first (filter #(= low (str/lower-case (first %))) (tget self :pairs)))]
                                   (java.util.Optional/of (second p)) (java.util.Optional/empty))))})

  (reg-statics! (both "java.net.http.HttpRequest$BodyPublishers")
    {"noBody"        (fn [& _] (doto (tt :jolt.http/body-bytes) (tput! :bytes nil)))
     "ofByteArray"   (fn [ba & _] (doto (tt :jolt.http/body-bytes) (tput! :bytes (byte-array ba))))
     "ofString"      (fn [s & _] (doto (tt :jolt.http/body-bytes) (tput! :bytes (core/->bytes (str s)))))
     ;; ofInputStream takes a Supplier<InputStream>; ofFile a Path. Both are read
     ;; eagerly to a byte[] here — the transport writes a Content-Length body, so
     ;; the length has to be known before the first byte goes out.
     "ofInputStream" (fn [supplier & _]
                       (doto (tt :jolt.http/body-bytes)
                         (tput! :bytes (core/->bytes (.get supplier)))))
     ;; ofFile reads BYTES. It used to slurp the path, which decodes as text:
     ;; every byte a UTF-8 decoder could not make sense of came back as U+FFFD
     ;; and re-encoded wider, so a 256-byte binary file went out as 512 bytes of
     ;; something else. Any file that is not valid UTF-8 text — an image, a zip,
     ;; a protobuf — was silently corrupted.
     "ofFile"        (fn [path & _]
                       (doto (tt :jolt.http/body-bytes)
                         (tput! :bytes (core/->bytes (clojure.java.io/input-stream (str path))))))})
  (__register-class-methods! :jolt.http/body-bytes
    {"contentLength" (fn [self] (if-let [b (tget self :bytes)] (alength b) 0))})

  (let [handlers {"ofByteArray"   (fn [& _] :jolt.http/handler-bytes)
                  "ofString"      (fn [& _] :jolt.http/handler-string)
                  "ofInputStream" (fn [& _] :jolt.http/handler-inputstream)
                  "discarding"    (fn [& _] :jolt.http/handler-discarding)}]
    (reg-statics! (both "java.net.http.HttpResponse$BodyHandlers") handlers))
  (__register-class-methods! :jolt.http/response
    {"statusCode" (fn [self] (tget self :status))
     "body"       (fn [self] (tget self :body))
     "uri"        (fn [self] (tget self :uri))
     "request"    (fn [self] (tget self :request))
     "version"    (fn [self] (or (tget self :version)
                                 (doto (tt :jolt.http/version-enum) (tput! :name "HTTP_1_1"))))
     "headers"    (fn [self] (doto (tt :jolt.http/headers) (tput! :pairs (tget self :resp-headers))))
     "previousResponse" (fn [_self] (java.util.Optional/empty))})

  ;; instance? for the shim types a caller gates on.
  ;;
  ;; Every class this namespace owns answers with a BOOLEAN, never nil: nil means
  ;; "not mine, keep looking", and for a class jolt has no implementation of that
  ;; is not a fall-through but an error — (instance? java.net.ProxySelector {…})
  ;; on a plain map raised "No dependency provides java.net.ProxySelector"
  ;; instead of returning false.
  (let [owned {"java.util.concurrent.CompletableFuture" ::cf
               "java.util.concurrent.CompletionStage"   ::cf
               "java.util.concurrent.Future"            ::cf
               "java.net.http.HttpRequest$BodyPublisher" :jolt.http/body-bytes
               "javax.net.ssl.SSLContext"        :jolt/ssl-context
               "javax.net.ssl.SSLParameters"     :jolt.http/ssl-parameters
               "javax.net.ssl.TrustManager"      #{:jolt.http/trust-manager :jolt.http/store-manager}
               "javax.net.ssl.X509TrustManager"  #{:jolt.http/trust-manager :jolt.http/store-manager}
               "javax.net.ssl.X509ExtendedTrustManager" #{:jolt.http/trust-manager :jolt.http/store-manager}
               "javax.net.ssl.KeyManager"        :jolt.http/store-manager
               "java.security.KeyStore"          :jolt.http/keystore
               "java.net.CookieHandler"          :jolt.http/cookie-manager
               "java.net.CookieManager"          :jolt.http/cookie-manager
               "java.net.CookieStore"            :jolt.http/cookie-store
               "java.net.HttpCookie"             :jolt.http/cookie
               "java.net.CookiePolicy"           #{}
               "java.net.Proxy"                  :jolt.http/proxy
               "java.net.ProxySelector"          :jolt.http/proxy-selector
               "java.net.Authenticator"          :jolt.http/authenticator
               "java.net.PasswordAuthentication" :jolt.http/password-auth
               "java.net.http.HttpClient"        :jolt.http/client
               "java.net.http.HttpRequest"       :jolt.http/request
               "java.net.http.HttpResponse"      :jolt.http/response
               "java.net.http.HttpHeaders"       :jolt.http/headers}
        ;; a class reaches instance? by simple name as often as by qualified name
        by-name (reduce-kv (fn [m k v] (assoc m k v (last (str/split k #"\.")) v)) {} owned)]
    (__register-instance-check!
      (fn [cn val]
        (when-let [want (get by-name cn)]
          (cond
            ;; a CompletableFuture is a reify, not a table
            (= ::cf want) (cf? val)
            (set? want) (contains? want (type-of val))
            :else (= want (type-of val)))))))
  nil)

(install!)
