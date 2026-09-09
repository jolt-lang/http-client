(ns jolt.http.tls
  "TLS transport over the system OpenSSL, bound through jolt.ffi. SSL runs against
  in-memory BIOs while ciphertext is shuttled over a plain jolt.http.net socket,
  so no raw-fd access into OpenSSL is needed and an in-process client + server can
  share one process.

  libssl/libcrypto are declared in deps.edn (:jolt/native), but this namespace
  re-loads them itself immediately below — see ensure-openssl!. A TLS stream is a
  host tagged-table carrying :write / :read / :close closures; jolt.http.platform
  dispatches socket ops through them."
  (:require [clojure.string :as str]
            [jolt.ffi :as ffi]
            [jolt.http.net :as net]))

;; --- pinning the right OpenSSL ---------------------------------------------
;; Chez resolves a foreign symbol against loaded shared objects most-recent-first,
;; and `defcfn` resolves when the def is evaluated. So whichever object was loaded
;; last before this namespace loads wins the SSL_* symbols.
;;
;; That is a live hazard on macOS, where the process image transitively links
;; /usr/lib/libssl.dylib — LibreSSL, not OpenSSL. Any library that calls
;; `(ffi/load-library)` with no argument, which loads the running process's own
;; symbols, therefore puts LibreSSL ahead of the OpenSSL that :jolt/native
;; loaded. jolt.nrepl does exactly that at ns load to bind sockets. The result is
;; not a missing symbol but a SILENT MIX: TLS_client_method comes from one
;; implementation and SSL_CTX_new from the other, whose SSL_CTX layouts disagree,
;; and the first call through it faults with "invalid memory reference".
;;
;; Loading the libraries again here re-asserts them as most-recent at exactly the
;; point the bindings below resolve, which makes this namespace independent of
;; who loaded what first. load-shared-object on an already-loaded object is cheap
;; and does not duplicate it. The candidate lists mirror jolt-lang/jolt-crypto's
;; :jolt/native, homebrew before /usr/lib, so the OpenSSL build is preferred and
;; the system LibreSSL is only a last resort.
(def ^:private openssl-candidates
  (if (str/includes? (str/lower-case (or (System/getProperty "os.name") "")) "mac")
    {:crypto ["/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib"
              "/usr/local/opt/openssl@3/lib/libcrypto.dylib"
              "libcrypto.dylib" "/usr/lib/libcrypto.dylib"]
     :ssl    ["/opt/homebrew/opt/openssl@3/lib/libssl.dylib"
              "/usr/local/opt/openssl@3/lib/libssl.dylib"
              "libssl.dylib" "/usr/lib/libssl.dylib"]}
    {:crypto ["libcrypto.so.3" "libcrypto.so.1.1" "libcrypto.so"]
     :ssl    ["libssl.so.3" "libssl.so.1.1" "libssl.so"]}))

(defn- load-first! [candidates]
  (some (fn [path]
          (when (try (ffi/load-library path) true (catch Throwable _ false))
            path))
        candidates))

;; crypto first, then ssl: ssl ends up most-recent and wins SSL_*, while symbols
;; it does not define (EVP_*, ERR_*) fall through to crypto, still ahead of the
;; process. Returns the pair actually loaded, which the AOT/load-order tests read.
(defn ensure-openssl! []
  {:crypto (load-first! (:crypto openssl-candidates))
   :ssl    (load-first! (:ssl openssl-candidates))})

(def loaded-openssl (ensure-openssl!))

;; SSL_get_error codes / verify modes / ctrl commands.
(def ^:private WANT-READ 2)
(def ^:private WANT-WRITE 3)
(def ^:private VERIFY-NONE 0)
(def ^:private VERIFY-PEER 1)
(def ^:private BIO-PENDING 10)
(def ^:private SET-TLSEXT-HOSTNAME 55)
(def ^:private NAMETYPE-host-name 0)
(def ^:private FILETYPE-PEM 1)
(def ^:private chunk 16384)

(ffi/defcfn c-TLS-client-method "TLS_client_method" [] :pointer)
(ffi/defcfn c-TLS-server-method "TLS_server_method" [] :pointer)
(ffi/defcfn c-SSL-CTX-new       "SSL_CTX_new"       [:pointer] :pointer)
(ffi/defcfn c-SSL-CTX-free      "SSL_CTX_free"      [:pointer] :void)
(ffi/defcfn c-SSL-CTX-set-verify "SSL_CTX_set_verify" [:pointer :int :pointer] :void)
(ffi/defcfn c-SSL-CTX-default-verify "SSL_CTX_set_default_verify_paths" [:pointer] :int)
(ffi/defcfn c-SSL-CTX-use-cert  "SSL_CTX_use_certificate_file" [:pointer :pointer :int] :int)
(ffi/defcfn c-SSL-CTX-use-key   "SSL_CTX_use_PrivateKey_file"  [:pointer :pointer :int] :int)
(ffi/defcfn c-SSL-new           "SSL_new"           [:pointer] :pointer)
(ffi/defcfn c-SSL-free          "SSL_free"          [:pointer] :void)
(ffi/defcfn c-SSL-set-bio       "SSL_set_bio"       [:pointer :pointer :pointer] :void)
(ffi/defcfn c-SSL-set-connect   "SSL_set_connect_state" [:pointer] :void)
(ffi/defcfn c-SSL-set-accept    "SSL_set_accept_state"  [:pointer] :void)
(ffi/defcfn c-SSL-connect       "SSL_connect"       [:pointer] :int)
(ffi/defcfn c-SSL-accept        "SSL_accept"        [:pointer] :int)
(ffi/defcfn c-SSL-read          "SSL_read"          [:pointer :pointer :int] :int)
(ffi/defcfn c-SSL-write         "SSL_write"         [:pointer :pointer :int] :int)
(ffi/defcfn c-SSL-get-error     "SSL_get_error"     [:pointer :int] :int)
(ffi/defcfn c-SSL-ctrl          "SSL_ctrl"          [:pointer :int :int64 :pointer] :int64)
(ffi/defcfn c-SSL-shutdown      "SSL_shutdown"      [:pointer] :int)
(ffi/defcfn c-SSL-set1-host     "SSL_set1_host"     [:pointer :pointer] :int)
(ffi/defcfn c-BIO-new           "BIO_new"           [:pointer] :pointer)
(ffi/defcfn c-BIO-s-mem         "BIO_s_mem"         [] :pointer)
(ffi/defcfn c-BIO-read          "BIO_read"          [:pointer :pointer :int] :int)
(ffi/defcfn c-BIO-write         "BIO_write"         [:pointer :pointer :int] :int)
(ffi/defcfn c-BIO-ctrl          "BIO_ctrl"          [:pointer :int :int64 :pointer] :int64)
;; PKCS#12 material: what a caller's :key-store / :trust-store actually holds.
;; libcrypto side, so these resolve off the crypto object loaded above.
(ffi/defcfn c-BIO-new-mem-buf   "BIO_new_mem_buf"   [:pointer :int] :pointer)
(ffi/defcfn c-BIO-free          "BIO_free"          [:pointer] :int)
(ffi/defcfn c-d2i-PKCS12-bio    "d2i_PKCS12_bio"    [:pointer :pointer] :pointer)
(ffi/defcfn c-PKCS12-parse      "PKCS12_parse"      [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-PKCS12-free       "PKCS12_free"       [:pointer] :void)
(ffi/defcfn c-X509-free         "X509_free"         [:pointer] :void)
(ffi/defcfn c-EVP-PKEY-free     "EVP_PKEY_free"     [:pointer] :void)
(ffi/defcfn c-sk-num            "OPENSSL_sk_num"    [:pointer] :int)
(ffi/defcfn c-sk-value          "OPENSSL_sk_value"  [:pointer :int] :pointer)
(ffi/defcfn c-sk-free           "OPENSSL_sk_free"   [:pointer] :void)
(ffi/defcfn c-SSL-CTX-use-cert-x509 "SSL_CTX_use_certificate" [:pointer :pointer] :int)
(ffi/defcfn c-SSL-CTX-use-key-evp   "SSL_CTX_use_PrivateKey"  [:pointer :pointer] :int)
(ffi/defcfn c-SSL-CTX-cert-store "SSL_CTX_get_cert_store" [:pointer] :pointer)
(ffi/defcfn c-X509-STORE-add-cert "X509_STORE_add_cert" [:pointer :pointer] :int)

(defn- ssl-ex
  "A typed SSLException carrying a real message. Built through
   jolt.host/throwable — the same path jolt.http.net's conn-ex uses — because a
   raw :jolt/ex-info tagged table throws fine but never wires :message into
   ex-message/.getMessage, so every TLS failure surfaced as a bare
   #object[javax.net.ssl.SSLException] with nil cause, hiding the actual error."
  [msg]
  (jolt.host/throwable "javax.net.ssl.SSLException" (str msg)))

;; A NUL-terminated C-string pointer; the caller frees it.
(defn- cstr [s] (ffi/string->ptr (str s)))

(defn- bio-pending [bio] (c-BIO-ctrl bio BIO-PENDING 0 ffi/null))

;; Drain ciphertext OpenSSL produced into wbio out to the socket.
(defn- flush-out [st]
  (let [wbio (jolt.host/ref-get st :wbio)
        sock (jolt.host/ref-get st :sock)]
    (loop []
      (let [p (bio-pending wbio)]
        (when (pos? p)
          (let [buf (ffi/alloc p)
                n   (c-BIO-read wbio buf p)]
            (when (pos? n) (net/send-bytes sock (ffi/read-array buf n)))
            (ffi/free buf)
            (recur)))))))

;; Pull one ciphertext chunk off the socket into rbio; false at EOF.
(defn- feed-in [st]
  (let [data (net/recv-bytes (jolt.host/ref-get st :sock))]
    (if (and data (pos? (alength data)))
      (let [n (alength data) buf (ffi/alloc n)]
        (ffi/write-array buf data)
        (c-BIO-write (jolt.host/ref-get st :rbio) buf n)
        (ffi/free buf)
        true)
      false)))

(defn- handshake! [st connect?]
  ;; A transport failure inside the handshake (reset, timeout, EOF from
  ;; feed-in/flush-out) surfaces as SSLException — the way javax.net.ssl wraps
  ;; "Remote host terminated the handshake". Letting the transport's own
  ;; SocketException/SocketTimeoutException escape told callers a read timed
  ;; out on a socket that never had a timeout, which is exactly the
  ;; misdirection self-signed-ssl-get's flake printed. The transport classes
  ;; still surface from the data phase (:read/:write), where java.net would
  ;; report them too.
  (letfn [(drive! []
            (loop []
              (let [ret (if connect? (c-SSL-connect (jolt.host/ref-get st :ssl))
                          (c-SSL-accept (jolt.host/ref-get st :ssl)))]
                (flush-out st)
                (when-not (= ret 1)
                  (let [err (c-SSL-get-error (jolt.host/ref-get st :ssl) ret)]
                    (cond
                      (= err WANT-READ) (do (when-not (feed-in st)
                                              (throw (ssl-ex "connection closed during TLS handshake")))
                                            (recur))
                      (= err WANT-WRITE) (recur)
                      :else (throw (ssl-ex (str "TLS handshake failed (SSL_get_error=" err ")")))))))))]
    (try
      (drive!)
      (catch Throwable e
        ;; (str (class e)) carries a leading "class ", so match with it — without
        ;; it no transport exception ever matched and all rethrew unwrapped.
        (if (str/starts-with? (str (class e)) "class java.net.")
          (throw (ssl-ex (str (ex-message e) " during TLS handshake")))
          (throw e))))))

(defn- make-stream [sock ssl ctx rbio wbio]
  (let [st (jolt.host/tagged-table :jolt/tls-stream)]
    (jolt.host/ref-put! st :sock sock) (jolt.host/ref-put! st :ssl ssl)
    (jolt.host/ref-put! st :ctx ctx) (jolt.host/ref-put! st :rbio rbio)
    (jolt.host/ref-put! st :wbio wbio) (jolt.host/ref-put! st :eof false)
    (jolt.host/ref-put! st :write
      (fn [self data]
        (let [n (alength data) buf (ffi/alloc (max 1 n))]
          (ffi/write-array buf data)
          (try
            (loop [off 0]
              (when (< off n)
                (let [wrote (c-SSL-write (jolt.host/ref-get self :ssl) (+ buf off) (- n off))]
                  (flush-out self)
                  (if (pos? wrote)
                    (recur (+ off wrote))
                    (let [err (c-SSL-get-error (jolt.host/ref-get self :ssl) wrote)]
                      (if (or (= err WANT-READ) (= err WANT-WRITE))
                        (do (feed-in self) (recur off))
                        (throw (ssl-ex "TLS write failed"))))))))
            (finally (ffi/free buf)))
          self)))
    (jolt.host/ref-put! st :read
      ;; return a decrypted byte-array chunk, or nil at EOF.
      (fn [self _timeout]
        (when-not (jolt.host/ref-get self :eof)
          (let [tmp (ffi/alloc chunk)]
            (try
              (loop []
                (let [got (c-SSL-read (jolt.host/ref-get self :ssl) tmp chunk)]
                  (if (pos? got)
                    (ffi/read-array tmp got)
                    (let [err (c-SSL-get-error (jolt.host/ref-get self :ssl) got)]
                      (cond
                        (= err WANT-READ) (if (feed-in self) (recur)
                                              (do (jolt.host/ref-put! self :eof true) nil))
                        (= err WANT-WRITE) (do (flush-out self) (recur))
                        :else (do (jolt.host/ref-put! self :eof true) nil))))))
              (finally (ffi/free tmp)))))))
    (jolt.host/ref-put! st :close
      (fn [& _]
        (try (c-SSL-shutdown ssl) (catch Throwable _ nil))
        (try (net/close sock) (catch Throwable _ nil))
        (try (c-SSL-free ssl) (catch Throwable _ nil))
        ;; the SSL_CTX is NOT freed here: client contexts are shared out of
        ;; ctx-cache and outlive any one connection. A server context is built
        ;; per accept and freed by tls-wrap-server's own failure path.
        nil))
    st))


;; --- PKCS#12 key / trust stores --------------------------------------------
;; babashka's `:ssl-context {:key-store … :trust-store …}` is a PKCS#12 file and a
;; password, which is what java.net.http's KeyManagerFactory/TrustManagerFactory
;; consume. OpenSSL reads the same container: parse it once, then a key store
;; becomes the client certificate + private key on the SSL_CTX and a trust store
;; becomes the CA set in the context's X509_STORE.

(defn- parse-pkcs12
  "Parse DER PKCS#12 `bytes` with `pass`. Returns {:key :cert :cas [ptr…]
  :free (fn [])} or throws. Every pointer stays owned by the caller until :free."
  [bytes pass]
  (let [n (alength bytes)
        buf (ffi/alloc (max 1 n))
        _ (ffi/write-array buf bytes)
        bio (c-BIO-new-mem-buf buf n)]
    (when (ffi/null? bio)
      (ffi/free buf)
      (throw (ssl-ex "cannot read key/trust store into memory")))
    (let [p12 (c-d2i-PKCS12-bio bio ffi/null)]
      (c-BIO-free bio)
      (when (ffi/null? p12)
        (ffi/free buf)
        (throw (ssl-ex "key/trust store is not a PKCS#12 container")))
      (let [pkey-out (ffi/alloc 8)
            cert-out (ffi/alloc 8)
            ca-out   (ffi/alloc 8)
            pass-buf (cstr (or pass ""))]
        (ffi/write pkey-out :pointer ffi/null 0)
        (ffi/write cert-out :pointer ffi/null 0)
        (ffi/write ca-out :pointer ffi/null 0)
        (let [rc (c-PKCS12-parse p12 pass-buf pkey-out cert-out ca-out)]
          (ffi/free pass-buf)
          (when (zero? rc)
            (c-PKCS12-free p12)
            (ffi/free pkey-out) (ffi/free cert-out) (ffi/free ca-out) (ffi/free buf)
            (throw (ssl-ex "cannot parse key/trust store — wrong password or not PKCS#12")))
          (let [pkey (ffi/read pkey-out :pointer 0)
                cert (ffi/read cert-out :pointer 0)
                cas  (ffi/read ca-out :pointer 0)
                ca-list (if (ffi/null? cas)
                          []
                          (vec (for [i (range (c-sk-num cas))] (c-sk-value cas i))))]
            (ffi/free pkey-out) (ffi/free cert-out) (ffi/free ca-out)
            {:key (when-not (ffi/null? pkey) pkey)
             :cert (when-not (ffi/null? cert) cert)
             :cas ca-list
             :free (fn []
                     (when-not (ffi/null? pkey) (c-EVP-PKEY-free pkey))
                     (when-not (ffi/null? cert) (c-X509-free cert))
                     (doseq [c ca-list] (c-X509-free c))
                     (when-not (ffi/null? cas) (c-sk-free cas))
                     (c-PKCS12-free p12)
                     (ffi/free buf))}))))))

(defn- apply-key-store! [ctx {:keys [bytes pass]}]
  (let [{:keys [key cert free]} (parse-pkcs12 bytes pass)]
    (try
      (when (and cert (not= 1 (c-SSL-CTX-use-cert-x509 ctx cert)))
        (throw (ssl-ex "cannot use the key store's certificate")))
      (when (and key (not= 1 (c-SSL-CTX-use-key-evp ctx key)))
        (throw (ssl-ex "cannot use the key store's private key")))
      (finally (free)))))

(defn- apply-trust-store! [ctx {:keys [bytes pass]}]
  (let [{:keys [cert cas free]} (parse-pkcs12 bytes pass)
        store (c-SSL-CTX-cert-store ctx)]
    (try
      ;; A trust store is a bag of CAs; PKCS12_parse hands the leaf back
      ;; separately from the chain, and both are trust anchors here.
      (doseq [c (cons cert cas) :when c] (c-X509-STORE-add-cert store c))
      (finally (free)))))

(defn- build-client-ctx
  "A client SSL_CTX configured for `insecure?` and the caller's stores. A trust
  store REPLACES the platform CA set, the way a TrustManagerFactory over a
  truststore does on the JVM."
  [insecure? {:keys [key-store trust-store] :as _ssl}]
  (let [ctx (c-SSL-CTX-new (c-TLS-client-method))]
    (when (ffi/null? ctx) (throw (ssl-ex "SSL_CTX_new failed")))
    (try
      (when key-store (apply-key-store! ctx key-store))
      (if insecure?
        (c-SSL-CTX-set-verify ctx VERIFY-NONE ffi/null)
        (do (if trust-store
              (apply-trust-store! ctx trust-store)
              (c-SSL-CTX-default-verify ctx))
            (c-SSL-CTX-set-verify ctx VERIFY-PEER ffi/null)))
      ctx
      (catch Throwable e (c-SSL-CTX-free ctx) (throw e)))))

;; A verifying SSL_CTX loads the platform CA bundle in
;; SSL_CTX_set_default_verify_paths, and building one measured 5.7 ms against
;; 0.09 ms for an insecure one — paid per REQUEST, since every connection built
;; its own context. An SSL_CTX is designed to be shared across connections
;; (SSL_new takes a reference), so contexts are cached by exactly what
;; configures them: the verify mode and the caller's PKCS#12 material.
;;
;; The cache owns every context it hands out, which is why make-stream's close
;; frees the SSL but not the SSL_CTX. Nothing evicts: the number of distinct
;; TLS configurations in a process is the number of clients an app builds, not
;; a function of how many requests it makes.
(def ^:private ctx-cache (atom {}))

(defn- ctx-key [insecure? ssl]
  ;; the stores are byte-arrays; identity is what distinguishes two clients,
  ;; and hashing megabytes of PKCS#12 per request would defeat the point
  [(boolean insecure?)
   (when-let [ks (:key-store ssl)] [(System/identityHashCode (:bytes ks)) (:pass ks)])
   (when-let [ts (:trust-store ssl)] [(System/identityHashCode (:bytes ts)) (:pass ts)])])

(defn- client-ctx [insecure? ssl]
  (let [k (ctx-key insecure? ssl)]
    (or (get @ctx-cache k)
        ;; build outside the swap!, then let the first writer win and free the
        ;; loser — swap! may retry, and an SSL_CTX built inside it would leak
        (let [ctx (build-client-ctx insecure? ssl)
              winner (get (swap! ctx-cache (fn [m] (if (contains? m k) m (assoc m k ctx)))) k)]
          (when-not (= winner ctx) (c-SSL-CTX-free ctx))
          winner))))

(defn- start-client-session
  "Build the SSL object + memory BIOs for a client handshake over `sock`, run the
  handshake and return the stream. Owns ctx from here on."
  [ctx sock host insecure?]
  (let [ssl     (c-SSL-new ctx)
        memmeth (c-BIO-s-mem)
        rbio    (c-BIO-new memmeth)
        wbio    (c-BIO-new memmeth)
        host-buf (cstr host)]
    (c-SSL-set-bio ssl rbio wbio)
    (c-SSL-set-connect ssl)
    (c-SSL-ctrl ssl SET-TLSEXT-HOSTNAME NAMETYPE-host-name host-buf)  ; SNI
    (when-not insecure? (c-SSL-set1-host ssl host-buf))
    (let [st (make-stream sock ssl ctx rbio wbio)]
      (try (handshake! st true)
           (catch Throwable e ((jolt.host/ref-get st :close)) (ffi/free host-buf) (throw e)))
      (ffi/free host-buf)
      st)))

(defn tls-wrap-client
  "Run the client side of a TLS handshake over an ALREADY CONNECTED socket fd.
  This is what a proxy CONNECT tunnel needs: the TCP connection goes to the
  proxy, the handshake goes to the origin, and `host` is the origin's name — so
  SNI and certificate verification both name the origin, not the proxy."
  ([sock host insecure?] (tls-wrap-client sock host insecure? nil))
  ([sock host insecure? ssl]
   (start-client-session (client-ctx insecure? ssl) sock host insecure?)))

(defn tls-connect
  "Open a TLS client connection to host:port. insecure? disables peer
  verification (self-signed/expired certs accepted). read-timeout, in
  milliseconds, bounds every recv on the underlying socket — both the handshake
  and the ciphertext reads that back SSL_read — so a peer that accepts the
  connection and then goes silent surfaces as a SocketTimeoutException rather
  than parking the calling thread forever. conn-timeout, in milliseconds, bounds
  the connect itself."
  ([host port insecure?] (tls-connect host port insecure? nil nil))
  ([host port insecure? read-timeout] (tls-connect host port insecure? read-timeout nil))
  ([host port insecure? read-timeout conn-timeout]
   (tls-connect host port insecure? read-timeout conn-timeout nil))
  ([host port insecure? read-timeout conn-timeout ssl]
   (let [ctx  (client-ctx insecure? ssl)
         ;; no c-SSL-CTX-free on failure: ctx is shared out of the cache
         sock (net/connect host port conn-timeout)]
     (net/set-read-timeout! sock read-timeout)
     (start-client-session ctx sock host insecure?))))

(defn tls-wrap-server
  "Wrap an accepted plain socket fd `sock` as the server side of a TLS session,
  using PEM `cert-file` and `key-file`. Returns a TLS stream."
  [sock cert-file key-file]
  (let [ctx (c-SSL-CTX-new (c-TLS-server-method))
        cf  (cstr cert-file)
        kf  (cstr key-file)]
    (try
      (when (zero? (c-SSL-CTX-use-cert ctx cf FILETYPE-PEM))
        (throw (ssl-ex (str "cannot load cert " cert-file))))
      (when (zero? (c-SSL-CTX-use-key ctx kf FILETYPE-PEM))
        (throw (ssl-ex (str "cannot load key " key-file))))
      (finally (ffi/free cf) (ffi/free kf)))
    (let [ssl     (c-SSL-new ctx)
          memmeth (c-BIO-s-mem)
          rbio    (c-BIO-new memmeth)
          wbio    (c-BIO-new memmeth)]
      (c-SSL-set-bio ssl rbio wbio)
      (c-SSL-set-accept ssl)
      (let [st (make-stream sock ssl ctx rbio wbio)]
        (handshake! st false)
        st))))
