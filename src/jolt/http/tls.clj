(ns jolt.http.tls
  "TLS transport over the system OpenSSL, bound through jolt.ffi. SSL runs against
  in-memory BIOs while ciphertext is shuttled over a plain jolt.http.net socket,
  so no raw-fd access into OpenSSL is needed and an in-process client + server can
  share one process.

  libssl/libcrypto are declared in deps.edn (:jolt/native) and loaded before this
  namespace, so the foreign-fn bindings resolve at load. A TLS stream is a host
  tagged-table carrying :write / :read / :close closures; jolt.http.platform
  dispatches socket ops through them."
  (:require [jolt.ffi :as ffi]
            [jolt.http.net :as net]))

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

(defn- ssl-ex [msg]
  (let [t (jolt.host/tagged-table :jolt/ex-info)]
    (jolt.host/ref-put! t :class "javax.net.ssl.SSLException")
    (jolt.host/ref-put! t :message (str msg))
    (jolt.host/ref-put! t :data {})
    t))

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
            :else (throw (ssl-ex (str "TLS handshake failed (SSL_get_error=" err ")")))))))))

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
        (try (c-SSL-CTX-free ctx) (catch Throwable _ nil))
        nil))
    st))

(defn tls-connect
  "Open a TLS client connection to host:port. insecure? disables peer
  verification (self-signed/expired certs accepted)."
  [host port insecure?]
  (let [ctx (c-SSL-CTX-new (c-TLS-client-method))]
    (when (ffi/null? ctx) (throw (ssl-ex "SSL_CTX_new failed")))
    (if insecure?
      (c-SSL-CTX-set-verify ctx VERIFY-NONE ffi/null)
      (do (c-SSL-CTX-default-verify ctx)
          (c-SSL-CTX-set-verify ctx VERIFY-PEER ffi/null)))
    (let [ssl     (c-SSL-new ctx)
          memmeth (c-BIO-s-mem)
          rbio    (c-BIO-new memmeth)
          wbio    (c-BIO-new memmeth)
          host-buf (cstr host)]
      (c-SSL-set-bio ssl rbio wbio)
      (c-SSL-set-connect ssl)
      (c-SSL-ctrl ssl SET-TLSEXT-HOSTNAME NAMETYPE-host-name host-buf)  ; SNI
      (when-not insecure? (c-SSL-set1-host ssl host-buf))
      (let [sock (net/connect host port)
            st   (make-stream sock ssl ctx rbio wbio)]
        (try (handshake! st true)
             (catch Throwable e ((jolt.host/ref-get st :close)) (ffi/free host-buf) (throw e)))
        (ffi/free host-buf)
        st))))

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
