(ns jolt.http.tls
  "TLS transport over the system OpenSSL, via Jolt's Janet FFI bridge. SSL runs
  against in-memory BIOs while ciphertext is shuttled over a plain Janet net
  stream, so TLS I/O cooperates with the ev loop (an in-process server + client
  can share one process) and no raw fd access is needed.

  Lazy: OpenSSL loads only on first https use; FFI handles/signatures live in an
  atom, never as module-level (unmarshalable) values.")

;; constants
(def ^:private WANT-READ 2)
(def ^:private WANT-WRITE 3)
(def ^:private ZERO-RETURN 6)
(def ^:private SYSCALL 5)
(def ^:private VERIFY-NONE 0)
(def ^:private VERIFY-PEER 1)
(def ^:private BIO-PENDING 10)
(def ^:private SET-TLSEXT-HOSTNAME 55)
(def ^:private NAMETYPE-host-name 0)
(def ^:private FILETYPE-PEM 1)

(def ^:private state (atom nil))

;; Build a throwable carrying a JVM :class name so (class e) / clojure.test's
;; thrown? match it (core's core-class reads :class off the thrown table).
(defn- ssl-ex [msg]
  (let [t (janet.table/new 8)]
    (janet/put t :jolt/type :jolt/ex-info)
    (janet/put t :class "javax.net.ssl.SSLException")
    (janet/put t :message (str msg))
    (janet/put t :data {})
    t))

(defn- load! []
  (or @state
      (let [try-pair (fn [s c]
                       (let [a (try (janet.ffi/native s) (catch Throwable _ nil))
                             b (when a (try (janet.ffi/native c) (catch Throwable _ nil)))]
                         (when (and a b) [a b])))
            pair (or (try-pair "/opt/homebrew/opt/openssl@3/lib/libssl.dylib"
                               "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib")
                     (try-pair "/usr/lib/libssl.dylib" "/usr/lib/libcrypto.dylib")
                     (try-pair "libssl.so.3" "libcrypto.so.3")
                     (try-pair "libssl.so.1.1" "libcrypto.so.1.1")
                     (try-pair "libssl.so" "libcrypto.so")
                     (throw (ssl-ex "TLS: could not load OpenSSL (libssl/libcrypto)")))
            [ssl-lib cr-lib] pair
            sig (fn [ret & args] (apply janet.ffi/signature :default ret args))
            reg (fn [lib name signature] [(janet.ffi/lookup lib name) signature])
            s {:fns
               {"TLS_client_method"           (reg ssl-lib "TLS_client_method" (sig :ptr))
                "TLS_server_method"           (reg ssl-lib "TLS_server_method" (sig :ptr))
                "SSL_CTX_new"                 (reg ssl-lib "SSL_CTX_new" (sig :ptr :ptr))
                "SSL_CTX_free"                (reg ssl-lib "SSL_CTX_free" (sig :void :ptr))
                "SSL_CTX_set_verify"          (reg ssl-lib "SSL_CTX_set_verify" (sig :void :ptr :int :ptr))
                "SSL_CTX_set_default_verify_paths" (reg ssl-lib "SSL_CTX_set_default_verify_paths" (sig :int :ptr))
                "SSL_CTX_use_certificate_file" (reg ssl-lib "SSL_CTX_use_certificate_file" (sig :int :ptr :ptr :int))
                "SSL_CTX_use_PrivateKey_file" (reg ssl-lib "SSL_CTX_use_PrivateKey_file" (sig :int :ptr :ptr :int))
                "SSL_new"                     (reg ssl-lib "SSL_new" (sig :ptr :ptr))
                "SSL_free"                    (reg ssl-lib "SSL_free" (sig :void :ptr))
                "SSL_set_bio"                 (reg ssl-lib "SSL_set_bio" (sig :void :ptr :ptr :ptr))
                "SSL_set_connect_state"       (reg ssl-lib "SSL_set_connect_state" (sig :void :ptr))
                "SSL_set_accept_state"        (reg ssl-lib "SSL_set_accept_state" (sig :void :ptr))
                "SSL_connect"                 (reg ssl-lib "SSL_connect" (sig :int :ptr))
                "SSL_accept"                  (reg ssl-lib "SSL_accept" (sig :int :ptr))
                "SSL_read"                    (reg ssl-lib "SSL_read" (sig :int :ptr :ptr :int))
                "SSL_write"                   (reg ssl-lib "SSL_write" (sig :int :ptr :ptr :int))
                "SSL_get_error"               (reg ssl-lib "SSL_get_error" (sig :int :ptr :int))
                "SSL_ctrl"                    (reg ssl-lib "SSL_ctrl" (sig :s64 :ptr :int :s64 :ptr))
                "SSL_shutdown"                (reg ssl-lib "SSL_shutdown" (sig :int :ptr))
                "SSL_set1_host"               (reg ssl-lib "SSL_set1_host" (sig :int :ptr :ptr))
                "BIO_new"                     (reg cr-lib "BIO_new" (sig :ptr :ptr))
                "BIO_s_mem"                   (reg cr-lib "BIO_s_mem" (sig :ptr))
                "BIO_read"                    (reg cr-lib "BIO_read" (sig :int :ptr :ptr :int))
                "BIO_write"                   (reg cr-lib "BIO_write" (sig :int :ptr :ptr :int))
                "BIO_ctrl"                    (reg cr-lib "BIO_ctrl" (sig :s64 :ptr :int :s64 :ptr))}}]
        (reset! state s)
        s)))

(defn- C [name & args]
  (let [[ptr sig] (get (:fns (load!)) name)]
    (apply janet.ffi/call ptr sig args)))

;; A NUL-terminated C string buffer. (Jolt's "\0" string escape yields the char
;; '0', not a NUL, so build the terminator explicitly with push-byte.)
(defn- cstr [s]
  (let [b (janet/buffer (str s))] (janet.buffer/push-byte b 0) b))

(defn- bio-pending [bio] (janet.int/to-number (C "BIO_ctrl" bio BIO-PENDING 0 nil)))

(defn- flush-out [st]
  (let [wbio (janet/get st :wbio) sock (janet/get st :sock)]
    (loop []
      (let [p (bio-pending wbio)]
        (when (pos? p)
          (let [buf (janet.buffer/new-filled p 0)
                n (C "BIO_read" wbio buf p)]
            (when (pos? n) (janet.net/write sock (janet.buffer/slice buf 0 n)))
            (recur)))))))

(defn- feed-in [st timeout]
  (let [sock (janet/get st :sock)
        data (if timeout (janet.net/read sock 16384 (janet/buffer "") timeout) (janet.net/read sock 16384))]
    (if (and data (pos? (janet/length data)))
      (do (C "BIO_write" (janet/get st :rbio) data (janet/length data)) true)
      false)))

(defn- handshake! [st connect?]
  (loop []
    (let [ret (C (if connect? "SSL_connect" "SSL_accept") (janet/get st :ssl))]
      (flush-out st)
      (when-not (= ret 1)
        (let [err (C "SSL_get_error" (janet/get st :ssl) ret)]
          (cond
            (= err WANT-READ) (do (when-not (feed-in st nil)
                                    (throw (ssl-ex "connection closed during TLS handshake")))
                                  (recur))
            (= err WANT-WRITE) (recur)
            :else (throw (ssl-ex (str "TLS handshake failed (SSL_get_error=" err ")")))))))))

(defn- make-stream [sock ssl ctx rbio wbio]
  (let [st (janet.table/new 8)]
    (janet/put st :jolt/type :jolt/tls-stream)
    (janet/put st :sock sock) (janet/put st :ssl ssl) (janet/put st :ctx ctx)
    (janet/put st :rbio rbio) (janet/put st :wbio wbio) (janet/put st :eof false)
    (janet/put st :write
      (fn [self data]
        (let [bytes (janet/buffer data)]
          (loop [off 0]
            (when (< off (janet/length bytes))
              (let [chunk (janet.buffer/slice bytes off)
                    n (C "SSL_write" (janet/get self :ssl) chunk (janet/length chunk))]
                (flush-out self)
                (if (pos? n)
                  (recur (+ off n))
                  (let [err (C "SSL_get_error" (janet/get self :ssl) n)]
                    (if (or (= err WANT-READ) (= err WANT-WRITE))
                      (do (feed-in self nil) (recur off))
                      (throw (ssl-ex "TLS write failed"))))))))
          self)))
    (janet/put st :read
      ;; timeout optional so spork's server (:read conn n buf) works over a TLS
      ;; stream too (in-process TLS test server)
      (fn [self n buf & rest]
        (let [timeout (first rest)]
          (when-not (janet/get self :eof)
            (loop []
              (let [tmp (janet.buffer/new-filled n 0)
                    got (C "SSL_read" (janet/get self :ssl) tmp n)]
                (if (pos? got)
                  (do (janet.buffer/push buf (janet.buffer/slice tmp 0 got)) buf)
                  (let [err (C "SSL_get_error" (janet/get self :ssl) got)]
                    (cond
                      (= err WANT-READ) (if (feed-in self timeout) (recur) (do (janet/put self :eof true) nil))
                      (= err WANT-WRITE) (do (flush-out self) (recur))
                      :else (do (janet/put self :eof true) nil))))))))))
    (janet/put st :close
      (fn [& _]
        (try (C "SSL_shutdown" ssl) (catch Throwable _ nil))
        (try (janet.net/close sock) (catch Throwable _ nil))
        (try (C "SSL_free" ssl) (catch Throwable _ nil))
        (try (C "SSL_CTX_free" ctx) (catch Throwable _ nil))
        nil))
    st))

(defn tls-connect
  "Open a TLS client connection to host:port. insecure? disables peer
  verification (self-signed/expired certs accepted)."
  [host port insecure?]
  (load!)
  (let [ctx (C "SSL_CTX_new" (C "TLS_client_method"))]
    (when (nil? ctx) (throw (ssl-ex "SSL_CTX_new failed")))
    (if insecure?
      (C "SSL_CTX_set_verify" ctx VERIFY-NONE nil)
      (do (C "SSL_CTX_set_default_verify_paths" ctx)
          (C "SSL_CTX_set_verify" ctx VERIFY-PEER nil)))
    (let [ssl (C "SSL_new" ctx)
          memmeth (C "BIO_s_mem")
          rbio (C "BIO_new" memmeth)
          wbio (C "BIO_new" memmeth)
          host-buf (cstr host)]
      (C "SSL_set_bio" ssl rbio wbio)
      (C "SSL_set_connect_state" ssl)
      (C "SSL_ctrl" ssl SET-TLSEXT-HOSTNAME NAMETYPE-host-name host-buf)
      (when-not insecure? (C "SSL_set1_host" ssl host-buf))
      (let [sock (janet.net/connect (str host) (str port))
            st (make-stream sock ssl ctx rbio wbio)]
        (try (handshake! st true)
             (catch Throwable e ((janet/get st :close)) (throw e)))
        st))))

(defn tls-wrap-server
  "Wrap an accepted plain net `sock` as the server side of a TLS session, using
  PEM `cert-file` and `key-file`. Returns a stream table."
  [sock cert-file key-file]
  (load!)
  (let [ctx (C "SSL_CTX_new" (C "TLS_server_method"))]
    (when (zero? (C "SSL_CTX_use_certificate_file" ctx (cstr cert-file) FILETYPE-PEM))
      (throw (ssl-ex (str "cannot load cert " cert-file))))
    (when (zero? (C "SSL_CTX_use_PrivateKey_file" ctx (cstr key-file) FILETYPE-PEM))
      (throw (ssl-ex (str "cannot load key " key-file))))
    (let [ssl (C "SSL_new" ctx)
          memmeth (C "BIO_s_mem")
          rbio (C "BIO_new" memmeth)
          wbio (C "BIO_new" memmeth)]
      (C "SSL_set_bio" ssl rbio wbio)
      (C "SSL_set_accept_state" ssl)
      (let [st (make-stream sock ssl ctx rbio wbio)]
        (handshake! st false)
        st))))
