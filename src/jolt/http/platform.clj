(ns jolt.http.platform
  "Platform support for clj-http-lite on Jolt: a hand-rolled HTTP/1.1 client over
  Janet's net sockets, exposed as the java.net.HttpURLConnection / URL surface
  clj-http-lite drives, plus the java.io byte streams and java.util.zip / SSL
  pieces it touches. Registers everything through Jolt's host-shim hooks
  (__register-class-ctor! / __register-class-statics! / __register-class-methods!
   / __register-instance-check!) — like jolt-lang/router does for reitit.

  https is handled by jolt.http.tls (OpenSSL via FFI); gzip/deflate by
  jolt.http.zlib (libz via FFI). Both load lazily, so nothing native is touched
  unless an https request or a compressed response actually occurs."
  (:require [clojure.string :as str]
            [jolt.http.zlib :as zlib]
            [jolt.http.tls :as tls]))

;; --- typed throwables ------------------------------------------------------
;; A throwable table carrying a JVM :class name; core's core-class reads :class,
;; so (class e) / catch / clojure.test thrown? match by class.
(defn- throw-typed [class msg]
  (let [t (janet.table/new 8)]
    (janet/put t :jolt/type :jolt/ex-info)
    (janet/put t :class class)
    (janet/put t :message (str msg))
    (janet/put t :data {})
    (throw t)))

;; --- byte coercion ---------------------------------------------------------
(defn- ->bytes [x]
  (cond
    (and (janet/table? x) (= :jolt/bais (janet/get x :jolt/type)))
      (subs (janet/get x :s) (or (janet/get x :pos) 0))
    (and (janet/table? x) (= :jolt/baos (janet/get x :jolt/type))) (janet/get x :buf)
    :else x))                          ;; string / buffer pass through

;; --- byte streams ----------------------------------------------------------
(defn make-bais [bytes]
  (let [t (janet.table/new 8)]
    (janet/put t :jolt/type :jolt/bais)
    (janet/put t :jolt/input-stream true)     ;; generic io/copy + slurp markers
    (janet/put t :s (janet/string bytes))     ;; :s/:pos so core slurp can drain it
    (janet/put t :pos 0)
    (janet/put t :close (fn [] nil))
    t))

(defn make-baos [shared-buf]
  (let [t (janet.table/new 8)]
    (janet/put t :jolt/type :jolt/baos)
    (janet/put t :jolt/output-stream true)
    (janet/put t :buf (or shared-buf (janet/buffer "")))
    (janet/put t :close (fn [] nil))
    t))

;; --- URL -------------------------------------------------------------------
(defn- min-idx [s chars]
  (reduce (fn [best ch] (if-let [i (str/index-of s (str ch))] (min best i) best))
          (count s) chars))

(defn parse-url [spec]
  (let [s (str spec)
        colon (str/index-of s ":")]
    (when (or (nil? colon) (= colon 0) (str/index-of (subs s 0 colon) "/"))
      (throw-typed "java.net.MalformedURLException" (str "no protocol: " s)))
    (let [protocol (subs s 0 colon)
          rest (subs s (inc colon))
          url (janet.table/new 8)]
      (janet/put url :jolt/type :jolt/url)
      (janet/put url :spec s)
      (janet/put url :protocol protocol)
      (janet/put url :host nil) (janet/put url :port -1)
      (janet/put url :path "") (janet/put url :query nil) (janet/put url :userinfo nil)
      (if (str/starts-with? rest "//")
        (let [rest (subs rest 2)
              auth-end (min-idx rest [\/ \? \#])
              authority (subs rest 0 auth-end)
              after (subs rest auth-end)
              at (str/index-of authority "@")
              hostport (if at
                         (do (janet/put url :userinfo (subs authority 0 at))
                             (subs authority (inc at)))
                         authority)
              pc (str/index-of hostport ":")]
          (if pc
            (do (janet/put url :host (subs hostport 0 pc))
                (janet/put url :port (or (janet/scan-number (subs hostport (inc pc))) -1)))
            (janet/put url :host hostport))
          (let [q (str/index-of after "?")]
            (if q
              (do (janet/put url :path (subs after 0 q)) (janet/put url :query (subs after (inc q))))
              (janet/put url :path after))))
        (janet/put url :path rest))
      url)))

(defn- url-file-path [url]
  (let [spec (janet/get url :spec)]
    (loop [p (if (str/starts-with? spec "file:") (subs spec 5) (or (janet/get url :path) ""))]
      (if (and (> (count p) 1) (str/starts-with? p "//")) (recur (subs p 1)) p))))

(defn- default-port? [protocol port]
  (or (= port -1) (and (= protocol "http") (= port 80)) (and (= protocol "https") (= port 443))))

(defn- effective-port [url]
  (let [p (janet/get url :port)]
    (if (and (number? p) (>= p 0)) p (if (= (janet/get url :protocol) "https") 443 80))))

;; --- stream abstraction (net core stream vs TLS table) ---------------------
(defn- tls-stream? [s] (janet/table? s))
(defn- s-write [stream data]
  (if (tls-stream? stream) ((janet/get stream :write) stream data) (janet.net/write stream data)))
(defn- s-read [stream n buf tmo]
  (if (tls-stream? stream)
    ((janet/get stream :read) stream n buf tmo)
    (if tmo (janet.net/read stream n buf tmo) (janet.net/read stream n buf))))
(defn- s-close [stream]
  (if (tls-stream? stream) ((janet/get stream :close)) (janet.net/close stream)))

;; --- HTTP/1.1 client -------------------------------------------------------
(defn- connect-stream [host port https? insecure?]
  (try
    (if https?
      (tls/tls-connect host port insecure?)
      (janet.net/connect (str host) (str port)))
    (catch Throwable err
      (let [msg (str err)]
        (cond
          (get err :class) (throw err)
          (str/includes? msg "address info") (throw-typed "java.net.UnknownHostException" host)
          (str/includes? msg "refused") (throw-typed "java.net.ConnectException" msg)
          :else (throw-typed "java.net.ConnectException" msg))))))

(defn- recv-all [stream read-timeout]
  (let [buf (janet/buffer "")
        tmo (when (and read-timeout (pos? read-timeout)) (/ read-timeout 1000))]
    (try
      (loop [] (when (s-read stream 65536 buf tmo) (recur)))
      (catch Throwable err
        (let [msg (str err)]
          (cond
            (get err :class) (throw err)
            (or (str/includes? msg "timeout") (str/includes? msg "deadline"))
              (throw-typed "java.net.SocketTimeoutException" "Read timed out")
            :else (throw err)))))
    buf))

(defn- header-ci [pairs name]
  (let [low (str/lower-case name)]
    (reduce (fn [v pair] (if (= low (str/lower-case (first pair))) (second pair) v)) nil pairs)))

(defn- dechunk [raw]
  (loop [i 0 out (janet/buffer "")]
    (if (>= i (count raw))
      (janet/string out)
      (let [crlf (str/index-of raw "\r\n" i)]
        (if (nil? crlf)
          (janet/string out)
          (let [line (subs raw i crlf)
                semi (str/index-of line ";")
                line (if semi (subs line 0 semi) line)
                sz (janet/scan-number (str "16r" (str/trim line)))]
            (if (or (nil? sz) (<= sz 0))
              (janet/string out)
              (let [start (+ crlf 2)
                    end (min (count raw) (+ start sz))]
                (janet.buffer/push-string out (subs raw start end))
                (recur (+ start sz 2) out)))))))))

(defn- parse-response [buf]
  (let [s (janet/string buf)
        end (str/index-of s "\r\n\r\n")]
    (when (nil? end) (throw-typed "java.io.IOException" "malformed response: no header terminator"))
    (let [head (subs s 0 end)
          body-raw (subs s (+ end 4))
          lines (str/split head #"\r\n")
          status-line (first lines)
          parts (str/split status-line #" ")
          status (or (janet/scan-number (nth parts 1 ""))
                     (throw-typed "java.io.IOException" (str "bad status line: " status-line)))
          pairs (vec (keep (fn [line]
                             (when-let [c (str/index-of line ":")]
                               [(str/trim (subs line 0 c)) (str/trim (subs line (inc c)))]))
                           (rest lines)))
          te (header-ci pairs "transfer-encoding")
          body (if (and te (str/includes? (str/lower-case te) "chunked")) (dechunk body-raw) body-raw)]
      {:status status :header-pairs pairs :body body})))

(defn- build-request [method url req-headers body]
  (let [host (janet/get url :host)
        port (effective-port url)
        path (let [p (janet/get url :path) q (janet/get url :query)]
               (str (if (or (nil? p) (= "" p)) "/" p) (if q (str "?" q) "")))
        req (janet/buffer "")]
    (janet.buffer/push-string req (str method " " path " HTTP/1.1\r\n"))
    (janet.buffer/push-string req (str "Host: "
                                       (if (default-port? (janet/get url :protocol) (janet/get url :port))
                                         host (str host ":" port))
                                       "\r\n"))
    (doseq [pair req-headers]
      (janet.buffer/push-string req (str (first pair) ": " (second pair) "\r\n")))
    (when body (janet.buffer/push-string req (str "Content-Length: " (janet/length (->bytes body)) "\r\n")))
    (janet.buffer/push-string req "Connection: close\r\n\r\n")
    (when body (janet.buffer/push-string req (->bytes body)))
    req))

(defn- resolve-location [base loc]
  (cond
    (or (str/starts-with? loc "http://") (str/starts-with? loc "https://")) (parse-url loc)
    (str/starts-with? loc "//") (parse-url (str (janet/get base :protocol) ":" loc))
    (str/starts-with? loc "/")
      (let [q (str/index-of loc "?")
            u (parse-url (str (janet/get base :protocol) "://"
                              (or (janet/get base :userinfo) "")
                              (when (janet/get base :userinfo) "@")
                              (janet/get base :host)
                              (let [p (janet/get base :port)] (if (and (number? p) (>= p 0)) (str ":" p) ""))
                              loc))]
        u)
    :else (parse-url (str (janet/get base :protocol) "://" (janet/get base :host) "/" loc))))

(def ^:private redirect-statuses #{301 302 303 307 308})

(defn- perform! [conn]
  (loop [url (janet/get conn :url)
         method (janet/get conn :method)
         redirects 0]
    (let [https? (= "https" (janet/get url :protocol))
          body (when (and (janet/get conn :do-output) (janet/get conn :out-buffer)) (janet/get conn :out-buffer))
          stream (connect-stream (janet/get url :host) (effective-port url) https? (janet/get conn :insecure))
          resp (try
                 (s-write stream (build-request method url (janet/get conn :req-headers) body))
                 (parse-response (recv-all stream (janet/get conn :read-timeout)))
                 (finally (try (s-close stream) (catch Throwable _ nil))))
          loc (header-ci (:header-pairs resp) "location")]
      (if (and (janet/get conn :follow-redirects)
               (redirect-statuses (:status resp))
               (or (= method "GET") (= method "HEAD"))
               loc (< redirects 20))
        (recur (resolve-location url loc)
               (if (= (:status resp) 303) "GET" method)
               (inc redirects))
        (do (janet/put conn :response resp)
            (janet/put conn :performed true)
            resp)))))

(defn- ensure-performed! [conn]
  (when-not (janet/get conn :performed) (perform! conn))
  (janet/get conn :response))

(defn- open-connection [url]
  (let [c (janet.table/new 16)]
    (janet/put c :jolt/type :jolt/http-url-connection)
    (janet/put c :url url)
    (janet/put c :https (= "https" (janet/get url :protocol)))
    (janet/put c :method "GET")
    (janet/put c :req-headers [])
    (janet/put c :do-output false)
    (janet/put c :follow-redirects true)
    (janet/put c :read-timeout nil) (janet/put c :connect-timeout nil)
    (janet/put c :insecure false) (janet/put c :out-buffer nil)
    (janet/put c :performed false) (janet/put c :response nil)
    c))

;; --- install ---------------------------------------------------------------
(defn install! []
  ;; ByteArrayInputStream / ByteArrayOutputStream
  (doseq [nm ["ByteArrayInputStream" "java.io.ByteArrayInputStream"]]
    (__register-class-ctor! nm (fn [bytes & _] (make-bais bytes))))
  (doseq [nm ["ByteArrayOutputStream" "java.io.ByteArrayOutputStream"]]
    (__register-class-ctor! nm (fn [& _] (make-baos nil))))
  (__register-class-methods! :jolt/bais
    {"read" (fn [self & args]
              (let [s (janet/get self :s) p (janet/get self :pos) n (count s)]
                (if (empty? args)
                  (if (>= p n) -1 (do (janet/put self :pos (inc p)) (janet/in s p)))
                  (let [buf (first args)
                        off (or (second args) 0)
                        len (or (nth args 2 nil) (janet/length buf))]
                    (if (>= p n)
                      -1
                      (let [avail (min len (- n p))]
                        (janet.buffer/blit buf (subs s p (+ p avail)) off)
                        (janet/put self :pos (+ p avail))
                        avail))))))
     "available" (fn [self] (- (count (janet/get self :s)) (janet/get self :pos)))
     "close" (fn [self] nil)})
  (__register-class-methods! :jolt/baos
    {"write" (fn [self x & args]
               (let [buf (janet/get self :buf)]
                 (cond
                   (number? x) (janet.buffer/push-byte buf (bit-and x 0xff))
                   (empty? args) (janet.buffer/push-string buf (->bytes x))
                   :else (janet.buffer/push-string buf (janet.buffer/slice (->bytes x) (first args) (+ (first args) (second args))))))
               nil)
     "toByteArray" (fn [self] (janet.buffer/slice (janet/get self :buf)))
     "toString" (fn [self & _] (janet/string (janet/get self :buf)))
     "size" (fn [self] (janet/length (janet/get self :buf)))
     "flush" (fn [self] nil)
     "reset" (fn [self] (janet.buffer/clear (janet/get self :buf)) nil)
     "close" (fn [self] nil)})

  ;; java.util.zip streams (eager: decompress/compress whole payloads)
  (doseq [nm ["GZIPInputStream" "java.util.zip.GZIPInputStream"]]
    (__register-class-ctor! nm (fn [src & _] (make-bais (zlib/gunzip (->bytes src))))))
  (doseq [nm ["InflaterInputStream" "java.util.zip.InflaterInputStream"]]
    (__register-class-ctor! nm (fn [src & _] (make-bais (zlib/zlib-inflate (->bytes src))))))
  (doseq [nm ["DeflaterInputStream" "java.util.zip.DeflaterInputStream"]]
    (__register-class-ctor! nm (fn [src & _] (make-bais (zlib/zlib-deflate (->bytes src))))))
  (doseq [nm ["GZIPOutputStream" "java.util.zip.GZIPOutputStream"]]
    (__register-class-ctor! nm (fn [target & _]
                                 (let [t (janet.table/new 8)]
                                   (janet/put t :jolt/type :jolt/gzip-out)
                                   (janet/put t :jolt/output-stream true)
                                   (janet/put t :buf (janet/buffer ""))
                                   (janet/put t :target target)
                                   (janet/put t :close (fn [] nil))
                                   t))))
  (__register-class-methods! :jolt/gzip-out
    {"write" (fn [self x & args]
               (let [buf (janet/get self :buf)]
                 (cond
                   (number? x) (janet.buffer/push-byte buf (bit-and x 0xff))
                   (empty? args) (janet.buffer/push-string buf (->bytes x))
                   :else (janet.buffer/push-string buf (janet.buffer/slice (->bytes x) (first args) (+ (first args) (second args))))))
               nil)
     "flush" (fn [self] nil)
     "finish" (fn [self] nil)
     "close" (fn [self]
               (let [target (janet/get self :target)
                     gz (zlib/gzip (janet/get self :buf))]
                 (janet.buffer/push-string (janet/get target :buf) gz))
               nil)})

  ;; java.net.URL (full parser; superset of core's file:-only shim)
  (doseq [nm ["URL" "java.net.URL"]]
    (__register-class-ctor! nm (fn [spec & _] (parse-url spec))))
  (__register-class-methods! :jolt/url
    {"getProtocol" (fn [self] (janet/get self :protocol))
     "getHost" (fn [self] (or (janet/get self :host) ""))
     "getPort" (fn [self] (janet/get self :port))
     "getDefaultPort" (fn [self] (if (= (janet/get self :protocol) "https") 443 80))
     "getPath" (fn [self] (if (= "file" (janet/get self :protocol))
                            (url-file-path self)
                            (let [p (janet/get self :path)] (if (or (nil? p) (= "" p)) "" p))))
     "getFile" (fn [self] (if (= "file" (janet/get self :protocol))
                            (url-file-path self)
                            (str (or (janet/get self :path) "")
                                 (if (janet/get self :query) (str "?" (janet/get self :query)) ""))))
     "getQuery" (fn [self] (janet/get self :query))
     "getUserInfo" (fn [self] (janet/get self :userinfo))
     "toString" (fn [self] (janet/get self :spec))
     "toExternalForm" (fn [self] (janet/get self :spec))
     "openConnection" (fn [self] (open-connection self))
     "openStream" (fn [self] (make-bais (:body (ensure-performed! (open-connection self)))))})

  ;; java.net.HttpURLConnection
  (__register-class-methods! :jolt/http-url-connection
    {"setRequestMethod" (fn [self m] (janet/put self :method (str/upper-case (str m))) nil)
     "getRequestMethod" (fn [self] (janet/get self :method))
     "setRequestProperty" (fn [self k v]
                            (let [lk (str/lower-case (str k))
                                  kept (vec (remove (fn [pair] (= lk (str/lower-case (first pair))))
                                                    (janet/get self :req-headers)))]
                              (janet/put self :req-headers (conj kept [(str k) (str v)])))
                            nil)
     "addRequestProperty" (fn [self k v]
                            (janet/put self :req-headers (conj (janet/get self :req-headers) [(str k) (str v)])) nil)
     "getRequestProperty" (fn [self k] (header-ci (janet/get self :req-headers) (str k)))
     "setDoOutput" (fn [self b] (janet/put self :do-output (boolean b)) nil)
     "setDoInput" (fn [self _b] nil)
     "setUseCaches" (fn [self _b] nil)
     "setInstanceFollowRedirects" (fn [self b] (janet/put self :follow-redirects (boolean b)) nil)
     "getInstanceFollowRedirects" (fn [self] (janet/get self :follow-redirects))
     "setReadTimeout" (fn [self ms]
                        (when (< ms 0) (throw-typed "java.lang.IllegalArgumentException" "timeouts can't be negative"))
                        (janet/put self :read-timeout ms) nil)
     "setConnectTimeout" (fn [self ms]
                           (when (< ms 0) (throw-typed "java.lang.IllegalArgumentException" "timeouts can't be negative"))
                           (janet/put self :connect-timeout ms) nil)
     "setChunkedStreamingMode" (fn [self _n] nil)
     "setFixedLengthStreamingMode" (fn [self _n] nil)
     "connect" (fn [self] nil)
     "disconnect" (fn [self] nil)
     "getOutputStream" (fn [self]
                         (when (nil? (janet/get self :out-buffer)) (janet/put self :out-buffer (janet/buffer "")))
                         (make-baos (janet/get self :out-buffer)))
     "getResponseCode" (fn [self] (:status (ensure-performed! self)))
     "getResponseMessage" (fn [self] (ensure-performed! self) "")
     "getHeaderFieldKey" (fn [self i]
                           (let [pairs (:header-pairs (ensure-performed! self))]
                             (when (and (>= i 1) (<= i (count pairs))) (first (nth pairs (dec i))))))
     "getHeaderField" (fn [self i]
                        (let [pairs (:header-pairs (ensure-performed! self))]
                          (when (and (>= i 1) (<= i (count pairs))) (second (nth pairs (dec i))))))
     "getInputStream" (fn [self]
                        (let [resp (ensure-performed! self)]
                          (if (>= (:status resp) 400)
                            (throw-typed "java.io.IOException" (str "Server returned HTTP response code: " (:status resp)))
                            (make-bais (:body resp)))))
     "getErrorStream" (fn [self]
                        (let [resp (ensure-performed! self)]
                          (when (>= (:status resp) 400) (make-bais (:body resp)))))
     "getContentLength" (fn [self]
                          (or (janet/scan-number (or (header-ci (:header-pairs (ensure-performed! self)) "content-length") "")) -1))
     "setHostnameVerifier" (fn [self v] (janet/put self :hostname-verifier v) nil)
     "setSSLSocketFactory" (fn [self f] (janet/put self :ssl-factory f) (janet/put self :insecure true) nil)})

  ;; javax.net.ssl / java.security stubs for clj-http-lite's trust-all-ssl!
  (doseq [nm ["SSLContext" "javax.net.ssl.SSLContext"]]
    (__register-class-statics! nm {"getInstance" (fn [& _] (let [t (janet.table/new 4)]
                                                             (janet/put t :jolt/type :jolt/ssl-context) t))}))
  (__register-class-methods! :jolt/ssl-context
    {"init" (fn [self & _] self)
     "getSocketFactory" (fn [self] (let [t (janet.table/new 4)]
                                     (janet/put t :jolt/type :jolt/ssl-socket-factory) t))})
  (doseq [nm ["SecureRandom" "java.security.SecureRandom"]]
    (__register-class-ctor! nm (fn [& _] (let [t (janet.table/new 4)]
                                           (janet/put t :jolt/type :jolt/secure-random) t))))
  ;; TrustManager used as a bare value: (into-array TrustManager [...]) — make it
  ;; resolvable (the array element type is ignored).
  (__register-class-ctor! "TrustManager" (fn [& _] nil))

  ;; instance? for the shim types (clj-http-lite's trust-all-ssl! gates on
  ;; HttpsURLConnection; util uses InputStream).
  (__register-instance-check!
    (fn [cn val]
      (let [t (and (janet/table? val) (janet/get val :jolt/type))]
        (cond
          (or (= cn "HttpsURLConnection") (= cn "javax.net.ssl.HttpsURLConnection"))
            (and (= t :jolt/http-url-connection) (boolean (janet/get val :https)))
          (or (= cn "HttpURLConnection") (= cn "java.net.HttpURLConnection"))
            (= t :jolt/http-url-connection)
          (or (= cn "InputStream") (= cn "java.io.InputStream"))
            (= t :jolt/bais)
          :else nil))))
  nil)

(install!)
