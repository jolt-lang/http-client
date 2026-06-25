(ns jolt.http.platform
  "Platform support for clj-http-lite on Jolt: a hand-rolled HTTP/1.1 client over
  jolt.http.net (BSD sockets via jolt.ffi), exposed as the java.net.URL /
  HttpURLConnection surface clj-http-lite drives, plus the java.io byte streams
  and java.util.zip / SSL pieces it touches. Registers everything through Jolt's
  host-shim hooks (__register-class-ctor! / __register-class-methods! /
  __register-instance-check!) — like jolt-lang/router does for reitit.

  https is handled by jolt.http.tls (OpenSSL); gzip/deflate by jolt.http.zlib
  (libz). Shim objects are host tagged-tables; their fields are read/written with
  jolt.host/ref-get / ref-put!."
  (:require [clojure.string :as str]
            [jolt.crypto]                ;; java.security.SecureRandom (real, RAND_bytes)
            [jolt.http.net :as net]
            [jolt.http.zlib :as zlib]
            [jolt.http.tls :as tls]))

;; --- helpers ---------------------------------------------------------------
(defn- tt [tag] (jolt.host/tagged-table tag))
(defn- tget [t k] (jolt.host/ref-get t k))
(defn- tput! [t k v] (jolt.host/ref-put! t k v))
(defn- table? [x] (jolt.host/table? x))

;; A throwable table carrying a JVM :class name; core's core-class reads :class,
;; so (class e) / catch / clojure.test thrown? match by class.
(defn- throw-typed [class msg]
  (let [t (tt :jolt/ex-info)]
    (tput! t :class class) (tput! t :message (str msg)) (tput! t :data {})
    (throw t)))

;; --- byte coercion ---------------------------------------------------------
;; bytes flow as jolt byte-arrays. Coerce a stream shim / string / bytevector to
;; one; a byte-array passes through.
(defn- ->bytes [x]
  (cond
    (and (table? x) (= :jolt/bais (tget x :jolt/type)))
      (let [b (tget x :bytes) p (or (tget x :pos) 0)]
        (byte-array (drop p (seq b))))
    (and (table? x) (= :jolt/baos (tget x :jolt/type))) (byte-array (tget x :acc))
    :else (byte-array x)))                       ;; string / bytevector / byte-array

(defn- ba->latin1 [ba] (String. ba "ISO-8859-1"))   ;; byte-array -> string, 1 char/byte
(defn- latin1->ba [s] (byte-array (map int s)))      ;; string -> byte-array (codes 0-255)
(defn- concat-ba [a b]
  (let [na (alength a) nb (alength b) out (byte-array (+ na nb))]
    (dotimes [i na] (aset out i (aget a i)))
    (dotimes [i nb] (aset out (+ na i) (aget b i)))
    out))

;; --- byte streams ----------------------------------------------------------
(defn make-bais [bytes]
  (let [t (tt :jolt/bais)]
    (tput! t :jolt/input-stream true)
    (tput! t :bytes (byte-array bytes))
    (tput! t :pos 0)
    t))

(defn make-baos []
  (let [t (tt :jolt/baos)]
    (tput! t :jolt/output-stream true)
    (tput! t :acc [])
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
          url (tt :jolt/url)]
      (tput! url :spec s) (tput! url :protocol protocol)
      (tput! url :host nil) (tput! url :port -1)
      (tput! url :path "") (tput! url :query nil) (tput! url :userinfo nil)
      (if (str/starts-with? rest "//")
        (let [rest (subs rest 2)
              auth-end (min-idx rest [\/ \? \#])
              authority (subs rest 0 auth-end)
              after (subs rest auth-end)
              at (str/index-of authority "@")
              hostport (if at
                         (do (tput! url :userinfo (subs authority 0 at))
                             (subs authority (inc at)))
                         authority)
              pc (str/index-of hostport ":")]
          (if pc
            (do (tput! url :host (subs hostport 0 pc))
                (tput! url :port (or (parse-long (subs hostport (inc pc))) -1)))
            (tput! url :host hostport))
          (let [q (str/index-of after "?")]
            (if q
              (do (tput! url :path (subs after 0 q)) (tput! url :query (subs after (inc q))))
              (tput! url :path after))))
        (tput! url :path rest))
      url)))

(defn- url-file-path [url]
  (let [spec (tget url :spec)]
    (loop [p (if (str/starts-with? spec "file:") (subs spec 5) (or (tget url :path) ""))]
      (if (and (> (count p) 1) (str/starts-with? p "//")) (recur (subs p 1)) p))))

(defn- default-port? [protocol port]
  (or (= port -1) (and (= protocol "http") (= port 80)) (and (= protocol "https") (= port 443))))

(defn- effective-port [url]
  (let [p (tget url :port)]
    (if (and (number? p) (>= p 0)) p (if (= (tget url :protocol) "https") 443 80))))

;; --- stream abstraction (plain socket fd vs TLS stream table) --------------
(defn- s-write [stream data] (if (table? stream) ((tget stream :write) stream data) (net/send-bytes stream data)))
(defn- s-read  [stream timeout] (if (table? stream) ((tget stream :read) stream timeout) (net/recv-bytes stream)))
(defn- s-close [stream] (if (table? stream) ((tget stream :close)) (net/close stream)))

;; --- HTTP/1.1 client -------------------------------------------------------
(defn- connect-stream [host port https? insecure? read-timeout]
  (if https?
    (tls/tls-connect host port insecure?)
    (let [fd (net/connect (str host) port)]
      (when (and read-timeout (pos? read-timeout)) (net/set-read-timeout! fd read-timeout))
      fd)))

(defn- recv-all [stream]
  (loop [chunks []]
    (if-let [b (s-read stream nil)]
      (recur (conj chunks b))
      (byte-array (mapcat seq chunks)))))

(defn- header-ci [pairs name]
  (let [low (str/lower-case name)]
    (reduce (fn [v pair] (if (= low (str/lower-case (first pair))) (second pair) v)) nil pairs)))

(defn- dechunk [raw]
  ;; raw: latin1 string of the chunked body. returns the dechunked latin1 string.
  (loop [i 0 out (StringBuilder.)]
    (if (>= i (count raw))
      (.toString out)
      (let [crlf (str/index-of raw "\r\n" i)]
        (if (nil? crlf)
          (.toString out)
          (let [line (subs raw i crlf)
                semi (str/index-of line ";")
                line (if semi (subs line 0 semi) line)
                sz (try (Long/parseLong (str/trim line) 16) (catch Throwable _ nil))]
            (if (or (nil? sz) (<= sz 0))
              (.toString out)
              (let [start (+ crlf 2)
                    end (min (count raw) (+ start sz))]
                (.append out (subs raw start end))
                (recur (+ start sz 2) out)))))))))

(defn- parse-response [raw]
  ;; raw: the full response byte-array.
  (let [s (ba->latin1 raw)
        end (str/index-of s "\r\n\r\n")]
    (when (nil? end) (throw-typed "java.io.IOException" "malformed response: no header terminator"))
    (let [head (subs s 0 end)
          body-raw (subs s (+ end 4))
          lines (str/split head #"\r\n")
          status-line (first lines)
          parts (str/split status-line #" ")
          status (or (parse-long (nth parts 1 ""))
                     (throw-typed "java.io.IOException" (str "bad status line: " status-line)))
          pairs (vec (keep (fn [line]
                             (when-let [c (str/index-of line ":")]
                               [(str/trim (subs line 0 c)) (str/trim (subs line (inc c)))]))
                           (rest lines)))
          te (header-ci pairs "transfer-encoding")
          body (if (and te (str/includes? (str/lower-case te) "chunked")) (dechunk body-raw) body-raw)]
      {:status status :header-pairs pairs :body (latin1->ba body)})))

(defn- build-request [method url req-headers body]
  (let [host (tget url :host)
        port (effective-port url)
        path (let [p (tget url :path) q (tget url :query)]
               (str (if (or (nil? p) (= "" p)) "/" p) (if q (str "?" q) "")))
        sb (StringBuilder.)]
    (.append sb (str method " " path " HTTP/1.1\r\n"))
    (.append sb (str "Host: "
                     (if (default-port? (tget url :protocol) (tget url :port))
                       host (str host ":" port))
                     "\r\n"))
    (doseq [pair req-headers]
      (.append sb (str (first pair) ": " (second pair) "\r\n")))
    (when body (.append sb (str "Content-Length: " (alength (->bytes body)) "\r\n")))
    (.append sb "Connection: close\r\n\r\n")
    (let [head (byte-array (.getBytes (.toString sb) "UTF-8"))]
      (if body (concat-ba head (->bytes body)) head))))

(defn- resolve-location [base loc]
  (cond
    (or (str/starts-with? loc "http://") (str/starts-with? loc "https://")) (parse-url loc)
    (str/starts-with? loc "//") (parse-url (str (tget base :protocol) ":" loc))
    (str/starts-with? loc "/")
      (parse-url (str (tget base :protocol) "://"
                      (or (tget base :userinfo) "")
                      (when (tget base :userinfo) "@")
                      (tget base :host)
                      (let [p (tget base :port)] (if (and (number? p) (>= p 0)) (str ":" p) ""))
                      loc))
    :else (parse-url (str (tget base :protocol) "://" (tget base :host) "/" loc))))

(def ^:private redirect-statuses #{301 302 303 307 308})

(defn- perform! [conn]
  (loop [url (tget conn :url)
         method (tget conn :method)
         redirects 0]
    (let [https? (= "https" (tget url :protocol))
          body (when (and (tget conn :do-output) (tget conn :out-buffer)) (tget conn :out-buffer))
          stream (connect-stream (tget url :host) (effective-port url) https?
                                 (tget conn :insecure) (tget conn :read-timeout))
          resp (try
                 (s-write stream (build-request method url (tget conn :req-headers) body))
                 (parse-response (recv-all stream))
                 (finally (try (s-close stream) (catch Throwable _ nil))))
          loc (header-ci (:header-pairs resp) "location")]
      (if (and (tget conn :follow-redirects)
               (redirect-statuses (:status resp))
               (or (= method "GET") (= method "HEAD"))
               loc (< redirects 20))
        (recur (resolve-location url loc)
               (if (= (:status resp) 303) "GET" method)
               (inc redirects))
        (do (tput! conn :response resp) (tput! conn :performed true) resp)))))

(defn- ensure-performed! [conn]
  (when-not (tget conn :performed) (perform! conn))
  (tget conn :response))

(defn- open-connection [url]
  (let [c (tt :jolt/http-url-connection)]
    (tput! c :url url)
    (tput! c :https (= "https" (tget url :protocol)))
    (tput! c :method "GET") (tput! c :req-headers [])
    (tput! c :do-output false) (tput! c :follow-redirects true)
    (tput! c :read-timeout nil) (tput! c :connect-timeout nil)
    (tput! c :insecure false) (tput! c :out-buffer nil)
    (tput! c :performed false) (tput! c :response nil)
    c))

;; --- install ---------------------------------------------------------------
(defn install! []
  ;; ByteArrayInputStream / ByteArrayOutputStream
  (doseq [nm ["ByteArrayInputStream" "java.io.ByteArrayInputStream"]]
    (__register-class-ctor! nm (fn [bytes & _] (make-bais bytes))))
  (doseq [nm ["ByteArrayOutputStream" "java.io.ByteArrayOutputStream"]]
    (__register-class-ctor! nm (fn [& _] (make-baos))))
  (__register-class-methods! :jolt/bais
    {"read" (fn [self & args]
              (let [b (tget self :bytes) p (tget self :pos) n (alength b)]
                (if (empty? args)
                  (if (>= p n) -1 (do (tput! self :pos (inc p)) (aget b p)))
                  (let [buf (first args)
                        off (or (second args) 0)
                        len (or (nth args 2 nil) (alength buf))]
                    (if (>= p n)
                      -1
                      (let [avail (min len (- n p))]
                        (dotimes [i avail] (aset buf (+ off i) (aget b (+ p i))))
                        (tput! self :pos (+ p avail))
                        avail))))))
     "available" (fn [self] (- (alength (tget self :bytes)) (tget self :pos)))
     "close" (fn [self & _] nil)})
  (__register-class-methods! :jolt/baos
    {"write" (fn [self x & args]
               (let [acc (tget self :acc)]
                 (cond
                   (number? x) (tput! self :acc (conj acc (bit-and x 0xff)))
                   (empty? args) (tput! self :acc (into acc (seq (->bytes x))))
                   :else (let [off (first args) len (second args)]
                           (tput! self :acc (into acc (take len (drop off (seq (->bytes x)))))))))
               nil)
     "toByteArray" (fn [self] (byte-array (tget self :acc)))
     "toString" (fn [self & _] (String. (byte-array (tget self :acc)) "UTF-8"))
     "size" (fn [self] (count (tget self :acc)))
     "flush" (fn [self & _] nil)
     "reset" (fn [self] (tput! self :acc []) nil)
     "close" (fn [self & _] nil)})

  ;; java.util.zip streams (eager: (de)compress whole payloads)
  (doseq [nm ["GZIPInputStream" "java.util.zip.GZIPInputStream"]]
    (__register-class-ctor! nm (fn [src & _] (make-bais (zlib/gunzip (->bytes src))))))
  (doseq [nm ["InflaterInputStream" "java.util.zip.InflaterInputStream"]]
    (__register-class-ctor! nm (fn [src & _] (make-bais (zlib/zlib-inflate (->bytes src))))))
  (doseq [nm ["DeflaterInputStream" "java.util.zip.DeflaterInputStream"]]
    (__register-class-ctor! nm (fn [src & _] (make-bais (zlib/zlib-deflate (->bytes src))))))
  (doseq [nm ["GZIPOutputStream" "java.util.zip.GZIPOutputStream"]]
    (__register-class-ctor! nm (fn [target & _]
                                 (let [t (tt :jolt/gzip-out)]
                                   (tput! t :jolt/output-stream true)
                                   (tput! t :acc []) (tput! t :target target)
                                   t))))
  (__register-class-methods! :jolt/gzip-out
    {"write" (fn [self x & args]
               (let [acc (tget self :acc)]
                 (cond
                   (number? x) (tput! self :acc (conj acc (bit-and x 0xff)))
                   (empty? args) (tput! self :acc (into acc (seq (->bytes x))))
                   :else (let [off (first args) len (second args)]
                           (tput! self :acc (into acc (take len (drop off (seq (->bytes x)))))))))
               nil)
     "flush" (fn [self & _] nil)
     "finish" (fn [self & _] nil)
     "close" (fn [self & _]
               (let [target (tget self :target)
                     gz (zlib/gzip (byte-array (tget self :acc)))]
                 (.write target gz))   ;; append the gzipped payload to the target baos
               nil)})

  ;; java.net.URL (full parser; superset of core's file:-only shim)
  (doseq [nm ["URL" "java.net.URL"]]
    (__register-class-ctor! nm (fn [spec & _] (parse-url spec))))
  (__register-class-methods! :jolt/url
    {"getProtocol" (fn [self] (tget self :protocol))
     "getHost" (fn [self] (or (tget self :host) ""))
     "getPort" (fn [self] (tget self :port))
     "getDefaultPort" (fn [self] (if (= (tget self :protocol) "https") 443 80))
     "getPath" (fn [self] (if (= "file" (tget self :protocol))
                            (url-file-path self)
                            (let [p (tget self :path)] (if (or (nil? p) (= "" p)) "" p))))
     "getFile" (fn [self] (if (= "file" (tget self :protocol))
                            (url-file-path self)
                            (str (or (tget self :path) "")
                                 (if (tget self :query) (str "?" (tget self :query)) ""))))
     "getQuery" (fn [self] (tget self :query))
     "getUserInfo" (fn [self] (tget self :userinfo))
     "toString" (fn [self] (tget self :spec))
     "toExternalForm" (fn [self] (tget self :spec))
     "openConnection" (fn [self] (open-connection self))
     "openStream" (fn [self] (make-bais (:body (ensure-performed! (open-connection self)))))})

  ;; java.net.HttpURLConnection
  (__register-class-methods! :jolt/http-url-connection
    {"setRequestMethod" (fn [self m] (tput! self :method (str/upper-case (str m))) nil)
     "getRequestMethod" (fn [self] (tget self :method))
     "setRequestProperty" (fn [self k v]
                            (let [lk (str/lower-case (str k))
                                  kept (vec (remove (fn [pair] (= lk (str/lower-case (first pair))))
                                                    (tget self :req-headers)))]
                              (tput! self :req-headers (conj kept [(str k) (str v)])))
                            nil)
     "addRequestProperty" (fn [self k v]
                            (tput! self :req-headers (conj (tget self :req-headers) [(str k) (str v)])) nil)
     "getRequestProperty" (fn [self k] (header-ci (tget self :req-headers) (str k)))
     "setDoOutput" (fn [self b] (tput! self :do-output (boolean b)) nil)
     "setDoInput" (fn [self _b] nil)
     "setUseCaches" (fn [self _b] nil)
     "setInstanceFollowRedirects" (fn [self b] (tput! self :follow-redirects (boolean b)) nil)
     "getInstanceFollowRedirects" (fn [self] (tget self :follow-redirects))
     "setReadTimeout" (fn [self ms]
                        (when (< ms 0) (throw-typed "java.lang.IllegalArgumentException" "timeouts can't be negative"))
                        (tput! self :read-timeout ms) nil)
     "setConnectTimeout" (fn [self ms]
                           (when (< ms 0) (throw-typed "java.lang.IllegalArgumentException" "timeouts can't be negative"))
                           (tput! self :connect-timeout ms) nil)
     "setChunkedStreamingMode" (fn [self _n] nil)
     "setFixedLengthStreamingMode" (fn [self _n] nil)
     "connect" (fn [self] nil)
     "disconnect" (fn [self] nil)
     "getOutputStream" (fn [self]
                         (when (nil? (tget self :out-buffer)) (tput! self :out-buffer (make-baos)))
                         (tget self :out-buffer))
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
                          (or (parse-long (or (header-ci (:header-pairs (ensure-performed! self)) "content-length") "")) -1))
     "setHostnameVerifier" (fn [self v] (tput! self :hostname-verifier v) nil)
     "setSSLSocketFactory" (fn [self f] (tput! self :ssl-factory f) (tput! self :insecure true) nil)})

  ;; javax.net.ssl / java.security stubs for clj-http-lite's trust-all-ssl!
  (doseq [nm ["SSLContext" "javax.net.ssl.SSLContext"]]
    (__register-class-statics! nm {"getInstance" (fn [& _] (tt :jolt/ssl-context))}))
  (__register-class-methods! :jolt/ssl-context
    {"init" (fn [self & _] self)
     "getSocketFactory" (fn [self] (tt :jolt/ssl-socket-factory))})
  ;; java.security.SecureRandom comes from jolt-crypto (real RAND_bytes), required above.
  ;; TrustManager used as a bare value: (into-array TrustManager [...]).
  (__register-class-ctor! "TrustManager" (fn [& _] nil))

  ;; instance? for the shim types (trust-all-ssl! gates on HttpsURLConnection;
  ;; util gates on InputStream).
  (__register-instance-check!
    (fn [cn val]
      (let [t (and (table? val) (tget val :jolt/type))]
        (cond
          (or (= cn "HttpsURLConnection") (= cn "javax.net.ssl.HttpsURLConnection"))
            (and (= t :jolt/http-url-connection) (boolean (tget val :https)))
          (or (= cn "HttpURLConnection") (= cn "java.net.HttpURLConnection"))
            (= t :jolt/http-url-connection)
          (or (= cn "InputStream") (= cn "java.io.InputStream"))
            (= t :jolt/bais)
          :else nil))))
  nil)

(install!)
