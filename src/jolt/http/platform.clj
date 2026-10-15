(ns jolt.http.platform
  "Platform support for clj-http-lite on Jolt: a hand-rolled HTTP/1.1 client over
  jolt.http.net (BSD sockets via jolt.ffi), exposed as the java.net.URL /
  HttpURLConnection surface clj-http-lite drives, plus the java.io byte streams
  and SSL pieces it touches. Registers everything through Jolt's host-shim
  hooks (__register-class-ctor! / __register-class-methods! /
  __register-instance-check!) — like jolt-lang/router does for reitit.

  https is handled by jolt.http.tls (OpenSSL); gzip/deflate by the runtime's
  own java.util.zip, since jolt 0.8.9. Shim objects are host tagged-tables;
  their fields are read/written with jolt.host/ref-get / ref-put!."
  (:require [clojure.string :as str]
            [jolt.crypto]                ;; java.security.SecureRandom (real, RAND_bytes)
            [jolt.http.core :as core]
            [jolt.http.jdk]              ;; side effect: installs the java.net.http surface
            [jolt.http.websocket]))      ;; side effect: installs java.net.http.WebSocket


;; --- engine ----------------------------------------------------------------
;; The transport, URL parser, request/response codec and byte helpers live in
;; jolt.http.core, shared with jolt.http.jdk (java.net.http) and
;; jolt.http.websocket. Aliased in rather than re-implemented so the two client
;; surfaces cannot drift apart.
(def tt core/tt)
(def tget core/tget)
(def tput! core/tput!)
(def table? core/table?)
(def throw-typed core/throw-typed)
(def host-byte-streams? core/host-byte-streams?)
(def ->bytes core/->bytes)
(def make-bais core/make-bais)
(def make-baos core/make-baos)
(def parse-url core/parse-url)
(def url-file-path core/url-file-path)
(def effective-port core/effective-port)
(def header-ci core/header-ci)
(def connect-stream core/connect-stream)
(def build-request core/build-request)
(def parse-response core/parse-response)
(def read-response core/read-response)
(def recv-all core/recv-all)
(def resolve-location core/resolve-location)
(def redirect-statuses core/redirect-statuses)
(def s-write core/s-write)
(def s-read core/s-read)
(def s-close core/s-close)

(defn set-max-response-ms!
  "Cap the total wall-clock time of a response body, across all reads.

  Complements, and does not replace, the per-read `:socket-timeout`. Pass nil to
  remove the cap. Applies process-wide to every request made through this
  library."
  [ms]
  (core/set-max-response-ms! ms))


;; The body is left on the wire. getResponseCode and the header getters only
;; need the head, and clj-http-lite reaches the body through getInputStream /
;; getErrorStream alone, so the call can come back at the headers and the body
;; can be read as it arrives: `:as :stream` over an SSE feed or an LLM token
;; stream used to wait for the whole response before returning anything. The
;; buffered coercions lose nothing — clj-http-lite drains the stream to EOF
;; itself, and gzip/deflate are decoded from those bytes afterwards.
;;
;; Unlike the java.net.http path, the socket's read timeout stays armed for the
;; body (read-response's body-unbounded? is false here): on HttpURLConnection
;; setReadTimeout is SO_RCVTIMEO and bounds every read of the body, which is
;; what lets an SSE reader bound the gap between events. set-max-response-ms!
;; still caps the body's total time.
;;
;; Where the runtime cannot carry a live body (jolt below 0.8.8, see
;; core/reify-input-streams?) read-response hands back a buffered body and
;; nothing here changes.

(defn- discard-body!
  "Drain and let go of a streamed body nobody will read — the response to a
  redirect being followed. Left alone, its connection stays open until GC and
  could never go back to the pool."
  [resp]
  (when-let [pull (:body-pull resp)]
    ((:release! resp) (try (loop [] (if (nil? (pull)) true (recur)))
                           (catch Throwable _ false)))))

(defn- perform! [conn]
  (loop [url (tget conn :url)
         method (tget conn :method)
         redirects 0]
    (let [https? (= "https" (tget url :protocol))
          body (when (and (tget conn :do-output) (tget conn :out-buffer)) (tget conn :out-buffer))
          key (core/pool-key (tget url :host) (effective-port url) https?
                             (tget conn :insecure) nil nil)
          open! (fn [] (connect-stream (tget url :host) (effective-port url) https?
                                       (tget conn :insecure) (tget conn :read-timeout)
                                       (tget conn :connect-timeout)))
          ;; A buffered response is done with its connection here: pooled when
          ;; the response says it may be kept, closed otherwise, including on
          ;; the way out of a failure. A streamed one still has its body on the
          ;; socket, so ownership passes to the body stream through :release!,
          ;; which takes true once the body was read to its end.
          once (fn [stream received]
                 (let [ok (atom false)
                       streaming (atom false)]
                   (try
                     (s-write stream (build-request method url
                                                    (core/with-user-agent (tget conn :req-headers)
                                                                          (core/default-user-agent :url-connection))
                                                    body))
                     (let [r (read-response stream nil method received true)]
                       (if (:body-pull r)
                         (do (reset! streaming true)
                             (assoc r :release!
                                    (fn [complete?]
                                      (if (and complete? (:reusable? r))
                                        (core/pool-release! key stream)
                                        (try (s-close stream) (catch Throwable _ nil))))))
                         (do (reset! ok (:reusable? r)) r)))
                     (finally
                       (when-not @streaming
                         (if @ok
                           (core/pool-release! key stream)
                           (try (s-close stream) (catch Throwable _ nil))))))))
          resp (if-let [pooled (core/pool-acquire key)]
                 ;; a connection the peer retired since the last request fails
                 ;; before answering — cleanly or with a reset, depending on the
                 ;; platform. Nothing received means nothing was acted on, so it
                 ;; is retried fresh.
                 (let [received (atom false)]
                   (try (once (core/set-stream-timeout! pooled (tget conn :read-timeout)) received)
                        (catch Throwable t
                          (if (and (not @received) (core/connection-gone? t))
                            (once (open!) (atom false))
                            (throw t)))))
                 (once (open!) (atom false)))
          loc (header-ci (:header-pairs resp) "location")]
      (if (and (tget conn :follow-redirects)
               (redirect-statuses (:status resp))
               (or (= method "GET") (= method "HEAD"))
               loc (< redirects 20))
        (do (discard-body! resp)
            (recur (resolve-location url loc)
               (if (= (:status resp) 303) "GET" method)
               (inc redirects)))
        (do (tput! conn :response resp) (tput! conn :performed true) resp)))))

(defn- ensure-performed! [conn]
  (when-not (tget conn :performed) (perform! conn))
  (tget conn :response))

(defn- body-stream
  "The response body as an InputStream: live when the transport left it on the
  wire, over the bytes otherwise. Made once, so getInputStream, getErrorStream
  and disconnect all see the same stream."
  [conn]
  (or (tget conn :body-stream)
      (let [resp (ensure-performed! conn)
            s (if-let [pull (:body-pull resp)]
                (core/make-body-stream pull (:release! resp))
                (make-bais (:body resp)))]
        (tput! conn :body-stream s)
        s)))

(defn- input-stream [conn]
  (let [resp (ensure-performed! conn)]
    (if (>= (:status resp) 400)
      (throw-typed "java.io.IOException" (str "Server returned HTTP response code: " (:status resp)))
      (body-stream conn))))

(defn- open-connection [url]
  (let [c (tt :jolt/http-url-connection)]
    (tput! c :url url)
    (tput! c :https (= "https" (tget url :protocol)))
    (tput! c :method "GET") (tput! c :req-headers [])
    (tput! c :do-output false) (tput! c :follow-redirects true)
    (tput! c :read-timeout nil) (tput! c :connect-timeout nil)
    (tput! c :insecure false) (tput! c :out-buffer nil)
    (tput! c :performed false) (tput! c :response nil)
    (tput! c :body-stream nil)
    c))

;; --- install ---------------------------------------------------------------
(defn install! []
  ;; ByteArrayInputStream / ByteArrayOutputStream — only when the host has none
  ;; of its own. Replacing a class jolt models costs every namespace in the
  ;; process (see host-byte-streams?); make-bais/make-baos hand back the host's
  ;; streams there, so clj-http-lite and our own shims get them either way.
  (when-not host-byte-streams?
    (doseq [nm ["ByteArrayInputStream" "java.io.ByteArrayInputStream"]]
      (__register-class-ctor! nm (fn [bytes & _] (make-bais bytes))))
    (doseq [nm ["ByteArrayOutputStream" "java.io.ByteArrayOutputStream"]]
      (__register-class-ctor! nm (fn [& _] (make-baos)))))
  (__register-class-methods! :jolt/bais
    ;; The no-arg read returns the byte as an UNSIGNED int 0..255, -1 at EOF —
    ;; InputStream.read()'s contract, and the only way a caller can tell 0xff from
    ;; end-of-stream. byte[] elements are signed, so mask. Unmasked, a high byte
    ;; read as negative and every drain loop (io/copy's included) stopped there:
    ;; (util/gzip …) silently truncated a body at its first non-ASCII byte.
    ;; The read(buf …) arm fills a byte[], whose elements ARE signed — no mask.
    {"read" (fn [self & args]
              (let [b (tget self :bytes) p (tget self :pos) n (alength b)]
                (if (empty? args)
                  (if (>= p n) -1 (do (tput! self :pos (inc p)) (bit-and (aget b p) 0xff)))
                  (let [buf (first args)
                        off (or (second args) 0)
                        len (or (nth args 2 nil) (alength buf))]
                    (if (>= p n)
                      -1
                      (let [avail (min len (- n p))]
                        (dotimes [i avail] (aset buf (+ off i) (aget b (+ p i))))
                        (tput! self :pos (+ p avail))
                        avail))))))
     ;; The rest of the InputStream surface. Registering the ctor for
     ;; "ByteArrayInputStream"/"java.io.ByteArrayInputStream" replaces jolt's
     ;; native stream PROCESS-WIDE, so every (ByteArrayInputStream. …) in an app
     ;; that merely requires this library lands here — including ones that have
     ;; nothing to do with HTTP. Anything this table omits then reports as
     ;; "No matching field found: readAllBytes for class :object" (a 0-arg miss
     ;; reads as a field probe, and a tagged table has no modelled class), which
     ;; looks like a jolt reflection limitation and is not one. So the shim owes
     ;; the whole surface, not just what the client itself calls.
     "readAllBytes" (fn [self]
                      (let [b (tget self :bytes) p (tget self :pos) n (alength b)
                            out (byte-array (max 0 (- n p)))]
                        (dotimes [i (- n p)] (aset out i (aget b (+ p i))))
                        (tput! self :pos n)
                        out))
     ;; readNBytes reads UP TO n bytes and returns what it got (never -1, and an
     ;; empty array at EOF); a negative n is an IllegalArgumentException.
     "readNBytes" (fn [self & args]
                    (if (= 1 (count args))
                      (let [want (first args)]
                        (when (neg? want)
                          (throw (IllegalArgumentException. "len < 0")))
                        (let [b (tget self :bytes) p (tget self :pos) n (alength b)
                              take-n (min want (- n p))
                              out (byte-array (max 0 take-n))]
                          (dotimes [i take-n] (aset out i (aget b (+ p i))))
                          (tput! self :pos (+ p take-n))
                          out))
                      ;; readNBytes(buf, off, len) returns the count, 0 at EOF
                      (let [[buf off len] args
                            b (tget self :bytes) p (tget self :pos) n (alength b)
                            take-n (max 0 (min len (- n p)))]
                        (dotimes [i take-n] (aset buf (+ off i) (aget b (+ p i))))
                        (tput! self :pos (+ p take-n))
                        take-n)))
     ;; transferTo writes the remainder to dst and returns the count as a long.
     "transferTo" (fn [self dst]
                    (let [b (tget self :bytes) p (tget self :pos) n (alength b)
                          cnt (- n p)
                          out (byte-array (max 0 cnt))]
                      (dotimes [i cnt] (aset out i (aget b (+ p i))))
                      (tput! self :pos n)
                      (when (pos? cnt) (.write dst out 0 cnt))
                      cnt))
     ;; skip never goes past the end and never negative, like the reference.
     "skip" (fn [self k]
              (let [b (tget self :bytes) p (tget self :pos) n (alength b)
                    d (max 0 (min k (- n p)))]
                (tput! self :pos (+ p d))
                d))
     ;; mark/reset are supported on a ByteArrayInputStream; mark's readlimit is
     ;; ignored there, and reset with no mark returns to the initial position.
     "markSupported" (fn [self] true)
     "mark" (fn [self & _] (tput! self :mark (tget self :pos)) nil)
     "reset" (fn [self & _] (tput! self :pos (or (tget self :mark) 0)) nil)
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
     "getRef" (fn [self] (tget self :ref))
     "getUserInfo" (fn [self] (tget self :userinfo))
     "toString" (fn [self] (tget self :spec))
     "toExternalForm" (fn [self] (tget self :spec))
     "openConnection" (fn [self] (open-connection self))
     ;; openConnection().getInputStream(), as on the JVM: an error status
     ;; throws rather than handing back the error page as if it were the body.
     "openStream" (fn [self] (input-stream (open-connection self)))})

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
     ;; Gives up a body still on the wire: its connection is closed rather
     ;; than pooled, since what is left of the response is unread.
     "disconnect" (fn [self]
                    (when (tget self :performed)
                      (try (.close ^java.io.InputStream (body-stream self))
                           (catch Throwable _ nil)))
                    nil)
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
     "getInputStream" (fn [self] (input-stream self))
     "getErrorStream" (fn [self]
                        (when (>= (:status (ensure-performed! self)) 400)
                          (body-stream self)))
     "getContentLength" (fn [self]
                          (or (parse-long (or (header-ci (:header-pairs (ensure-performed! self)) "content-length") "")) -1))
     "setHostnameVerifier" (fn [self v] (tput! self :hostname-verifier v) nil)
     "setSSLSocketFactory" (fn [self f] (tput! self :ssl-factory f) (tput! self :insecure true) nil)})

  ;; java.security.SecureRandom comes from jolt-crypto (real RAND_bytes); the
  ;; javax.net.ssl surface (SSLContext, TrustManager, …) comes from
  ;; jolt.http.jdk, required above — clj-http-lite's trust-all-ssl! builds an
  ;; SSLContext over a trust-everything X509TrustManager and hands it here
  ;; through setSSLSocketFactory.

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
