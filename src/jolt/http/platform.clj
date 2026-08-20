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

;; A typed throwable carrying a JVM class name, so (class e) / catch / thrown?
;; match by class AND .getMessage/ex-message return the message.
(defn- throw-typed [class msg]
  (throw (jolt.host/throwable class (str msg))))

;; jolt models java.io.ByteArrayInputStream / ByteArrayOutputStream natively.
;; Where it does, USE ITS OWN and do not register a ctor over it: that override
;; is PROCESS-WIDE, so every (ByteArrayInputStream. …) in an app that merely
;; requires this library lands on the shim — including in namespaces with
;; nothing to do with HTTP. Beyond the surface gaps that keeps reintroducing,
;; the shim is a tagged table read through a Clojure fn per byte: draining 1 MB
;; with io/copy measured 1136 ns/byte against 0.34 for the host stream, ~3300x.
;; The output side is worse in kind — it accumulates into a persistent vector,
;; one boxed element per byte, so a large upload builds a vector as long as the
;; body.
;;
;; Probed rather than assumed, and probed for the WHOLE surface the shim
;; provides — read/available/readNBytes/mark/reset/markSupported/transferTo/
;; readAllBytes and the output side. A host that models these classes but only
;; part of their behaviour is worse than the shim, because the gap surfaces in
;; a consumer's code rather than here. jolt gained the last of them in
;; jolt-lang/jolt#681; on anything older the probe fails and the shims below are
;; registered exactly as before. This runs at load, before install!, so it
;; probes the host and not ourselves.
(def ^:private host-byte-streams?
  (and (try (let [s (java.io.ByteArrayInputStream. (byte-array [1 2 3 4]))]
              (and (= 1 (.read s))
                   (= 3 (.available s))
                   (= [2] (seq (.readNBytes s 1)))
                   (do (.mark s 0) (.markSupported s))
                   (= 3 (.read s))
                   (do (.reset s) (= 3 (.read s)))
                   (= 1 (.transferTo s (java.io.ByteArrayOutputStream.)))
                   (zero? (alength (.readAllBytes s)))))
            (catch Throwable _ false))
       (try (let [o (java.io.ByteArrayOutputStream.)]
              (.write o (byte-array [7 8]) 0 2)
              (.write o 9)
              (and (= [7 8 9] (seq (.toByteArray o))) (= 3 (.size o))))
            (catch Throwable _ false))))

;; --- byte coercion ---------------------------------------------------------
;; bytes flow as jolt byte-arrays. Coerce a stream shim / string / bytevector to
;; one; a byte-array passes through.
(defn- ->bytes [x]
  (cond
    (and (table? x) (= :jolt/bais (tget x :jolt/type)))
      (let [b (tget x :bytes) p (or (tget x :pos) 0)]
        (byte-array (drop p (seq b))))
    (and (table? x) (= :jolt/baos (tget x :jolt/type))) (byte-array (tget x :acc))
    ;; a real host stream, when jolt models them (see host-byte-streams? below).
    ;; readAllBytes reads from the CURRENT position, the same as the shim arm's
    ;; (drop p …).
    (and host-byte-streams? (instance? java.io.InputStream x)) (.readAllBytes x)
    (and host-byte-streams? (instance? java.io.ByteArrayOutputStream x)) (.toByteArray x)
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
  (if host-byte-streams?
    (java.io.ByteArrayInputStream. (byte-array bytes))
    (let [t (tt :jolt/bais)]
      (tput! t :jolt/input-stream true)
      (tput! t :bytes (byte-array bytes))
      (tput! t :pos 0)
      t)))

(defn make-baos []
  (if host-byte-streams?
    (java.io.ByteArrayOutputStream.)
    (let [t (tt :jolt/baos)]
      (tput! t :jolt/output-stream true)
      (tput! t :acc [])
      t)))

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
(defn- connect-stream [host port https? insecure? read-timeout conn-timeout]
  (if https?
    (tls/tls-connect host port insecure? read-timeout conn-timeout)
    (let [fd (net/connect (str host) port conn-timeout)]
      (net/set-read-timeout! fd read-timeout)
      fd)))

;; --- total response deadline ------------------------------------------------
;; SO_RCVTIMEO bounds INACTIVITY, not total duration, so a peer that sends one
;; byte every few seconds resets the timer forever and the request never returns.
;; Measured: a 3000ms :socket-timeout against a server trickling a byte per
;; second ran past two minutes and was still going.
;;
;; The bound goes in the read loop rather than in a watchdog, because a
;; trickling peer is precisely one whose reads DO return, so the loop gets
;; control regularly and can check the clock itself. The case where the loop
;; does not get control is total silence, which SO_RCVTIMEO already covers. The
;; two together bound the call from both sides.
;;
;; Set through a var rather than a request option because clj-http-lite forwards
;; a fixed set of options to the connection and this is not one of them. nil
;; means unbounded, which is the historical behaviour.
(def ^:private max-response-ms (atom nil))

(defn set-max-response-ms!
  "Cap the total wall-clock time of a response body, across all reads.

  Complements, and does not replace, the per-read `:socket-timeout`. Pass nil to
  remove the cap. Applies process-wide to every request made through this
  namespace."
  [ms]
  (reset! max-response-ms ms))

(defn- recv-all [stream]
  (let [cap @max-response-ms
        deadline (when (and cap (pos? cap)) (+ (System/currentTimeMillis) cap))]
    (loop [chunks []]
      (when (and deadline (> (System/currentTimeMillis) deadline))
        ;; Thrown, so perform!'s finally closes the stream. That is what stops a
        ;; trickling peer leaking a socket and a parked thread per attempt.
        (throw-typed "java.net.SocketTimeoutException"
                     (str "Response exceeded the total time limit of " cap "ms")))
      (if-let [b (s-read stream nil)]
        (recur (conj chunks b))
        (byte-array (mapcat seq chunks))))))

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
                                 (tget conn :insecure) (tget conn :read-timeout)
                                 (tget conn :connect-timeout))
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

;; Perform a java.net.http request synchronously over the same socket/TLS layer
;; clj-http-lite uses, returning a :jolt.http/response. This is what wires the
;; java.net.http shim's send/sendAsync to a real request.
(defn- net-http-send [request handler conn-timeout]
  (let [url     (parse-url (str (tget request :uri)))
        method  (or (tget request :method) "GET")
        headers (or (tget request :headers) [])
        body    (when-let [bp (tget request :body)] (tget bp :bytes))
        https?  (= "https" (tget url :protocol))
        stream  (connect-stream (tget url :host) (effective-port url) https? false 30000 conn-timeout)
        resp    (try
                  (s-write stream (build-request method url headers body))
                  (parse-response (recv-all stream))
                  (finally (try (s-close stream) (catch Throwable _ nil))))
        ;; BodyHandlers.ofString hands the body back as a String; ofByteArray (the
        ;; aws backend's default) as the raw byte[]; ofInputStream (babashka's) as a
        ;; ByteArrayInputStream over those bytes.
        body-bytes (:body resp)
        out-body (cond
                   (= handler :jolt.http/handler-string) (String. ^bytes body-bytes "UTF-8")
                   (= handler :jolt.http/handler-inputstream) (make-bais body-bytes)
                   :else body-bytes)]
    (doto (tt :jolt.http/response)
      (tput! :status (:status resp))
      (tput! :body out-body)
      (tput! :uri (tget request :uri))
      (tput! :version (doto (tt :jolt.http/version-enum) (tput! :name "HTTP_1_1")))
      (tput! :resp-headers (:header-pairs resp)))))

;; A settled CompletableFuture: the request ran synchronously, so the future
;; already holds a value or an error. thenApply/exceptionally apply immediately.
(defn- settled-future [value error]
  (doto (tt :jolt.http/future) (tput! :value value) (tput! :error error)))

;; java.net.http stores the connect timeout as a java.time.Duration; the socket
;; layer wants milliseconds. Fall back to nil (no timeout) if it isn't a number
;; and has no .toMillis (e.g. an unknown shim shape).
(defn- duration-ms [d]
  (cond
    (nil? d) nil
    (number? d) d
    :else (try (.toMillis d) (catch Throwable _ nil))))

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
  ;; --- java.net.http (JDK 11+ HttpClient) -----------------------------------
  ;; Construction + getters for the cognitect aws-api java backend (and any lib on
  ;; the modern client). The conformance tests build clients/requests and read them
  ;; back; live sends are not covered here (sendAsync needs CompletableFuture).
  (doseq [nm ["HttpClient$Redirect" "java.net.http.HttpClient$Redirect"]]
    (__register-class-statics! nm {"NEVER" :jolt.http.redirect/NEVER
                                   "ALWAYS" :jolt.http.redirect/ALWAYS
                                   "NORMAL" :jolt.http.redirect/NORMAL}))
  ;; HttpClient.Version enum values: a shim carrying the enum name, since babashka's
  ;; response->map reads (.name (.version resp)) to recover the version keyword.
  (__register-class-methods! :jolt.http/version-enum
    {"name" (fn [self] (tget self :name))
     "toString" (fn [self] (tget self :name))})
  (doseq [nm ["HttpClient$Version" "java.net.http.HttpClient$Version"]]
    (__register-class-statics! nm {"HTTP_1_1" (doto (tt :jolt.http/version-enum) (tput! :name "HTTP_1_1"))
                                   "HTTP_2"   (doto (tt :jolt.http/version-enum) (tput! :name "HTTP_2"))}))
  (doseq [nm ["HttpClient" "java.net.http.HttpClient"]]
    (__register-class-statics! nm {"newBuilder" (fn [& _] (tt :jolt.http/client-builder))
                                   "newHttpClient" (fn [& _] (tt :jolt.http/client))}))
  (__register-class-methods! :jolt.http/client-builder
    {"connectTimeout"  (fn [self d] (tput! self :connect-timeout d) self)
     "followRedirects" (fn [self r] (tput! self :follow-redirects r) self)
     "version"         (fn [self v] (tput! self :version v) self)
     "build"           (fn [self] (doto (tt :jolt.http/client)
                                    (tput! :connect-timeout (tget self :connect-timeout))
                                    (tput! :follow-redirects (tget self :follow-redirects))
                                    (tput! :version (tget self :version))))})
  (__register-class-methods! :jolt.http/client
    {"connectTimeout"  (fn [self] (let [d (tget self :connect-timeout)]
                                    (if d (java.util.Optional/of d) (java.util.Optional/empty))))
     "followRedirects" (fn [self] (tget self :follow-redirects))
     "version"         (fn [self] (tget self :version))
     ;; live send over the socket/TLS layer. send is synchronous; sendAsync runs
     ;; the same request and hands back an already-settled future (thenApply /
     ;; exceptionally apply at once) — enough for the cognitect aws-api flow, which
     ;; does (.sendAsync client req handler) then .thenApply/.exceptionally.
      "send"            (fn [self req handler]
                          (net-http-send req handler (duration-ms (tget self :connect-timeout))))
      "sendAsync"       (fn [self req handler]
                          (try (settled-future (net-http-send req handler (duration-ms (tget self :connect-timeout))) nil)
                               (catch Throwable e (settled-future nil e))))})
  (__register-class-methods! :jolt.http/future
    {"thenApply"     (fn [self f] (if (tget self :error) self
                                    (settled-future (.apply f (tget self :value)) nil)))
     "exceptionally" (fn [self f] (if-let [e (tget self :error)]
                                    (settled-future (.apply f e) nil) self))
     "get"           (fn [self] (if-let [e (tget self :error)] (throw e) (tget self :value)))
     "join"          (fn [self] (if-let [e (tget self :error)] (throw e) (tget self :value)))})
  (doseq [nm ["HttpRequest" "java.net.http.HttpRequest"]]
    (__register-class-statics! nm {"newBuilder" (fn [& _] (doto (tt :jolt.http/request-builder) (tput! :headers [])))}))
  (__register-class-methods! :jolt.http/request-builder
    {"uri"     (fn [self uri] (tput! self :uri uri) self)
     "method"  (fn [self m bp] (tput! self :method (str m)) (tput! self :body bp) self)
     "GET"     (fn [self] (tput! self :method "GET") self)
     "POST"    (fn [self bp] (tput! self :method "POST") (tput! self :body bp) self)
     "PUT"     (fn [self bp] (tput! self :method "PUT") (tput! self :body bp) self)
     "DELETE"  (fn [self] (tput! self :method "DELETE") self)
     "header"  (fn [self k v] (tput! self :headers (conj (tget self :headers) [(str k) (str v)])) self)
     ;; HttpRequest.Builder.headers(String...): a flat name/value array (babashka
     ;; passes (into-array String (coerce-headers headers))).
     "headers" (fn [self arr] (tput! self :headers (into (tget self :headers)
                                                         (map vec (partition 2 (vec arr)))))
                 self)
     "expectContinue" (fn [self _] self)   ; no-op; the socket path doesn't 100-continue
     "version" (fn [self v] (tput! self :version v) self)
     "timeout" (fn [self d] (tput! self :timeout d) self)
     "build"   (fn [self] (doto (tt :jolt.http/request)
                            (tput! :uri (tget self :uri))
                            (tput! :method (or (tget self :method) "GET"))
                            (tput! :timeout (tget self :timeout))
                            (tput! :headers (tget self :headers))
                            (tput! :body (tget self :body))))})
  (__register-class-methods! :jolt.http/request
    {"uri"     (fn [self] (tget self :uri))
     "method"  (fn [self] (tget self :method))
     "timeout" (fn [self] (let [d (tget self :timeout)]
                            (if d (java.util.Optional/of d) (java.util.Optional/empty))))
     "headers" (fn [self] (doto (tt :jolt.http/headers) (tput! :pairs (tget self :headers))))})
  ;; HttpHeaders.map() groups to {name [values]} (java.net.http always vectors
  ;; values) with LOWERCASED names, like java.net.http — babashka's response->map
  ;; and callers look keys up lower-case. firstValue matches case-insensitively.
  (__register-class-methods! :jolt.http/headers
    {"map" (fn [self] (reduce (fn [m [k v]] (update m (str/lower-case k) (fnil conj []) v)) {} (tget self :pairs)))
     "firstValue" (fn [self k] (let [low (str/lower-case k)]
                                 (if-let [p (first (filter #(= low (str/lower-case (first %))) (tget self :pairs)))]
                                   (java.util.Optional/of (second p)) (java.util.Optional/empty))))})
  (doseq [nm ["HttpRequest$BodyPublishers" "java.net.http.HttpRequest$BodyPublishers"]]
    (__register-class-statics! nm {"noBody"      (fn [& _] (tt :jolt.http/body-empty))
                                   "ofByteArray" (fn [ba & _] (doto (tt :jolt.http/body-bytes) (tput! :bytes (byte-array ba))))
                                   "ofString"    (fn [s & _] (doto (tt :jolt.http/body-bytes) (tput! :bytes (->bytes (str s)))))
                                   ;; ofInputStream takes a Supplier<InputStream>; ofFile a Path.
                                   ;; Both are read eagerly to a byte[] here (no streaming upload).
                                   "ofInputStream" (fn [supplier & _]
                                                     (doto (tt :jolt.http/body-bytes)
                                                       (tput! :bytes (->bytes (.get supplier)))))
                                   "ofFile"      (fn [path & _]
                                                   (doto (tt :jolt.http/body-bytes)
                                                     (tput! :bytes (->bytes (slurp (str path))))))}))
  (doseq [nm ["HttpResponse$BodyHandlers" "java.net.http.HttpResponse$BodyHandlers"]]
    (__register-class-statics! nm {"ofByteArray"   (fn [& _] :jolt.http/handler-bytes)
                                   "ofString"      (fn [& _] :jolt.http/handler-string)
                                   "ofInputStream" (fn [& _] :jolt.http/handler-inputstream)}))
  (__register-class-methods! :jolt.http/response
    {"statusCode" (fn [self] (tget self :status))
     "body"       (fn [self] (tget self :body))
     "uri"        (fn [self] (tget self :uri))
     ;; babashka's response->map reads (.name (.version resp)); the version enum is
     ;; the same keyword the request/client side uses.
     "version"    (fn [self] (or (tget self :version) (doto (tt :jolt.http/version-enum) (tput! :name "HTTP_1_1"))))
     "headers"    (fn [self] (doto (tt :jolt.http/headers) (tput! :pairs (tget self :resp-headers))))})

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
