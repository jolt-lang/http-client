(ns jolt.http.core
  "The HTTP/1.1 engine shared by every shim in this library: byte helpers, the
  URL parser, the plain-socket/TLS stream abstraction, connect (direct or through
  an HTTP proxy), request serialisation and response parsing.

  jolt.http.platform layers java.net.URL / HttpURLConnection over it (what
  clj-http-lite drives), jolt.http.jdk layers java.net.http (what
  babashka.http-client drives) and jolt.http.websocket layers java.net.http's
  WebSocket. Keeping it here is what stops the two client surfaces drifting: one
  transport, one redirect policy, one deadline.

  Shim objects are host tagged-tables; fields are read/written with
  jolt.host/ref-get / ref-put!."
  (:require [clojure.string :as str]
            [jolt.http.net :as net]
            [jolt.http.tls :as tls]))

;; --- helpers ---------------------------------------------------------------
(defn tt [tag] (jolt.host/tagged-table tag))
(defn tget [t k] (jolt.host/ref-get t k))
(defn tput! [t k v] (jolt.host/ref-put! t k v))
(defn table? [x] (jolt.host/table? x))

;; A typed throwable carrying a JVM class name, so (class e) / catch / thrown?
;; match by class AND .getMessage/ex-message return the message.
(defn throw-typed [class msg]
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
(def host-byte-streams?
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
(defn ->bytes [x]
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

(defn ba->latin1 [ba] (String. ba "ISO-8859-1"))   ;; byte-array -> string, 1 char/byte
(defn latin1->ba [s] (byte-array (map int s)))      ;; string -> byte-array (codes 0-255)
(defn concat-ba [a b]
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
(defn min-idx [s chars]
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

(defn url-file-path [url]
  (let [spec (tget url :spec)]
    (loop [p (if (str/starts-with? spec "file:") (subs spec 5) (or (tget url :path) ""))]
      (if (and (> (count p) 1) (str/starts-with? p "//")) (recur (subs p 1)) p))))

(defn default-port? [protocol port]
  (or (= port -1) (and (= protocol "http") (= port 80)) (and (= protocol "https") (= port 443))))

(defn effective-port [url]
  (let [p (tget url :port)]
    (if (and (number? p) (>= p 0)) p (if (= (tget url :protocol) "https") 443 80))))

;; --- stream abstraction (plain socket fd vs TLS stream table) --------------
(defn s-write [stream data] (if (table? stream) ((tget stream :write) stream data) (net/send-bytes stream data)))
(defn s-read  [stream timeout] (if (table? stream) ((tget stream :read) stream timeout) (net/recv-bytes stream)))
(defn s-close [stream] (if (table? stream) ((tget stream :close)) (net/close stream)))

;; --- HTTP/1.1 client -------------------------------------------------------
(defn connect-stream
  "A connected stream to host:port — a TLS stream when https?, a raw socket fd
  otherwise. `ssl`, when given, carries the caller's PKCS#12 key/trust stores
  (see jolt.http.tls/tls-connect)."
  ([host port https? insecure? read-timeout conn-timeout]
   (connect-stream host port https? insecure? read-timeout conn-timeout nil))
  ([host port https? insecure? read-timeout conn-timeout ssl]
   (if https?
     (tls/tls-connect host port insecure? read-timeout conn-timeout ssl)
     (let [fd (net/connect (str host) port conn-timeout)]
       (net/set-read-timeout! fd read-timeout)
       fd))))

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
(def max-response-ms (atom nil))

(defn set-max-response-ms!
  "Cap the total wall-clock time of a response body, across all reads.

  Complements, and does not replace, the per-read `:socket-timeout`. Pass nil to
  remove the cap. Applies process-wide to every request made through this
  namespace."
  [ms]
  (reset! max-response-ms ms))

(defn recv-all
  "Drain `stream` to a byte-array. `deadline`, when given, is an absolute
  System/currentTimeMillis after which the read fails — a per-request bound on
  top of the process-wide one, which is what java.net.http's HttpRequest.timeout
  is."
  ([stream] (recv-all stream nil))
  ([stream deadline]
  (let [cap @max-response-ms
        cap-deadline (when (and cap (pos? cap)) (+ (System/currentTimeMillis) cap))
        deadline (cond (and deadline cap-deadline) (min deadline cap-deadline)
                       :else (or deadline cap-deadline))]
    (loop [chunks []]
      (when (and deadline (> (System/currentTimeMillis) deadline))
        ;; Thrown, so perform!'s finally closes the stream. That is what stops a
        ;; trickling peer leaking a socket and a parked thread per attempt.
        (throw-typed "java.net.SocketTimeoutException"
                     (str "Response exceeded the total time limit of "
                          (or cap "the request timeout") "ms")))
      (if-let [b (s-read stream nil)]
        (recur (conj chunks b))
        (byte-array (mapcat seq chunks)))))))

(defn header-ci [pairs name]
  (let [low (str/lower-case name)]
    (reduce (fn [v pair] (if (= low (str/lower-case (first pair))) (second pair) v)) nil pairs)))

(defn dechunk [raw]
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

(defn parse-response [raw]
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

(defn build-request
  "Serialise one HTTP/1.1 request. `absolute-target`, when given, replaces the
  origin-form path with a full URI — the request-target form a plain-http proxy
  needs (RFC 7230 5.3.2)."
  ([method url req-headers body] (build-request method url req-headers body nil))
  ([method url req-headers body absolute-target]
  (let [host (tget url :host)
        port (effective-port url)
        path (or absolute-target
                 (let [p (tget url :path) q (tget url :query)]
                   (str (if (or (nil? p) (= "" p)) "/" p) (if q (str "?" q) ""))))
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
      (if body (concat-ba head (->bytes body)) head)))))

(defn resolve-location [base loc]
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

(def redirect-statuses #{301 302 303 307 308})
