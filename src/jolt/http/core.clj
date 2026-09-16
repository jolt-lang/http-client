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

(defn ba->latin1 [ba] (String. ba "ISO-8859-1"))   ;; byte-array -> string, 1 char/byte
(defn latin1->ba [s] (.getBytes ^String s "ISO-8859-1"))  ;; string -> byte-array (codes 0-255)

;; Bulk byte moves go through System/arraycopy, which is one native call rather
;; than a boxed element per byte. Probed rather than assumed, the way
;; host-byte-streams? is: :jolt/min-version is 0.8.1 and arraycopy need not be
;; modelled there, so an aset loop stands in when it is missing. The gap is
;; large enough to be the difference between a working client and an unusable
;; one — assembling 1 MB of response measured 0.1 ms through arraycopy, 42 ms
;; through the loop, and 1476 ms through the (byte-array (mapcat seq chunks))
;; this replaced, which boxed a Byte per byte and put an 8 MB download at 39 s.
(def ^:private arraycopy?
  (try (let [dst (byte-array 3)]
         (System/arraycopy (byte-array [1 2 3]) 0 dst 0 3)
         (= [1 2 3] (vec dst)))
       (catch Throwable _ false)))

(defn copy-into!
  "Copy `len` bytes of `src` from `soff` into `dst` at `doff`; returns dst."
  [src soff dst doff len]
  (if arraycopy?
    (System/arraycopy src soff dst doff len)
    (dotimes [i len] (aset dst (+ doff i) (aget src (+ soff i)))))
  dst)

(defn sub-ba
  "The bytes of `ba` in [from, to) as a new byte-array."
  [ba from to]
  (let [n (max 0 (- to from))
        out (byte-array n)]
    (when (pos? n) (copy-into! ba from out 0 n))
    out))

(defn concat-bas
  "Concatenate a seq of byte-arrays into one."
  [chunks]
  (let [total (reduce (fn [n c] (+ n (alength c))) 0 chunks)
        out (byte-array total)]
    (loop [cs (seq chunks) off 0]
      (if cs
        (let [c (first cs) len (alength c)]
          (copy-into! c 0 out off len)
          (recur (next cs) (+ off len)))
        out))))

(defn concat-ba [a b] (concat-bas [a b]))

;; --- byte coercion ---------------------------------------------------------
;; bytes flow as jolt byte-arrays. Coerce a stream shim / string / bytevector to
;; one; a byte-array passes through.
(defn ->bytes [x]
  (cond
    (and (table? x) (= :jolt/bais (tget x :jolt/type)))
      (let [b (tget x :bytes) p (or (tget x :pos) 0)]
        (sub-ba b p (alength b)))
    (and (table? x) (= :jolt/baos (tget x :jolt/type))) (byte-array (tget x :acc))
    ;; a real host stream, when jolt models them (see host-byte-streams? above).
    ;; readAllBytes reads from the CURRENT position, the same as the shim arm's
    ;; (drop p …).
    (and host-byte-streams? (instance? java.io.InputStream x)) (.readAllBytes x)
    (and host-byte-streams? (instance? java.io.ByteArrayOutputStream x)) (.toByteArray x)
    ;; already bytes: hand them back. (byte-array <byte-array>) copies through a
    ;; boxed element per byte — 1.2 s for 8 MB — and there is nothing to convert.
    (bytes? x) x
    :else (byte-array x)))                       ;; string / bytevector

;; --- byte streams ----------------------------------------------------------
(defn make-bais [bytes]
  ;; ->bytes rather than (byte-array bytes): re-wrapping an array that already
  ;; IS one cost 5 s for an 8 MB response body, which is most of what a large
  ;; download used to spend after the transport had finished with it.
  (let [ba (->bytes bytes)]
    (if host-byte-streams?
      (java.io.ByteArrayInputStream. ba)
      (let [t (tt :jolt/bais)]
        (tput! t :jolt/input-stream true)
        (tput! t :bytes ba)
        (tput! t :pos 0)
        t))))

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
          after-scheme (subs s (inc colon))
          ;; The fragment belongs to the client, never to the request: it is not
          ;; part of the path or the query and java.net.http does not put it on
          ;; the wire. :spec still carries it, because java.net.URL.toString and
          ;; java.net.URI.toString both do.
          hash (str/index-of after-scheme "#")
          rest (if hash (subs after-scheme 0 hash) after-scheme)
          url (tt :jolt/url)]
      (tput! url :spec s) (tput! url :protocol protocol)
      (tput! url :host nil) (tput! url :port -1)
      (tput! url :path "") (tput! url :query nil) (tput! url :userinfo nil)
      (tput! url :ref (when hash (subs after-scheme (inc hash))))
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
              ;; An IPv6 literal is bracketed and full of colons, so the port
              ;; separator is the first colon AFTER the closing bracket. The
              ;; brackets stay in :host — java.net.URL/URI both report
              ;; getHost() as "[::1]" — and jolt.http.net strips them for
              ;; getaddrinfo, which wants the bare address.
              pc (if (str/starts-with? hostport "[")
                   (when-let [close (str/index-of hostport "]")]
                     (str/index-of hostport ":" close))
                   (str/index-of hostport ":"))]
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

(defn spec-no-ref
  "The URL's spec with any fragment removed — the absolute-form request-target a
  plain-http proxy is given (RFC 7230 5.3.2 admits no fragment)."
  [url]
  (let [s (str (tget url :spec))]
    (if-let [i (str/index-of s "#")] (subs s 0 i) s)))

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

;; --- connection pool --------------------------------------------------------
;; Every request used to open a fresh socket, and for https a fresh TLS session:
;; a connect plus a full handshake — two round trips — per call, against a server
;; the client had usually just finished talking to. Reuse is only safe now that
;; the response says how long it is (see read-response): a client that framed on
;; the connection closing could never keep one open.
;;
;; A pooled socket can still be retired by the peer between requests, which no
;; check can rule out. Two things cover that: idle-dead? rejects one the peer has
;; already closed, and a reused connection that yields NO response bytes is
;; retried once on a fresh one — the peer cannot have acted on a request it never
;; read.

(def pool-enabled?
  "Whether connections are kept alive and reused. Reset to false to make every
  request open (and close) its own socket."
  (atom true))

(def pool-idle-ms
  "How long an unused pooled connection is kept before it is closed."
  (atom 5000))

(def pool-max-per-key
  "How many idle connections are kept per origin."
  (atom 8))

(def ^:private pool (atom {}))

(defn- stream-fd
  "The socket underneath a stream — the fd itself for plaintext, :sock for a TLS
  stream table."
  [stream]
  (if (table? stream) (tget stream :sock) stream))

(defn pool-clear!
  "Close and forget every pooled connection."
  []
  (doseq [[_ entries] (first (swap-vals! pool (constantly {})))
          e entries]
    (try (s-close (:stream e)) (catch Throwable _ nil)))
  nil)

(defn pool-count
  "How many idle connections are currently pooled (for `key`, or in total)."
  ([] (reduce + 0 (map count (vals @pool))))
  ([key] (count (get @pool key))))

(defn pool-key
  "What makes two connections interchangeable: the origin, and everything that
  configures the transport to it."
  [host port https? insecure? ssl proxy]
  [(str host) port (boolean https?) (boolean insecure?)
   (when ssl [(System/identityHashCode (get-in ssl [:key-store :bytes]))
              (System/identityHashCode (get-in ssl [:trust-store :bytes]))])
   proxy])

(defn- expired? [e now] (>= (- now (:at e)) @pool-idle-ms))

(defn- prune!
  "Close every idle connection that has sat past pool-idle-ms, across all
  origins. Without it an app that touches many hosts once each keeps a socket
  open per host for the life of the process; with it, open fds are bounded by
  the origins actually talked to inside the idle window. Cheap — the map holds
  one entry per origin, not per request."
  []
  (let [now (System/currentTimeMillis)]
    (loop []
      (let [m @pool
            stale (mapcat (fn [[k es]] (map (fn [e] [k e]) (filter #(expired? % now) es))) m)]
        (when (seq stale)
          (let [m' (reduce-kv (fn [acc k es]
                                (let [keep (vec (remove #(expired? % now) es))]
                                  (if (seq keep) (assoc acc k keep) acc)))
                              {} m)]
            (if (compare-and-set! pool m m')
              (doseq [[_ e] stale] (try (s-close (:stream e)) (catch Throwable _ nil)))
              (recur))))))))

(defn pool-acquire
  "An idle connection for `key`, or nil.

  compare-and-set! rather than swap!, and the liveness check outside it: swap!
  may run its function more than once, so taking a connection there could hand
  the same socket to two threads or drop one it had not actually removed. The
  CAS takes exactly one entry, and only then is it ours to inspect or close."
  [key]
  (when @pool-enabled?
    (loop []
      (let [m @pool
            entries (vec (get m key))]
        (when (seq entries)
          (let [e (peek entries)
                remaining (pop entries)]
            (if (compare-and-set! pool m (if (seq remaining)
                                           (assoc m key remaining)
                                           (dissoc m key)))
              ;; exclusively ours now
              (if (and (not (expired? e (System/currentTimeMillis)))
                       (not (net/idle-dead? (stream-fd (:stream e)))))
                (:stream e)
                (do (try (s-close (:stream e)) (catch Throwable _ nil))
                    (recur)))
              (recur))))))))

(defn set-stream-timeout!
  "Re-apply a read timeout to a stream taken from the pool. A connection carries
  the SO_RCVTIMEO of whichever request opened it, and the next request to reuse
  it is entitled to its own."
  [stream ms]
  (try (net/set-read-timeout! (stream-fd stream) ms) (catch Throwable _ nil))
  stream)

(defn pool-release!
  "Hand a still-usable connection back. Closed rather than kept when pooling is
  off or the origin already holds its share."
  [key stream]
  (let [kept (and @pool-enabled?
                  (loop []
                    (let [m @pool
                          entries (vec (get m key))]
                      (if (>= (count entries) @pool-max-per-key)
                        false
                        (or (compare-and-set!
                              pool m
                              (assoc m key (conj entries {:stream stream
                                                          :at (System/currentTimeMillis)})))
                            (recur))))))]
    (if kept
      (prune!)
      (try (s-close stream) (catch Throwable _ nil)))
    nil))

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

(defn- effective-deadline
  "The absolute millisecond deadline in force: the caller's, the process-wide
  cap, or whichever of the two comes first."
  [deadline]
  (let [cap @max-response-ms
        cap-deadline (when (and cap (pos? cap)) (+ (System/currentTimeMillis) cap))]
    (cond (and deadline cap-deadline) (min deadline cap-deadline)
          :else (or deadline cap-deadline))))

(defn- check-deadline! [deadline]
  (when (and deadline (> (System/currentTimeMillis) deadline))
    ;; Thrown, so perform!'s finally closes the stream. That is what stops a
    ;; trickling peer leaking a socket and a parked thread per attempt.
    (throw-typed "java.net.SocketTimeoutException"
                 (str "Response exceeded the total time limit of "
                      (or @max-response-ms "the request timeout") "ms"))))

(defn recv-all
  "Drain `stream` to a byte-array. `deadline`, when given, is an absolute
  System/currentTimeMillis after which the read fails — a per-request bound on
  top of the process-wide one, which is what java.net.http's HttpRequest.timeout
  is."
  ([stream] (recv-all stream nil))
  ([stream deadline]
   (let [deadline (effective-deadline deadline)]
     (loop [chunks []]
       (check-deadline! deadline)
       (if-let [b (s-read stream nil)]
         (recur (conj chunks b))
         (concat-bas chunks))))))

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

(defn- parse-head
  "Status line + header pairs from the header block (a latin1 string, no
  terminator)."
  [head]
  (let [lines (str/split head #"\r\n")
        status-line (first lines)
        parts (str/split status-line #" ")
        status (or (parse-long (nth parts 1 ""))
                   (throw-typed "java.io.IOException" (str "bad status line: " status-line)))]
    {:status status
     :version (str/upper-case (str (first parts)))
     :header-pairs (vec (keep (fn [line]
                                (when-let [c (str/index-of line ":")]
                                  [(str/trim (subs line 0 c)) (str/trim (subs line (inc c)))]))
                              (rest lines)))}))

(defn parse-response [raw]
  ;; raw: the full response byte-array, read to EOF. Kept for callers that
  ;; already hold the whole thing; read-response is the framed path.
  (let [s (ba->latin1 raw)
        end (str/index-of s "\r\n\r\n")]
    (when (nil? end) (throw-typed "java.io.IOException" "malformed response: no header terminator"))
    (let [{:keys [status header-pairs]} (parse-head (subs s 0 end))
          body-raw (subs s (+ end 4))
          te (header-ci header-pairs "transfer-encoding")
          body (if (and te (str/includes? (str/lower-case te) "chunked")) (dechunk body-raw) body-raw)]
      {:status status :header-pairs header-pairs :body (latin1->ba body)})))

;; --- framed response reading -----------------------------------------------
;; Reading to EOF and slicing afterwards only works because every request we
;; send carries `Connection: close`, and it costs a full read timeout against
;; any peer that ignores it — measured: a complete `Content-Length: 5` response
;; from a server holding the socket open blocked for the whole 3000ms request
;; timeout and then failed, on a response that had already arrived. So the body
;; length is taken from the framing the response itself declares (RFC 7230 3.3.3)
;; and only the no-framing case falls back to reading until close.

(defn- index-of-crlf
  "The index of the first CRLF in `ba` at or after `from`, or nil."
  [ba from]
  (let [n (alength ba)]
    (loop [i (max 0 from)]
      (when (< (inc i) n)
        (if (and (= 13 (bit-and (aget ba i) 0xff))
                 (= 10 (bit-and (aget ba (inc i)) 0xff)))
          i
          (recur (inc i)))))))

(defn- read-more!
  "One more chunk off the stream, or nil at EOF."
  [stream deadline]
  (check-deadline! deadline)
  (s-read stream nil))

(defn- ensure-bytes
  "[buf pos] with at least `k` readable bytes from `pos`, reading as needed.
  Compacts before each read, so the copy is bounded by what is still unconsumed."
  [stream buf pos k deadline]
  (loop [buf buf pos pos]
    (if (>= (- (alength buf) pos) k)
      [buf pos]
      (if-let [b (read-more! stream deadline)]
        (recur (concat-bas [(sub-ba buf pos (alength buf)) b]) 0)
        (throw-typed "java.io.IOException" "connection closed mid-body")))))

(defn- fill-into!
  "Fill dst[off, off+len) from the stream. Returns whatever was read past the
  end, as a byte-array."
  [stream dst off len deadline]
  (loop [off off remaining len]
    (if (zero? remaining)
      (byte-array 0)
      (if-let [b (read-more! stream deadline)]
        (let [n (alength b)]
          (if (<= n remaining)
            (do (copy-into! b 0 dst off n) (recur (+ off n) (- remaining n)))
            (do (copy-into! b 0 dst off remaining)
                (sub-ba b remaining n))))
        (throw-typed "java.io.IOException" "connection closed mid-body")))))

(defn- crlf-line
  "The next CRLF-terminated line at `pos`, reading as needed. Returns
  [line buf pos-after-the-CRLF]."
  [stream buf pos deadline]
  (let [[buf pos] (loop [buf buf pos pos]
                    (if (index-of-crlf buf pos)
                      [buf pos]
                      (if-let [b (read-more! stream deadline)]
                        (recur (concat-bas [(sub-ba buf pos (alength buf)) b]) 0)
                        (throw-typed "java.io.IOException" "connection closed mid-chunk"))))
        crlf (index-of-crlf buf pos)]
    [(ba->latin1 (sub-ba buf pos crlf)) buf (+ crlf 2)]))

(defn- drain-trailers!
  "Consume a chunked message's trailer section — header lines up to a blank one
  — after the terminal chunk. It is not optional once the connection is reused:
  anything left of this message arrives in front of the NEXT response on it.
  Failing here means the peer went away rather than sending the trailers, which
  costs nothing — the body is already complete, and a pooled socket the peer has
  closed is detected before it is handed out again."
  [stream buf pos deadline]
  (try (loop [buf buf pos pos]
         (let [[l buf pos] (crlf-line stream buf pos deadline)]
           (when-not (= "" l) (recur buf pos))))
       (catch Throwable _ nil))
  nil)

(defn- read-sized
  "Exactly `len` body bytes, given `pending` (what was read past the headers)."
  [stream pending len deadline]
  (let [have (alength pending)]
    (if (>= have len)
      (sub-ba pending 0 len)
      (let [out (byte-array len)]
        (copy-into! pending 0 out 0 have)
        (fill-into! stream out have (- len have) deadline)
        out))))

(defn- read-chunked
  "A chunked body, given `pending` (what was read past the headers). A chunk
  larger than what is buffered is read straight into its own array rather than
  by growing and recopying the buffer, so one large chunk stays linear."
  [stream pending deadline]
  (loop [buf pending pos 0 out []]
    (let [[buf pos] (loop [buf buf pos pos]
                      (if (index-of-crlf buf pos)
                        [buf pos]
                        (if-let [b (read-more! stream deadline)]
                          (recur (concat-bas [(sub-ba buf pos (alength buf)) b]) 0)
                          (throw-typed "java.io.IOException" "connection closed mid-chunk"))))
          crlf (index-of-crlf buf pos)
          line (ba->latin1 (sub-ba buf pos crlf))
          semi (str/index-of line ";")
          size (try (Long/parseLong (str/trim (if semi (subs line 0 semi) line)) 16)
                    (catch Throwable _ nil))]
      (cond
        ;; A size we cannot read means the rest of the body is unrecoverable.
        ;; Returning what came before it silently truncated the response.
        (nil? size) (throw-typed "java.io.IOException"
                                 (str "malformed chunk size: " (pr-str line)))
        (neg? size) (throw-typed "java.io.IOException" (str "negative chunk size: " size))
        (zero? size) (do (drain-trailers! stream buf (+ crlf 2) deadline)
                         (concat-bas out))
        :else
        (let [data-start (+ crlf 2)
              n (alength buf)
              have (max 0 (- n data-start))
              copied (min size have)
              piece (byte-array size)
              _ (copy-into! buf data-start piece 0 copied)
              ;; when copied < size the buffer ended inside the chunk, so there
              ;; is nothing after it; otherwise the tail is what we already hold
              overflow (if (< copied size)
                         (fill-into! stream piece copied (- size copied) deadline)
                         (sub-ba buf (+ data-start size) n))
              ;; the CRLF that closes the chunk
              [buf pos] (ensure-bytes stream overflow 0 2 deadline)]
          (recur buf (+ pos 2) (conj out piece)))))))

;; --- streaming bodies -------------------------------------------------------
;; `:as :stream` (BodyHandlers/ofInputStream) used to hand back a
;; ByteArrayInputStream over a body that had already been read to EOF, so the
;; CALL did not return until the response ended: a live SSE stream — an LLM token
;; feed, an MCP text/event-stream, a log tailer — either blocked forever or died
;; at :timeout, and every such client had to shell out to curl instead
;; (jolt-lang/jolt#1007).
;;
;; The readers below pull one framed piece of the body off the wire per call, so
;; the response can be handed back the moment the headers are in. Framing is the
;; response's own — the same Content-Length / chunked / read-to-close reading the
;; buffered path does — so the stream ends where the BODY ends and not where the
;; connection does.
;;
;; `deadline` here is NOT the request timeout. java.net.http's HttpRequest.timeout
;; bounds the time to the RESPONSE, and does not cut a body already in flight; a
;; total deadline over the body is what made a stream that outlived :timeout fail
;; mid-flight on jolt and succeed on the JVM (jolt-lang/jolt#1017). What bounds a
;; streamed body is the socket's own read timeout — inactivity, which is what an
;; SSE reader wants — plus set-max-response-ms!, which an app asks for by name.

(defn- sized-pull
  "Pulls a Content-Length body, `len` bytes, in the pieces it arrives in."
  [stream pending len deadline]
  (let [buf (atom pending) left (atom len)]
    (fn []
      (when (pos? @left)
        (let [b (if (pos? (alength @buf))
                  @buf
                  (or (read-more! stream deadline)
                      (throw-typed "java.io.IOException" "connection closed mid-body")))
              n (min @left (alength b))]
          (reset! buf (sub-ba b n (alength b)))
          (swap! left - n)
          (sub-ba b 0 n))))))

(defn- to-close-pull
  "Pulls a body with no framing at all: the peer's close is the delimiter."
  [stream pending deadline]
  (let [buf (atom pending) done (atom false)]
    (fn []
      (when-not @done
        (if (pos? (alength @buf))
          (let [b @buf] (reset! buf (byte-array 0)) b)
          (or (read-more! stream deadline)
              (do (reset! done true) nil)))))))

(defn- chunked-pull
  "Pulls a chunked body one chunk at a time."
  [stream pending deadline]
  (let [state (atom {:buf pending :pos 0 :done false})]
    (fn []
      (let [{start-buf :buf start-pos :pos done :done} @state]
        (when-not done
          (let [[line buf pos] (crlf-line stream start-buf start-pos deadline)
                semi (str/index-of line ";")
                size (try (Long/parseLong (str/trim (if semi (subs line 0 semi) line)) 16)
                          (catch Throwable _ nil))]
            (cond
              (nil? size) (throw-typed "java.io.IOException"
                                       (str "malformed chunk size: " (pr-str line)))
              (neg? size) (throw-typed "java.io.IOException" (str "negative chunk size: " size))
              (zero? size) (do (swap! state assoc :done true)
                               (drain-trailers! stream buf pos deadline))
              :else
              (let [data-start pos
                    n (alength buf)
                    have (max 0 (- n data-start))
                    copied (min size have)
                    piece (byte-array size)
                    _ (copy-into! buf data-start piece 0 copied)
                    overflow (if (< copied size)
                               (fill-into! stream piece copied (- size copied) deadline)
                               (sub-ba buf (+ data-start size) n))
                    ;; the CRLF that closes the chunk data
                    [buf pos] (ensure-bytes stream overflow 0 2 deadline)]
                (reset! state {:buf buf :pos (+ pos 2) :done false})
                piece))))))))

;; A reify over java.io.InputStream rather than a tagged table, and that choice
;; is the whole point: jolt drives a reify InputStream through its own
;; read(byte[],int,int) — io/reader decodes it through a pull port, slurp and
;; io/copy read it block by block — whereas a :jolt/input-stream tagged table is
;; DRAINED to a string at every coercion site, which is exactly the blocking this
;; replaces. Probed rather than assumed, the way host-byte-streams? is: on a host
;; that cannot answer one, make-body-stream's caller keeps the buffered path.
(def reify-input-streams?
  (try (let [s (reify java.io.InputStream (read [_ _buf _off _len] -1))]
         (and (instance? java.io.InputStream s)
              (zero? (alength (.readAllBytes s)))))
       (catch Throwable _ false)))

(defn make-body-stream
  "A java.io.InputStream over a body still arriving on the wire.

  `pull` yields the next byte-array of the body, or nil at its end. `release!`
  is called exactly once with true when the body was read to its end — the
  connection can go back to the pool — and with false when the caller closed
  early or a read failed, where what is left on the socket is unknown and the
  connection must be closed."
  [pull release!]
  (let [queue (atom [])        ;; byte-arrays to serve before pulling any more
        buf (atom (byte-array 0))
        pos (atom 0)
        ;; what has been handed out since .mark, so .reset can replay it; nil
        ;; when there is no live mark
        marked (atom nil)
        ended (atom false)         ;; the body reached its end
        closed (atom false)        ;; the caller called .close
        released (atom false)
        release! (fn [complete?]
                   (when (compare-and-set! released false true)
                     (try (release! complete?) (catch Throwable _ nil))))
        ;; true when at least one byte is ready; false at the end of the body.
        ;; A pull that fails takes the connection with it: whatever is still on
        ;; the socket belongs to a response nobody can frame any more.
        fill! (fn []
                (loop []
                  (cond
                    (< @pos (alength @buf)) true
                    (seq @queue) (let [q @queue]
                                   (reset! buf (nth q 0))
                                   (reset! queue (subvec q 1))
                                   (reset! pos 0)
                                   (recur))
                    (or @ended @closed) false
                    :else (if-let [b (try (pull)
                                          (catch Throwable t (release! false) (throw t)))]
                            (do (reset! buf b) (reset! pos 0) (recur))
                            (do (reset! ended true) (release! true) false)))))
        take! (fn [n]
                ;; n bytes from the current buffer, recorded when marked
                (let [b @buf p @pos]
                  (when @marked (swap! marked conj (sub-ba b p (+ p n))))
                  (reset! pos (+ p n))
                  [b p]))]
    (reify java.io.InputStream
      ;; -1 at end of stream, an UNSIGNED byte otherwise: a caller cannot tell
      ;; 0xff from the end any other way, and byte-array elements are signed.
      (read [_]
        (if (fill!)
          (let [[b p] (take! 1)] (bit-and (aget b p) 0xff))
          -1))
      (read [this dst] (.read this dst 0 (alength dst)))
      ;; Fills what is ready and returns that count — a stream read is not
      ;; obliged to fill the array, and blocking for more is what a caller
      ;; reading a live stream is trying to avoid.
      (read [_ dst off len]
        (cond
          (zero? len) 0
          (not (fill!)) -1
          :else (let [n (min len (- (alength @buf) @pos))
                      [b p] (take! n)]
                  (copy-into! b p dst off n)
                  n)))
      (available [_] (reduce (fn [n b] (+ n (alength b)))
                             (max 0 (- (alength @buf) @pos))
                             @queue))
      ;; mark/reset over a live stream, by replaying what was read since the
      ;; mark. java.io.BufferedInputStream is the JVM's mark/reset provider and
      ;; wrapping ANY stream in one makes markSupported true there — but jolt's
      ;; BufferedInputStream has no replay layer, so over a stream that cannot
      ;; seek it is a pass-through with markSupported false. Which means the
      ;; mark has to live here or nowhere, and it is not optional:
      ;; babashka.http-client's deflate detection marks, reads, and resets
      ;; (interceptors/inflate), so without it every `Content-Encoding: deflate`
      ;; response fails.
      ;;
      ;; `readlimit` is not honoured, deliberately. The JVM treats it as the
      ;; point past which a mark MAY be dropped and BufferedInputStream keeps
      ;; more than asked; here the reader that resets is one whose first act is
      ;; to drain — our InflaterInputStream decompresses whole payloads up front
      ;; — so dropping the mark at babashka's 512 would break every deflate
      ;; response longer than that. The cost is that a marked stream buffers
      ;; what is read until the mark is dropped, which .reset does.
      (markSupported [_] true)
      (mark [_ _readlimit] (reset! marked []) nil)
      (reset [_]
        (when (nil? @marked)
          (throw-typed "java.io.IOException" "Resetting to invalid mark"))
        (let [replay (conj @marked (sub-ba @buf @pos (alength @buf)))]
          (reset! queue (vec (remove (fn [b] (zero? (alength b)))
                                     (concat replay @queue))))
          (reset! buf (byte-array 0))
          (reset! pos 0)
          ;; the mark survives a reset, as it does on the JVM
          (reset! marked []))
        nil)
      (close [_]
        (reset! closed true)
        (release! false)
        nil))))

(defn- bodyless?
  "Responses that carry no body however they are framed (RFC 7230 3.3): a HEAD
  response, 204, 304 and every 1xx."
  [method status]
  (or (= "HEAD" (str/upper-case (str method)))
      (= 204 status) (= 304 status) (< 99 status 200)))

(defn connection-gone?
  "Whether `t` says the connection went away rather than that the request
  failed: a clean close, a reset, or a broken pipe. A read TIMEOUT is none of
  these — it says the peer is slow, not that it is gone — and must not be
  mistaken for one.

  Which of these a retired keep-alive socket produces is not something a client
  gets to choose: Linux sends RST rather than FIN when it closes a socket with
  unread data, so the same dead connection surfaces as SocketException there and
  as a clean EOF elsewhere."
  [t]
  (contains? #{"class java.io.EOFException" "class java.net.SocketException"}
             (str (class t))))

(defn read-response
  "Read one HTTP/1.1 response off `stream`, framed the way the response says it
  is framed. `deadline` is an absolute System/currentTimeMillis bound on the
  read; `method` decides whether a body is expected at all.

  `received`, when given, is an atom set to true the moment the first response
  byte arrives. It is what tells a caller holding a reused connection whether a
  failure means the peer never answered.

  `stream-body?` asks for the body to be left on the wire: the map then carries
  `:body-pull`, a 0-arg fn yielding the next byte-array of the body and nil at
  its end, and `:body` is nil. The caller owns the connection until that pull is
  exhausted — nothing here closes or pools it — and `deadline` bounds only the
  read up to the end of the headers, because a total bound over a body still
  arriving is the divergence jolt-lang/jolt#1017 is about. A body that cannot
  stream (a HEAD/204/304, or a Content-Length of 0) comes back buffered, as it
  always did."
  ([stream] (read-response stream nil "GET" nil false))
  ([stream deadline] (read-response stream deadline "GET" nil false))
  ([stream deadline method] (read-response stream deadline method nil false))
  ([stream deadline method received] (read-response stream deadline method received false))
  ([stream deadline method received stream-body?]
   (let [deadline (effective-deadline deadline)
         read-more! (fn [stream deadline]
                      (let [b (read-more! stream deadline)]
                        (when (and b received) (reset! received true))
                        b))
         ;; headers first: read until the blank line, rescanning only the tail
         [buf end] (loop [buf (byte-array 0) scanned 0]
                     (let [s (ba->latin1 buf)]
                       (if-let [i (str/index-of s "\r\n\r\n" (max 0 (- scanned 3)))]
                         [buf i]
                         (if-let [b (read-more! stream deadline)]
                           (recur (concat-bas [buf b]) (alength buf))
                           ;; Nothing at all arrived: the peer hung up without
                           ;; answering, which on a REUSED connection means it
                           ;; had already retired the socket and never saw the
                           ;; request. Distinguished from a truncated response
                           ;; so the pool can retry that case and only that one.
                           (if (zero? (alength buf))
                             (throw-typed "java.io.EOFException"
                                          "connection closed before any response was received")
                             (throw-typed "java.io.IOException"
                                          "malformed response: no header terminator")))))) 
         {:keys [status version header-pairs]} (parse-head (ba->latin1 (sub-ba buf 0 end)))
         pending (sub-ba buf (+ end 4) (alength buf))
         te (header-ci header-pairs "transfer-encoding")
         chunked? (and te (str/includes? (str/lower-case te) "chunked"))
         len (when-not chunked?
               (parse-long (str/trim (or (header-ci header-pairs "content-length") ""))))
         ;; An empty body is not worth a stream, and a bodyless response has
         ;; nothing to stream: both keep the buffered path, so a caller always
         ;; gets either :body or :body-pull and never neither.
         stream? (boolean (and stream-body?
                               reify-input-streams?
                               (not (bodyless? method status))
                               (not (and len (zero? len)))))
         ;; Not `deadline`: see the docstring. set-max-response-ms! still
         ;; applies — an app that asks for a total cap by name gets one.
         body-deadline (when stream? (effective-deadline nil))
         body-pull (when stream?
                     (cond
                       chunked? (chunked-pull stream pending body-deadline)
                       (and len (pos? len)) (sized-pull stream pending len body-deadline)
                       :else (to-close-pull stream pending body-deadline)))
         body (when-not stream?
                (cond
                  (bodyless? method status) (byte-array 0)
                  chunked? (read-chunked stream pending deadline)
                  (and len (>= len 0)) (read-sized stream pending len deadline)
                  ;; no framing at all: the peer's close is the delimiter
                  :else (concat-bas (loop [chunks [pending]]
                                      (if-let [b (read-more! stream deadline)]
                                        (recur (conj chunks b))
                                        chunks)))))
         conn-hdr (str/lower-case (str (header-ci header-pairs "connection")))]
     {:status status
      :header-pairs header-pairs
      :body body
      :body-pull body-pull
      ;; A connection can only be kept when the response said exactly how long
      ;; it was — read-to-close framing IS the close — and the peer did not ask
      ;; to close it. HTTP/1.0 is the other way round: not persistent unless it
      ;; says so, so a 1.0 response is kept only on an explicit keep-alive.
      :reusable? (boolean (and (or chunked? (and len (>= len 0)) (bodyless? method status))
                               (not (str/includes? conn-hdr "close"))
                               (or (not= "HTTP/1.0" version)
                                   (str/includes? conn-hdr "keep-alive"))))})))

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
        has? (fn [nm] (let [low (str/lower-case nm)]
                        (some (fn [p] (= low (str/lower-case (str (first p))))) req-headers)))
        ;; We own the framing headers. A caller who also sets one used to get
        ;; BOTH on the wire — "Content-Length: 4, 4" — and RFC 7230 3.3.3 makes
        ;; more than one Content-Length an unrecoverable error, so a strict
        ;; server or proxy is entitled to reject the request outright. Host is
        ;; the other way round: a caller naming a virtual host means it, so
        ;; theirs wins and ours is left off.
        framing? (fn [p] (contains? #{"content-length" "connection"}
                                    (str/lower-case (str (first p)))))
        bytes (when body (->bytes body))
        ;; Content-Length matches what java.net.http actually puts on the wire,
        ;; measured method by method against a JDK: a non-empty body always
        ;; carries it; an empty body carries "0" for POST and PUT only; and a
        ;; request with no body publisher at all carries nothing.
        content-length (when bytes
                         (let [n (alength bytes)]
                           (when (or (pos? n)
                                     (contains? #{"POST" "PUT"} (str/upper-case (str method))))
                             n)))
        sb (StringBuilder.)]
    (.append sb (str method " " path " HTTP/1.1\r\n"))
    (when-not (has? "host")
      (.append sb (str "Host: "
                       (if (default-port? (tget url :protocol) (tget url :port))
                         host (str host ":" port))
                       "\r\n")))
    (doseq [pair (remove framing? req-headers)]
      (.append sb (str (first pair) ": " (second pair) "\r\n")))
    (when content-length (.append sb (str "Content-Length: " content-length "\r\n")))
    ;; HTTP/1.1 is persistent by default. `Connection: close` goes out only when
    ;; the connection genuinely will not be reused, because it also tells the
    ;; server to close — which is what made read-to-close framing work before
    ;; there was any framing at all.
    (.append sb (if @pool-enabled? "\r\n" "Connection: close\r\n\r\n"))
    (let [head (.getBytes (.toString sb) "UTF-8")]
      (if (and bytes (pos? (alength bytes))) (concat-ba head bytes) head)))))

;; --- reference resolution (RFC 3986 §5) -------------------------------------
;; A Location header is a URI reference, not necessarily an absolute URL. The
;; previous reading of a relative one — protocol://host/ + the reference — threw
;; away the port and the base directory both: from http://h:9000/deep/x, a
;; `Location: target` resolved to http://h/target and the next hop went to port
;; 80. Values below are java.net.URI/resolve's, measured.

(defn- remove-dot-segments
  "RFC 3986 5.2.4."
  [path]
  (loop [in (str path) out []]
    (cond
      (= "" in) (str/join out)
      (str/starts-with? in "../") (recur (subs in 3) out)
      (str/starts-with? in "./") (recur (subs in 2) out)
      (str/starts-with? in "/./") (recur (str "/" (subs in 3)) out)
      (= in "/.") (recur "/" out)
      (str/starts-with? in "/../") (recur (str "/" (subs in 4)) (if (seq out) (pop out) out))
      (= in "/..") (recur "/" (if (seq out) (pop out) out))
      (or (= in ".") (= in "..")) (recur "" out)
      :else (let [i (str/index-of in "/" 1)
                  seg (if i (subs in 0 i) in)]
              (recur (if i (subs in i) "") (conj out seg))))))

(defn- merge-path
  "RFC 3986 5.2.3: a relative reference resolves against the base's directory."
  [base-path rel]
  (let [p (str base-path)]
    (if (str/blank? p)
      (str "/" rel)
      (if-let [i (str/last-index-of p "/")]
        (str (subs p 0 (inc i)) rel)
        (str "/" rel)))))

(defn- base-authority [base]
  (str (when (tget base :userinfo) (str (tget base :userinfo) "@"))
       (tget base :host)
       (let [p (tget base :port)] (if (and (number? p) (>= p 0)) (str ":" p) ""))))

(defn resolve-location [base loc]
  (let [loc (str loc)
        origin (str (tget base :protocol) "://" (base-authority base))
        base-path (let [p (tget base :path)] (if (str/blank? (str p)) "/" p))]
    (cond
      ;; any scheme, not just http/https
      (re-find #"^[A-Za-z][A-Za-z0-9+.\-]*:" loc) (parse-url loc)
      (str/starts-with? loc "//") (parse-url (str (tget base :protocol) ":" loc))
      (str/starts-with? loc "/") (parse-url (str origin (remove-dot-segments loc)))
      ;; RFC 3986 5.3 keeps the base path for a bare query. java.net.URI/resolve
      ;; drops the last segment instead — a long-standing deviation; the RFC
      ;; reading is what a server sending `Location: ?page=2` means.
      (str/starts-with? loc "?") (parse-url (str origin base-path loc))
      (str/starts-with? loc "#") (parse-url (str origin base-path
                                                 (when-let [q (tget base :query)] (str "?" q))
                                                 loc))
      (str/blank? loc) base
      :else (parse-url (str origin (remove-dot-segments (merge-path (tget base :path) loc)))))))

(def redirect-statuses #{301 302 303 307 308})
