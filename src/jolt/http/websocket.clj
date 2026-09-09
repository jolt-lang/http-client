(ns jolt.http.websocket
  "RFC 6455 WebSocket over the same socket/TLS transport as everything else here,
  exposed as the java.net.http WebSocket surface (`HttpClient.newWebSocketBuilder`,
  `WebSocket`, `WebSocket.Listener`) that babashka.http-client.websocket drives.

  The frame codec is public because both ends of the test suite use it: a client
  that masks and a server that does not are the same encoder with one bit
  flipped, and having one implementation is what makes a round-trip test mean
  something.

  Not modelled: permessage-deflate (no extension is negotiated, so a server that
  offers one still gets an unextended session), and the JDK's flow control —
  `request` is accepted and ignored, the reader delivers every frame as it
  arrives. Fragmented messages ARE delivered fragment by fragment with the `last`
  flag, the way the JDK does."
  (:require [clojure.string :as str]
            [jolt.crypto]                ;; MessageDigest (SHA-1), SecureRandom
            [jolt.http.core :as core]
            [jolt.http.jdk :as jdk]))

(def ^:private tt core/tt)
(def ^:private tget core/tget)
(def ^:private tput! core/tput!)

;; ---------------------------------------------------------------------------
;; frames
;; ---------------------------------------------------------------------------
(def op-continuation 0x0)
(def op-text 0x1)
(def op-binary 0x2)
(def op-close 0x8)
(def op-ping 0x9)
(def op-pong 0xa)

(defn- ub [ba i] (bit-and (aget ba i) 0xff))

(defn encode-frame
  "One RFC 6455 frame. `mask?` is true for the client side, which MUST mask, and
  false for the server side, which MUST NOT."
  [opcode ^bytes payload {:keys [fin? mask?] :or {fin? true mask? true}}]
  (let [n (alength payload)
        len-bytes (cond (< n 126) []
                        (< n 65536) [(bit-and (bit-shift-right n 8) 0xff) (bit-and n 0xff)]
                        :else (mapv (fn [shift] (bit-and (bit-shift-right n shift) 0xff))
                                    [56 48 40 32 24 16 8 0]))
        len7 (cond (< n 126) n (< n 65536) 126 :else 127)
        mask-key (when mask?
                   (let [k (byte-array 4)]
                     (.nextBytes (java.security.SecureRandom.) k)
                     k))
        head (concat [(bit-or (if fin? 0x80 0) opcode)
                      (bit-or (if mask? 0x80 0) len7)]
                     len-bytes
                     (when mask-key (map (fn [i] (ub mask-key i)) (range 4))))
        out (byte-array (+ (count head) n))]
    (dotimes [i (count head)] (aset out i (byte (let [v (nth head i)] (if (> v 127) (- v 256) v)))))
    (dotimes [i n]
      (aset out (+ (count head) i)
            (byte (let [v (if mask-key
                            (bit-xor (ub payload i) (ub mask-key (mod i 4)))
                            (ub payload i))]
                    (if (> v 127) (- v 256) v)))))
    out))

(defn decode-frame
  "Decode one frame from the front of byte-array `buf`. Returns
  [{:opcode :fin? :payload} rest-bytes] or nil when `buf` holds an incomplete
  frame and more has to be read."
  [^bytes buf]
  (let [n (alength buf)]
    (when (>= n 2)
      (let [b0 (ub buf 0)
            b1 (ub buf 1)
            fin? (pos? (bit-and b0 0x80))
            opcode (bit-and b0 0x0f)
            masked? (pos? (bit-and b1 0x80))
            len7 (bit-and b1 0x7f)
            [len len-size] (cond
                             (< len7 126) [len7 0]
                             (= len7 126) (when (>= n 4) [(+ (bit-shift-left (ub buf 2) 8) (ub buf 3)) 2])
                             :else (when (>= n 10)
                                     [(reduce (fn [acc i] (+ (* acc 256) (ub buf i))) 0 (range 2 10)) 8]))]
        (when len
          (let [key-off (+ 2 len-size)
                data-off (+ key-off (if masked? 4 0))]
            (when (>= n (+ data-off len))
              (let [payload (byte-array len)]
                (dotimes [i len]
                  (let [v (if masked?
                            (bit-xor (ub buf (+ data-off i)) (ub buf (+ key-off (mod i 4))))
                            (ub buf (+ data-off i)))]
                    (aset payload i (byte (if (> v 127) (- v 256) v)))))
                (let [used (+ data-off len)
                      remaining (byte-array (- n used))]
                  (dotimes [i (- n used)] (aset remaining i (aget buf (+ used i))))
                  [{:opcode opcode :fin? fin? :payload payload} remaining])))))))))

;; ---------------------------------------------------------------------------
;; handshake
;; ---------------------------------------------------------------------------
(def ^:private ws-guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

(defn accept-key
  "The Sec-WebSocket-Accept value for a Sec-WebSocket-Key, per RFC 6455 4.2.2."
  [key]
  (.encodeToString (java.util.Base64/getEncoder)
                   (.digest (java.security.MessageDigest/getInstance "SHA-1")
                            (.getBytes (str key ws-guid) "UTF-8"))))

(defn- random-key []
  (let [b (byte-array 16)]
    (.nextBytes (java.security.SecureRandom.) b)
    (.encodeToString (java.util.Base64/getEncoder) b)))

(defn- ws-uri->parts [uri]
  (let [s (str uri)
        ;; ws/wss are http/https on the wire
        s (cond (str/starts-with? s "ws://") (str "http://" (subs s 5))
                (str/starts-with? s "wss://") (str "https://" (subs s 6))
                :else s)]
    (core/parse-url s)))

(defn- read-handshake
  "Read the 101 response. Returns [headers leftover-bytes]; leftover is the start
  of the frame stream, which can arrive in the same TCP segment as the response."
  [stream]
  (loop [acc (byte-array 0)]
    (let [text (core/ba->latin1 acc)
          end (str/index-of text "\r\n\r\n")]
      (if end
        (let [head (subs text 0 end)
              lines (str/split head #"\r\n")
              status (parse-long (or (nth (str/split (first lines) #" ") 1 nil) ""))
              headers (reduce (fn [m line]
                                (if-let [i (str/index-of line ":")]
                                  (assoc m (str/lower-case (str/trim (subs line 0 i)))
                                         (str/trim (subs line (inc i))))
                                  m))
                              {} (rest lines))
              used (+ end 4)
              leftover (byte-array (- (alength acc) used))]
          (dotimes [i (alength leftover)] (aset leftover i (aget acc (+ used i))))
          (when-not (= 101 status)
            (core/throw-typed "java.io.IOException"
                              (str "WebSocket handshake failed: " (first lines))))
          [headers leftover])
        (if-let [chunk (core/s-read stream nil)]
          (recur (core/concat-ba acc chunk))
          (core/throw-typed "java.io.IOException"
                            "connection closed during the WebSocket handshake"))))))

;; ---------------------------------------------------------------------------
;; the WebSocket object
;; ---------------------------------------------------------------------------
(defn- on-error! [ws listener t]
  (when listener (try (.onError listener ws t) (catch Throwable _ nil))))

(defmacro ^:private safely
  "Run a listener callback. An exception inside one goes to onError, the way the
  JDK routes it, rather than killing the reader thread."
  [ws listener & body]
  `(when ~listener
     (try ~@body (catch Throwable t# (on-error! ~ws ~listener t#)))))

(defn- send-frame! [ws opcode payload fin?]
  ;; One writer at a time: two interleaved frames on the wire are unparseable,
  ;; and every send is allowed from any thread.
  (locking (tget ws :write-lock)
    (when (tget ws :output-closed)
      (core/throw-typed "java.io.IOException" "WebSocket output is closed"))
    (core/s-write (tget ws :stream) (encode-frame opcode payload {:fin? fin? :mask? true})))
  (jdk/completed-future ws))

(defn- close-stream! [ws]
  (tput! ws :output-closed true)
  (tput! ws :input-closed true)
  (try (core/s-close (tget ws :stream)) (catch Throwable _ nil))
  nil)

(defn- reader-loop [ws listener leftover]
  (let [stream (tget ws :stream)]
    (loop [buf leftover
           frag {:opcode nil :parts []}]
      (if-let [[frame rest-bytes] (decode-frame buf)]
        (let [{:keys [opcode fin? payload]} frame]
          (cond
            (= opcode op-close)
            (let [status (if (>= (alength payload) 2)
                           (+ (* 256 (ub payload 0)) (ub payload 1))
                           1005)
                  reason (if (> (alength payload) 2)
                           (String. (byte-array (drop 2 (seq payload))) "UTF-8")
                           "")]
              (tput! ws :input-closed true)
              (safely ws listener (.onClose listener ws status reason))
              ;; echo the close and shut the socket, completing the handshake
              (try (when-not (tget ws :output-closed)
                     (core/s-write stream (encode-frame op-close payload {:mask? true})))
                   (catch Throwable _ nil))
              (close-stream! ws))

            (= opcode op-ping)
            (do (safely ws listener (.onPing listener ws (java.nio.ByteBuffer/wrap payload)))
                ;; RFC 6455 5.5.2: a pong must carry the ping's payload
                (try (core/s-write stream (encode-frame op-pong payload {:mask? true}))
                     (catch Throwable _ nil))
                (recur rest-bytes frag))

            (= opcode op-pong)
            (do (safely ws listener (.onPong listener ws (java.nio.ByteBuffer/wrap payload)))
                (recur rest-bytes frag))

            :else
            ;; text/binary/continuation. The JDK hands each fragment to the
            ;; listener with `last`, so the message type of a continuation is
            ;; the type of the frame that opened it.
            (let [kind (if (= opcode op-continuation) (:opcode frag) opcode)]
              (if (= kind op-text)
                (safely ws listener (.onText listener ws (String. payload "UTF-8") fin?))
                (safely ws listener (.onBinary listener ws (java.nio.ByteBuffer/wrap payload) fin?)))
              (recur rest-bytes (if fin? {:opcode nil :parts []} {:opcode kind :parts []})))))
        ;; incomplete frame: read more
        (let [chunk (try (core/s-read stream nil)
                         (catch Throwable t
                           (when-not (tget ws :input-closed) (on-error! ws listener t))
                           nil))]
          (if chunk
            (recur (core/concat-ba buf chunk) frag)
            (when-not (tget ws :input-closed)
              (tput! ws :input-closed true)
              (safely ws listener (.onClose listener ws 1006 ""))
              (close-stream! ws))))))))

(defn- connect!
  "Run the opening handshake and start the reader. Returns the WebSocket."
  [{:keys [uri listener headers subprotocols connect-timeout ssl insecure?]}]
  (let [url (ws-uri->parts uri)
        https? (= "https" (tget url :protocol))
        key (random-key)
        path (let [p (tget url :path) q (tget url :query)]
               (str (if (str/blank? (str p)) "/" p) (when q (str "?" q))))
        host (tget url :host)
        port (core/effective-port url)
        req (str "GET " path " HTTP/1.1\r\n"
                 "Host: " host (when-not (core/default-port? (tget url :protocol) (tget url :port))
                                 (str ":" port)) "\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-WebSocket-Key: " key "\r\n"
                 "Sec-WebSocket-Version: 13\r\n"
                 (when (seq subprotocols)
                   (str "Sec-WebSocket-Protocol: " (str/join ", " subprotocols) "\r\n"))
                 (apply str (map (fn [[k v]] (str k ": " v "\r\n")) headers))
                 "\r\n")
        stream (core/connect-stream host port https? insecure? nil connect-timeout ssl)]
    (try
      (core/s-write stream (core/latin1->ba req))
      (let [[resp-headers leftover] (read-handshake stream)]
        (when-not (= (accept-key key) (get resp-headers "sec-websocket-accept"))
          (core/throw-typed "java.io.IOException"
                            "WebSocket handshake failed: bad Sec-WebSocket-Accept"))
        (let [ws (tt :jolt.http/websocket)]
          (tput! ws :stream stream)
          (tput! ws :write-lock (Object.))
          (tput! ws :output-closed false)
          (tput! ws :input-closed false)
          (tput! ws :subprotocol (get resp-headers "sec-websocket-protocol" ""))
          (safely ws listener (.onOpen listener ws))
          (future (reader-loop ws listener leftover))
          ws))
      (catch Throwable t
        (try (core/s-close stream) (catch Throwable _ nil))
        (throw t)))))

;; ---------------------------------------------------------------------------
;; install
;; ---------------------------------------------------------------------------
(defn- ->payload [x]
  (cond
    (nil? x) (byte-array 0)
    (string? x) (byte-array (.getBytes ^String x "UTF-8"))
    ;; a ByteBuffer: take what remains, like the JDK's send does
    (instance? java.nio.ByteBuffer x) (let [d (byte-array (.remaining x))] (.get x d) d)
    :else (core/->bytes x)))

(defn install! []
  (doseq [nm ["java.net.http.WebSocket" "WebSocket"]]
    (__register-class-statics! nm {"NORMAL_CLOSURE" 1000}))
  (__register-class-methods! :jolt.http/websocket-builder
    {"connectTimeout" (fn [self d] (tput! self :connect-timeout d) self)
     "header" (fn [self k v] (tput! self :headers (conj (tget self :headers) [(str k) (str v)])) self)
     "subprotocols" (fn [self first-sub & more]
                      (tput! self :subprotocols
                             (into [(str first-sub)] (map str (or (first more) []))))
                      self)
     "buildAsync" (fn [self uri listener]
                    (jdk/async-future
                      (fn []
                        (connect! {:uri uri
                                   :listener listener
                                   :headers (tget self :headers)
                                   :subprotocols (tget self :subprotocols)
                                   :connect-timeout (jdk/duration->ms (tget self :connect-timeout))
                                   :ssl (tget self :ssl)
                                   :insecure? (tget self :insecure)}))))})
  (__register-class-methods! :jolt.http/websocket
    {"sendText"   (fn [self data last?] (send-frame! self op-text (->payload (str data)) (boolean last?)))
     "sendBinary" (fn [self data last?] (send-frame! self op-binary (->payload data) (boolean last?)))
     "sendPing"   (fn [self data] (send-frame! self op-ping (->payload data) true))
     "sendPong"   (fn [self data] (send-frame! self op-pong (->payload data) true))
     "sendClose"  (fn [self status reason]
                    (let [reason-bytes (.getBytes (str reason) "UTF-8")
                          payload (byte-array (+ 2 (alength reason-bytes)))]
                      (aset payload 0 (byte (let [v (bit-and (bit-shift-right status 8) 0xff)]
                                              (if (> v 127) (- v 256) v))))
                      (aset payload 1 (byte (let [v (bit-and status 0xff)]
                                              (if (> v 127) (- v 256) v))))
                      (dotimes [i (alength reason-bytes)]
                        (aset payload (+ 2 i) (aget reason-bytes i)))
                      (let [f (send-frame! self op-close payload true)]
                        (tput! self :output-closed true)
                        f)))
     "abort"      (fn [self] (close-stream! self) nil)
     ;; the JDK's flow control: the reader here delivers every frame as it
     ;; arrives, so a request for more is already satisfied.
     "request"    (fn [_self _n] nil)
     "getSubprotocol" (fn [self] (tget self :subprotocol))
     "isOutputClosed" (fn [self] (boolean (tget self :output-closed)))
     "isInputClosed"  (fn [self] (boolean (tget self :input-closed)))})
  ;; HttpClient.newWebSocketBuilder() lives on the client, which jolt.http.jdk
  ;; owns; it calls through this hook so the two namespaces need not require each
  ;; other in a cycle.
  (jdk/set-websocket-builder!
    (fn [client]
      (doto (tt :jolt.http/websocket-builder)
        (tput! :headers [])
        (tput! :subprotocols [])
        (tput! :connect-timeout (jdk/client-connect-timeout client))
        (tput! :ssl (jdk/client-ssl-material client))
        (tput! :insecure (jdk/client-insecure? client)))))
  (__register-instance-check!
    (fn [cn val]
      (when (contains? #{"WebSocket" "java.net.http.WebSocket"
                         "WebSocket$Builder" "java.net.http.WebSocket$Builder"} cn)
        (= (if (str/includes? cn "Builder") :jolt.http/websocket-builder :jolt.http/websocket)
           (and (core/table? val) (tget val :jolt/type))))))
  nil)

(install!)
