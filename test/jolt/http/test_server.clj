(ns jolt.http.test-server
  "In-process HTTP/1.1 servers (plaintext + OpenSSL TLS) for the test suite, over
  jolt.ffi BSD sockets — standing in for the Jetty subprocess clj-http-lite's
  integration tests would otherwise launch. Mirrors clj-http-lite's own test
  handler routes."
  (:require [clojure.string :as str]
            [jolt.ffi :as ffi]
            [jolt.http.core]
            [jolt.http.net :as net]
            [jolt.http.tls :as tls]
            [jolt.http.websocket :as ws]))

(ffi/defcfn c-socket     "socket"     [:int :int :int] :int)
(ffi/defcfn c-bind       "bind"       [:int :pointer :int] :int)
(ffi/defcfn c-listen     "listen"     [:int :int] :int)
(ffi/defcfn c-setsockopt "setsockopt" [:int :int :int :pointer :int] :int)
(ffi/defcfn c-accept     "accept"     [:int :pointer :pointer] :int :blocking)

(def ^:private AF-INET 2)
(def ^:private SOCK-STREAM 1)
(def ^:private macos?
  (str/includes? (str/lower-case (or (System/getProperty "os.name") "")) "mac"))
(def ^:private sol-socket (if macos? 0xffff 1))
(def ^:private so-reuse   (if macos? 4 2))

(def ^:private AF-INET6 (if macos? 30 10))

(defn- make-sockaddr6
  "struct sockaddr_in6, ::1. 28 bytes; macOS carries a length byte at offset 0."
  [port]
  (let [sa (ffi/alloc 28)]
    (dotimes [i 28] (ffi/write sa :uint8 0 i))
    (if macos?
      (do (ffi/write sa :uint8 28 0) (ffi/write sa :uint8 AF-INET6 1))
      (ffi/write sa :uint8 AF-INET6 0))
    (ffi/write sa :uint8 (bit-and (bit-shift-right port 8) 0xff) 2)
    (ffi/write sa :uint8 (bit-and port 0xff) 3)
    (ffi/write sa :uint8 1 23)                       ; ::1
    sa))

(defn- make-sockaddr [port]
  (let [sa (ffi/alloc 16)]
    (dotimes [i 16] (ffi/write sa :uint8 0 i))
    (if macos?
      (do (ffi/write sa :uint8 16 0) (ffi/write sa :uint8 AF-INET 1))
      (ffi/write sa :uint8 AF-INET 0))
    (ffi/write sa :uint8 (bit-and (bit-shift-right port 8) 0xff) 2)
    (ffi/write sa :uint8 (bit-and port 0xff) 3)
    (ffi/write sa :uint8 127 4) (ffi/write sa :uint8 1 7)   ; 127.0.0.1
    sa))

(defn listen-socket
  ([port] (listen-socket port nil))
  ([port family]
   (let [v6? (= :ipv6 family)
         fd (c-socket (if v6? AF-INET6 AF-INET) SOCK-STREAM 0)]
     (when (neg? fd) (throw (ex-info "socket() failed" {})))
     (let [opt (ffi/alloc 4)]
       (ffi/write opt :int 1 0)
       (c-setsockopt fd sol-socket so-reuse opt 4)
       (ffi/free opt))
     (let [sa (if v6? (make-sockaddr6 port) (make-sockaddr port))
           len (if v6? 28 16)]
       (when (neg? (c-bind fd sa len))
         (net/close fd) (ffi/free sa) (throw (ex-info (str "bind() failed on port " port) {})))
       (ffi/free sa))
     (when (neg? (c-listen fd 64)) (net/close fd) (throw (ex-info "listen() failed" {})))
     fd)))

(defn accept-raw
  "Block until a connection arrives on `listen-fd`; return the raw fd. Exposed so
  a test can drive its own accept loop (e.g. a server that answers the handshake
  and then deliberately never replies)."
  [listen-fd]
  (c-accept listen-fd ffi/null ffi/null))

;; --- connection read/write (plain fd or TLS stream) ------------------------
(defn conn-read [conn] (if (jolt.host/table? conn) ((jolt.host/ref-get conn :read) conn nil) (net/recv-bytes conn)))
(defn conn-write [conn data] (if (jolt.host/table? conn) ((jolt.host/ref-get conn :write) conn data) (net/send-bytes conn data)))
(defn conn-close [conn] (if (jolt.host/table? conn) ((jolt.host/ref-get conn :close)) (net/close conn)))

(defn ba->latin1 [ba] (String. ba "ISO-8859-1"))
(defn latin1->ba [s] (byte-array (map int s)))

(defn- parse-request [text]
  (let [blank (str/index-of text "\r\n\r\n")
        head (subs text 0 blank)
        rest-body (subs text (+ blank 4))
        lines (str/split head #"\r\n")
        [method target] (str/split (first lines) #" ")
        qi (str/index-of target "?")
        uri (if qi (subs target 0 qi) target)
        query (when qi (subs target (inc qi)))
        ;; A header repeated on the wire — accept-encoding: gzip then
        ;; accept-encoding: deflate, which is how java.net.http sends a
        ;; multi-valued header — is one comma-joined value, per RFC 7230 3.2.2.
        headers (reduce (fn [m line]
                          (let [i (str/index-of line ":")]
                            (if (and i (pos? i))
                              (let [k (str/lower-case (str/trim (subs line 0 i)))
                                    v (str/trim (subs line (inc i)))]
                                (assoc m k (if-let [prev (get m k)] (str prev ", " v) v)))
                              m)))
                        {} (rest lines))]
    {:request-method (keyword (str/lower-case method))
     :uri uri :query query :headers headers :body-raw rest-body
     :target target
     :content-length (or (parse-long (or (get headers "content-length") "")) 0)}))

;; read a full request (headers + content-length body) as a latin1 string, or nil.
(defn- read-request [conn]
  (loop [acc ""]
    (let [chunk (conn-read conn)]
      (if (nil? chunk)
        (when (pos? (count acc)) (parse-request acc))
        (let [acc (str acc (ba->latin1 chunk))
              he (str/index-of acc "\r\n\r\n")]
          (if (nil? he)
            (recur acc)
            (let [req (parse-request acc)]
              (if (>= (- (count acc) (+ he 4)) (:content-length req)) req (recur acc)))))))))

;; --- routes (mirror clj-http.lite.test-util.http-server) -------------------
(def ^:private CREDS "Basic dXNlcm5hbWU6cGFzc3dvcmQ=")   ; base64 username:password
(defn default-handler
  "clj-http-lite's own test routes. The babashka suite passes its own :handler."
  [req]
  (let [m (:request-method req) uri (:uri req) h (:headers req)]
    (cond
      (and (= m :get) (= uri "/get")) {:status 200 :body "get"}
      (and (= m :head) (= uri "/head")) {:status 200 :body ""}
      (and (= m :get) (= uri "/content-type")) {:status 200 :body (or (get h "content-type") "")}
      (and (= m :get) (= uri "/header")) {:status 200 :body (or (get h "x-my-header") "")}
      (and (= m :post) (= uri "/post")) {:status 200 :body (:body-raw req)}
      (and (= m :get) (= uri "/redirect")) {:status 302 :headers {"Location" "/get"} :body ""}
      (and (= m :get) (= uri "/error")) {:status 500 :body "o noes"}
      (and (= m :get) (= uri "/timeout")) (do (Thread/sleep 100) {:status 200 :body "timeout"})
      (and (= m :delete) (= uri "/delete-with-body")) {:status 200 :body "delete-with-body"}
      (and (= m :get) (= uri "/basic-auth"))
        (if (= CREDS (get h "authorization")) {:status 200 :body "welcome"} {:status 401 :body "denied"})
      :else {:status 404 :body "not found"})))

(def ^:private status-text
  {200 "OK" 201 "Created" 204 "No Content" 301 "Moved Permanently" 302 "Found"
   303 "See Other" 307 "Temporary Redirect" 400 "Bad Request" 401 "Unauthorized"
   403 "Forbidden" 404 "Not Found" 407 "Proxy Authentication Required"
   422 "Unprocessable Entity" 500 "Internal Server Error"})

(defn- body->ba [body]
  (cond (nil? body) (byte-array 0)
        (string? body) (.getBytes ^String body "UTF-8")
        (bytes? body) body
        :else (byte-array body)))

(defn write-response
  "Serialise a response. :body may be a string or a byte-array; a header value
  may be a collection, which emits the header once per value (Set-Cookie)."
  [conn resp]
  (let [body (body->ba (:body resp))
        sb (StringBuilder.)]
    (.append sb (str "HTTP/1.1 " (:status resp) " " (get status-text (:status resp) "OK") "\r\n"))
    (.append sb (str "Date: Mon, 01 Jan 2026 00:00:00 GMT\r\n"))
    (doseq [[k v] (:headers resp)
            v (if (or (sequential? v) (set? v)) v [v])]
      (.append sb (str k ": " v "\r\n")))
    (.append sb (str "Content-Length: " (alength body) "\r\n"))
    (.append sb "Connection: close\r\n\r\n")
    (conn-write conn (latin1->ba (.toString sb)))
    (when (pos? (alength body)) (conn-write conn body))))

(defn- serve-one [conn h]
  (let [hijacked? (atom false)]
    (try
      (when-let [req (read-request conn)]
        ;; A handler may take the connection over entirely — the websocket
        ;; upgrade does, and then owns reads, writes and the close.
        (let [resp (h (assoc req :conn conn))]
          (if (= :hijacked resp)
            (reset! hijacked? true)
            (write-response conn resp))))
      (catch Throwable _ nil)
      (finally (when-not @hijacked?
                 (try (conn-close conn) (catch Throwable _ nil)))))))

(defn- accept-loop [listen-fd running? wrap h concurrent?]
  (loop []
    (let [raw (c-accept listen-fd ffi/null ffi/null)]
      (cond
        (not @running?) nil
        (neg? raw) (when @running? (recur))
        :else
        (let [serve (fn []
                      (try
                        (let [conn (if wrap (wrap raw) raw)] (serve-one conn h))
                        (catch Throwable _ (try (net/close raw) (catch Throwable _ nil)))))]
          ;; Concurrent by default: an :async request, a proxied request (which
          ;; opens a second connection to this same server) and a websocket that
          ;; stays open all deadlock a serial loop.
          (if concurrent? (future (serve)) (serve))
          (recur))))))

(defn start-plain
  "Listen on `port` and serve `handler` (default: the clj-http-lite routes).
  opts: :handler (a fn of the ring-ish request map, which also carries :conn —
  a handler returning :hijacked has taken the connection over), :concurrent?
  (default true), :host (:ipv6 to bind ::1 instead of 127.0.0.1)."
  ([port] (start-plain port {}))
  ([port {:keys [handler concurrent? host] :or {concurrent? true}}]
   (let [fd (listen-socket port host) running? (atom true)]
     (future (accept-loop fd running? nil (or handler default-handler) concurrent?))
     {:fd fd :port port :running running?})))

;; --- persistent (keep-alive) server ----------------------------------------
;; Every other server here answers once and closes, which is exactly the shape
;; that makes connection reuse invisible. This one holds the connection open and
;; counts how many requests arrive on each, so a test can tell a reused socket
;; from a fresh one.

(defn- write-persistent-response [conn resp]
  (let [body (body->ba (:body resp))
        sb (StringBuilder.)]
    (.append sb (str "HTTP/1.1 " (:status resp) " " (get status-text (:status resp) "OK") "\r\n"))
    (doseq [[k v] (:headers resp)
            v (if (or (sequential? v) (set? v)) v [v])]
      (.append sb (str k ": " v "\r\n")))
    (when (:close resp) (.append sb "Connection: close\r\n"))
    (if (:chunked resp)
      (.append sb "Transfer-Encoding: chunked\r\n\r\n")
      (.append sb (str "Content-Length: " (alength body) "\r\n\r\n")))
    (conn-write conn (latin1->ba (.toString sb)))
    (if (:chunked resp)
      (do (doseq [part (partition-all 7 (seq body))]
            (conn-write conn (latin1->ba (format "%x\r\n" (count part))))
            (conn-write conn (byte-array part))
            (conn-write conn (latin1->ba "\r\n")))
          (conn-write conn (latin1->ba "0\r\n\r\n")))
      (when (pos? (alength body)) (conn-write conn body)))))

(defn- persistent-serve [conn handler stats running?]
  (try
    (loop [acc "" n 0]
      (let [chunk (when @running? (conn-read conn))]
        (if (nil? chunk)
          (when (pos? n) (swap! stats update :per-connection conj n))
          (let [acc (str acc (ba->latin1 chunk))
                he (str/index-of acc "\r\n\r\n")]
            (if (nil? he)
              (recur acc n)
              (let [req (parse-request acc)]
                (if (< (- (count acc) (+ he 4)) (:content-length req))
                  (recur acc n)
                  ;; :request-number lets a handler behave differently on a
                  ;; REUSED connection than on a fresh one, which is the only
                  ;; way to drive the client's stale-connection retry on
                  ;; purpose: answer the first request, hang up on the next.
                  (let [resp (handler (assoc req :request-number n))]
                    (swap! stats update :requests inc)
                    (if (= :hangup resp)
                      (swap! stats update :per-connection conj (inc n))
                      (do (write-persistent-response conn resp)
                          (if (:close resp)
                            (swap! stats update :per-connection conj (inc n))
                            (recur (subs acc (+ he 4 (:content-length req))) (inc n)))))))))))))
    (catch Throwable _ nil)
    (finally (try (conn-close conn) (catch Throwable _ nil)))))

(defn start-persistent
  "A server that keeps connections open. :stats holds {:requests n
  :per-connection [n …]} — one entry per connection that has finished, so a
  test can assert that several requests shared one socket. A handler may return
  :chunked true to frame the body with Transfer-Encoding, or :close true to ask
  the client to hang up.

  Accepted connections are tracked in :conns and closed by `stop`. Closing only
  the listening socket is not enough for a server whose whole point is that
  connections outlive a request: Linux refuses to rebind the port while they are
  still established, even with SO_REUSEADDR, so the next server on that port
  failed with \"bind() failed\"."
  [port handler]
  (let [fd (listen-socket port)
        running? (atom true)
        conns (atom #{})
        stats (atom {:requests 0 :per-connection []})]
    (future
      (loop []
        (let [raw (c-accept fd ffi/null ffi/null)]
          (cond
            (not @running?) nil
            (neg? raw) (when @running? (recur))
            :else (do (swap! conns conj raw)
                      (future (try (persistent-serve raw handler stats running?)
                                   (finally (swap! conns disj raw))))
                      (recur))))))
    {:fd fd :port port :running running? :stats stats :conns conns}))

(defn start-keepalive
  "A server that answers one complete, Content-Length-framed response and then
  HOLDS the connection open — the shape of any peer that ignores our
  `Connection: close`. A client that frames on the connection closing rather
  than on Content-Length blocks here until its read timeout."
  [port]
  (let [fd (listen-socket port) running? (atom true)]
    (future
      (loop []
        (let [raw (c-accept fd ffi/null ffi/null)]
          (cond
            (not @running?) nil
            (neg? raw) (when @running? (recur))
            :else
            (do (future
                  (try
                    (net/recv-bytes raw)
                    (net/send-bytes raw (latin1->ba "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
                    (loop [n 0] (when (and @running? (< n 600)) (Thread/sleep 100) (recur (inc n))))
                    (catch Throwable _ nil)
                    (finally (try (net/close raw) (catch Throwable _ nil)))))
                (recur))))))
    {:fd fd :port port :running running?}))

(defn start-tls
  ([port cert key] (start-tls port cert key {}))
  ([port cert key {:keys [handler concurrent?] :or {concurrent? true}}]
   (let [fd (listen-socket port) running? (atom true)]
     (future (accept-loop fd running? (fn [raw] (tls/tls-wrap-server raw cert key))
                          (or handler default-handler) concurrent?))
     {:fd fd :port port :running running?})))

(defn drop-connections!
  "Close every accepted connection, leaving the listener up — a peer retiring
  its idle keep-alive sockets."
  [server]
  (doseq [c (when-let [a (:conns server)] @a)]
    (try (net/close c) (catch Throwable _ nil)))
  nil)

(defn stop [server]
  (reset! (:running server) false)
  ;; accepted connections first: a persistent server's outlive the request that
  ;; made them, and the port cannot be rebound while they are established
  (doseq [c (when-let [a (:conns server)] @a)]
    (try (net/close c) (catch Throwable _ nil)))
  (net/close (:fd server))
  nil)

;; --- HTTP proxy ------------------------------------------------------------
;; A real forward proxy, because that is the only way to test that the client
;; actually routes through one: plain http arrives as an absolute-form request
;; line and is forwarded, https arrives as CONNECT and is tunnelled byte for
;; byte, so the TLS session runs end to end and the proxy never sees plaintext.
;; Every request seen is recorded in :seen, which is what a test asserts on.

(defn- pump
  "Copy everything from `in` to `out` until EOF, then stop."
  [in out]
  (try
    (loop []
      (when-let [b (net/recv-bytes in)]
        (net/send-bytes out b)
        (recur)))
    (catch Throwable _ nil)))

(defn- proxy-connect [client-fd target seen closed?]
  (let [[host port] (str/split target #":")
        upstream (net/connect host (parse-long port) 5000)
        shutdown! (fn []
                    ;; BOTH sides, and on whichever direction ends first: closing
                    ;; only the side that hung up leaves the other waiting on an
                    ;; EOF that can no longer arrive. That is exactly what an
                    ;; https-through-proxy request hung on — the origin sent its
                    ;; response and closed, the upstream pump finished, and the
                    ;; client sat in recv forever.
                    (when (compare-and-set! closed? false true)
                      (try (net/close upstream) (catch Throwable _ nil))
                      (try (net/close client-fd) (catch Throwable _ nil))))]
    (swap! seen conj {:method "CONNECT" :target target})
    (net/send-bytes client-fd (latin1->ba "HTTP/1.1 200 Connection Established\r\n\r\n"))
    (let [up (future (pump upstream client-fd) (shutdown!))]
      (pump client-fd upstream)
      (shutdown!)
      (deref up 5000 nil))))

(defn- proxy-forward [client-fd head body-rest seen]
  (let [lines (str/split head #"\r\n")
        [method target version] (str/split (first lines) #" ")
        url (java.net.URI/create target)
        host (.getHost url)
        port (if (pos? (.getPort url)) (.getPort url) 80)
        path (str (if (str/blank? (.getRawPath url)) "/" (.getRawPath url))
                  (when (.getRawQuery url) (str "?" (.getRawQuery url))))
        ;; forward every header except the hop-by-hop ones
        headers (remove (fn [l] (let [low (str/lower-case l)]
                                  (or (str/starts-with? low "proxy-")
                                      (str/starts-with? low "connection:"))))
                        (rest lines))
        upstream (net/connect host port 5000)]
    (swap! seen conj {:method method :target target})
    (net/send-bytes upstream (latin1->ba (str method " " path " " version "\r\n"
                                              (str/join "\r\n" headers)
                                              "\r\nConnection: close\r\n\r\n"
                                              body-rest)))
    (pump upstream client-fd)
    (try (net/close upstream) (catch Throwable _ nil))))

(defn- proxy-serve [client-fd seen]
  (let [closed? (atom false)]
    (try
      (loop [acc ""]
        (if-let [chunk (net/recv-bytes client-fd)]
          (let [acc (str acc (ba->latin1 chunk))
                end (str/index-of acc "\r\n\r\n")]
            (if (nil? end)
              (recur acc)
              (let [head (subs acc 0 end)
                    body-rest (subs acc (+ end 4))
                    [method target] (str/split (first (str/split head #"\r\n")) #" ")]
                (if (= "CONNECT" method)
                  (proxy-connect client-fd target seen closed?)
                  (proxy-forward client-fd head body-rest seen)))))
          nil))
      (catch Throwable _ nil)
      (finally (when (compare-and-set! closed? false true)
                 (try (net/close client-fd) (catch Throwable _ nil)))))))

(defn start-proxy
  "An HTTP forward proxy on `port`. Returns the server map with an extra :seen
  atom holding one {:method :target} per request the proxy handled."
  [port]
  (let [fd (listen-socket port)
        running? (atom true)
        seen (atom [])]
    (future
      (loop []
        (let [raw (c-accept fd ffi/null ffi/null)]
          (cond
            (not @running?) nil
            (neg? raw) (when @running? (recur))
            :else (do (future (proxy-serve raw seen)) (recur))))))
    {:fd fd :port port :running running? :seen seen}))

;; --- websocket -------------------------------------------------------------
;; An RFC 6455 echo server, built on the same frame codec the client uses
;; (jolt.http.websocket): the server side is the client side with the mask bit
;; off, so a round trip through both exercises one implementation from both
;; ends. Text and binary messages come back as they arrived; a ping gets a pong;
;; a close is echoed and ends the session. /reject answers 400 instead of
;; upgrading, and /greet sends a message unprompted after the handshake.

(defn- ws-accept-response [key protocol]
  (str "HTTP/1.1 101 Switching Protocols\r\n"
       "Upgrade: websocket\r\n"
       "Connection: Upgrade\r\n"
       "Sec-WebSocket-Accept: " (ws/accept-key key) "\r\n"
       (when protocol (str "Sec-WebSocket-Protocol: " protocol "\r\n"))
       "\r\n"))

(defn- ws-send! [conn opcode payload]
  (conn-write conn (ws/encode-frame opcode payload {:mask? false})))

(defn- ws-echo-loop [conn leftover]
  ;; offset-based, like the client's reader: (byte-array (concat (seq buf) …))
  ;; boxed a Byte per byte and recopied the whole buffer per read, which put the
  ;; SERVER side of a large echo in the same quadratic hole as the client's.
  (loop [buf leftover off 0]
    (if-let [[frame next-off] (ws/decode-frame-at buf off)]
      (let [{:keys [opcode payload fin?]} frame]
        (cond
          (= opcode ws/op-close) (do (ws-send! conn ws/op-close payload) nil)
          (= opcode ws/op-ping) (do (ws-send! conn ws/op-pong payload) (recur buf next-off))
          (= opcode ws/op-pong) (recur buf next-off)
          :else (do (conn-write conn (ws/encode-frame opcode payload {:mask? false :fin? fin?}))
                    (recur buf next-off))))
      (if-let [chunk (conn-read conn)]
        (recur (jolt.http.core/concat-bas [(jolt.http.core/sub-ba buf off (alength buf)) chunk]) 0)
        nil))))

(defn websocket-handler
  "A test-server handler that upgrades and then echoes. Returns :hijacked, so the
  accept loop leaves the connection alone."
  [{:keys [uri headers conn body-raw]}]
  (let [key (get headers "sec-websocket-key")]
    (cond
      (= uri "/reject") {:status 400 :body "no upgrade here"}
      (nil? key) {:status 400 :body "not a websocket request"}
      :else
      (let [protocol (when-let [p (get headers "sec-websocket-protocol")]
                       (str/trim (first (str/split p #","))))]
        (conn-write conn (latin1->ba (ws-accept-response key protocol)))
        (when (= uri "/greet") (ws-send! conn ws/op-text (.getBytes "hello from server" "UTF-8")))
        (try
          (ws-echo-loop conn (latin1->ba (or body-raw "")))
          (catch Throwable _ nil)
          (finally (try (conn-close conn) (catch Throwable _ nil))))
        :hijacked))))

(defn start-websocket [port]
  (start-plain port {:handler websocket-handler}))
