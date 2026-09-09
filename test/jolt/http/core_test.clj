(ns jolt.http.core-test
  "The HTTP/1.1 engine itself: URL parsing, RFC 3986 reference resolution,
  request serialisation, response framing and the byte pipeline.

  Expected values are what the JVM actually produces — java.net.URL/URI getters,
  java.net.URI/resolve, and the bytes java.net.http puts on the wire, each
  measured against a real JDK rather than recalled."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [jolt.http.core :as core]
            [jolt.http.test-server :as srv]
            [jolt.http.platform]))

;; --- a stream that hands back canned chunks, so framing is testable off-socket
(defn- canned-stream
  "A core stream table yielding `chunks` (byte-arrays or latin1 strings) in turn,
  then nil (EOF). :closed? records whether the reader closed it."
  [chunks]
  (let [left (atom (mapv (fn [c] (if (string? c) (core/latin1->ba c) c)) chunks))
        st (core/tt :jolt/canned-stream)]
    (core/tput! st :read (fn [_ _] (let [c (first @left)] (swap! left rest) c)))
    (core/tput! st :write (fn [_ _] nil))
    (core/tput! st :close (fn [& _] nil))
    st))

(defn- never-ends
  "A stream that hands back `chunks` and then blocks forever — a peer that keeps
  the connection open after a complete, framed response."
  [chunks]
  (let [left (atom (mapv (fn [c] (if (string? c) (core/latin1->ba c) c)) chunks))
        st (core/tt :jolt/canned-stream)]
    (core/tput! st :read (fn [_ _]
                           (if-let [c (first @left)]
                             (do (swap! left rest) c)
                             (do (Thread/sleep 30000) nil))))
    (core/tput! st :write (fn [_ _] nil))
    (core/tput! st :close (fn [& _] nil))
    st))

;; ---------------------------------------------------------------------------
;; URL parsing
;; ---------------------------------------------------------------------------

(deftest url-fragment-is-not-part-of-path-or-query
  (testing "java.net.URL: getPath /p, getQuery a=1, getRef frag, toString keeps it"
    (let [u (core/parse-url "http://h/p?a=1#frag")]
      (is (= "/p" (core/tget u :path)))
      (is (= "a=1" (core/tget u :query)))
      (is (= "frag" (core/tget u :ref)))
      (is (= "http://h/p?a=1#frag" (core/tget u :spec)))))
  (testing "a fragment with no query"
    (let [u (core/parse-url "http://h/p#frag")]
      (is (= "/p" (core/tget u :path)))
      (is (nil? (core/tget u :query)))
      (is (= "frag" (core/tget u :ref)))))
  (testing "no fragment leaves :ref nil"
    (is (nil? (core/tget (core/parse-url "http://h/p?a=1") :ref))))
  (testing "through the java.net.URL shim"
    (let [u (java.net.URL. "http://h/p?a=1#frag")]
      (is (= "/p" (.getPath u)))
      (is (= "a=1" (.getQuery u)))
      (is (= "frag" (.getRef u)))
      (is (= "/p?a=1" (.getFile u)))
      ;; .toString, not (str u): jolt's str on a tagged table does not route
      ;; through a registered toString, and nothing in either client calls it.
      (is (= "http://h/p?a=1#frag" (.toString u))))))

(deftest ipv6-literal-hosts
  (testing "the host keeps its brackets, like java.net.URL/URI getHost"
    (let [u (core/parse-url "http://[::1]:19201/v6")]
      (is (= "[::1]" (core/tget u :host)))
      (is (= 19201 (core/tget u :port)))
      (is (= "/v6" (core/tget u :path)))))
  (testing "no port"
    (let [u (core/parse-url "http://[2001:db8::1]/x")]
      (is (= "[2001:db8::1]" (core/tget u :host)))
      (is (= -1 (core/tget u :port)))
      (is (= 80 (core/effective-port u)))))
  (testing "the Host header carries the brackets and the port"
    (is (str/includes? (core/ba->latin1 (core/build-request "GET" (core/parse-url "http://[::1]:19201/v6") [] nil))
                       "Host: [::1]:19201\r\n"))))

;; ---------------------------------------------------------------------------
;; RFC 3986 reference resolution — values from java.net.URI/resolve
;; ---------------------------------------------------------------------------

(deftest resolve-location-matches-uri-resolve
  (doseq [[base loc expected]
          [["http://h:9000/a/b/c" "d"          "http://h:9000/a/b/d"]
           ["http://h:9000/a/b/c" "../d"       "http://h:9000/a/d"]
           ["http://h:9000/a/b/c" "/d"         "http://h:9000/d"]
           ["http://h:9000/a/b/c" "//other/x"  "http://other/x"]
           ["http://h:9000/a/b/"  "d"          "http://h:9000/a/b/d"]
           ["http://h:9000/a"     "d"          "http://h:9000/d"]
           ["http://h:9000"       "d"          "http://h:9000/d"]
           ["http://h:9000/a/b/c" "./x/../y"   "http://h:9000/a/b/y"]
           ["https://h/a/b"       "https://o/z" "https://o/z"]
           ["http://u@h:81/a/b"   "c"          "http://u@h:81/a/c"]]]
    (is (= expected (core/tget (core/resolve-location (core/parse-url base) loc) :spec))
        (str base " + " loc))))

(deftest resolve-location-query-only
  (testing "RFC 3986 5.3: a bare query keeps the base path (java.net.URI/resolve
            differs here and drops the last segment; the RFC reading is used)"
    (is (= "http://h:9000/a/b/c?q=1"
           (core/tget (core/resolve-location (core/parse-url "http://h:9000/a/b/c") "?q=1") :spec)))))

;; ---------------------------------------------------------------------------
;; Request serialisation — bytes measured off a real java.net.http
;; ---------------------------------------------------------------------------

(defn- wire [method url headers body]
  (core/ba->latin1 (core/build-request method (core/parse-url url) headers body)))

(defn- header-lines [w nm]
  (filter #(str/starts-with? (str/lower-case %) (str (str/lower-case nm) ":"))
          (str/split-lines w)))

(deftest request-target-never-carries-a-fragment
  (is (str/starts-with? (wire "GET" "http://h/frag#somefrag" [] nil) "GET /frag HTTP/1.1\r\n"))
  (is (str/starts-with? (wire "GET" "http://h/p?a=1#f" [] nil) "GET /p?a=1 HTTP/1.1\r\n")))

(deftest content-length-follows-java-net-http
  (testing "a body of n bytes always carries Content-Length: n"
    (is (= ["Content-Length: 4"] (header-lines (wire "POST" "http://h/x" [] (core/latin1->ba "abcd")) "content-length"))))
  (testing "an empty body: Content-Length: 0 for POST and PUT only"
    (doseq [m ["POST" "PUT"]]
      (is (= ["Content-Length: 0"] (header-lines (wire m "http://h/x" [] (byte-array 0)) "content-length"))
          m))
    (doseq [m ["GET" "HEAD" "DELETE" "PATCH"]]
      (is (empty? (header-lines (wire m "http://h/x" [] (byte-array 0)) "content-length")) m)))
  (testing "no body publisher at all: never"
    (is (empty? (header-lines (wire "POST" "http://h/x" [] nil) "content-length")))))

(deftest no-duplicate-framing-headers
  (testing "a caller's Content-Length and Connection never join ours on the wire"
    (let [w (wire "POST" "http://h/x"
                  [["Content-Length" "999"] ["Connection" "keep-alive"] ["X-Ok" "v"]]
                  (core/latin1->ba "abcd"))]
      (is (= ["Content-Length: 4"] (header-lines w "content-length")))
      (is (empty? (header-lines w "connection"))
          "HTTP/1.1 is persistent by default; the caller's own Connection is dropped")
      (is (= ["X-Ok: v"] (header-lines w "x-ok")))))
  (testing "a caller's Host replaces ours rather than doubling it"
    (let [w (wire "GET" "http://h/x" [["Host" "vhost.example"]] nil)]
      (is (= ["Host: vhost.example"] (header-lines w "host"))))))

;; ---------------------------------------------------------------------------
;; Response framing
;; ---------------------------------------------------------------------------

(deftest content-length-framing-does-not-wait-for-close
  (testing "a complete Content-Length response from a peer that holds the socket"
    (let [t0 (System/currentTimeMillis)
          r (core/read-response (never-ends ["HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"]) nil "GET")]
      (is (= 200 (:status r)))
      (is (= "hello" (core/ba->latin1 (:body r))))
      (is (< (- (System/currentTimeMillis) t0) 2000) "returned without waiting for EOF")))
  (testing "a body split across reads"
    (let [r (core/read-response (never-ends ["HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhel" "lo" "world"])
                                nil "GET")]
      (is (= "helloworld" (core/ba->latin1 (:body r))))))
  (testing "headers split across reads"
    (let [r (core/read-response (never-ends ["HTTP/1.1 200 OK\r\nCont" "ent-Length: 2\r\n" "\r\nhi"]) nil "GET")]
      (is (= 200 (:status r)))
      (is (= "hi" (core/ba->latin1 (:body r)))))))

(deftest bodyless-responses-do-not-wait
  (testing "HEAD: Content-Length describes the body a GET would return"
    (let [r (core/read-response (never-ends ["HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"]) nil "HEAD")]
      (is (= 200 (:status r)))
      (is (zero? (alength (:body r))))))
  (doseq [status [204 304]]
    (testing (str status " never has a body")
      (let [r (core/read-response (never-ends [(str "HTTP/1.1 " status " x\r\n\r\n")]) nil "GET")]
        (is (= status (:status r)))
        (is (zero? (alength (:body r))))))))

(deftest chunked-framing
  (testing "a chunked body ends at the terminal chunk, not at EOF"
    (let [r (core/read-response (never-ends ["HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                             "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"])
                                nil "GET")]
      (is (= "hello world" (core/ba->latin1 (:body r))))))
  (testing "chunk extensions are ignored"
    (let [r (core/read-response (canned-stream ["HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                                "5;a=b\r\nhello\r\n0\r\n\r\n"])
                                nil "GET")]
      (is (= "hello" (core/ba->latin1 (:body r))))))
  (testing "a chunk spanning several reads"
    (let [r (core/read-response (never-ends ["HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                             "a\r\nhel" "lo" "worl" "d\r\n0\r\n\r\n"])
                                nil "GET")]
      (is (= "helloworld" (core/ba->latin1 (:body r))))))
  (testing "a malformed chunk size is an error, not a silent truncation"
    (is (thrown? java.io.IOException
                 (core/read-response (canned-stream ["HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                                     "5\r\nhello\r\nZZZ\r\nworld\r\n0\r\n\r\n"])
                                     nil "GET")))))

(deftest read-to-close-still-works
  (testing "no Content-Length and no chunking: read until the peer closes"
    (let [r (core/read-response (canned-stream ["HTTP/1.1 200 OK\r\nX: y\r\n\r\n" "abc" "def"]) nil "GET")]
      (is (= "abcdef" (core/ba->latin1 (:body r)))))))

(deftest body-bytes-survive-the-pipeline
  (testing "every byte value round-trips through framing unchanged"
    (let [payload (byte-array (map (fn [i] (byte (- (mod i 256) 128))) (range 4096)))
          head (core/latin1->ba (str "HTTP/1.1 200 OK\r\nContent-Length: " (alength payload) "\r\n\r\n"))
          r (core/read-response (never-ends [head payload]) nil "GET")]
      (is (= (seq payload) (seq (:body r)))))))

;; ---------------------------------------------------------------------------
;; Byte pipeline throughput
;; ---------------------------------------------------------------------------

(deftest large-bodies-are-not-boxed-per-byte
  (testing "an 8MB body is assembled at transport speed, not one boxed Byte per byte"
    (let [n (* 8 1024 1024)
          payload (byte-array (repeat n (byte 65)))
          head (core/latin1->ba (str "HTTP/1.1 200 OK\r\nContent-Length: " n "\r\n\r\n"))
          chunks (into [head] (map byte-array (partition-all 65536 (seq payload))))
          t0 (System/currentTimeMillis)
          r (core/read-response (never-ends chunks) nil "GET")
          took (- (System/currentTimeMillis) t0)]
      (is (= n (alength (:body r))))
      (is (< took 4000) (str "8MB took " took "ms")))))

;; ---------------------------------------------------------------------------
;; Connection reuse
;; ---------------------------------------------------------------------------

;; a port per test: these servers hold connections open by design, so one test's
;; sockets must not still be established when the next one binds
(def ^:private pool-ports (atom 18150))
(defn- next-pool-port [] (swap! pool-ports inc))

(defn- pool-handler [req]
  (let [uri (:uri req)]
    (cond
      (= uri "/chunked") {:status 200 :body "chunked body here" :chunked true}
      (= uri "/close") {:status 200 :body "bye" :close true}
      (= uri "/echo") {:status 200 :body (:body-raw req)}
      :else {:status 200 :body (str "ok " uri)})))

(def ^:private ^:dynamic *pool-base* nil)

(defn- with-pool-server
  "Run `f` against a fresh keep-alive server on a port of its own, with an empty
  pool either side of it. The pool is cleared BEFORE the server stops, so the
  client ends of the connections it is holding are closed first."
  [f]
  (let [port (next-pool-port)
        s (srv/start-persistent port pool-handler)]
    (core/pool-clear!)
    (binding [*pool-base* (str "http://localhost:" port)]
      (try (f s) (finally (core/pool-clear!) (srv/stop s))))))

(defn- get! [path]
  (let [conn (.openConnection (java.net.URL. (str *pool-base* path)))]
    {:status (.getResponseCode conn)
     :body (slurp (.getInputStream conn))}))

(deftest connections-are-reused
  (with-pool-server
   (fn [s]
    (testing "several requests to one origin share a socket"
      (dotimes [i 5] (is (= (str "ok /r" i) (:body (get! (str "/r" i))))))
      (is (= 5 (:requests @(:stats s))))
      (is (= 1 (core/pool-count)) "one idle connection held for the origin"))
    (testing "a chunked response over a reused connection frames correctly"
      (is (= "chunked body here" (:body (get! "/chunked"))))
      (is (= 1 (core/pool-count))))
    (testing "the server asking to close retires the connection"
      (is (= "bye" (:body (get! "/close"))))
      (is (zero? (core/pool-count)))))))

(defn- hangup-handler
  "Answers the first request on a connection and hangs up on the next one
  without replying — a peer retiring a socket exactly as the client reuses it,
  which is the case the retry exists for."
  [req]
  (if (pos? (:request-number req)) :hangup {:status 200 :body "ok"}))

(deftest a-retired-connection-is-retried
  (testing "the peer hangs up once the reused request is already on the wire"
    ;; the pooled socket is alive when it is taken, so the liveness check passes
    ;; and only the retry can save this request
    (let [port (next-pool-port)
          s (srv/start-persistent port hangup-handler)]
      (core/pool-clear!)
      (binding [*pool-base* (str "http://localhost:" port)]
        (try
          (is (= "ok" (:body (get! "/first"))))
          (is (= 1 (core/pool-count)))
          (is (= "ok" (:body (get! "/second"))) "retried on a fresh connection")
          ;; three requests reached the server for two the caller made: the
          ;; first, the one it hung up on, and the retry
          (is (= 3 (:requests @(:stats s))))
          (finally (core/pool-clear!) (srv/stop s)))))))

(defn- typed [cls] (try (core/throw-typed cls "x") (catch Throwable t t)))

(deftest connection-gone-tells-a-dead-socket-from-a-slow-one
  (testing "a peer that went away, however the platform reports it"
    (is (true? (core/connection-gone? (typed "java.io.EOFException"))))
    (is (true? (core/connection-gone? (typed "java.net.SocketException")))))
  (testing "a timeout says the peer is slow, not gone, and is never retried"
    (is (false? (core/connection-gone? (typed "java.net.SocketTimeoutException")))))
  (testing "a malformed response is the peer's answer, not its absence"
    (is (false? (core/connection-gone? (typed "java.io.IOException"))))))

(defn- truncating-handler
  "Answers the first request on a connection; on the next one sends headers and
  then hangs up mid-body."
  [req]
  (if (pos? (:request-number req)) :truncate {:status 200 :body "ok"}))

(deftest a-failure-after-bytes-arrive-is-not-replayed
  ;; the retry is only safe while the peer cannot have acted on the request.
  ;; Once a byte of response has arrived it plainly has, so the error surfaces.
  (let [port (next-pool-port)
        s (srv/start-persistent port truncating-handler)]
    (core/pool-clear!)
    (binding [*pool-base* (str "http://localhost:" port)]
      (try
        (is (= "ok" (:body (get! "/first"))))
        (is (= 1 (core/pool-count)))
        (is (thrown? Exception (get! "/second")))
        (is (= 2 (:requests @(:stats s))) "not replayed on a fresh connection")
        (finally (core/pool-clear!) (srv/stop s))))))

(deftest a-dead-connection-is-dropped-before-it-is-used
  (with-pool-server
   (fn [s]
    (is (= "ok /a" (:body (get! "/a"))))
    (is (= 1 (core/pool-count)))
    ;; the peer closes its end while the connection sits idle
    (srv/drop-connections! s)
    (Thread/sleep 100)
    (is (= "ok /b" (:body (get! "/b"))) "the dead socket is replaced, not reported")
    (is (= 1 (core/pool-count))))))

(deftest pooling-can-be-switched-off
  (with-pool-server
   (fn [_s]
    (reset! core/pool-enabled? false)
    (try
      (dotimes [_ 3] (get! "/x"))
      (is (zero? (core/pool-count)) "nothing is kept")
      (finally (reset! core/pool-enabled? true))))))

(deftest an-expired-connection-is-not-reused
  (with-pool-server
   (fn [_s]
    (let [was @core/pool-idle-ms]
      (reset! core/pool-idle-ms 1)
      (try
        (get! "/a")
        (Thread/sleep 30)
        (is (= "ok /b" (:body (get! "/b"))))
        (finally (reset! core/pool-idle-ms was)))))))

(deftest concurrent-requests-never-share-a-connection
  (with-pool-server
   (fn [_s]
    (testing "20 requests in flight at once all come back with their own body"
      (let [fs (doall (for [i (range 20)]
                        (future (try (:body (get! (str "/c" i))) (catch Throwable t (str "ERR " (ex-message t)))))))
            got (mapv deref fs)]
        (is (= (set (map #(str "ok /c" %) (range 20))) (set got)))
        (is (<= (core/pool-count) @core/pool-max-per-key)
            "the pool never grows past its per-origin limit"))))))

(deftest a-reused-connection-takes-the-new-requests-timeout
  ;; the pooled socket carries the SO_RCVTIMEO of whichever request opened it
  (let [slow (srv/start-persistent (next-pool-port)
                                   (fn [req] (when (= "/slow" (:uri req)) (Thread/sleep 2000))
                                     {:status 200 :body "ok"}))]
    (core/pool-clear!)
    (try
      (testing "a first request with a generous timeout leaves a pooled connection"
        (let [c (.openConnection (java.net.URL. (str "http://localhost:" (:port slow) "/fast")))]
          (.setReadTimeout c 10000)
          (is (= 200 (.getResponseCode c))))
        (is (= 1 (core/pool-count))))
      (testing "the next request's own, shorter timeout is the one that applies"
        (let [c (.openConnection (java.net.URL. (str "http://localhost:" (:port slow) "/slow")))]
          (.setReadTimeout c 300)
          (is (thrown? java.net.SocketTimeoutException (.getResponseCode c)))))
      (finally (core/pool-clear!) (srv/stop slow)))))

(deftest http-1-0-is-not-persistent-by-default
  (testing "a 1.0 response with a length is still not reusable"
    (is (false? (:reusable? (core/read-response
                              (canned-stream ["HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok"]) nil "GET")))))
  (testing "unless it says keep-alive"
    (is (true? (:reusable? (core/read-response
                             (canned-stream ["HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"])
                             nil "GET")))))
  (testing "a 1.1 response is reusable unless it says close"
    (is (true? (:reusable? (core/read-response
                             (canned-stream ["HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"]) nil "GET"))))
    (is (false? (:reusable? (core/read-response
                              (canned-stream ["HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"])
                              nil "GET")))))
  (testing "read-to-close framing can never be kept"
    (is (false? (:reusable? (core/read-response
                              (canned-stream ["HTTP/1.1 200 OK\r\n\r\n" "body"]) nil "GET"))))))

(deftest concat-and-slice-helpers
  (let [a (byte-array [1 2 3]) b (byte-array [4 5])]
    (is (= [1 2 3 4 5] (vec (core/concat-ba a b))))
    (is (= [1 2 3 4 5] (vec (core/concat-bas [a b]))))
    (is (= [] (vec (core/concat-bas []))))
    (is (= [2 3] (vec (core/sub-ba (byte-array [1 2 3 4]) 1 3))))
    (is (= [] (vec (core/sub-ba (byte-array [1 2 3]) 2 2))))))
