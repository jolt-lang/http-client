(ns jolt.http.test-server
  "In-process HTTP/1.1 servers (plaintext + OpenSSL TLS) for the test suite, over
  jolt.ffi BSD sockets — standing in for the Jetty subprocess clj-http-lite's
  integration tests would otherwise launch. Mirrors clj-http-lite's own test
  handler routes."
  (:require [clojure.string :as str]
            [jolt.ffi :as ffi]
            [jolt.http.net :as net]
            [jolt.http.tls :as tls]))

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

(defn- make-sockaddr [port]
  (let [sa (ffi/alloc 16)]
    (dotimes [i 16] (ffi/write sa :uint8 i 0))
    (if macos?
      (do (ffi/write sa :uint8 0 16) (ffi/write sa :uint8 1 AF-INET))
      (ffi/write sa :uint8 0 AF-INET))
    (ffi/write sa :uint8 2 (bit-and (bit-shift-right port 8) 0xff))
    (ffi/write sa :uint8 3 (bit-and port 0xff))
    (ffi/write sa :uint8 4 127) (ffi/write sa :uint8 7 1)   ; 127.0.0.1
    sa))

(defn listen-socket [port]
  (let [fd (c-socket AF-INET SOCK-STREAM 0)]
    (when (neg? fd) (throw (ex-info "socket() failed" {})))
    (let [opt (ffi/alloc 4)]
      (ffi/write opt :int 0 1)
      (c-setsockopt fd sol-socket so-reuse opt 4)
      (ffi/free opt))
    (let [sa (make-sockaddr port)]
      (when (neg? (c-bind fd sa 16))
        (net/close fd) (ffi/free sa) (throw (ex-info (str "bind() failed on port " port) {})))
      (ffi/free sa))
    (when (neg? (c-listen fd 64)) (net/close fd) (throw (ex-info "listen() failed" {})))
    fd))

;; --- connection read/write (plain fd or TLS stream) ------------------------
(defn- conn-read [conn] (if (jolt.host/table? conn) ((jolt.host/ref-get conn :read) conn nil) (net/recv-bytes conn)))
(defn- conn-write [conn data] (if (jolt.host/table? conn) ((jolt.host/ref-get conn :write) conn data) (net/send-bytes conn data)))
(defn- conn-close [conn] (if (jolt.host/table? conn) ((jolt.host/ref-get conn :close)) (net/close conn)))

(defn- ba->latin1 [ba] (String. ba "ISO-8859-1"))
(defn- latin1->ba [s] (byte-array (map int s)))

(defn- parse-request [text]
  (let [blank (str/index-of text "\r\n\r\n")
        head (subs text 0 blank)
        rest-body (subs text (+ blank 4))
        lines (str/split head #"\r\n")
        [method target] (str/split (first lines) #" ")
        qi (str/index-of target "?")
        uri (if qi (subs target 0 qi) target)
        headers (reduce (fn [m line]
                          (let [i (str/index-of line ":")]
                            (if (and i (pos? i))
                              (assoc m (str/lower-case (str/trim (subs line 0 i))) (str/trim (subs line (inc i))))
                              m)))
                        {} (rest lines))]
    {:request-method (keyword (str/lower-case method))
     :uri uri :headers headers :body-raw rest-body
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
(defn handler [req]
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
  {200 "OK" 302 "Found" 401 "Unauthorized" 404 "Not Found" 500 "Internal Server Error"})

(defn- write-response [conn resp]
  (let [body (or (:body resp) "")
        sb (StringBuilder.)]
    (.append sb (str "HTTP/1.1 " (:status resp) " " (get status-text (:status resp) "OK") "\r\n"))
    (.append sb (str "Date: Mon, 01 Jan 2026 00:00:00 GMT\r\n"))
    (doseq [[k v] (:headers resp)] (.append sb (str k ": " v "\r\n")))
    (.append sb (str "Content-Length: " (count body) "\r\n"))
    (.append sb "Connection: close\r\n\r\n")
    (.append sb body)
    (conn-write conn (latin1->ba (.toString sb)))))

(defn- serve-one [conn]
  (try
    (when-let [req (read-request conn)]
      (write-response conn (handler req)))
    (catch Throwable _ nil)
    (finally (try (conn-close conn) (catch Throwable _ nil)))))

(defn- accept-loop [listen-fd running? wrap]
  (loop []
    (let [raw (c-accept listen-fd ffi/null ffi/null)]
      (cond
        (not @running?) nil
        (neg? raw) (when @running? (recur))
        :else (do
                (try
                  (let [conn (if wrap (wrap raw) raw)] (serve-one conn))
                  (catch Throwable _ (try (net/close raw) (catch Throwable _ nil))))
                (recur))))))

(defn start-plain [port]
  (let [fd (listen-socket port) running? (atom true)]
    (future (accept-loop fd running? nil))
    {:fd fd :port port :running running?}))

(defn start-tls [port cert key]
  (let [fd (listen-socket port) running? (atom true)]
    (future (accept-loop fd running? (fn [raw] (tls/tls-wrap-server raw cert key))))
    {:fd fd :port port :running running?}))

(defn stop [server]
  (reset! (:running server) false)
  (net/close (:fd server))
  nil)
