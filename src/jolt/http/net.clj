(ns jolt.http.net
  "A blocking BSD-socket TCP client over jolt.ffi: name resolution via
  getaddrinfo, then socket/connect/recv/send/close. Shared by jolt.http.platform
  (plaintext HTTP) and jolt.http.tls (the ciphertext transport under OpenSSL).

  libc is declared in deps.edn (:jolt/native :process), so these process symbols
  resolve at load. accept/recv/send/connect/getaddrinfo are marked :blocking so a
  parked socket call never pins jolt's stop-the-world collector."
  (:require [jolt.ffi :as ffi]
            [clojure.string :as str]))

(ffi/defcfn c-socket      "socket"      [:int :int :int] :int)
(ffi/defcfn c-connect     "connect"     [:int :pointer :int] :int :blocking)
(ffi/defcfn c-close       "close"       [:int] :int)
(ffi/defcfn c-recv        "recv"        [:int :pointer :size_t :int] :ssize_t :blocking)
(ffi/defcfn c-send        "send"        [:int :pointer :size_t :int] :ssize_t :blocking)
(ffi/defcfn c-setsockopt  "setsockopt"  [:int :int :int :pointer :int] :int)
(ffi/defcfn c-getaddrinfo "getaddrinfo" [:pointer :pointer :pointer :pointer] :int :blocking)
(ffi/defcfn c-freeaddrinfo "freeaddrinfo" [:pointer] :void)

(def ^:private macos?
  (str/includes? (str/lower-case (or (System/getProperty "os.name") "")) "mac"))

;; struct addrinfo field offsets (LP64). macOS swaps ai_canonname/ai_addr versus
;; Linux, so ai_addr sits at 32 on macOS, 24 on Linux. ai_addrlen=16, ai_next=40.
(def ^:private O-ai-family 4)
(def ^:private O-ai-socktype 8)
(def ^:private O-ai-protocol 12)
(def ^:private O-ai-addrlen 16)
(def ^:private O-ai-addr (if macos? 32 24))
(def ^:private O-ai-next 40)

;; SOL_SOCKET / SO_RCVTIMEO differ by platform: macOS 0xffff / 0x1006, Linux 1 / 20.
(def ^:private sol-socket (if macos? 0xffff 1))
(def ^:private so-rcvtimeo (if macos? 0x1006 20))

(defn- conn-ex [class msg]
  ;; a typed throwable so callers get the right (class e)/instance? AND a working
  ;; .getMessage/ex-message (the cognitect aws backend reads .getMessage).
  (throw (jolt.host/throwable class (str msg))))

(defn connect
  "Resolve host:port and open a connected TCP socket; return its fd. Throws a
  java.net.UnknownHostException / ConnectException-tagged throwable on failure."
  [host port]
  (let [node    (ffi/string->ptr (str host))
        service (ffi/string->ptr (str port))
        respp   (ffi/alloc (ffi/sizeof :pointer))
        ;; hints: ai_socktype = SOCK_STREAM, else getaddrinfo also returns UDP
        ;; entries and connect() on a datagram socket spuriously "succeeds".
        hints   (ffi/alloc 48)]
    (dotimes [i 48] (ffi/write hints :uint8 i 0))
    (ffi/write hints :int O-ai-socktype 1)   ; SOCK_STREAM
    (try
      (let [rc (c-getaddrinfo node service hints respp)]
        (when-not (zero? rc)
          (conn-ex "java.net.UnknownHostException" (str host)))
        (let [res (ffi/read respp :pointer)]
          (try
            (loop [ai res]
              (if (ffi/null? ai)
                (conn-ex "java.net.ConnectException" (str "connection refused: " host ":" port))
                (let [fam     (ffi/read ai :int O-ai-family)
                      sockt   (ffi/read ai :int O-ai-socktype)
                      proto   (ffi/read ai :int O-ai-protocol)
                      addrlen (ffi/read ai :int O-ai-addrlen)
                      addr    (ffi/read ai :pointer O-ai-addr)
                      fd      (c-socket fam sockt proto)]
                  (cond
                    (neg? fd) (recur (ffi/read ai :pointer O-ai-next))
                    (zero? (c-connect fd addr addrlen)) fd
                    :else (do (c-close fd) (recur (ffi/read ai :pointer O-ai-next)))))))
            (finally (c-freeaddrinfo res)))))
      (finally (ffi/free node) (ffi/free service) (ffi/free respp) (ffi/free hints)))))

(defn set-read-timeout!
  "Apply SO_RCVTIMEO of `ms` milliseconds to `fd` (a recv past it returns -1)."
  [fd ms]
  (when (and ms (pos? ms))
    ;; struct timeval { time_t tv_sec; suseconds_t tv_usec; } — 16 bytes LP64.
    (let [tv (ffi/alloc 16)]
      (dotimes [i 16] (ffi/write tv :uint8 i 0))
      (ffi/write tv :long 0 (quot ms 1000))
      (ffi/write tv :long 8 (* (rem ms 1000) 1000))
      (c-setsockopt fd sol-socket so-rcvtimeo tv 16)
      (ffi/free tv))))

(def ^:private bufsize 65536)

(defn recv-bytes
  "Read up to one bufferful from `fd`: a byte-array, nil at EOF (recv 0), or a
  thrown SocketTimeoutException if a read timeout (SO_RCVTIMEO) elapsed (recv -1)."
  [fd]
  (let [buf (ffi/alloc bufsize)]
    (try
      (let [got (c-recv fd buf bufsize 0)]
        (cond
          (pos? got) (ffi/read-array buf got)
          (zero? got) nil
          :else (conn-ex "java.net.SocketTimeoutException" "Read timed out")))
      (finally (ffi/free buf)))))

(defn send-bytes
  "Send all of byte-array `data` over `fd`."
  [fd data]
  (let [n (alength data)
        buf (ffi/alloc (max 1 n))]
    (try
      (ffi/write-array buf data)
      (loop [off 0]
        (when (< off n)
          (let [sent (c-send fd (+ buf off) (- n off) 0)]
            (if (pos? sent)
              (recur (+ off sent))
              (conn-ex "java.io.IOException" "send failed")))))
      (finally (ffi/free buf)))))

(defn close [fd] (c-close fd) nil)
