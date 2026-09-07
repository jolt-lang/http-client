(ns jolt.http.net
  "A blocking BSD-socket TCP client over jolt.ffi: name resolution via
  getaddrinfo, then socket/connect/recv/send/close. Shared by jolt.http.platform
  (plaintext HTTP) and jolt.http.tls (the ciphertext transport under OpenSSL).

  libc is declared in deps.edn (:jolt/native :process), so these process symbols
  resolve at load. accept/recv/send/connect/getaddrinfo are marked :blocking so a
  parked socket call never pins jolt's stop-the-world collector."
  (:require [jolt.ffi :as ffi]
            [jolt.io-poller :as poller]
            [clojure.string :as str]))

(ffi/defcfn c-socket      "socket"      [:int :int :int] :int)
(ffi/defcfn c-connect     "connect"     [:int :pointer :int] :int :blocking)
(ffi/defcfn c-close       "close"       [:int] :int)
(ffi/defcfn c-recv        "recv"        [:int :pointer :size_t :int] :ssize_t :blocking)
(ffi/defcfn c-send        "send"        [:int :pointer :size_t :int] :ssize_t :blocking)
(ffi/defcfn c-setsockopt  "setsockopt"  [:int :int :int :pointer :int] :int)
(ffi/defcfn c-getaddrinfo "getaddrinfo" [:pointer :pointer :pointer :pointer] :int :blocking)
(ffi/defcfn c-freeaddrinfo "freeaddrinfo" [:pointer] :void)
;; fcntl is variadic (int fd, int cmd, ...). A fixed-arity binding silently
;; corrupts the flags argument on Apple arm64, where variadic args travel on
;; the stack — the :varargs marker sits at the fixed/variadic boundary (two
;; fixed args, then the variadic flags int) and emits the (__varargs_after 2)
;; convention, so F_SETFL's third argument actually lands. The 2-arg
;; c-fcntl-get binding is safe fixed-arity: F_GETFL passes no variadic args
;; and named args ride the same registers in both conventions.
(ffi/defcfn c-fcntl-get  "fcntl"      [:int :int] :int)
(ffi/defcfn c-fcntl-set  "fcntl"      [:int :int :varargs :int] :int)
(ffi/defcfn c-poll       "poll"       [:pointer :int :int] :int :blocking)
(ffi/defcfn c-getsockopt "getsockopt" [:int :int :int :pointer :pointer] :int)

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

;; SOL_SOCKET / SO_RCVTIMEO / SO_ERROR differ by platform: macOS 0xffff / 0x1006 /
;; 0x1007, Linux 1 / 20 / 4.
(def ^:private sol-socket (if macos? 0xffff 1))
(def ^:private so-rcvtimeo (if macos? 0x1006 20))
(def ^:private so-error (if macos? 0x1007 4))

;; fcntl F_GETFL/F_SETFL are the same on macOS and Linux; O_NONBLOCK differs
;; (Darwin 0x4, Linux 0x800). POLLOUT is 0x4 on both.
(def ^:private f-getfl 3)
(def ^:private f-setfl 4)
(def ^:private o-nonblock (if macos? 0x4 0x800))
(def ^:private po-pollin 1)
(def ^:private po-pollout 4)

(defn- conn-ex [class msg]
  ;; a typed throwable so callers get the right (class e)/instance? AND a working
  ;; .getMessage/ex-message (the cognitect aws backend reads .getMessage).
  (throw (jolt.host/throwable class (str msg))))

;; A timed connect needs the socket non-blocking: connect() then returns -1
;; immediately (EINPROGRESS) and poll() waits on it, with SO_ERROR telling us
;; whether the connection actually succeeded. fcntl F_SETFL is the only way to
;; flip O_NONBLOCK, hence the variadic binding above.
(defn- set-nonblock! [fd nonblocking?]
  (let [flags (c-fcntl-get fd f-getfl)]
    (when (neg? flags)
      (conn-ex "java.io.IOException" "fcntl F_GETFL failed"))
    ;; An unchecked F_SETFL is the one failure that hides itself: the socket
    ;; stays blocking, connect() parks for the kernel's SYN window, and the
    ;; timeout the caller asked for silently does nothing.
    (when (neg? (c-fcntl-set fd f-setfl (if nonblocking?
                                          (bit-or flags o-nonblock)
                                          (bit-and-not flags o-nonblock))))
      (conn-ex "java.io.IOException" "fcntl F_SETFL failed"))
    nil))

(defn- socket-error [fd]
  ;; SO_ERROR for a socket poll() reported writable: 0 means the connect
  ;; completed, anything else is the errno of the failed connect. getsockopt
  ;; leaves the buffer untouched when it fails, so a fresh allocation would read
  ;; back as whatever was in that memory — zero it and report a failed getsockopt
  ;; as an error rather than risk calling a dead socket connected.
  (let [err (ffi/alloc 4) len (ffi/alloc 4)]
    (try
      (ffi/write err :int 0 0)
      (ffi/write len :uint 4 0)
      (if (neg? (c-getsockopt fd sol-socket so-error err len))
        -1
        (ffi/read err :int))
      (finally (ffi/free err) (ffi/free len)))))

;; Return 0 when the connection is established, :timeout when the poll deadline
;; elapsed, or a nonzero error code when the connect failed outright. All three
;; non-success outcomes mean only "this address did not work" — the caller closes
;; the fd and moves to the next one. connect() on a non-blocking socket returns
;; -1 (EINPROGRESS) instead of blocking; poll then waits on it and SO_ERROR
;; reports the outcome.
(defn- timed-connect [fd addr addrlen timeout-ms]
  (if (zero? (c-connect fd addr addrlen))
    0
    (let [pf (ffi/alloc 8)]
      (try
        ;; struct pollfd { int fd; short events; short revents; } — 8 bytes LP64.
        ;; jolt.ffi has no 16-bit type, so events and revents are set by one :int
        ;; write: little-endian puts events in the low half, revents (already
        ;; zeroed) in the high half.
        (dotimes [i 8] (ffi/write pf :uint8 0 i))
        (ffi/write pf :int fd 0)
        (ffi/write pf :int po-pollout 4)
        (let [pr (c-poll pf 1 (int timeout-ms))]
          (cond
            ;; writable — the connect either completed or failed; SO_ERROR tells.
            (pos? pr) (socket-error fd)
            (zero? pr) :timeout
            :else (conn-ex "java.io.IOException" "poll failed")))
        (finally (ffi/free pf))))))

(defn- attempt-connect [fd addr addrlen timeout-ms]
  (if (and timeout-ms (pos? timeout-ms))
    (do (set-nonblock! fd true)
        (let [rc (timed-connect fd addr addrlen timeout-ms)]
          ;; Restore blocking only for the fd we are handing back: recv/send and
          ;; SO_RCVTIMEO downstream all assume a blocking socket. On any failure
          ;; the caller closes it, so there is nothing to restore, and skipping
          ;; the restore keeps a failing fcntl from masking the real error.
          (when (= 0 rc) (set-nonblock! fd false))
          rc))
    (c-connect fd addr addrlen)))

(defn connect
  "Resolve host:port and open a connected TCP socket; return its fd. `timeout-ms`,
  when positive, bounds each connect attempt with a non-blocking connect + poll —
  without it, a blocked connect is bounded only by the kernel's SYN retry limit.
  The bound is per address, as java.net.Socket's is: a host resolving to both a
  dead and a live address still connects. Throws a java.net.UnknownHostException
  / ConnectException-tagged throwable on failure."
  ([host port] (connect host port nil))
  ([host port timeout-ms]
   (let [node    (ffi/string->ptr (str host))
         service (ffi/string->ptr (str port))
         respp   (ffi/alloc (ffi/sizeof :pointer))
         ;; hints: ai_socktype = SOCK_STREAM, else getaddrinfo also returns UDP
         ;; entries and connect() on a datagram socket spuriously "succeeds".
         hints   (ffi/alloc 48)]
     (dotimes [i 48] (ffi/write hints :uint8 0 i))
     (ffi/write hints :int 1 O-ai-socktype)   ; SOCK_STREAM
     (try
       (let [rc (c-getaddrinfo node service hints respp)]
         (when-not (zero? rc)
           (conn-ex "java.net.UnknownHostException" (str host)))
         (let [res (ffi/read respp :pointer)]
           (try
             ;; Walk every address getaddrinfo returned. A timeout retires only
             ;; the address it happened on — a name whose AAAA blackholes and
             ;; whose A answers is the ordinary shape of a broken-IPv6 network,
             ;; and giving up on the host there would make :conn-timeout turn a
             ;; working request into a failing one. `timed-out?` only decides
             ;; which message the exhausted walk reports.
             (loop [ai res timed-out? false]
               (if (ffi/null? ai)
                 (conn-ex "java.net.ConnectException"
                          (if timed-out?
                            (str "connect timed out: " host ":" port)
                            (str "connection refused: " host ":" port)))
                 (let [fam     (ffi/read ai :int O-ai-family)
                       sockt   (ffi/read ai :int O-ai-socktype)
                       proto   (ffi/read ai :int O-ai-protocol)
                       addrlen (ffi/read ai :int O-ai-addrlen)
                       addr    (ffi/read ai :pointer O-ai-addr)
                       fd      (c-socket fam sockt proto)]
                   (cond
                     (neg? fd) (recur (ffi/read ai :pointer O-ai-next) timed-out?)
                     ;; The try covers the CONNECT and nothing else, so the retry
                     ;; below is an ordinary tail recur. It used to wrap the whole
                     ;; arm, which put the recur inside a try — a shape Clojure
                     ;; refuses ("Cannot recur across try") and jolt compiled into
                     ;; a loop that rebound nothing. jolt refuses it too as of
                     ;; 0.8.2, so this walk no longer builds there.
                     ;;
                     ;; The fd still closes on the way out of a throw, still
                     ;; closes before the next address is tried, and is still
                     ;; returned OPEN on success — the only behaviour that changes
                     ;; is that a c-close raising during the retry path no longer
                     ;; reaches a handler that closes the same fd a second time.
                     :else
                     (let [rc (try (attempt-connect fd addr addrlen timeout-ms)
                                   (catch Throwable t (c-close fd) (throw t)))]
                       (if (= 0 rc)
                         fd
                         (do (c-close fd)
                             (recur (ffi/read ai :pointer O-ai-next)
                                    (or timed-out? (= :timeout rc))))))))))
             (finally (c-freeaddrinfo res)))))
       (finally (ffi/free node) (ffi/free service) (ffi/free respp) (ffi/free hints))))))

(defn set-read-timeout!
  "Apply SO_RCVTIMEO of `ms` milliseconds to `fd` (a recv past it returns -1)."
  [fd ms]
  (when (and ms (pos? ms))
    ;; struct timeval { time_t tv_sec; suseconds_t tv_usec; } — 16 bytes LP64.
    (let [tv (ffi/alloc 16)]
      (dotimes [i 16] (ffi/write tv :uint8 0 i))
      (ffi/write tv :long (quot ms 1000) 0)
      (ffi/write tv :long (* (rem ms 1000) 1000) 8)
      (c-setsockopt fd sol-socket so-rcvtimeo tv 16)
      (ffi/free tv))))

(def ^:private bufsize 65536)

;; errno values differ per platform: EINTR is 4 on both; EAGAIN 35/11,
;; ECONNRESET 54/104, EPIPE 32/32 (macOS/Linux).
(def ^:private eintr 4)
(def ^:private eagain (if macos? 35 11))
(def ^:private econnreset (if macos? 54 104))
(def ^:private epipe 32)

(def interrupt-slice-ms
  "How long one read waits for the socket to become readable before checking
  whether its thread has been interrupted.

  jolt's Thread.interrupt sets the flag and nothing more: a thread inside a
  blocking syscall is not signalled, so a `recv` parked on a silent peer ran
  its whole SO_RCVTIMEO after an interrupt (measured: 4.5 s of a 5 s timeout,
  and a 5 s `poll` likewise). So `recv-bytes` waits for readability in slices
  of this length and checks the flag between them, throwing
  InterruptedException — the same exception an interrupted sleep throws — so
  a caller that cancels a request gets its thread back within one slice
  instead of one socket timeout. The socket's read timeout stays the bound
  on the read as a whole; this only decides how promptly a cancel lands."
  250)

(defn- read-timeout-ms
  "The socket's SO_RCVTIMEO in milliseconds, 0 when none is set (or the query
  fails, which reads as unbounded rather than as a timeout that never was)."
  [fd]
  (let [tv (ffi/alloc 16) len (ffi/alloc 4)]
    (try
      (dotimes [i 16] (ffi/write tv :uint8 0 i))
      (ffi/write len :uint 16 0)
      (if (neg? (c-getsockopt fd sol-socket so-rcvtimeo tv len))
        0
        (+ (* 1000 (ffi/read tv :long 0)) (quot (ffi/read tv :long 8) 1000)))
      (finally (ffi/free tv) (ffi/free len)))))

(defn- await-readable!
  "Park until `fd` has something to read (or has hung up — recv decides which),
  in `interrupt-slice-ms` slices. Throws InterruptedException if the thread was
  interrupted between slices, SocketTimeoutException once the socket's own read
  timeout has elapsed with nothing to read."
  [fd]
  (let [timeout  (read-timeout-ms fd)
        deadline (when (pos? timeout) (+ (System/currentTimeMillis) timeout))
        pf       (ffi/alloc 8)]
    (try
      ;; struct pollfd, as in timed-connect: events in the low half of the int
      ;; at offset 4, revents zeroed in the high half.
      (dotimes [i 8] (ffi/write pf :uint8 0 i))
      (ffi/write pf :int fd 0)
      (ffi/write pf :int po-pollin 4)
      (loop []
        (when (Thread/interrupted)
          (conn-ex "java.lang.InterruptedException" "read interrupted"))
        (let [now   (System/currentTimeMillis)
              slice (if deadline
                      (min interrupt-slice-ms (max 0 (- deadline now)))
                      interrupt-slice-ms)
              pr    (c-poll pf 1 (int slice))]
          (cond
            (pos? pr) nil
            (and deadline (>= (System/currentTimeMillis) deadline))
            (conn-ex "java.net.SocketTimeoutException" "Read timed out")
            (zero? pr) (recur)
            (= (poller/errno) eintr) (recur)
            :else (conn-ex "java.io.IOException" "poll failed"))))
      (finally (ffi/free pf)))))

(defn- recv-err-ex
  "The exception a negative recv deserves, classed by what actually failed:
  EAGAIN is the SO_RCVTIMEO firing (SocketTimeoutException), ECONNRESET/EPIPE
  are the peer tearing the connection down mid-flight (SocketException, like
  java.net). Reported before by every failure alike as \"Read timed out\",
  which sent anyone debugging a reset connection chasing a timeout that was
  never set — that misdirection is what self-signed-ssl-get's flake printed."
  [err]
  (cond
    (= err eagain)      (conn-ex "java.net.SocketTimeoutException" "Read timed out")
    (= err econnreset)  (conn-ex "java.net.SocketException" "Connection reset")
    (= err epipe)       (conn-ex "java.net.SocketException" "Broken pipe")
    :else               (conn-ex "java.net.SocketException"
                                  (str "recv failed (errno " err ")"))))

(defn recv-bytes
  "Read up to one bufferful from `fd`: a byte-array, nil at EOF (recv 0), or a
  thrown exception classed by errno (see recv-err-ex). Waits for readability
  in interruptible slices first (await-readable!), so a cancelled caller's
  thread comes back within `interrupt-slice-ms` rather than after the socket
  timeout."
  [fd]
  (let [buf (ffi/alloc bufsize)]
    (try
      (loop []
        (await-readable! fd)
        (let [got (c-recv fd buf bufsize 0)
              err (when (neg? got) (poller/errno))]
          (cond
            (pos? got) (ffi/read-array buf got)
            (zero? got) nil
            ;; a signal is not the peer going away; the read is simply owed again
            (= err eintr) (recur)
            :else (throw (recv-err-ex err)))))
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
          (let [sent (c-send fd (+ buf off) (- n off) 0)
                err (when (neg? sent) (poller/errno))]
            (cond
              (pos? sent) (recur (+ off sent))
              (= err eintr) (recur off)
              (= err econnreset) (conn-ex "java.net.SocketException" "Connection reset")
              (= err epipe) (conn-ex "java.net.SocketException" "Broken pipe")
              :else (conn-ex "java.io.IOException" (str "send failed (errno " err ")"))))))
      (finally (ffi/free buf)))))

(defn close [fd] (c-close fd) nil)
