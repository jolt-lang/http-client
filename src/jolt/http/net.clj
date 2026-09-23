(ns jolt.http.net
  "A blocking BSD-socket TCP client over jolt.ffi: name resolution via
  getaddrinfo, then socket/connect/recv/send/close. Shared by jolt.http.platform
  (plaintext HTTP) and jolt.http.tls (the ciphertext transport under OpenSSL).

  On POSIX these are the process's own libc symbols, declared in deps.edn
  (:jolt/native :process). On Windows there is no libc socket: the symbols live
  in ws2_32, and a call before WSAStartup fails — getaddrinfo answers
  WSANOTINITIALISED, which surfaces as UnknownHostException — so connect/2 runs
  ensure-winsock! before the first one (jolt-lang/http-client#28).
  accept/recv/send/connect/getaddrinfo are marked :blocking so a parked socket
  call never pins jolt's stop-the-world collector."
  (:require [jolt.ffi :as ffi]
            [clojure.string :as str]))

(def ^:private os-name
  (str/lower-case (or (System/getProperty "os.name") "")))
(def ^:private macos?   (str/includes? os-name "mac"))
(def ^:private windows? (str/includes? os-name "win"))

;; Winsock 2.2 as MAKEWORD(2,2); every Windows since 98 has it.
(def ^:private WINSOCK-2-2 0x0202)
(ffi/defcfn c-wsa-startup "WSAStartup" [:int :pointer] :int)

;; Windows only, and the only failure it can throw is WSAStartup's own.
;;
;; A socket call before WSAStartup does not report the missing initialization —
;; socket() answers INVALID_SOCKET and getaddrinfo answers "unknown host", which
;; reads as an unreachable machine rather than an uninitialized library. That is
;; the UnknownHostException this library shipped on Windows (http-client#28).
;; ws2_32 must also be loaded BY NAME: its symbols are not in jolt.exe's export
;; table even though -lws2_32 is linked, so the process handle alone resolves
;; neither socket() nor getaddrinfo.
;;
;; The runtime ships jolt.winsock for exactly this, but it arrived in 0.8.11 and
;; this library's declared floor is 0.8.9 — a top-level require of it would fail
;; to load on the older runtime on every platform — so the initialization is
;; done here instead of taken from the runtime. Load and call both sit inside the
;; windows? branch, so on POSIX the ws2_32 symbol never has to resolve.
(def ^:private winsock-ready
  (delay
    (when windows?
      (ffi/load-library ["ws2_32.dll" "ws2_32"])
      (let [wsadata (ffi/alloc 512)]          ; WSADATA is ~400 bytes on x64
        (try
          (let [r (c-wsa-startup WINSOCK-2-2 wsadata)]
            (when-not (zero? r)
              (throw (java.io.IOException. (str "WSAStartup failed: " r)))))
          (finally (ffi/free wsadata)))))
    true))

(defn- ensure-winsock! [] @winsock-ready)

(ffi/defcfn c-socket      "socket"      [:int :int :int] :int)
(ffi/defcfn c-connect     "connect"     [:int :pointer :int] :int {:blocking true})
(ffi/defcfn c-setsockopt  "setsockopt"  [:int :int :int :pointer :int] :int)
(ffi/defcfn c-getsockopt  "getsockopt"  [:int :int :int :pointer :pointer] :int)
(ffi/defcfn c-getaddrinfo "getaddrinfo" [:pointer :pointer :pointer :pointer] :int :blocking)
(ffi/defcfn c-freeaddrinfo "freeaddrinfo" [:pointer] :void)

;; Everything below differs by name or by signature between the two libs, so it
;; lives in the taken branch — jolt interns the vars from both at analysis time
;; and the references further down resolve either way. Winsock has no fcntl and
;; no poll; recv/send take an int length and return int, not ssize_t; a socket is
;; closed with closesocket; and the fd flag is ioctlsocket, fixed-arity rather
;; than variadic. Failures carry a WSA code (set by :capture-native-error, which
;; reads GetLastError on Windows and errno elsewhere).
(if windows?
  (do
    (ffi/defcfn c-recv  "recv"        [:int :pointer :int :int] :int
      {:blocking true :capture-native-error true})
    (ffi/defcfn c-send  "send"        [:int :pointer :int :int] :int
      {:blocking true :capture-native-error true})
    (ffi/defcfn c-close "closesocket" [:int] :int)
    (ffi/defcfn c-ioctl "ioctlsocket" [:int :int :pointer] :int)
    (ffi/defcfn c-wsapoll "WSAPoll" [:pointer :ulong :int] :int
      {:blocking true :capture-native-error true}))
  (do
    ;; fcntl is variadic (int fd, int cmd, ...). A fixed-arity binding silently
    ;; corrupts the flags argument on Apple arm64, where variadic args travel on
    ;; the stack — the :varargs marker sits at the fixed/variadic boundary (two
    ;; fixed args, then the variadic flags int) and emits the (__varargs_after 2)
    ;; convention, so F_SETFL's third argument actually lands. The 2-arg
    ;; c-fcntl-get binding is safe fixed-arity: F_GETFL passes no variadic args
    ;; and named args ride the same registers in both conventions.
    (ffi/defcfn c-recv  "recv"  [:int :pointer :size_t :int] :ssize_t
      {:blocking true :capture-native-error true})
    (ffi/defcfn c-send  "send"  [:int :pointer :size_t :int] :ssize_t
      {:blocking true :capture-native-error true})
    (ffi/defcfn c-close "close" [:int] :int)
    (ffi/defcfn c-fcntl-get "fcntl" [:int :int] :int)
    (ffi/defcfn c-fcntl-set "fcntl" [:int :int :varargs :int] :int)
    (ffi/defcfn c-poll      "poll"  [:pointer :int :int] :int
      {:blocking true :capture-native-error true})))

;; struct addrinfo field offsets (LP64). ai_addrlen=16, ai_next=40, and the
;; ai_family/socktype/protocol words lead both layouts — but ai_addr's offset
;; is a libc fact, not a platform constant. glibc orders ai_addr BEFORE
;; ai_canonname (24); the BSD-derived libcs — macOS AND Android's bionic — put
;; ai_canonname first (32). Android reports os.name "Linux", so os.name cannot
;; choose between them.
;;
;; Probe the result instead: AI_CANONNAME is not requested below, so under the
;; BSD layout the word at 24 is NULL, while under glibc it IS ai_addr — and a
;; sockaddr's leading 16-bit sa_family is by definition the same number the
;; node already reports in ai_family. Comparing those two is what separates the
;; layouts, and unlike a fixed AF_INET/AF_INET6 test it keeps holding whatever
;; families the hints below go on to ask for. Reading ai_addr at the wrong
;; offset hands connect(2) a null or bogus sockaddr: every address fails with
;; EFAULT (errno 14), which then reads as "connection refused" for the name.
;; The layout cannot change while the process runs, so one probe is cached.
(def ^:private O-ai-family 4)
(def ^:private O-ai-socktype 8)
(def ^:private O-ai-protocol 12)
(def ^:private O-ai-addrlen 16)
(def ^:private O-ai-addr-glibc 24)
(def ^:private O-ai-addr-bsd 32)
(def ^:private O-ai-next 40)
(def ^:private ai-addr-offset-cache (atom nil))

(defn- ai-addr-offset
  "ai_addr's offset in the struct addrinfo AI points at: 24 under glibc's
   layout, 32 under the BSD one (macOS, Android/bionic)."
  [ai]
  (or @ai-addr-offset-cache
      (reset! ai-addr-offset-cache
              (let [p (ffi/read ai :pointer O-ai-addr-glibc)]
                (if (and (not (ffi/null? p))
                         (= (ffi/read p :uint16 0)
                            (ffi/read ai :int O-ai-family)))
                  O-ai-addr-glibc
                  O-ai-addr-bsd)))))

;; The numbers that differ by platform. Windows is Winsock, which grew out of BSD
;; and kept its numbering where it could: SOL_SOCKET stays 0xffff,
;; SO_RCVTIMEO/SO_ERROR keep their values. Where it could not, it is neither BSD
;; nor POSIX — there is no fcntl and no poll(2), WSAPoll numbers its event bits
;; its own way, and socket failures are reported as WSA codes, not errno. Answering any
;; of these with the POSIX value is silent misbehaviour, not a crash: a wrong
;; errno classifies a reset connection as a read timeout. So the map is data,
;; public and pinned by test/jolt/http/net_platform_test.clj the way the runtime
;; pins its own socket constants.
(defn platform-consts
  "The platform numbers jolt.http.net bakes into its bindings, for the three
   hosts jolt selects."
  [macos? windows?]
  (if windows?
    {:sol-socket  0xffff
     :so-rcvtimeo 0x1006
     :so-error    0x1007
     :pollin      0x0100       ; POLLRDNORM — WSAPoll's 0x1 is POLLERR
     :pollout     0x0010       ; POLLWRNORM — WSAPoll's 0x4 is POLLNVAL
     :eintr       10004        ; WSAEINTR
     :eagain      10035        ; WSAEWOULDBLOCK
     :econnreset  10054        ; WSAECONNRESET
     :epipe       10053}       ; WSAECONNABORTED: Winsock's counterpart to EPIPE
    {:sol-socket  (if macos? 0xffff 1)
     :so-rcvtimeo (if macos? 0x1006 20)
     :so-error    (if macos? 0x1007 4)
     :pollin      1
     :pollout     4
     :eintr       4
     :eagain      (if macos? 35 11)
     :econnreset  (if macos? 54 104)
     :epipe       32}))

(def ^:private platform   (platform-consts macos? windows?))
(def ^:private sol-socket (:sol-socket platform))
(def ^:private so-rcvtimeo (:so-rcvtimeo platform))
(def ^:private so-error    (:so-error platform))
(def ^:private po-pollin   (:pollin platform))
(def ^:private po-pollout  (:pollout platform))
(def ^:private eintr       (:eintr platform))
(def ^:private eagain      (:eagain platform))
(def ^:private econnreset  (:econnreset platform))
(def ^:private epipe       (:epipe platform))

;; fcntl F_GETFL/F_SETFL and O_NONBLOCK are POSIX-only — Windows flips blocking
;; with ioctlsocket(FIONBIO).
(def ^:private f-getfl 3)
(def ^:private f-setfl 4)
(def ^:private o-nonblock (if macos? 0x4 0x800))
(def ^:private fionbio 0x8004667E)

;; Winsock has no poll(2): WSAPoll is its readiness call, over WSAPOLLFD — which
;; is NOT BSD's struct pollfd. SOCKET is a 64-bit pointer on x64, so the handle
;; occupies offset 0..7 and events/revents sit at 8 and 10, the struct padded to
;; 16. Writing the POSIX offsets would ask WSAPoll about a socket whose handle it
;; reads from the wrong bytes. Returns [revents 0] on readiness, [0 code] on
;; timeout, [-1 code] on failure (WSAPoll's SOCKET_ERROR), the same [result code]
;; shape poll-fd hands back on either branch.
(defn- wsa-poll [fd events timeout-ms]
  (let [pf (ffi/alloc 16)]
    (try
      (dotimes [i 16] (ffi/write pf :uint8 0 i))
      (ffi/write pf :int fd 0)
      (ffi/write pf :uint16 events 8)
      (let [[r err] (c-wsapoll pf 1 timeout-ms)]
        [(if (pos? r) (ffi/read pf :uint16 10) r) err])
      (finally (ffi/free pf)))))

(defn- poll-fd
  "Wait until `fd` is ready for `events` (POLLIN/POLLOUT), at most `timeout-ms`
   (negative waits forever). Returns [revents error-code], revents being the ready
   bits (or 0 on timeout, or -1 on failure) and the code the native call reported —
   errno on POSIX, the WSA code on Windows, since both bindings capture it. POSIX
   poll(2) on one branch, WSAPoll on the other. The code is only meaningful when
   revents is negative; a timeout leaves it alone."
  [fd events timeout-ms]
  (if windows?
    (wsa-poll fd events (int timeout-ms))
    (let [pf (ffi/alloc 8)]
      (try
        ;; struct pollfd { int fd; short events; short revents; } — 8 bytes LP64.
        ;; events is the 16-bit field at offset 4 and revents the one at 6, left
        ;; zeroed for poll() to fill in. Writing events as a 16-bit value rather
        ;; than packing both halves into one :int keeps this right on a
        ;; big-endian host too.
        (dotimes [i 8] (ffi/write pf :uint8 0 i))
        (ffi/write pf :int fd 0)
        (ffi/write pf :uint16 events 4)
        (let [[r err] (c-poll pf 1 (int timeout-ms))]
          [(if (pos? r) (ffi/read pf :uint16 6) r) err])
        (finally (ffi/free pf))))))

(defn- conn-ex [class msg]
  ;; a typed throwable so callers get the right (class e)/instance? AND a working
  ;; .getMessage/ex-message (the cognitect aws backend reads .getMessage).
  (throw (jolt.host/throwable class (str msg))))

;; A timed connect needs the socket non-blocking: connect() then returns -1
;; immediately (EINPROGRESS) and a readiness wait says when to look, with
;; SO_ERROR telling us whether it actually succeeded. POSIX flips O_NONBLOCK with
;; fcntl F_SETFL (variadic, hence the binding above); Windows has no fcntl and
;; sets the same state with ioctlsocket(FIONBIO), whose argument is a plain
;; nonzero/zero int rather than a bit read-modify-write.
(defn- set-nonblock! [fd nonblocking?]
  (if windows?
    (let [buf (ffi/alloc 4)]
      (try
        (ffi/write buf :int (if nonblocking? 1 0) 0)
        (when (neg? (c-ioctl fd fionbio buf))
          (conn-ex "java.io.IOException" "ioctlsocket FIONBIO failed"))
        (finally (ffi/free buf))))
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
      nil)))

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
;; -1 (EINPROGRESS) instead of blocking; a readiness wait then says when to look
;; and SO_ERROR reports the outcome.
(defn- timed-connect [fd addr addrlen timeout-ms]
  (if (zero? (c-connect fd addr addrlen))
    0
    (let [[revents _] (poll-fd fd po-pollout timeout-ms)]
      (cond
        ;; writable — the connect either completed or failed; SO_ERROR tells.
        (pos? revents) (socket-error fd)
        (zero? revents) :timeout
        :else (conn-ex "java.io.IOException" "poll failed")))))

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
   (ensure-winsock!)
   (let [;; getaddrinfo wants the bare address; a URL carries an IPv6 literal
         ;; bracketed ("[::1]") and java.net.URL/URI both report getHost() that
         ;; way, so the brackets are stripped here rather than in the parser.
         host    (let [h (str host)]
                   (if (and (str/starts-with? h "[") (str/ends-with? h "]"))
                     (subs h 1 (dec (count h)))
                     h))
         node    (ffi/string->ptr (str host))
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
                       addr    (ffi/read ai :pointer (ai-addr-offset ai))
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
  "Apply SO_RCVTIMEO of `ms` milliseconds to `fd` (a recv past it returns -1).
  nil or a non-positive `ms` CLEARS the timeout rather than leaving whatever was
  there: a pooled connection outlives the request that opened it, and silently
  carrying that request's timeout into the next one gave the caller a bound it
  never asked for."
  [fd ms]
  (let [ms (if (and ms (pos? ms)) ms 0)]
    (if windows?
      ;; Winsock's SO_RCVTIMEO is a DWORD of milliseconds, not a struct timeval:
      ;; the four bytes are the timeout itself, so reading the POSIX layout there
      ;; would set a timeout of garbage nanoseconds.
      (let [tv (ffi/alloc 4)]
        (try
          (ffi/write tv :uint ms 0)
          (c-setsockopt fd sol-socket so-rcvtimeo tv 4)
          (finally (ffi/free tv)))
        nil)
      ;; struct timeval { time_t tv_sec; suseconds_t tv_usec; } — 16 bytes LP64.
      (let [tv (ffi/alloc 16)]
        (dotimes [i 16] (ffi/write tv :uint8 0 i))
        (ffi/write tv :long (quot ms 1000) 0)
        (ffi/write tv :long (* (rem ms 1000) 1000) 8)
        (c-setsockopt fd sol-socket so-rcvtimeo tv 16)
        (ffi/free tv)
        nil))))

(def ^:private bufsize 65536)

;; eintr/eagain/econnreset/epipe come from `platform` above — errno on POSIX,
;; WSA codes on Windows — and recv-err-ex classes a failure with whichever the
;; bound library reported.

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
  (if windows?
    (let [tv (ffi/alloc 4) len (ffi/alloc 4)]
      (try
        (ffi/write tv :uint 0 0)
        (ffi/write len :uint 4 0)
        (if (neg? (c-getsockopt fd sol-socket so-rcvtimeo tv len))
          0
          (ffi/read tv :uint 0))
        (finally (ffi/free tv) (ffi/free len))))
    (let [tv (ffi/alloc 16) len (ffi/alloc 4)]
      (try
        (dotimes [i 16] (ffi/write tv :uint8 0 i))
        (ffi/write len :uint 16 0)
        (if (neg? (c-getsockopt fd sol-socket so-rcvtimeo tv len))
          0
          (+ (* 1000 (ffi/read tv :long 0)) (quot (ffi/read tv :long 8) 1000)))
        (finally (ffi/free tv) (ffi/free len))))))

(defn- await-readable!
  "Park until `fd` has something to read (or has hung up — recv decides which),
  in `interrupt-slice-ms` slices. Throws InterruptedException if the thread was
  interrupted between slices, SocketTimeoutException once the socket's own read
  timeout has elapsed with nothing to read."
  [fd]
  (let [timeout  (read-timeout-ms fd)
        deadline (when (pos? timeout) (+ (System/currentTimeMillis) timeout))]
    (loop []
      (when (Thread/interrupted)
        (conn-ex "java.lang.InterruptedException" "read interrupted"))
      (let [now           (System/currentTimeMillis)
            slice         (if deadline
                            (min interrupt-slice-ms (max 0 (- deadline now)))
                            interrupt-slice-ms)
            [revents err] (poll-fd fd po-pollin slice)]
        (cond
          (pos? revents) nil
          (and deadline (>= (System/currentTimeMillis) deadline))
          (conn-ex "java.net.SocketTimeoutException" "Read timed out")
          (zero? revents) (recur)
          ;; A signal cut the wait short rather than the timeout elapsing; the
          ;; read is simply owed again. The code comes from poll's own capture —
          ;; errno on POSIX, the WSA code on Windows — so it matches this
          ;; platform's eintr without a second, racy errno read.
          (= err eintr) (recur)
          :else (conn-ex "java.io.IOException" (str "poll failed (code " err ")")))))))

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
        ;; :capture-native-error returns [result code]: the code is errno on
        ;; POSIX and the WSA error on Windows, so recv-err-ex's classes hold on
        ;; both without the read having to consult a separate errno.
        (let [[got err] (c-recv fd buf bufsize 0)]
          (cond
            (pos? got) (ffi/read-array buf got)
            (zero? got) nil
            ;; a signal is not the peer going away; the read is simply owed again
            (= err eintr) (recur)
            :else (throw (recv-err-ex err)))))
      (finally (ffi/free buf)))))

(defn idle-dead?
  "True when an idle socket must not be reused: the peer has hung up, or has
  sent something we never asked for. A pooled connection is idle by definition,
  so anything readable on it is one or the other.

  poll with a zero timeout, so this costs one syscall. It races — the peer can
  close between the check and the write — which is why a pooled connection that
  yields no response bytes at all is also retried on a fresh one."
  [fd]
  (try
    (not (zero? (first (poll-fd fd po-pollin 0))))
    (catch Throwable _ true)))

(defn send-bytes
  "Send all of byte-array `data` over `fd`."
  [fd data]
  (let [n (alength data)
        buf (ffi/alloc (max 1 n))]
    (try
      (ffi/write-array buf data)
      (loop [off 0]
        (when (< off n)
          (let [[sent err] (c-send fd (+ buf off) (- n off) 0)]
            (cond
              (pos? sent) (recur (+ off sent))
              (= err eintr) (recur off)
              (= err econnreset) (conn-ex "java.net.SocketException" "Connection reset")
              (= err epipe) (conn-ex "java.net.SocketException" "Broken pipe")
              :else (conn-ex "java.io.IOException" (str "send failed (errno " err ")"))))))
      (finally (ffi/free buf)))))

(defn close [fd] (c-close fd) nil)
