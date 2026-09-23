(ns jolt.http.net-platform-test
  "jolt.http.net's Windows port (jolt-lang/http-client#28).

  CI has no Windows leg, so what can be held on any host is held here: the
  platform numbers the transport bakes into its bindings, and that Winsock — not
  libc — is what Windows resolves against. A wrong SOL_SOCKET or a POSIX errno
  where Winsock reports a WSA code is silent misbehaviour, not a crash, which is
  exactly the kind of thing a host-independent test has to catch.

  The syscall branches themselves — blocking connect, SO_RCVTIMEO written as a
  DWORD, ioctlsocket(FIONBIO) for non-blocking and WSAPoll where POSIX uses
  fcntl and poll(2), recv/send classed by WSA code — need a Windows host to
  exercise. Neither this suite nor CI runs them; they are held by inspection
  against the runtime's own Winsock layer, not by a test."
  (:require [clojure.test :refer [deftest is testing]]
            [jolt.http.net :as net]))

(deftest windows-is-winsock-not-libc
  (let [c (net/platform-consts false true)]
    (testing "the socket level and options are the BSD/Winsock numbers"
      (is (= 0xffff (:sol-socket c)) "SOL_SOCKET is 0xffff on Winsock, 1 on Linux")
      (is (= 0x1006 (:so-rcvtimeo c)) "SO_RCVTIMEO")
      (is (= 0x1007 (:so-error c)) "SO_ERROR")
      (is (= 0x4004667F (:fionread c)) "the BSD _IOR encoding of FIONREAD"))
    (testing "failures are WSA codes, never ucrt errno"
      (is (= 10004 (:eintr c)) "WSAEINTR")
      (is (= 10035 (:eagain c)) "WSAEWOULDBLOCK")
      (is (= 10054 (:econnreset c)) "WSAECONNRESET")
      (is (= 10053 (:epipe c)) "WSAECONNABORTED"))))

(deftest posix-consts-are-unchanged
  (testing "macOS keeps its BSD numbers"
    (let [c (net/platform-consts true false)]
      (is (= 0xffff (:sol-socket c)))
      (is (= 0x1006 (:so-rcvtimeo c)))
      (is (= 0x1007 (:so-error c)))
      (is (= 4 (:eintr c)))
      (is (= 35 (:eagain c)))
      (is (= 54 (:econnreset c)))
      (is (= 32 (:epipe c)))))
  (testing "Linux keeps its numbers"
    (let [c (net/platform-consts false false)]
      (is (= 1 (:sol-socket c)))
      (is (= 20 (:so-rcvtimeo c)))
      (is (= 4 (:so-error c)))
      (is (= 4 (:eintr c)))
      (is (= 11 (:eagain c)))
      (is (= 104 (:econnreset c)))
      (is (= 32 (:epipe c))))))

(deftest winsock-is-bsd-shaped
  (is (= (:sol-socket (net/platform-consts true false))
         (:sol-socket (net/platform-consts false true)))
      "Windows sides with BSD on the socket level, as the runtime's own layer does"))
