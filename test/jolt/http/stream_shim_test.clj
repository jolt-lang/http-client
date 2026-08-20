(ns jolt.http.stream-shim-test
  "Byte-stream behaviour every app that requires this library depends on,
  whether it gets jolt's own streams or our shims. On a jolt that models
  java.io.ByteArrayInputStream/ByteArrayOutputStream with the full surface these
  ARE jolt's — platform.clj deliberately does not register over them, because
  that override is process-wide and lands on every (ByteArrayInputStream. …) an
  app writes, HTTP-related or not. On an older jolt they are the shims, which
  therefore owe the same surface. These assertions must hold either way, and
  expected values are JVM Clojure's."
  (:require [clojure.test :refer [deftest is testing]]
            [jolt.http.platform])
  (:import [java.io ByteArrayInputStream ByteArrayOutputStream]))

(defn- mk [] (ByteArrayInputStream. (.getBytes "hello" "UTF-8")))
(def ^:private all [104 101 108 108 111])

(deftest read-all-bytes
  (is (= all (vec (.readAllBytes (mk)))))
  (testing "reads from the current position, not the start"
    (let [s (mk)] (.read s) (is (= [101 108 108 111] (vec (.readAllBytes s))))))
  (testing "an exhausted stream yields an empty array, not nil or -1"
    (let [s (mk)] (.readAllBytes s) (is (= [] (vec (.readAllBytes s)))))))

(deftest read-n-bytes
  (is (= [104 101 108] (vec (.readNBytes (mk) 3))))
  (testing "asking for more than remains yields what remains"
    (is (= all (vec (.readNBytes (mk) 99)))))
  (testing "a negative count is an IllegalArgumentException"
    (is (thrown? IllegalArgumentException (.readNBytes (mk) -1))))
  (testing "the 3-arg arity fills a buffer and returns the count"
    (let [buf (byte-array 8)
          n (.readNBytes (mk) buf 1 3)]
      (is (= 3 n))
      (is (= [0 104 101 108 0] (vec (take 5 buf)))))))

(deftest transfer-to
  (let [o (ByteArrayOutputStream.)
        n (.transferTo (mk) o)]
    (is (= 5 n))
    (is (= all (vec (.toByteArray o)))))
  (testing "an exhausted stream transfers nothing"
    (let [s (mk) o (ByteArrayOutputStream.)]
      (.readAllBytes s)
      (is (= 0 (.transferTo s o)))
      (is (= [] (vec (.toByteArray o)))))))

(deftest skip-and-available
  (let [s (mk)]
    (is (= 2 (.skip s 2)))
    (is (= 108 (.read s))))
  (testing "skip never runs past the end"
    (is (= 5 (.skip (mk) 99))))
  (is (= 5 (.available (mk)))))

(deftest mark-and-reset
  (is (true? (.markSupported (mk))))
  (let [s (mk)]
    (.read s) (.mark s 0) (.read s) (.reset s)
    (is (= 101 (.read s))))
  (testing "reset with no mark returns to the start"
    (let [s (mk)] (.read s) (.reset s) (is (= 104 (.read s))))))

(deftest read-contract-unchanged
  (testing "no-arg read is an unsigned byte, -1 at EOF"
    (let [s (ByteArrayInputStream. (byte-array [-1]))]
      (is (= 255 (.read s)))
      (is (= -1 (.read s)))))
  (testing "buffer read fills signed bytes"
    (let [s (ByteArrayInputStream. (byte-array [-1 2]))
          buf (byte-array 2)]
      (is (= 2 (.read s buf 0 2)))
      (is (= [-1 2] (vec buf))))))


;; The point of preferring the host's classes: an app that requires this library
;; must not silently get a substitute for a class jolt already models. A shim
;; that answers this whole file's assertions is still not the host's stream —
;; draining one measured ~3300x slower — so assert the identity, not just the
;; behaviour. Keyed off the decision platform.clj actually made: on a jolt whose
;; own streams cannot answer the surface the shim IS the right answer, and this
;; asserts we installed it.
(deftest prefers-the-host-stream
  (let [host-streams? @#'jolt.http.platform/host-byte-streams?]
    (if host-streams?
      (testing "jolt models them, so no ctor override and these are jolt's own"
        (is (= "class java.io.InputStream" (str (type (ByteArrayInputStream. (byte-array 1))))))
        (is (not= "class :object" (str (type (ByteArrayOutputStream.))))))
      (testing "jolt cannot answer the surface, so the shim stands in"
        (is (= "class :object" (str (type (ByteArrayInputStream. (byte-array 1))))))))))
