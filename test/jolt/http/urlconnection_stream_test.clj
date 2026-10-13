(ns jolt.http.urlconnection-stream-test
  "`:as :stream` through clj-http-lite, i.e. over the HttpURLConnection shim in
  jolt.http.platform. The java.net.http path has streamed its body off the wire
  since b221fbf; this one read the whole body before getResponseCode returned,
  so an SSE feed or an LLM token stream arrived in one piece at the end.

  The routes write their headers at once and the body a tick at a time, so a
  client that buffers is visible as a call that takes the whole run."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [clojure.java.io :as io]
            [clj-http.lite.util :as util]
            [jolt.http-client :as http]
            [jolt.http.core :as core]
            [jolt.http.test-server :as srv]))

(def ^:private port 18110)
(def ^:private base (str "http://localhost:" port))

(def ^:private tick-count 6)
(def ^:private tick-ms 150)
(def ^:private ticks-ms (* tick-count tick-ms))
(def ^:private ticks (mapv (fn [i] (str "tick " i "\n")) (range tick-count)))
(def ^:private ticks-body (apply str ticks))
;; how long a route holds the socket open after a framed body has ended
(def ^:private hold-ms 1500)

;; Whether this jolt can carry a live body (a reify java.io.InputStream, jolt
;; 0.8.8+). Below that the transport keeps the buffered path, and the timing
;; assertions here do not apply.
(def ^:private live? core/reify-input-streams?)

(defn- send! [conn s] (srv/conn-write conn (core/latin1->ba s)))

(defn- head! [conn status & headers]
  (send! conn (apply str "HTTP/1.1 " status " X\r\n"
                     (concat (map (fn [h] (str h "\r\n")) headers) ["\r\n"]))))

(defn- chunked-ticks! [conn]
  (doseq [t ticks]
    (send! conn (str (Integer/toHexString (count t)) "\r\n" t "\r\n"))
    (Thread/sleep tick-ms))
  (send! conn "0\r\n\r\n"))

(defn- handler [{:keys [uri conn]}]
  (case uri
    "/chunked"
    (do (head! conn 200 "Content-Type: text/event-stream" "Transfer-Encoding: chunked"
               "Connection: close")
        (chunked-ticks! conn)
        (Thread/sleep hold-ms)
        (srv/conn-close conn)
        :hijacked)

    "/sized"
    (do (head! conn 200 (str "Content-Length: " (count ticks-body)) "Connection: close")
        (doseq [t ticks] (send! conn t) (Thread/sleep tick-ms))
        (Thread/sleep hold-ms)
        (srv/conn-close conn)
        :hijacked)

    "/to-close"
    (do (head! conn 200 "Content-Type: text/plain")
        (doseq [t ticks] (send! conn t) (Thread/sleep tick-ms))
        (srv/conn-close conn)
        :hijacked)

    "/short"
    (do (head! conn 200 "Content-Length: 100" "Connection: close")
        (send! conn "hello")
        (Thread/sleep 50)
        (srv/conn-close conn)
        :hijacked)

    "/stall"
    (do (head! conn 200 "Transfer-Encoding: chunked" "Connection: close")
        (send! conn "7\r\ntick 0\n\r\n")
        (Thread/sleep 2000)
        (send! conn "0\r\n\r\n")
        (srv/conn-close conn)
        :hijacked)

    "/error-ticks"
    (do (head! conn 500 "Transfer-Encoding: chunked" "Connection: close")
        (chunked-ticks! conn)
        (srv/conn-close conn)
        :hijacked)

    "/gzip"
    {:status 200
     :headers {"Content-Encoding" "gzip"}
     :body (util/gzip (.getBytes ^String ticks-body "UTF-8"))}

    {:status 404 :body "nope"}))

;; One server for the whole namespace. stop closes the listener, but on Linux a
;; thread parked in accept() on it keeps the socket listening, so a second
;; server on the same port fails to bind (seen on CI). Each test runs its body
;; as a thunk against the one server.
(use-fixtures :once
  (fn [t]
    (let [s (srv/start-plain port {:handler handler})]
      (Thread/sleep 100)
      (try (t) (finally (srv/stop s))))))

(defn- with-server [f] (f))

(defn- elapsed [t0] (- (System/currentTimeMillis) t0))

(deftest stream-returns-at-the-headers
  (with-server
    (fn []
      (doseq [path ["/chunked" "/sized" "/to-close"]]
        (testing (str path ": the call returns before the body has arrived")
          (let [t0 (System/currentTimeMillis)
                r (http/get (str base path) {:as :stream})
                headers-at (elapsed t0)]
            (is (= 200 (:status r)))
            (when live?
              (is (< headers-at (quot ticks-ms 2))
                  (str "returned after " headers-at "ms; the body runs for " ticks-ms "ms")))
            (is (= ticks-body (slurp (:body r))))
            (when (not= path "/to-close")
              (is (< (elapsed t0) (+ ticks-ms (quot hold-ms 2)))
                  "the stream ends where the body ends, not at the peer's close"))))))))

(deftest stream-reads-return-as-bytes-arrive
  (with-server
    (fn []
      (doseq [path ["/chunked" "/sized" "/to-close"]]
        (testing (str path ": each line comes off the wire as it is sent")
          (let [r (http/get (str base path) {:as :stream})
                rdr (java.io.BufferedReader. (io/reader (:body r)))
                t0 (System/currentTimeMillis)
                first-line (.readLine rdr)
                first-at (elapsed t0)
                _ (dotimes [_ (- tick-count 2)] (.readLine rdr))
                last-line (.readLine rdr)
                last-at (elapsed t0)]
            (is (= "tick 0" first-line))
            (is (= (str "tick " (dec tick-count)) last-line))
            (when live?
              (is (< first-at (- last-at (* 2 tick-ms)))
                  (str "first line at " first-at "ms, last at " last-at "ms")))
            (.close rdr)))))))

(deftest a-body-that-ends-early-is-an-error
  (with-server
    (fn []
      (testing "Content-Length promised 100 bytes and the peer closed after 5"
        (let [r (http/get (str base "/short") {:as :stream})]
          (is (= 200 (:status r)))
          (is (thrown? java.io.IOException (slurp (:body r))))))
      (testing "the buffered coercions see the same failure"
        (is (thrown? java.io.IOException (http/get (str base "/short"))))))))

(deftest buffered-coercions-still-read-the-whole-body
  (with-server
    (fn []
      (doseq [path ["/chunked" "/sized" "/to-close"]]
        (testing path
          (is (= ticks-body (:body (http/get (str base path)))))
          (is (= ticks-body (String. ^bytes (:body (http/get (str base path) {:as :byte-array}))
                                     "UTF-8")))))
      (testing "gzip is decoded after the body is read"
        (is (= ticks-body (:body (http/get (str base "/gzip")))))))))

(deftest an-error-status-streams-too
  (with-server
    (fn []
      (testing "getErrorStream hands back the live body"
        (let [t0 (System/currentTimeMillis)
              r (http/get (str base "/error-ticks") {:as :stream :throw-exceptions false})
              headers-at (elapsed t0)]
          (is (= 500 (:status r)))
          (when live?
            (is (< headers-at (quot ticks-ms 2)) (str "returned after " headers-at "ms")))
          (is (= ticks-body (slurp (:body r))))))
      (testing "and the buffered one reads it whole"
        (let [r (http/get (str base "/error-ticks") {:throw-exceptions false})]
          (is (= 500 (:status r)))
          (is (= ticks-body (:body r))))))))

(deftest socket-timeout-bounds-the-gap-between-reads
  (with-server
    (fn []
      (let [t0 (System/currentTimeMillis)
            r (http/get (str base "/stall") {:as :stream :socket-timeout 400})
            body (:body r)
            buf (byte-array 64)]
        (is (= 200 (:status r)))
        (is (= "tick 0\n" (String. buf 0 (.read body buf 0 64) "UTF-8")))
        (is (thrown? java.net.SocketTimeoutException (.read body buf 0 64)))
        (is (< (elapsed t0) 1800) "the stalled read gave up at the socket timeout")))))

(deftest closing-a-stream-early
  (with-server
    (fn []
      (let [r (http/get (str base "/chunked") {:as :stream})
            body (:body r)
            buf (byte-array 32)]
        (is (pos? (.read body buf 0 32)))
        (.close body)
        (is (= -1 (try (.read body buf 0 32) (catch java.io.IOException _ -1)))
            "nothing more is read from a closed body")))))
