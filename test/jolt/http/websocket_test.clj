(ns jolt.http.websocket-test
  "babashka.http-client.websocket over jolt.http.websocket's java.net.http
  WebSocket shim, against an in-process RFC 6455 echo server. Mirrors babashka's
  own websocket suite: open, send text and binary, ping/pong, subprotocols,
  headers, close and abort."
  (:require [jolt.http.platform]
            [babashka.http-client.websocket :as ws]
            [jolt.http.test-server :as srv]
            [jolt.http.websocket :as impl]
            [clojure.test :refer [deftest is testing run-tests use-fixtures]]))

(def ^:private port 18097)
(def ^:private base (str "ws://localhost:" port))

(defn- with-server [t]
  (let [s (srv/start-websocket port)]
    (try (t) (finally (srv/stop s)))))

(use-fixtures :once with-server)

(defn- collector
  "A promise-backed sink: `msgs` accumulates [kind value last?] and `done` is
  delivered once `n` messages have arrived."
  [n]
  (let [msgs (atom [])
        done (promise)]
    {:msgs msgs
     :done done
     :on-message (fn [_ws data last?]
                   (let [v (if (string? data)
                             [:text (str data) last?]
                             [:binary (let [d (byte-array (.remaining data))]
                                        (.get data d)
                                        (String. d "UTF-8"))
                              last?])]
                     (swap! msgs conj v)
                     (when (>= (count @msgs) n) (deliver done true))))}))

(defn- await!
  "Wait for a callback. The deadline is generous because the FIRST run under a
  given jolt compiles every dependency namespace first, and a warm-run deadline
  elapses before the work starts."
  [p]
  (is (= true (deref p 20000 :timeout)) "callback did not fire in time"))

;; --- the frame codec, both directions --------------------------------------

(deftest frame-round-trip
  (doseq [[label payload] [["short" (.getBytes "hi" "UTF-8")]
                           ;; 126..65535 uses the 16-bit length field
                           ["medium" (.getBytes (apply str (repeat 300 "x")) "UTF-8")]
                           ;; >= 65536 uses the 64-bit one
                           ["long" (.getBytes (apply str (repeat 70000 "y")) "UTF-8")]
                           ["empty" (byte-array 0)]
                           ["high bytes" (byte-array (map #(byte (- (mod % 256) 128)) (range 300)))]]]
    (doseq [mask? [true false]]
      (let [encoded (impl/encode-frame impl/op-binary payload {:mask? mask?})
            [frame rest-bytes] (impl/decode-frame encoded)]
        (is (= impl/op-binary (:opcode frame)) label)
        (is (:fin? frame) label)
        (is (zero? (alength rest-bytes)) label)
        (is (= (seq payload) (seq (:payload frame))) (str label " masked=" mask?))))))

(deftest decode-needs-a-whole-frame
  (let [encoded (impl/encode-frame impl/op-text (.getBytes "hello" "UTF-8") {})]
    (is (nil? (impl/decode-frame (byte-array (take 3 (seq encoded))))))
    (is (some? (impl/decode-frame encoded))))
  (testing "trailing bytes come back for the next frame"
    (let [a (impl/encode-frame impl/op-text (.getBytes "a" "UTF-8") {})
          b (impl/encode-frame impl/op-text (.getBytes "b" "UTF-8") {})
          [f1 r1] (impl/decode-frame (byte-array (concat (seq a) (seq b))))
          [f2 r2] (impl/decode-frame r1)]
      (is (= "a" (String. ^bytes (:payload f1) "UTF-8")))
      (is (= "b" (String. ^bytes (:payload f2) "UTF-8")))
      (is (zero? (alength r2))))))

(deftest accept-key-matches-rfc-6455
  ;; the worked example from RFC 6455 section 1.3
  (is (= "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" (impl/accept-key "dGhlIHNhbXBsZSBub25jZQ=="))))

;; --- the client ------------------------------------------------------------

(deftest connects-and-echoes-text
  (let [{:keys [msgs done on-message]} (collector 1)
        opened (promise)
        sock (ws/websocket {:uri base
                            :on-open (fn [_] (deliver opened true))
                            :on-message on-message})]
    (await! opened)
    (ws/send! sock "hello")
    (await! done)
    (is (= [[:text "hello" true]] @msgs))
    (ws/close! sock)))

(deftest echoes-binary
  (let [{:keys [msgs done on-message]} (collector 1)
        sock (ws/websocket {:uri base :on-message on-message})]
    (ws/send! sock (.getBytes "bytes here" "UTF-8"))
    (await! done)
    (is (= [[:binary "bytes here" true]] @msgs))
    (ws/close! sock)))

(deftest several-messages-in-order
  (let [{:keys [msgs done on-message]} (collector 3)
        sock (ws/websocket {:uri base :on-message on-message})]
    (doseq [m ["one" "two" "three"]] (ws/send! sock m))
    (await! done)
    (is (= ["one" "two" "three"] (mapv second @msgs)))
    (ws/close! sock)))

(deftest large-message
  (let [payload (apply str (repeat 100000 "z"))
        {:keys [msgs done on-message]} (collector 1)
        sock (ws/websocket {:uri base :on-message on-message})]
    (ws/send! sock payload)
    (await! done)
    (is (= payload (second (first @msgs))))
    (ws/close! sock)))

(deftest fragmented-message
  (let [{:keys [msgs done on-message]} (collector 2)
        sock (ws/websocket {:uri base :on-message on-message})]
    (ws/send! sock "part-" {:last false})
    (ws/send! sock "two")
    (await! done)
    (is (= ["part-" "two"] (mapv second @msgs)))
    (is (= [false true] (mapv #(nth % 2) @msgs)))
    (ws/close! sock)))

(deftest ping-gets-a-pong
  (let [pong (promise)
        sock (ws/websocket {:uri base :on-pong (fn [_ _] (deliver pong true))})]
    (ws/ping! sock (.getBytes "ping" "UTF-8"))
    (await! pong)
    (ws/close! sock)))

(deftest server-initiated-message
  (let [{:keys [done msgs on-message]} (collector 1)]
    (ws/websocket {:uri (str base "/greet") :on-message on-message})
    (await! done)
    (is (= "hello from server" (second (first @msgs))))))

(deftest close-notifies-and-shuts-output
  (let [closed (promise)
        sock (ws/websocket {:uri base :on-close (fn [_ status _] (deliver closed status))})]
    (ws/close! sock)
    (is (= 1000 (deref closed 20000 :timeout)))
    (is (.isOutputClosed sock))))

(deftest abort-closes-immediately
  (let [sock (ws/websocket {:uri base})]
    (ws/abort! sock)
    (is (.isOutputClosed sock))
    (is (.isInputClosed sock))
    (is (thrown? Exception (ws/send! sock "after abort")))))

(deftest subprotocol-is-negotiated
  (let [sock (ws/websocket {:uri base :subprotocols ["chat" "superchat"]})]
    (is (= "chat" (.getSubprotocol sock)))
    (ws/close! sock)))

(deftest handshake-headers-are-sent
  ;; the echo server rejects /reject, which is how a failed upgrade surfaces
  (is (thrown? Exception (ws/websocket {:uri (str base "/reject")})))
  (testing "custom headers do not break the handshake"
    (let [sock (ws/websocket {:uri base :headers {"x-test" "1"}})]
      (is (some? sock))
      (ws/close! sock))))

(deftest async-build
  (let [f (ws/websocket {:uri base :async true})]
    (is (instance? java.util.concurrent.CompletableFuture f))
    (let [sock @f]
      (is (instance? java.net.http.WebSocket sock))
      (ws/close! sock))))

(defn -main [& _]
  (let [r (run-tests 'jolt.http.websocket-test)]
    (println (str "\n========== websocket =========="))
    (println (str "tests=" (:test r) " pass=" (:pass r) " fail=" (:fail r) " error=" (:error r)))
    (when (or (pos? (:fail r)) (pos? (:error r)))
      (throw (ex-info "websocket failures" (select-keys r [:fail :error]))))))
