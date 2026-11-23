(ns jolt.http.sse-test
  "jolt.http.sse: the event-stream parser against the WHATWG rules, and
  subscribe! against a live server that writes events a tick at a time."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [jolt.http.core :as core]
            [jolt.http.sse :as sse]
            [jolt.http.test-server :as srv]))

;; --- the parser -----------------------------------------------------------------

(deftest events-end-at-a-blank-line
  (is (= [{:event "message" :data "hello" :id nil}]
         (sse/parse-lines ["data: hello" ""]))))

(deftest data-lines-join-with-newlines-and-types-and-ids-carry
  (is (= [{:event "datastar-patch-elements" :data "a\nb" :id "7"}
          {:event "message" :data "c" :id "7"}]
         (sse/parse-lines ["event: datastar-patch-elements" "id: 7" "data: a" "data: b" ""
                           "data: c" ""]))))

(deftest the-spec-s-edge-cases
  (testing "one leading space is dropped, no more"
    (is (= "  x" (:data (first (sse/parse-lines ["data:   x" ""]))))))
  (testing "a field with no colon has an empty value"
    (is (= "" (:data (first (sse/parse-lines ["data" ""]))))))
  (testing "comments are skipped"
    (is (= ["x"] (map :data (sse/parse-lines [": keep-alive" "data: x" ""])))))
  (testing "a blank line with no data dispatches nothing, and clears the type"
    (is (= [{:event "message" :data "x" :id nil}]
           (sse/parse-lines ["event: ignored" "" "data: x" ""]))))
  (testing "unknown fields are ignored"
    (is (= ["x"] (map :data (sse/parse-lines ["foo: bar" "data: x" ""])))))
  (testing "retry takes digits only"
    (is (= [{:retry 2500}] (sse/parse-lines ["retry: 2500"])))
    (is (= [] (sse/parse-lines ["retry: soon"]))))
  (testing "an id containing NUL is ignored; an empty id resets it"
    (is (= ["1" "1" nil] (map :id (sse/parse-lines ["id: 1" "data: a" "" "id: 2\u00002" "data: b" ""
                                                    "id:" "data: c" ""])))))
  (testing "an unterminated last event is not dispatched"
    (is (= [] (sse/parse-lines ["data: half"])))))

(deftest a-resumed-stream-keeps-the-last-id
  (is (= "41" (:id (first (sse/parse-lines (assoc sse/initial-state :id "41") ["data: x" ""]))))))

;; --- against a server -------------------------------------------------------------

(def ^:private port 18160)
(def ^:private base (str "http://localhost:" port))
(def ^:private last-event-id-seen (atom nil))

(defn- send! [conn s] (srv/conn-write conn (core/latin1->ba s)))

(defn- chunk! [conn s]
  (let [bs (core/latin1->ba s)]
    (send! conn (str (Integer/toHexString (count bs)) "\r\n"))
    (srv/conn-write conn bs)
    (send! conn "\r\n")))

(defn- head! [conn status & headers]
  (send! conn (apply str "HTTP/1.1 " status " X\r\n"
                     (concat (map (fn [h] (str h "\r\n")) headers) ["\r\n"]))))

(defn- handler [{:keys [uri conn headers]}]
  (case uri
    "/events"
    (do (reset! last-event-id-seen (get headers "last-event-id"))
        (head! conn 200 "Content-Type: text/event-stream" "Transfer-Encoding: chunked" "Connection: close")
        (doseq [i (range 3)]
          (chunk! conn (str "id: " i "\nevent: tick\ndata: " i "\n\n"))
          (Thread/sleep 100))
        (chunk! conn "retry: 1500\n\n")
        (send! conn "0\r\n\r\n")
        (srv/conn-close conn)
        :hijacked)

    "/forever"
    (do (head! conn 200 "Content-Type: text/event-stream" "Transfer-Encoding: chunked" "Connection: close")
        (chunk! conn "data: first\n\n")
        (Thread/sleep 3000)
        (srv/conn-close conn)
        :hijacked)

    "/json"
    {:status 404 :headers {"Content-Type" "application/json"} :body "{\"no\":1}"}

    {:status 404 :body "nope"}))

(use-fixtures :once
  (fn [t]
    (let [s (srv/start-plain port {:handler handler})]
      (Thread/sleep 100)
      (try (t) (finally (srv/stop s))))))

(deftest subscribe-reads-events-as-they-arrive
  (let [events (atom []) retries (atom []) opened (atom nil)
        sub (sse/subscribe! {:url (str base "/events")}
                            {:on-open (fn [r] (reset! opened (:status r)))
                             :on-event #(swap! events conj %)
                             :on-retry #(swap! retries conj %)})
        result (deref (:done sub) 5000 :timeout)]
    (is (= 200 @opened))
    (is (= [{:event "tick" :data "0" :id "0"} {:event "tick" :data "1" :id "1"}
            {:event "tick" :data "2" :id "2"}]
           @events))
    (is (= [1500] @retries))
    (is (= {:id "2" :closed? false} (select-keys result [:id :closed? :error])))))

(deftest subscribe-sends-last-event-id
  (let [sub (sse/subscribe! {:url (str base "/events")} {:last-event-id "41"})]
    (deref (:done sub) 5000 :timeout)
    (is (= "41" @last-event-id-seen))))

(deftest close-ends-a-stream-that-is-still-open
  (let [events (atom [])
        sub (sse/subscribe! {:url (str base "/forever")} {:on-event #(swap! events conj (:data %))})]
    (Thread/sleep 400)
    (is (= ["first"] @events))
    (let [t0 (System/currentTimeMillis)]
      ((:close sub))
      (let [result (deref (:done sub) 2500 :timeout)]
        (is (not= :timeout result) "the read returned when closed, not when the server hung up")
        (is (< (- (System/currentTimeMillis) t0) 2500))
        (when (map? result)
          (is (:closed? result))
          (is (nil? (:error result))))))))

(deftest a-reply-that-is-not-an-event-stream-goes-to-on-response
  (let [got (atom nil)
        sub (sse/subscribe! {:url (str base "/json")}
                            {:on-response (fn [r] (reset! got [(:status r) (slurp (:body r))]))
                             :on-event (fn [_] (throw (ex-info "no events expected" {})))})
        result (deref (:done sub) 5000 :timeout)]
    (is (= [404 "{\"no\":1}"] @got))
    (is (= 404 (get-in result [:response :status])))))
