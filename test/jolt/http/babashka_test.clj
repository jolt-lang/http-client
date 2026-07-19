(ns jolt.http.babashka-test
  "babashka.http-client runs on jolt through jolt.http.platform's java.net.http
  shim — no code change to babashka.http-client itself, just require the platform
  first. Exercises GET / POST / headers / :as against the in-process plaintext
  server (start-plain, so no TLS/crypto needed for the smoke)."
  (:require [jolt.http.platform]
            [babashka.http-client :as http]
            [jolt.http.test-server :as srv]
            [clojure.test :refer [deftest is run-tests use-fixtures]]))

(def ^:private port 18095)
(def ^:private base (str "http://localhost:" port))

(defn- with-server [t]
  (let [s (srv/start-plain port)]
    (try (t) (finally (srv/stop s)))))

(use-fixtures :once with-server)

(deftest get-request
  (let [r (http/get (str base "/get"))]
    (is (= 200 (:status r)))
    (is (= "get" (:body r)))))

(deftest post-request
  (let [r (http/post (str base "/post") {:body "hello=world"})]
    (is (= 200 (:status r)))
    (is (= "hello=world" (:body r)))))

(deftest sends-request-headers
  (let [r (http/get (str base "/header") {:headers {"x-my-header" "yes"}})]
    (is (= 200 (:status r)))
    (is (= "yes" (:body r)))))

(deftest response-headers-lowercased
  (let [r (http/get (str base "/get"))]
    ;; java.net.http lowercases header names; the shim matches it
    (is (some? (get-in r [:headers "content-length"])))))

(deftest as-bytes
  (let [r (http/get (str base "/get") {:as :bytes})]
    (is (bytes? (:body r)))
    (is (= "get" (String. ^bytes (:body r) "UTF-8")))))

(deftest as-stream
  (let [r (http/get (str base "/get") {:as :stream})]
    (is (= "get" (slurp (:body r))))))

(defn -main [& _]
  (let [r (run-tests 'jolt.http.babashka-test)]
    (println (str "\n========== babashka.http-client =========="))
    (println (str "tests=" (:test r) " pass=" (:pass r) " fail=" (:fail r) " error=" (:error r)))
    (when (or (pos? (:fail r)) (pos? (:error r)))
      (throw (ex-info "babashka.http-client compat failures" (select-keys r [:fail :error]))))))
