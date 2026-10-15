(ns jolt.http.user-agent-test
  "What a request goes out with when its caller names no User-Agent, through
  both shims, as the server sees it: the JDK always names itself, and a CDN
  commonly refuses a request that doesn't (a 403 challenge page)."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [jolt.http-client :as http]
            [jolt.http.core :as core]
            [jolt.http.test-server :as srv])
  (:import [java.net URI]
           [java.net.http HttpClient HttpRequest HttpResponse$BodyHandlers]))

(def ^:private port 18130)
(def ^:private base (str "http://localhost:" port))

(use-fixtures :once (fn [t] (let [s (srv/start-plain port)] (try (t) (finally (srv/stop s))))))

(defn- jdk-get [headers]
  (let [b (reduce (fn [b [k v]] (.header b k v)) (HttpRequest/newBuilder (URI/create (str base "/user-agent"))) headers)]
    (.body (.send (HttpClient/newHttpClient) (.build b) (HttpResponse$BodyHandlers/ofString)))))

(deftest http-url-connection-names-jolt
  (is (= (core/default-user-agent :url-connection) (:body (http/get (str base "/user-agent")))))
  (is (str/starts-with? (:body (http/get (str base "/user-agent"))) "Jolt/"))
  (testing "a caller's own is sent instead"
    (is (= "mine/1" (:body (http/get (str base "/user-agent") {:headers {"User-Agent" "mine/1"}}))))
    (is (= "mine/2" (:body (http/get (str base "/user-agent") {:headers {"user-agent" "mine/2"}}))))))

(deftest java-net-http-names-jolt
  (is (= (core/default-user-agent :http-client) (jdk-get [])))
  (is (str/starts-with? (jdk-get []) "Jolt-http-client/"))
  (is (= "mine/3" (jdk-get [["User-Agent" "mine/3"]])) "a caller's own is sent instead"))
