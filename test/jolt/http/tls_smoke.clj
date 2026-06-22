(ns jolt.http.tls-smoke
  "End-to-end TLS: stand up the OpenSSL loopback server, GET over https."
  (:require [jolt.http-client :as http]
            [jolt.http.test-server :as srv]))

(def failures (atom 0))
(defn check [label expected actual]
  (if (= expected actual) (println "  ok  " label)
      (do (swap! failures inc) (println "  FAIL" label "expected" (pr-str expected) "got" (pr-str actual)))))

(defn -main [& _]
  (let [cert (str (jolt.host/getenv "JOLT_PWD") "/test/resources/cert.pem")
        key  (str (jolt.host/getenv "JOLT_PWD") "/test/resources/key.pem")
        server (srv/start-tls 18092 cert key)]
    (Thread/sleep 300)
    (try
      (let [r (http/get "https://127.0.0.1:18092/get" {:insecure? true})]
        (check "https GET status" 200 (:status r))
        (check "https GET body" "get" (:body r)))
      (let [p (http/post "https://127.0.0.1:18092/post" {:body "ping" :insecure? true})]
        (check "https POST echoes body" "ping" (:body p)))
      (finally (srv/stop server)))
    (println (if (zero? @failures) "\nall passed" (str "\n" @failures " FAILED")))
    (when (pos? @failures) (throw (ex-info "tls smoke failures" {:n @failures})))))
