(ns jolt.http.tls-test
  "TLS through the java.net.http path: `:ssl-context` (insecure, and a real
  PKCS#12 trust store), an https request tunnelled through an HTTP proxy with
  CONNECT, and wss. The server presents test/resources/cert.pem, a self-signed
  CN=localhost certificate, so the default (verifying) client must REFUSE it —
  a test that only checked the insecure path would pass with verification
  switched off everywhere.

  Separate from the babashka suite because it stands up TLS servers of its own."
  (:require [jolt.http.platform]
            [babashka.http-client :as http]
            [babashka.http-client.websocket :as ws]
            [jolt.http.bhc-routes :as routes]
            [jolt.http.test-server :as srv]
            [clojure.test :refer [deftest is testing run-tests use-fixtures]]))

(def ^:private https-port 18101)
(def ^:private wss-port 18102)
(def ^:private proxy-port 18103)

(def ^:private resources (str (System/getProperty "user.dir") "/test/resources/"))
(def ^:private cert (str resources "cert.pem"))
(def ^:private key-file (str resources "key.pem"))
(def ^:private truststore (str resources "truststore.p12"))
(def ^:private keystore (str resources "keystore.p12"))

(def ^:private base (str "https://localhost:" https-port))

(def ^:private servers (atom nil))

(defn- with-servers [t]
  (let [https (srv/start-tls https-port cert key-file {:handler routes/handler})
        wss (srv/start-tls wss-port cert key-file {:handler srv/websocket-handler})
        prx (srv/start-proxy proxy-port)]
    (reset! servers {:https https :wss wss :proxy prx})
    (try (t) (finally (srv/stop https) (srv/stop wss) (srv/stop prx)))))

(use-fixtures :once with-servers)

(deftest self-signed-is-refused-by-default
  (is (thrown? Exception (http/get (str base "/200")))))

(deftest insecure-ssl-context-accepts-it
  (let [c (http/client {:ssl-context {:insecure true}})
        r (http/get (str base "/200") {:client c})]
    (is (= 200 (:status r)))
    (is (= "200 OK" (:body r)))))

(deftest trust-store-accepts-it
  (testing "a PKCS#12 trust store replaces the platform CA set"
    (let [c (http/client {:ssl-context {:trust-store truststore
                                        :trust-store-pass "jolt"}})]
      (is (= "200 OK" (:body (http/get (str base "/200") {:client c})))))))

(deftest key-store-is-loaded
  ;; the server asks for no client certificate, so this only has to not break
  ;; the handshake — but it does exercise PKCS12_parse on a store WITH a key
  (let [c (http/client {:ssl-context {:key-store keystore
                                      :key-store-pass "jolt"
                                      :trust-store truststore
                                      :trust-store-pass "jolt"}})]
    (is (= "200 OK" (:body (http/get (str base "/200") {:client c}))))))

(deftest wrong-trust-store-password-is-an-error
  (is (thrown? Exception
               (http/get (str base "/200")
                         {:client (http/client {:ssl-context {:trust-store truststore
                                                              :trust-store-pass "wrong"}})}))))

(deftest https-through-a-proxy-tunnel
  (let [seen (:seen (:proxy @servers))]
    (reset! seen [])
    (let [c (http/client {:ssl-context {:insecure true}
                          :proxy {:host "localhost" :port proxy-port}})
          r (http/get (str base "/200") {:client c})]
      (is (= 200 (:status r)))
      (is (= "200 OK" (:body r)))
      (testing "the proxy tunnelled it with CONNECT and never saw the request line"
        (is (= [{:method "CONNECT" :target (str "localhost:" https-port)}] @seen))))))

(deftest redirects-over-tls
  (let [c (http/client (assoc http/default-client-opts :ssl-context {:insecure true}))]
    (is (= "200 OK" (:body (http/get (str base "/redirect/2") {:client c}))))))

(deftest compressed-over-tls
  (let [c (http/client (assoc http/default-client-opts :ssl-context {:insecure true}))]
    (is (= "gzipped body" (:body (http/get (str base "/gzip") {:client c}))))))

(deftest wss-round-trip
  ;; :client here is the java.net.http.HttpClient itself, which is what
  ;; babashka.http-client.websocket calls .newWebSocketBuilder on — the TLS
  ;; settings ride along from it
  (let [got (promise)
        c (:client (http/client {:ssl-context {:insecure true}}))
        sock (ws/websocket {:uri (str "wss://localhost:" wss-port)
                            :client c
                            :on-message (fn [_ data _] (deliver got (str data)))})]
    (ws/send! sock "over tls")
    (is (= "over tls" (deref got 20000 :timeout)))
    (ws/close! sock)))

(deftest wss-refuses-an-untrusted-certificate
  (is (thrown? Exception (ws/websocket {:uri (str "wss://localhost:" wss-port)}))))

(defn -main [& _]
  (let [r (run-tests 'jolt.http.tls-test)]
    (println (str "\n========== TLS =========="))
    (println (str "tests=" (:test r) " pass=" (:pass r) " fail=" (:fail r) " error=" (:error r)))
    (when (or (pos? (:fail r)) (pos? (:error r)))
      (throw (ex-info "TLS failures" (select-keys r [:fail :error]))))))
