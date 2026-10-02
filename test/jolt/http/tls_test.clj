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
            [jolt.http.tls :as tls]
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

(deftest ssl-contexts-are-shared-across-connections
  (testing "the same client configuration reuses one SSL_CTX"
    ;; A verifying context loads the platform CA bundle; building one measured
    ;; 5.7ms against 0.09ms for an insecure one, and it used to be built per
    ;; request. Identity, not timing, is what this asserts.
    (let [a (#'tls/client-ctx false nil)
          b (#'tls/client-ctx false nil)
          insecure (#'tls/client-ctx true nil)]
      (is (= a b) "two verifying clients share a context")
      (is (not= a insecure) "verify and no-verify are different contexts")))
  (testing "a trust store gets its own context, and still verifies"
    (let [c (http/client {:ssl-context {:trust-store truststore :trust-store-pass "jolt"}})]
      (is (= 200 (:status (http/get (str base "/200") {:client c}))))
      (is (= 200 (:status (http/get (str base "/200") {:client c}))))
      (is (thrown? Exception (http/get (str base "/200"))))))
  (testing "repeat requests on one client still work after the context is cached"
    (let [c (http/client {:ssl-context {:insecure true}})]
      (dotimes [_ 5] (is (= 200 (:status (http/get (str base "/200") {:client c}))))))))

(defn -main [& _]
  (let [r (run-tests 'jolt.http.tls-test)]
    (println (str "\n========== TLS =========="))
    (println (str "tests=" (:test r) " pass=" (:pass r) " fail=" (:fail r) " error=" (:error r)))
    (System/exit (if (or (pos? (:fail r)) (pos? (:error r))) 1 0))))

;; A TLS stream's :close tore down the socket and the SSL object every time it
;; ran, so a second close — a finally after an error path already closed it —
;; closed whatever fd number had been handed out since and freed the SSL twice.
;; Server streams also never freed their per-connection SSL_CTX, and a failed
;; server handshake leaked the SSL, the BIOs and the context.
(defn- counting [f]
  (let [closes (atom []) ssl-frees (atom 0) ctx-frees (atom 0)
        close0 jolt.http.net/close ssl0 tls/c-SSL-free ctx0 tls/c-SSL-CTX-free]
    (with-redefs [jolt.http.net/close (fn [fd] (swap! closes conj fd) (close0 fd))
                  tls/c-SSL-free (fn [p] (swap! ssl-frees inc) (ssl0 p))
                  tls/c-SSL-CTX-free (fn [p] (swap! ctx-frees inc) (ctx0 p))]
      (f))
    {:closes @closes :ssl-frees @ssl-frees :ctx-frees @ctx-frees}))

(deftest closing-a-tls-stream-twice-releases-once
  (let [st (tls/tls-connect "localhost" https-port true)
        n (counting (fn [] ((jolt.host/ref-get st :close)) ((jolt.host/ref-get st :close))))]
    (is (= 1 (count (:closes n))) "the socket is closed once")
    (is (= 1 (:ssl-frees n)) "the SSL is freed once")
    (is (= 0 (:ctx-frees n)) "a client context is shared out of the cache, never freed")))

(deftest a-server-stream-frees-its-context
  (let [fd (srv/listen-socket 18104)
        server (future (tls/tls-wrap-server (srv/accept-raw fd) cert key-file))]
    (try
      (let [client (tls/tls-connect "localhost" 18104 true)
            st @server
            n (counting (fn [] ((jolt.host/ref-get st :close)) ((jolt.host/ref-get st :close))))]
        ((jolt.host/ref-get client :close))
        (is (= 1 (count (:closes n))))
        (is (= 1 (:ssl-frees n)))
        (is (= 1 (:ctx-frees n)) "the per-connection server context goes with it"))
      (finally (jolt.http.net/close fd)))))

(deftest a-failed-server-handshake-frees-everything
  ;; with-redefs is global, so the client's own cleanup is counted too: its SSL
  ;; is freed, its context is not (shared out of the cache). The accepted fd
  ;; stays the caller's on failure, closed once by the caller below.
  (let [fd (srv/listen-socket 18105)
        raw (promise)
        n (counting
            (fn []
              (let [server (future
                             (let [r (srv/accept-raw fd)]
                               (deliver raw r)
                               (try (tls/tls-wrap-server r cert key-file)
                                    (catch Throwable _ (jolt.http.net/close r)))))]
                ;; the verifying client rejects the self-signed cert mid-handshake
                (is (thrown? Exception (tls/tls-connect "localhost" 18105 false)))
                @server)))]
    (try
      (is (= 1 (count (filter #{@raw} (:closes n)))) "the accepted socket is closed once")
      (is (= 2 (:ssl-frees n)) "the server's SSL and the client's")
      (is (= 1 (:ctx-frees n)) "the server's per-connection context")
      (finally (jolt.http.net/close fd)))))
