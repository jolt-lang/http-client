(ns jolt.http.babashka-test
  "babashka.http-client — the Maven artifact, unmodified — running on jolt over
  the java.net.http shim in jolt.http.jdk. The cases mirror babashka's own suite:
  the request/response surface, the interceptor chain, :async, multipart, and the
  client options (proxy, cookies, redirects, auth, TLS)."
  (:require [jolt.http.platform]
            [babashka.http-client :as http]
            [babashka.http-client.interceptors :as interceptors]
            [clojure.string :as str]
            [jolt.http.bhc-routes :as routes]
            [jolt.http.test-server :as srv]
            [multipart.core :as multipart]
            [clojure.test :refer [deftest is testing run-tests use-fixtures]]))

(def ^:private port 18095)
(def ^:private proxy-port 18096)
(def ^:private base (str "http://localhost:" port))

(def ^:private servers (atom nil))

(defn- with-servers [t]
  (let [s (srv/start-plain port {:handler routes/handler})
        p (srv/start-proxy proxy-port)]
    (reset! servers {:http s :proxy p})
    (try (t) (finally (srv/stop s) (srv/stop p)))))

(use-fixtures :once with-servers)

(defn- header-line
  "Pull one header back out of the /get echo."
  [body nm]
  (some (fn [line] (when (str/starts-with? (str/lower-case line) (str (str/lower-case nm) ": "))
                     (subs line (+ 2 (count nm)))))
        (str/split-lines body)))

;; --- basics ---------------------------------------------------------------

(deftest get-request
  (let [r (http/get (str base "/200"))]
    (is (= 200 (:status r)))
    (is (= "200 OK" (:body r)))
    (is (= :http1.1 (:version r)))
    (is (= (str base "/200") (str (:uri r))))))

(deftest default-request-headers
  (let [b (:body (http/get (str base "/get")))]
    (is (= "*/*" (header-line b "accept")))
    (is (str/starts-with? (or (header-line b "user-agent") "") "babashka.http-client/"))
    (is (= "gzip, deflate" (header-line b "accept-encoding")))))

(deftest every-method
  (doseq [[f expected] [[http/get "GET"] [http/post "POST"] [http/put "PUT"]
                        [http/delete "DELETE"] [http/patch "PATCH"]]]
    (is (= expected (:body (f (str base "/method")))) (str "method " expected)))
  ;; HEAD has no body but must still round-trip
  (is (= 200 (:status (http/head (str base "/method"))))))

(deftest post-body
  (is (= "hello=world" (:body (http/post (str base "/echo") {:body "hello=world"}))))
  (is (= "from-bytes" (:body (http/post (str base "/echo") {:body (.getBytes "from-bytes" "UTF-8")}))))
  (is (= "from-stream"
         (:body (http/post (str base "/echo")
                           {:body (java.io.ByteArrayInputStream. (.getBytes "from-stream" "UTF-8"))})))))

(deftest sends-request-headers
  (let [b (:body (http/get (str base "/get") {:headers {"x-my-header" "yes"}}))]
    (is (= "yes" (header-line b "x-my-header")))))

(deftest header-with-keyword-key
  ;; prefer-string-keys: a string header wins over the keyword spelling
  (let [b (:body (http/get (str base "/get") {:headers {:x-kw "kw" "x-str" "str"}}))]
    (is (= "kw" (header-line b "x-kw")))
    (is (= "str" (header-line b "x-str")))))

(deftest response-headers-lowercased
  (let [r (http/get (str base "/200"))]
    ;; java.net.http lowercases header names; the shim matches it
    (is (some? (get-in r [:headers "content-length"])))
    (is (nil? (get-in r [:headers "Content-Length"])))))

(deftest as-coercions
  (is (bytes? (:body (http/get (str base "/200") {:as :bytes}))))
  (is (= "200 OK" (String. ^bytes (:body (http/get (str base "/200") {:as :bytes})) "UTF-8")))
  (is (= "200 OK" (slurp (:body (http/get (str base "/200") {:as :stream})))))
  (is (= "200 OK" (:body (http/get (str base "/200") {:as :string})))))

;; --- interceptors ---------------------------------------------------------

(deftest query-params
  (is (= "a=b+c&d=1" (:body (http/get (str base "/query") {:query-params {"a" "b c" "d" 1}}))))
  (testing "a list value repeats the key"
    (is (= "a=1&a=2" (:body (http/get (str base "/query") {:query-params {"a" [1 2]}})))))
  (testing "query params append to a query already in the uri"
    (is (= "x=0&a=1" (:body (http/get (str base "/query?x=0") {:query-params {"a" 1}}))))))

(deftest form-params
  (let [r (http/post (str base "/echo") {:form-params {:a "b c" :d 1}})]
    (is (= "a=b+c&d=1" (:body r))))
  (testing "sets the content type"
    (let [b (:body (http/post (str base "/get") {:form-params {:a 1}}))]
      (is (= "application/x-www-form-urlencoded" (header-line b "content-type"))))))

(deftest basic-auth
  (is (= 200 (:status (http/get (str base "/basic-auth") {:basic-auth ["username" "password"]}))))
  (is (= 200 (:status (http/get (str base "/basic-auth") {:basic-auth {:user "username" :pass "password"}}))))
  (is (= 401 (:status (http/get (str base "/basic-auth") {:basic-auth ["u" "p"] :throw false})))))

(deftest oauth-token
  (is (= "token=abc" (:body (http/get (str base "/bearer") {:oauth-token "abc"})))))

(deftest accept-header
  (let [b (:body (http/get (str base "/get") {:accept :json}))]
    (is (= "application/json" (header-line b "accept")))))

(deftest exceptional-status
  (is (thrown? clojure.lang.ExceptionInfo (http/get (str base "/404"))))
  (is (= 404 (:status (http/get (str base "/404") {:throw false}))))
  (testing "ex-data carries the response"
    (let [e (try (http/get (str base "/422")) nil (catch clojure.lang.ExceptionInfo e e))]
      (is (= 422 (:status (ex-data e))))
      (is (str/includes? (ex-message e) "Exceptional status code: 422")))))

(deftest decompress-body
  (is (= "gzipped body" (:body (http/get (str base "/gzip")))))
  (is (= "deflated body" (:body (http/get (str base "/deflate")))))
  (testing "raw deflate, which a default Inflater cannot read"
    (is (= "raw deflated body" (:body (http/get (str base "/raw-deflate"))))))
  (testing ":decompress-body false hands back the compressed bytes"
    (let [r (http/get (str base "/gzip") {:decompress-body false :as :bytes})]
      (is (not= "gzipped body" (String. ^bytes (:body r) "UTF-8")))
      (is (= "gzip" (get-in r [:headers "content-encoding"]))))))

(deftest custom-interceptor-chain
  (let [chain (into [{:name ::tag
                      :request (fn [req] (assoc-in req [:headers "x-tagged"] "1"))
                      :response (fn [resp] (assoc resp :tagged true))}]
                    interceptors/default-interceptors)
        r (http/get (str base "/get") {:interceptors chain})]
    (is (:tagged r))
    (is (= "1" (header-line (:body r) "x-tagged")))))

;; --- uri handling ---------------------------------------------------------

(deftest uri-as-map
  (is (= 200 (:status (http/request {:uri {:scheme "http" :host "localhost" :port port :path "/200"}
                                     :method :get}))))
  (testing "implicit port"
    (let [u (:uri (http/request {:uri {:scheme "http" :host "localhost" :port port :path "/200"}
                                 :method :get}))]
      (is (= (str base "/200") (str u))))))

(deftest leniency
  (is (http/request {:method :get :uri (str base "/200")}))
  (is (http/request {:request-method :get :uri (str base "/200")}))
  (is (http/request {:request-method :get :url (str base "/200")})))

;; --- redirects ------------------------------------------------------------

(deftest follows-redirects-by-default
  (is (= "200 OK" (:body (http/get (str base "/302")))))
  (testing "a chain"
    (is (= "200 OK" (:body (http/get (str base "/redirect/3")))))))

(deftest redirect-policies
  (testing ":never leaves the 302 alone"
    (let [c (http/client {:follow-redirects :never})]
      (is (= 302 (:status (http/get (str base "/302") {:client c :throw false}))))))
  (testing ":always follows"
    (let [c (http/client (assoc http/default-client-opts :follow-redirects :always))]
      (is (= "200 OK" (:body (http/get (str base "/302") {:client c})))))))

(deftest redirect-303-becomes-get
  ;; 303 rewrites the method to GET, which /method reports back
  (is (= "GET" (:body (http/post (str base "/303") {:body "x"})))))

;; --- client options -------------------------------------------------------

(deftest client-request-defaults
  (let [c (http/client (assoc-in http/default-client-opts [:request :headers :x-default] "yes"))
        b (:body (http/get (str base "/get") {:client c}))]
    (is (= "yes" (header-line b "x-default")))))

(deftest ring-client-fn
  (testing "a fn as :client gets the ring request and its return is the response"
    (doseq [resp [(http/get (str base "/200") {:client (fn [_req] {:body "Hello" :seen true})})
                  (http/get (str base "/200")
                            {:client (fn [req] {:body (java.io.ByteArrayInputStream. (.getBytes "Hello"))
                                                :seen (= (str base "/200") (str (:uri req)))})})]]
      (is (:seen resp))
      (is (= "Hello" (:body resp))))))

(deftest connect-and-request-timeouts
  (is (= 200 (:status (http/get (str base "/200") {:timeout 5000}))))
  (let [c (http/client {:connect-timeout 2000})]
    (is (= 200 (:status (http/get (str base "/200") {:client c})))))
  (testing "a request timeout actually bounds a slow response"
    (is (thrown? Exception (http/get (str base "/slow") {:timeout 300})))))

(deftest authenticator-answers-a-401
  (let [c (http/client {:authenticator {:user "username" :pass "password"}})
        r (http/get (str base "/auth-challenge") {:client c})]
    (is (= 200 (:status r)))
    (is (str/includes? (:body r) "Basic"))))

;; --- async ----------------------------------------------------------------

(deftest async-request
  (let [f (http/get (str base "/200") {:async true})]
    (is (instance? java.util.concurrent.CompletableFuture f))
    (is (= 200 (:status @f))))
  (testing ":async-then maps the response"
    (is (= 200 @(http/get (str base "/200") {:async true :async-then :status}))))
  (testing "an exceptional status surfaces from deref"
    (let [f (http/get (str base "/422") {:async true})]
      (is (thrown? java.util.concurrent.ExecutionException @f))))
  (testing ":async-catch sees the ex-data"
    (let [f (http/get (str base "/404") {:async true
                                         :async-then :status
                                         :async-catch (fn [e] (:ex-data e))})]
      (is (= 404 (:status @f))))))

;; --- multipart ------------------------------------------------------------

(deftest multipart-request
  (let [r (http/post (str base "/multipart")
                     {:multipart [{:name "title" :content "My Title"}
                                  {:name "field" :part-name "renamed" :content "value"}
                                  {:name "file" :content "file contents" :file-name "a.txt"
                                   :content-type "text/plain"}]})
        ct (get-in r [:headers "content-type"])
        parsed (multipart/parse-form-data {:headers {"content-type" ct}
                                           :body (.getBytes ^String (:body r) "ISO-8859-1")})]
    (is (str/starts-with? ct "multipart/form-data; boundary="))
    (is (= "My Title" (get-in parsed [:params "title"])))
    (is (= "value" (get-in parsed [:params "renamed"])))
    (let [f (get-in parsed [:files "file"])]
      (is (= "a.txt" (:filename f)))
      (is (= "text/plain" (:content-type f)))
      (is (= "file contents" (String. ^bytes (:bytes f) "UTF-8"))))))

(deftest multipart-overrides-content-type
  (let [r (http/post (str base "/multipart")
                     {:headers {"content-type" "application/json"}
                      :multipart [{:name "a" :content "b"}]})]
    (is (str/starts-with? (get-in r [:headers "content-type"]) "multipart/form-data"))))

;; --- cookies --------------------------------------------------------------

(deftest cookie-handler-round-trip
  (let [c (http/client {:cookie-handler {:policy :accept-all}})]
    (http/get (str base "/set-cookie") {:client c})
    (let [sent (:body (http/get (str base "/cookies") {:client c}))]
      (is (str/includes? sent "a=1"))
      (is (str/includes? sent "b=2"))))
  (testing ":accept-none stores nothing"
    (let [c (http/client {:cookie-handler {:policy :accept-none}})]
      (http/get (str base "/set-cookie") {:client c})
      (is (= "" (:body (http/get (str base "/cookies") {:client c}))))))
  (testing "a Path-scoped cookie only goes back under that path"
    (let [c (http/client {:cookie-handler {:policy :accept-all}})]
      (http/get (str base "/set-cookie-path") {:client c})
      (is (= "" (:body (http/get (str base "/cookies") {:client c}))))
      (is (str/includes? (:body (http/get (str base "/deep/cookies") {:client c})) "deep=1")))))

(deftest cookie-handler-construction
  (is (nil? (http/->CookieHandler nil)))
  (let [test-uri (java.net.URI. "http" nil "test.test" -1 nil nil nil)
        headers {"Set-Cookie" ["Test=Value; Domain=.test.test" "Test2=Value2; Domain=.not.test"]}]
    (doseq [[policy expected] [[:accept-all 2] [:accept-none 0] [:original-server 1] [nil 0]]]
      (let [ch (http/->CookieHandler {:policy policy})]
        (is (instance? java.net.CookieHandler ch))
        (.put ch test-uri headers)
        (is (= expected (count (.. ch getCookieStore getCookies)))
            (str "policy " policy))))))

;; --- proxy ----------------------------------------------------------------

(deftest proxy-routes-the-request
  (let [seen (:seen (:proxy @servers))]
    (reset! seen [])
    (let [c (http/client {:proxy {:host "localhost" :port proxy-port}})
          r (http/get (str base "/200") {:client c})]
      (is (= 200 (:status r)))
      (is (= "200 OK" (:body r)))
      (testing "the proxy saw an absolute-form request line"
        (is (= [{:method "GET" :target (str base "/200")}] @seen))))))

(deftest proxy-fn-selects-per-request
  (let [seen (:seen (:proxy @servers))]
    (reset! seen [])
    (let [c (http/client {:proxy (fn [uri] (when (str/includes? (str uri) "/200")
                                             {:host "localhost" :port proxy-port}))})]
      (is (= 200 (:status (http/get (str base "/200") {:client c}))))
      (is (= 1 (count @seen)))
      ;; a uri the fn declines goes direct, so the proxy sees nothing more
      (is (= 200 (:status (http/get (str base "/method") {:client c}))))
      (is (= 1 (count @seen))))))

(deftest proxy-selector-construction
  (is (instance? java.net.ProxySelector (http/->ProxySelector {:host "h" :port 1})))
  (is (instance? java.net.ProxySelector (http/->ProxySelector (http/->ProxySelector {:host "h" :port 1}))))
  (testing ":direct ignores host and port"
    (let [sel (http/->ProxySelector {:type :direct})]
      (is (= java.net.Proxy$Type/DIRECT (.type (first (.select sel (java.net.URI/create "http://x"))))))))
  (testing "a map always selects the same proxy"
    (let [sel (http/->ProxySelector {:host "127.0.0.1" :port 8081})
          p (first (.select sel (java.net.URI/create "http://x")))]
      (is (= java.net.Proxy$Type/HTTP (.type p)))
      (is (= "127.0.0.1" (.getHostString (.address p))))
      (is (= 8081 (.getPort (.address p))))))
  (testing "java.net.http supports HTTP proxies only"
    (is (thrown? clojure.lang.ExceptionInfo (http/->ProxySelector {:host "h" :port 1 :type :socks}))))
  (testing "a proxy needs host and port"
    (is (thrown? clojure.lang.ExceptionInfo (http/->ProxySelector {:host "h"})))))

;; --- ssl / other option constructors --------------------------------------

(deftest ssl-parameters
  (is (nil? (http/->SSLParameters nil)))
  (let [p (http/->SSLParameters {:ciphers [] :protocols []})]
    (is (instance? javax.net.ssl.SSLParameters p))
    (is (nil? (.getCipherSuites p)))
    (is (nil? (.getProtocols p))))
  (let [p (http/->SSLParameters {:ciphers ["SSL_NULL_WITH_NULL_NULL"] :protocols ["TLSv1"]})]
    (is (= "SSL_NULL_WITH_NULL_NULL" (first (.getCipherSuites p))))
    (is (= "TLSv1" (first (.getProtocols p))))
    (testing "an SSLParameters passes through"
      (is (= "TLSv1" (first (.getProtocols (http/->SSLParameters p))))))))

(deftest ssl-context-construction
  (let [insecure (http/->SSLContext {:insecure true})]
    (is (instance? javax.net.ssl.SSLContext insecure)))
  (testing "a client accepts one"
    (is (some? (:client (http/client {:ssl-context {:insecure true}}))))))

(deftest executor-and-authenticator-construction
  (is (nil? (http/->Executor nil)))
  (is (nil? (http/->Executor {})))
  (is (instance? java.util.concurrent.ThreadPoolExecutor (http/->Executor {:threads 2})))
  (is (some? (http/->Authenticator {:user "u" :pass "p"})))
  (is (nil? (http/->Authenticator {}))))

(deftest client-options-round-trip
  (let [c (:client (http/client {:connect-timeout 1234
                                 :follow-redirects :always
                                 :version :http2
                                 :cookie-handler {:policy :accept-all}
                                 :authenticator {:user "u" :pass "p"}
                                 :proxy {:host "h" :port 1}}))]
    (is (= java.net.http.HttpClient$Redirect/ALWAYS (.followRedirects c)))
    (is (= "HTTP_2" (.name (.version c))))
    (is (.isPresent (.connectTimeout c)))
    (is (.isPresent (.cookieHandler c)))
    (is (.isPresent (.authenticator c)))
    (is (.isPresent (.proxy c)))))

(defn -main [& _]
  (let [r (run-tests 'jolt.http.babashka-test)]
    (println (str "\n========== babashka.http-client =========="))
    (println (str "tests=" (:test r) " pass=" (:pass r) " fail=" (:fail r) " error=" (:error r)))
    (when (or (pos? (:fail r)) (pos? (:error r)))
      (throw (ex-info "babashka.http-client compat failures" (select-keys r [:fail :error]))))))
