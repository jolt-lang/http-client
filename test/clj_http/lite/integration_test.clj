(ns clj-http.lite.integration-test
  (:require [clj-http.lite.client :as client]
            [clj-http.lite.core :as core]
            [clj-http.lite.util :as util]
            [clj-http.lite.test-util.server-process :as server-process]
            [clj-http.lite.test-util.test-report]
            [clojure.test :refer [deftest is use-fixtures]]))

(def ^:dynamic *server* nil)

(defn with-server [t]
  (let [s (server-process/launch)]
    (try
      (binding [*server* s]
        (t))
      (finally
        (server-process/kill s)))))

(use-fixtures :once with-server)

(defn base-req []
  {:scheme      :http
   :server-name "localhost"
   :server-port (:http-port *server*)})

(defn request [req]
  (core/request (merge (base-req) req)))

(defn slurp-body [req]
  (slurp (:body req)))

;;
;; Lower level internal unwrapped core requests
;;
(deftest makes-get-request
  (let [resp (request {:request-method :get :uri "/get"})]
    (is (= 200 (:status resp)))
    (is (= "get" (slurp-body resp)))))

(deftest makes-head-request
  (let [resp (request {:request-method :head :uri "/head"})]
    (is (= 200 (:status resp)))
    (is (nil? (:body resp)))))

(deftest sets-content-type-with-charset
  (let [resp (request {:request-method :get         :uri                "/content-type"
                       :content-type   "text/plain" :character-encoding "UTF-8"})]
    (is (= "text/plain; charset=UTF-8" (slurp-body resp)))))

(deftest sets-content-type-without-charset
  (let [resp (request {:request-method :get :uri "/content-type"
                       :content-type   "text/plain"})]
    (is (= "text/plain" (slurp-body resp)))))

(deftest sets-arbitrary-headers
  (let [resp (request {:request-method :get :uri "/header"
                       :headers        {"X-My-Header" "header-val"}})]
    (is (= "header-val" (slurp-body resp)))))

(deftest sends-and-returns-byte-array-body
  (let [resp (request {:request-method :post :uri "/post"
                       :body           (util/utf8-bytes "contents")})]
    (is (= 200 (:status resp)))
    (is (= "contents" (slurp-body resp)))))

(deftest returns-arbitrary-headers
  (let [resp (request {:request-method :get :uri "/get"})]
    (is (string? (get-in resp [:headers "date"])))))

(deftest returns-status-on-exceptional-responses
  (let [resp (request {:request-method :get :uri "/error"})]
    (is (= 500 (:status resp)))))

(deftest returns-status-on-redirect
  (let [resp (request {:request-method :get :uri "/redirect" :follow-redirects false})]
    (is (= 302 (:status resp)))))

(deftest auto-follows-on-redirect
  (let [resp (request {:request-method :get :uri "/redirect"})]
    (is (= 200 (:status resp)))
    (is (= "get" (slurp-body resp)))))

(deftest sets-conn-timeout
  ;; indirect way of testing if a connection timeout will fail by passing in an
  ;; invalid argument
  (try
    (request {:request-method :get :uri "/timeout" :conn-timeout -1})
    (throw (Exception. "Shouldn't get here."))
    (catch Exception e
      (is (= IllegalArgumentException (class e))))))

(deftest sets-socket-timeout
  (try
    (request {:request-method :get :uri "/timeout" :socket-timeout 1})
    (is false "expected a throw")
    (catch Exception e
      (is (or (= java.net.SocketTimeoutException (class e))
              (= java.net.SocketTimeoutException (class (.getCause e))))))))

(deftest delete-with-body
  (let [resp (request {:request-method :delete :uri "/delete-with-body"
                       :body (.getBytes "foo bar")})]
    (is (= 200 (:status resp)))
    (is (= "delete-with-body" (slurp-body resp)))))

(deftest self-signed-ssl-get
  (let [client-opts {:request-method :get
                     :uri "/get"
                     :scheme         :https
                     :server-name "localhost"
                     :server-port (:https-port *server*)}]
    (is (thrown? javax.net.ssl.SSLException
                 (request client-opts)))
    (let [resp (request (assoc client-opts :insecure? true))]
      (is (= 200 (:status resp)))
      (is (= "get" (slurp-body resp))))
    (is (thrown? javax.net.ssl.SSLException
                 (request client-opts)))))

(deftest t-save-request-obj
  (let [resp (request {:request-method :post :uri "/post"
                       :body           (.getBytes "foo bar" "UTF-8")
                       :save-request?  true})]
    (is (= 200 (:status resp)))
    (is (= {:scheme         :http
            :http-url       (str "http://localhost:" (:http-port *server*) "/post")
            :request-method :post
            :uri            "/post"
            :server-name    "localhost"
            :server-port    (:http-port *server*)}
           (-> resp
               :request
               (dissoc :body))))))

(deftest t-streaming-response
  (let [stream (:body (request {:request-method :get :uri "/get" :as :stream}))
        body (slurp stream)]
    (is (= "get" body))))

;;
;; API level client wrapped requests
;;
(deftest roundtrip
  ;; roundtrip with scheme as a keyword
  (let [resp (client/request (merge (base-req) {:uri "/get" :method :get}))]
    (is (= 200 (:status resp)))
    (is (= "get" (:body resp))))
  ;; roundtrip with scheme as a string
  (let [resp (client/request (merge (base-req) {:uri    "/get"
                                                :method :get
                                                :scheme "http"}))]
    (is (= 200 (:status resp)))
    (is (= "get" (:body resp)))))

(deftest basic-auth-no-creds
  (let [resp (client/request (merge (base-req) {:method :get
                                                :uri "/basic-auth"
                                                :throw-exceptions false}))]
    (is (= 401 (:status resp)))
    (is (= "denied" (:body resp)))))

(deftest basic-auth-bad-creds
  (let [resp (client/request (merge (base-req) {:method :get
                                                :uri "/basic-auth"
                                                :throw-exceptions false
                                                :basic-auth "username:nope"}))]
    (is (= 401 (:status resp)))
    (is (= "denied" (:body resp)))))

(deftest basic-auth-creds-as-basic-auth
  (let [resp (client/request (merge (base-req) {:method :get
                                                :uri "/basic-auth"
                                                :basic-auth "username:password"}))]
    (is (= 200 (:status resp)))
    (is (= "welcome" (:body resp)))))

(deftest basic-auth-creds-as-user-info
  (let [resp (client/request (merge (base-req) {:method :get
                                                :uri "/basic-auth"
                                                :user-info "username:password"}))]
    (is (= 200 (:status resp)))
    (is (= "welcome" (:body resp)))))

(deftest basic-auth-creds-from-url
  (let [resp (client/request {:method :get
                              :url (format "http://username:password@localhost:%d/basic-auth"
                                           (:http-port *server*))})]
    (is (= 200 (:status resp)))
    (is (= "welcome" (:body resp)))))
