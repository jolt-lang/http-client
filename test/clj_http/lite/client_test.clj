(ns clj-http.lite.client-test
  (:require [clj-http.lite.client :as client]
            [clj-http.lite.util :as util]
            [clj-http.lite.test-util.test-report]
            [clojure.test :refer [deftest is testing]])
  (:import (java.net UnknownHostException)))

(defn is-passed [middleware req]
  (let [client (middleware identity)]
    (is (= req (client req)))))

(defn is-applied [middleware req-in req-out]
  (let [client (middleware identity)]
    (is (= req-out (client req-in)))))

(deftest redirect-on-get
  (let [client (fn [req]
                 (if (= "foo.com" (:server-name req))
                   {:status 302
                    :headers {"location" "http://bar.com/bat"}}
                   {:status 200
                    :req req}))
        r-client (-> client client/wrap-url client/wrap-redirects)
        resp (r-client {:server-name "foo.com" :request-method :get})]
    (is (= 200 (:status resp)))
    (is (= :get (:request-method (:req resp))))
    (is (= :http (:scheme (:req resp))))

    (is (= "/bat" (:uri (:req resp))))))

(deftest redirect-to-get-on-head
  (let [client (fn [req]
                 (if (= "foo.com" (:server-name req))
                   {:status 303
                    :headers {"location" "http://bar.com/bat"}}
                   {:status 200
                    :req req}))
        r-client (-> client client/wrap-url client/wrap-redirects)
        resp (r-client {:server-name "foo.com" :request-method :head})]
    (is (= 200 (:status resp)))
    (is (= :get (:request-method (:req resp))))
    (is (= :http (:scheme (:req resp))))
    (is (= "/bat" (:uri (:req resp))))))

(deftest pass-on-non-redirect
  (let [client (fn [req] {:status 200 :body (:body req)})
        r-client (client/wrap-redirects client)
        resp (r-client {:body "ok"})]
    (is (= 200 (:status resp)))
    (is (= "ok" (:body resp)))))

(deftest pass-on-follow-redirects-false
  (let [client (fn [req] {:status 302 :body (:body req)})
        r-client (client/wrap-redirects client)
        resp (r-client {:body "ok" :follow-redirects false})]
    (is (= 302 (:status resp)))
    (is (= "ok" (:body resp)))))

(deftest throw-on-exceptional
  (let [client (fn [_req] {:status 500})
        e-client (client/wrap-exceptions client)]
    (is (thrown-with-msg? Exception #"500"
          (e-client {})))))

(deftest pass-on-non-exceptional
  (let [client (fn [_req] {:status 200})
        e-client (client/wrap-exceptions client)
        resp (e-client {})]
    (is (= 200 (:status resp)))))

(deftest pass-on-exceptional-when-surpressed
  (let [client (fn [_req] {:status 500})
        e-client (client/wrap-exceptions client)
        resp (e-client {:throw-exceptions false})]
    (is (= 500 (:status resp)))))

(deftest apply-on-compressed
  (let [client (fn [req]
                 (is (= "gzip, deflate"
                        (get-in req [:headers "Accept-Encoding"])))
                 {:body (util/gzip (util/utf8-bytes "foofoofooƒ⊙⊙"))
                  :headers {"Content-Encoding" "gzip"}})
        c-client (client/wrap-decompression client)
        resp (c-client {})]
    (is (= "foofoofooƒ⊙⊙" (util/utf8-string (:body resp))))))

(deftest apply-on-deflated
  (let [client (fn [req]
                 (is (= "gzip, deflate"
                        (get-in req [:headers "Accept-Encoding"])))
                 {:body (util/deflate (util/utf8-bytes "barbarbar⒝⒜⒭"))
                  :headers {"Content-Encoding" "deflate"}})
        c-client (client/wrap-decompression client)
        resp (c-client {})]
    (is (= "barbarbar⒝⒜⒭" (util/utf8-string (:body resp))))))

(deftest pass-on-non-compressed
  (let [c-client (client/wrap-decompression (fn [_req] {:body "foo"}))
        resp (c-client {:uri "/foo"})]
    (is (= "foo" (:body resp)))))

(deftest apply-on-accept
  (is-applied client/wrap-accept
              {:accept :json}
              {:headers {"Accept" "application/json"}}))

(deftest pass-on-no-accept
  (is-passed client/wrap-accept
             {:uri "/foo"}))

(deftest apply-on-oauth
  (is-applied client/wrap-oauth
              {:oauth-token "sample-token"}
              {:headers {"Authorization" "Bearer sample-token"}}))

(deftest pass-on-no-oauth
  (is-passed client/wrap-oauth
             {:uri "/foo"}))

(deftest apply-on-accept-encoding
  (is-applied client/wrap-accept-encoding
              {:accept-encoding [:identity :gzip]}
              {:headers {"Accept-Encoding" "identity, gzip"}}))

(deftest pass-on-no-accept-encoding
  (is-passed client/wrap-accept-encoding
             {:uri "/foo"}))

(deftest apply-on-utf8-output-coercion
  (let [client (fn [_req] {:body (util/utf8-bytes "fooⓕⓞⓞ")})
        o-client (client/wrap-output-coercion client)
        resp (o-client {:uri "/foo"})]
    (is (= "fooⓕⓞⓞ" (:body resp)))))

(deftest apply-on-other-output-coercion
  (let [client (fn [_req] {:body (.getBytes "sõme ßÒññÝ chÀråcters" "ISO-8859-1")
                          :headers {"content-type" "text/foo;charset=ISO-8859-1"}})
        o-client (client/wrap-output-coercion client)
        resp (o-client {:uri "/foo" :as :auto})]
    (is (= "sõme ßÒññÝ chÀråcters" (:body resp)))))

(deftest pass-on-no-output-coercion
  (let [client (fn [_req] {:body nil})
        o-client (client/wrap-output-coercion client)
        resp (o-client {:uri "/foo"})]
    (is (nil? (:body resp))))
  (let [client (fn [_req] {:body :thebytes})
        o-client (client/wrap-output-coercion client)
        resp (o-client {:uri "/foo" :as :byte-array})]
    (is (= :thebytes (:body resp)))))

(deftest apply-on-input-coercion
  (let [i-client (client/wrap-input-coercion identity)]
    (doseq [[in-body encoding expected-encoding] [["μτƒ8 нαs мαηλ ςнαяαςτεяs ൠ" nil            "UTF-8"]
                                                  ["μτƒ8 нαs мαηλ ςнαяαςτεяs ൠ" "UTF-8"        "UTF-8"]
                                                  ["plain text"                "ASCII"        "ASCII"]
                                                  ["sõme ßÒññÝ chÀråcters"     "iso-8859-1"   "iso-8859-1"]]]
      (let [resp (i-client {:body in-body :body-encoding encoding})
            decoded-body (slurp (:body resp) :encoding expected-encoding)]
        (is (= expected-encoding (:character-encoding resp)) "character encoding")
        (is (= in-body decoded-body) "body")))))

(deftest pass-on-no-input-coercion
  (is-passed client/wrap-input-coercion
             {:body nil}))

(deftest apply-on-content-type
  (is-applied client/wrap-content-type
              {:content-type :json}
              {:content-type "application/json"}))

(deftest pass-on-no-content-type
  (is-passed client/wrap-content-type
             {:uri "/foo"}))

(deftest apply-on-query-params
  (is-applied client/wrap-query-params
              {:query-params {"foo" "bar" "dir" "<<"}}
              {:query-string "foo=bar&dir=%3C%3C"}))

(deftest pass-on-no-query-params
  (is-passed client/wrap-query-params
             {:uri "/foo"}))

(deftest apply-on-basic-auth
  (is-applied client/wrap-basic-auth
              {:basic-auth ["Aladdin" "open sesame"]}
              {:headers {"Authorization"
                         "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="}}))

(deftest pass-on-no-basic-auth
  (is-passed client/wrap-basic-auth
             {:uri "/foo"}))

(deftest apply-on-method
  (let [m-client (client/wrap-method identity)
        echo (m-client {:key :val :method :post})]
    (is (= :val (:key echo)))
    (is (= :post (:request-method echo)))
    (is (not (:method echo)))))

(deftest pass-on-no-method
  (let [m-client (client/wrap-method identity)
        echo (m-client {:key :val})]
    (is (= :val (:key echo)))
    (is (not (:request-method echo)))))

(deftest apply-on-url
  (let [u-client (client/wrap-url identity)
        resp (u-client {:url "http://google.com:8080/foo?bar=bat"})]
    (is (= :http (:scheme resp)))
    (is (= "google.com" (:server-name resp)))
    (is (= 8080 (:server-port resp)))
    (is (= "/foo" (:uri resp)))
    (is (= "bar=bat" (:query-string resp)))))

(deftest pass-on-no-url
  (let [u-client (client/wrap-url identity)
        resp (u-client {:uri "/foo"})]
    (is (= "/foo" (:uri resp)))))

(deftest provide-default-port
  (is (= nil  (-> "http://example.com/" client/parse-url :server-port)))
  (is (= 8080 (-> "http://example.com:8080/" client/parse-url :server-port)))
  (is (= nil  (-> "https://example.com/" client/parse-url :server-port)))
  (is (= 8443 (-> "https://example.com:8443/" client/parse-url :server-port))))

(deftest apply-on-form-params
  (testing "With form params"
    (let [param-client (client/wrap-form-params identity)
          resp (param-client {:request-method :post
                              :form-params {:param1 "value1"
                                            :param2 "value2"}})]
      (is (or (= "param1=value1&param2=value2" (:body resp))
              (= "param2=value2&param1=value1" (:body resp))))
      (is (= "application/x-www-form-urlencoded" (:content-type resp)))
      (is (not (contains? resp :form-params)))))
  (testing "Ensure it does not affect GET requests"
    (let [param-client (client/wrap-form-params identity)
          resp (param-client {:request-method :get
                              :body "untouched"
                              :form-params {:param1 "value1"
                                            :param2 "value2"}})]
      (is (= "untouched" (:body resp)))
      (is (not (contains? resp :content-type)))))

  (testing "with no form params"
    (let [param-client (client/wrap-form-params identity)
          resp (param-client {:body "untouched"})]
      (is (= "untouched" (:body resp)))
      (is (not (contains? resp :content-type))))))

(deftest apply-on-nest-params
  (let [param-client (client/wrap-nested-params identity)
        params {:a
                {:b
                 {:c 5}
                 :e
                 {:f 6}}
                :g 7}
        resp (param-client {:form-params params :query-params params})]
    (is (= {"a[b][c]" 5 "a[e][f]" 6 :g 7} (:form-params resp) (:query-params resp)))))

(deftest pass-on-no-nest-params
  (let [m-client (client/wrap-nested-params identity)
        in {:key :val}
        out (m-client in)]
    (is (= out in))))

(deftest t-ignore-unknown-host
  (is (thrown? UnknownHostException (client/get "http://aorecuf892983a.com")))
  (is (nil? (client/get "http://aorecuf892983a.com"
                        {:ignore-unknown-host? true}))))
