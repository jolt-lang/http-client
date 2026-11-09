(ns jolt.http.client-options-test
  "The babashka.http-client request options jolt.http-client takes on top of
  clj-http-lite's: :multipart, :form-params on any method, :query-params
  merged into the URL's query, :basic-auth as a map, keyword header names,
  :throw, :as :bytes, :async, and patch. The cases follow babashka's own
  suite, against the same in-process routes the :bhctest suite uses."
  (:require [jolt.http.platform]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [jolt.http-client :as http]
            [jolt.http.bhc-routes :as routes]
            [jolt.http.multipart :as mp]
            [jolt.http.test-server :as srv]
            [multipart.core :as multipart]))

(def ^:private port 18140)
(def ^:private base (str "http://localhost:" port))

(use-fixtures :once
  (fn [t]
    (let [s (srv/start-plain port {:handler routes/handler})]
      (try (t) (finally (srv/stop s))))))

(defn- parse-multipart
  "The parts of the multipart body /multipart echoed. The test server reads a
  request body as latin-1 and writes a string back as UTF-8, so the body
  decoded as UTF-8 (the default) is the request's bytes as latin-1."
  [r]
  (multipart/parse-form-data {:headers {"content-type" (get-in r [:headers "content-type"])}
                              :body (.getBytes ^String (:body r) "ISO-8859-1")}))

(defn- header-line [body nm]
  (some (fn [line] (when (str/starts-with? (str/lower-case line) (str (str/lower-case nm) ": "))
                     (subs line (+ 2 (count nm)))))
        (str/split-lines body)))

;; --- multipart ------------------------------------------------------------------

(deftest multipart-request
  (let [r (http/post (str base "/multipart")
                     {:multipart [{:name "title" :content "My Title"}
                                  {:name "field" :part-name "renamed" :content "value"}
                                  {:name "file" :content "file contents" :file-name "a.txt"
                                   :content-type "text/plain"}]})
        parsed (parse-multipart r)]
    (is (str/starts-with? (get-in r [:headers "content-type"]) "multipart/form-data; boundary="))
    (is (= "My Title" (get-in parsed [:params "title"])))
    (is (= "value" (get-in parsed [:params "renamed"])))
    (let [f (get-in parsed [:files "file"])]
      (is (= "a.txt" (:filename f)))
      (is (= "text/plain" (:content-type f)))
      (is (= "file contents" (String. ^bytes (:bytes f) "UTF-8"))))))

(deftest multipart-binary-parts
  (let [png (byte-array (map unchecked-byte [0x89 0x50 0x4e 0x47 0x0d 0x0a 0x1a 0x0a 0 255 128]))
        f (java.io.File/createTempFile "jolt-mp" ".png")
        _ (with-open [o (io/output-stream f)] (.write o png))
        r (http/post (str base "/multipart")
                     {:multipart [{:name "photo" :content f}
                                  {:name "raw" :content png :file-name "raw.bin"}
                                  {:name "stream" :content (io/input-stream png) :file-name "s.bin"
                                   :mime-type "image/png"}]})
        files (:files (parse-multipart r))]
    (testing "a File part takes its name and a type from its extension"
      (is (= (.getName f) (get-in files ["photo" :filename])))
      (is (= "image/png" (get-in files ["photo" :content-type]))))
    (testing "the bytes arrive intact, from a File, a byte array and a stream"
      (doseq [k ["photo" "raw" "stream"]]
        (is (= (seq png) (seq (get-in files [k :bytes]))) k)))
    (is (= "application/octet-stream" (get-in files ["raw" :content-type])))
    (is (= "image/png" (get-in files ["stream" :content-type])))
    (.delete f)))

(deftest multipart-overrides-content-type
  (let [r (http/post (str base "/multipart")
                     {:headers {"content-type" "application/json"} :content-type :json
                      :multipart [{:name "a" :content "b"}]})]
    (is (str/starts-with? (get-in r [:headers "content-type"]) "multipart/form-data"))))

(deftest multipart-part-checks
  (is (thrown? Exception (http/post (str base "/multipart") {:multipart [{:content "x"}]})))
  (is (thrown? Exception (http/post (str base "/multipart") {:multipart [{:name "a"}]}))))

(deftest multipart-body-shape
  (testing "the wire format babashka.http-client writes"
    (is (= (str "--B\r\n"
                "Content-Disposition: form-data; name=\"a\"\r\n"
                "Content-Type: text/plain; charset=UTF-8\r\n"
                "Content-Transfer-Encoding: 8bit\r\n"
                "\r\n"
                "b\r\n"
                "--B--\r\n")
           (String. ^bytes (mp/body-bytes [{:name "a" :content "b"}] "B") "UTF-8"))))
  ;; the JDK's built-in table, which matches extensions in any case
  (is (= "application/pdf" (mp/file-content-type (io/file "x.PDF"))))
  (is (= "application/octet-stream" (mp/file-content-type (io/file "noext")))))

;; --- form and query params ---------------------------------------------------------

(deftest form-params-on-any-method
  (doseq [f [http/post http/put http/patch http/delete]]
    (let [r (f (str base "/multipart") {:form-params {:a "1 2" "b" "x&y"}})]
      ;; a string body carries its charset, as clj-http-lite's POST form params do
      (is (= "application/x-www-form-urlencoded; charset=UTF-8" (get-in r [:headers "content-type"])))
      (is (= #{"a=1+2" "b=x%26y"} (set (str/split (:body r) #"&")))))))

(deftest form-params-keep-an-explicit-content-type
  (let [r (http/put (str base "/multipart") {:form-params {:a 1} :content-type "text/plain"})]
    (is (= "text/plain; charset=UTF-8" (get-in r [:headers "content-type"])))))

(deftest query-params-merge-with-the-url
  (is (= "x=1&a=2" (:body (http/get (str base "/query?x=1") {:query-params {:a 2}}))))
  (is (= "a=1&a=2&b=c" (:body (http/get (str base "/query") {:query-params (array-map :a #{1 2} :b "c")}))))
  (is (= "a=1&a=2" (:body (http/get (str base "/query") {:query-params {:a (list 1 2)}}))))
  (is (= "x=1" (:body (http/get (str base "/query?x=1"))))))

;; --- auth, headers, aliases -------------------------------------------------------

(deftest basic-auth-map
  (is (= "welcome" (:body (http/get (str base "/basic-auth")
                                    {:basic-auth {:user "username" :pass "password"}}))))
  (is (= "welcome" (:body (http/get (str base "/basic-auth")
                                    {:basic-auth ["username" "password"]})))))

(deftest keyword-header-names
  (let [b (:body (http/get (str base "/get") {:headers {:x-custom "yes" "X-Other" "too"}}))]
    (is (= "yes" (header-line b "x-custom")))
    (is (= "too" (header-line b "x-other"))))
  (is (= "token=abc" (:body (http/get (str base "/bearer") {:headers {:authorization "Bearer abc"}})))))

(deftest throw-alias
  (is (thrown? Exception (http/get (str base "/404"))))
  (is (= 404 (:status (http/get (str base "/404") {:throw false}))))
  (is (= 404 (:status (http/get (str base "/404") {:throw-exceptions false})))))

(deftest as-bytes
  (let [r (http/get (str base "/200") {:as :bytes})]
    (is (bytes? (:body r)))
    (is (= "200 OK" (String. ^bytes (:body r) "UTF-8")))))

(deftest patch-method
  (is (= "PATCH" (:body (http/patch (str base "/method"))))))

;; --- async ------------------------------------------------------------------------

(deftest async-request
  (is (= 200 (:status @(http/get (str base "/200") {:async true}))))
  (is (= "200 OK" @(http/get (str base "/200") {:async true :async-then :body})))
  (testing "a failure goes to :async-catch with babashka's keys"
    (let [r @(http/get (str base "/404") {:async true
                                         :async-catch (fn [e] [(:status (:ex-data e))
                                                               (some? (:ex e))
                                                               (string? (:ex-message e))
                                                               (map? (:request e))])})]
      (is (= [404 true true true] r))))
  (testing "without :async-catch the future rethrows on deref"
    (is (thrown? Exception @(http/get (str base "/404") {:async true}))))
  (testing "deref with a timeout"
    (is (= ::late (deref (http/get (str base "/slow") {:async true}) 50 ::late)))))
