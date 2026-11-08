(ns jolt.http-client
  "HTTP client for Jolt — clj-http-lite with Jolt platform support installed
  (java.net.HttpURLConnection / URL over jolt.ffi BSD sockets, TLS via OpenSSL,
  gzip/deflate via java.util.zip). Require this namespace and use the functions
  below like clj-http.lite.client.

      (require '[jolt.http-client :as http])
      (http/get \"https://example.com\")
      (http/post \"http://localhost:8080/x\" {:body \"hi\" :content-type :json})

  On top of clj-http-lite's options, `request` takes the following from
  babashka.http-client (https://github.com/babashka/http-client, Copyright (c)
  Michiel Borkent, MIT License, see licenses/babashka-http-client.LICENSE), so
  a request map written for either client
  works here:

    :multipart     [{:name \"field\" :content \"text\"}
                    {:name \"file\" :content (io/file \"a.png\") :file-name \"a.png\"
                     :content-type \"image/png\"}]
                   builds a multipart/form-data body (see jolt.http.multipart)
    :form-params   url-encoded on any method with a body, not only POST
    :query-params  appended to a query already in the URL rather than
                   replacing it; a collection value repeats the key
    :basic-auth    also {:user \"u\" :pass \"p\"}
    :headers       keyword names too: {:authorization \"Bearer x\"}
    :throw         false — the same as :throw-exceptions false
    :as            :bytes — the same as :byte-array
    :async         true runs the request on a future and answers it; with
                   :async-then / :async-catch fns the future answers their
                   result, as babashka.http-client's does"
  (:require [jolt.http.platform]            ;; side effect: installs host shims
            [clj-http.lite.client :as client]
            [clj-http.lite.core :as core]
            [clj-http.lite.links :refer [wrap-links]]
            [clojure.string :as str]
            [jolt.http.multipart :as multipart])
  (:refer-clojure :exclude [get update]))

;; --- middleware ported from babashka.http-client ----------------------------------

(defn- header-name [k] (if (keyword? k) (name k) (str k)))

(defn- dissoc-header
  "`headers` without any entry named `n`, whatever its case or key type."
  [headers n]
  (into {} (remove (fn [[k _]] (= (str/lower-case (header-name k)) (str/lower-case n)))) headers))

(defn wrap-request-aliases
  "babashka.http-client's spellings, normalized to clj-http-lite's before
  the rest of the chain sees the request: :throw, :as :bytes, :basic-auth
  {:user :pass}, keyword header names."
  [client]
  (fn [req]
    (client
     (cond-> req
       (contains? req :throw)
       (-> (assoc :throw-exceptions (boolean (:throw req))) (dissoc :throw))

       (= :bytes (:as req))
       (assoc :as :byte-array)

       (map? (:basic-auth req))
       (assoc :basic-auth [(:user (:basic-auth req)) (:pass (:basic-auth req))])

       (some keyword? (keys (:headers req)))
       (assoc :headers (into {} (map (fn [[k v]] [(header-name k) v])) (:headers req)))))))

(defn wrap-multipart
  "Request: a :multipart vector of parts becomes the body, and the
  Content-Type becomes multipart/form-data with the body's boundary,
  replacing any other. After babashka.http-client's `multipart`
  interceptor."
  [client]
  (fn [{:keys [multipart] :as req}]
    (if multipart
      (let [b (multipart/boundary)]
        (client (-> req
                    (dissoc :multipart :content-type :character-encoding :body-encoding)
                    (assoc :body (multipart/body multipart b))
                    (clojure.core/update :headers #(-> (dissoc-header % "content-type")
                                                       (assoc "Content-Type" (multipart/content-type-header b)))))))
      (client req))))

(defn wrap-form-params
  "Request: :form-params become an x-www-form-urlencoded body on any
  method but GET and HEAD (clj-http-lite only encodes them on POST). An
  explicit :content-type is kept, as babashka.http-client keeps one."
  [client]
  (fn [{:keys [form-params request-method] :as req}]
    (if (and form-params (not (#{:get :head} request-method)))
      (client (-> req
                  (dissoc :form-params)
                  (assoc :content-type (or (:content-type req)
                                           (client/content-type-value :x-www-form-urlencoded))
                         :body (client/generate-query-string form-params))))
      (client req))))

(defn- seq-params
  "Collection values (not only vectors) repeat their key, as in
  babashka.http-client's query params."
  [params]
  (into {} (map (fn [[k v]] [k (if (and (coll? v) (not (map? v))) (vec v) v)])) params))

(defn wrap-query-params
  "Request: :query-params are encoded and appended to the query string the
  URL already carries, rather than replacing it. After
  babashka.http-client's `query-params` interceptor."
  [client]
  (fn [{:keys [query-params query-string] :as req}]
    (if query-params
      (let [q (client/generate-query-string (seq-params query-params))]
        (client (-> req
                    (dissoc :query-params)
                    (assoc :query-string (if (str/blank? query-string) q (str query-string "&" q))))))
      (client req))))

(defn wrap-request
  "clj-http-lite's batteries-included chain (clj-http.lite.client/wrap-request)
  with babashka.http-client's request options added. As there, the request
  passes through these from the last to the first."
  [request]
  (-> request
      wrap-query-params
      client/wrap-basic-auth
      client/wrap-oauth
      client/wrap-user-info
      client/wrap-url
      client/wrap-redirects
      client/wrap-decompression
      client/wrap-input-coercion
      client/wrap-output-coercion
      client/wrap-exceptions
      client/wrap-accept
      client/wrap-accept-encoding
      client/wrap-content-type
      wrap-multipart
      wrap-form-params
      client/wrap-nested-params
      client/wrap-method
      wrap-links
      client/wrap-unknown-host
      wrap-request-aliases))

(def ^:private request* (wrap-request #'core/request))

(defn request
  "Executes the HTTP request map `req` and answers the response map. Takes
  every clj-http-lite option (see clj-http.lite.client/request) and the
  babashka.http-client ones listed in this namespace's doc. With :async
  true, answers a future of the response instead."
  [req]
  (if (:async req)
    (let [{:keys [async-then async-catch]} req
          req (dissoc req :async :async-then :async-catch)]
      (future
        (try (let [resp (request* req)]
               (if async-then (async-then resp) resp))
             (catch Exception e
               (if async-catch
                 ;; babashka.http-client's shape for the failure
                 (let [cause (ex-cause e)]
                   (async-catch {:ex e
                                 :ex-cause cause
                                 :ex-data (ex-data (or cause e))
                                 :ex-message (ex-message (or cause e))
                                 :request req}))
                 (throw e))))))
    (request* req)))

(defn get    [url & [req]] (request (merge req {:method :get :url url})))
(defn head   [url & [req]] (request (merge req {:method :head :url url})))
(defn post   [url & [req]] (request (merge req {:method :post :url url})))
(defn put    [url & [req]] (request (merge req {:method :put :url url})))
(defn patch  [url & [req]] (request (merge req {:method :patch :url url})))
(defn delete [url & [req]] (request (merge req {:method :delete :url url})))
