(ns jolt.http-client
  "HTTP client for Jolt — clj-http-lite with Jolt platform support installed
  (java.net.HttpURLConnection / URL over Janet sockets, TLS via OpenSSL FFI,
  gzip/deflate via libz FFI). Require this namespace and use the functions below
  exactly like clj-http.lite.client.

      (require '[jolt.http-client :as http])
      (http/get \"https://example.com\")
      (http/post \"http://localhost:8080/x\" {:body \"hi\" :content-type :json})"
  (:require [jolt.http.platform]            ;; side effect: installs host shims
            [clj-http.lite.client :as client])
  (:refer-clojure :exclude [get update]))

(def request client/request)

(defn get    [url & [req]] (client/get url req))
(defn head   [url & [req]] (client/head url req))
(defn post   [url & [req]] (client/post url req))
(defn put    [url & [req]] (client/put url req))
(defn delete [url & [req]] (client/delete url req))
