(ns jolt.http.bhc-routes
  "Routes for the babashka.http-client suite, modelled on the ones that suite
  drives against http-kit (echo the request, compressed bodies, redirect chains,
  status codes, auth challenges, cookies). Plain text rather than JSON — the
  assertions are about the HTTP client, not about a JSON codec."
  (:require [clojure.string :as str]
            [jolt.http.zlib :as zlib]))

;; built once: (byte-array (repeat n …)) walks a boxed seq, and paying that per
;; request would put the server, not the client, in the throughput measurement
(def ^:private big-body (byte-array (repeat (* 8 1024 1024) (byte 65))))

(defn- echo-headers [req]
  (str/join "\n" (map (fn [[k v]] (str k ": " v)) (sort (:headers req)))))

(def ^:private basic-creds "Basic dXNlcm5hbWU6cGFzc3dvcmQ=")   ; username:password

(defn handler [req]
  (let [uri (:uri req)
        m (:request-method req)
        h (:headers req)
        body (:body-raw req)]
    (cond
      ;; echoes every request header, one per line
      (= uri "/get") {:status 200 :body (echo-headers req)}
      ;; echoes the request target, so a fragment reaching the wire is visible
      (= uri "/echo-target") {:status 200 :body (:target req)}
      ;; length + checksum of the body as received, without re-encoding it
      (= uri "/body-info")
      {:status 200 :body (str (count body) " " (reduce + 0 (map int body)))}
      (= uri "/big") {:status 200 :body big-body}

      ;; a Location with no leading slash: resolves against the base directory
      (= uri "/deep/rel-redirect") {:status 302 :headers {"location" "target"} :body ""}
      (= uri "/deep/dot-redirect") {:status 302 :headers {"location" "../target"} :body ""}
      (= uri "/deep/target") {:status 200 :body "deep-target"}
      (= uri "/target") {:status 200 :body "root-target"}

      (= uri "/secure-cookie")
      {:status 200 :headers {"Set-Cookie" ["sec=1; Path=/; Secure" "plain=1; Path=/"]} :body "set"}
      (= uri "/expire-cookie") {:status 200 :headers {"Set-Cookie" "a=1; Path=/; Max-Age=0"} :body "gone"}
      (= uri "/past-cookie")
      {:status 200
       :headers {"Set-Cookie" "old=1; Path=/; Expires=Wed, 21 Oct 2015 07:28:00 GMT"}
       :body "gone"}
      ;; echoes the request body verbatim
      (= uri "/echo") {:status 200 :body body}
      ;; echoes the method, so :method / :request-method routing is visible
      (= uri "/method") {:status 200 :body (str/upper-case (name m))}
      ;; echoes the query string
      (= uri "/query") {:status 200 :body (or (:query req) "")}

      (= uri "/gzip")
      {:status 200
       :headers {"content-type" "text/plain" "content-encoding" "gzip"}
       :body (zlib/gzip (.getBytes "gzipped body" "UTF-8"))}

      (= uri "/deflate")
      {:status 200
       :headers {"content-type" "text/plain" "content-encoding" "deflate"}
       :body (zlib/zlib-deflate (.getBytes "deflated body" "UTF-8"))}

      ;; the framing servers actually send about half the time, and the one a
      ;; default Inflater cannot read
      (= uri "/raw-deflate")
      {:status 200
       :headers {"content-type" "text/plain" "content-encoding" "deflate"}
       :body (zlib/raw-deflate (.getBytes "raw deflated body" "UTF-8"))}

      (= uri "/bearer")
      (if-let [token (second (re-find #"^Bearer (.+)$" (or (get h "authorization") "")))]
        {:status 200 :body (str "token=" token)}
        {:status 401 :body "401 Unauthorized"})

      (= uri "/basic-auth")
      (if (= basic-creds (get h "authorization"))
        {:status 200 :body "welcome"}
        {:status 401 :body "denied"})

      ;; the Authenticator flow: challenge, then accept the credentials
      (= uri "/auth-challenge")
      (if (get h "authorization")
        {:status 200 :body (str "authorized: " (get h "authorization"))}
        {:status 401 :headers {"WWW-Authenticate" "Basic realm=\"jolt\""} :body "challenge"})

      (= uri "/set-cookie")
      {:status 200
       :headers {"Set-Cookie" ["a=1; Path=/" "b=2; Path=/; Domain=localhost"]}
       :body "cookies set"}

      ;; a path-scoped cookie: only /deep/... should ever see it
      (= uri "/set-cookie-path")
      {:status 200 :headers {"Set-Cookie" "deep=1; Path=/deep"} :body "path cookie set"}

      (or (= uri "/cookies") (= uri "/deep/cookies"))
      {:status 200 :body (or (get h "cookie") "")}

      ;; echoes content-type + body, which is what a multipart assertion needs
      (= uri "/multipart")
      {:status 200
       :headers {"content-type" (or (get h "content-type") "")}
       :body body}

      (= uri "/slow") (do (Thread/sleep 1500) {:status 200 :body "slow"})

      (= uri "/redirect-to")
      {:status 302 :headers {"location" (second (str/split (str (:query req)) #"url="))} :body ""}

      (= uri "/no-content") {:status 204 :body ""}

      :else
      (if-let [n (some-> (re-find #"^/redirect/(\d+)$" uri) second parse-long)]
        {:status 302 :headers {"location" (if (> n 1) (str "/redirect/" (dec n)) "/200")} :body ""}
        (let [status (parse-long (subs uri 1))]
          (case status
            200 {:status 200 :body (if (str/blank? body) "200 OK" body)}
            302 {:status 302 :headers {"location" "/200"} :body ""}
            303 {:status 303 :headers {"location" "/method"} :body ""}
            307 {:status 307 :headers {"location" "/method"} :body ""}
            nil {:status 404 :body "404 Not Found"}
            {:status status :body (str status)}))))))
