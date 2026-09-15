(ns jolt.http.bhc-routes
  "Routes for the babashka.http-client suite, modelled on the ones that suite
  drives against http-kit (echo the request, compressed bodies, redirect chains,
  status codes, auth challenges, cookies). Plain text rather than JSON — the
  assertions are about the HTTP client, not about a JSON codec."
  (:require [clojure.string :as str]
            [jolt.http.test-server :as srv]
            [jolt.http.zlib :as zlib]))

(defn- latin1 [s] (.getBytes ^String s "ISO-8859-1"))

(defn- trickle!
  "Hijack the connection and dribble `n` events out with `gap` ms between them,
  so a client reading the body sees it arrive rather than all at once. `frame`
  wraps one event's text for the wire; `tail`, when given, closes the message
  off, and `hold` is how long the socket then stays open — a hijacked handler
  owns the close, so this is what decides whether the peer's close and the end
  of the body are the same event."
  [conn head frame tail n gap hold]
  (let [send! (fn [s] (srv/conn-write conn (latin1 s)))]
    (send! head)
    (dotimes [i n]
      (send! (frame (str "data: tick " i "\n")))
      (Thread/sleep gap))
    (when tail (send! tail))
    (when (pos? hold) (Thread/sleep hold))
    (srv/conn-close conn)
    :hijacked))

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

      ;; --- bodies that arrive over time (gh-1007) -----------------------------
      ;; A live stream is the one body a client cannot read to completion before
      ;; handing it over, so these hold the connection open between events. Both
      ;; framings, because they end differently: /trickle ends when the peer
      ;; closes, /trickle-chunked at its terminal chunk — and that one then HOLDS
      ;; the socket open, so a client that mistook close for end-of-body would
      ;; hang instead of finishing.
      (= uri "/trickle")
      (trickle! (:conn req)
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
                identity
                nil 3 250 0)

      (= uri "/trickle-chunked")
      (trickle! (:conn req)
                (str "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                     "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n")
                (fn [ev] (str (Integer/toHexString (count ev)) "\r\n" ev "\r\n"))
                "0\r\n\r\n" 3 250 1000)

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
