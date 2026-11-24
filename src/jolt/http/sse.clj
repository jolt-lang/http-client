(ns jolt.http.sse
  "Server-sent events: reading a `text/event-stream` body as events, by the
  parsing rules of the WHATWG HTML standard (\"Server-sent events\", 9.2.6), on
  top of jolt.http-client's `:as :stream`.

      (require '[jolt.http.sse :as sse])

      (def sub (sse/subscribe! {:url \"http://localhost:3000/events\"}
                               {:on-event (fn [e] (prn (:event e) (:data e)))}))
      ((:close sub))                       ; stop reading and drop the connection

  An event is a map:
    :event  the event type, \"message\" when the stream named none
    :data   the data lines, joined with \"\\n\"
    :id     the last event id the stream has set, or nil

  This namespace reads one stream. Reconnecting, and with what delay, is the
  caller's policy: an EventSource reconnects after `retry`, Datastar after its
  own backoff. `subscribe!` reports what a reconnect needs (the last event id,
  the server's last `retry`) and leaves the decision to the caller.

  The parser is pure (`parse-line`), so it can also frame lines that arrive
  some other way."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [jolt.http-client :as http]))

;; --- parsing -------------------------------------------------------------------

(def initial-state
  "A parser state for a fresh stream. Pass `:id` to resume after a reconnect,
  so events that set no id keep the one the last stream ended with."
  {:event nil :data nil :id nil})

(defn- field-value
  "Split a line into [field value]: the value after the first colon, less one
  leading space; a line with no colon is all field, with an empty value."
  [line]
  (if-let [i (str/index-of line ":")]
    (let [v (subs line (inc i))]
      [(subs line 0 i) (if (str/starts-with? v " ") (subs v 1) v)])
    [line ""]))

(defn parse-line
  "Feed one line (no terminator) to the parser. Returns [state out], where out
  is nil, an event map (on the blank line ending one), or {:retry ms} when the
  stream sets its reconnection time."
  [state line]
  (cond
    (= "" line)
    (let [st (assoc state :event nil :data nil)]
      (if (:data state)
        [st {:event (or (:event state) "message")
             :data (str/join "\n" (:data state))
             :id (:id state)}]
        [st nil]))

    (str/starts-with? line ":") [state nil]          ; a comment

    :else
    (let [[field value] (field-value line)]
      (case field
        "event" [(assoc state :event value) nil]
        "data"  [(update state :data (fnil conj []) value) nil]
        "id"    [(if (str/includes? value "\u0000") state (assoc state :id (not-empty value))) nil]
        "retry" [state (when (re-matches #"[0-9]+" value) {:retry (Long/parseLong value)})]
        [state nil]))))

(defn parse-lines
  "Every event in `lines`, a seq of lines, in order, as a vector of event maps
  and {:retry ms} maps. For tests and for text already in hand."
  ([lines] (parse-lines initial-state lines))
  ([state lines]
   (loop [st state ls lines out []]
     (if-let [[l & more] (seq ls)]
       (let [[st' o] (parse-line st l)] (recur st' more (if o (conj out o) out)))
       out))))

;; --- reading a stream ------------------------------------------------------------

(defn read-events!
  "Read events off `reader` (a java.io.BufferedReader) until the stream ends,
  calling (on-event event) for each and (on-retry ms) when the server sets its
  reconnection time. Blocks. Returns the last event id, for a reconnect's
  Last-Event-ID. A leading byte order mark is skipped."
  [^java.io.BufferedReader reader {:keys [on-event on-retry id]}]
  (loop [st (assoc initial-state :id id) first? true]
    (if-let [line (.readLine reader)]
      (let [line (if (and first? (str/starts-with? line "\uFEFF")) (subs line 1) line)
            [st' out] (parse-line st line)]
        (cond
          (:retry out) (when on-retry (on-retry (:retry out)))
          out (when on-event (on-event out)))
        (recur st' false))
      (:id st))))

(defn- event-stream? [resp]
  (let [ct (some (fn [[k v]] (when (= "content-type" (str/lower-case (name k))) v)) (:headers resp))]
    (and ct (str/starts-with? (str/lower-case (str ct)) "text/event-stream"))))

(defn subscribe!
  "Open `request` (a jolt.http-client request map: :url, and :method, :body,
  :headers as for any request) as an event stream and read it on a future.
  Sends Accept: text/event-stream and, with `:last-event-id`, Last-Event-ID.

  `handlers`:
    :on-open    (fn [response]) once the headers are in; the body is the stream
    :on-event   (fn [event]) for each event
    :on-retry   (fn [ms]) when the server sets its reconnection time
    :on-response (fn [response]) instead of reading, when the response is not
                 an event stream (an error status, a JSON or HTML reply); the
                 body is a stream the handler should read or close
    :on-close   (fn [{:keys [id error closed?]}]) when it is over: the last
                event id, the exception that ended it (nil for a clean end), and
                whether `close` ended it
    :last-event-id  resume after this id

  Returns {:close (fn []) :done future}. `close` stops the read and drops the
  connection; `done` derefs to what on-close was given."
  [request {:keys [on-open on-event on-retry on-response on-close last-event-id]}]
  (let [body (atom nil)
        closed? (atom false)
        finish (fn [m] (let [m (assoc m :closed? @closed?)] (when on-close (on-close m)) m))
        done (future
               (try
                 (let [headers (cond-> (merge {"Accept" "text/event-stream" "Cache-Control" "no-cache"}
                                              (:headers request))
                                 last-event-id (assoc "Last-Event-ID" last-event-id))
                       resp (http/request (merge {:method :get :throw-exceptions false}
                                                 request
                                                 {:headers headers :as :stream}))]
                   (reset! body (:body resp))
                   (if @closed?
                     (do (some-> (:body resp) .close) (finish {:id last-event-id}))
                     (if (and (<= 200 (:status resp) 299) (event-stream? resp))
                       (do (when on-open (on-open resp))
                           (let [id (with-open [r (io/reader (:body resp))]
                                      (read-events! r {:on-event on-event :on-retry on-retry
                                                       :id last-event-id}))]
                             (finish {:id id})))
                       (do (if on-response
                             (on-response resp)
                             (some-> (:body resp) .close))
                           (finish {:id last-event-id :response (dissoc resp :body)})))))
                 (catch Throwable e
                   (finish {:id last-event-id :error (when-not @closed? e)}))))]
    {:close (fn []
              (reset! closed? true)
              (when-let [b @body] (try (.close b) (catch Throwable _ nil)))
              nil)
     :done done}))
