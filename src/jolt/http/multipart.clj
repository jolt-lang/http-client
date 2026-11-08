(ns jolt.http.multipart
  "multipart/form-data request bodies for jolt.http-client.

  Ported from babashka.http-client's internal multipart namespace
  (https://github.com/babashka/http-client, src/babashka/http_client/internal/multipart.clj),
  Copyright (c) Michiel Borkent, MIT License (licenses/babashka-http-client.LICENSE)
  — itself largely inspired by hato
  (https://github.com/gnarroway/hato), MIT License. The part format, the
  `:multipart` part keys and the boundary prefix are babashka's, so a request
  built for babashka.http-client builds the same body here.

  Changes from the original: a File part with no :content-type is typed from
  its extension when java.nio.file.Files/probeContentType has no answer (it
  answers nil on jolt), byte arrays are accepted as content, and the body is
  also available as bytes for transports that want a length up front."
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.io File InputStream]))

;; A part is a map:
;;   :name          the form field name (required)
;;   :part-name     overrides :name in the Content-Disposition
;;   :content       a String, File, InputStream, byte array, or anything
;;                  clojure.java.io/input-stream accepts
;;   :file-name     the filename; defaults to a File's own name
;;   :content-type  the part's media type; :mime-type is accepted too

(def ^:private extension-types
  {"txt" "text/plain" "html" "text/html" "htm" "text/html" "css" "text/css"
   "csv" "text/csv" "xml" "application/xml" "json" "application/json"
   "js" "text/javascript" "edn" "application/edn" "md" "text/markdown"
   "pdf" "application/pdf" "zip" "application/zip" "gz" "application/gzip"
   "tar" "application/x-tar" "png" "image/png" "jpg" "image/jpeg"
   "jpeg" "image/jpeg" "gif" "image/gif" "webp" "image/webp" "svg" "image/svg+xml"
   "bmp" "image/bmp" "ico" "image/x-icon" "mp3" "audio/mpeg" "wav" "audio/wav"
   "ogg" "audio/ogg" "mp4" "video/mp4" "webm" "video/webm" "mov" "video/quicktime"})

(defn file-content-type
  "The media type of `f`: what the platform probes, else its extension's,
  else application/octet-stream."
  [^File f]
  (or (try (java.nio.file.Files/probeContentType (.toPath f)) (catch Throwable _ nil))
      (let [n (str/lower-case (.getName f))
            i (str/last-index-of n ".")]
        (when (and i (< i (dec (count n))))
          (get extension-types (subs n (inc i)))))
      "application/octet-stream"))

(defn- content-disposition
  [{:keys [part-name name content file-name]}]
  (str "Content-Disposition: form-data; "
       (format "name=\"%s\"" (or part-name name))
       (when-let [fname (or file-name
                            (when (instance? File content)
                              (.getName ^File content)))]
         (format "; filename=\"%s\"" fname))))

(defn- content-type
  [{:keys [content] :as part}]
  (str "Content-Type: "
       (cond
         (:content-type part) (:content-type part)
         (:mime-type part) (:mime-type part)
         (string? content) "text/plain; charset=UTF-8"
         (instance? File content) (file-content-type content)
         :else "application/octet-stream")))

(defn- content-transfer-encoding
  [{:keys [content]}]
  (if (string? content)
    "Content-Transfer-Encoding: 8bit"
    "Content-Transfer-Encoding: binary"))

(def crlf "\r\n")

(defn boundary
  "Creates a boundary string compliant with RFC 2046.

  See https://www.ietf.org/rfc/rfc2046.txt"
  []
  (str "babashka_http_client_Boundary" (java.util.UUID/randomUUID)))

(defn content-type-header
  "The request Content-Type for a body built with boundary `b`."
  [b]
  (str "multipart/form-data; boundary=" b))

(defn concat-streams [^InputStream is1 ^InputStream is2 & more]
  (let [is (java.io.SequenceInputStream. is1 is2)]
    (if more
      (recur is (first more) (next more))
      is)))

(defn ->input-stream [x]
  (if (string? x)
    (java.io.ByteArrayInputStream. (.getBytes ^String x "UTF-8"))
    (io/input-stream x)))

(defn- check-part! [part]
  (when-not (map? part)
    (throw (ex-info "a :multipart part must be a map" {:part part})))
  (when-not (or (:name part) (:part-name part))
    (throw (ex-info "a :multipart part needs a :name" {:part (dissoc part :content)})))
  (when (nil? (:content part))
    (throw (ex-info (str "multipart part " (or (:part-name part) (:name part)) " has no :content")
                    {:part (dissoc part :content)}))))

(defn body
  "Returns an InputStream of the multipart body for the parts `ms` with
  boundary `b`."
  [ms b]
  (doseq [m ms] (check-part! m))
  (let [streams
        (mapcat (fn [m]
                  (map ->input-stream
                       [(str "--" b)
                        crlf
                        (content-disposition m)
                        crlf
                        (content-type m)
                        crlf
                        (content-transfer-encoding m)
                        crlf
                        crlf
                        (:content m)
                        crlf]))
                ms)]
    (apply concat-streams
           (concat streams
                   [(->input-stream (str "--" b "--"))
                    (->input-stream crlf)]))))

(defn body-bytes
  "The multipart body for `ms` with boundary `b` as a byte array."
  [ms b]
  (let [out (java.io.ByteArrayOutputStream.)]
    (with-open [in (body ms b)]
      (io/copy in out))
    (.toByteArray out)))
