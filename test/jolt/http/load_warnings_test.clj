(ns jolt.http.load-warnings-test
  "Loading the library prints nothing. A def that shadows a clojure.core var
  (jolt.http.tls/chunk did, #46) warns on stderr once per process, which lands
  in the output of any script whose stdout or stderr is consumed. The load
  runs in a fresh jolt process: in this one every namespace is already loaded,
  and a reload re-interns the var without warning."
  (:require [clojure.java.shell :as sh]
            [clojure.string :as str]
            [clojure.test :refer [deftest is]]))

(def ^:private library-namespaces
  '[jolt.http-client jolt.http.core jolt.http.jdk jolt.http.multipart
    jolt.http.net jolt.http.pkcs12 jolt.http.platform jolt.http.tls jolt.http.websocket])

;; JOLT_PWD is set by CI, not by an interactive `jolt -M:test`
(defn- project-dir []
  (or (jolt.host/getenv "JOLT_PWD") (System/getProperty "user.dir")))

(deftest loading-the-library-prints-no-warnings
  (let [{:keys [exit out err]}
        (sh/sh "jolt" "-e" (pr-str (list* 'require (map #(list 'quote %) library-namespaces)))
               :dir (project-dir))]
    (is (zero? exit) err)
    (is (str/blank? out) out)
    (is (str/blank? err) err)))
