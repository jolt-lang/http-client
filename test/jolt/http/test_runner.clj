(ns jolt.http.test-runner
  "Runs clj-http-lite's own client / links / integration suites under Jolt. The
  suite namespaces are vendored under test/clj_http/lite; their server-process
  fixture is replaced (test_util/server_process.clj) with in-process plaintext +
  TLS servers, so no Jetty subprocess and no external checkout are needed.

  integration-test is required last: its (use-fixtures :once with-server) — the
  one that starts the servers — must be the winning :once fixture."
  (:require [jolt.http.platform]                 ;; installs the host shims
            [clojure.test :as t]
            [clj-http.lite.links-test]
            [clj-http.lite.client-test]
            [clj-http.lite.integration-test]))

(defn -main [& _]
  (let [r (t/run-tests)]
    (println (str "\n========== TOTAL =========="))
    (println (str "tests=" (:test r) " pass=" (:pass r) " fail=" (:fail r) " error=" (:error r)))
    (when (or (pos? (:fail r)) (pos? (:error r)))
      (throw (ex-info "suite failures" (select-keys r [:fail :error]))))))
