(ns jolt.http.test-runner
  "Runs clj-http-lite's own client / links / integration suites under Jolt. The
  suite namespaces are vendored under test/clj_http/lite; their server-process
  fixture is replaced (test_util/server_process.clj) with in-process plaintext +
  TLS servers, so no Jetty subprocess and no external checkout are needed.

  integration-test is required last: its (use-fixtures :once with-server) — the
  one that starts the servers — must be the winning :once fixture."
  (:require [jolt.http.platform]                 ;; installs the host shims
            [clojure.test :as t]
            [jolt.http.deps-test]
            [jolt.http.net-platform-test]
            [jolt.http.stream-shim-test]
            [jolt.http.core-test]
            [clj-http.lite.links-test]
            [clj-http.lite.client-test]
            [clj-http.lite.integration-test]))

(defn -main [& _]
  ;; Name the suites: a bare (t/run-tests) runs only *ns*, which here is not
  ;; any of them, so the runner reported 0 tests and exited clean.
  (let [r (t/run-tests 'jolt.http.deps-test
                       'jolt.http.net-platform-test
                       'jolt.http.stream-shim-test
                       'jolt.http.core-test
                       'clj-http.lite.links-test
                       'clj-http.lite.client-test
                       'clj-http.lite.integration-test)]
    (println (str "\n========== TOTAL =========="))
    (println (str "tests=" (:test r) " pass=" (:pass r) " fail=" (:fail r) " error=" (:error r)))
    (when (or (zero? (:test r)) (pos? (:fail r)) (pos? (:error r)))
      (throw (ex-info "suite failures" (select-keys r [:fail :error]))))))
