(ns jolt.http.timeout-runner
  "Runs the https regressions (jolt.http.timeout-test) on their own.

  Kept out of the main runner deliberately. These tests park a connection on
  purpose and stand up their own servers on their own ports, while that suite
  requires its namespaces in a fixed order so integration-test's (use-fixtures
  :once with-server) wins. Isolating a deliberately-stalled peer from that is
  cheap insurance.

  self-signed-ssl-get once read as flaky from here (#6): the integration
  fixture built its cert path from JOLT_PWD alone, so an interactive run had
  the TLS server close every handshake and the test crashed on whichever
  exception class the close race produced. That was the cert path, not a race
  in the accept loop — fixed in test_util/server_process.clj (#12), and the
  test has since held over hundreds of consecutive iterations."
  (:require [jolt.http.platform]                 ;; installs the host shims
            [clojure.test :as t]
            [jolt.http.timeout-test]))

(defn -main [& _]
  (let [r (t/run-tests 'jolt.http.timeout-test)]
    (println (str "\n========== TOTAL =========="))
    (println (str "tests=" (:test r) " pass=" (:pass r) " fail=" (:fail r) " error=" (:error r)))
    (when (or (pos? (:fail r)) (pos? (:error r)))
      (throw (ex-info "suite failures" (select-keys r [:fail :error]))))))
