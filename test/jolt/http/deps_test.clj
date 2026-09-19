(ns jolt.http.deps-test
  "The deps.edn declarations jolt reads before any of this library compiles.

  :jolt/native is per platform, and jolt.main/load-natives! reads exactly the
  key current-platform selects: a spec with no key for the running platform was
  searched for nothing at all on every jolt through 0.8.8, and on later jolts
  falls back to conventional spellings that may not be the ones a library
  ships under (zlib1.dll was the case, before java.util.zip moved into the
  runtime). Either way the library failed to load on Windows before any app
  code ran (jolt-lang/jolt#990). These tests hold the declaration to the
  platforms jolt can select, so dropping a key is a red suite rather than a
  bug report from the one platform CI does not run."
  (:require [clojure.edn :as edn]
            [clojure.test :refer [deftest is testing]]))

;; JOLT_PWD is set by CI, not by an interactive `jolt -M:test`
(defn- project-deps []
  (let [pwd (or (jolt.host/getenv "JOLT_PWD") (System/getProperty "user.dir"))]
    (edn/read-string (slurp (str pwd "/deps.edn")))))

;; every value current-platform can answer
(def ^:private platforms [:darwin :linux :windows])

(defn- native-specs []
  (remove :process (:jolt/native (project-deps))))

(deftest every-native-declares-every-platform
  ;; the process's own symbols (libc) need no per-platform key; every shared
  ;; object declared beyond that does. There is none today — libz left when
  ;; java.util.zip moved into the runtime — so this holds the rule for the next.
  (let [specs (native-specs)]
    (is (some :process (:jolt/native (project-deps))) "libc is declared as the process's own symbols")
    (doseq [spec specs, plat platforms]
      (testing (str (:name spec) " on " (name plat))
        (let [c (get spec plat)
              cands (if (string? c) [c] c)]
          (is (seq cands) (str "no " plat " candidates — load-natives! searches for nothing")))))))

