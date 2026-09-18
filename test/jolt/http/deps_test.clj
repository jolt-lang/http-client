(ns jolt.http.deps-test
  "The deps.edn declarations jolt reads before any of this library compiles.

  :jolt/native is per platform, and jolt.main/load-natives! reads exactly the
  key current-platform selects: a spec with no key for the running platform was
  searched for nothing at all on every jolt through 0.8.8, and on later jolts
  falls back to conventional spellings that can never derive zlib1.dll from
  \"z\". Either way the library failed to load on Windows before any app code
  ran (jolt-lang/jolt#990). These tests hold the declaration to the platforms
  jolt can select, so dropping a key is a red suite rather than a bug report
  from the one platform CI does not run."
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
  (let [specs (native-specs)]
    (is (seq specs) "deps.edn declares at least one shared-object native")
    (doseq [spec specs, plat platforms]
      (testing (str (:name spec) " on " (name plat))
        (let [c (get spec plat)
              cands (if (string? c) [c] c)]
          (is (seq cands) (str "no " plat " candidates — load-natives! searches for nothing")))))))

(deftest libz-windows-candidates-name-what-zlib-ships
  ;; zlib1.dll is what zlib's own Windows builds are called (Git for Windows,
  ;; winlibs, vcpkg). No spelling convention derives it from "z", so it has to
  ;; be written down; z.dll / libz.dll are the conventional names and stay so a
  ;; declared key loses nothing the loader's fallback would have tried.
  (let [z (first (filter #(= "z" (:name %)) (native-specs)))]
    (is (some? z) "a :jolt/native spec named \"z\"")
    (is (= "zlib1.dll" (first (:windows z))))
    (is (every? (set (:windows z)) ["z.dll" "libz.dll"]))
    (doseq [c (:windows z)]
      (is (not (re-find #"[/\\]" c))
          (str c " should be bare so the loader's own search order applies")))))
