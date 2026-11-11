;; Writes crafted-pairing.p12: two keys whose certificates are found by the
;; JDK's last-match rules in findMatchedCertificate.
(require '[clojure.java.io :as io] '[jolt.ffi :as ffi] '[jolt.http.pkcs12 :as p])
(def dir (first *command-line-args*))
(defn slurp-bytes [f] (with-open [in (io/input-stream f)] (let [o (java.io.ByteArrayOutputStream.)] (io/copy in o) (.toByteArray o))))
(defn pem->der [f] (.getEncoded (.generateCertificate (java.security.cert.CertificateFactory/getInstance "X.509") (io/input-stream (str dir "/" f)))))
(def enc (p/encrypt-key (slurp-bytes (str dir "/leaf.p8.der")) "changeit"))
(def root (pem->der "root.pem")) (def inter (pem->der "int.pem")) (def leaf (pem->der "leaf.pem"))
(defn b [s] (.getBytes s "UTF-8"))
(def key-bags (p/c-sk-new-null)) (def cert-bags (p/c-sk-new-null))
(doseq [[nm id] [["k1" "K1"] ["k2" "K2"]]]
  (#'p/push-bag! key-bags (p/c-bag-create0-pkcs8 (#'p/d2i p/c-d2i-X509-SIG enc)) {:name nm :key-id (b id)}))
(doseq [[der nm id] [[root "c1" "K1"] [leaf "c2" "K1"] [root "k2" nil] [inter "k2" nil]]]
  (#'p/push-bag! cert-bags (#'p/cert-bag der) {:name nm :key-id (some-> id b)}))
(def cell (ffi/alloc 8))
(ffi/write cell :pointer (p/c-sk-new-null) 0)
(assert (= 1 (p/c-add-safe cell key-bags -1 0 ffi/null)))
(assert (= 1 (#'p/with-cstr "changeit" #(p/c-add-safe cell cert-bags 427 10000 %))))
(def p12 (p/c-add-safes (ffi/read cell :pointer 0) 0))
(assert (= 1 (#'p/with-cstr "changeit" #(p/c-PKCS12-set-mac p12 % -1 ffi/null 20 10000 (p/c-sha256)))))
(def out (#'p/der-out p/c-i2d-PKCS12 p12))
(with-open [o (io/output-stream (str dir "/crafted-pairing.p12"))] (.write o out))
(println :wrote (alength out))
