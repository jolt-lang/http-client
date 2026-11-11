(ns jolt.http.keystore-test
  "java.security.KeyStore as a real PKCS#12 key store. The stores under
  test/resources/keystores were written by keytool and by the OpenSSL 3 CLI,
  and expected.edn is what the JDK's own KeyStore reports for them, measured by
  jvm_expected.clj in the same directory. So these tests hold Jolt to the JVM's
  answers (aliases, entry kinds, the bytes of every certificate and key, the
  exception and message of every refusal) rather than to what this library
  happens to do."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]
            [jolt.http.core :as core]
            [jolt.http.pkcs12 :as pkcs12]
            [jolt.http.tls :as tls])
  (:import [java.security KeyStore MessageDigest]))

;; JOLT_PWD is set by CI, not by an interactive `jolt -M:test`
(def ^:private dir
  (str (or (jolt.host/getenv "JOLT_PWD") (System/getProperty "user.dir"))
       "/test/resources/keystores/"))

(def ^:private expected (edn/read-string (slurp (str dir "expected.edn"))))

(def ^:private pass "changeit")

(defn- sha [b]
  (when b
    (apply str (map #(format "%02x" (bit-and % 0xff))
                    (.digest (MessageDigest/getInstance "SHA-256") b)))))

(defn- err [e]
  (cond-> {:class (.getName (class e)) :message (.getMessage e)}
    (.getCause e) (assoc :cause {:class (.getName (class (.getCause e)))
                                 :message (.getMessage (.getCause e))})))

(defmacro ^:private caught [& body] `(try ~@body (catch Throwable e# {:error (err e#)})))

(defn- load-ks
  ([f p] (load-ks "PKCS12" f p))
  ([type f p]
   (with-open [in (io/input-stream (str dir f))]
     (doto (KeyStore/getInstance type) (.load in (some-> p char-array))))))

(defn- empty-ks [] (doto (KeyStore/getInstance "PKCS12") (.load nil nil)))

(defn- cert-from-pem [f]
  (.generateCertificate (java.security.cert.CertificateFactory/getInstance "X.509")
                        (io/input-stream (str dir f))))

;; the same shape jvm_expected.clj prints
(defn- describe
  ([ks] (describe ks pass))
  ([ks key-pass]
   (let [aliases (vec (enumeration-seq (.aliases ks)))]
     {:size (.size ks)
      :aliases aliases
      :entries (into (sorted-map)
                     (for [a aliases]
                       [a {:key? (.isKeyEntry ks a)
                           :cert? (.isCertificateEntry ks a)
                           :cert (some-> (.getCertificate ks a) .getEncoded sha)
                           :chain (some->> (.getCertificateChain ks a) (mapv #(sha (.getEncoded %))))
                           :key (when-let [k (.getKey ks a (char-array key-pass))]
                                  {:algorithm (.getAlgorithm k) :format (.getFormat k)
                                   :encoded (sha (.getEncoded k))})}]))})))

(deftest reads-every-store-as-the-jdk-does
  (doseq [[f want] (:stores expected)]
    (testing f
      (is (= want (describe (load-ks f pass)))))))

(deftest a-null-password-skips-the-encrypted-certificates
  ;; the JDK cannot decrypt the certificate safe without a password, so it
  ;; still lists the key entry, with no certificate or chain, and checks no MAC
  (is (= (:null-password expected) (describe (load-ks "openssl-chain.p12" nil)))))

(deftest refusals-match-the-jdk
  (let [want (:errors expected)
        ks #(load-ks "openssl-chain.p12" pass)]
    (testing "a wrong store password, caught decrypting the certificates"
      (is (= (:wrong-password want) (caught (load-ks "openssl-chain.p12" "wrong")))))
    (testing "a wrong store password, caught by the MAC when nothing is encrypted"
      (is (= (:wrong-password-mac want) (caught (load-ks "openssl-nocertpbe.p12" "wrong")))))
    (testing "a wrong key password"
      (is (= (:wrong-key-password want)
             (caught (.getKey (ks) "chained leaf" (char-array "wrong"))))))
    (testing "a null key password, on a key under a real one"
      (is (= (:null-key-password want) (caught (.getKey (ks) "chained leaf" nil)))))
    (testing "an unknown store type"
      (is (= (:unknown-type want) (caught (KeyStore/getInstance "FOO")))))
    (testing "a store that was never loaded"
      (is (= (:uninitialized want) (caught (.size (KeyStore/getInstance "PKCS12"))))))
    (testing "a private key needs a chain"
      (is (= (:key-without-chain want)
             (caught (let [s (ks)]
                       (.setKeyEntry s "x" (.getKey s "chained leaf" (char-array pass))
                                     (char-array pass) nil))))))
    (testing "a certificate entry cannot replace a key entry"
      (is (= (:overwrite-key-with-cert want)
             (caught (let [s (ks)]
                       (.setCertificateEntry s "chained leaf" (.getCertificate s "chained leaf")))))))
    (testing "a chain whose links do not issue each other"
      (is (= (:broken-chain want)
             (caught (let [s (ks)
                           [leaf _ root] (.getCertificateChain s "chained leaf")]
                       (.setKeyEntry s "x" (.getKey s "chained leaf" (char-array pass))
                                     (char-array pass) (into-array [leaf root])))))))))

(deftest a-legacy-cipher-is-not-a-wrong-password
  ;; RC2-40 is in OpenSSL 3's legacy provider, which is not loaded by default,
  ;; while the JDK reads it. Where it cannot be decrypted the MAC still says
  ;; the password was right, so the error must not blame the password.
  (let [r (caught (describe (load-ks "openssl-legacy-rc2.p12" pass)))]
    (if (:error r)
      (is (re-find #"^cannot decrypt the key store's certificates: " (:message (:error r))) (pr-str r))
      (is (= (:legacy expected) r))))
  (is (= "keystore password was incorrect"
         (:message (:error (caught (load-ks "openssl-legacy-rc2.p12" "wrong")))))))

(deftest missing-aliases-answer-as-the-jdk-does
  (let [ks (load-ks "openssl-chain.p12" pass)]
    (is (nil? (.getCertificate ks "nope")))
    (is (nil? (.getCertificateChain ks "nope")))
    (is (nil? (.getKey ks "nope" (char-array pass))))
    (is (false? (.isKeyEntry ks "nope")))
    (is (false? (.isCertificateEntry ks "nope")))
    (is (false? (.containsAlias ks "nope")))
    (is (nil? (.deleteEntry ks "nope")) "deleting nothing is not an error")
    (testing "aliases are case-insensitive"
      (is (.containsAlias ks "CHAINED LEAF"))
      (is (= (sha (.getEncoded (.getCertificate ks "chained leaf")))
             (sha (.getEncoded (.getCertificate ks "Chained Leaf"))))))
    (testing "a trusted entry has no chain and no key"
      (let [t (load-ks "keytool-trust.p12" pass)]
        (is (nil? (.getCertificateChain t "rootca")))
        (is (nil? (.getKey t "rootca" (char-array pass))))))))

(deftest types
  (is (= "pkcs12" (KeyStore/getDefaultType)))
  (testing "getType answers the spelling asked for, which matches case-insensitively"
    (is (= ["PKCS12" "pkcs12" "PkCs12"]
           (mapv #(.getType (KeyStore/getInstance %)) ["PKCS12" "pkcs12" "PkCs12"]))))
  (testing "an empty store"
    (is (= {:size 0 :aliases [] :entries {}} (describe (empty-ks))))))

(deftest deleting-and-re-adding-keeps-insertion-order
  (let [ks (load-ks "keytool-trust.p12" pass)
        root (.getCertificate ks "rootca")]
    (.deleteEntry ks "RootCA")
    (is (= ["intermediate"] (vec (enumeration-seq (.aliases ks)))))
    (.setCertificateEntry ks "RootCA" root)
    (is (= ["intermediate" "rootca"] (vec (enumeration-seq (.aliases ks)))))
    (is (= 2 (.size ks)))))

(defn- built-store
  "A store made in memory: a key entry with its three-certificate chain and two
  trusted certificates, one of them deleted and re-added on the way."
  []
  (let [src (load-ks "openssl-chain.p12" pass)
        ks (empty-ks)]
    (.setKeyEntry ks "Built Key" (.getKey src "chained leaf" (char-array pass)) (char-array "keypw")
                  (.getCertificateChain src "chained leaf"))
    (.setCertificateEntry ks "Trusted Root" (cert-from-pem "root.pem"))
    (.setCertificateEntry ks "second" (cert-from-pem "int.pem"))
    (.deleteEntry ks "second")
    (.setCertificateEntry ks "Inter" (cert-from-pem "int.pem"))
    ks))

(def ^:private built-want
  ;; what the same store reads as: the chain, the key and the two CA
  ;; certificates are the ones in openssl-chain.p12
  (let [chained (get-in expected [:stores "openssl-chain.p12" :entries "chained leaf"])
        [_ inter root] (:chain chained)]
    {:size 3
     :aliases ["built key" "trusted root" "inter"]
     :entries {"built key" chained
               "inter" {:key? false :cert? true :cert inter :chain nil :key nil}
               "trusted root" {:key? false :cert? true :cert root :chain nil :key nil}}}))

(deftest a-store-built-in-memory
  (is (= built-want (describe (built-store) "keypw"))))

(deftest a-stored-store-reads-back
  (let [ks (built-store)
        out (java.io.ByteArrayOutputStream.)]
    (.store ks out (char-array "storepw"))
    (let [bytes (.toByteArray out)
          back (doto (KeyStore/getInstance "PKCS12")
                 (.load (java.io.ByteArrayInputStream. bytes) (char-array "storepw")))]
      (is (= built-want (describe back "keypw")))
      (testing "the store password protects it"
        (is (= "keystore password was incorrect"
               (:message (:error (caught (.load (KeyStore/getInstance "PKCS12")
                                                (java.io.ByteArrayInputStream. bytes)
                                                (char-array "wrong")))))))))))

(deftest an-empty-store-stores
  (let [out (java.io.ByteArrayOutputStream.)]
    (.store (empty-ks) out (char-array "p"))
    (is (= {:size 0 :aliases [] :entries {}}
           (describe (doto (KeyStore/getInstance "PKCS12")
                       (.load (java.io.ByteArrayInputStream. (.toByteArray out)) (char-array "p")))))))
  (testing "store needs a loaded store"
    (is (= "Uninitialized keystore"
           (:message (:error (caught (.store (KeyStore/getInstance "PKCS12")
                                             (java.io.ByteArrayOutputStream.) (char-array "p")))))))))

(deftest the-fixture-certificates-are-the-ones-measured
  ;; root.pem is the CA the stores chain to; a regenerated fixture set that
  ;; forgot to re-run jvm_expected.clj fails here first
  (is (= (get-in expected [:pem "root.pem"]) (sha (.getEncoded (cert-from-pem "root.pem"))))))

;; --- what the key and trust manager factories hand jolt.http.tls ----------
(defn- trust-material [ks]
  (let [tmf (doto (javax.net.ssl.TrustManagerFactory/getInstance "PKIX") (.init ks))]
    (jolt.host/ref-get (first (.getTrustManagers tmf)) :material)))

(defn- key-material [ks key-pass]
  (let [kmf (doto (javax.net.ssl.KeyManagerFactory/getInstance "PKIX") (.init ks (char-array key-pass)))]
    (jolt.host/ref-get (first (.getKeyManagers kmf)) :material)))

(defn- parsed-certs
  "The certificates OpenSSL's PKCS12_parse finds in a manager's material, as
  jolt.http.tls reads it."
  [{:keys [bytes pass]}]
  (let [{:keys [cert cas free]} (#'tls/parse-pkcs12 bytes pass)]
    (try (count (remove nil? (cons cert cas))) (finally (free)))))

(deftest material-is-keyed-by-content
  ;; tls's SSL_CTX cache and core's connection pool key on the material; an
  ;; identity hash of an array nothing retains can be reused by another store
  (testing "two loads of one file share a context"
    (let [a (trust-material (load-ks "keytool-trust.p12" pass))
          b (trust-material (load-ks "keytool-trust.p12" pass))]
      (is (some? (:id a)))
      (is (= (:id a) (:id b)))
      (is (= (#'tls/ctx-key false {:trust-store a}) (#'tls/ctx-key false {:trust-store b})))
      (is (= (core/pool-key "h" 443 true false {:trust-store a} nil)
             (core/pool-key "h" 443 true false {:trust-store b} nil)))))
  (testing "an unchanged in-memory store is one array, a changed one another"
    (let [ks (doto (empty-ks) (.setCertificateEntry "root" (cert-from-pem "root.pem")))
          a (trust-material ks)
          b (trust-material ks)]
      (is (identical? (:bytes a) (:bytes b)))
      (is (= (:id a) (:id b)))
      (.setCertificateEntry ks "inter" (cert-from-pem "int.pem"))
      (is (not= (:id a) (:id (trust-material ks))))
      (is (not= (#'tls/ctx-key false {:trust-store a})
                (#'tls/ctx-key false {:trust-store (trust-material ks)}))))))

(deftest trust-material-is-certificates-only
  ;; the key is under "kp", the trust manager has no password: a key bag in
  ;; the trust material would make PKCS12_parse fail at connect. The JDK
  ;; trusts the trusted entries and each key entry's own certificate.
  (let [src (load-ks "openssl-chain.p12" pass)
        ks (doto (empty-ks)
             (.setKeyEntry "k" (.getKey src "chained leaf" (char-array pass)) (char-array "kp")
                           (.getCertificateChain src "chained leaf"))
             (.setCertificateEntry "root" (cert-from-pem "root.pem")))]
    (is (= 2 (parsed-certs (trust-material ks))))
    (testing "and the key manager's material holds the key"
      (let [{:keys [bytes pass]} (key-material ks "kp")
            {:keys [key free]} (#'tls/parse-pkcs12 bytes pass)]
        (try (is (some? key)) (finally (free)))))))

(deftest a-changed-plain-certificate-store-keeps-trusting-its-certificates
  ;; openssl-plain-certs.p12 is two plain certificate bags: no entries to the
  ;; JDK, but trusted here while unchanged. Changing it must not drop them.
  (let [ks (load-ks "openssl-plain-certs.p12" pass)]
    (is (= 2 (parsed-certs (trust-material ks))))
    (.setCertificateEntry ks "leaf" (.getCertificate (load-ks "openssl-chain.p12" pass) "chained leaf"))
    (let [m (trust-material ks)]
      (is (= 3 (parsed-certs m)))
      (is (= "" (:pass m)) "re-encoded under the factory's password, not the load password"))))

(deftest key-manager-factories-check-keys-as-the-jdk-does
  (is (= (:kmf-default-algorithm expected) (javax.net.ssl.KeyManagerFactory/getDefaultAlgorithm)))
  (testing "SunX509 reads every key at init"
    (is (= (:kmf-wrong-password (:errors expected))
           (caught (.init (javax.net.ssl.KeyManagerFactory/getInstance
                            (javax.net.ssl.KeyManagerFactory/getDefaultAlgorithm))
                          (load-ks "openssl-chain.p12" pass) (char-array "wrong"))))))
  (testing "PKIX reads them when it needs them"
    (is (nil? (.init (javax.net.ssl.KeyManagerFactory/getInstance "PKIX")
                     (load-ks "openssl-chain.p12" pass) (char-array "wrong"))))))

(deftest a-legacy-key-cipher-is-not-a-wrong-password
  ;; the key is under RC2-40, in OpenSSL 3's legacy provider
  (let [ks (load-ks "openssl-key-rc2.p12" pass)
        r (caught (.getKey ks "rc2 key" (char-array pass)))]
    (if (:error r)
      (is (re-find #"^Get Key failed: error:" (:message (:error r))) (pr-str r))
      (is (= (get-in expected [:legacy-key :entries "rc2 key" :key])
             {:algorithm (.getAlgorithm r) :format (.getFormat r) :encoded (sha (.getEncoded r))})))))

(deftest jks-instances-read-pkcs12
  ;; JDK 9+ reads a PKCS12 file through a JKS instance (keystore.type.compat)
  (let [ks (load-ks "JKS" "openssl-chain.p12" pass)]
    (is (= (:type (:jks expected)) (.getType ks)))
    (is (= (dissoc (:jks expected) :type) (describe ks))))
  (testing "JKS-format content is refused by name"
    (let [jks (byte-array (map unchecked-byte [0xfe 0xed 0xfe 0xed 0 0 0 2 0 0 0 0]))]
      (is (re-find #"JKS"
                   (str (:message (:error (caught (.load (KeyStore/getInstance "JKS")
                                                         (java.io.ByteArrayInputStream. jks)
                                                         (char-array "x")))))))))))

(deftest a-throw-mid-safe-frees-every-certificate
  (let [got (atom 0) freed (atom 0) n (atom 0)
        get1 pkcs12/c-bag-get1-cert free pkcs12/c-X509-free attrs @#'pkcs12/bag-attributes]
    (with-redefs [pkcs12/c-bag-get1-cert (fn [b] (swap! got inc) (get1 b))
                  pkcs12/c-X509-free (fn [x] (swap! freed inc) (free x))
                  pkcs12/bag-attributes (fn [b] (when (= 3 (swap! n inc)) (throw (ex-info "boom" {})))
                                          (attrs b))]
      (is (thrown? Exception (load-ks "openssl-nocertpbe.p12" pass))))
    (is (pos? @got))
    (is (= @got @freed))))

(deftest concurrent-changes-are-not-lost
  (let [ks (empty-ks)
        root (cert-from-pem "root.pem")
        fs (doall (for [i (range 40)] (future (.setCertificateEntry ks (str "c" i) root))))]
    (run! deref fs)
    (is (= 40 (.size ks)))))
