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
            [clojure.test :refer [deftest is testing]])
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
