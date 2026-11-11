;; Measures what the JDK's PKCS12 KeyStore reports for the stores in this
;; directory, and prints it as the EDN that jolt.http.keystore-test holds Jolt
;; to (expected.edn). JVM only, from a directory with no deps.edn of its own:
;;
;;   cd "$(mktemp -d)" && echo '{:deps {org.clojure/clojure {:mvn/version "1.12.3"}}}' > deps.edn
;;   clojure -M <this-dir>/jvm_expected.clj <this-dir> > <this-dir>/expected.edn
;;
;; Every store's password is "changeit". The stores themselves came from
;; keytool (keytool-*.p12) and the OpenSSL 3 CLI (openssl-*.p12); root.pem and
;; int.pem are the CA and intermediate in openssl-chain.p12's chain.
;; openssl-legacy-rc2.p12 is `openssl pkcs12 -export -legacy`: certificates
;; under RC2-40, which OpenSSL 3 keeps in its legacy provider.
(require '[clojure.java.io :as io] '[clojure.pprint :as pp])
(import '[java.security KeyStore MessageDigest])

(def dir (first *command-line-args*))
(def pass "changeit")

(defn- sha [^bytes b]
  (when b
    (apply str (map #(format "%02x" (bit-and % 0xff))
                    (.digest (MessageDigest/getInstance "SHA-256") b)))))

(defn- err [^Throwable e]
  (cond-> {:class (.getName (class e)) :message (.getMessage e)}
    (.getCause e) (assoc :cause {:class (.getName (class (.getCause e)))
                                 :message (.getMessage (.getCause e))})))

(defmacro ^:private caught [& body] `(try ~@body (catch Throwable e# {:error (err e#)})))

(defn- load-ks [f p]
  (with-open [in (io/input-stream (str dir "/" f))]
    (doto (KeyStore/getInstance "PKCS12") (.load in (some-> p char-array)))))

(defn- describe [^KeyStore ks]
  (let [aliases (vec (enumeration-seq (.aliases ks)))]
    {:size (.size ks)
     :aliases aliases
     :entries (into (sorted-map)
                    (for [a aliases]
                      [a {:key? (.isKeyEntry ks a)
                          :cert? (.isCertificateEntry ks a)
                          :cert (some-> (.getCertificate ks a) .getEncoded sha)
                          :chain (some->> (.getCertificateChain ks a) (mapv #(sha (.getEncoded %))))
                          :key (when-let [k (.getKey ks a (char-array pass))]
                                 {:algorithm (.getAlgorithm k) :format (.getFormat k)
                                  :encoded (sha (.getEncoded k))})}]))}))

(def stores ["keytool-rsa.p12" "keytool-ec2.p12" "openssl-chain.p12" "keytool-trust.p12"
             "openssl-jdktrust.p12" "openssl-plain-certs.p12" "openssl-nocertpbe.p12"])

(pp/pprint
  {:java-version (System/getProperty "java.version")
   :stores (into (sorted-map) (for [f stores] [f (describe (load-ks f pass))]))
   :null-password (describe (load-ks "openssl-chain.p12" nil))
   :legacy (describe (load-ks "openssl-legacy-rc2.p12" pass))
   :pem {"root.pem" (sha (.getEncoded (.generateCertificate (java.security.cert.CertificateFactory/getInstance "X.509")
                                                           (io/input-stream (str dir "/root.pem")))))}
   :errors {:wrong-password (caught (load-ks "openssl-chain.p12" "wrong"))
            :wrong-password-mac (caught (load-ks "openssl-nocertpbe.p12" "wrong"))
            :wrong-key-password (caught (.getKey (load-ks "openssl-chain.p12" pass) "chained leaf" (char-array "wrong")))
            :unknown-type (caught (KeyStore/getInstance "FOO"))
            :uninitialized (caught (.size (KeyStore/getInstance "PKCS12")))
            :key-without-chain (caught (let [ks (load-ks "openssl-chain.p12" pass)]
                                         (.setKeyEntry ks "x" (.getKey ks "chained leaf" (char-array pass))
                                                       (char-array pass) nil)))
            :overwrite-key-with-cert (caught (let [ks (load-ks "openssl-chain.p12" pass)]
                                               (.setCertificateEntry ks "chained leaf" (.getCertificate ks "chained leaf"))))
            :broken-chain (caught (let [ks (load-ks "openssl-chain.p12" pass)
                                        [leaf _ root] (.getCertificateChain ks "chained leaf")]
                                    (.setKeyEntry ks "x" (.getKey ks "chained leaf" (char-array pass))
                                                  (char-array pass) (into-array java.security.cert.Certificate [leaf root]))))}})
