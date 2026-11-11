(ns jolt.http.pkcs12
  "PKCS#12 key stores read and written the way the JDK's PKCS12 KeyStore reads
  and writes them, over libcrypto through jolt.ffi. jolt.http.jdk's
  java.security.KeyStore is built on this; nothing here knows about host
  objects, only DER bytes and plain maps.

  PKCS12_parse is no use for a KeyStore: it hands back one key, one
  certificate and a bag of CAs, and drops the two things the JDK keys its
  entries by, the friendlyName (the alias) and the localKeyID (what pairs a key
  with its certificate). So this walks the safe bags itself and applies the
  JDK's rules (sun.security.pkcs12.PKCS12KeyStore) to what it finds:

  - a pkcs8ShroudedKeyBag is a key entry, kept encrypted until getKey;
  - a certBag carrying Oracle's trusted-key-usage attribute
    (2.16.840.1.113894.746875.1.1) is a trusted certificate entry;
  - any other certBag is not an entry. It pairs with a key by localKeyID
    (falling back to the alias) and the chain grows from it by issuer;
  - an entry without a friendlyName is named by a counter, \"1\", \"2\", ...

  Every symbol bound here is in OpenSSL 3.0 (PKCS12_add1_attr_by_txt is the
  newest, added in 3.0); none of the 3.2+ additions are used."
  (:require [clojure.string :as str]
            [jolt.ffi :as ffi]
            [jolt.http.tls :as tls]))

;; Re-assert the OpenSSL that jolt.http.tls pinned, so the bindings below
;; resolve against it rather than whatever was loaded last (see tls.clj).
(tls/ensure-openssl!)

(ffi/defcfn c-d2i-PKCS12          "d2i_PKCS12"               [:pointer :pointer :long] :pointer)
(ffi/defcfn c-i2d-PKCS12          "i2d_PKCS12"               [:pointer :pointer] :int)
(ffi/defcfn c-PKCS12-free         "PKCS12_free"              [:pointer] :void)
(ffi/defcfn c-PKCS12-mac-present  "PKCS12_mac_present"       [:pointer] :int)
(ffi/defcfn c-PKCS12-verify-mac   "PKCS12_verify_mac"        [:pointer :pointer :int] :int)
(ffi/defcfn c-PKCS12-set-mac      "PKCS12_set_mac"           [:pointer :pointer :int :pointer :int :int :pointer] :int)
(ffi/defcfn c-unpack-authsafes    "PKCS12_unpack_authsafes"  [:pointer] :pointer)
(ffi/defcfn c-unpack-p7data       "PKCS12_unpack_p7data"     [:pointer] :pointer)
(ffi/defcfn c-unpack-p7encdata    "PKCS12_unpack_p7encdata"  [:pointer :pointer :int] :pointer)
(ffi/defcfn c-PKCS7-free          "PKCS7_free"               [:pointer] :void)
(ffi/defcfn c-add-safe            "PKCS12_add_safe"          [:pointer :pointer :int :int :pointer] :int)
(ffi/defcfn c-add-safes           "PKCS12_add_safes"         [:pointer :int] :pointer)
(ffi/defcfn c-bag-nid             "PKCS12_SAFEBAG_get_nid"   [:pointer] :int)
(ffi/defcfn c-bag-bag-nid         "PKCS12_SAFEBAG_get_bag_nid" [:pointer] :int)
(ffi/defcfn c-bag-get1-cert       "PKCS12_SAFEBAG_get1_cert" [:pointer] :pointer)
(ffi/defcfn c-bag-get0-pkcs8      "PKCS12_SAFEBAG_get0_pkcs8" [:pointer] :pointer)
(ffi/defcfn c-bag-get0-attrs      "PKCS12_SAFEBAG_get0_attrs" [:pointer] :pointer)
(ffi/defcfn c-bag-free            "PKCS12_SAFEBAG_free"      [:pointer] :void)
(ffi/defcfn c-bag-create-cert     "PKCS12_SAFEBAG_create_cert" [:pointer] :pointer)
(ffi/defcfn c-bag-create0-pkcs8   "PKCS12_SAFEBAG_create0_pkcs8" [:pointer] :pointer)
(ffi/defcfn c-get-friendlyname    "PKCS12_get_friendlyname"  [:pointer] :pointer)
(ffi/defcfn c-add-friendlyname    "PKCS12_add_friendlyname_utf8" [:pointer :pointer :int] :int)
(ffi/defcfn c-add-localkeyid      "PKCS12_add_localkeyid"    [:pointer :pointer :int] :int)
(ffi/defcfn c-add1-attr-by-txt    "PKCS12_add1_attr_by_txt"  [:pointer :pointer :int :pointer :int] :int)
(ffi/defcfn c-attr-object         "X509_ATTRIBUTE_get0_object" [:pointer] :pointer)
(ffi/defcfn c-attr-count          "X509_ATTRIBUTE_count"     [:pointer] :int)
(ffi/defcfn c-attr-type           "X509_ATTRIBUTE_get0_type" [:pointer :int] :pointer)
(ffi/defcfn c-i2d-ASN1-TYPE       "i2d_ASN1_TYPE"            [:pointer :pointer] :int)
(ffi/defcfn c-obj-obj2txt         "OBJ_obj2txt"              [:pointer :int :pointer :int] :int)
(ffi/defcfn c-obj-txt2obj         "OBJ_txt2obj"              [:pointer :int] :pointer)
(ffi/defcfn c-ASN1-OBJECT-free    "ASN1_OBJECT_free"         [:pointer] :void)
(ffi/defcfn c-d2i-X509-SIG        "d2i_X509_SIG"             [:pointer :pointer :long] :pointer)
(ffi/defcfn c-i2d-X509-SIG        "i2d_X509_SIG"             [:pointer :pointer] :int)
(ffi/defcfn c-X509-SIG-free       "X509_SIG_free"            [:pointer] :void)
(ffi/defcfn c-d2i-p8              "d2i_PKCS8_PRIV_KEY_INFO"  [:pointer :pointer :long] :pointer)
(ffi/defcfn c-i2d-p8              "i2d_PKCS8_PRIV_KEY_INFO"  [:pointer :pointer] :int)
(ffi/defcfn c-p8-free             "PKCS8_PRIV_KEY_INFO_free" [:pointer] :void)
(ffi/defcfn c-p8-pkey-get0        "PKCS8_pkey_get0"          [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-PKCS8-decrypt       "PKCS8_decrypt"            [:pointer :pointer :int] :pointer)
(ffi/defcfn c-PKCS8-encrypt       "PKCS8_encrypt"            [:int :pointer :pointer :int :pointer :int :int :pointer] :pointer)
(ffi/defcfn c-aes-256-cbc         "EVP_aes_256_cbc"          [] :pointer)
(ffi/defcfn c-sha256              "EVP_sha256"               [] :pointer)
(ffi/defcfn c-d2i-X509            "d2i_X509"                 [:pointer :pointer :long] :pointer)
(ffi/defcfn c-i2d-X509            "i2d_X509"                 [:pointer :pointer] :int)
(ffi/defcfn c-X509-free           "X509_free"                [:pointer] :void)
(ffi/defcfn c-X509-subject        "X509_get_subject_name"    [:pointer] :pointer)
(ffi/defcfn c-X509-issuer         "X509_get_issuer_name"     [:pointer] :pointer)
(ffi/defcfn c-X509-NAME-cmp       "X509_NAME_cmp"            [:pointer :pointer] :int)
(ffi/defcfn c-X509-get0-pubkey    "X509_get0_pubkey"         [:pointer] :pointer)
(ffi/defcfn c-X509-verify         "X509_verify"              [:pointer :pointer] :int)
(ffi/defcfn c-X509-skid           "X509_get0_subject_key_id" [:pointer] :pointer)
(ffi/defcfn c-X509-akid           "X509_get0_authority_key_id" [:pointer] :pointer)
(ffi/defcfn c-octet-cmp           "ASN1_OCTET_STRING_cmp"    [:pointer :pointer] :int)
(ffi/defcfn c-sk-new-null         "OPENSSL_sk_new_null"      [] :pointer)
(ffi/defcfn c-sk-push             "OPENSSL_sk_push"          [:pointer :pointer] :int)
(ffi/defcfn c-sk-num              "OPENSSL_sk_num"           [:pointer] :int)
(ffi/defcfn c-sk-value            "OPENSSL_sk_value"         [:pointer :int] :pointer)
(ffi/defcfn c-sk-free             "OPENSSL_sk_free"          [:pointer] :void)
(ffi/defcfn c-crypto-free         "CRYPTO_free"              [:pointer :pointer :int] :void)
(ffi/defcfn c-ERR-clear-error     "ERR_clear_error"          [] :void)
(ffi/defcfn c-ERR-get-error       "ERR_get_error"            [] :long)
(ffi/defcfn c-ERR-error-string-n  "ERR_error_string_n"       [:long :pointer :size_t] :void)

;; obj_mac.h; NIDs are part of OpenSSL's ABI
(def ^:private NID-pkcs8ShroudedKeyBag 151)
(def ^:private NID-certBag 152)
(def ^:private NID-x509Certificate 158)
(def ^:private V-ASN1-OBJECT 6)

(def ^:private OID-friendlyName "1.2.840.113549.1.9.20")
(def ^:private OID-localKeyID "1.2.840.113549.1.9.21")
;; Oracle's trustedKeyUsage. OpenSSL 3.2 named it NID_oracle_jdk_trustedkeyusage;
;; by OID it works on 3.0 as well.
(def ^:private OID-trusted-key-usage "2.16.840.1.113894.746875.1.1")
;; what the JDK writes as that attribute's value: anyExtendedKeyUsage
(def ^:private OID-any-extended-key-usage "2.5.29.37.0")

;; The JDK's defaults for a store it writes (PBEWithHmacSHA256AndAES_256,
;; HmacPBESHA256, 10000 iterations, a 20-byte MAC salt). OpenSSL 3 makes
;; AES-256-CBC a PBES2 scheme with PBKDF2 over HMAC-SHA256.
(def ^:private ITER 10000)
(def ^:private MAC-SALT-LEN 20)

(def ^:private ptr-size (ffi/sizeof :pointer))

;; --- exceptions, in the JDK's classes and words ---------------------------
(defn- ex
  ([cls msg] (jolt.host/throwable cls msg))
  ([cls msg cause] (jolt.host/throwable cls msg cause)))

(def ^:private bad-padding
  "Given final block not properly padded. Such issues can arise if a bad key is used during decryption.")

(defn- wrong-store-password []
  (ex "java.io.IOException" "keystore password was incorrect"
      (ex "java.security.UnrecoverableKeyException"
          (str "failed to decrypt safe contents entry: javax.crypto.BadPaddingException: " bad-padding))))

(defn- integrity-failed []
  (ex "java.io.IOException"
      "Integrity check failed: java.security.UnrecoverableKeyException: Failed PKCS12 integrity checking"
      (ex "java.security.UnrecoverableKeyException" "Failed PKCS12 integrity checking")))

;; --- memory helpers ---------------------------------------------------------
(defn- der-out
  "Run an i2d_* encoder over obj and return the DER bytes: once with a null
  output to size the buffer, once to fill it."
  [i2d obj]
  (let [len (i2d obj ffi/null)]
    (when (<= len 0) (throw (ex "java.io.IOException" "DER encoding failed")))
    (let [buf (ffi/alloc len) holder (ffi/alloc ptr-size)]
      (try
        (ffi/write holder :pointer buf 0)
        (ffi/read-array buf (i2d obj holder))
        (finally (ffi/free buf) (ffi/free holder))))))

(defn- d2i
  "Decode DER bytes with a d2i_* parser. Returns the object, or nil. d2i
  advances the pointer it is handed, hence the holder cell."
  [d2i-fn bytes]
  (let [n (alength bytes) buf (ffi/alloc (max 1 n)) holder (ffi/alloc ptr-size)]
    (try
      (ffi/write-array buf bytes)
      (ffi/write holder :pointer buf 0)
      (let [obj (d2i-fn ffi/null holder n)]
        (when-not (ffi/null? obj) obj))
      (finally (ffi/free buf) (ffi/free holder)))))

(defn- with-cstr [s f]
  (if (nil? s)
    (f ffi/null)
    (let [p (ffi/string->ptr (str s))]
      (try (f p) (finally (ffi/free p))))))

(defn- with-bytes-ptr [bytes f]
  (let [n (alength bytes) buf (ffi/alloc (max 1 n))]
    (try (ffi/write-array buf bytes) (f buf n) (finally (ffi/free buf)))))

(defn- stack-items [sk]
  (if (ffi/null? sk) [] (mapv #(c-sk-value sk %) (range (c-sk-num sk)))))

(defn- free-stack! [sk free-item]
  (when-not (ffi/null? sk)
    (doseq [x (stack-items sk)] (free-item x))
    (c-sk-free sk)))

(defn- obj-txt [obj]
  (let [buf (ffi/alloc 128)]
    (try
      (let [n (c-obj-obj2txt buf 128 obj 1)]
        (when (pos? n) (ffi/ptr->string buf)))
      (finally (ffi/free buf)))))

(defn- der-content
  "The contents octets of a DER TLV (an OCTET STRING's bytes, say)."
  [der]
  (let [b #(bit-and (aget der %) 0xff)
        l (b 1)
        [start len] (if (< l 0x80)
                      [2 l]
                      (let [k (bit-and l 0x7f)]
                        [(+ 2 k) (reduce (fn [acc i] (+ (* acc 256) (b (+ 2 i)))) 0 (range k))]))
        out (byte-array len)]
    (dotimes [i len] (aset out i (aget der (+ start i))))
    out))

(defn- bytes= [a b] (and a b (= (seq a) (seq b))))

;; --- reading ----------------------------------------------------------------
(defn- bag-attributes
  "{oid-text [value-DER ...]} for a bag's attributes."
  [bag]
  (into {}
        (for [attr (stack-items (c-bag-get0-attrs bag))]
          [(obj-txt (c-attr-object attr))
           (mapv #(der-out c-i2d-ASN1-TYPE (c-attr-type attr %)) (range (c-attr-count attr)))])))

(defn- friendly-name [bag]
  (let [p (c-get-friendlyname bag)]
    (when-not (ffi/null? p)
      (try (ffi/ptr->string p) (finally (c-crypto-free p ffi/null 0))))))

(defn- self-signed? [x]
  (let [r (and (zero? (c-X509-NAME-cmp (c-X509-subject x) (c-X509-issuer x)))
               (= 1 (c-X509-verify x (c-X509-get0-pubkey x))))]
    (c-ERR-clear-error)
    r))

(defn- find-issuer
  "PKCS12KeyStore.findIssuer: the first certificate whose subject is `cert`'s
  issuer, where an AuthorityKeyIdentifier on `cert` must also match the
  candidate's SubjectKeyIdentifier when it has one."
  [cert all]
  (let [x (:x cert)
        akid (c-X509-akid x)]
    (loop [[c & more] all fallback nil]
      (cond
        (nil? c) fallback
        (not (zero? (c-X509-NAME-cmp (c-X509-subject (:x c)) (c-X509-issuer x)))) (recur more fallback)
        (ffi/null? akid) c
        :else (let [skid (c-X509-skid (:x c))]
                (cond (ffi/null? skid) (recur more c)
                      (zero? (c-octet-cmp akid skid)) c
                      :else (recur more fallback)))))))

(defn- build-chain [start all]
  (loop [cert start chain []]
    (if (or (nil? cert) (some #(bytes= (:der %) (:der cert)) chain))
      chain
      (let [chain (conj chain cert)]
        (if (self-signed? (:x cert))
          chain
          (recur (find-issuer cert all) chain))))))

(defn- matched-certificate
  "PKCS12KeyStore.findMatchedCertificate: a full keyId + alias match wins, then
  a keyId match, then an alias match."
  [entry cert-entries]
  (let [same-alias? #(and (:alias entry) (:alias %)
                          (= (str/lower-case (:alias entry)) (str/lower-case (:alias %))))]
    (or (some #(when (and (bytes= (:key-id entry) (:key-id %)) (same-alias? %)) %) cert-entries)
        (some #(when (bytes= (:key-id entry) (:key-id %)) %) cert-entries)
        (some #(when (same-alias? %) %) cert-entries))))

(defn put-entry
  "LinkedHashMap.put: a new alias goes last, an existing one keeps its place."
  [entries k v]
  (if (contains? (:by entries) k)
    (assoc-in entries [:by k] v)
    (-> entries (update :order conj k) (assoc-in [:by k] v))))

(def empty-entries {:order [] :by {}})

(defn- utf8 [s] (.getBytes ^String s "UTF-8"))

(defn- read-bags
  "Fold one safe's bags into the load state `st`, as loadSafeContents does."
  [st bags]
  (reduce
   (fn [st [i bag]]
     (let [nid (c-bag-nid bag)
           attrs (bag-attributes bag)
           alias (when (contains? attrs OID-friendlyName) (friendly-name bag))
           key-id (some-> (first (get attrs OID-localKeyID)) der-content)
           trusted? (contains? attrs OID-trusted-key-usage)
           name-it (fn [st] (if alias [st alias]
                                (let [n (inc (:counter st))] [(assoc st :counter n) (str n)])))]
       (cond
         (= nid NID-pkcs8ShroudedKeyBag)
         (let [st (update st :key-count inc)
               key-id (or key-id (when (= 1 (:key-count st)) (utf8 "01")))]
           (if (nil? key-id)
             st                                ; an unidentifiable second key: skipped
             (let [[st alias] (name-it st)
                   entry {:kind :key :alias alias :key-id key-id
                          :enc (der-out c-i2d-X509-SIG (c-bag-get0-pkcs8 bag))}]
               (-> st
                   (update :keys conj (str/lower-case alias))
                   (update :entries put-entry (str/lower-case alias) entry)))))

         (and (= nid NID-certBag) (= NID-x509Certificate (c-bag-bag-nid bag)))
         (let [x (c-bag-get1-cert bag)
               cert {:x x :der (der-out c-i2d-X509 x)}
               key-id (or key-id (when (and (= 1 (:key-count st)) (zero? i)) (utf8 "01")))
               st (update st :all conj cert)]
           (if trusted?
             (let [[st alias] (name-it st)]
               (update st :entries put-entry (str/lower-case alias)
                       {:kind :trusted :alias alias :key-id key-id :cert (:der cert)}))
             (update st :cert-entries conj (assoc cert :key-id key-id :alias alias))))

          ;; keyBag, secretBag, crlBag, ...: not something this store keeps
         :else st)))
   st
   (map-indexed vector bags)))

(defn- openssl-error
  "The oldest error on this thread's OpenSSL queue, as text, and clear the rest."
  []
  (let [code (c-ERR-get-error)]
    (c-ERR-clear-error)
    (when-not (zero? code)
      (let [buf (ffi/alloc 256)]
        (try (c-ERR-error-string-n code buf 256) (ffi/ptr->string buf)
             (finally (ffi/free buf)))))))

(defn- mac-verifies? [p12 pass]
  (let [ok (and (= 1 (c-PKCS12-mac-present p12))
                (= 1 (with-cstr pass #(c-PKCS12-verify-mac p12 % -1))))]
    (c-ERR-clear-error)
    ok))

(defn- unpack-safe
  "The bags of one authenticated-safe ContentInfo: plain data, or encrypted
  data decrypted with `pass`. nil when it is encrypted and there is no
  password, which the JDK skips rather than fails on."
  [p12 p7 pass]
  (let [plain (c-unpack-p7data p7)]
    (if-not (ffi/null? plain)
      plain
      (do (c-ERR-clear-error)
          (when (some? pass)
            (let [enc (with-cstr pass #(c-unpack-p7encdata p7 % -1))]
              (when (ffi/null? enc)
                (let [why (openssl-error)]
                  ;; A MAC that verifies says the password is right, so the
                  ;; cipher is what failed: RC2-40, which OpenSSL 1.1 and older
                  ;; JDKs wrote by default, is in OpenSSL 3's legacy provider,
                  ;; and the JDK reads it where this cannot.
                  (throw (if (mac-verifies? p12 pass)
                           (ex "java.io.IOException"
                               (str "cannot decrypt the key store's certificates: " why))
                           (wrong-store-password)))))
              enc))))))

(defn read-store
  "Parse DER PKCS#12 `bytes` with the store password `pass` (a string, or nil
  for none). Returns the entries as {:order [lowercased alias ...] :by {alias
  entry}}, where an entry is
    {:kind :key :alias :key-id :enc <EncryptedPrivateKeyInfo DER> :chain [DER ...]|nil}
    {:kind :trusted :alias :key-id :cert DER}
  Throws java.io.IOException as the JDK does on a wrong password or a store
  that is not PKCS#12."
  [bytes pass]
  (let [p12 (d2i c-d2i-PKCS12 bytes)]
    (when-not p12
      (c-ERR-clear-error)
      (throw (ex "java.io.IOException" "not a PKCS#12 key store: its DER does not parse")))
    (let [state (volatile! {:entries empty-entries :counter 0 :key-count 0
                            :keys [] :cert-entries [] :all []})]
      (try
        (let [safes (c-unpack-authsafes p12)]
          (when (ffi/null? safes)
            (throw (ex "java.io.IOException" "not a PKCS#12 key store: no authenticated safe")))
          (try
            (doseq [p7 (stack-items safes)]
              (when-let [bags (unpack-safe p12 p7 pass)]
                (try (vswap! state read-bags (stack-items bags))
                     (finally (free-stack! bags c-bag-free)))))
            (finally (free-stack! safes c-PKCS7-free))))
        ;; the MAC is checked after the safes, as the JDK does, and not at all
        ;; without a password
        (when (and (some? pass) (= 1 (c-PKCS12-mac-present p12)))
          (when-not (= 1 (with-cstr pass #(c-PKCS12-verify-mac p12 % -1)))
            (c-ERR-clear-error)
            (throw (integrity-failed))))
        (let [{:keys [entries keys cert-entries all]} @state]
          (reduce (fn [entries k]
                    (let [entry (get-in entries [:by k])
                          chain (some-> (matched-certificate entry cert-entries) (build-chain all))]
                      (if (= :key (:kind entry))
                        (assoc-in entries [:by k :chain] (when (seq chain) (mapv :der chain)))
                        entries)))
                  entries
                  (distinct keys)))
        (finally
          (doseq [c (:all @state)] (c-X509-free (:x c)))
          (c-PKCS12-free p12))))))

;; --- keys -------------------------------------------------------------------
(def ^:private key-algorithms
  {"1.2.840.113549.1.1.1" "RSA"
   "1.2.840.10045.2.1" "EC"
   "1.3.101.112" "EdDSA"})

(defn decrypt-key
  "Decrypt an EncryptedPrivateKeyInfo with `pass`. Returns {:der <PKCS#8 DER>
  :algorithm \"RSA\"|\"EC\"|\"EdDSA\"|<oid>}, or nil when the password does not
  decrypt it."
  [enc pass]
  (let [sig (d2i c-d2i-X509-SIG enc)]
    (when-not sig (throw (ex "java.io.IOException" "Private key not stored as PKCS#8 EncryptedPrivateKeyInfo")))
    (try
      (let [p8 (with-cstr (or pass "") #(c-PKCS8-decrypt sig % -1))]
        (c-ERR-clear-error)
        (when-not (ffi/null? p8)
          (try
            (let [holder (ffi/alloc ptr-size)]
              (try
                (c-p8-pkey-get0 holder ffi/null ffi/null ffi/null p8)
                (let [oid (obj-txt (ffi/read holder :pointer 0))]
                  {:der (der-out c-i2d-p8 p8)
                   :algorithm (get key-algorithms oid oid)})
                (finally (ffi/free holder))))
            (finally (c-p8-free p8)))))
      (finally (c-X509-SIG-free sig)))))

(defn encrypt-key
  "Encrypt PKCS#8 `der` with `pass` into an EncryptedPrivateKeyInfo, as the
  JDK protects a key it is given in setKeyEntry."
  [der pass]
  (let [p8 (d2i c-d2i-p8 der)]
    (when-not p8
      (throw (ex "java.security.KeyStoreException" "Private key is not encoded as PKCS#8")))
    (try
      (let [sig (with-cstr (or pass "")
                  #(c-PKCS8-encrypt -1 (c-aes-256-cbc) % -1 ffi/null 0 ITER p8))]
        (when (ffi/null? sig)
          (c-ERR-clear-error)
          (throw (ex "java.security.KeyStoreException" "Key protection algorithm not found: PKCS8_encrypt failed")))
        (try (der-out c-i2d-X509-SIG sig) (finally (c-X509-SIG-free sig))))
      (finally (c-p8-free p8)))))

;; --- certificates -----------------------------------------------------------
(defn- with-x509s [ders f]
  (let [xs (mapv #(d2i c-d2i-X509 %) ders)]
    (try
      (when (some nil? xs) (throw (ex "java.security.KeyStoreException" "not a DER X.509 certificate")))
      (f xs)
      (finally (doseq [x xs :when x] (c-X509-free x))))))

(defn chain-valid?
  "PKCS12KeyStore.validateChain: each certificate is issued by the next, by
  name, and none repeats."
  [ders]
  (and (= (count ders) (count (distinct (map seq ders))))
       (with-x509s ders
         (fn [xs]
           (every? (fn [[a b]] (zero? (c-X509-NAME-cmp (c-X509-issuer a) (c-X509-subject b))))
                   (partition 2 1 xs))))))

;; --- writing ----------------------------------------------------------------
(defn- add-attrs! [bag {:keys [name key-id trusted?]}]
  (when name
    (with-cstr name #(when-not (= 1 (c-add-friendlyname bag % -1))
                       (throw (ex "java.io.IOException" "cannot set friendlyName")))))
  (when key-id
    (with-bytes-ptr key-id #(when-not (= 1 (c-add-localkeyid bag %1 %2))
                              (throw (ex "java.io.IOException" "cannot set localKeyID")))))
  (when trusted?
    (let [usage (with-cstr OID-any-extended-key-usage #(c-obj-txt2obj % 1))]
      (try
        (with-cstr OID-trusted-key-usage
          #(when-not (= 1 (c-add1-attr-by-txt bag % V-ASN1-OBJECT usage -1))
             (throw (ex "java.io.IOException" "cannot set the trusted key usage"))))
        (finally (c-ASN1-OBJECT-free usage))))))

(defn- push-bag! [sk bag attrs]
  (when (ffi/null? bag) (throw (ex "java.io.IOException" "cannot build a PKCS#12 safe bag")))
  (c-sk-push sk bag)
  (add-attrs! bag attrs))

(defn- cert-bag [der]
  (let [x (d2i c-d2i-X509 der)]
    (when-not x (throw (ex "java.security.cert.CertificateEncodingException" "not a DER X.509 certificate")))
    (try (c-bag-create-cert x) (finally (c-X509-free x)))))

(defn write-store
  "Encode entries ({:order :by}, entries as read-store returns them, except that
  each certificate is {:der :name} with :name its subject in RFC 2253) as DER
  PKCS#12 under `pass`, in the JDK's layout: the shrouded keys in a plain data
  safe, every certificate in an encrypted one, then a SHA-256 MAC. A nil
  password writes the certificates unencrypted and no MAC, as the JDK does."
  [{:keys [order by]} pass]
  (let [entries (map by order)
        key-bags (c-sk-new-null)
        cert-bags (c-sk-new-null)
        safes-cell (ffi/alloc ptr-size)]
    (ffi/write safes-cell :pointer (c-sk-new-null) 0)
    (try
      (doseq [{:keys [kind alias key-id enc]} entries :when (= kind :key)]
        (let [sig (d2i c-d2i-X509-SIG enc)]
          (when-not sig (throw (ex "java.io.IOException" "Private key not stored as PKCS#8 EncryptedPrivateKeyInfo")))
          (push-bag! key-bags (c-bag-create0-pkcs8 sig) {:name alias :key-id key-id})))
      (doseq [{:keys [kind alias key-id chain cert]} entries]
        (if (= kind :key)
          (doseq [[i c] (map-indexed vector chain)]
            ;; only the end-entity certificate carries the localKeyID; the
            ;; CA certificates are named by their subject (NSS wants it so)
            (push-bag! cert-bags (cert-bag (:der c))
                       (if (zero? i) {:name alias :key-id key-id} {:name (:name c)})))
          (push-bag! cert-bags (cert-bag (:der cert)) {:name alias :key-id key-id :trusted? true})))
      (when (pos? (c-sk-num key-bags))
        (when-not (= 1 (c-add-safe safes-cell key-bags -1 0 ffi/null))
          (throw (ex "java.io.IOException" "cannot build the key safe"))))
      (when (pos? (c-sk-num cert-bags))
        (when-not (= 1 (with-cstr pass #(c-add-safe safes-cell cert-bags (if pass 427 -1) ITER %)))
          (c-ERR-clear-error)
          (throw (ex "java.io.IOException" "cannot build the certificate safe"))))
      (let [safes (ffi/read safes-cell :pointer 0)
            p12 (c-add-safes safes 0)]
        (when (ffi/null? p12) (throw (ex "java.io.IOException" "cannot build the PKCS#12 container")))
        (try
          (when (some? pass)
            (when-not (= 1 (with-cstr pass #(c-PKCS12-set-mac p12 % -1 ffi/null MAC-SALT-LEN ITER (c-sha256))))
              (c-ERR-clear-error)
              (throw (ex "java.io.IOException" "calculateMac failed"))))
          (der-out c-i2d-PKCS12 p12)
          (finally (c-PKCS12-free p12))))
      (finally
        (free-stack! key-bags c-bag-free)
        (free-stack! cert-bags c-bag-free)
        (free-stack! (ffi/read safes-cell :pointer 0) c-PKCS7-free)
        (ffi/free safes-cell)))))
