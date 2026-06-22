(ns jolt.http.zlib
  "gzip / zlib / raw-deflate over the system libz, bound through jolt.ffi. Backs
  the java.util.zip stream shims clj-http-lite uses for content-encoding.

  Window-bits convention (zlib inflateInit2/deflateInit2):
    15  -> zlib format (java.util.zip default)   31 -> gzip (15+16)
    47  -> auto-detect zlib/gzip on inflate       -15 -> raw, no header

  libz is declared in deps.edn (:jolt/native) and loaded before this namespace is
  required, so the foreign-fn bindings resolve at load. Payloads are jolt
  byte-arrays in and out — the same carrier clj-http-lite's util.clj uses."
  (:require [jolt.ffi :as ffi]))

;; z_stream layout (LP64): the four fields the pump drives, by byte offset.
(def ^:private ZS 112)            ;; sizeof(z_stream)
(def ^:private O-next-in 0)
(def ^:private O-avail-in 8)
(def ^:private O-next-out 24)
(def ^:private O-avail-out 32)
(def ^:private CHUNK 65536)
(def ^:private Z-STREAM-END 1)
(def ^:private Z-FINISH 4)
(def ^:private Z-NO-FLUSH 0)

(ffi/defcfn c-zlib-version "zlibVersion"   [] :pointer)
(ffi/defcfn c-deflate-init "deflateInit2_" [:pointer :int :int :int :int :int :pointer :int] :int)
(ffi/defcfn c-deflate      "deflate"       [:pointer :int] :int)
(ffi/defcfn c-deflate-end  "deflateEnd"    [:pointer] :int)
(ffi/defcfn c-inflate-init "inflateInit2_" [:pointer :int :pointer :int] :int)
(ffi/defcfn c-inflate      "inflate"       [:pointer :int] :int)
(ffi/defcfn c-inflate-end  "inflateEnd"    [:pointer] :int)

;; Lay out a zeroed z_stream pointed at `src` (a byte-array) copied into foreign
;; memory; return [strm src-buf out-buf]. The caller frees all three.
(defn- setup [src]
  (let [n (alength src)
        strm    (ffi/alloc ZS)
        src-buf (ffi/alloc (max 1 n))
        out-buf (ffi/alloc CHUNK)]
    (dotimes [i ZS] (ffi/write strm :uint8 i 0))
    (ffi/write-array src-buf src)
    (ffi/write strm :pointer O-next-in src-buf)
    (ffi/write strm :uint O-avail-in n)
    [strm src-buf out-buf]))

(defn deflate-bytes
  "Compress byte-array `src` into `window-bits` format (15 zlib, 31 gzip, -15 raw)."
  [src window-bits]
  (let [[strm src-buf out-buf] (setup src)]
    (try
      (when-not (zero? (c-deflate-init strm 6 8 window-bits 8 0 (c-zlib-version) ZS))
        (throw (ex-info "zlib: deflateInit2 failed" {})))
      (let [chunks
            (loop [acc []]
              (ffi/write strm :pointer O-next-out out-buf)
              (ffi/write strm :uint O-avail-out CHUNK)
              (let [r (c-deflate strm Z-FINISH)
                    produced (- CHUNK (ffi/read strm :uint O-avail-out))
                    acc (if (pos? produced) (conj acc (ffi/read-array out-buf produced)) acc)]
                (cond
                  (neg? r) (do (c-deflate-end strm) (throw (ex-info "zlib: deflate failed" {:rc r})))
                  (= r Z-STREAM-END) acc
                  :else (recur acc))))]
        (c-deflate-end strm)
        (byte-array (mapcat seq chunks)))
      (finally (ffi/free strm) (ffi/free src-buf) (ffi/free out-buf)))))

(defn inflate-bytes
  "Decompress byte-array `src` read in `window-bits` format (15 zlib, 47 auto, -15 raw)."
  [src window-bits]
  (let [[strm src-buf out-buf] (setup src)]
    (try
      (when-not (zero? (c-inflate-init strm window-bits (c-zlib-version) ZS))
        (throw (ex-info "zlib: inflateInit2 failed" {})))
      (let [chunks
            (loop [acc []]
              (ffi/write strm :pointer O-next-out out-buf)
              (ffi/write strm :uint O-avail-out CHUNK)
              (let [r (c-inflate strm Z-NO-FLUSH)
                    produced (- CHUNK (ffi/read strm :uint O-avail-out))
                    acc (if (pos? produced) (conj acc (ffi/read-array out-buf produced)) acc)]
                (cond
                  (= r Z-STREAM-END) acc
                  (neg? r) (do (c-inflate-end strm) (throw (ex-info "zlib: inflate failed" {:rc r})))
                  ;; no output and no input left to consume — done.
                  (and (zero? produced) (zero? (ffi/read strm :uint O-avail-in))) acc
                  :else (recur acc))))]
        (c-inflate-end strm)
        (byte-array (mapcat seq chunks)))
      (finally (ffi/free strm) (ffi/free src-buf) (ffi/free out-buf)))))

(defn gzip         [src] (deflate-bytes src 31))
(defn gunzip       [src] (inflate-bytes src 47))
(defn zlib-deflate [src] (deflate-bytes src 15))
(defn zlib-inflate [src] (inflate-bytes src 15))
