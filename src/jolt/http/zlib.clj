(ns jolt.http.zlib
  "gzip / zlib / raw-deflate over the system libz, via Jolt's Janet FFI bridge.
  Backs the java.util.zip stream shims clj-http-lite uses for content-encoding.

  Window-bits convention (zlib inflateInit2/deflateInit2):
    15  -> zlib format (java.util.zip default)   31 -> gzip (15+16)
    47  -> auto-detect zlib/gzip on inflate       -15 -> raw, no header

  All FFI handles/signatures are created lazily and held in an atom — never
  module-level values (ffi handles are unmarshalable; an app baking this lib into
  a native image would otherwise fail).")

(def ^:private ZS 112)            ;; sizeof(z_stream) on LP64
(def ^:private O-next-in 0)
(def ^:private O-avail-in 8)
(def ^:private O-next-out 24)
(def ^:private O-avail-out 32)
(def ^:private CHUNK 65536)
(def ^:private Z-STREAM-END 1)
(def ^:private Z-FINISH 4)
(def ^:private Z-NO-FLUSH 0)

(def ^:private state (atom nil))

(defn- load! []
  (or @state
      (let [libz (or (try (janet.ffi/native "/usr/lib/libz.dylib") (catch Throwable _ nil))
                     (try (janet.ffi/native "/opt/homebrew/lib/libz.dylib") (catch Throwable _ nil))
                     (try (janet.ffi/native "libz.so.1") (catch Throwable _ nil))
                     (try (janet.ffi/native "libz.so") (catch Throwable _ nil))
                     (throw (ex-info "zlib: could not load libz (gzip/deflate unavailable)" {})))
            look (fn [n] (janet.ffi/lookup libz n))
            s {:deflateInit2_ (look "deflateInit2_")
               :deflate       (look "deflate")
               :deflateEnd    (look "deflateEnd")
               :inflateInit2_ (look "inflateInit2_")
               :inflate       (look "inflate")
               :inflateEnd    (look "inflateEnd")
               :ver           (janet.ffi/call (look "zlibVersion") (janet.ffi/signature :default :ptr))
               :sig-di   (janet.ffi/signature :default :int :ptr :int :int :int :int :int :ptr :int)
               :sig-ii   (janet.ffi/signature :default :int :ptr :int :ptr :int)
               :sig-pump (janet.ffi/signature :default :int :ptr :int)
               :sig-end  (janet.ffi/signature :default :int :ptr)}]
        (reset! state s)
        s)))

(defn deflate-bytes
  "Compress `src` into `window-bits` format (15 zlib, 31 gzip, -15 raw)."
  [src window-bits]
  (let [{:keys [deflateInit2_ deflate deflateEnd ver sig-di sig-pump sig-end]} (load!)
        src (janet/string src)
        strm (janet.buffer/new-filled ZS 0)]
    (janet.ffi/write :ptr src strm O-next-in)
    (janet.ffi/write :u32 (janet/length src) strm O-avail-in)
    (when-not (zero? (janet.ffi/call deflateInit2_ sig-di strm 6 8 window-bits 8 0 ver ZS))
      (throw (ex-info "zlib: deflateInit2 failed" {})))
    (let [out (janet/buffer "")
          chunk (janet.buffer/new-filled CHUNK 0)]
      (loop []
        (janet.ffi/write :ptr chunk strm O-next-out)
        (janet.ffi/write :u32 CHUNK strm O-avail-out)
        (let [r (janet.ffi/call deflate sig-pump strm Z-FINISH)
              produced (- CHUNK (janet.ffi/read :u32 strm O-avail-out))]
          (when (pos? produced) (janet.buffer/push out (janet.buffer/slice chunk 0 produced)))
          (when (neg? r) (janet.ffi/call deflateEnd sig-end strm) (throw (ex-info "zlib: deflate failed" {:rc r})))
          (when-not (= r Z-STREAM-END) (recur))))
      (janet.ffi/call deflateEnd sig-end strm)
      out)))

(defn inflate-bytes
  "Decompress `src` read in `window-bits` format (15 zlib, 47 auto, -15 raw)."
  [src window-bits]
  (let [{:keys [inflateInit2_ inflate inflateEnd ver sig-ii sig-pump sig-end]} (load!)
        src (janet/string src)
        strm (janet.buffer/new-filled ZS 0)]
    (janet.ffi/write :ptr src strm O-next-in)
    (janet.ffi/write :u32 (janet/length src) strm O-avail-in)
    (when-not (zero? (janet.ffi/call inflateInit2_ sig-ii strm window-bits ver ZS))
      (throw (ex-info "zlib: inflateInit2 failed" {})))
    (let [out (janet/buffer "")
          chunk (janet.buffer/new-filled CHUNK 0)]
      (loop []
        (janet.ffi/write :ptr chunk strm O-next-out)
        (janet.ffi/write :u32 CHUNK strm O-avail-out)
        (let [r (janet.ffi/call inflate sig-pump strm Z-NO-FLUSH)
              produced (- CHUNK (janet.ffi/read :u32 strm O-avail-out))]
          (when (pos? produced) (janet.buffer/push out (janet.buffer/slice chunk 0 produced)))
          (cond
            (= r Z-STREAM-END) nil
            (neg? r) (do (janet.ffi/call inflateEnd sig-end strm) (throw (ex-info "zlib: inflate failed" {:rc r})))
            (and (zero? produced) (zero? (janet.ffi/read :u32 strm O-avail-in))) nil
            :else (recur))))
      (janet.ffi/call inflateEnd sig-end strm)
      out)))

(defn gzip [src] (deflate-bytes src 31))
(defn gunzip [src] (inflate-bytes src 47))
(defn zlib-deflate [src] (deflate-bytes src 15))
(defn zlib-inflate [src] (inflate-bytes src 15))
