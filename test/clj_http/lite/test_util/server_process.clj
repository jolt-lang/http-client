(ns clj-http.lite.test-util.server-process
  "Jolt stand-in for clj-http-lite's server-process fixture. The upstream version
  shells out to a Jetty subprocess; here `launch` starts in-process plaintext +
  TLS servers (jolt.http.test-server, over jolt.ffi sockets + OpenSSL) serving the
  same routes, and returns their ports. `kill` stops them."
  (:require [jolt.http.test-server :as srv]))

(def ^:private http-port 18091)
(def ^:private https-port 18092)

(defn launch []
  (let [pwd  (jolt.host/getenv "JOLT_PWD")
        cert (str pwd "/test/resources/cert.pem")
        key  (str pwd "/test/resources/key.pem")
        plain (srv/start-plain http-port)
        tls   (srv/start-tls https-port cert key)]
    (Thread/sleep 300)
    {:http-port http-port :https-port https-port :plain plain :tls tls}))

(defn kill [{:keys [plain tls]}]
  (when plain (srv/stop plain))
  (when tls (srv/stop tls))
  nil)
