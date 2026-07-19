(ns kagitaba.import.sealed-archive
  "Production admission for an encrypted, secret-bearing archive.

  Authorization and hybrid-envelope validation complete before ciphertext is
  handed to a caller-supplied decryptor. Cryptography remains provider-owned."
  (:require [kotoba.security.crypto-policy :as crypto-policy]
            [kagitaba.import.admission :as import-admission]))

(def default-policy
  {:kotoba.security/crypto-policy-version 1
   :mode :hybrid-required
   :hybrid-epoch-floor 1})

(defn evaluate
  [{:keys [envelope ciphertext ciphertext-digest verify-digest-fn]
    :as request}]
  (let [crypto-result (crypto-policy/check-production-envelope
                       default-policy envelope)
        authorization-result (import-admission/evaluate
                              (assoc request :archive-digest ciphertext-digest))
        ciphertext-present? (and (some? ciphertext)
                                 (or (not (coll? ciphertext)) (seq ciphertext)))
        digest-verified? (and (ifn? verify-digest-fn)
                              (true? (verify-digest-fn ciphertext
                                                       ciphertext-digest)))
        violations (cond-> []
                     (not (:valid? crypto-result)) (conj :hybrid-envelope)
                     (not (:import/allowed? authorization-result))
                     (conj :import-authorization)
                     (not ciphertext-present?) (conj :ciphertext-required)
                     (not digest-verified?) (conj :ciphertext-digest))]
    {:sealed-import/allowed? (empty? violations)
     :sealed-import/violations violations
     :sealed-import/crypto crypto-result
     :sealed-import/authorization authorization-result
     :sealed-import/ciphertext-digest ciphertext-digest}))

(defn decrypt-admitted!
  "Invoke decrypt-fn only after every admission check succeeds."
  [{:keys [decrypt-fn ciphertext envelope] :as request}]
  (let [result (evaluate request)]
    (when-not (:sealed-import/allowed? result)
      (throw (ex-info "sealed archive import denied" result)))
    (when-not (ifn? decrypt-fn)
      (throw (ex-info "sealed archive decryptor required"
                      (assoc result :sealed-import/violations [:decryptor-required]))))
    (assoc result :sealed-import/plaintext (decrypt-fn envelope ciphertext))))
