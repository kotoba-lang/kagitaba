(ns kagitaba.import.sealed-archive-test
  (:require [clojure.test :refer [deftest is]]
            [kagitaba.import.sealed-archive :as sealed]))

(def digest "sha256:ciphertext")
(def decrypt-calls (atom 0))

(def request
  {:envelope {:envelope/algorithms [:x25519 :ml-kem-768 :aes-256-gcm]
              :envelope/provider {:provider/id :qualified-provider
                                  :provider/fips-validated false}
              :envelope/epoch 2 :envelope/kem? true :envelope/hybrid? true}
   :ciphertext [1 2 3] :ciphertext-digest digest
   :verify-digest-fn (fn [bytes expected]
                       (and (= [1 2 3] bytes) (= digest expected)))
   :decrypt-fn (fn [_ _] (swap! decrypt-calls inc) :plaintext)
   :capability-token
   {:capability/version 1 :capability/audience :kagitaba/import
    :capability/subject :local-user :capability/actions #{:secret-archive/import}
    :capability/resources #{digest} :capability/request-digest digest
    :capability/not-before-ms 1000 :capability/expires-at-ms 2000
    :capability/nonce "sealed-1" :capability/signature [:valid digest]}
   :capability-context
   {:subject :local-user :now-ms 1500 :consume-nonce-fn (constantly true)
    :verify-signature-fn
    (fn [body signature] (= signature [:valid (:capability/request-digest body)]))}
   :hardware-signing-evidence
   {:provider-id :apple-secure-enclave :hardware-backed? true
    :provider-origin-verified? true :private-exported? false
    :sign-verified? true :unavailable-failed-closed? true}
   :audit-receipt
   {:receipt/version 1 :receipt/environment :production
    :receipt/authority-id :import-audit :receipt/artifact-digest digest
    :receipt/issued-at-ms 1500 :receipt/signature [:valid digest]}
   :receipt-context
   {:environment :production :authority-id :import-audit :now-ms 1600
    :max-age-ms 500
    :verify-signature-fn
    (fn [body signature] (= signature [:valid (:receipt/artifact-digest body)]))}})

(deftest hybrid-ciphertext-is-admitted-before-decryption
  (reset! decrypt-calls 0)
  (is (= :plaintext (:sealed-import/plaintext
                     (sealed/decrypt-admitted! request))))
  (is (= 1 @decrypt-calls)))

(deftest downgrade-tamper-and-missing-evidence-never-reach-decryptor
  (doseq [bad [(assoc-in request [:envelope :envelope/algorithms] [:x25519])
               (assoc-in request [:envelope :envelope/hybrid?] false)
               (assoc-in request [:envelope :envelope/epoch] 0)
               (assoc request :ciphertext [])
               (assoc request :verify-digest-fn (constantly false))
               (dissoc request :verify-digest-fn)
               (assoc-in request [:audit-receipt :receipt/artifact-digest]
                         "sha256:other")]]
    (reset! decrypt-calls 0)
    (is (false? (:sealed-import/allowed? (sealed/evaluate bad))))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"sealed archive import denied"
                          (sealed/decrypt-admitted! bad)))
    (is (zero? @decrypt-calls))))

(deftest missing-decryptor-fails-after-admission-without-plaintext
  (is (thrown-with-msg? clojure.lang.ExceptionInfo
                        #"sealed archive decryptor required"
                        (sealed/decrypt-admitted! (dissoc request :decrypt-fn)))))
