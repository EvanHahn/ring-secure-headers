(ns ring-secure-headers.frameguard-test
  (:require [clojure.test :refer :all]
            [ring-secure-headers.test-helpers :refer [dummy-handler make-test-helper]]
            [ring-secure-headers.core :refer [frameguard]]))

(def test-helper (make-test-helper frameguard "x-frame-options"))

(deftest frameguard-happy-path-test
  (testing "sets header to 'SAMEORIGIN' when passed no options"
    (test-helper {:expected "SAMEORIGIN"}))
  (testing "sets header to 'SAMEORIGIN' when passed empty options"
    (test-helper {:options {} :expected "SAMEORIGIN"}))
  (testing "sets header to 'DENY' when asked to"
    (test-helper {:options {:action :deny} :expected "DENY"}))
  (testing "sets header to 'SAMEORIGIN' when asked to"
    (test-helper {:options {:action :same-origin} :expected "SAMEORIGIN"}))
  (testing "sets header to 'ALLOW-FROM' when asked to"
    (test-helper {:options {:action :allow-from
                            :domain "https://example.com"}
                  :expected "ALLOW-FROM https://example.com"})))

(deftest frameguard-sad-path-test
  (testing "throws when not passed a map"
    (is (thrown? Exception (frameguard dummy-handler "deny")))
    (is (thrown? Exception (frameguard dummy-handler [:action :sameorigin]))))
  (testing "throws when passed a bogus action"
    (is (thrown? Exception (frameguard dummy-handler {:action nil})))
    (is (thrown? Exception (frameguard dummy-handler {:action "DENY"})))
    (is (thrown? Exception (frameguard dummy-handler {:action :bogus}))))
  (testing "throws when using ALLOW-FROM without a domain"
    (is (thrown? Exception (frameguard dummy-handler {:action :allow-from}))))
  (testing "throws when using ALLOW-FROM with a bogus domain"
    (is (thrown? Exception (frameguard dummy-handler {:action :allow-from
                                                      :domain nil})))
    (is (thrown? Exception (frameguard dummy-handler {:action :allow-from
                                                      :domain ""})))
    (is (thrown? Exception (frameguard dummy-handler {:action :allow-from
                                                      :domain 123})))))
