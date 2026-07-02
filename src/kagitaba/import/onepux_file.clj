(ns kagitaba.import.onepux-file
  "`.1pux` ファイル(zip)を読んで `kagitaba.import.onepux` の純粋変換に渡す JVM 専用 IO 層。

  1PUX archive layout(1Password 公式ドキュメント support.1password.com/1pux-format/):
    export.attributes  — {version, description, createdAt}
    export.data        — 本体(accounts/vaults/items の JSON)
    files/...           — 添付ファイル・カスタムアイコン(パス構造は非公開。
                           best-effort でファイル名 → bytes を集めるだけに留める)"
  (:require [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [kagitaba.import.onepux :as onepux])
  (:import [java.util.zip ZipFile]
           [java.io ByteArrayOutputStream]))

(defn- entry-bytes ^bytes [^ZipFile zf entry]
  (with-open [in (.getInputStream zf entry)
              out (ByteArrayOutputStream.)]
    (.transferTo in out)
    (.toByteArray out)))

(defn- entry-str [^ZipFile zf entry]
  (String. (entry-bytes zf entry) "UTF-8"))

(defn load-1pux
  "path(String/java.io.File)を読み、
  `{:attributes {...} :vaults [...] :warnings [...] :files {name -> bytes}}` を返す。
  `:vaults`/`:warnings` の shape は `kagitaba.import.onepux/parse-export-data` と同じ。"
  [path]
  (with-open [zf (ZipFile. (io/file path))]
    (let [entries (enumeration-seq (.entries zf))
          by-name (into {} (map (fn [e] [(.getName e) e])) entries)
          attrs-entry (get by-name "export.attributes")
          data-entry (or (get by-name "export.data")
                         (throw (ex-info "not a 1PUX export: export.data missing"
                                         {:path (str path) :entries (keys by-name)})))
          attributes (when attrs-entry
                       (json/read-str (entry-str zf attrs-entry) :key-fn keyword))
          export-data (json/read-str (entry-str zf data-entry) :key-fn keyword)
          {:keys [vaults warnings]} (onepux/parse-export-data export-data)
          files (into {}
                      (keep (fn [[name entry]]
                              (when (and (str/starts-with? name "files/")
                                         (not (.isDirectory entry)))
                                [(subs name (count "files/")) (entry-bytes zf entry)])))
                      by-name)]
      {:attributes attributes
       :vaults vaults
       :warnings warnings
       :files files})))
