(ns sudoers.main
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [sudoers.audit :as a]))

(defn usage []
  (binding [*out* *err*]
    (println "usage: sudoers-audit PATH [--tsv] [--fail-on medium|high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input."))
  2)

(defn sudoers-file? [^java.io.File f]
  (let [n (.getName f) parent (some-> (.getParentFile f) .getName)]
    (or (= n "sudoers") (str/ends-with? n ".sudoers") (= parent "sudoers.d"))))

(defn parse-args [args]
  (loop [xs args st {:path nil :tsv false :fail nil}]
    (cond
      (empty? xs) st
      (= (first xs) "--tsv") (recur (rest xs) (assoc st :tsv true))
      (= (first xs) "--fail-on")
      (let [v (second xs)]
        (if (#{"medium" "high" "critical"} v) (recur (nnext xs) (assoc st :fail v)) :bad))
      (str/starts-with? (first xs) "-") :bad
      (:path st) :bad
      :else (recur (rest xs) (assoc st :path (first xs))))))

(defn run [args]
  (let [st (parse-args args)]
    (if (or (= st :bad) (nil? (:path st)))
      (usage)
      (let [root (io/file (:path st))]
        (if-not (.exists root)
          (do (binding [*out* *err*] (println (str "error: no such file or directory: " (:path st)))) 2)
          (let [files (if (.isDirectory root)
                        (let [base (.toPath (.getAbsoluteFile root))]
                          (->> (file-seq root)
                               (filter #(and (.isFile ^java.io.File %) (sudoers-file? %)))
                               (map (fn [f] [(str/replace (str (.relativize base (.toPath (.getAbsoluteFile ^java.io.File f)))) "\\" "/") f]))
                               (sort-by first)))
                        [[(.getName root) root]])
                all (mapcat (fn [[label f]]
                              (if (> (.length ^java.io.File f) 4000000) [] (a/audit (slurp f) label)))
                            files)
                sorted (a/sort-findings all)
                head (str (count files) " files, " (count sorted) " findings")]
            (println (if (:tsv st) (str "# " head) head))
            (doseq [{:keys [sev rule where msg]} sorted]
              (if (:tsv st)
                (println (str/join "\t" [sev rule where msg]))
                (do (println (format "%-8s %s %s" (str/upper-case sev) rule where))
                    (println (str "         " msg)))))
            (if (and (:fail st) (some #(<= (a/rank (:sev %)) (a/rank (:fail st))) sorted)) 1 0)))))))

(defn -main [& args]
  (let [code (run args)]
    (flush)
    (System/exit code)))
