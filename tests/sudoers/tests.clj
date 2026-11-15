(ns sudoers.tests
  (:require [clojure.java.shell :refer [sh]]
            [clojure.string :as str]
            [sudoers.audit :as a]))

(def passed (atom 0))
(def failed (atom 0))
(defn check [ok what]
  (if ok (swap! passed inc) (do (swap! failed inc) (println "FAIL:" what))))

(defn rules [text] (set (map :rule (a/audit text "t"))))
(defn has? [text r] (contains? (rules text) r))
(defn cli [& args]
  (let [r (apply sh "bin/sudoers-audit" args)] [(:exit r) (:out r)]))

(defn -main [& _]
  ;; line handling
  (check (= [[2 "a b"]] (a/logical-lines "# c\na b # trailing\n")) "comments dropped")
  (check (= [[1 "a b c"]] (a/logical-lines "a \\\n b \\\n c\n")) "continuations joined")
  (check (= [[3 "x y"]] (a/logical-lines "\n\nx y\n")) "line numbers")
  (check (= [[1 "#include /etc/x"]] (a/logical-lines "#include /etc/x\n")) "#include kept")
  (check (empty? (a/logical-lines "")) "empty input")
  (check (= [[1 "a"]] (a/logical-lines "a \\")) "dangling continuation")
  (check (= [[1 "a"] [2 "b"]] (a/logical-lines "a\r\nb\r\n")) "CRLF")

  ;; aliases
  (let [al (a/parse-aliases (a/logical-lines "Cmnd_Alias A = /bin/ls, /bin/cat\nUser_Alias U = x, y : V = z\n"))]
    (check (= ["/bin/ls" "/bin/cat"] (al "A")) "cmnd alias members")
    (check (= ["x" "y"] (al "U")) "user alias members")
    (check (= ["z"] (al "V")) "second alias on a line"))
  (check (= ["/bin/ls" "/bin/cat"] (a/expand {"A" ["/bin/ls" "/bin/cat"]} ["A"])) "alias expansion")
  (check (= ["A"] (a/expand {"A" ["A"]} ["A"])) "alias loop terminates")
  (check (= ["x" "y"] (a/expand {"A" ["B"] "B" ["x" "y"]} ["A"])) "nested aliases")

  ;; spec parsing
  (let [s (a/parse-cmd-spec "(root) NOPASSWD: /bin/a, /bin/b, PASSWD: /bin/c" {})]
    (check (= 3 (count s)) "three commands")
    (check (contains? (:tags (first s)) "NOPASSWD") "first has NOPASSWD")
    (check (contains? (:tags (second s)) "NOPASSWD") "tag carries to next command")
    (check (not (contains? (:tags (nth s 2)) "NOPASSWD")) "PASSWD resets")
    (check (= "root" (:runas (first s))) "runas"))

  ;; rules
  (check (has? "bob ALL=(ALL) NOPASSWD: ALL" "SUD001") "SUD001 nopasswd all")
  (check (not (has? "bob ALL=(ALL) ALL" "SUD001")) "SUD001 needs NOPASSWD")
  (check (not (has? "bob ALL=(ALL) NOPASSWD: /bin/ls" "SUD001")) "SUD001 needs ALL")
  (check (has? "Cmnd_Alias X = ALL\nbob ALL=(ALL) NOPASSWD: X" "SUD001") "SUD001 through an alias")
  (check (not (has? "bob ALL=(ALL) NOPASSWD: ALL, !/bin/su" "SUD000")) "negation parses")
  (check (has? "ALL ALL=(root) /bin/id" "SUD002") "SUD002 ALL users")
  (check (has? "User_Alias U = ALL\nU ALL=(root) /bin/id" "SUD002") "SUD002 through an alias")
  (check (not (has? "bob ALL=(root) /bin/id" "SUD002")) "SUD002 named user")
  (check (has? "bob ALL=(root) /bin/chown * /srv" "SUD003") "SUD003 wildcard")
  (check (not (has? "bob ALL=(root) /bin/chown bob /srv" "SUD003")) "SUD003 no wildcard")
  (check (has? "bob ALL=(root) NOPASSWD: /usr/bin/vim" "SUD004") "SUD004 vim")
  (check (has? "bob ALL=(root) /bin/bash" "SUD004") "SUD004 bash")
  (check (= "high" (:sev (first (filter #(= "SUD004" (:rule %)) (a/audit "bob ALL=(root) NOPASSWD: /usr/bin/vim" "t"))))) "SUD004 high with NOPASSWD")
  (check (= "medium" (:sev (first (filter #(= "SUD004" (:rule %)) (a/audit "bob ALL=(root) /usr/bin/vim" "t"))))) "SUD004 medium with password")
  (check (not (has? "bob ALL=(root) NOEXEC: /usr/bin/vim" "SUD004")) "NOEXEC editors")
  (check (has? "bob ALL=(root) NOEXEC: /bin/bash" "SUD004") "NOEXEC does not save a shell")
  (check (has? "bob ALL=(root) /usr/bin/find" "SUD004") "bare find")
  (check (not (has? "bob ALL=(root) /usr/bin/find /var/log -name x" "SUD004")) "pinned arguments are not an escape")
  (check (has? "bob ALL=(root) /usr/bin/find /var/log *" "SUD004") "wildcard arguments are")
  (check (not (has? "bob ALL=(root) /usr/bin/systemctl restart nginx" "SUD004")) "systemctl with pinned arguments")
  (check (not (has? "bob ALL=(root) /bin/ls" "SUD004")) "ls is fine")
  (check (not (has? "bob ALL=(root) ALL, !/bin/bash" "SUD004")) "negated command is not a grant")
  (check (has? "Defaults env_keep += \"LD_PRELOAD\"" "SUD005") "SUD005 LD_PRELOAD")
  (check (has? "Defaults env_keep+=PATH" "SUD005") "SUD005 PATH")
  (check (has? "Defaults !env_reset" "SUD005") "SUD005 !env_reset")
  (check (not (has? "Defaults env_keep += \"EDITOR\"" "SUD005")) "SUD005 harmless variable")
  (check (not (has? "Defaults env_reset" "SUD005")) "env_reset is fine")
  (check (has? "Defaults !authenticate" "SUD006") "SUD006")
  (check (has? "Defaults:bob !authenticate" "SUD006") "SUD006 scoped Defaults")
  (check (not (has? "Defaults authenticate" "SUD006")) "authenticate is fine")
  (check (has? "bob ALL=(root) service apache2 restart" "SUD007") "SUD007 relative command")
  (check (not (has? "bob ALL=(root) /usr/sbin/service apache2 restart" "SUD007")) "absolute is fine")
  (check (not (has? "bob ALL=(root) sudoedit /etc/hosts" "SUD007")) "sudoedit is allowed")
  (check (has? "bob ALL=(root) SETENV: /bin/ls" "SUD008") "SUD008")
  (check (not (has? "bob ALL=(root) NOSETENV: /bin/ls" "SUD008")) "NOSETENV")
  (check (has? "this is not a rule" "SUD000") "SUD000")
  (check (empty? (rules "root ALL=(ALL:ALL) ALL\n%admin ALL=(ALL) ALL\nDefaults env_reset\n")) "typical Debian file is clean")
  (check (empty? (rules "")) "empty file")
  (check (empty? (rules "#include /etc/sudoers.local\n@includedir /etc/sudoers.d\n")) "include lines are not findings")

  ;; location and sorting
  (check (= "svc/sudoers:3" (:where (first (filter #(= "SUD006" (:rule %)) (a/audit "\n\nDefaults !authenticate\n" "svc/sudoers"))))) "where is label:line")
  (check (= ["a:2" "b:9" "b:10" "a:1"]
            (map :where (a/sort-findings [{:sev "low" :rule "B" :where "a:1"} {:sev "high" :rule "A" :where "b:9"}
                                          {:sev "high" :rule "A" :where "b:10"} {:sev "high" :rule "A" :where "a:2"}])))
         "sort by severity, file, numeric line")

  ;; hostile input and fuzz
  (let [ok (atom true)]
    (doseq [h [(apply str (repeat 200000 "a")) (apply str (repeat 50000 "\\\n")) (apply str (repeat 20000 ",")) "=" ":" "() =" "x y=" "Cmnd_Alias" "Cmnd_Alias A = A" "A ALL=(" "\u0000"
               (str "ALL ALL=(ALL) " (apply str (repeat 20000 "NOPASSWD: ")))]]
      (try (a/audit h "h") (catch Throwable e (reset! ok false) (println "hostile:" (.getName (class e))))))
    (check @ok "hostile inputs do not throw"))
  (let [rnd (java.util.Random. 42)
        alphabet "\\\n,:=()!*#@ ALLNOPASSWD/bin/vi"
        seed "User_Alias U = a, b\nCmnd_Alias C = /usr/bin/vim, /bin/ls *\nDefaults env_keep += \"LD_PRELOAD\"\nU ALL=(root) NOPASSWD: C, SETENV: /bin/id\nALL ALL=(ALL) ALL\n"
        ok (atom true)]
    (loop [i 0]
      (when (and (< i 3000) @ok)
        (let [sb (StringBuilder. ^String seed)]
          (dotimes [_ (inc (.nextInt rnd 6))]
            (when (zero? (.length sb)) (.append sb "x"))
            (let [pos (.nextInt rnd (.length sb))]
              (case (.nextInt rnd 3)
                0 (.replace sb pos (inc pos) (str (.charAt ^String alphabet (.nextInt rnd (count alphabet)))))
                1 (.delete sb pos (min (.length sb) (+ pos 1 (.nextInt rnd 8))))
                (.insert sb pos (str (.charAt ^String alphabet (.nextInt rnd (count alphabet))))))))
          (try (a/audit (str sb) "f") (catch Throwable e (reset! ok false) (println "fuzz:" (.getName (class e))))))
        (recur (inc i))))
    (check @ok "fuzzing 3000 inputs never throws"))

  ;; CLI
  (check (= 0 (first (cli "examples"))) "cli exit 0")
  (check (= 1 (first (cli "examples" "--fail-on" "high"))) "cli --fail-on high")
  (check (= 0 (first (cli "examples/sudoers" "--fail-on" "high"))) "plain file passes --fail-on high")
  (let [lines (remove str/blank? (str/split-lines (second (cli "examples" "--tsv"))))]
    (check (and (str/starts-with? (first lines) "# ") (every? #(= 3 (count (re-seq #"\t" %))) (rest lines))) "tsv format"))
  (check (= 2 (first (cli "/no/such/path"))) "missing path")
  (check (= 2 (first (cli))) "no args")
  (check (= 2 (first (cli "examples" "--bogus"))) "unknown flag")
  (check (= 2 (first (cli "examples" "--fail-on" "nope"))) "bad --fail-on")
  (check (= 2 (first (cli "examples" "examples"))) "two paths")

  (println (str @passed " passed, " @failed " failed"))
  (System/exit (if (pos? @failed) 1 0)))
