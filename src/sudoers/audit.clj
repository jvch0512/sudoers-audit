(ns sudoers.audit
  (:require [clojure.string :as str]))

(def rank {"critical" 0 "high" 1 "medium" 2 "low" 3 "info" 4})

(def shell-escape
  #{"sh" "bash" "dash" "zsh" "ksh" "csh" "vi" "vim" "view" "nano" "ed" "less" "more" "man" "find" "awk" "gawk" "mawk"
    "python" "python2" "python3" "perl" "ruby" "lua" "php" "node" "env" "tar" "zip" "unzip" "nmap" "git" "ftp" "ssh" "scp"
    "rsync" "tcpdump" "systemctl" "journalctl" "docker" "mount" "cp" "mv" "tee" "dd" "gdb" "strace" "busybox" "socat" "nc"
    "ncat" "wget" "curl" "apt" "apt-get" "yum" "pip" "pip3" "make" "script" "watch" "xargs" "time" "timeout" "nice" "su"})

(def pager-editors #{"vi" "vim" "view" "nano" "ed" "less" "more" "man"})

;; Escapes that work even when the arguments are pinned in sudoers.
(def always-escape (into pager-editors #{"sh" "bash" "dash" "zsh" "ksh" "csh" "su" "script" "busybox"}))

(defn logical-lines
  "Returns [[line-number text] ...] with continuations joined and comments dropped."
  [text]
  (let [raw (str/split text #"\r\n|\n|\r" -1)]
    (loop [i 0 acc []]
      (if (>= i (count raw))
        acc
        (let [start (inc i)
              [joined next-i]
              (loop [j i buf ""]
                (if (>= j (count raw))
                  [buf j]
                  (let [l (str/trim (nth raw j))
                        cont? (str/ends-with? l "\\")
                        body (if cont? (subs l 0 (dec (count l))) l)]
                    (if (and cont? (< (inc j) (count raw)) (< (count buf) 16384))
                      (recur (inc j) (str buf body " "))
                      [(str buf body) (inc j)]))))
              t (str/replace (str/trim (subs joined 0 (min 8192 (count joined)))) #"\s+" " ")
              t (if (and (str/starts-with? t "#") (not (re-find #"^#(include|includedir)\b" t))
                         (not (re-find #"^#\d+\s" t)))
                  ""
                  t)
              t (if (re-find #"\s#" t) (str/trim (first (str/split t #"\s#" 2))) t)]
          (recur next-i (if (str/blank? t) acc (conj acc [start t]))))))))

(defn split-commas [s]
  (->> (str/split s #"\s*,\s*") (map str/trim) (remove str/blank?)))

(defn parse-aliases
  "Map of alias name -> list of members, for User_Alias, Cmnd_Alias, Host_Alias, Runas_Alias."
  [lines]
  (reduce
   (fn [m [_ t]]
     (if-let [[_ _ body] (re-find #"^(User_Alias|Cmnd_Alias|Host_Alias|Runas_Alias)\s+(.+)$" t)]
       (reduce (fn [m2 part]
                 (if-let [[_ nm vals] (re-find #"^([A-Z][A-Z0-9_]*)\s*=\s*(.*)$" (str/trim part))]
                   (assoc m2 nm (vec (split-commas vals)))
                   m2))
               m (str/split body #"\s*:\s*(?=[A-Z][A-Z0-9_]*\s*=)"))
       m))
   {} lines))

(defn expand
  "Expands alias names inside a list of items, one level deep, guarding against loops."
  [aliases items]
  (loop [todo (vec items) seen #{} out []]
    (if (empty? todo)
      out
      (let [x (first todo) more (subvec todo 1)]
        (if (and (contains? aliases x) (not (seen x)))
          (recur (into (vec (aliases x)) more) (conj seen x) out)
          (recur more seen (conj out x)))))))

(defn parse-cmd-spec
  "Parses the right side of a user spec into [{:cmd :tags :runas}]."
  [rhs aliases]
  (loop [items (split-commas rhs) tags #{} runas nil acc []]
    (if (empty? items)
      acc
      (let [item (first items)
            [_ ra rest1] (re-find #"^\(([^)]*)\)\s*(.*)$" item)
            runas (or ra runas)
            item (if ra rest1 item)
            tag-match (re-find #"^((?:[A-Z_]+:\s*)+)(.*)$" item)
            [tags item] (if tag-match
                          (let [ts (map #(str/replace % ":" "") (re-seq #"[A-Z_]+:" (second tag-match)))
                                tags (reduce (fn [t x]
                                               (case x
                                                 "PASSWD" (disj t "NOPASSWD")
                                                 "NOPASSWD" (conj t "NOPASSWD")
                                                 "EXEC" (disj t "NOEXEC")
                                                 "NOEXEC" (conj t "NOEXEC")
                                                 "NOSETENV" (disj t "SETENV")
                                                 (conj t x)))
                                             tags ts)]
                            [tags (nth tag-match 2)])
                          [tags item])
            item (str/trim item)]
        (recur (rest items) tags runas
               (if (str/blank? item) acc (conj acc {:cmd item :tags tags :runas runas})))))))

(defn base-name [cmd]
  (let [w (first (str/split (str/replace cmd #"^!" "") #"\s+"))]
    (last (str/split w #"/"))))

(defn audit [text label]
  (let [lines (logical-lines text)
        aliases (parse-aliases lines)
        out (atom [])
        add! (fn [sev rule ln msg] (swap! out conj {:sev sev :rule rule :where (str label ":" ln) :msg msg}))]
    (doseq [[ln t] lines]
      (cond
        (re-find #"^(User_Alias|Cmnd_Alias|Host_Alias|Runas_Alias)\b" t) nil
        (re-find #"^#(include|includedir)\b|^@(include|includedir)\b" t) nil
        (re-find #"^Defaults\b" t)
        (let [body (str/replace t #"^Defaults\S*\s+" "")]
          (doseq [d (split-commas body)]
            (cond
              (re-find #"^!\s*authenticate\b" d)
              (add! "high" "SUD006" ln "Defaults !authenticate: sudo never asks for a password")
              (re-find #"^!\s*env_reset\b" d)
              (add! "medium" "SUD005" ln "!env_reset: the caller's whole environment reaches the command")
              (re-find #"^env_keep\s*[+]?=" d)
              (when-let [bad (seq (filter #(re-find #"(?i)^\"?(LD_PRELOAD|LD_LIBRARY_PATH|PATH|PYTHONPATH|PERL5LIB|RUBYLIB)\"?$" %)
                                          (map #(str/replace % #"[\"']" "") (str/split (str/replace d #"^env_keep\s*[+]?=\s*" "") #"\s+"))))]
                (add! "high" "SUD005" ln (str "env_keep passes " (str/join ", " bad) " to privileged commands"))))))
        :else
        (if-let [[_ who rest-of] (re-find #"^(\S+)\s+(.+?=.*)$" t)]
          (let [eqi (str/index-of rest-of "=")
                rhs (str/trim (subs rest-of (inc eqi)))
                who-items (expand aliases (split-commas who))
                specs (parse-cmd-spec rhs aliases)]
            (when (some #{"ALL"} who-items)
              (add! "high" "SUD002" ln "rule applies to ALL users: everyone on the host gets this grant"))
            (doseq [{:keys [cmd tags]} specs]
              (let [cmds (expand aliases [cmd])]
                (doseq [c cmds]
                  (let [neg? (str/starts-with? c "!")
                        bn (base-name c)]
                    (when-not neg?
                      (cond-> nil
                        (= c "ALL") (do (when (tags "NOPASSWD")
                                          (add! "high" "SUD001" ln "NOPASSWD with ALL commands: passwordless root for this principal")) nil))
                      (when (and (not= c "ALL") (str/includes? c "*"))
                        (add! "medium" "SUD003" ln (str "wildcard in command: " (subs c 0 (min 50 (count c))))))
                      (when (and (not= c "ALL") (not (str/starts-with? c "/")) (not (re-find #"^(sudoedit|ALL)\b" c))
                                 (not (re-find #"^[A-Z][A-Z0-9_]*$" c)))
                        (add! "medium" "SUD007" ln (str "command without an absolute path: " (subs c 0 (min 50 (count c))))))
                      (when (and (shell-escape bn)
                                 (or (always-escape bn)
                                     (not (re-find #"\s\S" (str/trim c)))
                                     (str/includes? c "*"))
                                 (not (and (tags "NOEXEC") (pager-editors bn))))
                        (add! (if (tags "NOPASSWD") "high" "medium") "SUD004" ln
                              (str bn " can spawn a shell or write arbitrary files"
                                   (when (tags "NOPASSWD") " (no password)"))))))))
              (when (tags "SETENV")
                (add! "medium" "SUD008" ln "SETENV tag: the caller chooses the environment of the command"))))
          (add! "info" "SUD000" ln (str "could not parse: " (subs t 0 (min 40 (count t))))))))
    (vec (distinct @out))))

(defn sort-findings [fs]
  (sort-by (fn [{:keys [sev where rule]}]
             (let [i (str/last-index-of where ":")]
               [(rank sev) (subs where 0 i) (Long/parseLong (subs where (inc i))) rule]))
           fs))
