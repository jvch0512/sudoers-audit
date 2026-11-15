test:
	clojure -cp src:tests -m sudoers.tests

sample:
	mkdir -p docs site
	bin/sudoers-audit examples 2>/dev/null > docs/sample-output.txt; true
	bin/sudoers-audit examples --tsv 2>/dev/null > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "sudoers-audit" "Audits sudoers files for passwordless root, shell escapes, wildcards, kept environment variables and rules that apply to everyone. Clojure." "Synthetic sudoers files."
