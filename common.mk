SHELL := /bin/bash

release-major:
	$(eval export TAG=$(shell git describe --tags --match 'v*.*.*' | perl -ne '/^v(\d+)\.(\d+)\.(\d+)/; print "v@{[$$1+1]}.0.0"'))
	$(MAKE) release

release-minor:
	$(eval export TAG=$(shell git describe --tags --match 'v*.*.*' | perl -ne '/^v(\d+)\.(\d+)\.(\d+)/; print "v$$1.@{[$$2+1]}.0"'))
	$(MAKE) release

release-patch:
	$(eval export TAG=$(shell git describe --tags --match 'v*.*.*' | perl -ne '/^v(\d+)\.(\d+)\.(\d+)/; print "v$$1.$$2.@{[$$3+1]}"'))
	$(MAKE) release

release:
	@if [[ "$$(git branch --show-current)" != main ]]; then echo "Releases must be run from main"; exit 1; fi
	@if ! git diff --quiet HEAD; then echo "Commit staged and unstaged changes before proceeding"; exit 1; fi
	@if [[ ! $$TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+$$ ]]; then echo "Use release-{major,minor,patch}"; exit 1; fi
	@command -v pandoc >/dev/null || { echo "Please install pandoc"; exit 1; }
	@command -v sponge >/dev/null || { echo "Please install moreutils"; exit 1; }
	@command -v gh >/dev/null || { echo "Please install gh"; exit 1; }
	@python -c 'import build' || { echo "Please install build"; exit 1; }
	git pull --ff-only
	@if git show-ref --verify --quiet "refs/tags/$$TAG"; then echo "Tag $$TAG already exists"; exit 1; fi
	@set -eo pipefail; \
	    release_dir=$$(mktemp -d); \
	    trap 'rm -rf "$$release_dir"' EXIT; \
	    notes="$$release_dir/notes.md"; \
	    printf '# Changes for %s (%s)\n\n' "$$TAG" "$$(date +%Y-%m-%d)" > "$$notes"; \
	    git log --format=%s "$$(git describe --tags --abbrev=0 --match 'v*.*.*')..HEAD" >> "$$notes"; \
	    $${EDITOR:-emacs} "$$notes"; \
	    { pandoc --from markdown --to rst "$$notes"; echo; cat Changes.rst; } | sponge Changes.rst; \
	    git add Changes.rst; \
	    git commit -m "$$TAG"; \
	    git tag --annotate --file "$$notes" "$$TAG"; \
	    python -m build --outdir "$$release_dir/dist"; \
	    git push --atomic origin HEAD:refs/heads/main "refs/tags/$$TAG"; \
	    gh release create "$$TAG" "$$release_dir"/dist/*.whl --verify-tag --title "$$TAG" --notes-file "$$notes"

.PHONY: release-major release-minor release-patch release
