.PHONY: check build dist smoke

VERSION := $(shell sed -n 's/^version = "\(.*\)"$$/\1/p' Cargo.toml)
TARGET := $(shell rustc -vV | sed -n 's/^host: //p')
PACKAGE := kaist-mail-v$(VERSION)-$(TARGET)

check:
	cargo fmt --all -- --check
	cargo test --locked --all-targets
	cargo clippy --locked --all-targets -- -D warnings
	cargo deny --locked check

build:
	cargo build --release --locked

# COPYFILE_DISABLE keeps macOS tar from adding AppleDouble (._*) members.
dist: build
	rm -rf dist/$(PACKAGE)
	mkdir -p dist/$(PACKAGE)
	cp target/release/kaist-mail README.md LICENSE dist/$(PACKAGE)/
	COPYFILE_DISABLE=1 tar -C dist -czf dist/$(PACKAGE).tar.gz $(PACKAGE)
	cd dist && shasum -a 256 $(PACKAGE).tar.gz > $(PACKAGE).tar.gz.sha256

smoke: dist
	python3 scripts/release_smoke.py dist/$(PACKAGE).tar.gz
