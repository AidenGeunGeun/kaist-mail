.PHONY: check build

check:
	cargo fmt --all -- --check
	cargo test --locked --all-targets
	cargo clippy --locked --all-targets -- -D warnings
	cargo deny --locked check

build:
	cargo build --release --locked
