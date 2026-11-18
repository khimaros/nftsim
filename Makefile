# the UML kernel and rootfs live in ~/.local/share/nftsim and are shared by
# every checkout and `cargo install`, so no target here touches them
CLEAN_BUILD := target
RELEASE_BIN := target/release/nftsim

build:
	cargo build --release
.PHONY: build

test: build
	./test.sh
.PHONY: test

test-e2e: build
	python3 -m unittest discover -s tests/e2e -v
.PHONY: test-e2e

precommit:
	cargo clippy --release --all-targets
	cargo test --release
	shellcheck res/*.sh test.sh
	ruff check tests
.PHONY: precommit

clean-build:
	rm -rf $(CLEAN_BUILD)
.PHONY: clean-build

# everything but the release binary
clean-intermediates:
	[ ! -d target ] || find target -mindepth 1 ! -path $(RELEASE_BIN) \
		! -path target/release ! -path target/CACHEDIR.TAG -delete
.PHONY: clean-intermediates

clean: clean-build
.PHONY: clean
