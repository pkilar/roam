CARGO     ?= cargo
PREFIX    ?= /usr
CONFDIR   ?= /etc/roam
POLICYDIR ?= /etc/roam

TARGET      := roam
DEBUG_BIN   := target/debug/$(TARGET)
RELEASE_BIN := target/release/$(TARGET)

all: release

debug: $(DEBUG_BIN)

release: $(TARGET)

$(DEBUG_BIN):
	$(CARGO) build --workspace --bins

$(RELEASE_BIN):
	$(CARGO) build --workspace --release --bins

$(TARGET): $(RELEASE_BIN)
	install -m0755 $(RELEASE_BIN) $(TARGET)

check:
	$(CARGO) check --workspace

test:
	$(CARGO) test --workspace

fmt:
	$(CARGO) fmt --all

clippy:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

rpm:
	./build-rpm.sh

deb:
	./build-deb.sh

arch:
	./build-arch.sh

install: $(TARGET)
	install -Dm0755 $(TARGET) $(DESTDIR)$(PREFIX)/sbin/$(TARGET)
	@# Session config — don't overwrite existing
	test -f $(DESTDIR)$(CONFDIR)/config.toml || \
		install -Dm0644 roam.config.toml $(DESTDIR)$(CONFDIR)/config.toml
	@# Broker policy — don't overwrite existing
	test -f $(DESTDIR)$(POLICYDIR)/policy.toml || \
		install -Dm0644 roam.policy.toml $(DESTDIR)$(POLICYDIR)/policy.toml
	@# Sudoers — don't overwrite existing
	test -f $(DESTDIR)/etc/sudoers.d/roam || \
		install -Dm0440 roam.sudoers $(DESTDIR)/etc/sudoers.d/roam

install-user:
	@echo "Creating 'roam' system user..."
	useradd -r -m -s /sbin/nologin roam 2>/dev/null || \
		echo "User 'roam' already exists"

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/$(TARGET)

clean:
	rm -f $(TARGET)
	$(CARGO) clean

.PHONY: all debug release check test fmt clippy rpm deb arch install install-user uninstall clean
