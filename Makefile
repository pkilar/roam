CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
PREFIX  ?= /usr/local
CONFDIR ?= /etc/sysconfig

TARGET = roam

all: $(TARGET)

$(TARGET): roam.c
	$(CC) $(CFLAGS) -o $@ $<
	strip $@

install: $(TARGET)
	install -Dm0755 -o root -g root $(TARGET) $(DESTDIR)$(PREFIX)/sbin/$(TARGET)
	setcap cap_dac_read_search,cap_setpcap+eip $(DESTDIR)$(PREFIX)/sbin/$(TARGET)
	@# Config — don't overwrite existing
	test -f $(DESTDIR)$(CONFDIR)/roam || \
		install -Dm0644 -o root -g root roam.conf $(DESTDIR)$(CONFDIR)/roam
	@# Sudoers — don't overwrite existing
	test -f $(DESTDIR)/etc/sudoers.d/roam || \
		install -Dm0440 -o root -g root roam.sudoers $(DESTDIR)/etc/sudoers.d/roam

install-user:
	@echo "Creating 'roam' system user..."
	useradd -r -m -s /sbin/nologin roam 2>/dev/null || \
		echo "User 'roam' already exists"

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all install install-user uninstall clean
