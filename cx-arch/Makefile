# CXMOD — Connection eXperience MODule
# GNU Makefile
#
# Targets:
#   make            Build the cxmod binary
#   make install    Install to $(PREFIX)/sbin + man page
#   make uninstall  Remove installed files
#   make clean      Remove build artifacts
#   make dist       Create CXMOD.tar.gz source tarball
#   make check      Run self-tests
#   make rpm        Build RPM package (requires rpmbuild)
#   make deb        Build .deb package (requires dpkg-deb)

PREFIX  ?= /usr/local
DESTDIR ?=
VERSION := $(shell grep 'CXMOD_VERSION' include/cxmod.h | grep define | sed 's/.*"\(.*\)".*/\1/')

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -std=c99 \
           -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
           -Iinclude
LDFLAGS ?=

SRCS    := src/main.c      \
           src/util.c      \
           src/iface.c     \
           src/proto.c     \
           src/diagnose.c  \
           src/tune.c      \
           src/conntrack.c \
           src/irq.c       \
           src/qos.c       \
           src/route.c     \
           src/monitor.c   \
           src/sockstat.c  \
           src/offload.c   \
           src/persist.c   \
           src/report.c    \
           src/fix.c

OBJS    := $(SRCS:.c=.o)
TARGET  := cxmod

SBINDIR  := $(DESTDIR)$(PREFIX)/sbin
MANDIR   := $(DESTDIR)$(PREFIX)/share/man/man8
DOCDIR   := $(DESTDIR)$(PREFIX)/share/doc/cxmod
ETCDIR   := $(DESTDIR)/etc

.PHONY: all install uninstall clean dist check rpm deb

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo ""
	@echo "  Build OK: ./$(TARGET)  (v$(VERSION))"
	@echo "  Test:     ./$(TARGET) --help"
	@echo "  Fix-all:  sudo ./$(TARGET) fix"

src/%.o: src/%.c include/cxmod.h
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	install -d $(SBINDIR)
	install -m 755 $(TARGET) $(SBINDIR)/$(TARGET)
	install -d $(MANDIR)
	install -m 644 man/cxmod.8 $(MANDIR)/cxmod.8
	gzip -f $(MANDIR)/cxmod.8 2>/dev/null || true
	install -d $(DOCDIR)
	install -m 644 README   $(DOCDIR)/README
	install -m 644 INSTALL  $(DOCDIR)/INSTALL
	install -m 644 COPYING  $(DOCDIR)/COPYING 2>/dev/null || true
	@if [ -d $(DESTDIR)/etc/systemd/system ]; then \
	    install -m 644 scripts/cxmod.service \
	        $(DESTDIR)/etc/systemd/system/cxmod.service; \
	    echo "  systemd: systemctl enable --now cxmod"; \
	fi
	@echo ""
	@echo "  Installed: $(SBINDIR)/$(TARGET)  (v$(VERSION))"
	@echo "  Quick start:"
	@echo "    sudo cx diagnose"
	@echo "    sudo cx fix"

uninstall:
	rm -f  $(SBINDIR)/$(TARGET)
	rm -f  $(MANDIR)/cxmod.8 $(MANDIR)/cxmod.8.gz
	rm -rf $(DOCDIR)
	rm -f  $(DESTDIR)/etc/systemd/system/cxmod.service
	@echo "  Uninstalled."

clean:
	rm -f $(OBJS) $(TARGET)
	@echo "  Cleaned."

dist: clean
	@DIR=cxmod-$(VERSION); \
	cd .. && tar -czf CXMOD.tar.gz \
	    --transform="s|^cxmod_src|$$DIR|" \
	    cxmod_src/ && \
	echo "  Created CXMOD.tar.gz  ($$DIR/)"

check: $(TARGET)
	@chmod +x tests/test_basic.sh
	@./tests/test_basic.sh ./$(TARGET)

rpm: dist
	@mkdir -p ~/rpmbuild/BUILD ~/rpmbuild/RPMS ~/rpmbuild/SOURCES \
	           ~/rpmbuild/SPECS ~/rpmbuild/SRPMS
	@cp ../CXMOD.tar.gz ~/rpmbuild/SOURCES/cxmod-$(VERSION).tar.gz
	@printf 'Name:    cxmod\nVersion: $(VERSION)\nRelease: 1%%{?dist}\n' \
	    > ~/rpmbuild/SPECS/cxmod.spec
	@printf 'Summary: Connection eXperience MODule\n' >> ~/rpmbuild/SPECS/cxmod.spec
	@printf 'License: GPL-2.0-or-later\n' >> ~/rpmbuild/SPECS/cxmod.spec
	@printf 'Source0: %%{name}-%%{version}.tar.gz\n' >> ~/rpmbuild/SPECS/cxmod.spec
	@printf 'BuildRequires: gcc make\n' >> ~/rpmbuild/SPECS/cxmod.spec
	@printf '%%description\nCXMOD Linux network management utility.\n' \
	    >> ~/rpmbuild/SPECS/cxmod.spec
	@printf '%%prep\n%%setup -q\n%%build\nmake PREFIX=%%{_prefix}\n' \
	    >> ~/rpmbuild/SPECS/cxmod.spec
	@printf '%%install\nmake install PREFIX=%%{_prefix} DESTDIR=%%{buildroot}\n' \
	    >> ~/rpmbuild/SPECS/cxmod.spec
	@printf '%%files\n%%{_sbindir}/cxmod\n%%{_mandir}/man8/cxmod.8*\n%%doc README INSTALL\n' \
	    >> ~/rpmbuild/SPECS/cxmod.spec
	@rpmbuild -ba ~/rpmbuild/SPECS/cxmod.spec
	@echo "  RPM built in ~/rpmbuild/RPMS/"

deb: $(TARGET)
	@rm -rf /tmp/cxmod-deb
	@mkdir -p /tmp/cxmod-deb/DEBIAN /tmp/cxmod-deb/usr/sbin \
	           /tmp/cxmod-deb/usr/share/man/man8 \
	           /tmp/cxmod-deb/usr/share/doc/cxmod
	@install -m 755 $(TARGET) /tmp/cxmod-deb/usr/sbin/cxmod
	@install -m 644 man/cxmod.8 /tmp/cxmod-deb/usr/share/man/man8/
	@gzip -f /tmp/cxmod-deb/usr/share/man/man8/cxmod.8
	@install -m 644 README INSTALL /tmp/cxmod-deb/usr/share/doc/cxmod/
	@printf 'Package: cxmod\nVersion: $(VERSION)\nSection: net\n' \
	    > /tmp/cxmod-deb/DEBIAN/control
	@printf 'Priority: optional\nArchitecture: amd64\n' >> /tmp/cxmod-deb/DEBIAN/control
	@printf 'Maintainer: CXMOD Contributors\n' >> /tmp/cxmod-deb/DEBIAN/control
	@printf 'Description: Connection eXperience MODule\n' >> /tmp/cxmod-deb/DEBIAN/control
	@printf ' Linux server network management and diagnostics.\n' \
	    >> /tmp/cxmod-deb/DEBIAN/control
	@dpkg-deb --build /tmp/cxmod-deb cxmod_$(VERSION)_amd64.deb
	@echo "  DEB built: cxmod_$(VERSION)_amd64.deb"
