# SplitGate - install / packaging
#
#   make test                 run the tests
#   sudo make install         install under /usr
#   make install DESTDIR=...  build a package (this is how the PKGBUILD uses it)
#   sudo make uninstall       remove (keeps the config file; PURGE=1 deletes it)
#   make dist                 create dist/dpigec-<version>.tar.gz

NAME      := dpigec
VERSION   := $(shell sed -n 's/^__version__ = "\(.*\)"/\1/p' src/dpigec/__init__.py)
PREFIX    ?= /usr
DESTDIR   ?=
SYSCONFDIR ?= /etc
PYTHON    ?= python3
SYSTEMD_DIR ?= $(PREFIX)/lib/systemd/system
# Debian/Ubuntu: dist-packages, diğerleri: site-packages
PYSITE    ?= $(shell if [ -d /usr/lib/python3/dist-packages ]; then echo /usr/lib/python3/dist-packages; else $(PYTHON) -c 'import sysconfig; print(sysconfig.get_path("purelib", scheme="posix_prefix", vars={"base": "$(PREFIX)", "platbase": "$(PREFIX)"}))'; fi)

SED_TPL = sed -e 's|@PREFIX@|$(PREFIX)|g'

.PHONY: all install uninstall test dist clean

all:
	@echo "Nothing to build. To install: sudo make install"

install:
	install -d $(DESTDIR)$(PYSITE)/dpigec/gui/resources
	install -m 644 src/dpigec/*.py $(DESTDIR)$(PYSITE)/dpigec/
	install -m 644 src/dpigec/gui/*.py $(DESTDIR)$(PYSITE)/dpigec/gui/
	install -m 644 src/dpigec/gui/resources/dpigec.svg $(DESTDIR)$(PYSITE)/dpigec/gui/resources/
	install -Dm 755 bin/dpigec $(DESTDIR)$(PREFIX)/bin/dpigec
	install -Dm 755 bin/dpigec-gui $(DESTDIR)$(PREFIX)/bin/dpigec-gui
	install -Dm 755 bin/dpigecctl $(DESTDIR)$(PREFIX)/lib/dpigec/dpigecctl
	install -d $(DESTDIR)$(SYSTEMD_DIR) $(DESTDIR)$(PREFIX)/share/polkit-1/actions \
	           $(DESTDIR)$(PREFIX)/share/applications \
	           $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps \
	           $(DESTDIR)$(PREFIX)/share/doc/$(NAME)
	$(SED_TPL) data/dpigec.service > $(DESTDIR)$(SYSTEMD_DIR)/dpigec.service
	$(SED_TPL) data/org.dpigec.policy > $(DESTDIR)$(PREFIX)/share/polkit-1/actions/org.dpigec.policy
	$(SED_TPL) data/dpigec.desktop > $(DESTDIR)$(PREFIX)/share/applications/dpigec.desktop
	chmod 644 $(DESTDIR)$(SYSTEMD_DIR)/dpigec.service \
	          $(DESTDIR)$(PREFIX)/share/polkit-1/actions/org.dpigec.policy \
	          $(DESTDIR)$(PREFIX)/share/applications/dpigec.desktop
	install -m 644 src/dpigec/gui/resources/dpigec.svg $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/dpigec.svg
	install -m 644 README.md README.tr.md $(DESTDIR)$(PREFIX)/share/doc/$(NAME)/
	install -d $(DESTDIR)$(SYSCONFDIR)/dpigec
	@if [ ! -e $(DESTDIR)$(SYSCONFDIR)/dpigec/config.json ]; then \
	    install -m 644 data/config.json $(DESTDIR)$(SYSCONFDIR)/dpigec/config.json; \
	else echo "existing config file kept"; fi
	@echo "Installed. Service: systemctl daemon-reload"

uninstall:
	rm -rf $(DESTDIR)$(PYSITE)/dpigec $(DESTDIR)$(PREFIX)/lib/dpigec
	rm -f $(DESTDIR)$(PREFIX)/bin/dpigec $(DESTDIR)$(PREFIX)/bin/dpigec-gui \
	      $(DESTDIR)$(SYSTEMD_DIR)/dpigec.service \
	      $(DESTDIR)$(PREFIX)/share/polkit-1/actions/org.dpigec.policy \
	      $(DESTDIR)$(PREFIX)/share/applications/dpigec.desktop \
	      $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/dpigec.svg
	rm -rf $(DESTDIR)$(PREFIX)/share/doc/$(NAME)
	@if [ "$(PURGE)" = "1" ]; then rm -rf $(DESTDIR)$(SYSCONFDIR)/dpigec; \
	else echo "Config file kept ($(SYSCONFDIR)/dpigec). To delete it: make uninstall PURGE=1"; fi

test:
	$(PYTHON) -m unittest discover -s tests -v

dist:
	rm -rf dist/$(NAME)-$(VERSION)
	mkdir -p dist/$(NAME)-$(VERSION)
	cp -r src bin data tests packaging Makefile README.md README.tr.md LICENSE install.sh uninstall.sh .gitignore \
	      dist/$(NAME)-$(VERSION)/
	find dist/$(NAME)-$(VERSION) -name __pycache__ -type d -prune -exec rm -rf {} +
	tar --owner=0 --group=0 --numeric-owner -C dist -czf dist/$(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)
	rm -rf dist/$(NAME)-$(VERSION)
	@echo "dist/$(NAME)-$(VERSION).tar.gz ready"

clean:
	rm -rf dist build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
