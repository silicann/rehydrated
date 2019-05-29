include make.d/makefilet.mk

.PHONY: default-target
default-target:
	true

.PHONY: install
install:
	install -D -o 755 src/rehydrated-hook.py "$$DESTDIR/usr/share/rehydrated/rehydrated-hook.py"
	install -D -o 755 src/rehydrated-hook-helper "$$DESTDIR/usr/share/rehydrated/rehydrated-hook-helper"

.PHONY: test
test:
	shellcheck -s sh debian/system-files/rehydrated-gpg
	shellcheck -s sh src/rehydrated-hook-helper
	flake8 src
