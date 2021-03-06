MAN_PATH	= /usr/share/man/man1
PYTHON_EXEC	= python
PIP_EXEC	= pip
VERSION		= 0.1a8

make:
	@echo "make install   Build and then install via pip and move manpage"
	@echo "make uninstall Clean build files and uninstall via pip"
	@echo
	@echo "Developer commands"
	@echo "make doc       Build html documentation with Sphinx"
	@echo "make man       Build manpage with Sphinx"
	@echo "make dist      Build python source archive file"
	@echo "make clean     Clean program and doc build files"

rm_pyc:
	find . -name "*.pyc" | xargs /bin/rm -f

doc_clean: rm_pyc
	cd sphinx-doc/root/; make clean
	cd sphinx-doc/en/; make clean
	#cd sphinx-doc/nl/; make clean

doc: doc_clean
	cd sphinx-doc/root/; make html
	cd sphinx-doc/en/; make html
	#cd sphinx-doc/nl/; make html
	rm -rf doc/html
	mkdir -p doc
	mv sphinx-doc/root/_build/html doc/html
	mkdir -p doc/html/$(VERSION)
	mv sphinx-doc/en/_build/html doc/html/$(VERSION)/en
	mv doc/html/index.html doc/html/all.html
	#mv sphinx-doc/nl/_build/html doc/html/$(VERSION)/nl
	make doc_clean

man: rm_pyc
	cd sphinx-doc/man-en/; make clean
	cd sphinx-doc/man-en/; make man
	mv sphinx-doc/man-en/_build/man/dispass.1 .
	cd sphinx-doc/man-en/; make clean

dist: rm_pyc
	$(PYTHON_EXEC) setup.py sdist

install: dist
	$(PIP_EXEC) install --upgrade dist/DisPass-$(VERSION).tar.gz
	gzip -c dispass.1 > dispass.1.gz
	mv dispass.1.gz $(MAN_PATH)/
	make clean

uninstall: clean
	$(PIP_EXEC) uninstall dispass

clean: doc_clean
	rm -f MANIFEST dispass.1.gz
	rm -rf dist doc

# vim: set noet ts=8 sw=8 sts=8:
