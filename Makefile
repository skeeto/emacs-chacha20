.POSIX:
EMACS = emacs

compile: chacha20.elc

check: test
test: chacha20.elc
	$(EMACS) -batch -Q -l chacha20.elc -f ert-run-tests-batch

clean:
	rm -f chacha20.elc

.SUFFIXES: .el .elc
.el.elc:
	$(EMACS) -batch -Q -f batch-byte-compile $<
