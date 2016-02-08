
vmoddir = $(VMOD_DIR)
vmod_LTLIBRARIES = libvmod_crypto.la

libvmod_crypto_la_CFLAGS = $(VMOD_INCLUDES) $(CRYPTO_CFLAGS)
libvmod_crypto_la_LDFLAGS = -module -export-dynamic -avoid-version -shared \
	$(CRYPTO_LIBS)

libvmod_crypto_la_SOURCES = \
	vmod_crypto.c
nodist_libvmod_crypto_la_SOURCES = \
	vcc_if.c \
	vcc_if.h

dist_man_MANS = vmod_crypto.3

VTC_LOG_COMPILER = $(VARNISHTEST) -v \
	-Dvarnishd=$(VARNISHD) -Dvmod_topbuild=$(abs_top_builddir)
TEST_EXTENSIONS = .vtc
TESTS = @VMOD_TESTS@

$(libvmod_crypto_la_OBJECTS): vcc_if.h

vcc_if.c vcc_if.h vmod_crypto.man.rst: $(VMODTOOL) $(top_srcdir)/src/vmod.vcc
	$(PYTHON) $(VMODTOOL) $(top_srcdir)/src/vmod.vcc

vmod_crypto.3: vmod_crypto.man.rst
	$(RST2MAN) $? $@

EXTRA_DIST = vmod.vcc \
	$(TESTS)

CLEANFILES = $(builddir)/vcc_if.c \
	$(builddir)/vcc_if.h \
	$(builddir)/vmod_crypto.man.rst \
	$(builddir)/vmod_crypto.rst \
	$(builddir)/$(dist_man_MANS)

check-local:
if USE_LCOV
	$(LCOV) -c -d .libs -o .libs/$(PACKAGE).info
	$(GENHTML) -o lcov .libs/$(PACKAGE).info
endif

clean-local:
	rm -rf lcov
