AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = README.md

pkglib_LTLIBRARIES = sidh.la

sidh_la_LDFLAGS = -module -avoid-version -shared
sidh_la_SOURCES = engine_sidh.c kex.c ec_isogeny.c validate.c SIDH.c SIDH_setup.c fpx.c amd64/fp_x64.c amd64/fp_x64_asm.S

pkglibdir = /usr/lib/engines-1.1
