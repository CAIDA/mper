#!/bin/sh

FILES="Makefile.in aclocal.m4 config.guess config.guess config.h.in \
config.sub configure depcomp install-sh ltmain.sh missing";

DIRS="m4/ autom4te.cache/";

echo "attempting to distclean using make";
make distclean;

echo "removing files created by ac_prepare.sh";
rm -rfv $FILES $DIRS;
