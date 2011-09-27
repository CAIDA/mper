#!/bin/sh

mkdir -p m4;
autoreconf --install --force --verbose;
touch mper_keywords.c;