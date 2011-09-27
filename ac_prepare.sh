#!/bin/sh

mkdir -p m4;
autoreconf --install --force --verbose;
echo "sleeping 2 secs to ensure mper_keywords.c is newer than mper_keywords.gperf";
sleep 2;
touch mper_keywords.c;