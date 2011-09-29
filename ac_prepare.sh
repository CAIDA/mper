#!/bin/sh

echo "creating m4 directory";
mkdir -p m4;
autoreconf --install --force --verbose;
echo "sleeping 2 secs to ensure mper_keywords.c is newer than mper_keywords.gperf";
sleep 2;
echo "touching mper_keywords.c"; 
touch -c mper_keywords.c;
