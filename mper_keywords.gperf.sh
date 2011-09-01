#!/bin/sh

if $1 $2 mper_keywords.gperf >$3~; then
    mv $3~ $3;
elif $1 --version >/dev/null 2>&1; then
    printf "\n\nERROR: gperf failed. $3 may not be up to date.\n";
    printf "  This likely means you have a problem with mper_keywords.gperf,\n";
    printf "  but it can mean that you are using an old version of gperf.\n";
    printf "  If you have not modified mper_keywords.gperf, then it is probably\n";
    printf "  safe to touch mper_keywords.c and re-run make, otherwise,\n";
    printf "  you should ensure you have gperf 3.x or higher and that there are\n";
    printf "  no problems in mper_keywords.gperf\n";
    rm $3~;
    exit 1;
else
    printf "\n\nERROR: gperf not installed. $3 may not be up to date.\n";
    printf "  If you have not modified mper_keywords.gperf, then it is probably\n";
    printf "  safe to touch mper_keywords.c and re-run make\n";
    rm $3~;
    exit 1;
fi
