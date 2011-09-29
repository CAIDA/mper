#!/bin/sh

if test -z "$1" ;
then
   echo "usage $0 build_name";
   exit -1;
fi

if [ ! -e mper_keywords.h ];
then
    echo "ERROR: mper sources not found in current directory";
    exit -1;
fi

BUILD_NAME=$1;
REPO_DIR=`pwd`;

if ! git status ;
then
    echo "ERROR: must be in mper git repo";
    exit -1;
fi

echo "extracting sources from git";
git archive --format=tar --prefix=$BUILD_NAME/ HEAD | (cd /tmp/ && tar xvpf -)

echo "updating the changelog";
# full git logs
git --no-pager log --format="%ai %aN %n%n%x09* %s%d%n%n%b%n" > /tmp/$BUILD_NAME/ChangeLog;

# one-line git logs
#git --no-pager log --format="%ai %aN %n%n%x09* %s%d%n" > /tmp/$BUILD_NAME/ChangeLog;

cd /tmp/$BUILD_NAME;

echo "preparing auto tools related files";
./ac_prepare.sh;
cd ..;

echo "packaging release";
tar zcvf $BUILD_NAME.tar.gz $BUILD_NAME;
cd $REPO_DIR;
mv /tmp/$BUILD_NAME.tar.gz .;

echo "removing temporary files";
rm -rfv /tmp/$BUILD_NAME;