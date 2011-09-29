#!/bin/sh

if [ $1 -eq "" ] ;
then
   echo "usage $0 build_name";
   exit -1;
fi

BUILD_NAME=$1;
REPO_DIR=`pwd`;

echo "extracting sources from git";
git archive --format=tar --prefix=$BUILD_NAME/ HEAD | (cd /tmp/ && tar xvpf -)

echo "updating the changelog";
git --no-pager log --format="%ai %aN %n%n%x09* %s%d%n" > /tmp/$BUILD_NAME/ChangeLog;
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