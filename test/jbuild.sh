#!/bin/sh

TOP=$PWD

OS=`uname -s`
MACHINE=`uname -m`
if [ ${OS} = "FreeBSD" ] ; then
  OS_ID=`uname -r | sed -e 's/[-_].*//' | sed -e 's/\..*// '`
  OS_DIR=fbsd${OS_ID}
elif [ $OS = "Linux" ]; then
  OS_ID=`cat /etc/os-release | grep VERSION_ID | awk -F \" '{ print $2 }'`
  NUM=`echo $OS_ID | awk -F . '{ print $1 }'`
  OS_DIR=ubuntu${NUM}
  OS_ID="Ubuntu-${OS_ID}"
else
  OS_ID="UNKNOWN"
fi

TOP=$PWD
BUILD=$TOP/build/$OS/$OS_ID/$MACHINE
INSTALL=$TOP/install/$OS/$OS_ID/$MACHINE
export PATH=/volume/hab/$OS/$OS_ID/$MACHINE/autoconf/2.69/bin:/volume/hab/$OS/$OS_ID/$MACHINE/automake/1.15/bin:$PATH
export PATH=/volume/hab/$OS/$OS_ID/$MACHINE/gcc/4.9.4/current/bin:$PATH
mkdir -p $BUILD $INSTALL
cd $BUILD
$TOP/../configure --prefix=$TOP/$INSTALL
make
make install
