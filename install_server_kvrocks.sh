#!/bin/bash

set -e
set -x

sudo apt-get install python3-pip virtualenv screen -y

if [ -z "$VIRTUAL_ENV" ]; then
    virtualenv -p python3 PDNSENV
    echo export PDNS_HOME=$(pwd) >> ./PDNSENV/bin/activate
    . ./PDNSENV/bin/activate
fi

python3 -m pip install -r requirements

# REDIS #
mkdir -p db
test ! -d kvrocks/ && git clone https://github.com/apache/incubator-kvrocks.git kvrocks 
pushd kvrocks/
git checkout 2.0 
make -j4
popd
