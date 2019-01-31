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
test ! -d redis/ && git clone https://github.com/antirez/redis.git
pushd redis/
git checkout 5.0
make
popd
