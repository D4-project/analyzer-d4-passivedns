#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -e "${DIR}/PDNSENV/bin/python" ]; then
    ENV_PY="${DIR}/PDNSENV/bin/python"
else
    echo "Please make sure you ran install_server.py first."
    exit 1
fi

screen -dmS "pdns"
sleep 0.1

if [ -e "${DIR}/redis" ]; then
    screen -S "pdns" -X screen -t "pdns-lookup-redis" bash -c "(${DIR}/redis/src/redis-server ${DIR}/etc/redis.conf); read x;"
fi

if [ -e "${DIR}/kvrocks" ]; then
    screen -S "pdns" -X screen -t "pdns-lookup-kvrocks" bash -c "(${DIR}/kvrocks/src/kvrocks -c ${DIR}/etc/kvrocks.conf); read x;"
fi

screen -S "pdns" -X screen -t "pdns-cof" bash -c "(cd bin; ${ENV_PY} ./pdns-cof-server.py; read x;)"
screen -S "pdns" -X screen -t "pdns-ingester" bash -c "(cd bin; ${ENV_PY} ./pdns-ingestion.py; read x;)"

exit 0
