#!/usr/bin/env python3
#
# pdns-ingestion is the D4 analyzer for the Passive DNS backend.
#
# This software parses input (via a Redis list) from a D4 server and
# ingest it into a redis compliant server to server the records for
# the passive DNS at later stage.
#
# This software is part of the D4 project.
#
# The software is released under the GNU Affero General Public version 3.
#
# Copyright (c) 2019 Alexandre Dulaunoy - a@foo.be
# Copyright (c) Computer Incident Response Center Luxembourg (CIRCL)


import re
import redis
import fileinput
import json
import configparser
import time
import logging
import sys

config = configparser.RawConfigParser()
config.read('../etc/analyzer.conf')

myuuid = config.get('global', 'my-uuid')
myqueue = "analyzer:8:{}".format(myuuid)
mylogginglevel = config.get('global', 'logging-level')
logger = logging.getLogger('pdns ingestor')
ch = logging.StreamHandler()
if mylogginglevel == 'DEBUG':
    logger.setLevel(logging.DEBUG)
    ch.setLevel(logging.DEBUG)
elif mylogginglevel == 'INFO':
    logger.setLevel(logging.INFO)
    ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

logger.info("Starting and using FIFO {} from D4 server".format(myqueue))

d4_server = config.get('global', 'd4-server')
r = redis.Redis(host="127.0.0.1",port=6400)
r_d4 = redis.Redis(host=d4_server.split(':')[0], port=d4_server.split(':')[1], db=2)


with open('../etc/records-type.json') as rtypefile:
    rtype = json.load(rtypefile)

dnstype = {}

stats = True

for v in rtype:
    dnstype[(v['type'])] = v['value']


def process_format_passivedns(line=None):
    # log line example
    # timestamp||ip-src||ip-dst||class||q||type||v||ttl||count
    # 1548624738.280922||192.168.1.12||8.8.8.8||IN||www-google-analytics.l.google.com.||AAAA||2a00:1450:400e:801::200e||299||12
    vkey = ['timestamp','ip-src','ip-dst','class','q','type','v','ttl','count']
    record = {}
    if line is None or line == '':
        return False
    v = line.split("||")
    i = 0
    for r in v:
        # trailing dot is removed and avoid case sensitivity
        if i == 4 or i == 6:
            r = r[:-1]
            r = r.lower()
        # timestamp is just epoch - second precision is only required
        if i == 0:
            r = r.split('.')[0]
        record[vkey[i]] = r
        # replace DNS type with the known DNS record type value
        if i == 5:
            record[vkey[i]] = dnstype[r]
        i = i + 1
    return record


while (True):
    d4_record_line =  r_d4.rpop(myqueue)
    if d4_record_line is None:
        time.sleep (1)
        continue
    l = d4_record_line.decode('utf-8')
    rdns = process_format_passivedns(line=l.strip())
    logger.debug("parsed record: {}".format(rdns))
    if rdns is False:
    # need to add logging when it fails
        continue
    if 'q' not in rdns:
        continue
    if rdns['q'] and rdns['type']:
        query = "r:{}:{}".format(rdns['q'],rdns['type'])
        logger.debug('redis sadd: {} -> {}'.format(query,rdns['v']))
        r.sadd(query, rdns['v'])

        res = "v:{}:{}".format(rdns['v'], rdns['type'])
        logger.debug('redis sadd: {} -> {}'.format(res,rdns['q']))
        r.sadd(res, rdns['q'])

        firstseen = "s:{}:{}:{}".format(rdns['q'], rdns['v'], rdns['type'])
        if not r.exists(firstseen):
            r.set(firstseen, rdns['timestamp'])
            logger.debug('redis set: {} -> {}'.format(firstseen, rdns['timestamp']))
        lastseen = "l:{}:{}:{}".format(rdns['q'], rdns['v'], rdns['type'])
        last = r.get(lastseen)
        if last is None or int(last) < int(rdns['timestamp']):
            r.set(lastseen, rdns['timestamp'])
            logger.debug('redis set: {} -> {}'.format(lastseen, rdns['timestamp']))
        occ = "o:{}:{}:{}".format(rdns['q'], rdns['v'], rdns['type'])
        r.incr(occ, amount=1)


        # TTL, Class, DNS Type distribution stats
        if 'ttl' in rdns:
            r.hincrby('dist:ttl', rdns['ttl'], amount=1)
        if 'class' in rdns:
            r.hincrby('dist:class', rdns['class'], amount=1)
        if 'type' in rdns:
            r.hincrby('dist:type', rdns['type'], amount=1)
        if stats:
            r.incrby('stats:processed', amount=1)
    if not r:
        logger.info('empty passive dns record')
        continue
