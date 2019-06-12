#!/usr/bin/env python3
#
# pdns-import is a simple import from Passive DNS cof format (in an array)
# and import these back into a Passive DNS backend
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
import argparse
import os

parser = argparse.ArgumentParser(description='Import array of standard Passive DNS cof format into your Passive DNS server')
parser.add_argument('--file', dest='filetoimport', help='JSON file to import')
args = parser.parse_args()

config = configparser.RawConfigParser()
config.read('../etc/analyzer.conf')

expirations = config.items('expiration')
excludesubstrings = config.get('exclude', 'substring').split(',')
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

analyzer_redis_host = os.getenv('D4_ANALYZER_REDIS_HOST', '127.0.0.1')
analyzer_redis_port = int(os.getenv('D4_ANALYZER_REDIS_PORT', 6400))

d4_server, d4_port = config.get('global', 'd4-server').split(':')
host_redis_metadata = os.getenv('D4_REDIS_METADATA_HOST', d4_server)
port_redis_metadata = int(os.getenv('D4_REDIS_METADATA_PORT', d4_port))

r = redis.Redis(host=analyzer_redis_host, port=analyzer_redis_port)
r_d4 = redis.Redis(host=host_redis_metadata, port=port_redis_metadata, db=2)

with open('../etc/records-type.json') as rtypefile:
    rtype = json.load(rtypefile)

dnstype = {}

stats = True

for v in rtype:
    dnstype[(v['type'])] = v['value']

expiration = None
if not (args.filetoimport):
    parser.print_help()
    sys.exit(0)
with open(args.filetoimport) as dnsimport:
    records = json.load(dnsimport)

print (records)
for rdns in records:
    logger.debug("parsed record: {}".format(r))
    if 'rrname' not in rdns:
        logger.debug('Parsing of passive DNS line is incomplete: {}'.format(l.strip()))
        continue
    if rdns['rrname'] and rdns['rrtype']:
        rdns['type'] = dnstype[rdns['rrtype']]
        rdns['v'] = rdns['rdata']
        excludeflag = False
        for exclude in excludesubstrings:
            if exclude in rdns['rrname']:
               excludeflag = True
        if excludeflag:
            logger.debug('Excluded {}'.format(rdns['rrname']))
            continue
        if rdns['type'] == '16':
            rdns['v'] = rdns['v'].replace("\"", "", 1)
        query = "r:{}:{}".format(rdns['rrname'],rdns['type'])
        logger.debug('redis sadd: {} -> {}'.format(query,rdns['v']))
        r.sadd(query, rdns['v'])
        res = "v:{}:{}".format(rdns['v'], rdns['type'])
        logger.debug('redis sadd: {} -> {}'.format(res,rdns['rrname']))
        r.sadd(res, rdns['rrname'])

        firstseen = "s:{}:{}:{}".format(rdns['rrname'], rdns['v'], rdns['type'])
        if not r.exists(firstseen):
            r.set(firstseen, rdns['time_first'])
            logger.debug('redis set: {} -> {}'.format(firstseen, rdns['time_first']))


        lastseen = "l:{}:{}:{}".format(rdns['rrname'], rdns['v'], rdns['type'])
        last = r.get(lastseen)
        if last is None or int(last) < int(rdns['time_last']):
            r.set(lastseen, rdns['time_last'])
            logger.debug('redis set: {} -> {}'.format(lastseen, rdns['time_last']))

        occ = "o:{}:{}:{}".format(rdns['rrname'], rdns['v'], rdns['type'])
        r.set(occ, rdns['count'])


        if stats:
            r.incrby('stats:processed', amount=1)
    if not r:
        logger.info('empty passive dns record')
        continue
