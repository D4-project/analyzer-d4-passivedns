#!/usr/bin/env python3
#
# pdns-import is a simple import from Passive DNS cof format (from NDJSON)
# and import these back into a Passive DNS backend
#
# This software is part of the D4 project.
#
# The software is released under the GNU Affero General Public version 3.
#
# Copyright (c) 2019-2022 Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2019 Computer Incident Response Center Luxembourg (CIRCL)


import redis
import json
import logging
import sys
import argparse
import os
import ndjson

# ! websocket-client not websocket
import websocket

parser = argparse.ArgumentParser(
    description='Import array of standard Passive DNS cof format into your Passive DNS server'
)
parser.add_argument('--file', dest='filetoimport', help='JSON file to import')
parser.add_argument(
    '--websocket', dest='websocket', help='Import from a websocket stream'
)
args = parser.parse_args()


logger = logging.getLogger('pdns ingestor')
ch = logging.StreamHandler()
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

logger.info("Starting COF ingestor")

analyzer_redis_host = os.getenv('D4_ANALYZER_REDIS_HOST', '127.0.0.1')
analyzer_redis_port = int(os.getenv('D4_ANALYZER_REDIS_PORT', 6400))

r = redis.Redis(host='127.0.0.1', port=6400)

excludesubstrings = ['spamhaus.org', 'asn.cymru.com']
with open('../etc/records-type.json') as rtypefile:
    rtype = json.load(rtypefile)

dnstype = {}

stats = True

for v in rtype:
    dnstype[(v['type'])] = v['value']

expiration = None
if (not (args.filetoimport)) and (not (args.websocket)):
    parser.print_help()
    sys.exit(0)


def add_record(rdns=None):
    if rdns is None:
        return False
    logger.debug("parsed record: {}".format(rdns))
    if 'rrname' not in rdns:
        logger.debug(
            'Parsing of passive DNS line is incomplete: {}'.format(rdns.strip())
        )
        return False
    if rdns['rrname'] and rdns['rrtype']:
        rdns['type'] = dnstype[rdns['rrtype']]
        rdns['v'] = rdns['rdata']
        excludeflag = False
        for exclude in excludesubstrings:
            if exclude in rdns['rrname']:
                excludeflag = True
        if excludeflag:
            logger.debug('Excluded {}'.format(rdns['rrname']))
            return False
        if rdns['type'] == '16':
            rdns['v'] = rdns['v'].replace("\"", "", 1)
        query = "r:{}:{}".format(rdns['rrname'], rdns['type'])
        logger.debug('redis sadd: {} -> {}'.format(query, rdns['v']))
        r.sadd(query, rdns['v'])
        res = "v:{}:{}".format(rdns['v'], rdns['type'])
        logger.debug('redis sadd: {} -> {}'.format(res, rdns['rrname']))
        r.sadd(res, rdns['rrname'])

        firstseen = "s:{}:{}:{}".format(rdns['rrname'], rdns['v'], rdns['type'])
        if not r.exists(firstseen):
            r.set(firstseen, int(float(rdns['time_first'])))
            logger.debug('redis set: {} -> {}'.format(firstseen, rdns['time_first']))

        lastseen = "l:{}:{}:{}".format(rdns['rrname'], rdns['v'], rdns['type'])
        last = r.get(lastseen)
        if last is None or int(float(last)) < int(float(rdns['time_last'])):
            r.set(lastseen, int(float(rdns['time_last'])))
            logger.debug('redis set: {} -> {}'.format(lastseen, rdns['time_last']))

        occ = "o:{}:{}:{}".format(rdns['rrname'], rdns['v'], rdns['type'])
        if 'count' in rdns:
            r.set(occ, rdns['count'])
        else:
            r.incrby(occ, amount=1)

        if stats:
            r.incrby('stats:processed', amount=1)
            r.sadd('sensors:seen', rdns["sensor_id"])
            r.zincrby('stats:sensors', 1, rdns["sensor_id"])
    if not r:
        logger.info('empty passive dns record')
        return False


def on_open(ws):
    logger.debug('[websocket] connection open')


def on_close(ws):
    logger.debug('[websocket] connection closed')


def on_message(ws, message):
    logger.debug('Message received via websocket')
    add_record(rdns=json.loads(message))


if args.filetoimport:
    with open(args.filetoimport, "r") as dnsimport:
        reader = ndjson.load(dnsimport)
        for rdns in reader:
            add_record(rdns=rdns)
elif args.websocket:
    ws = websocket.WebSocketApp(
        args.websocket, on_open=on_open, on_close=on_close, on_message=on_message
    )
    ws.run_forever()
