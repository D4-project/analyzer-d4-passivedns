import re
import redis
import fileinput
import json
import configparser
import time

config = configparser.RawConfigParser()
config.read('../etc/analyzer.conf')

myuuid = config.get('global', 'my-uuid')
myqueue = "analyzer:8:{}".format(myuuid)
print (myqueue)
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



#for l in fileinput.input('-'):
while (True):
    d4_record_line =  r_d4.rpop(myqueue)
    if d4_record_line is None:
        time.sleep (1)
        continue
    l = d4_record_line.decode('utf-8')
    rdns = process_format_passivedns(line=l.strip())
    print (rdns)
    if rdns is False:
    # need to add logging when it fails
        continue
    if 'q' not in rdns:
        continue
    if rdns['q'] and rdns['type']:
        query = "r:{}:{}".format(rdns['q'],rdns['type'])
        r.sadd(query, rdns['v'])
        res = "v:{}:{}".format(rdns['v'], rdns['type'])
        r.sadd(res, rdns['q'])
        firstseen = "s:{}:{}:{}".format(rdns['q'], rdns['v'], rdns['type'])
        if not r.exists(firstseen):
            r.set(firstseen, rdns['timestamp'])
        lastseen = "l:{}:{}:{}".format(rdns['q'], rdns['v'], rdns['type'])
        last = r.get(lastseen)
        if last is None or int(last) < int(rdns['timestamp']):
            r.set(lastseen, rdns['timestamp'])
        occ = "o:{}:{}:{}".format(rdns['q'], rdns['v'], rdns['type'])
        r.incr(occ, amount=1)
        # TTL distribution stats
        if 'ttl' in rdns:
            r.hincrby('dist:ttl', rdns['ttl'], amount=1)
        if 'class' in rdns:
            r.hincrby('dist:class', rdns['class'], amount=1)
        if 'type' in rdns:
            r.hincrby('dist:type', rdns['type'], amount=1)
        if stats:
            r.incrby('stats:processed', amount=1)
        print (last)
    print (query)
    if not r:
        continue
