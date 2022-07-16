# analyzer-d4-passivedns

analyzer-d4-passivedns is an analyzer for a D4 network sensor including a complete Passive DNS server. The analyser can process data produced by D4 sensors (in [passivedns](https://github.com/gamelinux/passivedns) CSV format (more to come)) or independently from D4 using [COF websocket](https://datatracker.ietf.org/doc/html/draft-dulaunoy-dnsop-passive-dns-cof) streams.

The package include a Passive DNS server which can be queried later to search for the Passive DNS records.

# Features

- [Input stream] - A D4 analyzer which can be plugged to one or more [D4 servers](https://github.com/D4-project/d4-core) to get a stream of DNS records
- [Input Stream] - A websocket stream (or a file stream) in NDJSON [COF format](https://datatracker.ietf.org/doc/html/draft-dulaunoy-dnsop-passive-dns-cof) 
- [Output API] A compliant [Passive DNS ReST server compliant to Common Output Format](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof)
- A flexible and simple analyser which can be configured to collect the required records from DNS records

# Overview

## Requirements

- Python 3.8
- Redis >5.0 or [kvrocks](https://github.com/apache/incubator-kvrocks)
- Tornado
- iptools

## Install

### Redis

~~~~
./install_server.sh
~~~~

All the Python 3 code will be installed in a virtualenv (PDNSENV).

### Kvrocks

~~~
./install_server_kvrocks.sh
~~~

All the Python 3 code will be installed in a virtualenv (PDNSENV).

## Running

### Start the redis server or kvrocks server

Don't forget to set the DB directory in the redis.conf configuration. By default, the redis for Passive DNS is running on TCP port 6400

~~~~
./redis/src/redis-server ./etc/redis.conf
~~~~

or

~~~~
./kvrocks/src/kvrocks -c ./etc/kvrocks.conf
~~~~

### Start the Passive DNS COF server

~~~~
. ./PDNSENV/bin/activate
cd ./bin/
python3 ./pdns-cof-server.py
~~~~

## Feeding the Passive DNS server

You have two ways to feed the Passive DNS server. You can combine multiple streams. A sample public COF stream is available from CIRCL with the newly seen IPv6 addresses and DNS records.

### (via COF websocket stream) start the importer

~~~~
python3 pdns-import-cof.py --websocket ws://crh.circl.lu:8888
~~~~

### (via D4) Configure and start the D4 analyzer

~~~~
cd ./etc
cp analyzer.conf.sample analyzer.conf
~~~~

Edit the analyzer.conf to match the UUID of the analyzer queue from your D4 server.

~~~~
[global]
my-uuid = 6072e072-bfaa-4395-9bb1-cdb3b470d715
d4-server = 127.0.0.1:6380
# INFO|DEBUG
logging-level = INFO
~~~~

then you can start the analyzer which will fetch the data from the analyzer, parse it and
populate the Passive DNS database.

~~~~
. ./PDNSENV/bin/activate/
cd ./bin/
python3 pdns-ingestion.py
~~~~

## Usage

### Querying the server

~~~~shell
adulau@kolmogorov ~/git/analyzer-d4-passivedns (master)$ curl -s http://127.0.0.1:8400/query/xn--ihuvudetpevap-xfb.se | jq .
{
  "time_first": 1657878272,
  "time_last": 1657878272,
  "count": 1,
  "rrtype": "AAAA",
  "rrname": "xn--ihuvudetpevap-xfb.se",
  "rdata": "2a02:250:0:8::53",
  "origin": "origin not configured"
}
~~~~

~~~~shell
curl -s http://127.0.0.1:8400/query/2a02:250:0:8::53 
{"time_first": 1657878141, "time_last": 1657878141, "count": 1, "rrtype": "AAAA", "rrname": "media.vastporten.se", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657878929, "time_last": 1657878929, "count": 1, "rrtype": "AAAA", "rrname": "www.folkinitiativetarjeplog.se", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657878272, "time_last": 1657878272, "count": 1, "rrtype": "AAAA", "rrname": "xn--ihuvudetpevap-xfb.se", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657878189, "time_last": 1657878189, "count": 1, "rrtype": "AAAA", "rrname": "media.primesteps.se", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657878986, "time_last": 1657878986, "count": 1, "rrtype": "AAAA", "rrname": "media.skellefteaadventurepark.se", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657874940, "time_last": 1657874940, "count": 1, "rrtype": "AAAA", "rrname": "galleri.torsaspaintball.se", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657874205, "time_last": 1657874205, "count": 1, "rrtype": "AAAA", "rrname": "www.media1.harlaut.se", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657878165, "time_last": 1657878165, "count": 1, "rrtype": "AAAA", "rrname": "www.sd-nekretnine.rs", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657878678, "time_last": 1657878678, "count": 1, "rrtype": "AAAA", "rrname": "www.www2.resultat-balans.se", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657874288, "time_last": 1657874288, "count": 1, "rrtype": "AAAA", "rrname": "www.assistanshemtjanst.se", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657878943, "time_last": 1657878943, "count": 1, "rrtype": "AAAA", "rrname": "kafekultur.se", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657878141, "time_last": 1657878141, "count": 1, "rrtype": "AAAA", "rrname": "media1.rlab.se", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657878997, "time_last": 1657878997, "count": 1, "rrtype": "AAAA", "rrname": "serbiagreenbuildingexpo.com", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657879064, "time_last": 1657879064, "count": 1, "rrtype": "AAAA", "rrname": "www.framtro.nu", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657874285, "time_last": 1657874285, "count": 1, "rrtype": "AAAA", "rrname": "www.twotheartist.com", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
{"time_first": 1657878774, "time_last": 1657878774, "count": 1, "rrtype": "AAAA", "rrname": "media.narkesten.se", "rdata": "2a02:250:0:8::53", "origin": "origin not configured"}
~~~~

# License

The software is free software/open source released under the GNU Affero General Public License version 3.

