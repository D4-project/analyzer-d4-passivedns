# analyzer-d4-passivedns

analyzer-d4-passivedns is an analyzer for a D4 network sensor. The analyser can process data produced by D4 sensors (in [passivedns](https://github.com/gamelinux/passivedns) CSV format (more to come)) and
ingest these into a Passive DNS server which can be queried later to search for the Passive DNS records.

# Features

- A D4 analyzer which can be plugged to one or more [D4 servers](https://github.com/D4-project/d4-core) to get a stream of DNS records
- A compliant [Passive DNS ReST server compliant to Common Output Format](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof-04)
- A flexible and simple analyser which can be configured to collect the required records from DNS records

# Overview

## Requirements

- Python 3
- Redis >5.0
- Tornado
- iptools

## Install

~~~~
./install_server.sh
~~~~

All the Python 3 code will be installed in a virtualenv (PDNSENV).

## Running

### Start the redis server

Don't forget to set the DB directory in the redis.conf configuration. By default, the redis for Passive DNS is running on TCP port 6400

~~~~
./redis/src/redis-server ./etc/redis.conf
~~~~

### Start the Passive DNS COF server

~~~~
. ./PDNSENV/bin/activate
cd ./bin/
python3 ./pdns-cof-server.py
~~~~

### Configure and start the D4 analyzer

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

# License

The software is free software/open source released under the GNU Affero General Public License version 3.

