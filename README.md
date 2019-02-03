# analyzer-d4-passivedns

analyzer-d4-passivedns is an analyzer for a D4 network sensor. The analyser can process data produced by D4 sensors (in [passivedns](https://github.com/gamelinux/passivedns) CSV format (more to come)) and
ingest them into a Passive DNS server which can be queried later to search for the Passive DNS records.

# Features

- A D4 analyzer which can be plugged to one or more [D4 servers](https://github.com/D4-project/d4-core) to get a stream of DNS records
- A compliant [Passive DNS ReST server compliant to Common Output Format](https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof-04)
- A flexible and simple analyser which can be configured to collect the required records from DNS records

# Requirements

- Python 3
- Redis >5.0
- Tornado
- iptools

# License

The software is free software/open source released under the GNU Affero General Public License version 3.

