#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# A Passive DNS COF compliant passive DNS server for the analyzer-d4-passivedns
#
# The output format is compliant with Passive DNS - Common Output Format
#
# https://tools.ietf.org/html/draft-dulaunoy-dnsop-passive-dns-cof
#
# This software is part of the D4 project.
#
# The software is released under the GNU Affero General Public version 3.
#
# Copyright (c) 2013-2022 Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2019-2022 Computer Incident Response Center Luxembourg (CIRCL)


from datetime import date
import tornado.escape
import tornado.ioloop
import tornado.web

import iptools
import redis
import json
import os

rrset = [
    {
        "Reference": "[RFC1035]",
        "Type": "A",
        "Value": "1",
        "Meaning": "a host address",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "NS",
        "Value": "2",
        "Meaning": "an authoritative name server",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MD",
        "Value": "3",
        "Meaning": "a mail destination (OBSOLETE - use MX)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MF",
        "Value": "4",
        "Meaning": "a mail forwarder (OBSOLETE - use MX)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "CNAME",
        "Value": "5",
        "Meaning": "the canonical name for an alias",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "SOA",
        "Value": "6",
        "Meaning": "marks the start of a zone of authority",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MB",
        "Value": "7",
        "Meaning": "a mailbox domain name (EXPERIMENTAL)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MG",
        "Value": "8",
        "Meaning": "a mail group member (EXPERIMENTAL)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MR",
        "Value": "9",
        "Meaning": "a mail rename domain name (EXPERIMENTAL)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "NULL",
        "Value": "10",
        "Meaning": "a null RR (EXPERIMENTAL)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "WKS",
        "Value": "11",
        "Meaning": "a well known service description",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "PTR",
        "Value": "12",
        "Meaning": "a domain name pointer",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "HINFO",
        "Value": "13",
        "Meaning": "host information",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MINFO",
        "Value": "14",
        "Meaning": "mailbox or mail list information",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MX",
        "Value": "15",
        "Meaning": "mail exchange",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "TXT",
        "Value": "16",
        "Meaning": "text strings",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1183]",
        "Type": "RP",
        "Value": "17",
        "Meaning": "for Responsible Person",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1183][RFC5864]",
        "Type": "AFSDB",
        "Value": "18",
        "Meaning": "for AFS Data Base location",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1183]",
        "Type": "X25",
        "Value": "19",
        "Meaning": "for X.25 PSDN address",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1183]",
        "Type": "ISDN",
        "Value": "20",
        "Meaning": "for ISDN address",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1183]",
        "Type": "RT",
        "Value": "21",
        "Meaning": "for Route Through",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1706]",
        "Type": "NSAP",
        "Value": "22",
        "Meaning": "for NSAP address, NSAP style A record",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1348][RFC1637][RFC1706]",
        "Type": "NSAP-PTR",
        "Value": "23",
        "Meaning": "for domain name pointer, NSAP style",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2931][RFC3110][RFC3008]",
        "Type": "SIG",
        "Value": "24",
        "Meaning": "for security signature",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110]",
        "Type": "KEY",
        "Value": "25",
        "Meaning": "for security key",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC2163]",
        "Type": "PX",
        "Value": "26",
        "Meaning": "X.400 mail mapping information",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1712]",
        "Type": "GPOS",
        "Value": "27",
        "Meaning": "Geographical Position",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC3596]",
        "Type": "AAAA",
        "Value": "28",
        "Meaning": "IP6 Address",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1876]",
        "Type": "LOC",
        "Value": "29",
        "Meaning": "Location Information",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC3755][RFC2535]",
        "Type": "NXT",
        "Value": "30",
        "Meaning": "Next Domain (OBSOLETE)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]",
        "Type": "EID",
        "Value": "31",
        "Meaning": "Endpoint Identifier",
        "Template": "",
        "Registration Date": "1995-06",
    },
    {
        "Reference": "[1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]",
        "Type": "NIMLOC",
        "Value": "32",
        "Meaning": "Nimrod Locator",
        "Template": "",
        "Registration Date": "1995-06",
    },
    {
        "Reference": "[1][RFC2782]",
        "Type": "SRV",
        "Value": "33",
        "Meaning": "Server Selection",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[\n        ATM Forum Technical Committee, \"ATM Name System, V2.0\", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]",
        "Type": "ATMA",
        "Value": "34",
        "Meaning": "ATM Address",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC2915][RFC2168][RFC3403]",
        "Type": "NAPTR",
        "Value": "35",
        "Meaning": "Naming Authority Pointer",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC2230]",
        "Type": "KX",
        "Value": "36",
        "Meaning": "Key Exchanger",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4398]",
        "Type": "CERT",
        "Value": "37",
        "Meaning": "CERT",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC3226][RFC2874][RFC6563]",
        "Type": "A6",
        "Value": "38",
        "Meaning": "A6 (OBSOLETE - use AAAA)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC6672]",
        "Type": "DNAME",
        "Value": "39",
        "Meaning": "DNAME",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink]",
        "Type": "SINK",
        "Value": "40",
        "Meaning": "SINK",
        "Template": "",
        "Registration Date": "1997-11",
    },
    {
        "Reference": "[RFC6891][RFC3225]",
        "Type": "OPT",
        "Value": "41",
        "Meaning": "OPT",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC3123]",
        "Type": "APL",
        "Value": "42",
        "Meaning": "APL",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4034][RFC3658]",
        "Type": "DS",
        "Value": "43",
        "Meaning": "Delegation Signer",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4255]",
        "Type": "SSHFP",
        "Value": "44",
        "Meaning": "SSH Key Fingerprint",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4025]",
        "Type": "IPSECKEY",
        "Value": "45",
        "Meaning": "IPSECKEY",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4034][RFC3755]",
        "Type": "RRSIG",
        "Value": "46",
        "Meaning": "RRSIG",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4034][RFC3755]",
        "Type": "NSEC",
        "Value": "47",
        "Meaning": "NSEC",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4034][RFC3755]",
        "Type": "DNSKEY",
        "Value": "48",
        "Meaning": "DNSKEY",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC4701]",
        "Type": "DHCID",
        "Value": "49",
        "Meaning": "DHCID",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC5155]",
        "Type": "NSEC3",
        "Value": "50",
        "Meaning": "NSEC3",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC5155]",
        "Type": "NSEC3PARAM",
        "Value": "51",
        "Meaning": "NSEC3PARAM",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC6698]",
        "Type": "TLSA",
        "Value": "52",
        "Meaning": "TLSA",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC5205]",
        "Type": "HIP",
        "Value": "55",
        "Meaning": "Host Identity Protocol",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[Jim_Reid]",
        "Type": "NINFO",
        "Value": "56",
        "Meaning": "NINFO",
        "Template": "NINFO/ninfo-completed-template",
        "Registration Date": "2008-01-21",
    },
    {
        "Reference": "[Jim_Reid]",
        "Type": "RKEY",
        "Value": "57",
        "Meaning": "RKEY",
        "Template": "RKEY/rkey-completed-template",
        "Registration Date": "2008-01-21",
    },
    {
        "Reference": "[Wouter_Wijngaards]",
        "Type": "TALINK",
        "Value": "58",
        "Meaning": "Trust Anchor LINK",
        "Template": "TALINK/talink-completed-template",
        "Registration Date": "2010-02-17",
    },
    {
        "Reference": "[George_Barwood]",
        "Type": "CDS",
        "Value": "59",
        "Meaning": "Child DS",
        "Template": "CDS/cds-completed-template",
        "Registration Date": "2011-06-06",
    },
    {
        "Reference": "[RFC4408]",
        "Type": "SPF",
        "Value": "99",
        "Meaning": "",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[IANA-Reserved]",
        "Type": "UINFO",
        "Value": "100",
        "Meaning": "",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[IANA-Reserved]",
        "Type": "UID",
        "Value": "101",
        "Meaning": "",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[IANA-Reserved]",
        "Type": "GID",
        "Value": "102",
        "Meaning": "",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[IANA-Reserved]",
        "Type": "UNSPEC",
        "Value": "103",
        "Meaning": "",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC6742]",
        "Type": "NID",
        "Value": "104",
        "Meaning": "",
        "Template": "ILNP/nid-completed-template",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC6742]",
        "Type": "L32",
        "Value": "105",
        "Meaning": "",
        "Template": "ILNP/l32-completed-template",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC6742]",
        "Type": "L64",
        "Value": "106",
        "Meaning": "",
        "Template": "ILNP/l64-completed-template",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC6742]",
        "Type": "LP",
        "Value": "107",
        "Meaning": "",
        "Template": "ILNP/lp-completed-template",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC7043]",
        "Type": "EUI48",
        "Value": "108",
        "Meaning": "an EUI-48 address",
        "Template": "EUI48/eui48-completed-template",
        "Registration Date": "2013-03-27",
    },
    {
        "Reference": "[RFC7043]",
        "Type": "EUI64",
        "Value": "109",
        "Meaning": "an EUI-64 address",
        "Template": "EUI64/eui64-completed-template",
        "Registration Date": "2013-03-27",
    },
    {
        "Reference": "[RFC2930]",
        "Type": "TKEY",
        "Value": "249",
        "Meaning": "Transaction Key",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC2845]",
        "Type": "TSIG",
        "Value": "250",
        "Meaning": "Transaction Signature",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1995]",
        "Type": "IXFR",
        "Value": "251",
        "Meaning": "incremental transfer",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035][RFC5936]",
        "Type": "AXFR",
        "Value": "252",
        "Meaning": "transfer of an entire zone",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MAILB",
        "Value": "253",
        "Meaning": "mailbox-related RRs (MB, MG or MR)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035]",
        "Type": "MAILA",
        "Value": "254",
        "Meaning": "mail agent RRs (OBSOLETE - see MX)",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[RFC1035][RFC6895]",
        "Type": "*",
        "Value": "255",
        "Meaning": "A request for all records the server/cache has available",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "[Patrik_Faltstrom]",
        "Type": "URI",
        "Value": "256",
        "Meaning": "URI",
        "Template": "URI/uri-completed-template",
        "Registration Date": "2011-02-22",
    },
    {
        "Reference": "[RFC6844]",
        "Type": "CAA",
        "Value": "257",
        "Meaning": "Certification Authority Restriction",
        "Template": "CAA/caa-completed-template",
        "Registration Date": "2011-04-07",
    },
    {
        "Reference": "[Sam_Weiler][http://cameo.library.cmu.edu/][\n        Deploying DNSSEC Without a Signed Root.  Technical Report 1999-19,\nInformation Networking Institute, Carnegie Mellon University, April 2004.]",
        "Type": "TA",
        "Value": "32768",
        "Meaning": "DNSSEC Trust Authorities",
        "Template": "",
        "Registration Date": "2005-12-13",
    },
    {
        "Reference": "[RFC4431]",
        "Type": "DLV",
        "Value": "32769",
        "Meaning": "DNSSEC Lookaside Validation",
        "Template": "",
        "Registration Date": "",
    },
    {
        "Reference": "",
        "Type": "Reserved",
        "Value": "65535",
        "Meaning": "",
        "Template": "",
        "Registration Date": "",
    },
]

analyzer_redis_host = os.getenv('D4_ANALYZER_REDIS_HOST', '127.0.0.1')
analyzer_redis_port = int(os.getenv('D4_ANALYZER_REDIS_PORT', 6400))

r = redis.StrictRedis(host=analyzer_redis_host, port=analyzer_redis_port, db=0)

rrset_supported = ['1', '2', '5', '15', '16', '28', '33', '46']
expiring_type = ['16']


origin = "origin not configured"


def getFirstSeen(t1=None, t2=None):
    if t1 is None or t2 is None:
        return False
    rec = f's:{t1.lower()}:{t2.lower()}'
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            qrec = f'{rec}:{rr["Value"]}'
            recget = r.get(qrec)
            if recget is not None:
                return int(recget.decode(encoding='UTF-8'))


def getLastSeen(t1=None, t2=None):
    if t1 is None or t2 is None:
        return False
    rec = f'l:{t1.lower()}:{t2.lower()}'
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            qrec = f'{rec}:{rr["Value"]}'
            recget = r.get(qrec)
            if recget is not None:
                return int(recget.decode(encoding='UTF-8'))


def getCount(t1=None, t2=None):
    if t1 is None or t2 is None:
        return False
    rec = f'o:{t1.lower()}:{t2.lower()}'
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            qrec = f'{rec}:{rr["Value"]}'
            recget = r.get(qrec)
            if recget is not None:
                return int(recget.decode(encoding='UTF-8'))


def getRecord(t=None):
    if t is None:
        return False
    rrfound = []
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            rec = f'r:{t}:{rr["Value"]}'
            setsize = r.scard(rec)
            if setsize < 200:
                rs = r.smembers(rec)
            else:
                # TODO: improve with a new API end-point with SSCAN
                # rs = r.srandmember(rec, number=300)
                rs = False

            if rs:
                for v in rs:
                    rrval = {}
                    rdata = v.decode(encoding='UTF-8').strip()
                    rrval['time_first'] = getFirstSeen(t1=t, t2=rdata)
                    rrval['time_last'] = getLastSeen(t1=t, t2=rdata)
                    if rrval['time_first'] is None:
                        break
                    rrval['count'] = getCount(t1=t, t2=rdata)
                    rrval['rrtype'] = rr['Type']
                    rrval['rrname'] = t
                    rrval['rdata'] = rdata
                    if origin:
                        rrval['origin'] = origin
                    rrfound.append(rrval)
    return rrfound


def getAssociatedRecords(rdata=None):
    if rdata is None:
        return False
    rec = f'v:{rdata.lower()}'
    records = []
    for rr in rrset:
        if (rr['Value']) is not None and rr['Value'] in rrset_supported:
            qrec = f'{rec}:{rr["Value"]}'
            if r.smembers(qrec):
                for v in r.smembers(qrec):
                    records.append(v.decode(encoding='UTF-8'))
    return records


def RemDuplicate(d=None):
    if d is None:
        return False
    outd = [dict(t) for t in set([tuple(o.items()) for o in d])]
    return outd


def JsonQOF(rrfound=None, RemoveDuplicate=True):
    if rrfound is None:
        return False
    rrqof = ""

    if RemoveDuplicate:
        rrfound = RemDuplicate(d=rrfound)

    for rr in rrfound:
        rrqof = rrqof + json.dumps(rr) + "\n"
    return rrqof


class InfoHandler(tornado.web.RequestHandler):
    def get(self):
        stats = int(r.get("stats:processed"))
        response = {'version': 'git', 'software': 'analyzer-d4-passivedns'}
        response['stats'] = stats
        sensors = r.zrevrange('stats:sensors', 0, -1, withscores=True)
        rsensors = []
        for x in sensors:
            d = dict()
            d['sensor_id'] = x[0].decode()
            d['count'] = int(float(x[1]))
            rsensors.append(d)
        response['sensors'] = rsensors
        self.write(response)


class QueryHandler(tornado.web.RequestHandler):
    def get(self, q):
        print(f'query: {q}')
        if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
            for x in getAssociatedRecords(q):
                self.write(JsonQOF(getRecord(x)))
        else:
            self.write(JsonQOF(getRecord(t=q.strip())))


class FullQueryHandler(tornado.web.RequestHandler):
    def get(self, q):
        print(f'fquery: {q}')
        if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
            for x in getAssociatedRecords(q):
                self.write(JsonQOF(getRecord(x)))
        else:
            for x in getAssociatedRecords(q):
                self.write(JsonQOF(getRecord(t=x.strip())))


application = tornado.web.Application(
    [
        (r"/query/(.*)", QueryHandler),
        (r"/fquery/(.*)", FullQueryHandler),
        (r"/info", InfoHandler),
    ]
)

if __name__ == "test":

    qq = ["foo.be", "8.8.8.8"]

    for q in qq:
        if iptools.ipv4.validate_ip(q) or iptools.ipv6.validate_ip(q):
            for x in getAssociatedRecords(q):
                print(JsonQOF(getRecord(x)))
        else:
            print(JsonQOF(getRecord(t=q)))
else:
    application.listen(8400)
    tornado.ioloop.IOLoop.instance().start()
