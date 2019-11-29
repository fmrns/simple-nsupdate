#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
#
# depends: dnspython http://www.dnspython.org/
#
# Copyright (c) 2019 Abacus Technologies, Inc.
# Copyright (c) 2019 Fumiyuki Shimizu
# MIT License: https://opensource.org/licenses/MIT

import os
import configparser
import logging
import logging.handlers
from datetime import datetime
from urllib import parse as urlparse
 
import socket
import ipaddress
import sqlite3

import dns.tsigkeyring
import dns.resolver
import dns.query
import dns.update

from mod_python import apache

config = configparser.ConfigParser()
config.read(os.path.dirname(__file__) + '/snsup.ini')

log_level  = logging.INFO
#log_level  = logging.DEBUG
log_format = '%(asctime)s [%(name)s]:%(levelname)s:%(message)s'
if 'syslog' in config and 'server' in config['syslog']:
    handler = logging.handlers.SysLogHandler(
        address=(config['syslog'].get('server'), config['syslog'].getint('port', 514)),
        socktype=socket.SOCK_DGRAM)
    logging.basicConfig(level=log_level, format=log_format, handlers=( handler, ))
else:
    logging.basicConfig(level=log_level, format=log_format)
log = logging.getLogger(os.path.basename(__file__[:-3] if __file__.endswith('.py') else __file__))

class dbms:
    def __enter__(self):
        dbfile = config['db'].get('file')
        self.conn = sqlite3.connect(f'file:{dbfile}', uri=True)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self.conn.close()
        except Exception as e:
            log.debug(f'{e}')
        
    def create_table(self):
        self.conn.cursor().executescript('''\
DROP TABLE IF EXISTS updated_time;
CREATE TABLE updated_time(
  host    TEXT    NOT NULL,
  origin  TEXT    NOT NULL,
  ip      TEXT    NOT NULL,
  ipver   INTEGER NOT NULL,
  updated DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(host, origin, ip)
);
CREATE INDEX tm_idx ON updated_time(updated); 
''')
        self.conn.commit()

    def getCursor(self):
        cur = self.conn.cursor()
        #cur.execute(sql_init_tz, ( elconst.SMAME_TZ_IN_NORMAL, ))
        return cur

    def execute(self, cur, sql, *, arglist=None, commit=True):
        try:
            log.debug('{} {}'.format(sql, arglist))
            cur.execute(sql, arglist)
            if commit:
                self.conn.commit()
        except sqlite3.Error as e:
            if commit:
                self.conn.rollback()
            log.error(f'{e}')
            raise e

    def commit(self):
        try:
            self.conn.commit()
        except sqlite3.Error as e:
            log.error(f'{e}')
            raise e

class nsupdate:
    def __init__(self):
        self.keyname = config['tsig'].get('name')
        self.keyalgorithm = config['tsig'].get('algorithm')
        self.keyring = dns.tsigkeyring.from_text({
                self.keyname: config['tsig'].get('key')
        })

        self.origin = config['nsupdate'].get('origin')
        self.ttl = config['nsupdate'].getint('ttl', 300)
        self.nsupdate_server = config['nsupdate'].get('server')
        self.nsupdate_port = config['nsupdate'].getint('port', 53)

    @staticmethod
    def rr_type(ipver):
        if 4 == ipver:
            return dns.rdatatype.A
        elif 6 == ipver:
            return dns.rdatatype.AAAA
        raise ValueError(f"unknown ipversion: {ipver}")
    
    @staticmethod
    def ipv_prefix(ipver):
        if 4 == ipver:
            return "v4"
        elif 6 == ipver:
            return "v6"
        raise ValueError(f"unknown ipversion: {ipver}")

    def getUpdater(self):
        return dns.update.Update(
                self.origin,
                keyring=self.keyring,
                keyname=self.keyname,
                keyalgorithm=self.keyalgorithm)

    def getResolver(self):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.timeout = 20.0
        resolver.nameservers      = [ self.nsupdate_server ]
        resolver.nameserver_ports = { self.nsupdate_server: self.nsupdate_port }
        return resolver

    def _resolve(self, host, ipver):
        resolver = self.getResolver()
        rrtype = self.rr_type(ipver)
        try:
            ans = resolver.query(dns.name.from_text(host, origin=dns.name.from_text(self.origin)), rrtype)
            rc = set()
            if ans is not None:
                for rr in ans:
                    if rr.rdtype == rrtype:
                        rc.add(ipaddress.ip_address(rr.address))
            if 1 > len(rc):
                return None
            return rc
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except Exception as e:
            log.error(f'{host}: {e}')
        return None            

    def resolve(self, host, ipver=0):
        rc = set()
        if ipver in (0, 4):
            ans = self._resolve(host, 4)
            if not ans is None:
                rc.update(ans)
        if ipver in (0, 6):
            ans = self._resolve(host, 6)
            if not ans is None:
                rc.update(ans)
        if 1 > len(rc):
            return None
        return rc

    def setips(self, db, host, ipset):
        h1 = f'{host}'
        oldipset = set()
        cur = db.getCursor()
        db.execute(cur, "SELECT ip FROM updated_time WHERE host=? AND updated>=datetime('now','-1 hour') AND origin=?",
                        arglist=[ h1, self.origin ])
        while True:
            row = cur.fetchone()
            if row is None:
                break
            oldipset.add(ipaddress.ip_address(row[0]))
        if ipset == oldipset:
            log.debug(f'no change: {host}')
            return

        update = self.getUpdater()
        sqls = []
        ipvers = set()
        for ip in ipset:
            ipaddr = ip.compressed
            ipver = ip.version
            rrtype = nsupdate.rr_type(ipver)
            h2 = f'{nsupdate.ipv_prefix(ipver)}.{h1}'
            if ipver in ipvers:
                update.add(h1, self.ttl, rrtype, ipaddr)
                update.add(h2, self.ttl, rrtype, ipaddr)
            else:
                ipvers.add(ipver)
                update.replace(h1, self.ttl, rrtype, ipaddr)
                update.replace(h2, self.ttl, rrtype, ipaddr)
                sqls.append(('DELETE FROM updated_time WHERE(host=? OR(host=? AND ipver=?))AND origin=?',
                             h2, h1, ipver, self.origin ))
            sqls.append(('INSERT INTO updated_time(host,origin,ip,ipver)VALUES(?,?,?,?),(?,?,?,?)',
                         h1, self.origin, ipaddr, ipver,
                         h2, self.origin, ipaddr, 0 ))
        dns.query.tcp(update, self.nsupdate_server, port=self.nsupdate_port)

        for sql in sqls:
            db.execute(cur, sql[0], arglist=sql[1:], commit=False)
        db.commit()

    def sweep(self, db):
        cur = db.getCursor()
        db.execute(cur, "SELECT host,ip FROM updated_time WHERE updated<datetime('now','-7 days')AND origin=?",
                   arglist=[ self.origin ])
        update = None
        pairs = {}
        while True:
            row = cur.fetchone()
            if row is None:
                break
            if update is None:
                update = self.getUpdater()
            host = row[0]
            ip = ipaddress.ip_address(row[1])
            if host not in pairs:
                pairs[host] = { ip }
            else:
                pairs[host].add(ip)
            update.delete(host, dns.rdata.from_text(
                    dns.rdataclass.IN, nsupdate.rr_type(ip.version), ip.compressed))
        if update is None:
            return
        dns.query.tcp(update, self.nsupdate_server, port=self.nsupdate_port)

        sqls = []
        for host in pairs.keys():
            ans = self.resolve(host)
            for ip in pairs[host]:
                if ans is not None and ip in ans:
                    continue
                sqls.append(("DELETE FROM updated_time WHERE host=? AND ip=? AND origin=?",
                             host, ip.compressed, self.origin ))
                log.info(f'deleting unseen {host}: {ip}')

        for sql in sqls:
            db.execute(cur, sql[0], arglist=sql[1:], commit=False)
        db.commit()

    def obsolete(self, db, host, ipset=None):
        cur = db.getCursor()
        sqls = []
        if ipset is None or 1 > len(ipset):
            sqls.append(("UPDATE updated_time SET updated=datetime('now','-1 year')WHERE host=? AND origin=?",
                         host, self.origin))
        else:
            for ip in ipset:
                sqls.append(("UPDATE updated_time SET updated=datetime('now','-1 year')WHERE host=? AND ip=? AND origin=?",
                             host, ip.compressed, self.origin))
        for sql in sqls:
            db.execute(cur, sql[0], arglist=sql[1:], commit=False)
        db.commit()
        self.sweep(db)

def dispatch(qs, host, remote_ip):
    snsup = nsupdate()
    is_delete = False
    ipset = set()
    if qs is not None and 0 < len(qs):
        try:
            for nv in urlparse.parse_qsl(qs):
                if 'resolve4' == nv[0]:
                    if 2 == len(nv):
                        ipset.add(snsup.resolve(nv[1], 4))
                elif 'resolve6' == nv[0]:
                    if 2 == len(nv):
                        ipset.add(snsup.resolve(nv[1], 6))
                elif 'resolve' == nv[0]:
                    if 2 == len(nv):
                        ipset.add(snsup.resolve(nv[1]))
                elif 'ip' == nv[0]:
                    if 2 == len(nv):
                        ipset.add(ipaddress.ip_address(nv[1]))
                elif 'del' == nv[0]:
                    is_delete = True
                else:
                    log.error(f'unknown option: {nv[0]}: {host}: {qs}')
        except Exception as e:
            log.error(f'{host}: {qs}: {e}')
            return False

    if 1 > len(ipset):
        ipset.add(ipaddress.ip_address(remote_ip))

    if is_delete:
        snsup.obsolete(db, host, ipset)
    else:
        snsup.setips(db, host, ipset)

def handler(req):
#    AddHandler mod_python .py
#    PythonHandler snsup
    req.content_type = "text/plain"
    req.server.server_hostname
    try:
        dispatch(req.args, req.user, req.get_remote_host(apache.REMOTE_NOLOOKUP))
        req.write("OK")
        return apache.OK
    except Exception as e:
        log.error(f'{e}')
     #   raise apache.SERVER_RETURN, apache.HTTP_INTERNAL_SERVER_ERROR

def test():
    ip4 = ipaddress.ip_address('127.0.0.1')
    ip6 = ipaddress.ip_address('2001:DB2::0')
    print(f"ipv{ip4.version}: {ip4}")
    print(f"ipv{ip6.version}: {ip6}")
    
    try:
        ip4 = ipaddress.ip_address('127.1')
    except ValueError as e:
        print (e)

if __name__=='__main__':
    test()

    dispatch(None, 'test', '10.1.2.3')
    dispatch('resolve4=homepac.f&resolve6=metal.f', 'test', '10.1.2.3')

    with dbms() as db:
        db.create_table()
        snsup = nsupdate()
        snsup.setips(db, 'test', {
                ipaddress.ip_address('192.168.33.33'),
                ipaddress.ip_address('2002:123::'),
                ipaddress.ip_address('192.168.12.34') })
        snsup.obsolete(db, 'test', {ipaddress.ip_address('192.168.12.34')})
        snsup.obsolete(db, 'test')


    print('done.')

# end of file
