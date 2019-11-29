#!/usr/local/bin/python3.6
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

config = configparser.ConfigParser()
wd=os.path.dirname(__file__)
if 1 > len(wd):
    wd = '.'
config.read(wd + '/snsup.ini')
if 'reconfig' in config and 'file' in config['reconfig']:
    config.read(wd + '/' + config['reconfig'].get('file'))

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
            log.debug(f'dbms exit: {e}')
        
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

    def get_cursor(self):
        cur = self.conn.cursor()
        #cur.execute(sql_init_tz, ( elconst.SMAME_TZ_IN_NORMAL, ))
        return cur

    def execute(self, cur, sql, *, arglist=None, commit=True):
        try:
            log.debug('{} {}'.format(sql, arglist))
            if arglist is None:
                cur.execute(sql)
            else:
                cur.execute(sql, arglist)
            if commit:
                self.conn.commit()
        except sqlite3.Error as e:
            if commit:
                self.conn.rollback()
            log.error(f'dbms execute: {e}')
            raise e

    def commit(self):
        try:
            self.conn.commit()
        except sqlite3.Error as e:
            log.error(f'dbms commit: {e}')
            raise e

    def vacuum(self):
        try:
            self.conn.commit()
            cur = self.get_cursor()
            self.execute(cur, 'VACUUM')
        except sqlite3.Error as e:
            log.error(f'dbms vacuum: {e}')
            raise e

class nsupdate:
    def __init__(self):
        self.keyname = config['tsig'].get('name')
        self.keyalgorithm = config['tsig'].get('algorithm')
        self.keyring = dns.tsigkeyring.from_text({
                self.keyname: config['tsig'].get('key')
        })

        self.origin_text = config['nsupdate'].get('origin')
        self.origin = dns.name.from_text(self.origin_text)
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
    def add_prefix(ipver, name):
        if 4 == ipver:
            return dns.name.from_text("v4", origin=dns.name.empty).derelativize(name)
        elif 6 == ipver:
            return dns.name.from_text("v6", origin=dns.name.empty).derelativize(name)
        raise ValueError(f"unknown ipversion: {ipver}")

    def is_subdomain(self, host):
        return host != self.origin and host.is_subdomain(self.origin)

    def relativize(self, host):
        return host.relativize(self.origin)

    def get_updater(self):
        return dns.update.Update(
                self.origin,
                keyring=self.keyring,
                keyname=self.keyname,
                keyalgorithm=self.keyalgorithm)

    def get_resolver(self):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.timeout = 20.0
        resolver.nameservers      = [ self.nsupdate_server ]
        resolver.nameserver_ports = { self.nsupdate_server: self.nsupdate_port }
        return resolver

    def _resolve(self, host, ipver):
        resolver = self.get_resolver()
        rrtype = self.rr_type(ipver)
        try:
            ans = resolver.query(dns.name.from_text(host, origin=self.origin), rrtype)
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
            if ans is not None:
                rc.update(ans)
        if ipver in (0, 6):
            ans = self._resolve(host, 6)
            if ans is not None:
                rc.update(ans)
        if 1 > len(rc):
            return None
        return rc

    def setips(self, db, host, ipset, filter_ipver=None):
        host4 = nsupdate.add_prefix(4, host)
        host6 = nsupdate.add_prefix(6, host)
        host_text  = host.to_text()
        host4_text = host4.to_text()
        host6_text = host6.to_text()
        log.debug(f'{host}, {host_text}')
        log.debug(f'{host4}, {host4_text}')
        log.debug(f'{host6}, {host6_text}')
        sqls = []
        if filter_ipver is None:
            sqls.append(("SELECT ip FROM updated_time WHERE host=? AND updated>=datetime('now','-1 hour')AND origin=?",
                         host_text, self.origin_text))
        else:
            sqls.append(("SELECT ip FROM updated_time WHERE host=? AND updated>=datetime('now','-1 hour')AND ipver=? AND origin=?",
                         host_text, filter_ipver, self.origin_text))
            if 4 == filter_ipver:
                hostp_text = host4_text
            else:
                assert 6 == filter_ipver, f'unknown ipver: {filter_ipver}'
                hostp_text = host6_text
            sqls.append(("SELECT ip FROM updated_time WHERE host=? AND updated>=datetime('now','-1 hour')AND origin=?",
                         hostp_text, self.origin_text))

        is_changed = False
        for sql in sqls:
            oldipset = set()
            cur = db.get_cursor()
            db.execute(cur, sql[0], arglist=sql[1:], commit=False)
            while True:
                row = cur.fetchone()
                if row is None:
                    break
                oldipset.add(ipaddress.ip_address(row[0]))
            if ipset != oldipset:
                log.info(f'{host_text}: {oldipset - ipset} -> {ipset - oldipset}')
                is_changed = True
                break
        if not is_changed:
            log.debug(f'no change: {host}')
            return

        update = self.get_updater()
        sqls = []
        ipvers = set()
        if filter_ipver is None:
            sqls.append(('DELETE FROM updated_time WHERE(host=? OR host=? OR host=?)AND origin=?',
                         host_text, host4_text, host6_text, ipver, self.origin_text ))
        for ip in ipset:
            ipaddr = ip.compressed
            ipver = ip.version
            rrtype = nsupdate.rr_type(ipver)
            if 4 == ipver:
                hostp = host4
                hostp_text = host4_text
            else:
                assert 6 == ipver, f'unknown ipver: {ipver}'
                hostp = host6
                hostp_text = host6_text
            if ipver in ipvers:
                update.add(host,  self.ttl, rrtype, ipaddr)
                update.add(hostp, self.ttl, rrtype, ipaddr)
            else:
                ipvers.add(ipver)
                update.replace(host,  self.ttl, rrtype, ipaddr)
                update.replace(hostp, self.ttl, rrtype, ipaddr)
                if filter_ipver is not None:
                    assert ipver == filter_ipver, f'invalid ipver({ip.compressed}) while ipver is restricted to {filter_ipver}'
                    sqls.append(('DELETE FROM updated_time WHERE(host=? OR host=? OR host=?)AND ipver=? AND origin=?',
                                 host_text, host4_text, host6_text, ipver, self.origin_text ))
            sqls.append(('INSERT INTO updated_time(host,origin,ip,ipver)VALUES(?,?,?,?),(?,?,?,?)',
                         host_text,  self.origin_text, ipaddr, ipver,
                         hostp_text, self.origin_text, ipaddr, ipver ))
        dns.query.tcp(update, self.nsupdate_server, port=self.nsupdate_port)

        for sql in sqls:
            db.execute(cur, sql[0], arglist=sql[1:], commit=False)
        db.commit()

    def sweep(self, db):
        cur = db.get_cursor()
        db.execute(cur, "SELECT host,ip FROM updated_time WHERE updated<datetime('now','-7 days')AND origin=?",
                   arglist=[ self.origin_text ])
        update = None
        pairs = {}
        while True:
            row = cur.fetchone()
            if row is None:
                break
            if update is None:
                update = self.get_updater()
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
                    log.warn(f'removed host is still resolvable: {host}: {ip}')
                    continue
                sqls.append(("DELETE FROM updated_time WHERE host=? AND ip=? AND origin=?",
                             host, ip.compressed, self.origin_text ))
                log.warn(f'deleting unseen {host}: {ip}')

        for sql in sqls:
            db.execute(cur, sql[0], arglist=sql[1:], commit=False)
        db.commit()
        db.vacuum()

    def obsolete(self, db, host, ipset=None, filter_ipver=None):
        cur = db.get_cursor()
        sqls = []
        host_text = host.to_text()
        host4_text = nsupdate.add_prefix(4, host).to_text()
        host6_text = nsupdate.add_prefix(6, host).to_text()
        if ipset is None or 1 > len(ipset):
            if filter_ipver is None:
                sqls.append(("UPDATE updated_time SET updated=datetime('now','-1 year')WHERE(host=? OR host=? OR host=?)AND origin=?",
                             host_text, host4_text, host6_text, self.origin_text))
            else:
                sqls.append(("UPDATE updated_time SET updated=datetime('now','-1 year')WHERE(host=? OR host=? OR host=?)AND ipver=? AND origin=?",
                             host_text, host4_text, host6_text, filter_ipver, self.origin_text))
        else:
            for ip in ipset:
                sqls.append(("UPDATE updated_time SET updated=datetime('now','-1 year')WHERE(host=? OR host=? OR host=?)AND ip=? AND origin=?",
                             host_text, host4_text, host6_text, ip.compressed, self.origin_text))
        for sql in sqls:
            log.debug(sql[0])
            db.execute(cur, sql[0], arglist=sql[1:], commit=False)
        db.commit()
        self.sweep(db)

def dispatch(db, qs, remote_user, remote_addr, http_host):
    snsup = nsupdate()
    is_delete = False
    filter_ipver = None
    is_sweep = False
    ipset = set()
    suffix = None
    if qs is not None and 0 < len(qs):
        for nv in urlparse.parse_qsl(qs):
            try:
                assert 2 == len(nv), f'arg error: {nv[0]}'
                log.debug(f'{nv[0]}: {nv[1]}')
                if 'resolve4' == nv[0]:
                    ans = snsup.resolve(nv[1], 4)
                    if ans is not None:
                        ipset.update(ans)
                elif 'resolve6' == nv[0]:
                    ans = snsup.resolve(nv[1], 6)
                    if ans is not None:
                        ipset.update(ans)
                elif 'resolve' == nv[0]:
                    ans = snsup.resolve(nv[1])
                    if ans is not None:
                        ipset.update(ans)
                elif 'ip' == nv[0]:
                    ipset.update(ipaddress.ip_address(nv[1]))
                elif 'suffix' == nv[0]:
                    suffix = dns.name.from_text(nv[1], origin=dns.name.empty)
                elif 'mode' == nv[0]:
                    if 'delete4' == nv[1]:
                        is_delete = True
                        filter_ipver = 4
                    elif 'delete6' == nv[1]:
                        is_delete = True
                        filter_ipver = 6
                    elif 'delete' == nv[1]:
                        is_delete = True
                    elif 'sweep' == nv[1]:
                        is_sweep = True
                    else:
                        log.error(f'unknown mode: {nv[1]}: {remote_user}, {remote_addr}, {qs}')
                else:
                    log.error(f'unknown option: {nv[0]}: {remote_user}, {remote_addr}, {qs}')
            except Exception as e:
                log.warn(f'{remote_user}, {remote_addr}, {qs}: {e}')
    # defaults
    if 1 > len(ipset):
        ip = ipaddress.ip_address(remote_addr)
        ipset.add(ip)
        filter_ipver = ip.version
        log.debug(f'using remote ip: {ip.compressed}')
    if suffix is None:
        server = dns.name.from_text(http_host)
        p = server.parent()
        if snsup.is_subdomain(p):
            suffix = snsup.relativize(p)
            log.debug(f'using default suffix: {suffix}')

    host = dns.name.from_text(remote_user, origin=dns.name.empty)
    if suffix is not None:
        host = host.derelativize(suffix)
    log.debug(f'host: {host}')
        
    if is_delete:
        snsup.obsolete(db, host, ipset, filter_ipver)
    else:
        snsup.setips(db, host, ipset, filter_ipver)

    if is_sweep:
        snsup.sweep(db)


def cgi():
    try:
        print('Content-Type: text/plain; charset=iso-8859-1\n');
        with dbms() as db:
            dispatch(db,
                     os.environ.get('QUERY_STRING'), 
                     os.environ.get('REMOTE_USER'),
                     os.environ.get('REMOTE_ADDR'),
                     os.environ.get('HTTP_HOST'))
        print('OK')
    except Exception as e:
        log.error(f'cgi: {e}')
        print(f'cgi: {e}')
        import traceback
        traceback.print_exc()

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
    cgi()



#    test()
#
#    with dbms() as db:
#        db.create_table()
#        dispatch(db, None, 'test', '10.1.2.3', 'xxx.zzz.' + config['nsupdate'].get('origin'))
#        dispatch(db, 'resolve4=x3.f&resolve6=x4.f', 'test', '10.1.2.3', 'xxx.zzz.' + config['nsupdate'].get('origin'))
#        dispatch(db, 'mode=delete', 'test', '10.1.2.3',  'xxx.zzz.' + config['nsupdate'].get('origin'))
#        snsup = nsupdate()
#        snsup.setips(db, dns.name.from_text('test', origin=dns.name.empty), {
#                ipaddress.ip_address('192.168.33.33'),
#                ipaddress.ip_address('2002:123::'),
#                ipaddress.ip_address('192.168.12.34') })
#        snsup.obsolete(db, dns.name.from_text('test', origin=dns.name.empty), {ipaddress.ip_address('192.168.12.34')})
#        snsup.obsolete(db, dns.name.from_text('test', origin=dns.name.empty))
#
#    print('done.')

# end of file
