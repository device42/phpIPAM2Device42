#!/usr/bin/env python
# -*- coding: utf-8 -*-
__version__ = 1.0

"""
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

#############################################################################################################
# v1.0 of python script that connects to PHPIPAM DB and migrates data to Device42 appliance using APIs
# Refer to README for further instructions
#############################################################################################################

import os
import sys
import imp
import json
import codecs
import base64
import netaddr
import requests
import pymysql as sql

conf = imp.load_source('conf', 'conf')


dev_types = ['physical', 'virtual', 'blade', 'cluster', 'other']
ip_types = ['static', 'dhcp', 'reserved']

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass


class Logger:

    def __init__(self, logfile, stdout):
        self.logfile = logfile
        self.stdout = stdout
        self.check_log_file()

    def check_log_file(self):
        while 1:
            if os.path.exists(self.logfile):
                reply = raw_input("[!] Log file already exists. Overwrite or append [O|A]? ")
                if reply.lower().strip() == 'o':
                    with open(self.logfile, 'w'):
                        pass
                    break
                elif reply.lower().strip() == 'a':
                    break
            else:
                break
        if conf.DEBUG and os.path.exists(conf.DEBUG_LOG):
            with open(conf.DEBUG_LOG, 'w'):
                pass

    def writer(self, msg):
        if conf.LOGFILE and conf.LOGFILE != '':
            with codecs.open(self.logfile, 'a', encoding='utf-8') as f:
                msg = msg.decode('UTF-8', 'ignore')
                f.write(msg + '\r\n')  # \r\n for notepad
        if self.stdout:
            try:
                print msg
            except:
                print msg.encode('ascii', 'ignore') + ' # < non-ASCII chars detected! >'

    @staticmethod
    def debugger(msg):
        if conf.DEBUG_LOG and conf.DEBUG_LOG != '':
            with codecs.open(conf.DEBUG_LOG, 'a', encoding='utf-8') as f:
                title, message = msg
                row = '\n-----------------------------------------------------\n%s\n%s' % (title, message)
                f.write(row + '\r\n\r\n')  # \r\n for notepad


class REST:

    def __init__(self):
        self.password = conf.D42_PWD
        self.username = conf.D42_USER
        self.base_url = conf.D42_URL

    def uploader(self, data, url):
        payload = data
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(self.username + ':' + self.password),
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        r = requests.post(url, data=payload, headers=headers, verify=False)
        msg = unicode(payload)
        logger.writer(msg)
        msg = 'Status code: %s' % str(r.status_code)
        logger.writer(msg)
        msg = str(r.text)
        logger.writer(msg)

        try:
            return r.json()
        except Exception as e:

            print '\n[*] Exception: %s' % str(e)
            pass

    def fetcher(self, url):
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(self.username + ':' + self.password),
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        r = requests.get(url, headers=headers, verify=False)
        return r.text

    def post_vrf(self, data):
        url = self.base_url + '/api/1.0/vrf_group/'
        msg = '\r\nPosting data to %s ' % url
        logger.writer(msg)
        return self.uploader(data, url)

    def get_vrfs(self):
        url = self.base_url + '/api/1.0/vrf_group/'
        msg = '\r\nGetting data from %s ' % url
        logger.writer(msg)
        return self.fetcher(url)

    def post_subnet(self, data):
        url = self.base_url + '/api/1.0/subnets/'
        msg = '\r\nPosting data to %s ' % url
        logger.writer(msg)
        self.uploader(data, url)

    def get_subnets(self):
        url = self.base_url + '/api/1.0/subnets/'
        msg = '\r\nGetting data from %s ' % url
        logger.writer(msg)
        return self.fetcher(url)

    def get_vlans(self):
        url = self.base_url + '/api/1.0/vlans/'
        msg = '\r\nGetting data from %s ' % url
        logger.writer(msg)
        return self.fetcher(url)

    def post_vlan(self, data):
        url = self.base_url + '/api/1.0/vlans/'
        msg = '\r\nPosting VLAN data to %s ' % url
        logger.writer(msg)
        self.uploader(data, url)

    def post_ip(self, data):
        url = self.base_url + '/api/1.0/ips/'
        msg = '\r\nPosting IP data to %s ' % url
        logger.writer(msg)
        self.uploader(data, url)

    def post_device(self, data):
        url = self.base_url + '/api/1.0/devices/'
        msg = '\r\nPosting IP data to %s ' % url
        logger.writer(msg)
        self.uploader(data, url)


class DB:
    """
    Fetching data from phpipam and converting them to Device42 API format.
    """

    def __init__(self):
        self.con = None
        self.default_vrf_group = conf.DEFAULT_VRF_GROUP

    def connect(self):
        """
        Connection to phpipam database
        :return:
        """
        self.con = sql.connect(host=conf.DB_IP, port=int(conf.DB_PORT), db=conf.DB_NAME,
                               user=conf.DB_USER, passwd=conf.DB_PWD)

    @staticmethod
    def convert_ip(ip_raw):
        """
        IP address conversion to human readable format
        :param ip_raw:
        :return:
        """
        ip = netaddr.IPAddress(ip_raw)
        return ip

    def integrate_devices(self):
        """
        Fetch devices from phpipam and send them to upload function
        :return:
        """
        if not self.con:
            self.connect()

        with self.con:
            cur = self.con.cursor()
            q = '''
                SELECT devices.hostname, devices.ip_addr, devices.description,
                       devices.type, devices.vendor, devices.model, deviceTypes.tname
                FROM devices LEFT JOIN deviceTypes ON devices.type = deviceTypes.tid
                '''
            cur.execute(q)
            db_devs = cur.fetchall()
            if conf.DEBUG:
                msg = ('Devices', str(db_devs))
                logger.debugger(msg)

        for line in db_devs:
            dev = {}
            ip = {}
            dev_name, dev_ip, dev_description, dev_type_id, dev_vendor, dev_model, dev_type_name = line

            dev.update({'name': dev_name})
            dev.update({'manufacturer': dev_vendor})
            dev.update({'hardware': dev_model})

            if dev_type_name is not None and dev_type_name.lower() in dev_types:
                dev.update({'type': dev_type_name.lower()})

            rest.post_device(dev)

            # send additional ip
            ip.update({'ipaddress': dev_ip})
            ip.update({'device': dev_name})

            if dev_description is not None:
                ip.update({'label': dev_description})

            rest.post_ip(ip)

    def integrate_vrfs(self):
        """
        Fetch vrfs from phpipam and send them to upload function
        :return:
        """
        if not self.con:
            self.connect()

        with self.con:
            cur = self.con.cursor()
            q = "SELECT vrf.name, vrf.description FROM vrf"
            cur.execute(q)
            db_vrfs = cur.fetchall()
            if conf.DEBUG:
                msg = ('VRFs', str(db_vrfs))
                logger.debugger(msg)

        for line in db_vrfs:
            vrf = {}
            name, description = line

            vrf.update({'name': name})
            vrf.update({'description': description})

            rest.post_vrf(vrf)

        vrf = {}
        vrf.update({'name': self.default_vrf_group})
        vrf.update({'description': 'default_vrf'})
        res = rest.post_vrf(vrf)
        self.default_vrf_group_id = res['msg'][1]

    def integrate_vlans(self):
        """
        Fetch vlans from phpipam and send them to upload function
        :return:
        """
        if not self.con:
            self.connect()

        with self.con:
            cur = self.con.cursor()
            q = "SELECT vlans.name, vlans.number, vlans.description FROM vlans"
            cur.execute(q)
            db_vlans = cur.fetchall()
            if conf.DEBUG:
                msg = ('VLANs', str(db_vlans))
                logger.debugger(msg)

        for line in db_vlans:
            vlan = {}
            name, number, description = line

            vlan.update({'name': name})
            vlan.update({'number': number})
            vlan.update({'description': description})

            rest.post_vlan(vlan)

    def integrate_subnets(self):
        """
        Fetch subnets from phpipam and send them to upload function
        :return:
        """
        if not self.con:
            self.connect()

        with self.con:
            cur = self.con.cursor()
            q = '''
                SELECT subnets.subnet, subnets.mask, subnets.description,
                       subnets.vlanId, subnets.masterSubnetId, vrf.name, vlans.number
                FROM subnets LEFT JOIN vrf ON subnets.vrfId = vrf.vrfId
                LEFT JOIN vlans ON subnets.vlanId = vlans.vlanId
                WHERE subnets.isFolder = 0
                '''
            cur.execute(q)
            subnets = cur.fetchall()
            if conf.DEBUG:
                msg = ('Subnets', str(subnets))
                logger.debugger(msg)

        rest_vrfs = json.loads(rest.get_vrfs())
        rest_vlans = json.loads(rest.get_vlans())
        rest_subnets = json.loads(rest.get_subnets())

        for line in subnets:
            sub = {}
            raw_subnet, mask, description, parent_vlan, parent_subnet, vrf, vlan_number = line
            subnet = self.convert_ip(int(raw_subnet))

            sub.update({'network': subnet})
            sub.update({'mask_bits': str(mask)})
            sub.update({'name': description})

            if vrf is not None:
                # assign vrf group
                for rest_vrf in rest_vrfs:
                    if rest_vrf['name'] == vrf:
                        sub.update({'vrf_group_id': rest_vrf['id']})
                        break
            else:
                sub.update({'vrf_group_id': self.default_vrf_group_id})

            if parent_subnet is not 0:
                # assign parent subnet
                for rest_subnet in rest_subnets['subnets']:
                    if rest_subnet['name'] == subnet:
                        sub.update({'parent_subnet_id': rest_subnet['subnet_id']})
                        break

            if parent_vlan is not 0:
                # assign parent vlan
                for rest_vlan in rest_vlans['vlans']:
                    if rest_vlan['number'] == vlan_number:
                        sub.update({'parent_vlan_id': rest_vlan['vlan_id']})
                        break

            rest.post_subnet(sub)

    def integrate_ips(self):
        """
        Fetch ips from phpipam and send them to upload function
        :return:
        """
        if not self.con:
            self.connect()

        with self.con:
            cur = self.con.cursor()
            q = '''
                SELECT ipaddresses.ip_addr, ipaddresses.description, ipaddresses.mac,
                       ipaddresses.lastSeen, subnets.subnet, vrf.name, devices.hostname, ipTags.type
                FROM ipaddresses LEFT JOIN subnets ON ipaddresses.subnetId = subnets.id
                LEFT JOIN vrf ON subnets.vrfId = vrf.vrfId
                LEFT JOIN devices ON ipaddresses.switch = devices.id
                LEFT JOIN ipTags ON ipaddresses.state = ipTags.id
                '''
            cur.execute(q)
            ips = cur.fetchall()
            if conf.DEBUG:
                msg = ('IPs', str(ips))
                logger.debugger(msg)

        for line in ips:
            address = {}
            ip_raw, label, mac, last_seen, subnet, vrf, device, ip_type = line
            subnet = self.convert_ip(int(subnet))
            ip = self.convert_ip(int(ip_raw))

            address.update({'ipaddress': ip})
            address.update({'label': label})
            address.update({'subnet': subnet})

            if ip_type.lower() in ip_types:
                address.update({'type': ip_type.lower()})

            if last_seen is not None:
                address.update({'available': 'yes'})

            if device is not None:
                address.update({'device': device})

            if vrf is not None:
                address.update({'vrf_group': vrf})

            if mac is not None:
                address.update({'macaddress': mac})

            rest.post_ip(address)


def main():
    db = DB()
    db.integrate_devices()
    db.integrate_vrfs()
    db.integrate_vlans()
    db.integrate_subnets()
    db.integrate_ips()

if __name__ == '__main__':
    logger = Logger(conf.LOGFILE, conf.STDOUT)
    rest = REST()
    main()
    print '\n[!] Done!'
    sys.exit()
