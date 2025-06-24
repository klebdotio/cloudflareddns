#!/usr/bin/env python3
import requests
import yaml
import os
from os import path
from sys import exit
import logging
import argparse
from subprocess import Popen, PIPE

# Current directory
CURRENT_DIR = path.dirname(path.realpath(__file__))

# CLI
parser = argparse.ArgumentParser('cloudflare-ddns2.0.py')
parser.add_argument('-z', '--zone', dest="zone", action="append", help="Zone name")
args = parser.parse_args()

# Logger
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
log.addHandler(ch)

# Cloudflare API
API_HEADERS = {}
API_ENDPOINT = 'https://api.cloudflare.com/client/v4/'

# Cached IP addresses
IP_ADDRESSES = {
    4: None,
    6: None
}

# Start the client
def main():
    if not args.zone:
        log.critical("Please specify a zone name using -z")
        return

    os.makedirs(path.join(CURRENT_DIR, 'logs'), exist_ok=True)

    for zone in set(args.zone):
        config_path = path.join(CURRENT_DIR, 'zones', zone + '.yml')
        if not path.isfile(config_path):
            log.critical(f"Zone config file for '{zone}' not found at {config_path}")
            continue

        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
            cf_api_key = config.get('cf_api_key')
            cf_email = config.get('cf_email')
            cf_zone = config.get('cf_zone')
            cf_records = config.get('cf_records')
            cf_resolving_method = config.get('cf_resolving_method', 'http')
            cf_logging_level = config.get('cf_logging_level', 'INFO')

        # Type check
        if not isinstance(cf_records, list):
            log.critical(f"'cf_records' must be a list in {zone}.yml")
            continue

        # Auth headers
        global API_HEADERS
        API_HEADERS = {
            'X-Auth-Key': cf_api_key,
            'X-Auth-Email': cf_email
        }

        # Get zone info
        payload = {'name': cf_zone}
        try:
            r = requests.get(API_ENDPOINT + 'zones', headers=API_HEADERS, params=payload)
            r.raise_for_status()
            data = r.json().get('result')
        except Exception as e:
            log.critical(f"Error fetching zone info: {e}")
            continue

        if not data:
            log.critical(f"The zone '{cf_zone}' was not found on your account")
            continue

        cf_zone_uuid = data[0]['id']
        cf_zone_name = data[0]['name']

        fh = logging.FileHandler(path.join(CURRENT_DIR, 'logs', cf_zone_name + '.log'))
        fh.setFormatter(formatter)
        log.addHandler(fh)

        cf_zone_records = get_zone_records(cf_zone_uuid)

        for records in cf_records:
            for record_name in records:
                local_record = records[record_name]
                log_level = local_record.get('log', cf_logging_level)
                ch.setLevel(logging.getLevelName(log_level))
                fh.setLevel(logging.getLevelName(log_level))

                if record_name == '@':
                    name = cf_zone_name
                else:
                    name = record_name + '.' + cf_zone_name

                zone_record = None
                for record in cf_zone_records:
                    if record.get('name') == name and record.get('type') == local_record.get('type'):
                        zone_record = record
                        break

                if not zone_record:
                    log.error(f"The record '{name}' ({local_record.get('type')}) was not found")
                    continue

                update_record(zone_record, local_record, cf_resolving_method, cf_zone_uuid)

# Get all records from zone
def get_zone_records(zone_uuid):
    records = []
    current_page = 0
    total_pages = 1

    while current_page != total_pages:
        current_page += 1
        payload = {'page': current_page, 'per_page': 50}
        try:
            r = requests.get(API_ENDPOINT + f'zones/{zone_uuid}/dns_records', headers=API_HEADERS, params=payload)
            r.raise_for_status()
            result = r.json()
        except Exception as e:
            log.error(f"Failed to fetch DNS records: {e}")
            break

        data = result.get('result', [])
        info = result.get('result_info', {})
        total_pages = info.get('total_pages', 1)
        records.extend(data)

    return records

# Update a record
def update_record(zone_record, local_record, resolving_method, zone_uuid):
    ip = get_ip(resolving_method, local_record.get('type'))
    name = zone_record.get('name')
    record_type = zone_record.get('type')
    ttl = local_record.get('ttl', zone_record.get('ttl'))
    proxied = local_record.get('proxied', zone_record.get('proxied'))

    if proxied:
        if ttl != 1:
            log.warning(f"TTL for proxied record '{name}' forced to 1")
        ttl = 1
    elif not 120 <= ttl <= 2147483647 and ttl != 1:
        log.error(f"Skipping record '{name}' ({record_type}) due to invalid TTL")
        return

    if zone_record.get('content') == ip and zone_record.get('ttl') == ttl and zone_record.get('proxied') == proxied:
        log.info(f"The record '{name}' ({record_type}) is already up to date")
        return

    payload = {
        'ttl': ttl,
        'name': name,
        'type': record_type,
        'content': ip,
        'proxied': proxied
    }

    try:
        r = requests.put(API_ENDPOINT + f'zones/{zone_uuid}/dns_records/{zone_record["id"]}', headers=API_HEADERS, json=payload)
        success = r.json().get('success', False)
    except Exception as e:
        log.critical(f"Error updating record '{name}': {e}")
        return

    if not success:
        log.critical(f"Failed to update record '{name}' ({record_type})")
        return

    log.info(f"The record '{name}' ({record_type}) has been updated successfully")

# Resolve the server's IP
def get_ip(method, record_type):
    v = 6 if record_type == 'AAAA' else 4

    if IP_ADDRESSES[v]:
        return IP_ADDRESSES[v]

    if method == 'dig':
        resolvers = {
            4: 'resolver1.opendns.com',
            6: 'resolver1.ipv6-sandbox.opendns.com'
        }
        p = Popen(['dig', '+short', 'myip.opendns.com', record_type, '@' + resolvers[v], f'-{v}'], stdin=PIPE, stderr=PIPE, stdout=PIPE)
        output, err = p.communicate()
        public_ip = output.decode().strip()
    else:
        r = requests.get(f'https://ipv{v}.icanhazip.com')
        public_ip = r.text.strip()

    IP_ADDRESSES[v] = public_ip
    return public_ip

# Main entry
if __name__ == '__main__':
    main()