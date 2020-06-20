"""
Telemetry module for ceph-mgr

Collect statistics from Ceph cluster and send this back to the Ceph project
when user has opted-in
"""
import errno
import json
import re
import requests
import uuid
import time
from datetime import datetime
from threading import Event
from collections import defaultdict

from mgr_module import MgrModule

ALL_CHANNELS = ['basic', 'ident']

LICENSE='sharing-1-0'
LICENSE_NAME='Community Data License Agreement - Sharing - Version 1.0'
LICENSE_URL='https://cdla.io/sharing-1-0/'

# If the telemetry revision has changed since this point, re-require
# an opt-in.  This should happen each time we add new information to
# the telemetry report.
LAST_REVISION_RE_OPT_IN = 2

# Latest revision of the telemetry report.  Bump this each time we make
# *any* change.
REVISION = 3

# History of revisions
# --------------------
#
# Version 1:
#   Mimic and/or nautilus are lumped together here, since
#   we didn't track revisions yet.
#
# Version 2:
#   - added revision tracking, nagging, etc.
#   - added config option changes
#   - added channels
#   - added explicit license acknowledgement to the opt-in process
#
# Version 3:
#   - added CephFS metadata (how many MDSs, fs features, how many data pools)
#   - remove crush_rule
#   - added CephFS metadata (how many MDSs, fs features, how many data pools,
#     how much metadata is cached)
#   - added more pool metadata (rep vs ec, cache tiering mode, ec profile)
#   - rgw daemons, zones, zonegroups; which rgw frontends
#   - crush map stats

class Module(MgrModule):
    config = dict()

    metadata_keys = [
            "arch",
            "ceph_version",
            "os",
            "cpu",
            "kernel_description",
            "kernel_version",
            "distro_description",
            "distro"
    ]

    OPTIONS = [
        {
            'name': 'url',
            'default': 'https://telemetry.ceph.com/report'
        },
        {
            'name': 'enabled',
            'default': False
        },
        {
            'name': 'last_opt_revision',
            'type': 'int',
            'default': 1,
        },
        {
            'name': 'leaderboard',
            'default': False
        },
        {
            'name': 'description',
            'default': None
        },
        {
            'name': 'contact',
            'default': None
        },
        {
            'name': 'organization',
            'default': None
        },
        {
            'name': 'proxy',
            'default': None
        },
        {
            'name': 'interval',
            'default': 24
        },
        {
            'name': 'channel_basic',
            'type': 'bool',
            'default': True,
            'description': 'Share basic cluster information (size, version)',
        },
        {
            'name': 'channel_ident',
            'type': 'bool',
            'default': False,
            'description': 'Share a user-provided description and/or contact email for the cluster',
        }
    ]

    COMMANDS = [
        {
            "cmd": "telemetry config-set name=key,type=CephString "
                   "name=value,type=CephString",
            "desc": "Set a configuration value",
            "perm": "rw"
        },
        {
            "cmd": "telemetry config-show",
            "desc": "Show current configuration",
            "perm": "r"
        },
        {
            "cmd": "telemetry send",
            "desc": "Force sending data to Ceph telemetry",
            "perm": "rw"
        },
        {
            "cmd": "telemetry show "
                   "name=channels,type=CephString,n=N,req=False",
            "desc": "Show last report or report to be sent",
            "perm": "r"
        },
        {
            "cmd": "telemetry self-test",
            "desc": "Perform a self-test",
            "perm": "r"
        },
        {
            "cmd": "telemetry on name=license,type=CephString,req=false",
            "desc": "Enable telemetry reports from this cluster",
            "perm": "rw",
        },
        {
            "cmd": "telemetry off",
            "desc": "Disable telemetry reports from this cluster",
            "perm": "rw",
        }
    ]

    @property
    def config_keys(self):
        return dict((o['name'], o.get('default', None)) for o in self.OPTIONS)

    def __init__(self, *args, **kwargs):
        super(Module, self).__init__(*args, **kwargs)
        self.event = Event()
        self.run = False
        self.last_upload = None
        self.last_report = dict()
        self.report_id = None

    @staticmethod
    def str_to_bool(string):
        return str(string).lower() in ['true', 'yes', 'on']

    @staticmethod
    def is_valid_email(email):
        regexp = "^.+@([?)[a-zA-Z0-9-.]+.([a-zA-Z]{2,3}|[0-9]{1,3})(]?))$"
        try:
            if len(email) <= 7 or len(email) > 255:
                return False

            if not re.match(regexp, email):
                return False

            return True
        except:
            pass

        return False

    def set_config_option(self, option, value):
        if option not in self.config_keys.keys():
            raise RuntimeError('{0} is a unknown configuration '
                               'option'.format(option))

        if option == 'interval':
            try:
                value = int(value)
            except (ValueError, TypeError):
                raise RuntimeError('invalid interval. Please provide a valid '
                                   'integer')

            if value < 24:
                raise RuntimeError('interval should be set to at least 24 hours')

        if option in ['leaderboard', 'enabled']:
            value = self.str_to_bool(value)

        if option == 'contact':
            if value and not self.is_valid_email(value):
                raise RuntimeError('%s is not a valid e-mail address as a '
                                   'contact', value)

        if option in ['description', 'organization']:
            if value and len(value) > 256:
                raise RuntimeError('%s should be limited to 256 '
                                   'characters', option)

        self.config[option] = value
        return True

    def init_module_config(self):
        for key, default in self.config_keys.items():
            self.set_config_option(key, self.get_config(key, default))

        self.last_upload = self.get_config('last_upload', None)
        if self.last_upload is not None:
            self.last_upload = int(self.last_upload)

        self.report_id = self.get_config('report_id', None)
        if self.report_id is None:
            self.report_id = str(uuid.uuid4())
            self.set_config('report_id', self.report_id)

    def gather_osd_metadata(self, osd_map):
        keys = ["osd_objectstore", "rotational"]
        keys += self.metadata_keys

        metadata = dict()
        for key in keys:
            metadata[key] = defaultdict(int)

        for osd in osd_map['osds']:
            for k, v in self.get_metadata('osd', str(osd['osd'])).items():
                if k not in keys:
                    continue

                metadata[k][v] += 1

        return metadata

    def gather_mon_metadata(self, mon_map):
        keys = list()
        keys += self.metadata_keys

        metadata = dict()
        for key in keys:
            metadata[key] = defaultdict(int)

        for mon in mon_map['mons']:
            for k, v in self.get_metadata('mon', mon['name']).items():
                if k not in keys:
                    continue

                metadata[k][v] += 1

        return metadata

    def gather_crush_info(self):
        osdmap = self.get_osdmap()
        crush_raw = osdmap.get_crush()
        crush = crush_raw.dump()

        def inc(d, k):
            if k in d:
                d[k] += 1
            else:
                d[k] = 1

        device_classes = {}
        for dev in crush['devices']:
            inc(device_classes, dev.get('class', ''))

        bucket_algs = {}
        bucket_types = {}
        bucket_sizes = {}
        for bucket in crush['buckets']:
            if '~' in bucket['name']:  # ignore shadow buckets
                continue
            inc(bucket_algs, bucket['alg'])
            inc(bucket_types, bucket['type_id'])
            inc(bucket_sizes, len(bucket['items']))

        return {
            'num_devices': len(crush['devices']),
            'num_types': len(crush['types']),
            'num_buckets': len(crush['buckets']),
            'num_rules': len(crush['rules']),
            'device_classes': list(device_classes.values()),
            'tunables': crush['tunables'],
            'compat_weight_set': '-1' in crush['choose_args'],
            'num_weight_sets': len(crush['choose_args']),
            'bucket_algs': bucket_algs,
            'bucket_sizes': bucket_sizes,
            'bucket_types': bucket_types,
        }

    def get_active_channels(self):
        r = []
        if self.config['channel_basic']:
            r.append('basic')
        return r

    def get_latest(self, daemon_type, daemon_name, stat):
        data = self.get_counter(daemon_type, daemon_name, stat)[stat]
        #self.log.error("get_latest {0} data={1}".format(stat, data))
        if data:
            return data[-1][1]
        else:
            return 0

    def compile_report(self, channels=[]):
        if not channels:
            channels = self.get_active_channels()
        report = {
            'leaderboard': False,
            'report_version': 1,
            'report_timestamp': datetime.utcnow().isoformat(),
            'report_id': self.report_id,
            'channels': channels,
            'channels_available': ALL_CHANNELS,
            'license': LICENSE,
        }

        if 'ident' in channels:
            if self.config['leaderboard']:
                report['leaderboard'] = True
            for option in ['description', 'contact', 'organization']:
                report[option] = self.config.get(option, None)

        if 'basic' in channels:
            mon_map = self.get('mon_map')
            osd_map = self.get('osd_map')
            service_map = self.get('service_map')
            fs_map = self.get('fs_map')
            df = self.get('df')

            report['created'] = mon_map['created']

            ipv4_mons = 0
            ipv6_mons = 0
            for mon in mon_map['mons']:
                if mon['public_addr'].startswith('['):
                    ipv6_mons += 1
                else:
                    ipv4_mons += 1

            report['mon'] = {
                'count': len(mon_map['mons']),
                'features': mon_map['features'],
                'ipv4_addr_mons': ipv4_mons,
                'ipv6_addr_mons': ipv6_mons,
            }

            # pools
            num_pg = 0
            report['pools'] = list()
            for pool in osd_map['pools']:
                num_pg += pool['pg_num']
                ec_profile = {}
                if pool['erasure_code_profile']:
                    orig = osd_map['erasure_code_profiles'].get(
                        pool['erasure_code_profile'], {})
                    ec_profile = {
                        k: orig[k] for k in orig.keys()
                        if k in ['k', 'm', 'plugin', 'technique',
                                 'crush-failure-domain', 'l']
                    }
                report['pools'].append(
                    {
                        'pool': pool['pool'],
                        'type': pool['type'],
                        'pg_num': pool['pg_num'],
                        'pgp_num': pool['pg_placement_num'],
                        'size': pool['size'],
                        'min_size': pool['min_size'],
                        'type': ['', 'replicated', '', 'erasure'][pool['type']],
                        'erasure_code_profile': ec_profile,
                        'cache_mode': pool['cache_mode'],
                    }
                )

            # osds
            report['osd'] = {
                'count': len(osd_map['osds']),
                'require_osd_release': osd_map['require_osd_release'],
                'require_min_compat_client': osd_map['require_min_compat_client']
            }

            # crush
            report['crush'] = self.gather_crush_info()

            # cephfs
            report['fs'] = {
                'count': len(fs_map['filesystems']),
                'feature_flags': fs_map['feature_flags'],
                'num_standby_mds': len(fs_map['standbys']),
                'filesystems': [],
            }
            num_mds = len(fs_map['standbys'])
            for fsm in fs_map['filesystems']:
                fs = fsm['mdsmap']
                num_sessions = 0
                cached_ino = 0
                cached_dn = 0
                cached_cap = 0
                subtrees = 0
                for gid, mds in fs['info'].items():
                    num_sessions += self.get_latest('mds', mds['name'],
                                                    'mds_sessions.session_count')
                    cached_ino += self.get_latest('mds', mds['name'],
                                                  'mds_mem.ino')
                    cached_dn += self.get_latest('mds', mds['name'],
                                                 'mds_mem.dn')
                    cached_cap += self.get_latest('mds', mds['name'],
                                                  'mds_mem.cap')
                    subtrees += self.get_latest('mds', mds['name'],
                                                'mds.subtrees')
                report['fs']['filesystems'].append({
                    'max_mds': fs['max_mds'],
                    'ever_allowed_features': fs['ever_allowed_features'],
                    'explicitly_allowed_features': fs['explicitly_allowed_features'],
                    'num_in': len(fs['in']),
                    'num_up': len(fs['up']),
                    'num_standby_replay': len(
                        [mds for gid, mds in fs['info'].items()
                         if mds['state'] == 'up:standby-replay']),
                    'num_mds': len(fs['info']),
                    'num_sessions': num_sessions,
                    'cached_inos': cached_ino,
                    'cached_dns': cached_dn,
                    'cached_caps': cached_cap,
                    'cached_subtrees': subtrees,
                    'balancer_enabled': len(fs['balancer']) > 0,
                    'num_data_pools': len(fs['data_pools']),
                    'standby_count_wanted': fs['standby_count_wanted'],
                    'approx_ctime': fs['created'][0:7],
                })
                num_mds += len(fs['info'])
            report['fs']['total_num_mds'] = num_mds

            # daemons
            report['metadata'] = dict()
            report['metadata']['osd'] = self.gather_osd_metadata(osd_map)
            report['metadata']['mon'] = self.gather_mon_metadata(mon_map)

            report['usage'] = {
                'pools': len(df['pools']),
                'pg_num:': num_pg,
                'total_used_bytes': df['stats']['total_used_bytes'],
                'total_bytes': df['stats']['total_bytes'],
                'total_avail_bytes': df['stats']['total_avail_bytes']
            }

            report['services'] = defaultdict(int)
            for key, value in service_map['services'].items():
                report['services'][key] += 1
                if key == 'rgw':
                    report['rgw'] = {
                        'count': 0,
                    }
                    zones = set()
                    realms = set()
                    zonegroups = set()
                    frontends = set()
                    d = value.get('daemons', dict())

                    for k,v in d.items():
                        if k == 'summary' and v:
                            report['rgw'][k] = v
                        elif isinstance(v, dict) and 'metadata' in v:
                            report['rgw']['count'] += 1
                            zones.add(v['metadata']['zone_id'])
                            zonegroups.add(v['metadata']['zonegroup_id'])
                            frontends.add(v['metadata']['frontend_type#0'])

                            # we could actually iterate over all the keys of
                            # the dict and check for how many frontends there
                            # are, but it is unlikely that one would be running
                            # more than 2 supported ones
                            f2 = v['metadata'].get('frontend_type#1', None)
                            if f2:
                                frontends.add(f2)

                    report['rgw']['zones'] = len(zones)
                    report['rgw']['zonegroups'] = len(zonegroups)
                    report['rgw']['frontends'] = list(frontends)  # sets aren't json-serializable

        return report

    def send(self, report):
        self.log.info('Upload report to: %s', self.config['url'])
        proxies = dict()
        if 'proxy' in self.config:
            self.log.info('Using HTTP(S) proxy: %s', self.config['proxy'])
            proxies['http'] = self.config['proxy']
            proxies['https'] = self.config['proxy']

        resp = requests.put(url=self.config['url'],
                            json=report, proxies=proxies)
        if not resp.ok:
            self.log.error("Report send failed: %d %s %s" %
                           (resp.status_code, resp.reason, resp.text))
        return resp

    def handle_command(self, command):
        if command['prefix'] == 'telemetry config-show':
            return 0, json.dumps(self.config), ''
        elif command['prefix'] == 'telemetry config-set':
            key = command['key']
            value = command['value']
            if not value:
                return -errno.EINVAL, '', 'Value should not be empty or None'

            self.log.debug('Setting configuration option %s to %s', key, value)
            self.set_config_option(key, value)
            self.set_config(key, value)
            return 0, 'Configuration option {0} updated'.format(key), ''
        elif command['prefix'] == 'telemetry on':
            if command.get('license') != LICENSE:
                return -errno.EPERM, '', "Telemetry data is licensed under the " + LICENSE_NAME + " (" + LICENSE_URL + ").\nTo enable, add '--license " + LICENSE + "' to the 'ceph telemetry on' command."
            self.set_config('enabled', True)
            self.set_config('last_opt_revision', REVISION)
            return 0, '', ''
        elif command['prefix'] == 'telemetry off':
            self.set_config('enabled', False)
            self.set_config('last_opt_revision', REVISION)
            return 0, '', ''
        elif command['prefix'] == 'telemetry send':
            self.last_report = self.compile_report()
            resp = self.send(self.last_report)
            if resp.ok:
                return 0, 'Report sent to {0}'.format(self.config['url']), ''
            return 1, '', 'Failed to send report to %s: %d %s %s' % (
                self.config['url'],
                resp.status_code,
                resp.reason,
                resp.text
            )
        elif command['prefix'] == 'telemetry show':
            report = self.compile_report(
                channels=command.get('channels', None)
            )
            return 0, json.dumps(report, indent=4), ''
        elif command['prefix'] == 'telemetry self-test':
            self.self_test()
            return 0, 'Self-test succeeded', ''
        else:
            return (-errno.EINVAL, '',
                    "Command not found '{0}'".format(command['prefix']))

    def self_test(self):
        report = self.compile_report()
        if len(report) == 0:
            raise RuntimeError('Report is empty')

        if 'report_id' not in report:
            raise RuntimeError('report_id not found in report')

    def shutdown(self):
        self.run = False
        self.event.set()

    def refresh_health_checks(self):
        health_checks = {}
        if self.enabled and self.last_opt_revision < LAST_REVISION_RE_OPT_IN:
            health_checks['TELEMETRY_CHANGED'] = {
                'severity': 'warning',
                'summary': 'Telemetry requires re-opt-in',
                'detail': [
                    'telemetry report includes new information; must re-opt-in (or out)'
                ]
            }
        self.set_health_checks(health_checks)

    def serve(self):
        self.init_module_config()
        self.run = True

        self.log.debug('Waiting for mgr to warm up')
        self.event.wait(10)

        while self.run:
            self.event.clear()

            self.refresh_health_checks()

            if self.last_opt_revision < LAST_REVISION_RE_OPT_IN:
                self.log.debug('Not sending report until user re-opts-in')
                self.event.wait(1800)
                continue
            if not self.config['enabled']:
                self.log.debug('Not sending report until configured to do so')
                self.event.wait(1800)
                continue

            now = int(time.time())
            if not self.last_upload or (now - self.last_upload) > \
                            self.config['interval'] * 3600:
                self.log.info('Compiling and sending report to %s',
                              self.config['url'])

                try:
                    self.last_report = self.compile_report()
                except:
                    self.log.exception('Exception while compiling report:')

                try:
                    resp = self.send(self.last_report)
                    # self.send logs on failure; only update last_upload
                    # if we succeed
                    if resp.ok:
                        self.last_upload = now
                        self.set_config('last_upload', str(now))
                except:
                    self.log.exception('Exception while sending report:')
            else:
                self.log.debug('Interval for sending new report has not expired')

            sleep = 3600
            self.log.debug('Sleeping for %d seconds', sleep)
            self.event.wait(sleep)

    def self_test(self):
        self.compile_report()
        return True

    @staticmethod
    def can_run():
        return True, ''
