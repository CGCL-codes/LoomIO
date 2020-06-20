from __future__ import print_function
from ceph_volume.util import disk, prepare
from ceph_volume.api import lvm
from . import validators
from .strategies import Strategy
from .strategies import MixedStrategy
from ceph_volume.devices.lvm.create import Create
from ceph_volume.devices.lvm.prepare import Prepare
from ceph_volume.util import templates
from ceph_volume.exceptions import SizeAllocationError


def get_journal_size(args):
    """
    Helper for Filestore strategies, to prefer the --journal-size value from
    the CLI over anything that might be in a ceph configuration file (if any).
    """
    if args.journal_size:
        return disk.Size(mb=args.journal_size)
    else:
        return prepare.get_journal_size(lv_format=False)


class SingleType(Strategy):
    """
    Support for all SSDs, or all HDDs, data and journal LVs will be colocated
    in the same device
    """

    def __init__(self, devices, args):
        super(SingleType, self).__init__(devices, args)
        self.journal_size = get_journal_size(args)
        self.validate_compute()

    @staticmethod
    def type():
        return "filestore.SingleType"

    def report_pretty(self):
        string = ""
        if self.args.filtered_devices:
            string += templates.filtered_devices(self.args.filtered_devices)
        string += templates.total_osds.format(
            total_osds=self.total_osds
        )
        string += templates.osd_component_titles

        for osd in self.computed['osds']:
            string += templates.osd_header
            string += templates.osd_component.format(
                _type='[data]',
                path=osd['data']['path'],
                size=osd['data']['human_readable_size'],
                percent=osd['data']['percentage'],
            )
            string += templates.osd_component.format(
                _type='[journal]',
                path=osd['journal']['path'],
                size=osd['journal']['human_readable_size'],
                percent=osd['journal']['percentage'],
            )

        print(string)

    def validate(self):
        """
        Ensure that the minimum requirements for this type of scenario is
        met, raise an error if the provided devices would not work
        """
        # validate minimum size for all devices
        validators.minimum_device_size(self.devices, osds_per_device=self.osds_per_device)

        # validate collocation
        if self.hdds:
            validators.minimum_device_collocated_size(
                self.hdds, self.journal_size, osds_per_device=self.osds_per_device
            )
        else:
            validators.minimum_device_collocated_size(
                self.ssds, self.journal_size, osds_per_device=self.osds_per_device
            )

        # make sure that data devices do not have any LVs
        validators.no_lvm_membership(self.hdds)

    def compute(self):
        """
        Go through the rules needed to properly size the lvs, return
        a dictionary with the result
        """
        # chose whichever is the one group we have to compute against
        devices = self.hdds or self.ssds
        osds = self.computed['osds']
        for device in devices:
            for osd in range(self.osds_per_device):
                device_size = disk.Size(b=device.sys_api['size'])
                osd_size = device_size / self.osds_per_device
                journal_size = self.journal_size
                data_size = osd_size - journal_size
                data_percentage = data_size * 100 / device_size
                osd = {'data': {}, 'journal': {}}
                osd['data']['path'] = device.abspath
                osd['data']['size'] = data_size.b.as_int()
                osd['data']['parts'] = self.osds_per_device
                osd['data']['percentage'] = int(data_percentage)
                osd['data']['human_readable_size'] = str(data_size)
                osd['journal']['path'] = device.abspath
                osd['journal']['size'] = journal_size.b.as_int()
                osd['journal']['percentage'] = int(100 - data_percentage)
                osd['journal']['human_readable_size'] = str(journal_size)
                osds.append(osd)

        self.computed['changed'] = len(osds) > 0

    def execute(self):
        """
        Create vgs/lvs from the incoming set of devices, assign their roles
        (data, journal) and offload the OSD creation to ``lvm create``
        """
        device_vgs = dict([(osd['data']['path'], None) for osd in self.computed['osds']])

        # create 1 vg per data device first, mapping them to the device path,
        # when the lvs get created later, it can create as many as needed,
        # including the journals since it is going to be collocated
        for osd in self.computed['osds']:
            vg = device_vgs.get(osd['data']['path'])
            if not vg:
                vg = lvm.create_vg(osd['data']['path'], name_prefix='ceph-filestore')
                device_vgs[osd['data']['path']] = vg

        # create the lvs from the per-device vg created in the beginning
        for osd in self.computed['osds']:
            data_path = osd['data']['path']
            data_lv_size = disk.Size(b=osd['data']['size']).gb.as_int()
            device_vg = device_vgs[data_path]
            data_lv_extents = device_vg.sizing(size=data_lv_size)['extents']
            journal_lv_extents = device_vg.sizing(size=self.journal_size.gb.as_int())['extents']
            data_lv = lvm.create_lv(
                'osd-data', device_vg.name, extents=data_lv_extents, uuid_name=True
            )
            journal_lv = lvm.create_lv(
                'osd-journal', device_vg.name, extents=journal_lv_extents, uuid_name=True
            )

            command = ['--filestore', '--data']
            command.append('%s/%s' % (device_vg.name, data_lv.name))
            command.extend(['--journal', '%s/%s' % (device_vg.name, journal_lv.name)])
            if self.args.dmcrypt:
                command.append('--dmcrypt')
            if self.args.no_systemd:
                command.append('--no-systemd')
            if self.args.crush_device_class:
                command.extend(['--crush-device-class', self.args.crush_device_class])

            if self.args.prepare:
                Prepare(command).main()
            else:
                Create(command).main()


class MixedType(MixedStrategy):
    """
    Supports HDDs with SSDs, journals will be placed on SSDs, while HDDs will
    be used fully for data.

    If an existing common VG is detected on SSDs, it will be extended if blank
    SSDs are used, otherwise it will be used directly.
    """

    def __init__(self, devices, args):
        super(MixedType, self).__init__(devices, args)
        self.blank_ssds = []
        self.journals_needed = len(self.hdds) * self.osds_per_device
        self.journal_size = get_journal_size(args)
        self.system_vgs = lvm.VolumeGroups()
        self.validate_compute()

    @staticmethod
    def type():
        return "filestore.MixedType"

    def report_pretty(self):
        string = ""
        if self.args.filtered_devices:
            string += templates.filtered_devices(self.args.filtered_devices)
        string += templates.total_osds.format(
            total_osds=self.total_osds
        )

        string += templates.ssd_volume_group.format(
            target='journal',
            total_lv_size=str(self.total_available_journal_space),
            total_lvs=self.journals_needed,
            block_db_devices=', '.join([d.path for d in self.ssds]),
            lv_size=str(self.journal_size),
            total_osds=self.journals_needed
        )

        string += templates.osd_component_titles

        for osd in self.computed['osds']:
            string += templates.osd_header
            string += templates.osd_component.format(
                _type='[data]',
                path=osd['data']['path'],
                size=osd['data']['human_readable_size'],
                percent=osd['data']['percentage'],
            )
            string += templates.osd_component.format(
                _type='[journal]',
                path=osd['journal']['path'],
                size=osd['journal']['human_readable_size'],
                percent=osd['journal']['percentage'],
            )

        print(string)

    def validate(self):
        """
        Ensure that the minimum requirements for this type of scenario is
        met, raise an error if the provided devices would not work
        """
        # validate minimum size for all devices
        validators.minimum_device_size(self.devices, osds_per_device=self.osds_per_device)

        # make sure that data devices do not have any LVs
        validators.no_lvm_membership(self.hdds)

        # do not allow non-common VG to continue
        validators.has_common_vg(self.ssds)

        # find the common VG to calculate how much is available
        self.common_vg = self.get_common_vg()

        # find how many journals are possible from the common VG
        if self.common_vg:
            common_vg_size = disk.Size(gb=self.common_vg.free)
        else:
            common_vg_size = disk.Size(gb=0)

        # non-VG SSDs
        self.vg_ssds = set([d for d in self.ssds if d.is_lvm_member])
        self.blank_ssds = set(self.ssds).difference(self.vg_ssds)
        self.total_blank_ssd_size = disk.Size(b=0)
        for blank_ssd in self.blank_ssds:
            self.total_blank_ssd_size += disk.Size(b=blank_ssd.sys_api['size'])

        self.total_available_journal_space = self.total_blank_ssd_size + common_vg_size

        try:
            self.vg_extents = lvm.sizing(
                self.total_available_journal_space.b, size=self.journal_size.b * self.osds_per_device
            )
        except SizeAllocationError:
            msg = "Not enough space in fast devices (%s) to create %s x %s journal LV"
            raise RuntimeError(
                msg % (self.total_available_journal_space, self.osds_per_device, self.journal_size)
            )

        # validate that number of journals possible are enough for number of
        # OSDs proposed
        total_journals_possible = self.total_available_journal_space / self.journal_size
        if self.osds_per_device > total_journals_possible:
            msg = "Not enough space (%s) to create %s x %s journal LVs" % (
                self.total_available_journal_space, self.journals_needed, self.journal_size
            )
            raise RuntimeError(msg)

    def compute(self):
        """
        Go through the rules needed to properly size the lvs, return
        a dictionary with the result
        """
        osds = self.computed['osds']

        vg_free = int(self.total_available_journal_space.gb)
        if not self.common_vg:
            # there isn't a common vg, so a new one must be created with all
            # the blank SSDs
            self.computed['vg'] = {
                'devices': ", ".join([ssd.abspath for ssd in self.blank_ssds]),
                'parts': self.journals_needed,
                'percentages': self.vg_extents['percentages'],
                'sizes': self.journal_size.b.as_int(),
                'size': self.total_blank_ssd_size.b.as_int(),
                'human_readable_sizes': str(self.journal_size),
                'human_readable_size': str(self.total_available_journal_space),
            }
            vg_name = 'lv/vg'
        else:
            vg_name = self.common_vg.name

        for device in self.hdds:
            for osd in range(self.osds_per_device):
                device_size = disk.Size(b=device.sys_api['size'])
                data_size = device_size / self.osds_per_device
                osd = {'data': {}, 'journal': {}}
                osd['data']['path'] = device.path
                osd['data']['size'] = data_size.b.as_int()
                osd['data']['percentage'] = 100 / self.osds_per_device
                osd['data']['human_readable_size'] = str(data_size)
                osd['journal']['path'] = 'vg: %s' % vg_name
                osd['journal']['size'] = self.journal_size.b.as_int()
                osd['journal']['percentage'] = int(self.journal_size.gb * 100 / vg_free)
                osd['journal']['human_readable_size'] = str(self.journal_size)
                osds.append(osd)

        self.computed['changed'] = len(osds) > 0

    def execute(self):
        """
        Create vgs/lvs from the incoming set of devices, assign their roles
        (data, journal) and offload the OSD creation to ``lvm create``
        """
        blank_ssd_paths = [d.abspath for d in self.blank_ssds]
        data_vgs = dict([(osd['data']['path'], None) for osd in self.computed['osds']])

        # no common vg is found, create one with all the blank SSDs
        if not self.common_vg:
            journal_vg = lvm.create_vg(blank_ssd_paths, name_prefix='ceph-journals')
        # a vg exists that can be extended
        elif self.common_vg and blank_ssd_paths:
            journal_vg = lvm.extend_vg(self.common_vg, blank_ssd_paths)
        # one common vg with nothing else to extend can be used directly
        else:
            journal_vg = self.common_vg

        journal_size = prepare.get_journal_size(lv_format=True)

        # create 1 vg per data device first, mapping them to the device path,
        # when the lv gets created later, it can create as many as needed (or
        # even just 1)
        for osd in self.computed['osds']:
            vg = data_vgs.get(osd['data']['path'])
            if not vg:
                vg = lvm.create_vg(osd['data']['path'], name_prefix='ceph-data')
                data_vgs[osd['data']['path']] = vg

        for osd in self.computed['osds']:
            data_path = osd['data']['path']
            data_lv_size = disk.Size(b=osd['data']['size']).gb.as_int()
            data_vg = data_vgs[data_path]
            data_lv_extents = data_vg.sizing(size=data_lv_size)['extents']
            data_lv = lvm.create_lv(
                'osd-data', data_vg.name, extents=data_lv_extents, uuid_name=True
            )
            journal_lv = lvm.create_lv(
                'osd-journal', journal_vg.name, size=journal_size, uuid_name=True
            )

            command = ['--filestore', '--data']
            command.append('%s/%s' % (data_vg.name, data_lv.name))
            command.extend(['--journal', '%s/%s' % (journal_vg.name, journal_lv.name)])
            if self.args.dmcrypt:
                command.append('--dmcrypt')
            if self.args.no_systemd:
                command.append('--no-systemd')
            if self.args.crush_device_class:
                command.extend(['--crush-device-class', self.args.crush_device_class])

            if self.args.prepare:
                Prepare(command).main()
            else:
                Create(command).main()
