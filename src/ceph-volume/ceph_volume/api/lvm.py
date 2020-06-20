"""
API for CRUD lvm tag operations. Follows the Ceph LVM tag naming convention
that prefixes tags with ``ceph.`` and uses ``=`` for assignment, and provides
set of utilities for interacting with LVM.
"""
import logging
import os
import uuid
from math import floor
from ceph_volume import process, util
from ceph_volume.exceptions import (
    MultipleLVsError, MultipleVGsError,
    MultiplePVsError, SizeAllocationError
)

logger = logging.getLogger(__name__)


def _output_parser(output, fields):
    """
    Newer versions of LVM allow ``--reportformat=json``, but older versions,
    like the one included in Xenial do not. LVM has the ability to filter and
    format its output so we assume the output will be in a format this parser
    can handle (using ',' as a delimiter)

    :param fields: A string, possibly using ',' to group many items, as it
                   would be used on the CLI
    :param output: The CLI output from the LVM call
    """
    field_items = fields.split(',')
    report = []
    for line in output:
        # clear the leading/trailing whitespace
        line = line.strip()

        # remove the extra '"' in each field
        line = line.replace('"', '')

        # prevent moving forward with empty contents
        if not line:
            continue

        # spliting on ';' because that is what the lvm call uses as
        # '--separator'
        output_items = [i.strip() for i in line.split(';')]
        # map the output to the fiels
        report.append(
            dict(zip(field_items, output_items))
        )

    return report


def _splitname_parser(line):
    """
    Parses the output from ``dmsetup splitname``, that should contain prefixes
    (--nameprefixes) and set the separator to ";"

    Output for /dev/mapper/vg-lv will usually look like::

        DM_VG_NAME='/dev/mapper/vg';DM_LV_NAME='lv';DM_LV_LAYER=''


    The ``VG_NAME`` will usually not be what other callers need (e.g. just 'vg'
    in the example), so this utility will split ``/dev/mapper/`` out, so that
    the actual volume group name is kept

    :returns: dictionary with stripped prefixes
    """
    parsed = {}
    try:
        parts = line[0].split(';')
    except IndexError:
        logger.exception('Unable to parse mapper device: %s', line)
        return parsed

    for part in parts:
        part = part.replace("'", '')
        key, value = part.split('=')
        if 'DM_VG_NAME' in key:
            value = value.split('/dev/mapper/')[-1]
        key = key.split('DM_')[-1]
        parsed[key] = value

    return parsed


def sizing(device_size, parts=None, size=None):
    """
    Calculate proper sizing to fully utilize the volume group in the most
    efficient way possible. To prevent situations where LVM might accept
    a percentage that is beyond the vg's capabilities, it will refuse with
    an error when requesting a larger-than-possible parameter, in addition
    to rounding down calculations.

    A dictionary with different sizing parameters is returned, to make it
    easier for others to choose what they need in order to create logical
    volumes::

        >>> sizing(100, parts=2)
        >>> {'parts': 2, 'percentages': 50, 'sizes': 50}

    """
    if parts is not None and size is not None:
        raise ValueError(
            "Cannot process sizing with both parts (%s) and size (%s)" % (parts, size)
        )

    if size and size > device_size:
        raise SizeAllocationError(size, device_size)

    def get_percentage(parts):
        return int(floor(100 / float(parts)))

    if parts is not None:
        # Prevent parts being 0, falling back to 1 (100% usage)
        parts = parts or 1
        percentages = get_percentage(parts)

    if size:
        parts = int(device_size / size) or 1
        percentages = get_percentage(parts)

    sizes = device_size / parts if parts else int(floor(device_size))

    return {
        'parts': parts,
        'percentages': percentages,
        'sizes': int(sizes),
    }


def parse_tags(lv_tags):
    """
    Return a dictionary mapping of all the tags associated with
    a Volume from the comma-separated tags coming from the LVM API

    Input look like::

       "ceph.osd_fsid=aaa-fff-bbbb,ceph.osd_id=0"

    For the above example, the expected return value would be::

        {
            "ceph.osd_fsid": "aaa-fff-bbbb",
            "ceph.osd_id": "0"
        }
    """
    if not lv_tags:
        return {}
    tag_mapping = {}
    tags = lv_tags.split(',')
    for tag_assignment in tags:
        if not tag_assignment.startswith('ceph.'):
            continue
        key, value = tag_assignment.split('=', 1)
        tag_mapping[key] = value

    return tag_mapping


def _vdo_parents(devices):
    """
    It is possible we didn't get a logical volume, or a mapper path, but
    a device like /dev/sda2, to resolve this, we must look at all the slaves of
    every single device in /sys/block and if any of those devices is related to
    VDO devices, then we can add the parent
    """
    parent_devices = []
    for parent in os.listdir('/sys/block'):
        for slave in os.listdir('/sys/block/%s/slaves' % parent):
            if slave in devices:
                parent_devices.append('/dev/%s' % parent)
                parent_devices.append(parent)
    return parent_devices


def _vdo_slaves(vdo_names):
    """
    find all the slaves associated with each vdo name (from realpath) by going
    into /sys/block/<realpath>/slaves
    """
    devices = []
    for vdo_name in vdo_names:
        mapper_path = '/dev/mapper/%s' % vdo_name
        if not os.path.exists(mapper_path):
            continue
        # resolve the realpath and realname of the vdo mapper
        vdo_realpath = os.path.realpath(mapper_path)
        vdo_realname = vdo_realpath.split('/')[-1]
        slaves_path = '/sys/block/%s/slaves' % vdo_realname
        if not os.path.exists(slaves_path):
            continue
        devices.append(vdo_realpath)
        devices.append(mapper_path)
        devices.append(vdo_realname)
        for slave in os.listdir(slaves_path):
            devices.append('/dev/%s' % slave)
            devices.append(slave)
    return devices


def _is_vdo(path):
    """
    A VDO device can be composed from many different devices, go through each
    one of those devices and its slaves (if any) and correlate them back to
    /dev/mapper and their realpaths, and then check if they appear as part of
    /sys/kvdo/<name>/statistics

    From the realpath of a logical volume, determine if it is a VDO device or
    not, by correlating it to the presence of the name in
    /sys/kvdo/<name>/statistics and all the previously captured devices
    """
    if not os.path.isdir('/sys/kvdo'):
        return False
    realpath = os.path.realpath(path)
    realpath_name = realpath.split('/')[-1]
    devices = []
    vdo_names = set()
    # get all the vdo names
    for dirname in os.listdir('/sys/kvdo/'):
        if os.path.isdir('/sys/kvdo/%s/statistics' % dirname):
            vdo_names.add(dirname)

    # find all the slaves associated with each vdo name (from realpath) by
    # going into /sys/block/<realpath>/slaves
    devices.extend(_vdo_slaves(vdo_names))

    # Find all possible parents, looking into slaves that are related to VDO
    devices.extend(_vdo_parents(devices))

    return any([
        path in devices,
        realpath in devices,
        realpath_name in devices])


def is_vdo(path):
    """
    Detect if a path is backed by VDO, proxying the actual call to _is_vdo so
    that we can prevent an exception breaking OSD creation. If an exception is
    raised, it will get captured and logged to file, while returning
    a ``False``.
    """
    try:
        if _is_vdo(path):
            return '1'
        return '0'
    except Exception:
        logger.exception('Unable to properly detect device as VDO: %s', path)
        return '0'


def dmsetup_splitname(dev):
    """
    Run ``dmsetup splitname`` and parse the results.

    .. warning:: This call does not ensure that the device is correct or that
    it exists. ``dmsetup`` will happily take a non existing path and still
    return a 0 exit status.
    """
    command = [
        'dmsetup', 'splitname', '--noheadings',
        "--separator=';'", '--nameprefixes', dev
    ]
    out, err, rc = process.call(command)
    return _splitname_parser(out)


def is_lv(dev, lvs=None):
    """
    Boolean to detect if a device is an LV or not.
    """
    splitname = dmsetup_splitname(dev)
    # Allowing to optionally pass `lvs` can help reduce repetitive checks for
    # multiple devices at once.
    lvs = lvs if lvs is not None else Volumes()
    if splitname.get('LV_NAME'):
        lvs.filter(lv_name=splitname['LV_NAME'], vg_name=splitname['VG_NAME'])
        return len(lvs) > 0
    return False


def get_api_vgs():
    """
    Return the list of group volumes available in the system using flags to
    include common metadata associated with them

    Command and sample delimited output should look like::

        $ vgs --noheadings --units=g --readonly --separator=';' \
          -o vg_name,pv_count,lv_count,snap_count,vg_attr,vg_size,vg_free
          ubuntubox-vg;1;2;0;wz--n-;299.52g;12.00m
          osd_vg;3;1;0;wz--n-;29.21g;9.21g

    To normalize sizing, the units are forced in 'g' which is equivalent to
    gigabytes, which uses multiples of 1024 (as opposed to 1000)
    """
    fields = 'vg_name,pv_count,lv_count,snap_count,vg_attr,vg_size,vg_free,vg_free_count'
    stdout, stderr, returncode = process.call(
        ['vgs', '--noheadings', '--readonly', '--units=g', '--separator=";"', '-o', fields],
        verbose_on_failure=False
    )
    return _output_parser(stdout, fields)


def get_api_lvs():
    """
    Return the list of logical volumes available in the system using flags to include common
    metadata associated with them

    Command and delimited output should look like::

        $ lvs --noheadings --readonly --separator=';' -o lv_tags,lv_path,lv_name,vg_name
          ;/dev/ubuntubox-vg/root;root;ubuntubox-vg
          ;/dev/ubuntubox-vg/swap_1;swap_1;ubuntubox-vg

    """
    fields = 'lv_tags,lv_path,lv_name,vg_name,lv_uuid,lv_size'
    stdout, stderr, returncode = process.call(
        ['lvs', '--noheadings', '--readonly', '--separator=";"', '-o', fields],
        verbose_on_failure=False
    )
    return _output_parser(stdout, fields)


def get_api_pvs():
    """
    Return the list of physical volumes configured for lvm and available in the
    system using flags to include common metadata associated with them like the uuid

    This will only return physical volumes set up to work with LVM.

    Command and delimited output should look like::

        $ pvs --noheadings --readonly --separator=';' -o pv_name,pv_tags,pv_uuid
          /dev/sda1;;
          /dev/sdv;;07A4F654-4162-4600-8EB3-88D1E42F368D

    """
    fields = 'pv_name,pv_tags,pv_uuid,vg_name,lv_uuid'

    stdout, stderr, returncode = process.call(
        ['pvs', '--no-heading', '--readonly', '--separator=";"', '-o', fields],
        verbose_on_failure=False
    )

    return _output_parser(stdout, fields)


def get_lv_from_argument(argument):
    """
    Helper proxy function that consumes a possible logical volume passed in from the CLI
    in the form of `vg/lv`, but with some validation so that an argument that is a full
    path to a device can be ignored
    """
    if argument.startswith('/'):
        lv = get_lv(lv_path=argument)
        return lv
    try:
        vg_name, lv_name = argument.split('/')
    except (ValueError, AttributeError):
        return None
    return get_lv(lv_name=lv_name, vg_name=vg_name)


def get_lv(lv_name=None, vg_name=None, lv_path=None, lv_uuid=None, lv_tags=None, lvs=None):
    """
    Return a matching lv for the current system, requiring ``lv_name``,
    ``vg_name``, ``lv_path`` or ``tags``. Raises an error if more than one lv
    is found.

    It is useful to use ``tags`` when trying to find a specific logical volume,
    but it can also lead to multiple lvs being found, since a lot of metadata
    is shared between lvs of a distinct OSD.
    """
    if not any([lv_name, vg_name, lv_path, lv_uuid, lv_tags]):
        return None
    if lvs is None:
        lvs = Volumes()
    return lvs.get(
        lv_name=lv_name, vg_name=vg_name, lv_path=lv_path, lv_uuid=lv_uuid,
        lv_tags=lv_tags
    )


def get_pv(pv_name=None, pv_uuid=None, pv_tags=None):
    """
    Return a matching pv (physical volume) for the current system, requiring
    ``pv_name``, ``pv_uuid``, or ``pv_tags``. Raises an error if more than one
    pv is found.
    """
    if not any([pv_name, pv_uuid, pv_tags]):
        return None
    pvs = PVolumes()
    return pvs.get(pv_name=pv_name, pv_uuid=pv_uuid, pv_tags=pv_tags)


def create_pv(device):
    """
    Create a physical volume from a device, useful when devices need to be later mapped
    to journals.
    """
    process.run([
        'pvcreate',
        '-v',  # verbose
        '-f',  # force it
        '--yes', # answer yes to any prompts
        device
    ])


def create_vg(devices, name=None, name_prefix=None):
    """
    Create a Volume Group. Command looks like::

        vgcreate --force --yes group_name device

    Once created the volume group is returned as a ``VolumeGroup`` object

    :param devices: A list of devices to create a VG. Optionally, a single
                    device (as a string) can be used.
    :param name: Optionally set the name of the VG, defaults to 'ceph-{uuid}'
    :param name_prefix: Optionally prefix the name of the VG, which will get combined
                        with a UUID string
    """
    if isinstance(devices, set):
        devices = list(devices)
    if not isinstance(devices, list):
        devices = [devices]
    if name_prefix:
        name = "%s-%s" % (name_prefix, str(uuid.uuid4()))
    elif name is None:
        name = "ceph-%s" % str(uuid.uuid4())
    process.run([
        'vgcreate',
        '--force',
        '--yes',
        name] + devices
    )

    vg = get_vg(vg_name=name)
    return vg


def extend_vg(vg, devices):
    """
    Extend a Volume Group. Command looks like::

        vgextend --force --yes group_name [device, ...]

    Once created the volume group is extended and returned as a ``VolumeGroup`` object

    :param vg: A VolumeGroup object
    :param devices: A list of devices to extend the VG. Optionally, a single
                    device (as a string) can be used.
    """
    if not isinstance(devices, list):
        devices = [devices]
    process.run([
        'vgextend',
        '--force',
        '--yes',
        vg.name] + devices
    )

    vg = get_vg(vg_name=vg.name)
    return vg


def remove_vg(vg_name):
    """
    Removes a volume group.
    """
    if not vg_name:
        logger.warning('Skipping removal of invalid VG name: "%s"', vg_name)
        return
    fail_msg = "Unable to remove vg %s" % vg_name
    process.run(
        [
            'vgremove',
            '-v',  # verbose
            '-f',  # force it
            vg_name
        ],
        fail_msg=fail_msg,
    )


def remove_pv(pv_name):
    """
    Removes a physical volume using a double `-f` to prevent prompts and fully
    remove anything related to LVM. This is tremendously destructive, but so is all other actions
    when zapping a device.

    In the case where multiple PVs are found, it will ignore that fact and
    continue with the removal, specifically in the case of messages like::

        WARNING: PV $UUID /dev/DEV-1 was already found on /dev/DEV-2

    These situations can be avoided with custom filtering rules, which this API
    cannot handle while accommodating custom user filters.
    """
    fail_msg = "Unable to remove vg %s" % pv_name
    process.run(
        [
            'pvremove',
            '-v',  # verbose
            '-f',  # force it
            '-f',  # force it
            pv_name
        ],
        fail_msg=fail_msg,
    )


def remove_lv(lv):
    """
    Removes a logical volume given it's absolute path.

    Will return True if the lv is successfully removed or
    raises a RuntimeError if the removal fails.

    :param lv: A ``Volume`` object or the path for an LV
    """
    if isinstance(lv, Volume):
        path = lv.lv_path
    else:
        path = lv

    stdout, stderr, returncode = process.call(
        [
            'lvremove',
            '-v',  # verbose
            '-f',  # force it
            path
        ],
        show_command=True,
        terminal_verbose=True,
    )
    if returncode != 0:
        raise RuntimeError("Unable to remove %s" % path)
    return True


def create_lv(name, group, extents=None, size=None, tags=None, uuid_name=False):
    """
    Create a Logical Volume in a Volume Group. Command looks like::

        lvcreate -L 50G -n gfslv vg0

    ``name``, ``group``, are required. If ``size`` is provided it must follow
    lvm's size notation (like 1G, or 20M). Tags are an optional dictionary and is expected to
    conform to the convention of prefixing them with "ceph." like::

        {"ceph.block_device": "/dev/ceph/osd-1"}

    :param uuid_name: Optionally combine the ``name`` with UUID to ensure uniqueness
    """
    if uuid_name:
        name = '%s-%s' % (name, uuid.uuid4())
    if tags is None:
        tags = {
            "ceph.osd_id": "null",
            "ceph.type": "null",
            "ceph.cluster_fsid": "null",
            "ceph.osd_fsid": "null",
        }

    # XXX add CEPH_VOLUME_LVM_DEBUG to enable -vvvv on lv operations
    type_path_tag = {
        'journal': 'ceph.journal_device',
        'data': 'ceph.data_device',
        'block': 'ceph.block_device',
        'wal': 'ceph.wal_device',
        'db': 'ceph.db_device',
        'lockbox': 'ceph.lockbox_device',  # XXX might not ever need this lockbox sorcery
    }
    if size:
        process.run([
            'lvcreate',
            '--yes',
            '-L',
            '%s' % size,
            '-n', name, group
        ])
    elif extents:
        process.run([
            'lvcreate',
            '--yes',
            '-l',
            '%s' % extents,
            '-n', name, group
        ])
    # create the lv with all the space available, this is needed because the
    # system call is different for LVM
    else:
        process.run([
            'lvcreate',
            '--yes',
            '-l',
            '100%FREE',
            '-n', name, group
        ])

    lv = get_lv(lv_name=name, vg_name=group)
    lv.set_tags(tags)

    # when creating a distinct type, the caller doesn't know what the path will
    # be so this function will set it after creation using the mapping
    path_tag = type_path_tag.get(tags.get('ceph.type'))
    if path_tag:
        lv.set_tags(
            {path_tag: lv.lv_path}
        )
    return lv


def create_lvs(volume_group, parts=None, size=None, name_prefix='ceph-lv'):
    """
    Create multiple Logical Volumes from a Volume Group by calculating the
    proper extents from ``parts`` or ``size``. A custom prefix can be used
    (defaults to ``ceph-lv``), these names are always suffixed with a uuid.

    LV creation in ceph-volume will require tags, this is expected to be
    pre-computed by callers who know Ceph metadata like OSD IDs and FSIDs. It
    will probably not be the case when mass-creating LVs, so common/default
    tags will be set to ``"null"``.

    .. note:: LVs that are not in use can be detected by querying LVM for tags that are
              set to ``"null"``.

    :param volume_group: The volume group (vg) to use for LV creation
    :type group: ``VolumeGroup()`` object
    :param parts: Number of LVs to create *instead of* ``size``.
    :type parts: int
    :param size: Size (in gigabytes) of LVs to create, e.g. "as many 10gb LVs as possible"
    :type size: int
    :param extents: The number of LVM extents to use to create the LV. Useful if looking to have
    accurate LV sizes (LVM rounds sizes otherwise)
    """
    if parts is None and size is None:
        # fallback to just one part (using 100% of the vg)
        parts = 1
    lvs = []
    tags = {
        "ceph.osd_id": "null",
        "ceph.type": "null",
        "ceph.cluster_fsid": "null",
        "ceph.osd_fsid": "null",
    }
    sizing = volume_group.sizing(parts=parts, size=size)
    for part in range(0, sizing['parts']):
        size = sizing['sizes']
        extents = sizing['extents']
        lv_name = '%s-%s' % (name_prefix, uuid.uuid4())
        lvs.append(
            create_lv(lv_name, volume_group.name, extents=extents, tags=tags)
        )
    return lvs


def get_vg(vg_name=None, vg_tags=None):
    """
    Return a matching vg for the current system, requires ``vg_name`` or
    ``tags``. Raises an error if more than one vg is found.

    It is useful to use ``tags`` when trying to find a specific volume group,
    but it can also lead to multiple vgs being found.
    """
    if not any([vg_name, vg_tags]):
        return None
    vgs = VolumeGroups()
    return vgs.get(vg_name=vg_name, vg_tags=vg_tags)


class VolumeGroups(list):
    """
    A list of all known volume groups for the current system, with the ability
    to filter them via keyword arguments.
    """

    def __init__(self):
        self._populate()

    def _populate(self):
        # get all the vgs in the current system
        for vg_item in get_api_vgs():
            self.append(VolumeGroup(**vg_item))

    def _purge(self):
        """
        Deplete all the items in the list, used internally only so that we can
        dynamically allocate the items when filtering without the concern of
        messing up the contents
        """
        self[:] = []

    def _filter(self, vg_name=None, vg_tags=None):
        """
        The actual method that filters using a new list. Useful so that other
        methods that do not want to alter the contents of the list (e.g.
        ``self.find``) can operate safely.

        .. note:: ``vg_tags`` is not yet implemented
        """
        filtered = [i for i in self]
        if vg_name:
            filtered = [i for i in filtered if i.vg_name == vg_name]

        # at this point, `filtered` has either all the volumes in self or is an
        # actual filtered list if any filters were applied
        if vg_tags:
            tag_filtered = []
            for volume in filtered:
                matches = all(volume.tags.get(k) == str(v) for k, v in vg_tags.items())
                if matches:
                    tag_filtered.append(volume)
            return tag_filtered

        return filtered

    def filter(self, vg_name=None, vg_tags=None):
        """
        Filter out groups on top level attributes like ``vg_name`` or by
        ``vg_tags`` where a dict is required. For example, to find a Ceph group
        with dmcache as the type, the filter would look like::

            vg_tags={'ceph.type': 'dmcache'}

        .. warning:: These tags are not documented because they are currently
                     unused, but are here to maintain API consistency
        """
        if not any([vg_name, vg_tags]):
            raise TypeError('.filter() requires vg_name or vg_tags (none given)')
        # first find the filtered volumes with the values in self
        filtered_groups = self._filter(
            vg_name=vg_name,
            vg_tags=vg_tags
        )
        # then purge everything
        self._purge()
        # and add the filtered items
        self.extend(filtered_groups)

    def get(self, vg_name=None, vg_tags=None):
        """
        This is a bit expensive, since it will try to filter out all the
        matching items in the list, filter them out applying anything that was
        added and return the matching item.

        This method does *not* alter the list, and it will raise an error if
        multiple VGs are matched

        It is useful to use ``tags`` when trying to find a specific volume group,
        but it can also lead to multiple vgs being found (although unlikely)
        """
        if not any([vg_name, vg_tags]):
            return None
        vgs = self._filter(
            vg_name=vg_name,
            vg_tags=vg_tags
        )
        if not vgs:
            return None
        if len(vgs) > 1:
            # this is probably never going to happen, but it is here to keep
            # the API code consistent
            raise MultipleVGsError(vg_name)
        return vgs[0]


class Volumes(list):
    """
    A list of all known (logical) volumes for the current system, with the ability
    to filter them via keyword arguments.
    """

    def __init__(self):
        self._populate()

    def _populate(self):
        # get all the lvs in the current system
        for lv_item in get_api_lvs():
            self.append(Volume(**lv_item))

    def _purge(self):
        """
        Delete all the items in the list, used internally only so that we can
        dynamically allocate the items when filtering without the concern of
        messing up the contents
        """
        self[:] = []

    def _filter(self, lv_name=None, vg_name=None, lv_path=None, lv_uuid=None, lv_tags=None):
        """
        The actual method that filters using a new list. Useful so that other
        methods that do not want to alter the contents of the list (e.g.
        ``self.find``) can operate safely.
        """
        filtered = [i for i in self]
        if lv_name:
            filtered = [i for i in filtered if i.lv_name == lv_name]

        if vg_name:
            filtered = [i for i in filtered if i.vg_name == vg_name]

        if lv_uuid:
            filtered = [i for i in filtered if i.lv_uuid == lv_uuid]

        if lv_path:
            filtered = [i for i in filtered if i.lv_path == lv_path]

        # at this point, `filtered` has either all the volumes in self or is an
        # actual filtered list if any filters were applied
        if lv_tags:
            tag_filtered = []
            for volume in filtered:
                # all the tags we got need to match on the volume
                matches = all(volume.tags.get(k) == str(v) for k, v in lv_tags.items())
                if matches:
                    tag_filtered.append(volume)
            return tag_filtered

        return filtered

    def filter(self, lv_name=None, vg_name=None, lv_path=None, lv_uuid=None, lv_tags=None):
        """
        Filter out volumes on top level attributes like ``lv_name`` or by
        ``lv_tags`` where a dict is required. For example, to find a volume
        that has an OSD ID of 0, the filter would look like::

            lv_tags={'ceph.osd_id': '0'}

        """
        if not any([lv_name, vg_name, lv_path, lv_uuid, lv_tags]):
            raise TypeError('.filter() requires lv_name, vg_name, lv_path, lv_uuid, or tags (none given)')
        # first find the filtered volumes with the values in self
        filtered_volumes = self._filter(
            lv_name=lv_name,
            vg_name=vg_name,
            lv_path=lv_path,
            lv_uuid=lv_uuid,
            lv_tags=lv_tags
        )
        # then purge everything
        self._purge()
        # and add the filtered items
        self.extend(filtered_volumes)

    def get(self, lv_name=None, vg_name=None, lv_path=None, lv_uuid=None, lv_tags=None):
        """
        This is a bit expensive, since it will try to filter out all the
        matching items in the list, filter them out applying anything that was
        added and return the matching item.

        This method does *not* alter the list, and it will raise an error if
        multiple LVs are matched

        It is useful to use ``tags`` when trying to find a specific logical volume,
        but it can also lead to multiple lvs being found, since a lot of metadata
        is shared between lvs of a distinct OSD.
        """
        if not any([lv_name, vg_name, lv_path, lv_uuid, lv_tags]):
            return None
        lvs = self._filter(
            lv_name=lv_name,
            vg_name=vg_name,
            lv_path=lv_path,
            lv_uuid=lv_uuid,
            lv_tags=lv_tags
        )
        if not lvs:
            return None
        if len(lvs) > 1:
            raise MultipleLVsError(lv_name, lv_path)
        return lvs[0]


class PVolumes(list):
    """
    A list of all known (physical) volumes for the current system, with the ability
    to filter them via keyword arguments.
    """

    def __init__(self):
        self._populate()

    def _populate(self):
        # get all the pvs in the current system
        for pv_item in get_api_pvs():
            self.append(PVolume(**pv_item))

    def _purge(self):
        """
        Deplete all the items in the list, used internally only so that we can
        dynamically allocate the items when filtering without the concern of
        messing up the contents
        """
        self[:] = []

    def _filter(self, pv_name=None, pv_uuid=None, pv_tags=None):
        """
        The actual method that filters using a new list. Useful so that other
        methods that do not want to alter the contents of the list (e.g.
        ``self.find``) can operate safely.
        """
        filtered = [i for i in self]
        if pv_name:
            filtered = [i for i in filtered if i.pv_name == pv_name]

        if pv_uuid:
            filtered = [i for i in filtered if i.pv_uuid == pv_uuid]

        # at this point, `filtered` has either all the physical volumes in self
        # or is an actual filtered list if any filters were applied
        if pv_tags:
            tag_filtered = []
            for pvolume in filtered:
                matches = all(pvolume.tags.get(k) == str(v) for k, v in pv_tags.items())
                if matches:
                    tag_filtered.append(pvolume)
            # return the tag_filtered pvolumes here, the `filtered` list is no
            # longer useable
            return tag_filtered

        return filtered

    def filter(self, pv_name=None, pv_uuid=None, pv_tags=None):
        """
        Filter out volumes on top level attributes like ``pv_name`` or by
        ``pv_tags`` where a dict is required. For example, to find a physical volume
        that has an OSD ID of 0, the filter would look like::

            pv_tags={'ceph.osd_id': '0'}

        """
        if not any([pv_name, pv_uuid, pv_tags]):
            raise TypeError('.filter() requires pv_name, pv_uuid, or pv_tags (none given)')
        # first find the filtered volumes with the values in self
        filtered_volumes = self._filter(
            pv_name=pv_name,
            pv_uuid=pv_uuid,
            pv_tags=pv_tags
        )
        # then purge everything
        self._purge()
        # and add the filtered items
        self.extend(filtered_volumes)

    def get(self, pv_name=None, pv_uuid=None, pv_tags=None):
        """
        This is a bit expensive, since it will try to filter out all the
        matching items in the list, filter them out applying anything that was
        added and return the matching item.

        This method does *not* alter the list, and it will raise an error if
        multiple pvs are matched

        It is useful to use ``tags`` when trying to find a specific logical volume,
        but it can also lead to multiple pvs being found, since a lot of metadata
        is shared between pvs of a distinct OSD.
        """
        if not any([pv_name, pv_uuid, pv_tags]):
            return None
        pvs = self._filter(
            pv_name=pv_name,
            pv_uuid=pv_uuid,
            pv_tags=pv_tags
        )
        if not pvs:
            return None
        if len(pvs) > 1 and pv_tags:
            raise MultiplePVsError(pv_name)
        return pvs[0]


class VolumeGroup(object):
    """
    Represents an LVM group, with some top-level attributes like ``vg_name``
    """

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)
        self.name = kw['vg_name']
        self.tags = parse_tags(kw.get('vg_tags', ''))

    def __str__(self):
        return '<%s>' % self.name

    def __repr__(self):
        return self.__str__()

    def _parse_size(self, size):
        error_msg = "Unable to convert vg size to integer: '%s'" % str(size)
        try:
            integer, _ = size.split('g')
        except ValueError:
            logger.exception(error_msg)
            raise RuntimeError(error_msg)

        return util.str_to_int(integer)

    @property
    def free(self):
        """
        Parse the available size in gigabytes from the ``vg_free`` attribute, that
        will be a string with a character ('g') to indicate gigabytes in size.
        Returns a rounded down integer to ease internal operations::

        >>> data_vg.vg_free
        '0.01g'
        >>> data_vg.size
        0
        """
        return self._parse_size(self.vg_free)

    @property
    def size(self):
        """
        Parse the size in gigabytes from the ``vg_size`` attribute, that
        will be a string with a character ('g') to indicate gigabytes in size.
        Returns a rounded down integer to ease internal operations::

        >>> data_vg.vg_size
        '1024.9g'
        >>> data_vg.size
        1024
        """
        return self._parse_size(self.vg_size)

    def sizing(self, parts=None, size=None):
        """
        Calculate proper sizing to fully utilize the volume group in the most
        efficient way possible. To prevent situations where LVM might accept
        a percentage that is beyond the vg's capabilities, it will refuse with
        an error when requesting a larger-than-possible parameter, in addition
        to rounding down calculations.

        A dictionary with different sizing parameters is returned, to make it
        easier for others to choose what they need in order to create logical
        volumes::

        >>> data_vg.free
        1024
        >>> data_vg.sizing(parts=4)
        {'parts': 4, 'sizes': 256, 'percentages': 25}
        >>> data_vg.sizing(size=512)
        {'parts': 2, 'sizes': 512, 'percentages': 50}


        :param parts: Number of parts to create LVs from
        :param size: Size in gigabytes to divide the VG into

        :raises SizeAllocationError: When requested size cannot be allocated with
        :raises ValueError: If both ``parts`` and ``size`` are given
        """
        if parts is not None and size is not None:
            raise ValueError(
                "Cannot process sizing with both parts (%s) and size (%s)" % (parts, size)
            )

        # if size is given we need to map that to extents so that we avoid
        # issues when trying to get this right with a size in gigabytes find
        # the percentage first, cheating, because these values are thrown out
        vg_free_count = util.str_to_int(self.vg_free_count)

        if size:
            extents = int(size * vg_free_count / self.free)
            disk_sizing = sizing(self.free, size=size, parts=parts)
        else:
            if parts is not None:
                # Prevent parts being 0, falling back to 1 (100% usage)
                parts = parts or 1
            size = int(self.free / parts)
            extents = size * vg_free_count / self.free
            disk_sizing = sizing(self.free, parts=parts)

        extent_sizing = sizing(vg_free_count, size=extents)

        disk_sizing['extents'] = int(extents)
        disk_sizing['percentages'] = extent_sizing['percentages']
        return disk_sizing


class Volume(object):
    """
    Represents a Logical Volume from LVM, with some top-level attributes like
    ``lv_name`` and parsed tags as a dictionary of key/value pairs.
    """

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)
        self.lv_api = kw
        self.name = kw['lv_name']
        self.tags = parse_tags(kw['lv_tags'])
        self.encrypted = self.tags.get('ceph.encrypted', '0') == '1'
        self.used_by_ceph = 'ceph.osd_id' in self.tags

    def __str__(self):
        return '<%s>' % self.lv_api['lv_path']

    def __repr__(self):
        return self.__str__()

    def as_dict(self):
        obj = {}
        obj.update(self.lv_api)
        obj['tags'] = self.tags
        obj['name'] = self.name
        obj['type'] = self.tags['ceph.type']
        obj['path'] = self.lv_path
        return obj

    def report(self):
        if not self.used_by_ceph:
            return {
                'name': self.lv_name,
                'comment': 'not used by ceph'
            }
        else:
            type_ = self.tags['ceph.type']
            report = {
                'name': self.lv_name,
                'osd_id': self.tags['ceph.osd_id'],
                'cluster_name': self.tags['ceph.cluster_name'],
                'type': type_,
                'osd_fsid': self.tags['ceph.osd_fsid'],
                'cluster_fsid': self.tags['ceph.cluster_fsid'],
            }
            type_uuid = '{}_uuid'.format(type_)
            report[type_uuid] = self.tags['ceph.{}'.format(type_uuid)]
            return report

    def clear_tags(self):
        """
        Removes all tags from the Logical Volume.
        """
        for k, v in self.tags.items():
            tag = "%s=%s" % (k, v)
            process.run(['lvchange', '--deltag', tag, self.lv_path])

    def set_tags(self, tags):
        """
        :param tags: A dictionary of tag names and values, like::

            {
                "ceph.osd_fsid": "aaa-fff-bbbb",
                "ceph.osd_id": "0"
            }

        At the end of all modifications, the tags are refreshed to reflect
        LVM's most current view.
        """
        for k, v in tags.items():
            self.set_tag(k, v)
        # after setting all the tags, refresh them for the current object, use the
        # lv_* identifiers to filter because those shouldn't change
        lv_object = get_lv(lv_name=self.lv_name, lv_path=self.lv_path)
        self.tags = lv_object.tags

    def set_tag(self, key, value):
        """
        Set the key/value pair as an LVM tag. Does not "refresh" the values of
        the current object for its tags. Meant to be a "fire and forget" type
        of modification.
        """
        # remove it first if it exists
        if self.tags.get(key):
            current_value = self.tags[key]
            tag = "%s=%s" % (key, current_value)
            process.call(['lvchange', '--deltag', tag, self.lv_api['lv_path']])

        process.call(
            [
                'lvchange',
                '--addtag', '%s=%s' % (key, value), self.lv_path
            ]
        )


class PVolume(object):
    """
    Represents a Physical Volume from LVM, with some top-level attributes like
    ``pv_name`` and parsed tags as a dictionary of key/value pairs.
    """

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)
        self.pv_api = kw
        self.name = kw['pv_name']
        self.tags = parse_tags(kw['pv_tags'])

    def __str__(self):
        return '<%s>' % self.pv_api['pv_name']

    def __repr__(self):
        return self.__str__()

    def set_tags(self, tags):
        """
        :param tags: A dictionary of tag names and values, like::

            {
                "ceph.osd_fsid": "aaa-fff-bbbb",
                "ceph.osd_id": "0"
            }

        At the end of all modifications, the tags are refreshed to reflect
        LVM's most current view.
        """
        for k, v in tags.items():
            self.set_tag(k, v)
        # after setting all the tags, refresh them for the current object, use the
        # pv_* identifiers to filter because those shouldn't change
        pv_object = get_pv(pv_name=self.pv_name, pv_uuid=self.pv_uuid)
        self.tags = pv_object.tags

    def set_tag(self, key, value):
        """
        Set the key/value pair as an LVM tag. Does not "refresh" the values of
        the current object for its tags. Meant to be a "fire and forget" type
        of modification.

        **warning**: Altering tags on a PV has to be done ensuring that the
        device is actually the one intended. ``pv_name`` is *not* a persistent
        value, only ``pv_uuid`` is. Using ``pv_uuid`` is the best way to make
        sure the device getting changed is the one needed.
        """
        # remove it first if it exists
        if self.tags.get(key):
            current_value = self.tags[key]
            tag = "%s=%s" % (key, current_value)
            process.call(['pvchange', '--deltag', tag, self.pv_name])

        process.call(
            [
                'pvchange',
                '--addtag', '%s=%s' % (key, value), self.pv_name
            ]
        )
