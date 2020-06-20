import os
import pytest
from ceph_volume.api import lvm as api
from ceph_volume.devices.lvm import zap


class TestFindAssociatedDevices(object):

    def test_no_lvs_found_that_match_id(self, volumes, monkeypatch, device_info):
        monkeypatch.setattr(zap.api, 'Volumes', lambda: volumes)
        tags = 'ceph.osd_id=9,ceph.journal_uuid=x,ceph.type=data'
        osd = api.Volume(
            lv_name='volume1', lv_uuid='y', lv_path='/dev/VolGroup/lv', vg_name='vg', lv_tags=tags)
        volumes.append(osd)
        with pytest.raises(RuntimeError):
            zap.find_associated_devices(osd_id=10)

    def test_no_lvs_found_that_match_fsid(self, volumes, monkeypatch, device_info):
        monkeypatch.setattr(zap.api, 'Volumes', lambda: volumes)
        tags = 'ceph.osd_id=9,ceph.osd_fsid=asdf-lkjh,ceph.journal_uuid=x,ceph.type=data'
        osd = api.Volume(
            lv_name='volume1', lv_uuid='y', lv_path='/dev/VolGroup/lv', vg_name='vg', lv_tags=tags)
        volumes.append(osd)
        with pytest.raises(RuntimeError):
            zap.find_associated_devices(osd_fsid='aaaa-lkjh')

    def test_no_lvs_found_that_match_id_fsid(self, volumes, monkeypatch, device_info):
        monkeypatch.setattr(zap.api, 'Volumes', lambda: volumes)
        tags = 'ceph.osd_id=9,ceph.osd_fsid=asdf-lkjh,ceph.journal_uuid=x,ceph.type=data'
        osd = api.Volume(
            lv_name='volume1', lv_uuid='y', lv_path='/dev/VolGroup/lv', vg_name='vg', lv_tags=tags)
        volumes.append(osd)
        with pytest.raises(RuntimeError):
            zap.find_associated_devices(osd_id='9', osd_fsid='aaaa-lkjh')

    def test_no_ceph_lvs_found(self, volumes, monkeypatch):
        monkeypatch.setattr(zap.api, 'Volumes', lambda: volumes)
        osd = api.Volume(
            lv_name='volume1', lv_uuid='y', lv_path='/dev/VolGroup/lv', lv_tags='')
        volumes.append(osd)
        with pytest.raises(RuntimeError):
            zap.find_associated_devices(osd_id=100)

    def test_lv_is_matched_id(self, volumes, monkeypatch):
        monkeypatch.setattr(zap.api, 'Volumes', lambda: volumes)
        tags = 'ceph.osd_id=0,ceph.journal_uuid=x,ceph.type=data'
        osd = api.Volume(
            lv_name='volume1', lv_uuid='y', vg_name='', lv_path='/dev/VolGroup/lv', lv_tags=tags)
        volumes.append(osd)
        result = zap.find_associated_devices(osd_id='0')
        assert result[0].abspath == '/dev/VolGroup/lv'

    def test_lv_is_matched_fsid(self, volumes, monkeypatch):
        monkeypatch.setattr(zap.api, 'Volumes', lambda: volumes)
        tags = 'ceph.osd_id=0,ceph.osd_fsid=asdf-lkjh,ceph.journal_uuid=x,ceph.type=data'
        osd = api.Volume(
            lv_name='volume1', lv_uuid='y', vg_name='', lv_path='/dev/VolGroup/lv', lv_tags=tags)
        volumes.append(osd)
        result = zap.find_associated_devices(osd_fsid='asdf-lkjh')
        assert result[0].abspath == '/dev/VolGroup/lv'

    def test_lv_is_matched_id_fsid(self, volumes, monkeypatch):
        monkeypatch.setattr(zap.api, 'Volumes', lambda: volumes)
        tags = 'ceph.osd_id=0,ceph.osd_fsid=asdf-lkjh,ceph.journal_uuid=x,ceph.type=data'
        osd = api.Volume(
            lv_name='volume1', lv_uuid='y', vg_name='', lv_path='/dev/VolGroup/lv', lv_tags=tags)
        volumes.append(osd)
        result = zap.find_associated_devices(osd_id='0', osd_fsid='asdf-lkjh')
        assert result[0].abspath == '/dev/VolGroup/lv'


class TestEnsureAssociatedLVs(object):

    def test_nothing_is_found(self, volumes):
        result = zap.ensure_associated_lvs(volumes)
        assert result == []

    def test_data_is_found(self, volumes):
        tags = 'ceph.osd_id=0,ceph.osd_fsid=asdf-lkjh,ceph.journal_uuid=x,ceph.type=data'
        osd = api.Volume(
            lv_name='volume1', lv_uuid='y', vg_name='', lv_path='/dev/VolGroup/data', lv_tags=tags)
        volumes.append(osd)
        result = zap.ensure_associated_lvs(volumes)
        assert result == ['/dev/VolGroup/data']

    def test_block_is_found(self, volumes):
        tags = 'ceph.osd_id=0,ceph.osd_fsid=asdf-lkjh,ceph.journal_uuid=x,ceph.type=block'
        osd = api.Volume(
            lv_name='volume1', lv_uuid='y', vg_name='', lv_path='/dev/VolGroup/block', lv_tags=tags)
        volumes.append(osd)
        result = zap.ensure_associated_lvs(volumes)
        assert result == ['/dev/VolGroup/block']

    def test_success_message_for_fsid(self, factory, is_root, capsys):
        cli_zap = zap.Zap([])
        args = factory(devices=[], osd_id=None, osd_fsid='asdf-lkjh')
        cli_zap.args = args
        cli_zap.zap()
        out, err = capsys.readouterr()
        assert "Zapping successful for OSD: asdf-lkjh" in err

    def test_success_message_for_id(self, factory, is_root, capsys):
        cli_zap = zap.Zap([])
        args = factory(devices=[], osd_id='1', osd_fsid=None)
        cli_zap.args = args
        cli_zap.zap()
        out, err = capsys.readouterr()
        assert "Zapping successful for OSD: 1" in err

    def test_block_and_partition_are_found(self, volumes, monkeypatch):
        monkeypatch.setattr(zap.disk, 'get_device_from_partuuid', lambda x: '/dev/sdb1')
        tags = 'ceph.osd_id=0,ceph.osd_fsid=asdf-lkjh,ceph.journal_uuid=x,ceph.type=block'
        osd = api.Volume(
            lv_name='volume1', lv_uuid='y', vg_name='', lv_path='/dev/VolGroup/block', lv_tags=tags)
        volumes.append(osd)
        result = zap.ensure_associated_lvs(volumes)
        assert '/dev/sdb1' in result
        assert '/dev/VolGroup/block' in result

    def test_journal_is_found(self, volumes):
        tags = 'ceph.osd_id=0,ceph.osd_fsid=asdf-lkjh,ceph.journal_uuid=x,ceph.type=journal'
        osd = api.Volume(
            lv_name='volume1', lv_uuid='y', vg_name='', lv_path='/dev/VolGroup/lv', lv_tags=tags)
        volumes.append(osd)
        result = zap.ensure_associated_lvs(volumes)
        assert result == ['/dev/VolGroup/lv']

    def test_multiple_journals_are_found(self, volumes):
        tags = 'ceph.osd_id=0,ceph.osd_fsid=asdf-lkjh,ceph.journal_uuid=x,ceph.type=journal'
        for i in range(3):
            osd = api.Volume(
                lv_name='volume%s' % i, lv_uuid='y', vg_name='', lv_path='/dev/VolGroup/lv%s' % i, lv_tags=tags)
            volumes.append(osd)
        result = zap.ensure_associated_lvs(volumes)
        assert '/dev/VolGroup/lv0' in result
        assert '/dev/VolGroup/lv1' in result
        assert '/dev/VolGroup/lv2' in result

    def test_multiple_dbs_are_found(self, volumes):
        tags = 'ceph.osd_id=0,ceph.osd_fsid=asdf-lkjh,ceph.journal_uuid=x,ceph.type=db'
        for i in range(3):
            osd = api.Volume(
                lv_name='volume%s' % i, lv_uuid='y', vg_name='', lv_path='/dev/VolGroup/lv%s' % i, lv_tags=tags)
            volumes.append(osd)
        result = zap.ensure_associated_lvs(volumes)
        assert '/dev/VolGroup/lv0' in result
        assert '/dev/VolGroup/lv1' in result
        assert '/dev/VolGroup/lv2' in result

    def test_multiple_wals_are_found(self, volumes):
        tags = 'ceph.osd_id=0,ceph.osd_fsid=asdf-lkjh,ceph.wal_uuid=x,ceph.type=wal'
        for i in range(3):
            osd = api.Volume(
                lv_name='volume%s' % i, lv_uuid='y', vg_name='', lv_path='/dev/VolGroup/lv%s' % i, lv_tags=tags)
            volumes.append(osd)
        result = zap.ensure_associated_lvs(volumes)
        assert '/dev/VolGroup/lv0' in result
        assert '/dev/VolGroup/lv1' in result
        assert '/dev/VolGroup/lv2' in result

    def test_multiple_backing_devs_are_found(self, volumes):
        for _type in ['journal', 'db', 'wal']:
            tags = 'ceph.osd_id=0,ceph.osd_fsid=asdf-lkjh,ceph.wal_uuid=x,ceph.type=%s' % _type
            osd = api.Volume(
                lv_name='volume%s' % _type, lv_uuid='y', vg_name='', lv_path='/dev/VolGroup/lv%s' % _type, lv_tags=tags)
            volumes.append(osd)
        result = zap.ensure_associated_lvs(volumes)
        assert '/dev/VolGroup/lvjournal' in result
        assert '/dev/VolGroup/lvwal' in result
        assert '/dev/VolGroup/lvdb' in result


class TestWipeFs(object):

    def setup(self):
        os.environ['CEPH_VOLUME_WIPEFS_INTERVAL'] = '0'

    def test_works_on_second_try(self, stub_call):
        os.environ['CEPH_VOLUME_WIPEFS_TRIES'] = '2'
        stub_call([('wiping /dev/sda', '', 1), ('', '', 0)])
        result = zap.wipefs('/dev/sda')
        assert result is None

    def test_does_not_work_after_several_tries(self, stub_call):
        os.environ['CEPH_VOLUME_WIPEFS_TRIES'] = '2'
        stub_call([('wiping /dev/sda', '', 1), ('', '', 1)])
        with pytest.raises(RuntimeError):
            zap.wipefs('/dev/sda')

    def test_does_not_work_default_tries(self, stub_call):
        stub_call([('wiping /dev/sda', '', 1)]*8)
        with pytest.raises(RuntimeError):
            zap.wipefs('/dev/sda')
