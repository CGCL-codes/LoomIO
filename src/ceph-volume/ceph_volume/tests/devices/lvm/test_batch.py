from ceph_volume.devices.lvm import batch


class TestBatchSmoke(object):

    def test_batch_instance(self, is_root):
        b = batch.Batch([])
        b.main()


class TestFilterDevices(object):

    def test_filter_used_device(self, factory):
        device1 = factory(used_by_ceph=True, abspath="/dev/sda")
        args = factory(devices=[device1], filtered_devices={})
        result = batch.filter_devices(args)
        assert not result
        assert device1.abspath in args.filtered_devices

    def test_has_unused_devices(self, factory):
        device1 = factory(
            used_by_ceph=False,
            abspath="/dev/sda",
            rotational=False,
            is_lvm_member=False
        )
        args = factory(devices=[device1], filtered_devices={})
        result = batch.filter_devices(args)
        assert device1 in result
        assert not args.filtered_devices

    def test_filter_device_used_as_a_journal(self, factory):
        hdd1 = factory(
            used_by_ceph=True,
            abspath="/dev/sda",
            rotational=True,
            is_lvm_member=True,
        )
        lv = factory(tags={"ceph.type": "journal"})
        ssd1 = factory(
            used_by_ceph=False,
            abspath="/dev/nvme0n1",
            rotational=False,
            is_lvm_member=True,
            lvs=[lv],
        )
        args = factory(devices=[hdd1, ssd1], filtered_devices={})
        result = batch.filter_devices(args)
        assert not result
        assert ssd1.abspath in args.filtered_devices

    def test_last_device_is_not_filtered(self, factory):
        hdd1 = factory(
            used_by_ceph=True,
            abspath="/dev/sda",
            rotational=True,
            is_lvm_member=True,
        )
        ssd1 = factory(
            used_by_ceph=False,
            abspath="/dev/nvme0n1",
            rotational=False,
            is_lvm_member=False,
        )
        args = factory(devices=[hdd1, ssd1], filtered_devices={})
        result = batch.filter_devices(args)
        assert result
        assert len(args.filtered_devices) == 1
