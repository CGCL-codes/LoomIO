# LoomIO: object-level coordination for object file systems

LoomIO is currently implemented with Redis and integrated in Ceph. Thus, you should prepare Redis and Ceph first to test and use LoomIO.
The branch Redis3 is under maintaining.

## Build Prerequisites

The list of Debian or RPM packages dependencies can be installed with:

	./install-deps.sh


## Building Ceph

Note that these instructions are meant for developers who are
compiling the code for development and testing.  To build binaries
suitable for installation we recommend you build deb or rpm packages,
or refer to the `ceph.spec.in` or `debian/rules` to see which
configuration options are specified for production builds.

Prerequisite: CMake 2.8.11

Build instructions:

	./do_cmake.sh
	cd build
	make

This assumes you make your build dir a subdirectory of the ceph.git
checkout. If you put it elsewhere, just replace `..` in do_cmake.sh with a
correct path to the checkout.

To build only certain targets use:

        make [target name]

To install:

        make install
 
## Enable LoomIO

After successfully installed, you can enable LoomIO with 
	
	ceph tell osd.* injectargs '--osd_gio 1' #0 means off
Besides, you can tune the coordination window size with	
	
	ceph tell osd.* injectargs '--osd_gio_wait_interval xxxx'



Publications：

Yusheng Hua, Xuanhua Shi, Kang He, Hai Jin, Wei Xie, Ligang He, Yong Chen，"LoomIO: Object-Level Coordination in Distributed File Systems", IEEE Transactions on Parallel and Distributed Systems, 33(8): 1799-1810, 2022
