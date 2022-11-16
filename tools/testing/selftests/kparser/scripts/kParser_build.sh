#!/usr/bin/bash
screen -x kernel_compile 
#git config --global credential.helper 'cache --timeout=3600'
USERNAME=
TOKEN=
rndStr=`env date --date 'now ' +'%Y-%m-%d_%H%M%S'`
KERNDIR=${LINUX_NET_NEXT}
IPROUTE2_DIR=${IPROUTE2_PATH}
LIBBPFDIR=~/tmpbpf/libbpf_${rndStr}
REPO=https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git
LNN_REPO=https://$USERNAME:$TOKEN@github.com/SiPandaInc/linux-net-next.git
IPROUTE2_REPO=https://$USERNAME:$TOKEN@github.com/SiPandaInc/iproute2.git
LNN_BRANCH="kparser-dev"
IPROUTE2_BRANCH="kParser-dev"

export PKG_CONFIG_PATH=${KERNDIR}/tools/lib/bpf

function pre_install()
{
	sudo DEBIAN_FRONTEND=noninteractive apt-get -y install build-essential \
		binutils-dev			\
		build-essential 		\
		libreadline-dev clang		\
		uuid-dev			\
	libncurses-dev 				\
	net-tools				\
	bison					\
	flex					\
	libssl-dev 				\
	libelf-dev 				\
	bc 					\
	pahole 					\
	dwarves					\
	git         				\
	pkg-config				\
	libmnl-dev				\
	screen					\
	iperf					\
	iperf3					\
	llvm

}

function clone_iproute2()
{
	if [ -d "$IPROUTE2_DIR" ]; then
 		 echo "$IPROUTE2_DIR does exist."
		 cd $IPROUTE2_DIR
		 git fetch 
	else 
		mkdir -p $IPROUTE2_DIR
		cd $IPROUTE2_DIR
		git clone $IPROUTE_REPO

	fi

	git switch $IPROUTE2_BRANCH
}
function clone_lnn()
{
	if [ -d "$KERNDIR" ]; then
 		 echo "$KERNDIR does exist."
		 cd $KERNDIR
		 git fetch 
	else 
		mkdir -p $KERNDIR
		cd $KERNDIR
		git clone $LNN_REPO

	fi

	git switch $LNN_BRANCH
}

function perform_step() 
{
	echo " Performing $1 in $PWD "

	$@

	retval=$?
	if [[ $retval -eq 0 ]]; then
		  echo " COMMAND : $@ -> Ok "
	else
		    echo " COMMAND : $@ -> Failure "
		    exit $retval
	fi

}


function compile_kernel() 
{

	perform_step cd ${KERNDIR}/
	perform_step make -j4
	perform_step make modules_install
	perform_step make INSTALL_HDR_PATH=/usr headers_install
	perform_step make install
	

}
function compile_libbpf() 
{
	perform_step cd ${KERNDIR}/tools/lib/bpf
	#perform_step make clean 
	perform_step make DESTDIR=${LIBBPFDIR} install  

	perform_step mv ${LIBBPFDIR}/usr/local/include ${LIBBPFDIR}/usr/
	perform_step mv ${LIBBPFDIR}/usr/local/lib64 ${LIBBPFDIR}/usr/

}

function compile_iproute2() 
{
	perform_step cd $IPROUTE2_DIR
	perform_step make clean
	perform_step ./configure --libbpf_dir ${LIBBPFDIR}
	perform_step make
}

function compile_bpftool() 
{
	
	perform_step cd ${KERNDIR}/tools/bpf
	#perform_step make clean
	perform_step make

}

function compile_xdp() 
{
	
	perform_step cd ${KERNDIR}/samples/bpf
	perform_step make clean
	perform_step make MDATA=2
}

function compile_kparser()
{
	perform_step cd ${KERNDIR}
	perform_step make M=net/kparser clean
	perform_step make M=net/kparser 

}


#pre_install
#clone_linux_net_next
#compile_kernel
#exit 0
#reboot
compile_libbpf
compile_iproute2
compile_bpftool
compile_kparser
compile_xdp
