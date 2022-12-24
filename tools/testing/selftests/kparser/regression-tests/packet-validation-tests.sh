#!/bin/bash

lnn_path="/root/repos/linux-net-next/"
iproute2_path="/root/repos/iproute2-next/"

echo_info() {
	echo "INFO: $@"
}

echo_warn() {
	echo "WARN: $@"
}

echo_err() {
	echo "ERROR: $@"
}

die() {
	echo_err $@
	echo_err "This test is stopping!"
	exit -1
}


usage() {
	die "Usage: $0 -i 'ip repo path' -l 'linux repo path' \
	-t 'single custom test config json file'"
}

while getopts ":i:l:t:" o; do
	case "${o}" in
		l) lnn_path="$OPTARG"
		;;
		i) iproute2_path="$OPTARG"
		;;
		t) single_test="$OPTARG"
		;;
		*)
		usage
		;;
	esac
done
shift $((OPTIND-1))

# if [ ! -z "$2" -o ! -z "${IPROUTE2_PATH}" ]; then

if [ ! -z "${LINUX_NET_NEXT}" ]; then
	lnn_path=${LINUX_NET_NEXT}
fi

if [ ! -z "${IPROUTE2_PATH}" ]; then
	iproute2_path=${IPROUTE2_PATH}
fi

echo_info "Using linux repo path: $lnn_path, iproute2 repo path: $iproute2_path"

if [ ! -d "$lnn_path" ]; then
  die "$lnn_path does not exist."
fi

if [ ! -d "$iproute2_path" ]; then
  die "$iproute2_path does not exist."
fi

cd $lnn_path/tools/testing/selftests/kparser
if [ ! -z "$single_test" ]; then
	echo_info "Running only this custom test: $single_test"
	configs=($single_test)
else
	configs=($(find pkt-validation-tests/ -name *test-config.json))
fi

test_cnt=0

for config in "${configs[@]}"
do
	echo_info "Starting test for config: ${config}"
	cmd="python3 ./test_kParser_with_pkts.py -f ${config} -l $lnn_path -i $iproute2_path"
	echo_info "Starting test: $cmd"
	eval $cmd
	retVal=$?
	if [ $retVal -ne 0 ]; then
		echo_info "Tests passed: $test_cnt/${#configs[@]}"
    		die "FAIL: Test for ${config} failed!"
	else
    		echo_info "SUCCESS: Test for ${config} passed!"
		test_cnt=$(($test_cnt+1))
	fi
done

echo_info "Tests passed: $test_cnt/${#configs[@]}"
