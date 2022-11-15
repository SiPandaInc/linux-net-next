# kParser Test 

This folder contains the various build and test scripts utilized for testing kParser. Following is the folder structure :

- *data* - This folder contains the test input data.
- *scripts* - This folder contains general scripts utilized in performing different tests.
- *scripts/kparser_config* - This folder contains different kparser config scripts.

## Prerequisites
Install following modules in ubuntu :

The env variable LINUX_NET_NEXT is set to the folder which containst the source :

Enable tap interface support in kernel config with following : 
*CONFIG_TUN=y*
*CONFIG_TAP=y*

```sh
export LINUX_NET_NEXT=/home/testusr/wspace/linux-net-next/
```
Install requisite modules 
```sh
apt install python3-pip
pip3 install pytest
pip3 install netns
pip3 install deepdiff 
pip3 install scapy
pip3 install pyroute2
pip3 install allure-pytest
```

## Build Scripts

The *scripts* folder contains following script utilitis for building the kParser module:

-  *kParser_build.sh* - This script has different functions which may be used to build kernel, iproute2, bpftool and samples/bpf modules. 
- *md_dump.sh* - This script displays the context map ( metadata dump) 


## Run Tests


For running kParser node related tests utilize following command :
*   pytest -v -s test_kparser_node.py --testfile ./data/testfunc_node.txt 

For running the kParser cli tests, run following command :
*   pytest -v -s test_kparser_cli.py --testfile ./data/test_crd_operations.txt
