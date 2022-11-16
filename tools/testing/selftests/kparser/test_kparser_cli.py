import pytest
import subprocess
import kparser_util
import json
import re
import os
import allure

parent_testsuite=os.getenv("PARENT_TESTSUITE")
suite_name=os.getenv("TESTSUITE_NAME")
subsuite_name=os.getenv("SUB_TESTSUITE_NAME")


def pytest_generate_tests(metafunc):

    test_ids = []
    test_data = []
    try:
        ifile = open(metafunc.config.option.testfile)
        for line in ifile:
            tokens = line.split("|")
            test_ids.append(tokens[0])
            test_data.append([tokens[1], tokens[2], tokens[3]])
    except Exception as exception:
        print(" Exception reading testfile :  ", exception)

    if 'testdata' in metafunc.fixturenames:
        metafunc.parametrize(
            'testdata', test_data, ids=test_ids
        )

@pytest.fixture()
def testdata(request):
    return request.param


def kparser_cmd(args, json=True):
    _args = [os.getenv("IPROUTE2_PATH") + "/ip/ip"]
    if json:
        _args.append("-j")

    _args.append("parser")
    _args.append(args)
    returnObj = {}
    try:
        test_cmd = " ".join(_args)
        print("CMD : ", " ".join(_args))
        result = subprocess.run(test_cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=True)

        returnObj['returncode'] = result.returncode
        returnObj['stdout'] = str(result.stdout)
        returnObj['stderr'] = str(result.stderr)
        return returnObj

    except Exception as exception:
        print(" Failed to execute command ", exception)
        return None


def check_output(exp_str_list, result_str, negativeTest=False):
    for expected_str in exp_str_list:
        if (len(re.findall(expected_str, str(result_str))) > 0):
            continue
        else:
            print("  Expected String {} not found in result : {} ".
                  format(expected_str, result_str))
            return False
    return True


@pytest.fixture(scope="session")
def setup(request):
    #if (request.config.option.compile):
    #    print("Compiling xdp ... ")
    #    status = kparser_util.compile_xdp(mdata=None)
    #    print(" Compile XDP status ", status )

    print(" Removing kparser ..")
    lnn_path = ""
    if os.getenv("LINUX_NET_NEXT") is None:
        print(" LINUX_NET_NEXT not set ")
        exit(1)
    else:
        lnn_path = os.getenv("LINUX_NET_NEXT")

     
    print(" Loading kparser ..  \${LINUX_NET_NEXT}/net/kparser/kparser.ko")
    test_cmd = lnn_path + "/net/kparser/kparser.ko" 
    result = kparser_util.load_kparser_module(test_cmd)
    if (result['returncode'] != 0):
        print(" Error loading kparser.ko : ")
        print(" STDOUT : ", result['stdout'])
        print(" STDERR : ", result['stderr'])
        exit(1)
    print(" Loading kparser completed")

@allure.parent_suite(parent_testsuite)
@allure.suite(suite_name)
@allure.sub_suite(subsuite_name)
def test_cli(testdata, setup):
    print(" PARAM ", testdata)
    result = kparser_util._kparser_cmd_(" parser " + testdata[0])
    if result['returncode'] > 0:
        if testdata[1] in "True":
            assert check_output(testdata[2], result['stdout'])
        else:
            print(" Test Failed as return value is not 0 :  ", result)
            assert False
    else:
        assert check_output(testdata[2], result['stdout'])


if __name__ == '__main__':
    import xmlrunner
    unittest.main(testRunner=xmlrunner.XMLTestRunner(output='test-reports'))
