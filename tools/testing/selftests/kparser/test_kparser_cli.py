import pytest
import test_util
import subprocess
import json
import re

def pytest_generate_tests(metafunc):

    test_ids = []
    test_data = []
    try : 
        ifile = open(metafunc.config.option.testfile ) 
        for line in ifile: 
            tokens = line.split("|")
            test_ids.append(tokens[0] )
            test_data.append([tokens[1],tokens[2],tokens[3]] )
    except Exception as exception:
        print(" Exception reading testfile :  ", exception)


    if 'testdata' in metafunc.fixturenames:
        metafunc.parametrize(
            'testdata', test_data , ids=test_ids
        )


@pytest.fixture()
def testdata(request):
    return request.param


def kparser_cmd(args, json=True):
    _args = ["/home/testusr/wspace/iproute2/ip/ip"]
    if json:
        _args.append("-j")

    _args.append("parser")
    _args.append(args)
    returnObj = {}
    try :
        test_cmd = " ".join(_args)
        print("CMD : " , " ".join(_args) )
        result = subprocess.run( test_cmd , stdout = subprocess.PIPE, stderr = subprocess.PIPE,  shell=True )

        returnObj['returncode'] = result.returncode
        returnObj['stdout'] = str(result.stdout)
        returnObj['stderr'] = str(result.stderr)
        return returnObj

    except Exception as exception :
      print(" Failed to execute command ", exception )
      return None



#def bpftool(args):
#    return _bpftool(args, json=False).decode("utf-8")


def check_output( exp_str_list, result_str, negativeTest=False): 
       
       for expected_str in exp_str_list :
             if ( len( re.findall( expected_str , str(result_str) )) > 0 ) :
                   continue
             else :
                print(" Expected String {} not found in result : {} ".format(expected_str , result_str ))
                return False
       return True

#@pytest.fixture(scope="class")
@pytest.fixture()
def setup(request) :
        new_test_obj  =   test_util.test_obj( )
        new_test_obj.set_installdir(request.config.option.installdir)
        new_test_obj.set_testfile(request.config.option.testfile)
        new_test_obj.set_docker(request.config.option.docker)
        new_test_obj.set_static(request.config.option.static )
        return new_test_obj


#@pytest.mark.usefixtures("setup")
#class TestClass:


#@pytest.mark.usefixtures("setup")
#def test_equals( testdata, setup):
def test_cli( testdata ):
        print(" PARAM " , testdata )
        result = kparser_cmd(testdata[0])
        
        if result['returncode']  > 0 :
            if testdata[1] in  "True" :
               assert  check_output(testdata[2], result['stdout'])
            else :
               print(" Test Failed as return value is not 0 :  ", result )
               assert False 
        else :
            assert  check_output(testdata[2], result['stdout'])

if __name__ == '__main__':
    import xmlrunner
    unittest.main(testRunner=xmlrunner.XMLTestRunner(output='test-reports'))
