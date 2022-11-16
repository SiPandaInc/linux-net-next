import pytest
import kparser_util
# conftest.py

def pytest_addoption(parser):
    parser.addoption( "--testfile", action="store", default="testlist.txt" , help="testfile which contains test command details") ,
    parser.addoption( "--testobj", action="store", default="table" , help="testfile which contains test command details") ,
    parser.addoption( "--kparserconfig", action="store", default="./scripts/kparser_config/scenarios/ftuple_demo1.sh" , help="kParser config testscript") ,
    parser.addoption( "--testdir", action="store", default="." , help="testdir which contains kparser test commands files ") ,
    parser.addoption( "--installdir", action="store", default="/root/install" , help="installdir path for test executables"),
    parser.addoption( "--docker", action="store", default=None, help=" docker image name, if not provided run test locally " ),
    parser.addoption( "--static", action="store_true", default=False, help=" docker image name, if not provided run test locally " ),
    parser.addoption( "--mode", action="store_true", default="no-threads", help=" docker image name, if not provided run test locally " ),
    parser.addoption( "--count", action="store_true", default=1, help=" docker image name, if not provided run test locally " ),
    parser.addoption( "--compile", action="store_true", default=False, help=" docker image name, if not provided run test locally " ),

@pytest.fixture(scope="session", autouse=True)
def preconfig(request):
    if (request.config.option.compile):
        print("\nCompiling xdp ... \n")
        return kparser_util.compile_xdp(mdata=None)
    else:
        print("\nSkipping Compiling xdp ... \n")
        return True

