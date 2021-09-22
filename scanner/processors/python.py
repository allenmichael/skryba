import urllib.request
from zipfile import ZipFile
import subprocess
import json
from skrybautils import util


packages_file = util.get_packages_file_name()
vuln_file = util.get_vuln_file_name()

packages_json_file = util.get_packages_json_file_name()
vuln_json_file = util.get_vuln_json_file_name()

runtime_commands = util.get_runtime_commands()
default_version = '3.8.0'


def parse(p, v):
    with open(f'{util.get_tmp_lambda_package_path()}/{packages_json_file}', 'a+') as pj, open(f'{util.get_tmp_lambda_package_path()}/{vuln_json_file}', 'a+') as vj:
        p.seek(0)
        pobj = []
        packages = json.load(p)
        try:
            if(len(packages) > 0):
                for package in packages:
                    if(package.get('name', '') != '' and package.get('version', '') != ''):
                        pobj.append(
                            {'packageName': package.get('name', ''), 'version': package.get('version', '')})
        except:
            pass
        print(pobj)
        pj.write(json.dumps(pobj))

        v.seek(0)
        vobj = []
        vuln_file = json.load(v)
        try:
            if(len(vuln_file) > 0):
                for vuln in vuln_file:
                    if(len(vuln) >= 4):
                        vobj.append(
                            {'packageName': vuln[0], 'affected': vuln[1], 'severity': '', 'references': [vuln[3]]})
        except:
            pass
        print(vobj)
        vj.write(json.dumps(vobj))


def process(code_url, bucket_name, fn_name, scan_time, region):
    filename = '/tmp/lambda.zip'
    urllib.request.urlretrieve(code_url, filename)
    with ZipFile(filename, 'r') as zipObj:
        zipObj.extractall(path='/tmp/scanner')
        with open(f'{util.get_tmp_lambda_package_path()}/{packages_file}', 'a+') as p, open(f'{util.get_tmp_lambda_package_path()}/{vuln_file}', 'a+') as v:
            try:
                inventory_command = ['pip3', 'list', '--format', 'json']
                subprocess.check_call(inventory_command, stdout=p)
                install_vuln_scanner_command = ['pip3', 'install', 'safety']
                subprocess.check_call(install_vuln_scanner_command, stdout=subprocess.DEVNULL)
                vuln_command = ['safety', 'check', '--json']
                subprocess.check_call(vuln_command, stdout=v)
                print('ran report and inventory...')
                parse(p, v)
                util.send_files(bucket_name, f'{scan_time}/{fn_name}-{region}')
            except Exception as e:
                print(e)
            finally:
                cleanup_command = ['rm', '-rf',
                                   util.get_tmp_lambda_package_path()]
                subprocess.call(cleanup_command)
