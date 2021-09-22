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
        for _ in range(3):
            p.readline()
        packages = p.readlines()
        pobj = []
        try:
            for package in packages:
                items = package.split()
                if len(items) == 4:
                    pobj.append(
                        {'packageName': items[1], 'version': items[3]})
        except:
            pass
        print(pobj)
        pj.write(json.dumps(pobj))

        v.seek(0)
        vobj = []
        for _ in range(7):
            v.readline()

        vulns = v.readlines()
        try:
            for vuln in vulns:
                items = vuln.split()
                if len(items) == 6:
                    vobj.append(
                        {'packageName': items[1], 'affected': items[3], 'severity': items[4], 'references': [items[5]]})
        except:
            pass
        print(vobj)
        vj.write(json.dumps(vobj))


def process(code_url, bucket_name, fn_name, scan_time, region):
    filename = '/tmp/lambda.zip'
    urllib.request.urlretrieve(code_url, filename)
    with ZipFile(filename, 'r') as zipObj:
        zipObj.extractall(path='/tmp/scanner')
        pre_scan_command_rm = ['rm', '-rf', 'obj/']
        pre_scan_command_restore = ['dotnet', 'restore']
        subprocess.check_call(pre_scan_command_rm, stdout=subprocess.DEVNULL, cwd=util.get_tmp_lambda_package_path())
        subprocess.check_call(pre_scan_command_restore, stdout=subprocess.DEVNULL, cwd=util.get_tmp_lambda_package_path())
        with open(f'{util.get_tmp_lambda_package_path()}/{packages_file}', 'a+') as p, open(f'{util.get_tmp_lambda_package_path()}/{vuln_file}', 'a+') as v:
            try:
                inventory_command = ['dotnet', 'list', 'package']
                subprocess.check_call(
                    inventory_command, stdout=p, cwd=util.get_tmp_lambda_package_path())
                vuln_command = ['dotnet', 'list', 'package', '--vulnerable']
                subprocess.check_call(vuln_command, stdout=v, cwd=util.get_tmp_lambda_package_path())
                parse(p, v)
                util.send_files(bucket_name, f'{scan_time}/{fn_name}-{region}')
            except Exception as e:
                print(e)
            finally:
                cleanup_command = ['rm', '-rf',
                                   util.get_tmp_lambda_package_path()]
                subprocess.call(cleanup_command)
