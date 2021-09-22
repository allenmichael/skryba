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
default_version = '14'


def parse(p, v):
    with open(f'{util.get_tmp_lambda_package_path()}/{packages_json_file}', 'a+') as pj, open(f'{util.get_tmp_lambda_package_path()}/{vuln_json_file}', 'a+') as vj:
        p.seek(0)
        pobj = []
        packages = json.load(p)
        try:
            dependencies = packages.get('dependencies')
            for depenency in dependencies:
                pobj.append(
                    {'packageName': depenency, 'version': dependencies[depenency].get('version')})
        except:
            pass
        print(pobj)
        pj.write(json.dumps(pobj))

        v.seek(0)
        vobj = []
        vuln_file = json.load(v)
        try:
            vulns = vuln_file.get('vulnerabilities')
            for vuln in vulns:
                vuln_obj = vulns[vuln]
                references = []
                for source in vuln_obj.get('via'):
                    references.append(source.get('url'))
                vobj.append(
                    {'packageName': vuln_obj.get('name'), 'severity': vuln_obj.get('severity'),
                     'affected': vuln_obj.get('range'), 'references': references})
        except:
            pass
        print(vobj)
        vj.write(json.dumps(vobj))


def process(code_url, bucket_name, fn_name, scan_time, region):
    print('processing begins...')
    filename = '/tmp/lambda.zip'
    msg = urllib.request.urlretrieve(code_url, filename)
    print(msg)
    with ZipFile(filename, 'r') as zipObj:
        zipObj.extractall(path=util.get_tmp_lambda_package_path())
        print('unzipped')
        try:
            with open(f'{util.get_tmp_lambda_package_path()}/{packages_file}', 'a+') as p, open(f'{util.get_tmp_lambda_package_path()}/{vuln_file}', 'a+') as v:
                print('install packages...')
                install_command = ['npm', 'i']
                subprocess.check_call(
                    install_command, cwd=util.get_tmp_lambda_package_path(), stdout=subprocess.DEVNULL)
                print('writing inventory file...')
                inventory_command = ['npm', 'list', '--json']
                subprocess.call(inventory_command, stdout=p,
                                cwd=util.get_tmp_lambda_package_path())
                print('writing vuln file...')
                vuln_command = ['npm', 'audit', '--json']
                subprocess.check_call(
                    vuln_command, stdout=v, cwd=util.get_tmp_lambda_package_path())
                parse(p, v)
                util.send_files(bucket_name, f'{scan_time}/{fn_name}-{region}')
        except Exception as e:
            print(e)
        finally:
            cleanup_command = ['rm', '-rf', util.get_tmp_lambda_package_path()]
            subprocess.call(cleanup_command)
