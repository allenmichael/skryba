import boto3
from botocore.exceptions import ClientError

node_runtimes = ['nodejs14.x', 'nodejs12.x', 'nodejs10.x']
dotnet_runtimes = ['dotnetcore3.1', 'dotnetcore2.1']
python_runtimes = ['python3.9', 'python3.8', 'python3.7', 'python3.6']

runtime_commands = {
    'nodejs14.x': ['/bin/bash', '-i',
                   '-c', 'nvm use 14'],
    'nodejs12.x': ['/bin/bash', '-i',
                   '-c', 'nvm use 12'],
    'nodejs10.x': ['/bin/bash', '-i',
                   '-c', 'nvm use 10'],
    'python3.9': ['pyenv', 'global' '3.9.0'],
    'python3.8': ['pyenv', 'global' '3.8.0'],
    'python3.7': ['pyenv', 'global' '3.7.0'],
    'python3.6': ['pyenv', 'global' '3.6.0']
}

packages_file = 'packages.txt'
vuln_file = 'report.txt'

packages_json_file = 'found_packages.json'
vuln_json_file = 'found_vulns.json'

tmp_lambda_package_path = '/tmp/scanner'


def get_node_runtimes():
    return node_runtimes


def get_dotnet_runtimes():
    return dotnet_runtimes


def get_python_runtimes():
    return python_runtimes


def get_runtime_commands():
    return runtime_commands


def get_packages_file_name():
    return packages_file


def get_vuln_file_name():
    return vuln_file


def get_packages_json_file_name():
    return packages_json_file


def get_vuln_json_file_name():
    return vuln_json_file


def get_tmp_lambda_package_path():
    return tmp_lambda_package_path


def send_files(bucket, prefix):
    s3_client = boto3.client('s3')
    try:
        package_response = s3_client.upload_file(
            f'{tmp_lambda_package_path}/{packages_json_file}',
            bucket, f'{prefix}/{packages_json_file}')
        vuln_response = s3_client.upload_file(
            f'{tmp_lambda_package_path}/{vuln_json_file}',
            bucket, f'{prefix}/{vuln_json_file}')
        print(package_response)
        print(vuln_response)
    except ClientError as e:
        print(e)
        return False
    return True
