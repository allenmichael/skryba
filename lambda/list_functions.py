import boto3
from botocore.config import Config
from datetime import datetime, timezone

AWS_REGIONS = [
    # 'af-south-1',  # Africa(Cape Town)
    # 'ap-east-1',  # Asia Pacific(Hong Kong)
    'ap-northeast-1',  # Asia Pacific(Tokyo)
    'ap-northeast-2',  # Asia Pacific(Seoul)
    'ap-northeast-3',  # Asia Pacific(Osaka)
    'ap-south-1',  # Asia Pacific(Mumbai)
    'ap-southeast-1',  # Asia Pacific(Singapore)
    'ap-southeast-2',  # Asia Pacific(Sydney)
    'ca-central-1',  # Canada(Central)
    # 'cn-north-1',  # China(Beijing)
    # 'cn-northwest-1',  # China(Ningxia)
    'eu-central-1',  # Europe(Frankfurt)
    'eu-north-1',  # Europe(Stockholm)
    # 'eu-south-1',  # Europe(Milan)
    'eu-west-1',  # Europe(Ireland)
    'eu-west-2',  # Europe(London)
    'eu-west-3',  # Europe(Paris)
    # 'me-south-1',  # Middle East(Bahrain)
    'sa-east-1',  # South America(São Paulo)
    'us-east-1',  # US East(N. Virginia)
    'us-east-2',  # US East(Ohio)
    # 'us-gov-east-1',  # AWS GovCloud(US-East)
    # 'us-gov-west-1',  # AWS GovCloud(US-West)
    # 'us-iso-east-1',  # AWS ISO
    # 'us-isob-east-1',  # AWS ISO-B
    'us-west-1',  # US West(N. California)
    'us-west-2'
]


def handler(event, context):
    scan_time = datetime.now(tz=timezone.utc)
    functions = []
    for region in AWS_REGIONS:
        config = Config(
            region_name=region
        )
        client = boto3.client('lambda', config=config)
        paginator = client.get_paginator('list_functions')
        try:
            print(f'Scanning {region}')
            response_iterator = paginator.paginate(
                FunctionVersion='ALL',
                PaginationConfig={
                    'PageSize': 1
                }
            )
            for result in response_iterator:
                for func in result['Functions']:
                    functions.append({
                        "scanTime": round(scan_time.timestamp()),
                        "region": region,
                        "name": func['FunctionName']
                    })
        except Exception as e:
            print('oops')
            print(e)
    print(functions)
    return {'items': functions}
