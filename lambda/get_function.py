import os
import json
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def handler(event, context):
    fn_name = event.get('name')
    region = event.get('region')
    scan_time = event.get('scanTime')
    bucket_name = os.environ.get('SKRYBA_BUCKET_NAME')

    print(fn_name)
    config = Config(
        region_name=region
    )
    client = boto3.client('lambda', config=config)

    func = client.get_function(FunctionName=fn_name)
    print(func)

    location = func.get('Code').get('Location')
    runtime = func.get('Configuration').get('Runtime')

    result = {"bucketName": bucket_name, "region": region,
              "codeLocation": location, "runtime": runtime,
              "functionName": fn_name, "scanTime": scan_time}
    queue_url = os.environ.get('SKRYBA_QUEUE')
    sqs = boto3.client('sqs')
    sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps(result))
    return True
