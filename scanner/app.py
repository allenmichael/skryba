import boto3
import os
import json
from skrybautils import util
from processors import node, python, dotnet
from datetime import datetime, timezone

sqs = boto3.client('sqs')
dynamodb = boto3.resource('dynamodb')

queue_url = os.environ.get('SKRYBA_QUEUE')
dynamo_table_name = os.environ.get('SKRYBA_JOBS_TABLE')

table = dynamodb.Table(dynamo_table_name)


def read_sqs(queue_url):
    print(f"We will try to read {queue_url}")
    response = sqs.receive_message(
        QueueUrl=queue_url,
        AttributeNames=[
            'SentTimestamp'
        ],
        MaxNumberOfMessages=1,
        MessageAttributeNames=[
            'All'
        ],
        VisibilityTimeout=0,
        WaitTimeSeconds=0
    )

    print(f"SQS responded with {response}")

    return response.get('Messages', [])


def delete_sqs_message(receipt_handle):
    print(f"Deleting message {receipt_handle}")
    sqs.delete_message(
        QueueUrl=queue_url,
        ReceiptHandle=receipt_handle
    )


messages = read_sqs(queue_url)
print(f"Found messages {messages}")

for message in messages:
    print(f"Activating {message}")
    func = json.loads(message.get('Body', {}))
    if func == {}:
        delete_sqs_message(message['ReceiptHandle'])
        continue
    runtime = func.get('runtime', '')
    fn_name = func.get(
        'functionName', '')
    region = func.get('region', '')
    scan_time = func.get('scanTime', 0)
    code_location = func.get('codeLocation', '')
    bucket_name = func.get('bucketName', '')

    if runtime == '' or fn_name == '' or region == '' or scan_time == 0 or code_location == '' or bucket_name == '':
        print('Incomplete data from SQS')
        delete_sqs_message(message['ReceiptHandle'])
        continue

    table.put_item(
        Item={
            'scanTime': scan_time,
            'functionName': f'{fn_name}-{region}',
            'status': 'RUNNING'
        }
    )

    try:
        print('testing for runtime')
        if runtime in util.get_node_runtimes():
            print('node function detected...')
            node.process(code_url=code_location, bucket_name=bucket_name,
                         fn_name=fn_name, scan_time=scan_time, region=region)
        elif runtime in util.get_dotnet_runtimes():
            dotnet.process(code_url=code_location, bucket_name=bucket_name,
                           fn_name=fn_name, scan_time=scan_time, region=region)
        elif runtime in util.get_python_runtimes():
            python.process(code_url=code_location, bucket_name=bucket_name,
                           fn_name=fn_name, scan_time=scan_time, region=region)
    except Exception as e:
        print(e)
        table.update_item(
            Key={
                'scanTime': scan_time,
                'functionName': f'{fn_name}-{region}'
            },
            UpdateExpression='SET #s = :val1',
            ExpressionAttributeNames={
                "#s": "status"
            },
            ExpressionAttributeValues={
                ':val1': 'FAILED'
            })
        delete_sqs_message(message['ReceiptHandle'])

    delete_sqs_message(message['ReceiptHandle'])
    table.update_item(
        Key={
            'scanTime': scan_time,
            'functionName': f'{fn_name}-{region}'
        },
        UpdateExpression='SET #s = :val1',
        ExpressionAttributeValues={
            ':val1': 'FINISHED',
        },
        ExpressionAttributeNames={
            "#s": "status"
        }
    )
    print(f"Finished for {message}")
