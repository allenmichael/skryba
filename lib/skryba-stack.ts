import * as cdk from '@aws-cdk/core';
import * as ec2 from '@aws-cdk/aws-ec2';
import * as ecs from '@aws-cdk/aws-ecs';
import * as logs from "@aws-cdk/aws-logs";
import * as apigw from '@aws-cdk/aws-apigateway';
import * as s3 from '@aws-cdk/aws-s3';
import * as iam from '@aws-cdk/aws-iam';
import * as lambda from "@aws-cdk/aws-lambda";
import * as sfn from "@aws-cdk/aws-stepfunctions";
import * as tasks from "@aws-cdk/aws-stepfunctions-tasks";
import * as sqs from "@aws-cdk/aws-sqs";
import * as dynamodb from '@aws-cdk/aws-dynamodb';
import * as ecsPatterns from "@aws-cdk/aws-ecs-patterns";
import { WebSocketApi, WebSocketStage } from "@aws-cdk/aws-apigatewayv2";
import { LambdaWebSocketIntegration } from "@aws-cdk/aws-apigatewayv2-integrations";
import * as fs from "fs";

export class SkrybaStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const namespace = 'skryba';

    const artifactBucket = new s3.Bucket(this, "SkrybaStorage", {
      bucketName: `${namespace.toLowerCase()}-${cdk.Aws.ACCOUNT_ID}`,
      versioned: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY
    });

    const table = new dynamodb.Table(this, 'SkrybaJobTable', {
      partitionKey: { name: 'scanTime', type: dynamodb.AttributeType.NUMBER },
      sortKey: { name: 'functionName', type: dynamodb.AttributeType.STRING }
    });

    const wssTable = new dynamodb.Table(this, 'SkrybaWSSTable', {
      partitionKey: { name: 'connectionId', type: dynamodb.AttributeType.STRING }
    });

    const natGatewayProvider = ec2.NatProvider.instance({
      instanceType: new ec2.InstanceType('t3.micro'),
    });

    const skrybaVpc = new ec2.Vpc(this, 'SkyrbaVPC', {
      cidr: '10.0.0.0/16',
      natGatewayProvider,
      gatewayEndpoints: {
        S3: {
          service: ec2.GatewayVpcEndpointAwsService.S3,
        },
        DDB: {
          service: ec2.GatewayVpcEndpointAwsService.DYNAMODB
        }
      },
      natGateways: 1,
      maxAzs: 2,
      subnetConfiguration: [
        {
          name: 'private-subnet-1',
          subnetType: ec2.SubnetType.PRIVATE,
          cidrMask: 24,
        },
        {
          name: 'public-subnet-1',
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask: 24,
        }
      ],
    });

    skrybaVpc.addInterfaceEndpoint('EcrDockerEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
    });
    
    const cluster = new ecs.Cluster(this, "SkrybaCluster", {
      vpc: skrybaVpc
    });

    const messageQueue = new sqs.Queue(this, 'DockerEcsSqsAutoScalingQueue', {
      visibilityTimeout: cdk.Duration.seconds(300)
    });

    const vulnLogGroup = new logs.LogGroup(this, "vulnLogGroup", {
      logGroupName: "/ecs/VulnService",
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const vulnLogDriver = new ecs.AwsLogDriver({
      logGroup: vulnLogGroup,
      streamPrefix: "VulnService",
    });

    const fargate = new ecsPatterns.QueueProcessingFargateService(this, "SkrybaProcessor", {
      cluster,
      image: ecs.ContainerImage.fromAsset("scanner"),
      cpu: 1024,
      memoryLimitMiB: 2048,
      enableLogging: true,
      logDriver: vulnLogDriver,
      minScalingCapacity: 0,
      maxScalingCapacity: 10,
      queue: messageQueue,
      scalingSteps: [
        { upper: 0, change: -5 },
        { lower: 1, change: +5 }
      ],
      visibilityTimeout: cdk.Duration.seconds(300),
      environment: {
        "SKRYBA_QUEUE": messageQueue.queueUrl,
        "SKRYBA_JOBS_TABLE": table.tableName
      }
    })

    fargate.taskDefinition.addToTaskRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "dynamodb:BatchGetItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ],
        effect: iam.Effect.ALLOW,
        resources: [table.tableArn],
      }))

    artifactBucket.grantPut(fargate.taskDefinition.taskRole);

    const lfc = fs.readFileSync('lambda/list_functions.py', { encoding: 'utf-8' });

    const functionListFunctions = new lambda.Function(this, "listFunctions", {
      runtime: lambda.Runtime.PYTHON_3_8,
      handler: "index.handler",
      code: lambda.Code.fromInline(lfc),
      timeout: cdk.Duration.minutes(15)
    });

    const listFunctionPolicy = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['lambda:ListFunctions'],
      resources: ['*']
    })
    functionListFunctions.role?.attachInlinePolicy(new iam.Policy(this, 'list-functions', {
      statements: [listFunctionPolicy]
    }))

    const gfc = fs.readFileSync('lambda/get_function.py', { encoding: 'utf-8' });

    const functionGetFunctionInfo = new lambda.Function(this, "GetFunctionFunc", {
      runtime: lambda.Runtime.PYTHON_3_8,
      handler: "index.handler",
      code: lambda.Code.fromInline(gfc),
      timeout: cdk.Duration.minutes(2),
      environment: {
        'SKRYBA_BUCKET_NAME': artifactBucket.bucketName,
        "SKRYBA_QUEUE": messageQueue.queueUrl
      }
    });

    const getFunctionPolicy = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['lambda:GetFunction'],
      resources: ['*']
    });

    const getFunctionSQSPolicy = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['sqs:SendMessage'],
      resources: [messageQueue.queueArn]
    })

    functionGetFunctionInfo.role?.attachInlinePolicy(new iam.Policy(this, 'get-functions', {
      statements: [getFunctionPolicy, getFunctionSQSPolicy]
    }));

    artifactBucket.grantReadWrite(functionGetFunctionInfo);

    const getFunctionInfoTask = new tasks.LambdaInvoke(this, "Get Function Info", {
      lambdaFunction: functionGetFunctionInfo
    })

    const definition = new tasks.LambdaInvoke(this, "List Function", {
      lambdaFunction: functionListFunctions,
      outputPath: "$.Payload",
    })
      .next(
        new sfn.Map(this, "Process Functions", {
          itemsPath: "$.items",
          maxConcurrency: 3,
        }).iterator(getFunctionInfoTask)
      )

    const sfnLogGroup = new logs.LogGroup(this, "sfnLogGroup", {
      logGroupName: "/stepfunctions/Skryba",
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const machine = new sfn.StateMachine(this, "StateMachine", {
      definition,
      stateMachineType: sfn.StateMachineType.EXPRESS,
      logs: { destination: sfnLogGroup }
    });

    const credentialsRole = new iam.Role(this, "getRole", {
      assumedBy: new iam.ServicePrincipal("apigateway.amazonaws.com"),
    });

    credentialsRole.attachInlinePolicy(
      new iam.Policy(this, "getPolicy", {
        statements: [
          new iam.PolicyStatement({
            actions: ["states:StartExecution"],
            effect: iam.Effect.ALLOW,
            resources: [machine.stateMachineArn],
          }),
        ],
      })
    );

    const api = new apigw.RestApi(this, 'skryba-api');

    const plan = api.addUsagePlan('UsagePlan', {
      name: 'SkrybaUsage',
      throttle: {
        rateLimit: 100,
        burstLimit: 200
      }
    });

    const key = api.addApiKey('SkrybaAPIKey', {
      apiKeyName: `skryba-key`,
    });
    plan.addApiKey(key);

    const cf = fs.readFileSync('lambda/connect.js', { encoding: 'utf-8' });

    const connectHandler = new lambda.Function(this, "ConnectFunction", {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: "index.handler",
      code: lambda.Code.fromInline(cf),
      timeout: cdk.Duration.seconds(15),
      environment: {
        "TABLE_NAME": wssTable.tableName
      }
    });
    wssTable.grantReadWriteData(connectHandler);

    const dcf = fs.readFileSync('lambda/disconnect.js', { encoding: 'utf-8' });

    const disconnectHandler = new lambda.Function(this, "DisconnectFunction", {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: "index.handler",
      code: lambda.Code.fromInline(dcf),
      timeout: cdk.Duration.seconds(15),
      environment: {
        "TABLE_NAME": wssTable.tableName
      }
    });
    wssTable.grantReadWriteData(disconnectHandler);

    const webSocketApi = new WebSocketApi(this, 'SkrybaNotifications', {
      connectRouteOptions: { integration: new LambdaWebSocketIntegration({ handler: connectHandler }) },
      disconnectRouteOptions: { integration: new LambdaWebSocketIntegration({ handler: disconnectHandler }) },
    });

    const wsStage = new WebSocketStage(this, 'SkrybaNotificationsStage', {
      webSocketApi,
      stageName: 'prod',
      autoDeploy: true,
    });

    const v1 = api.root.addResource('v1');
    const skyrbaPath = v1.addResource('skryba');
    const skrybaMethod = skyrbaPath.addMethod(
      "GET",
      new apigw.AwsIntegration({
        service: "states",
        action: "StartExecution",
        integrationHttpMethod: "POST",
        options: {
          credentialsRole,
          integrationResponses: [
            {
              statusCode: "200",
              responseTemplates: {
                "application/json": `{"done": true, "connect": "${wsStage.url}"}`,
              },
            },
          ],
          requestTemplates: {
            "application/json": `{
                  "input": "{\\"prefix\\":\\"prod\\"}",
                  "stateMachineArn": "${machine.stateMachineArn}"
                }`
          }
        }
      }),
      {
        apiKeyRequired: true,
        methodResponses: [{ statusCode: "200" }],
      }
    );

    plan.addApiStage({
      stage: api.deploymentStage,
      throttle: [
        {
          method: skrybaMethod,
          throttle: {
            rateLimit: 100,
            burstLimit: 200
          }
        }
      ]
    });
  }
}
