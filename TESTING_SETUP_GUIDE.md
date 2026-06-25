# AIML Security Assessment Testing Setup Guide

This guide provides comprehensive instructions for deploying test resources to validate all security checks in the AIML Security Assessment tool.

## Table of Contents
- [Prerequisites](#prerequisites)
- [CloudFormation Deployment](#cloudformation-deployment)
- [Manual Bedrock Configuration](#manual-bedrock-configuration)
- [Manual AgentCore Configuration](#manual-agentcore-configuration)
- [Manual SageMaker Configuration](#manual-sagemaker-configuration)
- [Running the Assessment](#running-the-assessment)
- [Expected Results](#expected-results)
- [Cleanup](#cleanup)

---

## Prerequisites

### Required
- AWS Account with appropriate permissions
- AWS CLI configured
- Access to Amazon Bedrock (enabled in your account)
- Access to Amazon Bedrock AgentCore (preview access)

### Recommended Regions
- `us-west-2` (Oregon) - Primary testing region
- `eu-west-1` (Ireland) - Multi-region testing

### Estimated Costs
- **CloudFormation Resources**: ~$5-10/day
  - SageMaker Notebooks (ml.t3.medium): ~$0.05/hour each
  - SageMaker Endpoints (ml.t2.medium): ~$0.065/hour each
  - NAT Gateway: ~$0.045/hour + data transfer
  - VPC Endpoints: ~$0.01/hour each
- **GuardDuty** (if enabled): ~$4.50/month base + usage
- **Total Daily Estimate**: ~$8-15/day when resources are running

---

## CloudFormation Deployment

### Step 1: Prepare Parameters

Create a parameters file `parameters.json`:

```json
[
  {
    "ParameterKey": "EnvironmentName",
    "ParameterValue": "aiml-sec-test"
  },
  {
    "ParameterKey": "AvailabilityZone1",
    "ParameterValue": "us-west-2a"
  },
  {
    "ParameterKey": "AvailabilityZone2",
    "ParameterValue": "us-west-2b"
  },
  {
    "ParameterKey": "EnableAgentCore",
    "ParameterValue": "true"
  },
  {
    "ParameterKey": "EnableGuardDuty",
    "ParameterValue": "false"
  }
]
```

### Step 2: Deploy the Stack

```bash
aws cloudformation create-stack \
  --stack-name aiml-sec-test-stack \
  --template-body file://test-resources-cloudformation.yaml \
  --parameters file://parameters.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2

# Monitor deployment
aws cloudformation describe-stacks \
  --stack-name aiml-sec-test-stack \
  --region us-west-2 \
  --query 'Stacks[0].StackStatus'

# Wait for completion (10-15 minutes)
aws cloudformation wait stack-create-complete \
  --stack-name aiml-sec-test-stack \
  --region us-west-2
```

### Step 3: Capture Outputs

```bash
aws cloudformation describe-stacks \
  --stack-name aiml-sec-test-stack \
  --region us-west-2 \
  --query 'Stacks[0].Outputs' > stack-outputs.json
```

---

## Manual Bedrock Configuration

CloudFormation cannot create all Bedrock resources. Follow these steps for complete coverage:

### BR-04: Model Invocation Logging (FAIL scenario)

**Current State**: No logging configured (will FAIL BR-04)

**To create PASS scenario**:

```bash
# Get bucket name from stack outputs
BUCKET_NAME=$(aws cloudformation describe-stacks \
  --stack-name aiml-sec-test-stack \
  --region us-west-2 \
  --query 'Stacks[0].Outputs[?OutputKey==`BedrockLoggingBucketName`].OutputValue' \
  --output text)

# Configure model invocation logging
aws bedrock put-model-invocation-logging-configuration \
  --region us-west-2 \
  --logging-config "{
    \"s3Config\": {
      \"bucketName\": \"${BUCKET_NAME}\",
      \"keyPrefix\": \"model-invocations\"
    },
    \"cloudWatchConfig\": {
      \"logGroupName\": \"/aws/bedrock/aiml-sec-test\",
      \"roleArn\": \"arn:aws:iam::YOUR_ACCOUNT_ID:role/service-role/AmazonBedrockLoggingRole\"
    },
    \"textDataDeliveryEnabled\": true,
    \"imageDataDeliveryEnabled\": true,
    \"embeddingDataDeliveryEnabled\": true
  }"
```

### BR-05: Guardrails

**FAIL Scenario**: No guardrails (default state)

**PASS Scenario**: Create at least one guardrail

```bash
# Create a basic guardrail
aws bedrock create-guardrail \
  --region us-west-2 \
  --name aiml-sec-test-guardrail \
  --description "Test guardrail for security assessment" \
  --content-policy-config '{
    "filtersConfig": [
      {
        "type": "HATE",
        "inputStrength": "MEDIUM",
        "outputStrength": "MEDIUM"
      },
      {
        "type": "VIOLENCE",
        "inputStrength": "MEDIUM",
        "outputStrength": "MEDIUM"
      }
    ]
  }' \
  --topic-policy-config '{
    "topicsConfig": [
      {
        "name": "Financial Advice",
        "definition": "Providing specific financial or investment advice",
        "type": "DENY"
      }
    ]
  }' \
  --blocked-input-messaging "This request has been blocked by content filters." \
  --blocked-outputs-messaging "This response has been blocked by content filters." \
  --tags Key=Purpose,Value=SecurityTesting
```

### BR-07: Prompt Management

**FAIL Scenario**: No prompts (default state)

**PASS Scenario**: Create test prompts

```bash
# Create a prompt
aws bedrock-agent create-prompt \
  --region us-west-2 \
  --name aiml-sec-test-prompt \
  --description "Test prompt for security assessment" \
  --variants '[
    {
      "name": "variant1",
      "templateType": "TEXT",
      "templateConfiguration": {
        "text": {
          "text": "You are a helpful AI assistant. Answer the following question: {{question}}"
        }
      },
      "modelId": "anthropic.claude-3-sonnet-20240229-v1:0"
    },
    {
      "name": "variant2",
      "templateType": "TEXT",
      "templateConfiguration": {
        "text": {
          "text": "You are an expert AI assistant. Provide a detailed answer to: {{question}}"
        }
      },
      "modelId": "anthropic.claude-3-sonnet-20240229-v1:0"
    }
  ]' \
  --tags Key=Purpose,Value=SecurityTesting
```

### BR-09: Knowledge Base Encryption

**Create a Knowledge Base with encryption**:

```bash
# First, create an OpenSearch Serverless collection
aws opensearchserverless create-collection \
  --region us-west-2 \
  --name aiml-sec-test-kb \
  --type VECTORSEARCH \
  --description "Test knowledge base for security assessment"

# Get the collection endpoint
COLLECTION_ENDPOINT=$(aws opensearchserverless batch-get-collection \
  --region us-west-2 \
  --names aiml-sec-test-kb \
  --query 'collectionDetails[0].collectionEndpoint' \
  --output text)

# Create Knowledge Base
aws bedrock-agent create-knowledge-base \
  --region us-west-2 \
  --name aiml-sec-test-knowledge-base \
  --description "Test knowledge base for security assessment" \
  --role-arn "arn:aws:iam::YOUR_ACCOUNT_ID:role/AmazonBedrockExecutionRoleForKnowledgeBase" \
  --knowledge-base-configuration '{
    "type": "VECTOR",
    "vectorKnowledgeBaseConfiguration": {
      "embeddingModelArn": "arn:aws:bedrock:us-west-2::foundation-model/amazon.titan-embed-text-v1"
    }
  }' \
  --storage-configuration "{
    \"type\": \"OPENSEARCH_SERVERLESS\",
    \"opensearchServerlessConfiguration\": {
      \"collectionArn\": \"arn:aws:aoss:us-west-2:YOUR_ACCOUNT_ID:collection/aiml-sec-test-kb\",
      \"vectorIndexName\": \"aiml-sec-test-index\",
      \"fieldMapping\": {
        \"vectorField\": \"vector\",
        \"textField\": \"text\",
        \"metadataField\": \"metadata\"
      }
    }
  }" \
  --tags Key=Purpose,Value=SecurityTesting
```

### BR-10: Guardrail IAM Enforcement

**FAIL Scenario**: Roles without guardrail condition (default)

**PASS Scenario**: Update role with guardrail condition

```bash
# Create a role with guardrail enforcement
cat > bedrock-guardrail-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "bedrock:guardrailIdentifier": "YOUR_GUARDRAIL_ID"
        }
      }
    }
  ]
}
EOF

aws iam create-policy \
  --policy-name aiml-sec-test-guardrail-enforced \
  --policy-document file://bedrock-guardrail-policy.json \
  --description "Policy enforcing guardrail usage"
```

---

## Manual AgentCore Configuration

AgentCore resources require the control plane APIs. Here's how to create test resources:

### AC-01: VPC Configuration

**Create a Runtime with VPC** (assuming you have AgentCore CLI or SDK access):

```python
# Python example using boto3 (requires AgentCore preview access)
import boto3

agentcore = boto3.client('bedrock-agentcore-control', region_name='us-west-2')

# Get VPC details from CloudFormation stack
vpc_id = 'vpc-xxx'  # From stack outputs
subnet_ids = ['subnet-xxx', 'subnet-yyy']  # Private subnets from stack
sg_id = 'sg-xxx'  # Security group from stack

# Create Runtime with VPC (PASS)
runtime_vpc_response = agentcore.create_agent_runtime(
    agentRuntimeName='aiml-sec-test-runtime-vpc',
    description='Runtime with VPC for security testing',
    networkConfiguration={
        'networkMode': 'VPC',
        'subnetIds': subnet_ids,
        'securityGroupIds': [sg_id]
    },
    loggingConfig={
        'cloudWatchLogsConfig': {
            'logGroupName': '/aws/bedrock-agentcore/aiml-sec-test',
            'enabled': True
        }
    },
    tracingConfig={
        'enabled': True
    },
    tags={
        'Purpose': 'SecurityTestingPass'
    }
)

# Create Runtime without VPC (FAIL)
runtime_no_vpc_response = agentcore.create_agent_runtime(
    agentRuntimeName='aiml-sec-test-runtime-public',
    description='Runtime without VPC for security testing',
    networkConfiguration={
        'networkMode': 'PUBLIC'
    },
    tags={
        'Purpose': 'SecurityTestingFail'
    }
)
```

### AC-04: Observability

The VPC runtime above has logging and tracing enabled (PASS). Create one without:

```python
# Create Runtime without observability (FAIL)
runtime_no_obs = agentcore.create_agent_runtime(
    agentRuntimeName='aiml-sec-test-runtime-no-observability',
    description='Runtime without observability',
    networkConfiguration={
        'networkMode': 'PUBLIC'
    },
    # No loggingConfig or tracingConfig - will FAIL AC-04
    tags={
        'Purpose': 'SecurityTestingFail'
    }
)
```

### AC-07: Memory Configuration

```python
# Get KMS key ARN from stack outputs
kms_key_arn = 'arn:aws:kms:us-west-2:xxx:key/xxx'  # AgentCore KMS key

# Create Memory with encryption (PASS)
memory_with_encryption = agentcore.create_memory(
    name='aiml-sec-test-memory-encrypted',
    description='Memory with encryption',
    memoryType='AGENT',
    encryptionKeyArn=kms_key_arn,
    tags={
        'Purpose': 'SecurityTestingPass'
    }
)

# Create Memory without customer-managed key (FAIL)
memory_no_cmk = agentcore.create_memory(
    name='aiml-sec-test-memory-no-cmk',
    description='Memory without customer-managed encryption',
    memoryType='AGENT',
    # No encryptionKeyArn - will use AWS-managed key (FAIL AC-07)
    tags={
        'Purpose': 'SecurityTestingFail'
    }
)
```

---

## Manual SageMaker Configuration

### SM-04: GuardDuty

If you set `EnableGuardDuty: true` in parameters, GuardDuty will be automatically enabled via the CloudFormation template. Otherwise, enable manually:

```bash
# Enable GuardDuty
aws guardduty create-detector \
  --region us-west-2 \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES
```

### SM-06: Clarify Processing Jobs

```bash
# Create a Clarify processing job
aws sagemaker create-processing-job \
  --region us-west-2 \
  --processing-job-name aiml-sec-test-clarify-job \
  --role-arn arn:aws:iam::YOUR_ACCOUNT_ID:role/aiml-sec-test-sagemaker-execution-role \
  --app-specification '{
    "ImageUri": "306415355426.dkr.ecr.us-west-2.amazonaws.com/sagemaker-clarify-processing:1.0"
  }' \
  --processing-inputs '[
    {
      "InputName": "dataset",
      "S3Input": {
        "S3Uri": "s3://aiml-sec-test-sagemaker-YOUR_ACCOUNT_ID/clarify-input/",
        "LocalPath": "/opt/ml/processing/input",
        "S3DataType": "S3Prefix",
        "S3InputMode": "File"
      }
    }
  ]' \
  --processing-output-config '{
    "Outputs": [
      {
        "OutputName": "analysis",
        "S3Output": {
          "S3Uri": "s3://aiml-sec-test-sagemaker-YOUR_ACCOUNT_ID/clarify-output/",
          "LocalPath": "/opt/ml/processing/output",
          "S3UploadMode": "EndOfJob"
        }
      }
    ]
  }' \
  --processing-resources '{
    "ClusterConfig": {
      "InstanceType": "ml.m5.xlarge",
      "InstanceCount": 1,
      "VolumeSizeInGB": 10
    }
  }' \
  --stopping-condition '{
    "MaxRuntimeInSeconds": 3600
  }' \
  --tags Key=Purpose,Value=SecurityTesting
```

### SM-07: Model Monitor

```bash
# Create a monitoring schedule
aws sagemaker create-monitoring-schedule \
  --region us-west-2 \
  --monitoring-schedule-name aiml-sec-test-monitor \
  --monitoring-schedule-config '{
    "ScheduleConfig": {
      "ScheduleExpression": "cron(0 * * * ? *)"
    },
    "MonitoringJobDefinition": {
      "MonitoringInputs": [
        {
          "EndpointInput": {
            "EndpointName": "aiml-sec-test-endpoint-multi-instance",
            "LocalPath": "/opt/ml/processing/input"
          }
        }
      ],
      "MonitoringOutputConfig": {
        "MonitoringOutputs": [
          {
            "S3Output": {
              "S3Uri": "s3://aiml-sec-test-sagemaker-YOUR_ACCOUNT_ID/monitoring-output/",
              "LocalPath": "/opt/ml/processing/output"
            }
          }
        ]
      },
      "MonitoringResources": {
        "ClusterConfig": {
          "InstanceType": "ml.m5.xlarge",
          "InstanceCount": 1,
          "VolumeSizeInGB": 10
        }
      },
      "MonitoringAppSpecification": {
        "ImageUri": "159807026194.dkr.ecr.us-west-2.amazonaws.com/sagemaker-model-monitor-analyzer"
      },
      "RoleArn": "arn:aws:iam::YOUR_ACCOUNT_ID:role/aiml-sec-test-sagemaker-execution-role"
    }
  }' \
  --tags Key=Purpose,Value=SecurityTesting
```

### SM-13: Monitoring Schedule Network Isolation

```bash
# Create monitoring schedule with network isolation (PASS)
aws sagemaker create-monitoring-schedule \
  --region us-west-2 \
  --monitoring-schedule-name aiml-sec-test-monitor-isolated \
  --monitoring-schedule-config '{
    "ScheduleConfig": {
      "ScheduleExpression": "cron(0 * * * ? *)"
    },
    "MonitoringJobDefinition": {
      "NetworkConfig": {
        "EnableNetworkIsolation": true,
        "VpcConfig": {
          "SecurityGroupIds": ["sg-xxx"],
          "Subnets": ["subnet-xxx", "subnet-yyy"]
        }
      },
      "MonitoringInputs": [
        {
          "EndpointInput": {
            "EndpointName": "aiml-sec-test-endpoint-multi-instance",
            "LocalPath": "/opt/ml/processing/input"
          }
        }
      ],
      "MonitoringOutputConfig": {
        "MonitoringOutputs": [
          {
            "S3Output": {
              "S3Uri": "s3://aiml-sec-test-sagemaker-YOUR_ACCOUNT_ID/monitoring-output/",
              "LocalPath": "/opt/ml/processing/output"
            }
          }
        ]
      },
      "MonitoringResources": {
        "ClusterConfig": {
          "InstanceType": "ml.m5.xlarge",
          "InstanceCount": 1,
          "VolumeSizeInGB": 10
        }
      },
      "MonitoringAppSpecification": {
        "ImageUri": "159807026194.dkr.ecr.us-west-2.amazonaws.com/sagemaker-model-monitor-analyzer"
      },
      "RoleArn": "arn:aws:iam::YOUR_ACCOUNT_ID:role/aiml-sec-test-sagemaker-execution-role"
    }
  }' \
  --tags Key=Purpose,Value=SecurityTesting
```

---

## Running the Assessment

### Step 1: Deploy the Assessment Stack

```bash
cd aiml-security-assessment

# Deploy the assessment application
sam build
sam deploy --guided
```

### Step 2: Execute Assessment

```bash
# Get the State Machine ARN from the assessment stack
STATE_MACHINE_ARN=$(aws cloudformation describe-stacks \
  --stack-name aiml-security-assessment \
  --query 'Stacks[0].Outputs[?OutputKey==`SecurityAssessmentStateMachineArn`].OutputValue' \
  --output text)

# Start execution
EXECUTION_ARN=$(aws stepfunctions start-execution \
  --state-machine-arn $STATE_MACHINE_ARN \
  --input '{
    "regions": ["us-west-2"],
    "services": ["bedrock", "sagemaker", "agentcore"]
  }' \
  --query 'executionArn' \
  --output text)

# Monitor execution
aws stepfunctions describe-execution \
  --execution-arn $EXECUTION_ARN

# Wait for completion
aws stepfunctions describe-execution \
  --execution-arn $EXECUTION_ARN \
  --query 'status'
```

### Step 3: Review Results

```bash
# Get the S3 bucket where reports are stored
REPORT_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name aiml-security-assessment \
  --query 'Stacks[0].Outputs[?OutputKey==`AssessmentBucketName`].OutputValue' \
  --output text)

# List reports
aws s3 ls s3://${REPORT_BUCKET}/ --recursive | grep .csv

# Download latest reports
aws s3 sync s3://${REPORT_BUCKET}/ ./reports/ --exclude "*" --include "*security_report*.csv"
```

---

## Expected Results

### Bedrock Checks

| Check ID | Resource | Expected Status | Reason |
|----------|----------|-----------------|--------|
| BR-01 | `aiml-sec-test-bedrock-full-access-role` | **FAIL** | Has AmazonBedrockFullAccess policy |
| BR-02 | VPC Endpoints | **FAIL** | Missing bedrock-agent endpoints |
| BR-03 | `aiml-sec-test-marketplace-overpermissive-role` | **FAIL** | Wildcard marketplace subscribe |
| BR-04 | Model Invocation Logging | **FAIL** | No logging configured (until manual setup) |
| BR-05 | Guardrails | **FAIL** | No guardrails (until manual creation) |
| BR-06 | CloudTrail | **PASS** | Trail configured with management events |
| BR-07 | Prompt Management | **FAIL** | No prompts (until manual creation) |
| BR-09 | Knowledge Base | **N/A** | No KB (until manual creation) |
| BR-10 | Guardrail IAM | **FAIL** | No condition keys in policies |

### SageMaker Checks

| Check ID | Resource | Expected Status | Reason |
|----------|----------|-----------------|--------|
| SM-01 | `aiml-sec-test-notebook-with-internet` | **FAIL** | DirectInternetAccess=Enabled |
| SM-01 | `aiml-sec-test-notebook-secure` | **PASS** | In VPC, no direct internet |
| SM-02 | `aiml-sec-test-sagemaker-full-access-role` | **FAIL** | Has AmazonSageMakerFullAccess |
| SM-03 | `aiml-sec-test-training-no-encryption` | **FAIL** | No KMS key for output |
| SM-04 | GuardDuty | **FAIL** | Not enabled (unless parameter set) |
| SM-05 | MLOps Features | **PASS** | Model Package Group & Feature Group exist |
| SM-06 | Clarify | **N/A** | No Clarify jobs (until manual creation) |
| SM-07 | Model Monitor | **N/A** | No monitoring schedules (until manual) |
| SM-09 | `aiml-sec-test-notebook-with-internet` | **FAIL** | RootAccess=Enabled |
| SM-09 | `aiml-sec-test-notebook-secure` | **PASS** | RootAccess=Disabled |
| SM-10 | `aiml-sec-test-notebook-with-internet` | **FAIL** | Not in VPC |
| SM-10 | `aiml-sec-test-notebook-secure` | **PASS** | In VPC |
| SM-11 | `aiml-sec-test-model-no-isolation` | **FAIL** | NetworkIsolation not enabled |
| SM-11 | `aiml-sec-test-model-with-isolation` | **PASS** | NetworkIsolation enabled |
| SM-12 | `aiml-sec-test-endpoint-single-instance` | **FAIL** | InstanceCount=1 |
| SM-12 | `aiml-sec-test-endpoint-multi-instance` | **PASS** | InstanceCount=2 |

### AgentCore Checks

| Check ID | Resource | Expected Status | Reason |
|----------|----------|-----------------|--------|
| AC-01 | Runtime (VPC) | **PASS** | Deployed in VPC (manual creation) |
| AC-01 | Runtime (Public) | **FAIL** | No VPC configuration (manual creation) |
| AC-02 | `aiml-sec-test-agentcore-overpermissive-role` | **FAIL** | Wildcard permissions |
| AC-03 | Stale Access | **Varies** | Based on actual usage |
| AC-04 | Runtime (observability) | **PASS** | Logging & tracing enabled |
| AC-04 | Runtime (no observability) | **FAIL** | No logging/tracing |
| AC-05 | ECR Encryption | **Varies** | Depends on AgentCore container images |
| AC-07 | Memory (encrypted) | **PASS** | Customer-managed KMS key |
| AC-07 | Memory (no CMK) | **FAIL** | AWS-managed key |
| AC-08 | VPC Endpoints | **FAIL** | No AgentCore endpoints (until manual) |

---

## Cleanup

### Step 1: Stop Running Resources

```bash
# Stop SageMaker notebooks
aws sagemaker stop-notebook-instance \
  --notebook-instance-name aiml-sec-test-notebook-with-internet \
  --region us-west-2

aws sagemaker stop-notebook-instance \
  --notebook-instance-name aiml-sec-test-notebook-secure \
  --region us-west-2
```

### Step 2: Delete Manual Resources

```bash
# Delete Bedrock resources (if created)
aws bedrock delete-guardrail --guardrail-identifier YOUR_GUARDRAIL_ID --region us-west-2
aws bedrock-agent delete-prompt --prompt-identifier YOUR_PROMPT_ID --region us-west-2
aws bedrock-agent delete-knowledge-base --knowledge-base-id YOUR_KB_ID --region us-west-2

# Delete AgentCore resources (if created)
# Use AgentCore CLI or SDK to delete runtimes, memories, etc.

# Delete SageMaker monitoring schedules
aws sagemaker delete-monitoring-schedule \
  --monitoring-schedule-name aiml-sec-test-monitor \
  --region us-west-2

# Disable GuardDuty (if enabled)
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text --region us-west-2)
aws guardduty delete-detector --detector-id $DETECTOR_ID --region us-west-2
```

### Step 3: Delete CloudFormation Stack

```bash
# Delete the test resources stack
aws cloudformation delete-stack \
  --stack-name aiml-sec-test-stack \
  --region us-west-2

# Wait for deletion to complete
aws cloudformation wait stack-delete-complete \
  --stack-name aiml-sec-test-stack \
  --region us-west-2
```

### Step 4: Clean S3 Buckets

CloudFormation cannot delete non-empty S3 buckets. Clean them manually:

```bash
# List buckets created by the stack
aws s3 ls | grep aiml-sec-test

# Empty and delete each bucket
aws s3 rm s3://aiml-sec-test-sagemaker-YOUR_ACCOUNT_ID --recursive
aws s3 rb s3://aiml-sec-test-sagemaker-YOUR_ACCOUNT_ID

aws s3 rm s3://aiml-sec-test-bedrock-logs-YOUR_ACCOUNT_ID --recursive
aws s3 rb s3://aiml-sec-test-bedrock-logs-YOUR_ACCOUNT_ID

aws s3 rm s3://aiml-sec-test-cloudtrail-YOUR_ACCOUNT_ID --recursive
aws s3 rb s3://aiml-sec-test-cloudtrail-YOUR_ACCOUNT_ID
```

---

## Troubleshooting

### CloudFormation Deployment Issues

**Issue**: `Parameter validation failed: parameter value for parameter name AvailabilityZone1 does not exist`

**Solution**: Use valid AZs for your region:
```bash
aws ec2 describe-availability-zones --region us-west-2 --query 'AvailabilityZones[*].ZoneName'
```

**Issue**: `Resource limit exceeded for SageMaker endpoints`

**Solution**: Request service quota increase or reduce instance types.

### SageMaker Notebook Fails to Start

**Issue**: Notebook instance stuck in "Pending" state

**Solution**: 
1. Check subnet has internet access (NAT Gateway for private subnets)
2. Verify security group allows egress to AWS services
3. Check CloudWatch Logs: `/aws/sagemaker/NotebookInstances/[instance-name]`

### Bedrock Model Invocation Logging

**Issue**: `InvalidRequestException: Logging configuration requires a service role`

**Solution**: Create the AmazonBedrockLoggingRole:
```bash
aws iam create-role \
  --role-name AmazonBedrockLoggingRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "bedrock.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy \
  --role-name AmazonBedrockLoggingRole \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchLogsFullAccess

aws iam attach-role-policy \
  --role-name AmazonBedrockLoggingRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
```

### AgentCore Access Issues

**Issue**: `AccessDeniedException: User is not authorized to perform bedrock-agentcore:CreateAgentRuntime`

**Solution**: AgentCore is in preview. Request access through AWS support or your account team.

---

## Multi-Region Testing

To test in multiple regions:

1. Deploy the CloudFormation stack in both regions:
   ```bash
   # us-west-2
   aws cloudformation create-stack --stack-name aiml-sec-test-stack \
     --template-body file://test-resources-cloudformation.yaml \
     --parameters file://parameters-us-west-2.json \
     --capabilities CAPABILITY_NAMED_IAM \
     --region us-west-2

   # eu-west-1
   aws cloudformation create-stack --stack-name aiml-sec-test-stack \
     --template-body file://test-resources-cloudformation.yaml \
     --parameters file://parameters-eu-west-1.json \
     --capabilities CAPABILITY_NAMED_IAM \
     --region eu-west-1
   ```

2. Run assessment with multiple regions:
   ```bash
   aws stepfunctions start-execution \
     --state-machine-arn $STATE_MACHINE_ARN \
     --input '{
       "regions": ["us-west-2", "eu-west-1"],
       "services": ["bedrock", "sagemaker", "agentcore"]
     }'
   ```

---

## Cost Optimization Tips

1. **Stop notebooks when not in use**: Notebooks accrue charges even when idle
2. **Delete endpoints after testing**: Endpoints are the most expensive component
3. **Use spot instances**: For training jobs (not covered in this template)
4. **Set up billing alerts**: Monitor costs during testing
5. **Clean up promptly**: Delete the stack as soon as testing is complete

---

## Support

For issues with:
- **CloudFormation template**: Review the template and check AWS service quotas
- **Security checks**: Refer to the main repository documentation
- **AWS services**: Consult AWS documentation or support

---

## License

This testing infrastructure is provided as-is for security assessment purposes. Ensure compliance with your organization's AWS usage policies before deployment.
