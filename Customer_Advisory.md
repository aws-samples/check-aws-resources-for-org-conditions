© 2022 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
This work is licensed under a Creative Commons Attribution 4.0 International License.

# Customer Advisory

The code in this package provides a useful tool for scanning AWS accounts, in preparation for removal from an AWS organization. As with any code deployed into your infrastructure, it should be carefully reviewed for any risks that it may pose. This code deploys various AWS resources, including cross-account IAM roles to facilitate account scanning. As written, these roles have read-only permissions. If these role templates or any other portions of the code are modified, additional permissions may be intentionally or accidentally granted, and destructive potential may be introduced. Any changes must be thoroughly reviewed before use. 

AWS is responsible for securing the underlying infrastructure that supports the cloud and the services provided; while customers, acting either as data controllers or data processors, are responsible for any personal data they put in the cloud. The [shared responsibility model](https://aws.amazon.com/compliance/shared-responsibility-model/) illustrates the various responsibilities of AWS and our customers.

## Scanned Resource Types

The scanning performed by this code inspects AWS resources of various types, for dependencies on AWS Organizations conditional statements, or AWS Organizations API calls. Since AWS frequently releases new services, not all AWS resource types are scanned by this code. Only the following resource types are supported by this code:
- S3 BUCKETS
- SNS TOPICS
- SQS QUEUES
- CODEBUILD PROJECTS
- KMS KEYS
- ELASTIC SEARCH DOMAINS
- EFS FILESYSTEMS
- ECR REPOSITORIES
- SES IDENTITIES
- SECRETS MANAGER SECRETS
- MEDIASTORE CONTAINERS
- GLUE RESOURCE POLICIES
- IOT POLICIES
- GLACIER VAULTS
- IAM POLICIES
- IAM ROLES
- STACK POLICIES
- API GATEWAY APIS
- CLOUDWATCH EVENTBUS POLICIES
- LAMBDA RESOURCE POLICIES
- LAMBDA FN HANDLER CODE
- RAM SHARE ASSOCIATIONS
- CONFIG RULES
- CONFIG CONFORMANCE PACKS

### Optimize services scanned

For the resource types where you do not need the scanning just comment the services in the `ENABLED_REPORTS` section in the [code](src/dependencyChecker.py).

## More Reading

The full list of AWS resource types which support resource policies can be found [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html), in the “Resource-based policies” column:


This documentation should be compared with the list of resources supported by this code, in order to identify any gaps in coverage. Those additional resource types will need to be manually inspected, to ensure their resource policies do not depend on AWS Organizations conditions, or embed any code which relies on the AWS Organizations API.