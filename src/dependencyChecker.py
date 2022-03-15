# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0


# Import Pip Installed Modules:
from botocore.exceptions import ClientError
from openpyxl import Workbook
import multiprocessing
import boto3
import urllib3
import shutil
import zipfile

# Import standard Python Modules
import datetime as dt
import logging
import json
import csv
import sys
import os

####################
# Define the logger.
####################
log = logging.getLogger(__name__)

######################################
# Create AWS service client objects
######################################
SESSION = boto3.session.Session()
ORG_CLIENT = SESSION.client('organizations')
STS_CLIENT = SESSION.client('sts')
S3_CLIENT = SESSION.client('s3')

######################################
# Set Execution Variables / Runtime
######################################
# Get this account ID where this function will execute
ACCOUNT_ID = STS_CLIENT.get_caller_identity().get('Account', '000000000000')

# Gather the list of accounts from the Organizations API
log.debug("Gathering accounts attached to the specified AWS Organization.")

ACCOUNT_LIST = []
if os.getenv("USE_ORG_FOR_ACCOUNT_LIST") == "true":
    paginator = ORG_CLIENT.get_paginator('list_accounts')
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for acct in page.get('Accounts'):
            if acct is not None:
                ACCOUNT_LIST.append(acct['Id'])
else:
    account_env_var = os.getenv("ACCOUNT_LIST")
    if account_env_var:
        ACCOUNT_LIST = [item for item in account_env_var.split(",") if item]

# If this account is not in the account list, add it
if ACCOUNT_ID in ACCOUNT_LIST:
    pass
else:
    ACCOUNT_LIST.append(ACCOUNT_ID)

# Remove the following stale accounts from the list
# ACCOUNT_LIST.remove("")

print(f"{len(ACCOUNT_LIST)} discovered in Organizations\n")

log.info(
    f"The following account Ids are attached to the specified Org:"
    f"{json.dumps(ACCOUNT_LIST, indent=4)}"
)

# Set the default region, and a list of regions to query for resources.
CURRENT_REGION = os.environ['AWS_REGION']
region_env_var = os.getenv("REGION_LIST")
REGION_LIST = []
if region_env_var:
    REGION_LIST = [item for item in region_env_var.split(",") if item]

# Get todays date, and evalute if today is an odd day or even day
TODAY = dt.datetime.today()

# Set the Role Name this function will assume to access the other accounts.
try:
    ASSUME_ROLE = os.environ['ASSUME_ROLE_NAME']
except KeyError:
    ASSUME_ROLE = "check-resource-policies-role"
    # ASSUME_ROLE = "AWS-Lambda-Organizations-Reporting-Role"

# Set the destination report S3 bucket
try:
    REPORT_BUCKET = os.environ['REPORT_BUCKET']
except KeyError:
    REPORT_BUCKET = f"{ACCOUNT_ID}-org-check-resource-reports"

# Define the service checks that will run as part of this report
ENABLED_REPORTS = [
    "S3_BUCKETS",
    "SNS_TOPICS",
    "SQS_QUEUES",
    "CODEBUILD_PROJECTS",
    "KMS_KEYS",
    "ELASTIC_SEARCH_DOMAINS",
    "EFS_FILESYSTEMS",
    "ECR_REPOSITORIES",
    "SES_IDENTITIES",
    "SECRETS_MANAGER_SECRETS",
    "MEDIASTORE_CONTAINERS",
    "GLUE_RESOURCE_POLICIES",
    "IOT_POLICIES",
    "GLACIER_VAULTS",
    "IAM_POLICIES",
    "IAM_ROLES",
    "STACK_POLICIES",
    "API_GATEWAY_APIS",
    # "MEDIALIVE_CHANNELS",
    "CLOUDWATCH_EVENTBUS_POLICIES",
    "LAMBDA_RESOURCE_POLICIES",
    "LAMBDA_FN_HANDLER_CODE",
    "RAM_SHARE_ASSOCIATIONS",
    "CONFIG_RULES",
    "CONFIG_CONFORMANCE_PACKS"
]

# Urllib3 Connection Pool
URLLIB = urllib3.PoolManager()

# Construct Multiprocessing Pool
MP_SERVICE_QUEUE = []
MP_LAMBDA_QUEUE = []

# ################################################
# Handler / Helper Functions:
# ################################################


def DateHandler(DateObject):
    """ Common Date String Handler
    The purpose of this function is to take a passed DateTime formatted
    value, and apply a string filter to the value to convert the date into
    a standardized properly formatted string."
    """
    # Ensure all returned tag data is of type string
    DateString = ""
    try:
        if (
            DateObject is not None and isinstance(DateObject, dt.datetime) and bool(DateObject)
        ):
            log.debug("DateTime object found! Converting to string format...")
            DateString = DateObject.strftime(
                '%Y-%m-%d %H:%M:%S'
            )
            log.debug(f"Date converted to {type(DateString)}: {DateString}")
        else:
            log.debug(
                "Given object was not of type datetime, Object was of type "
                f"{type(DateObject)}... Type casting to string..."
            )
            DateString = f"{str(DateObject)}"
            log.debug(f"Date converted to {type(DateString)}: {DateString}")
        return DateString
    except Exception as e:
        log.error(str(e))
        raise e


def FileExtentionHandler(Runtime):
    """This function will determine the file extention for a lambda function
    based on the functions configured or compatible (layer) runtime"""
    if Runtime[0].find("nodejs") != -1:
        Ext = [".js"]
    elif Runtime[0].find("java") != -1:
        Ext = [".jar", ".war"]
    elif Runtime[0].find("python") != -1:
        Ext = [".py"]
    elif Runtime[0].find("dotnetcore") != -1:
        Ext = [".cs", ".csproj"]
    elif Runtime[0].find("go1") != -1:
        Ext = [".go"]
    elif Runtime[0].find("ruby") != -1:
        Ext = [".rb"]
    else:
        Ext = ["Custom"]
    log.debug(f"Determined appriorate file extentions: {Ext}")
    return Ext


def ParsePolicy(Policy, ResourceName):
    """This function will parse a given policy to check for
    organization dependencies. If found, the resource will be
    added to the Resource List"""
    HasOrgId = False
    HasOrgPath = False
    try:
        PolicyObject = json.dumps(Policy)
        # print(PolicyObject)
        if "aws:PrincipalOrgID" in PolicyObject:
            HasOrgId = True
            log.debug(f"OrgId dependency policy found on: {ResourceName}")
        if "aws:PrincipalOrgPaths" in PolicyObject:
            HasOrgPath = True
            log.debug(f"OrgPath dependency policy found on: {ResourceName}")
        if not HasOrgId and not HasOrgPath:
            log.debug(f"No policy dependencies found on: {ResourceName}")
        return HasOrgId, HasOrgPath
    except Exception as e:
        log.error(str(e))
        return False, False


def DownloadCode(Link, FnName):
    """This function will accept a download link and use URLLib3 to download
    the code archive to a file for later processing."""
    ResponseObj = {}
    DownloadPath = f"/tmp/{FnName}.zip"
    try:
        log.debug(f"Downloading source code to {DownloadPath}")
        with open(DownloadPath, 'wb') as file:
            SourceCode = URLLIB.request(
                'GET',
                Link,
                preload_content=False
            )
            shutil.copyfileobj(SourceCode, file)
            ResponseObj.update(
                filepath=DownloadPath,
                status=SourceCode.status
            )
        SourceCode.release_conn()
        print(f"Download completed with status: {ResponseObj.get('status')}")
        log.debug(f"Download completed with status: {ResponseObj.get('status')}")
    except Exception as e:
        print("An error was encountered while attempting to download:"f"{DownloadPath}\n{e}")
        log.error(
            "An error was encountered while attempting to download:"
            f"{DownloadPath}\n{e}"
        )
        ResponseObj.update(
            status=500,
            error=str(e)
        )
    return ResponseObj


def ParseCode(CodePath, HandlerName, Runtime):
    """This function will accept a zip code archive, decompress and parse the
    code to check for organization dependencies. If found, the resource will
    be added to the Resource List"""
    ResponseObj = {}
    HandlerPath = []
    ExtractionPath = ''
    try:
        OrgAPICall = False
        ExtractionPath = CodePath.split('.zip')[0]
        log.info(f"Extracting {CodePath} to {ExtractionPath}...")
        if not os.path.exists(ExtractionPath):
            os.mkdir(ExtractionPath)
            log.debug(f"{ExtractionPath} doesn't exist, creating directory...")
        # Extract the Zip
        with zipfile.ZipFile(
            CodePath,
            'r'
        ) as SourceCode:
            SourceCode.extractall(ExtractionPath)
            # log.debug(os.system(f"ls -lah {ExtractionPath}"))
        # Delete the Zip File after its been properly extracted
        os.remove(CodePath)
        print(f"Removing file: {CodePath}")
        # Set Handler FileNames
        # If HandlerName indicates a layer, perform a .py file discovery
        log.debug(f"Determining appropriate file extentions for {Runtime}...")
        ExtensionList = FileExtentionHandler(Runtime)
        log.debug(f"Runtime identified as {Runtime} --> {ExtensionList}")
        # print(f"Runtime identified as {Runtime} --> {ExtensionList}")
        if HandlerName == "LambdaLayer":
            files = [f for f in os.listdir(ExtractionPath) if os.path.isfile(f)]
            for f in files:
                if f.endswith(tuple(ExtensionList)):
                    HandlerPath.append(f)
        else:
            for ext in ExtensionList:
                FilePath = os.path.join(ExtractionPath, f"{HandlerName}{ext}")
                # print(f"Searching for {FilePath}")
                if os.path.exists(FilePath):
                    HandlerPath.append(FilePath)
        log.info(f"Identified {len(HandlerPath)} file(s) to parse: {HandlerPath}")
        # print(f"Identified {len(HandlerPath)} file(s) to parse: {HandlerPath}")
        # Open and read the Handler File
        OrgReferenceLines = []
        LineCount = 0
        if len(HandlerPath) > 0:
            for filename in HandlerPath:
                log.info(f"Opening {filename}...")
                # print(f"Opening {filename}...")
                HandlerCode = open(filename, 'r')
                # print("Reading file lines...")
                Lines = HandlerCode.readlines()
                # Parse each line of code and look for a call to organizations
                LineCount = 0
                OrgReferenceLines = []
                log.info(f"Parsing {filename}...")
                for line in Lines:
                    line = line.lower()
                    line = line.strip()
                    LineCount += 1
                    if 'organizations' in line:
                        log.info(f"Search reference found in {filename}:{LineCount} --> {line}")
                        # print(f"Search reference found in {filename}:{LineCount} --> {line}")
                        OrgAPICall = True
                        OrgReferenceLines.append(f"{filename}:{LineCount}")
                log.info(f"Closing {filename}...")
                HandlerCode.close()
                shutil.rmtree(ExtractionPath)
                log.debug(f"Removing {ExtractionPath}")
        else:
            OrgReferenceLines = []
            LineCount = 0
        ResponseObj.update(
            status=200,
            callsOrg=OrgAPICall,
            referenceList=OrgReferenceLines,
            total_lines=LineCount
        )
    except Exception as e:
        print("An error was encountered while attempting to parse:"
              f"{ExtractionPath}/{HandlerName}\n{e}")
        log.error(
            "An error was encountered while attempting to parse:"
            f"{ExtractionPath}/{HandlerName}\n{e}"
        )
        ResponseObj.update(
            status=500,
            error=str(e)
        )
    if os.path.exists(ExtractionPath):
        shutil.rmtree(ExtractionPath)
        print(f"Removing directory: {ExtractionPath}")
        log.debug(f"{ExtractionPath} still exists, removing directory...")
    return ResponseObj


def CountDeps(ResourceList):
    """This function will parse through the object collection, identifying
    only the resources that have the organization dependencies, and return
    a count of only those resources for the passed list."""
    Count = 0
    try:
        for resource in ResourceList:
            if resource.get('hasOrgId') or resource.get('hasOrgPath'):
                Count += 1
        return Count
    except Exception as e:
        log.error(str(e))
        raise e

# ################################################
# Assume Role:
# ################################################


def AssumeRole(RoleArn):
    """ Function that can be used to assume the
    another account Role to allow the collection and
    analysis of resource cleanup in other specified
    accounts.
    """
    log.debug("AssumeRole() called")
    try:
        log.info(f"Assuming Account Role: {RoleArn}")
        timestamp = DateHandler(dt.datetime.now())
        timestamp = timestamp.replace(" ", "-")
        timestamp = timestamp.replace(":", "-")
        AssumeRole = STS_CLIENT.assume_role(
            RoleArn=RoleArn,
            RoleSessionName=timestamp,
            DurationSeconds=900  # 15 min (lambda max)
        )
        return AssumeRole
    except Exception as e:
        log.exception(e)
        raise(e)

# ################################################
# CSV Report Generator:
# ################################################


def CSVReportWriter(ReportObj):
    """ Function that will create a CSV file from a specified
    data set and push the report to an appropriate S3 bucket."""

    # Ensure that the filename ends with the proper extention.
    Report = f"Organizations-Resource-Report-{dt.datetime.now()}.csv"
    # Set the CSV report headers
    ReportHeaders = [
        "Account Id",
        "Region",
        "Resource Type",
        "Resource Name",
        "Attached Policy",
        "OrgId Dependency",
        "OrgPath Dependency",
        "Notes"
    ]
    try:
        # Open the csv file as a writable object
        with open(f"/tmp/{Report}", 'w') as csv_file:
            # Create the CSV writer object
            CSVReport = csv.writer(
                csv_file,
                delimiter=',',
                quotechar='"',
                quoting=csv.QUOTE_MINIMAL
            )
            # Write the header row
            CSVReport.writerow(ReportHeaders)

            # Now loop through the object and write each row
            for obj in ReportObj:
                CSVReport.writerow([
                    obj.get('account'),
                    obj.get('region'),
                    obj.get('resource_type'),
                    obj.get('resource_name'),
                    obj.get('hasPolicy'),
                    obj.get('hasOrgId'),
                    obj.get('hasOrgPath'),
                    obj.get('notes')
                ])
        # Write the Report to S3
        # File Path and File Name will be the same, as the path is
        # the file name without any leading directories.
        FullBucketPath = REPORT_BUCKET.split("/")
        TargetBucket = FullBucketPath[0]
        if len(FullBucketPath) > 1:
            ObjectPath = f"{FullBucketPath[1]}/{Report}"
        else:
            ObjectPath = f"{Report}"
        Upload = S3_CLIENT.upload_file(
            f"/tmp/{Report}",  # File Path
            TargetBucket,  # Bucket to Upload to
            ObjectPath  # File Name
        )
        log.info(
            "Organizations dependency report written to S3 location: "
            f"{TargetBucket}/{ObjectPath}"
        )
        log.debug(
            f"{Upload}"
        )
    except Exception as e:
        log.error(str(e))
        raise e


# ################################################
# EXCEL Report Generator:
# ################################################
def XlsReportWriter(ReportObj):
    """ Function that will create an Excel file from a specified
    data set and push the report to an appropriate S3 bucket."""

    # Ensure that the filename ends with the proper extention.
    Report = f"Organizations-Resource-Report-{dt.datetime.now()}.xlsx"

    try:
        # Create a workbook
        WB = Workbook()

        # Rename the primary worksheet, and then create additional worksheets.
        WS = WB.active
        WS.title = "Metrics"
        WS['A1'] = "Service"
        WS['B1'] = "Total Resources Scanned"
        WS['C1'] = "Total Dependencies Found"

        # Create a tab for each of the services queried
        for cell, service in enumerate(ENABLED_REPORTS, start=2):
            # Search the Report Object for data for the service
            Data = ReportObj.get(service)
            # Write the totals to the metrics worksheet
            WS[f"A{cell}"] = service
            WS[f"B{cell}"] = len(Data)
            WS[f"C{cell}"] = CountDeps(Data)
            # print(Data)
            # print(cell)

            # If the data object has data, create the sheet
            if Data is not None and len(Data) > 0:
                # Create the service specific worksheet.
                worksheet = WB.create_sheet(service)
                worksheet['A1'] = "Account Id"
                worksheet['B1'] = "Region"
                worksheet['C1'] = "Resource Name"
                worksheet['D1'] = "Policy Attached"
                worksheet['E1'] = "OrgID Dependency Found"
                
                worksheet['F1'] = "OrgPath Dependency Found"
                worksheet['G1'] = "Dependent Component"
                worksheet['H1'] = "Notes"
                # Make some extra columns for roles
                if service == "IAM_ROLES":
                    worksheet['I1'] = "Role ID"
                    worksheet['J1'] = "Role Effect"
                    worksheet['K1'] = "Role Principals"
                    worksheet['L1'] = "Role Action"
                    worksheet['M1'] = "Role Attached Policies"
                    worksheet['N1'] = "Role Conditions"
                # Dump the data into the sheet
                for row, record in enumerate(Data, start=2):
                    # print(row)
                    worksheet[f"A{row}"] = record.get('account')
                    worksheet[f"B{row}"] = record.get('region')
                    worksheet[f"C{row}"] = record.get('resource_name')
                    worksheet[f"D{row}"] = "Yes" if record.get('hasPolicy') else "No"
                    worksheet[f"E{row}"] = "Yes" if record.get('hasOrgId') else "No"
                    worksheet[f"F{row}"] = "Yes" if record.get('hasOrgPath') else "No"
                    worksheet[f"G{row}"] = record.get('resource_type')
                    worksheet[f"H{row}"] = record.get('notes')
                    # Make some extra columns for roles
                    if service == "IAM_ROLES":
                        principals = ","
                        policies = ","
                        conditions = ","
                        actions = ","
                        worksheet[f"I{row}"] = record.get('id')
                        worksheet[f"J{row}"] = record.get('effect')
                        worksheet[f"K{row}"] = principals.join(record.get('principals'))
                        worksheet[f"L{row}"] = actions.join(record.get('action'))
                        worksheet[f"M{row}"] = policies.join(record.get('policies'))
                        worksheet[f"N{row}"] = conditions.join(record.get('conditions'))
        # Save the file
        WB.save(f"/tmp/{Report}")

        # Write the Report to S3
        # File Path and File Name will be the same, as the path is
        # the file name without any leading directories.
        FullBucketPath = REPORT_BUCKET.split("/")
        TargetBucket = FullBucketPath[0]
        if len(FullBucketPath) > 1:
            ObjectPath = f"{FullBucketPath[1]}/{Report}"
        else:
            ObjectPath = f"{Report}"
        Upload = S3_CLIENT.upload_file(
            f"/tmp/{Report}",  # File Path
            TargetBucket,  # Bucket to Upload to
            ObjectPath  # File Name
        )
        log.info(
            "Organizations dependency report written to S3 location: "
            f"{TargetBucket}/{ObjectPath}"
        )
        log.debug(
            f"{Upload}"
        )
    except Exception as e:
        log.error(str(e))
        raise e

# ################################################
# Report Service Queries:
# ################################################
# --------------------
# S3 Bucket Resources
# --------------------


def QueryS3(Session, S3ResourceList, Account="000000000000"):
    """Query S3 for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "S3"
    # Fetch resources and check for Org dependencies
    ServiceClient = Session.client(service_name=f"{Service.lower()}")
    log.info(f"Querying {Service} for applicable resources:")
    print(f"Querying {Service} for applicable resources:")
    # Get a list of all resources
    try:
        ResourceList = ServiceClient.list_buckets()
    except Exception as e:
        log.error(
            f"An error occurred attempting to list buckets "
            f"{Service} policy data from {Account} :\n"
            f"{e}"
        )
    if ResourceList is not None and 'Buckets' in ResourceList:
        try:
            for bucket in ResourceList.get('Buckets', None):
                ResourceName = bucket.get('Name', None)
                # Gather resource policy if applicable
                log.debug(f"Scanning {ResourceName}...")
                # Attempt to fetch the policy
                try:
                    ResourcePolicy = ServiceClient.get_bucket_policy(
                        Bucket=ResourceName
                    ).get('Policy', None)
                    # print(ResourcePolicy)
                except Exception as e:
                    ResourcePolicy = None
                    log.debug(str(e))
                # If a bucket policy was found, check it for org statements
                if ResourcePolicy is not None:
                    log.debug(ResourcePolicy)
                    HasOrgId, HasOrgPath = ParsePolicy(
                        ResourcePolicy,
                        ResourceName
                    )
                    HasPolicy = True
                else:
                    log.debug(f"No policy attached to: {ResourceName}")
                    HasPolicy = False
                    HasOrgId = False
                    HasOrgPath = False
                ResponseObject.append(
                    {
                        "account": Account,
                        "region": "Global",
                        "resource_type": "S3 Bucket Policy",
                        "resource_name": ResourceName,
                        "hasPolicy": HasPolicy,
                        "hasOrgId": HasOrgId,
                        "hasOrgPath": HasOrgPath,
                        "notes": ""
                    }
                )
        except Exception as e:
            log.error(
                f"An error occurred attempting to gather "
                f"{Service} policy data from {Account}:\n"
                f"{e}"
            )
    print('\n')
    S3ResourceList.extend(ResponseObject)

# --------------------
# SNS Topic Resources
# --------------------


def QuerySNS(Session, SNSResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query SNS Topics for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "SNS"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.list_topics()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list topics "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'Topics' in ResourceList:
            try:
                for topic in ResourceList.get('Topics', None):
                    # Gather the topic policy and construct the object list
                    # print(f"*******{topic}**********")
                    ResourceName = topic.get('TopicArn')
                    ResourceName = ResourceName.split(f"{Account}:")[1]
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = ServiceClient.get_topic_attributes(
                            TopicArn=topic.get('TopicArn', None)
                        ).get('Attributes', None).get('Policy', None)
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If a topic policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "SNS Topic Resource Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    SNSResourceList.extend(ResponseObject)

# --------------------
# SQS Queue Resources
# --------------------


def QuerySQS(Session, SQSResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query SQS Queues for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "SQS"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.list_queues()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list queues "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'QueueUrls' in ResourceList:
            try:
                for queue in ResourceList.get('QueueUrls', None):
                    # Gather the queue policy and construct the object list
                    # print(f"*******{queue}**********")
                    ResourceName = queue.split(f"{Account}/")[1]
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = ServiceClient.get_queue_attributes(
                            QueueUrl=queue,
                            AttributeNames=['Policy']
                        ).get('Attributes', None).get('Policy', None)
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If a queue policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "SQS Queue Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    SQSResourceList.extend(ResponseObject)

# --------------------
# CodeBuild Resources
# --------------------


def QueryCodeBuild(Session, CBResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query CodeBuild Projects for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "CodeBuild"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all project resources
        try:
            ProjectList = ServiceClient.list_projects().get('projects')
            if len(ProjectList) > 0:
                ResourceList = ServiceClient.batch_get_projects(
                    names=ProjectList
                )
            else:
                ResourceList = None
            # Get a list of all report group resources
            ReportGroups = ServiceClient.list_report_groups().get('reportGroups')
            if len(ReportGroups) > 0:
                ReportGroupList = ServiceClient.batch_get_report_groups(
                    reportGroupArns=ReportGroups
                )
            else:
                ReportGroupList = None
        except Exception as e:
            log.error(
                f"An error occurred attempting to list projects "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        # Scan Projects
        if ResourceList is not None and 'projects' in ResourceList:
            try:
                for project in ResourceList.get('projects', None):
                    # Gather the CodeBuild policy and construct the object list
                    # print(f"*******{project}**********")
                    ResourceName = project.get('name')
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        # Resource policies can only be allied through the CLI
                        ResourcePolicy = ServiceClient.get_resource_policy(
                            resourceArn=project.get("arn")
                        ).get('policy')
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If a project policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "CodeBuild Project Resource Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
        # Scan Report Groups
        if ReportGroupList is not None and 'reportGroups' in ReportGroupList:
            try:
                for group in ReportGroupList.get('reportGroups', None):
                    # Gather the Group policy and construct the object list
                    # print(f"*******{group}**********")
                    GroupName = group.get('name')
                    log.debug(f"Scanning {GroupName}...")
                    # Attempt to fetch the group policy
                    try:
                        # Group policies can only be allied through the CLI
                        GroupPolicy = ServiceClient.get_resource_policy(
                            resourceArn=group.get("arn")
                        ).get('policy')
                        # print(GroupPolicy)
                    except Exception as e:
                        GroupPolicy = None
                        log.debug(str(e))
                    # If a group policy was found, check it for org statements
                    if GroupPolicy is not None:
                        log.debug(GroupPolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            GroupPolicy,
                            GroupName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {GroupName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "CodeBuild Report Group Policy",
                            "resource_name": GroupName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} group policy data from {Account} in {region}:"
                    f"\n {e}"
                )
    print('\n')
    CBResourceList.extend(ResponseObject)

# --------------------
# KMS Key Resources
# --------------------


def QueryKMS(Session, KMSResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query KMS Keys for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "KMS"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.list_keys()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list keys "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'Keys' in ResourceList:
            try:
                for key in ResourceList.get('Keys', None):
                    # Gather the key policy and construct the object list
                    # print(f"*******{key}**********")
                    ResourceName = key.get('KeyId')
                    log.debug(f"Scanning {ResourceName}...")
                    # print(ResourceName)
                    # Attempt to fetch the policy
                    try:
                        # KeyList = ServiceClient.list_key_policies(
                        #     KeyId=ResourceName
                        # )
                        # print(KeyList)
                        ResourcePolicy = ServiceClient.get_key_policy(
                            KeyId=ResourceName,
                            PolicyName='default'
                        ).get('Policy')
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If a kms key policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "KMS Key Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    KMSResourceList.extend(ResponseObject)

# -------------------------------
# Elastic Search Domain Resources
# -------------------------------


def QueryElasticSearch(Session, ESDResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query Elastic Search Domains for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "ES"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.list_domain_names()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list domain names "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'DomainNames' in ResourceList:
            try:
                for domain in ResourceList.get('DomainNames', None):
                    # Gather the ES Domain policy and construct the object list
                    # print(f"*******{domain}**********")
                    ResourceName = domain.get('DomainName')
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = ServiceClient.describe_elasticsearch_domain(
                            DomainName=ResourceName
                        ).get('DomainStatus', None).get('AccessPolicies', None)
                        print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If a domain policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "Elastic Search Domain Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    ESDResourceList.extend(ResponseObject)


# --------------------
# EFS FileSystem Resources
# --------------------
def QueryEFS(Session, EFSResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query EFS FileSystems for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "EFS"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.describe_file_systems()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list file systems "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'FileSystems' in ResourceList:
            try:
                for fs in ResourceList.get('FileSystems', None):
                    # Gather the filesystem policy and construct the object list
                    # print(f"*******{fs}**********")
                    ResourceName = fs.get('FileSystemId')
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = ServiceClient.describe_file_system_policy(
                            FileSystemId=ResourceName
                        ).get('Policy')
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If a filesystem policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "EFS File System Resource Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    EFSResourceList.extend(ResponseObject)

# --------------------
# ECR Repository Resources
# --------------------


def QueryECR(Session, ECRResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query ECR Repositories for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "ECR"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.describe_repositories()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list repositories "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'repositories' in ResourceList:
            try:
                for repo in ResourceList.get('repositories', None):
                    # Gather the repository policy and construct the object list
                    # print(f"*******{repo}**********")
                    ResourceName = repo.get('repositoryName')
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = ServiceClient.get_repository_policy(
                            repositoryName=ResourceName
                        ).get('policyText')
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If a repository policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "ECR Repository Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    ECRResourceList.extend(ResponseObject)

# --------------------
# SES Resources
# --------------------


def QuerySES(Session, SESResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query SES for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "SES"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.list_identities()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list identities "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'Identities' in ResourceList:
            try:
                for identity in ResourceList.get('Identities', None):
                    # Gather the identity policy and construct the object list
                    # print(f"*******{identity}**********")
                    ResourceName = identity
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        PolicyList = ServiceClient.list_identity_policies(
                            Identity=ResourceName
                        ).get('PolicyNames')
                        ResourcePolicy = ServiceClient.get_identity_policies(
                            Identity=ResourceName,
                            PolicyNames=PolicyList
                        ).get('Policies')
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If a SES Identity policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "SES Identity Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    SESResourceList.extend(ResponseObject)

# --------------------
# Secrets Mgr Resources
# --------------------


def QuerySecrets(Session, SMResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query Secrets Manager secrets for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "SecretsManager"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.list_secrets()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list secrets "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'SecretList' in ResourceList:
            try:
                for secret in ResourceList.get('SecretList', None):
                    # Gather the secret policy and construct the object list
                    # print(f"*******{secret}**********")
                    ResourceName = secret.get('Name')
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = ServiceClient.get_resource_policy(
                            SecretId=secret.get('ARN')
                        ).get('ResourcePolicy')
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If a repository policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "SecretsManager Secret Resource Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    SMResourceList.extend(ResponseObject)

# --------------------
# MediaStore Resources
# --------------------


def QueryMediaStore(Session, MSCResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query MediaStore Containers for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "MediaStore"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.list_containers()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list containers "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'Containers' in ResourceList:
            try:
                for container in ResourceList.get('Containers', None):
                    # Gather the mediastore container policy and construct the object list
                    # print(f"*******{container}**********")
                    ResourceName = container.get('Name')
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = ServiceClient.get_container_policy(
                            ContainerName=ResourceName
                        ).get('Policy')
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If a container policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "MediaStore Container Resource Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    MSCResourceList.extend(ResponseObject)

# --------------------
# Glue Resources
# --------------------


def QueryGlue(Session, GlueResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query Glue Resources for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "Glue"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.get_resource_policies()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list resource policies "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'GetResourcePoliciesResponseList' in ResourceList:
            try:
                for policy in ResourceList.get('GetResourcePoliciesResponseList', None):
                    # Gather the glue resource policy and construct the object list
                    # print(f"*******{policy}**********")
                    ResourceName = policy.get('PolicyHash')
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = policy.get('PolicyInJson')
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If a container policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "Glue Resource Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    GlueResourceList.extend(ResponseObject)

# --------------------
# IOT Resources
# --------------------


def QueryIoT(Session, IOTResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query IoT Resources for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "IoT"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.list_policies()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list policies "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'policies' in ResourceList:
            try:
                for policy in ResourceList.get('policies', None):
                    # Gather the glue resource policy and construct the object list
                    # print(f"*******{policy}**********")
                    ResourceName = policy.get('policyName')
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = ServiceClient.get_policy(
                            policyName=ResourceName
                        ).get('policyDocument')
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If an IoT policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "IoT Resource Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    IOTResourceList.extend(ResponseObject)

# --------------------
# Glacier Storage Resources
# --------------------


def QueryGlacier(Session, GVResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query Glacier Vaults for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "Glacier"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.list_vaults()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list vaults "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'VaultList' in ResourceList:
            try:
                for vault in ResourceList.get('VaultList', None):
                    # Gather the Glacier vault policy and construct the object list
                    # print(f"*******{vault}**********")
                    ResourceName = vault.get('VaultName')
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = ServiceClient.get_vault_access_policy(
                            vaultName=ResourceName
                        ).get('policy').get('Policy')
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If a glacier vault policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "Glacier Vault Access Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    GVResourceList.extend(ResponseObject)

# --------------------
# IAM Policy Resources
# --------------------


def QueryIAMPolicies(Session, IAMResourceList, Account="000000000000"):
    """Query IAM Policies for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "IAM"
    # Fetch resources and check for Org dependencies
    ServiceClient = Session.client(service_name=f"{Service.lower()}")
    log.info(f"Querying {Service} for applicable resources:")
    print(f"Querying {Service} for applicable resources:")
    # Get a list of all resources
    try:
        ResourceList = ServiceClient.list_policies(
            Scope='Local'
        )
    except Exception as e:
        log.error(
            f"An error occurred attempting to list policies "
            f"{Service} policy data from {Account} :\n"
            f"{e}"
        )
    if ResourceList is not None and 'Policies' in ResourceList:
        try:
            for policy in ResourceList.get('Policies', None):
                ResourceName = policy.get('PolicyName', None)
                # Gather resource policy if applicable
                log.debug(f"Scanning {ResourceName}...")
                # Attempt to fetch the policy
                try:
                    ResourcePolicy = ServiceClient.get_policy_version(
                        PolicyArn=policy.get('Arn'),
                        VersionId=policy.get('DefaultVersionId')
                    ).get('PolicyVersion').get('Document')
                    # print(ResourcePolicy)
                except Exception as e:
                    ResourcePolicy = None
                    log.debug(str(e))
                # If an IAM policy was found, check it for org statements
                if ResourcePolicy is not None:
                    log.debug(ResourcePolicy)
                    HasOrgId, HasOrgPath = ParsePolicy(
                        ResourcePolicy,
                        ResourceName
                    )
                    HasPolicy = True
                else:
                    log.debug(f"No policy attached to: {ResourceName}")
                    HasPolicy = False
                    HasOrgId = False
                    HasOrgPath = False
                ResponseObject.append(
                    {
                        "account": Account,
                        "region": "Global",
                        "resource_type": "IAM Policy",
                        "resource_name": ResourceName,
                        "hasPolicy": HasPolicy,
                        "hasOrgId": HasOrgId,
                        "hasOrgPath": HasOrgPath,
                        "notes": ""
                    }
                )
        except Exception as e:
            log.error(
                f"An error occurred attempting to gather "
                f"{Service} policy data from {Account}:\n"
                f"{e}"
            )
    print('\n')
    IAMResourceList.extend(ResponseObject)


def QueryIAMRoles(Session, RoleResourceList, Account="000000000000"):
    """Query IAM Policies for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "IAM"
    # Fetch resources and check for Org dependencies
    ServiceClient = Session.client(service_name=f"{Service.lower()}")
    log.info(f"Querying {Service} for applicable resources:")
    print(f"Querying {Service} for applicable resources:")
    # Get a list of all resources
    try:
        ResourceList = ServiceClient.list_roles()
    except Exception as e:
        log.error(
            f"An error occurred attempting to list roles "
            f"{Service} policy data from {Account} :\n"
            f"{e}"
        )
    if ResourceList is not None and 'Roles' in ResourceList:
        try:
            for role in ResourceList.get('Roles', None):
                ResourceName = role.get('RoleName', None)
                # Gather resource role if applicable
                log.debug(f"Scanning {ResourceName}...")
                # print(f"Scanning {ResourceName}...")
                # Attempt to parse the role policy statements
                AssumeRolePolicy = role.get('AssumeRolePolicyDocument')
                RolePolicyStatements = AssumeRolePolicy.get('Statement')
                # print(f"AssumeRolePolicyStatement: {RolePolicyStatements}")
                RolePrincipals = []
                RolePolicies = []
                RoleConditions = []
                effect = ''
                action = ''
                # Parse each policy statement attached to the role
                # and collect policy Effects and Actions
                for policy in RolePolicyStatements:
                    effect = policy.get('Effect')
                    # print(f"Effect: {effect}")
                    action = policy.get('Action')
                    # print(f"Action: {action}")
                    # Now pull the role principals
                    PrincipalList = policy.get('Principal', None)
                    if PrincipalList is not None:
                        for k, v in PrincipalList.items():
                            if isinstance(v, str):
                                RolePrincipals.append(v)
                            elif isinstance(v, list):
                                for r in v:
                                    RolePrincipals.append(r)
                    # print(f"Principals: {RolePrincipals}")
                    # Next Get role conditions
                    ConditionList = policy.get('Condition')
                    if ConditionList is not None:
                        for k, v in ConditionList.items():
                            conditions = []
                            name = k
                            for c in v:
                                conditions.append(c)
                            separator = ","
                            RoleConditions.append(
                                f"{name}:{separator.join(conditions)}"
                            )
                    # print(f"Conditions: {RoleConditions}")
                # Get Policies attached to the role
                AttachedPolicies = ServiceClient.list_attached_role_policies(
                    RoleName=ResourceName
                ).get('AttachedPolicies')
                # print(f"Attached Policies: {AttachedPolicies}")
                for policy in AttachedPolicies:
                    RolePolicies.append(policy.get('PolicyName'))
                # print(f"Role Policies: {RolePolicies}")
                # If an IAM policy was found, check it for org statements
                if RoleConditions is not None:
                    log.debug(RoleConditions)
                    HasOrgId, HasOrgPath = ParsePolicy(
                        RoleConditions,
                        ResourceName
                    )
                    HasPolicy = True
                else:
                    log.debug(f"No role conditions defined in: {ResourceName}")
                    HasPolicy = False
                    HasOrgId = False
                    HasOrgPath = False
                ResponseObject.append(
                    {
                        "account": Account,
                        "region": "Global",
                        "resource_type": "IAM Role",
                        "resource_name": ResourceName,
                        "hasPolicy": HasPolicy,
                        "hasOrgId": HasOrgId,
                        "hasOrgPath": HasOrgPath,
                        "notes": "",
                        "id": role.get('RoleId'),
                        "principals": RolePrincipals,
                        "effect": effect,
                        "action": action,
                        "policies": RolePolicies,
                        "conditions": RoleConditions
                    }
                )
        except Exception as e:
            log.error(
                f"An error occurred attempting to gather "
                f"{Service} role data from {Account}:\n"
                f"{e}"
            )
    print('\n')
    RoleResourceList.extend(ResponseObject)

# --------------------
# CF Stack Policy Resources
# --------------------


def QueryCF(Session, CFResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query CloudFormation Stack Policies for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "CloudFormation"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.list_stacks()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list stacks "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'StackSummaries' in ResourceList:
            try:
                for stack in ResourceList.get('StackSummaries', None):
                    # Gather the cf stack policy and construct the object list
                    # print(f"*******{stack}**********")
                    ResourceName = stack.get('StackName')
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = ServiceClient.get_stack_policy(
                            StackName=ResourceName
                        ).get('StackPolicyBody', None)
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If a stack policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "CloudFormation Stack Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    CFResourceList.extend(ResponseObject)

# --------------------
# API Stack Policy Resources
# --------------------


def QueryAPI(Session, APIResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query API Gateway Policies for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "APIGateway"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.get_rest_apis()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list REST APIs "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'items' in ResourceList:
            try:
                for api in ResourceList.get('items', None):
                    # Gather the API GW policy and construct the object list
                    # print(f"*******{items}**********")
                    ResourceName = api.get('name')
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = api.get('policy', None)
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If an api policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "API Gateway Restful API Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    APIResourceList.extend(ResponseObject)

# --------------------
# MediaLive Resources
# --------------------


def QueryMediaLive(Session, MLResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query MediaLive Policies for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "MediaLive"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.list_channels()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list channels "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'Channels' in ResourceList:
            try:
                for channel in ResourceList.get('Channels', None):
                    # Gather the MediaLive Channel policy and construct the object list
                    # print(f"*******{channel}**********")
                    ResourceName = channel.get('Id')
                    log.debug(f"Scanning {ResourceName}...")
                    # Return channel Ids (Inquiring on how to fetch policies)
                    HasPolicy = False
                    HasOrgId = False
                    HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "MediaLive Channel Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    MLResourceList.extend(ResponseObject)

# --------------------------
# CloudWatch Event Resources
# --------------------------


def QueryCloudWatch(Session, CWResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query CloudWatch Event Policies for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "Events"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.list_event_buses()
        except Exception as e:
            log.error(
                f"An error occurred attempting to list event buses "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'EventBuses' in ResourceList:
            try:
                for eventbus in ResourceList.get('EventBuses', None):
                    # Gather the Event Bus policy and construct the object list
                    # print(f"*******{eventbus}**********")
                    ResourceName = eventbus.get('Name')
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = eventbus.get('Policy', None)
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If an event bus policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "CloudWatch Event Bus Policy",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    CWResourceList.extend(ResponseObject)

# ----------------------
# Lambda Layer Resources
# ----------------------


def QueryLambdaHandlers(LambdaResource, HandlerResourceList):
    """Query Lambda and Layer Handler code for calls to the Organizations API"""
    # Instantiate Local Results List to store return results
    ResponseObject = {}
    ResourceName = None
    log.info(f"Querying Lambda Handler Code for applicable API call code references:")
    print(f"Querying Lambda Handler Code for applicable API call code references:")
    try:
        # Collect function metadata
        FunctionNotes = json.loads(LambdaResource.get('notes'))
        log.debug(f"Starting Check on {FunctionNotes}...")
        ResourceName = LambdaResource.get('resource_name')
        Handler = FunctionNotes.get('handler')
        DownloadURL = FunctionNotes.get('url')
        Runtime = FunctionNotes.get('runtime')
        if DownloadURL is not None:
            log.debug(
                f"DownloadLink found for {ResourceName}, "
                "attempting to download Fn source code..."
            )
            # Download the Function Source Code
            SourceCode = DownloadCode(DownloadURL, ResourceName)
            print(f"Status of Download is: {SourceCode.get('status')}")
            print(os.system("ls -lah /tmp"))
            if SourceCode.get('status') == 500:
                Error = SourceCode.get('error')
                log.error(Error)
                print(f"\n\n** {Error} **")
                sys.exit(1)
            else:
                log.debug(
                    f"Source code download of {ResourceName}, "
                    "completed, attempting to decompress and parse code:"
                    f"\n{SourceCode}"
                )
            # Decompress and Parse
            log.debug("Attempting to parse downloaded files...")
            CheckOrgAPICall = ParseCode(
                SourceCode.get('filepath'),
                Handler,
                Runtime
            )
            print(f"Status of Parse is: {CheckOrgAPICall.get('status')}")
            if CheckOrgAPICall.get('status') == 500:
                Error = CheckOrgAPICall.get('error')
                log.error(Error)
                print(f"\n\n** {Error} **")
                sys.exit(1)
            else:
                print(
                    f"Source code file parse completed:"
                    f"\n{CheckOrgAPICall}"
                )
                log.debug(
                    f"Source code file parse completed:"
                    f"\n{CheckOrgAPICall}"
                )
            # Set the result resource_type
            if "Lambda Function" in LambdaResource.get('resource_type'):
                CodeType = "Lambda Function Handler Code"
            else:
                CodeType = "Lambda Layer Handler Code"
            # Add the results to the response object
            ResponseObject = {
                "account": LambdaResource.get('account'),
                "region": LambdaResource.get('region'),
                "resource_type": CodeType,
                "resource_name": f"{ResourceName}/{Handler}",
                "hasPolicy": False,
                "hasOrgId": CheckOrgAPICall.get('callsOrg'),
                "hasOrgPath": CheckOrgAPICall.get('callsOrg'),
                "notes": (
                    f"{len(CheckOrgAPICall.get('referenceList', []))}"
                    f"/{CheckOrgAPICall.get('total_lines', 0)}"
                    " lines referenced the search term 'Organizations':\n"
                    f"{CheckOrgAPICall.get('referenceList', 0)}"
                )
            }
    except Exception as e:
        log.error(
            f"An error occurred attempting to parse lambda function handler "
            f"code data from {ResourceName}:\n"
            f"{e}"
        )
    # print('\n')
    # print(os.system("du -h -d 1"))
    HandlerResourceList.append(ResponseObject)


def QueryLambda(Session, LambdaResourceList, FnHandlerResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query Lambda and Layers Policies for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    FnProcessManager = multiprocessing.Manager()
    HandlerResourceList = FnProcessManager.list()
    Service = "Lambda"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all Lambda Function resources
        try:
            ResourceList = []
            paginator = ServiceClient.get_paginator('list_functions')
            page_iterator = paginator.paginate()
            for page in page_iterator:
                for lambdafun in page.get('Functions'):
                    if lambdafun is not None:
                        ResourceList.append(lambdafun)

            print(f"Lambda Resource List Length in Query Lambda is {len(ResourceList)}")
        except Exception as e:
            log.error(
                f"An error occurred attempting to list functions "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and len(ResourceList) > 0:
            try:
                for fn in ResourceList:
                    # Gather the Lambda policy and construct the object list
                    # print(f"*******{fn}**********")
                    ResourceName = fn.get('FunctionName')
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = ServiceClient.get_policy(
                            FunctionName=ResourceName
                        ).get('Policy')
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If an function policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                        # Determine Handler File Name
                    HandlerFile = fn.get('Handler').split('.')[0]
                    ResponseObjRecord = {
                        "account": Account,
                        "region": region,
                        "resource_type": "Lambda Function Resource Policy",
                        "resource_name": ResourceName,
                        "hasPolicy": HasPolicy,
                        "hasOrgId": HasOrgId,
                        "hasOrgPath": HasOrgPath,
                        "notes": json.dumps(
                            {
                                "handler": f"{HandlerFile}",
                                "url": ServiceClient.get_function(
                                    FunctionName=ResourceName
                                ).get('Code').get('Location', None),
                                "runtime": [fn.get('Runtime')]
                            }
                        )
                    }
                    # Add the Lambda Resource to the LambdaResourceList
                    ResponseObject.append(ResponseObjRecord)
                    # Call the function to check the lambda code while the dl url is fresh
                    if "LAMBDA_FN_HANDLER_CODE" in ENABLED_REPORTS and (Account == "157385605725" or Account == "596799782469"):
                        if len(MP_LAMBDA_QUEUE) >= 4:
                            for proc in MP_LAMBDA_QUEUE:
                                proc.join()
                                proc.close()
                                MP_LAMBDA_QUEUE.remove(proc)
                                print(f"Closing {proc.name}")
                        CodeCheckProcess = multiprocessing.Process(
                            name=f"Lambda-{ResourceName} Code Check",
                            target=QueryLambdaHandlers,
                            args=(ResponseObjRecord, HandlerResourceList)
                        )
                        MP_LAMBDA_QUEUE.append(CodeCheckProcess)
                        print(f"Starting Lambda-{ResourceName} Fn Code Check Process...")
                        CodeCheckProcess.start()
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
        # Get a list of all Lambda Layer resources
        ResourceList = ServiceClient.list_layers()
        if ResourceList is not None and 'Layers' in ResourceList:
            try:
                for layer in ResourceList.get('Layers', None):
                    # Gather the Lambda Layer policy and construct the object list
                    # print(f"*******{layer}**********")
                    ResourceName = layer.get('LayerName')
                    log.debug(f"Scanning {ResourceName}...")
                    # Attempt to fetch the policy
                    try:
                        ResourcePolicy = ServiceClient.get_layer_version_policy(
                            LayerName=ResourceName,
                            VersionNumber=layer.get('LatestMatchingVersion').get('Version')
                        ).get('Policy')
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If an a Lambda Layer Policy was found, check it for org statements
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        HasOrgId, HasOrgPath = ParsePolicy(
                            ResourcePolicy,
                            ResourceName
                        )
                        HasPolicy = True
                    else:
                        log.debug(f"No policy attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObjRecord = {
                        "account": Account,
                        "region": region,
                        "resource_type": "Lambda Layer Resource Policy",
                        "resource_name": ResourceName,
                        "hasPolicy": HasPolicy,
                        "hasOrgId": HasOrgId,
                        "hasOrgPath": HasOrgPath,
                        "notes": json.dumps(
                            {
                                "handler": "LambdaLayer",
                                "url": ServiceClient.get_layer_version(
                                    LayerName=ResourceName,
                                    VersionNumber=layer.get('LatestMatchingVersion').get('Version')
                                ).get('Content').get('Location'),
                                "runtime": layer.get('LatestMatchingVersion').get('CompatibleRuntimes')
                            }
                        )
                    }
                    ResponseObject.append(ResponseObjRecord)
                    # Call the function to check the lambda code while the dl url is fresh
                    if "LAMBDA_FN_HANDLER_CODE" in ENABLED_REPORTS and (Account == "157385605725" or Account == "596799782469"):
                        if len(MP_LAMBDA_QUEUE) >= 4:
                            for proc in MP_LAMBDA_QUEUE:
                                proc.join()
                                proc.close()
                                MP_LAMBDA_QUEUE.remove(proc)
                                print(f"Closing {proc.name}")
                        CodeCheckProcess = multiprocessing.Process(
                            name=f"Lambda-{ResourceName} Code Check",
                            target=QueryLambdaHandlers,
                            args=(ResponseObjRecord, HandlerResourceList)
                        )
                        MP_LAMBDA_QUEUE.append(CodeCheckProcess)
                        print(f"Starting Lambda-{ResourceName} Fn Code Check Process...")
                        CodeCheckProcess.start()
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    for proc in MP_LAMBDA_QUEUE:
        proc.join()
        proc.close()
        MP_LAMBDA_QUEUE.remove(proc)
        print(f"Closing {proc.name}")
    LambdaResourceList.extend(ResponseObject)
    FnHandlerResourceList.extend(HandlerResourceList)

# --------------------
# RAM Shared Resources
# --------------------


def QueryRAM(Session, RAMResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query RAM Shared Resources for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "RAM"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} in {region} for applicable resources:")
        print(f"Querying {Service} in {region} for applicable resources:")
        # Get a list of all resource share associations
        try:
            ResourceList = ServiceClient.get_resource_share_associations(associationType='PRINCIPAL')
            print(f" RAM Resource List in {Account} is {ResourceList}")
        except Exception:
            continue
        if ResourceList is not None and 'resourceShareAssociations' in ResourceList:
            try:
                for resourceShareAssociation in ResourceList.get('resourceShareAssociations', None):
                    # Gather the RAM Share Associations and construct the object list
                    # print(f"*******{resourceShareAssociations}**********")
                    ResourceName = resourceShareAssociation.get('resourceShareName')
                    log.debug(f"Scanning {ResourceName}...")
                    print(f"Scanning {ResourceName}...")
                    # Attempt to fetch the association
                    try:
                        ResourcePolicy = resourceShareAssociation.get('associatedEntity')
                        # print(ResourcePolicy)
                    except Exception as e:
                        ResourcePolicy = None
                        log.debug(str(e))
                    # If an association was found, check it for org statements
                    HasOrgId = False
                    HasOrgPath = False
                    if ResourcePolicy is not None:
                        log.debug(ResourcePolicy)
                        print(f" RAM Resource Association POLICY is ##### {ResourcePolicy}")
                        PolicyObject = json.dumps(ResourcePolicy)
                        print(f" RAM Resource Association POLICY Object is ##### {PolicyObject}")
                        if "organization" in PolicyObject:
                            HasOrgId = True
                            log.debug(f"OrgId dependency policy found on: {ResourceName}")
                        if "ou-" in PolicyObject:
                            HasOrgPath = True
                            log.debug(f"OrgPath dependency policy found on: {ResourceName}")
                        if not HasOrgId and not HasOrgPath:
                            log.debug(f"No policy dependencies found on: {ResourceName}")
                        HasPolicy = True
                    else:
                        log.debug(f"No association attached to: {ResourceName}")
                        HasPolicy = False
                        HasOrgId = False
                        HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "RAM Shares",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    RAMResourceList.extend(ResponseObject)

# ----------------------
# Config Resources
# ----------------------


def QueryConfigRules(Session, ConfigRuleResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query Config Rules for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "Config"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} Rules in {region} for applicable resources:")
        print(f"Querying {Service} Rules in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.describe_organization_config_rules()
        except Exception as e:
            log.error(
                f"An error occurred attempting to gather Org-based Config Rules "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'OrganizationConfigRules' in ResourceList:
            try:
                for rule in ResourceList.get('OrganizationConfigRules', None):
                    # Gather the config rule policy and construct the object list
                    # print(f"*******{rule}**********")
                    ResourceName = rule.get('OrganizationConfigRuleName')
                    log.debug(f"Scanning {ResourceName}...")
                    HasPolicy = False
                    HasOrgId = False
                    HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "Config Organization Rules",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    ConfigRuleResourceList.extend(ResponseObject)


def QueryConfigCPs(Session, ConfigCPResourceList, Account="000000000000", Regions=REGION_LIST):
    """Query Config Conformance Packs for Organizations dependencies"""
    # Instantiate Local Results List to store return results
    ResponseObject = []
    ResourceList = None
    Service = "Config"
    # Interate through each region, and gather/examine resources
    for region in Regions:
        ServiceClient = Session.client(
            service_name=f"{Service.lower()}",
            region_name=region
        )
        log.info(f"Querying {Service} Conformance Packs in {region} for applicable resources:")
        print(f"Querying {Service} Conformance Packs in {region} for applicable resources:")
        # Get a list of all resources
        try:
            ResourceList = ServiceClient.describe_conformance_packs()
        except Exception as e:
            log.error(
                f"An error occurred attempting to gather Conformance Packs "
                f"{Service} policy data from {Account} in {region}:\n"
                f"{e}"
            )
            continue
        if ResourceList is not None and 'ConformancePackDetails' in ResourceList:
            try:
                for cp in ResourceList.get('ConformancePackDetails', None):
                    # Gather the config conformance packs and construct the object list
                    # print(f"*******{cp}**********")
                    ResourceName = cp.get('ConformancePackName')
                    log.debug(f"Scanning {ResourceName}...")
                    HasPolicy = False
                    HasOrgId = False
                    HasOrgPath = False
                    ResponseObject.append(
                        {
                            "account": Account,
                            "region": region,
                            "resource_type": "Config Conformance Packs",
                            "resource_name": ResourceName,
                            "hasPolicy": HasPolicy,
                            "hasOrgId": HasOrgId,
                            "hasOrgPath": HasOrgPath,
                            "notes": ""
                        }
                    )
            except Exception as e:
                log.error(
                    f"An error occurred attempting to gather "
                    f"{Service} policy data from {Account} in {region}:\n"
                    f"{e}"
                )
    print('\n')
    ConfigCPResourceList.extend(ResponseObject)

####################
# Main Function
####################
# Main Action Logic


def lambda_handler(event, context):
    """ Main lambda entry function"""
    ResourceList = []
    XLSReportObj = {}
    ResourceManager = multiprocessing.Manager()

    # Create individual service lists for accurate metrics
    S3ResourceList = ResourceManager.list()
    SNSResourceList = ResourceManager.list()
    SQSResourceList = ResourceManager.list()
    CBResourceList = ResourceManager.list()
    KMSResourceList = ResourceManager.list()
    ESDResourceList = ResourceManager.list()
    EFSResourceList = ResourceManager.list()
    ECRResourceList = ResourceManager.list()
    SESResourceList = ResourceManager.list()
    SMResourceList = ResourceManager.list()
    MSCResourceList = ResourceManager.list()
    GlueResourceList = ResourceManager.list()
    IOTResourceList = ResourceManager.list()
    GVResourceList = ResourceManager.list()
    IAMResourceList = ResourceManager.list()
    RoleResourceList = ResourceManager.list()
    CFResourceList = ResourceManager.list()
    APIResourceList = ResourceManager.list()
    MLResourceList = ResourceManager.list()
    CWResourceList = ResourceManager.list()
    LambdaResourceList = ResourceManager.list()
    FnHandlerResourceList = ResourceManager.list()
    RAMResourceList = ResourceManager.list()
    ConfigRuleResourceList = ResourceManager.list()
    ConfigCPResourceList = ResourceManager.list()

    try:
        # =========================================
        # Assume the proper role for account access
        # =========================================
        # For each Account, loop through the account and perform queries
        # for account in account_list:
        # AccountList -> Key = Account Number, Value = Account Name
        for account in ACCOUNT_LIST:
            log.debug(f"Processing account: {account}...")
            print(f"\nProcessing account: {account}...")

            # Assume Account Role
            AccountRole = f"arn:aws:iam::{account}:role/{ASSUME_ROLE}"
            print(f"Calling Assume Role for: {AccountRole}\n")

            # Assume the account specific role
            AccountCredentials = AssumeRole(AccountRole)
            AccountTokens = AccountCredentials.get('Credentials')

            # Build a new account session to pass to the collectors
            AccountSession = boto3.session.Session(
                aws_access_key_id=AccountTokens.get('AccessKeyId'),
                aws_secret_access_key=AccountTokens.get('SecretAccessKey'),
                aws_session_token=AccountTokens.get('SessionToken')
            )

            # ==========================================================
            # Iterate through each applicable service within the account
            # ==========================================================
            # --------------------
            # S3 Bucket Resources
            # --------------------
            if "S3_BUCKETS" in ENABLED_REPORTS:
                S3Process = multiprocessing.Process(name="S3 Worker", target=QueryS3, args=(AccountSession, S3ResourceList, account))
                MP_SERVICE_QUEUE.append(S3Process)
                print("Starting S3 Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                S3Process.start()
            # --------------------
            # SNS Topic Resources
            # --------------------
            if "SNS_TOPICS" in ENABLED_REPORTS:
                SNSProcess = multiprocessing.Process(name="SNS Worker", target=QuerySNS, args=(AccountSession, SNSResourceList, account))
                MP_SERVICE_QUEUE.append(SNSProcess)
                print("Starting SNS Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                SNSProcess.start()
            # --------------------
            # SQS Queue Resources
            # --------------------
            if "SQS_QUEUES" in ENABLED_REPORTS:
                SQSProcess = multiprocessing.Process(name="SQS Worker", target=QuerySQS, args=(AccountSession, SQSResourceList, account))
                MP_SERVICE_QUEUE.append(SQSProcess)
                print("Starting SQS Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                SQSProcess.start()
            # --------------------
            # SQS Queue Resources
            # --------------------
            if "CODEBUILD_PROJECTS" in ENABLED_REPORTS:
                CBProcess = multiprocessing.Process(name="CodeBuild Worker", target=QueryCodeBuild, args=(AccountSession, CBResourceList, account))
                MP_SERVICE_QUEUE.append(CBProcess)
                print("Starting CodeBuild Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                CBProcess.start()
            # --------------------
            # KMS Key Resources
            # --------------------
            if "KMS_KEYS" in ENABLED_REPORTS:
                KMSProcess = multiprocessing.Process(name="KMS Worker", target=QueryKMS, args=(AccountSession, KMSResourceList, account))
                MP_SERVICE_QUEUE.append(KMSProcess)
                print("Starting KMS Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                KMSProcess.start()
            # -------------------------------
            # Elastic Search Domain Resources
            # -------------------------------
            if "ELASTIC_SEARCH_DOMAINS" in ENABLED_REPORTS:
                ESDProcess = multiprocessing.Process(name="ElasticSearch Worker", target=QueryElasticSearch, args=(AccountSession, ESDResourceList, account))
                MP_SERVICE_QUEUE.append(ESDProcess)
                print("Starting ElasticSearch Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                ESDProcess.start()
            # -------------------------------
            # EFS FileSystem Resources
            # -------------------------------
            if "EFS_FILESYSTEMS" in ENABLED_REPORTS:
                EFSProcess = multiprocessing.Process(name="EFS Worker", target=QueryEFS, args=(AccountSession, EFSResourceList, account))
                MP_SERVICE_QUEUE.append(EFSProcess)
                print("Starting EFS Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                EFSProcess.start()
            # -------------------------------
            # ECR Repository Resources
            # -------------------------------
            if "ECR_REPOSITORIES" in ENABLED_REPORTS:
                ECRProcess = multiprocessing.Process(name="ECR Worker", target=QueryECR, args=(AccountSession, ECRResourceList, account))
                MP_SERVICE_QUEUE.append(ECRProcess)
                print("Starting ECR Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                ECRProcess.start()
            # -------------------------------
            # SES Identity Resources
            # -------------------------------
            if "SES_IDENTITIES" in ENABLED_REPORTS:
                SESProcess = multiprocessing.Process(name="SES Worker", target=QuerySES, args=(AccountSession, SESResourceList, account))
                MP_SERVICE_QUEUE.append(SESProcess)
                print("Starting SES Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                SESProcess.start()
            # -------------------------------
            # Secrets Manager Secrets Resources
            # -------------------------------
            if "SECRETS_MANAGER_SECRETS" in ENABLED_REPORTS:
                SMProcess = multiprocessing.Process(name="SecretsManager Worker", target=QuerySecrets, args=(AccountSession, SMResourceList, account))
                MP_SERVICE_QUEUE.append(SMProcess)
                print("Starting SecretsManager Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                SMProcess.start()
            # -------------------------------
            # MediaStore Container Resources
            # -------------------------------
            if "MEDIASTORE_CONTAINERS" in ENABLED_REPORTS:
                MSCProcess = multiprocessing.Process(name="MediaStore Worker", target=QueryMediaStore, args=(AccountSession, MSCResourceList, account))
                MP_SERVICE_QUEUE.append(MSCProcess)
                print("Starting MediaStore Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                MSCProcess.start()
            # -------------------------------
            # Glue Resource Policy Resources
            # -------------------------------
            if "GLUE_RESOURCE_POLICIES" in ENABLED_REPORTS:
                GlueProcess = multiprocessing.Process(name="Glue Worker", target=QueryGlue, args=(AccountSession, GlueResourceList, account))
                MP_SERVICE_QUEUE.append(GlueProcess)
                print("Starting Glue Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                GlueProcess.start()
            # -------------------------------
            # IoT Resource Policy Resources
            # -------------------------------
            if "IOT_POLICIES" in ENABLED_REPORTS:
                IOTProcess = multiprocessing.Process(name="IoT Worker", target=QueryIoT, args=(AccountSession, IOTResourceList, account))
                MP_SERVICE_QUEUE.append(IOTProcess)
                print("Starting IoT Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                IOTProcess.start()
            # -------------------------------
            # Glacier Vault Resources
            # -------------------------------
            if "GLACIER_VAULTS" in ENABLED_REPORTS:
                GlacierProcess = multiprocessing.Process(name="Glacier Worker", target=QueryGlacier, args=(AccountSession, GVResourceList, account))
                MP_SERVICE_QUEUE.append(GlacierProcess)
                print("Starting Glacier Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                GlacierProcess.start()
            # -------------------------------
            # IAM Policy Resources
            # -------------------------------
            if "IAM_POLICIES" in ENABLED_REPORTS:
                IAMProcess = multiprocessing.Process(name="IAM Policy Worker", target=QueryIAMPolicies, args=(AccountSession, IAMResourceList, account))
                MP_SERVICE_QUEUE.append(IAMProcess)
                print("Starting IAM Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                IAMProcess.start()
            if "IAM_ROLES" in ENABLED_REPORTS:
                RoleProcess = multiprocessing.Process(name="IAM Role Worker", target=QueryIAMRoles, args=(AccountSession, RoleResourceList, account))
                MP_SERVICE_QUEUE.append(RoleProcess)
                print("Starting IAM Role Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                RoleProcess.start()
            # -------------------------------
            # CloudFormation Stack Resources
            # -------------------------------
            if "STACK_POLICIES" in ENABLED_REPORTS:
                CFProcess = multiprocessing.Process(name="CF Stack Policy Worker", target=QueryCF, args=(AccountSession, CFResourceList, account))
                MP_SERVICE_QUEUE.append(CFProcess)
                print("Starting CloudFormation Stack Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                CFProcess.start()
            # -------------------------------
            # API Gateway API Resources
            # -------------------------------
            if "API_GATEWAY_APIS" in ENABLED_REPORTS:
                APIProcess = multiprocessing.Process(name="API Gateway Worker", target=QueryAPI, args=(AccountSession, APIResourceList, account))
                MP_SERVICE_QUEUE.append(APIProcess)
                print("Starting API Gateway Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                APIProcess.start()
            # -------------------------------
            # MediaLive Channel Resources
            # -------------------------------
            if "MEDIALIVE_CHANNELS" in ENABLED_REPORTS:
                MLProcess = multiprocessing.Process(name="MediaLive Channel Worker", target=QueryMediaLive, args=(AccountSession, MLResourceList, account))
                MP_SERVICE_QUEUE.append(MLProcess)
                print("Starting MediaLive Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                MLProcess.start()
            # -------------------------------
            # CloudWatch EventBus Resources
            # -------------------------------
            if "CLOUDWATCH_EVENTBUS_POLICIES" in ENABLED_REPORTS:
                CWProcess = multiprocessing.Process(name="CloudWatch EventBus Worker", target=QueryCloudWatch, args=(AccountSession, CWResourceList, account))
                MP_SERVICE_QUEUE.append(CWProcess)
                print("Starting CloudWatch EventBus Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                CWProcess.start()
            # -------------------------------
            # Lambda Resources
            # -------------------------------
            if "LAMBDA_RESOURCE_POLICIES" in ENABLED_REPORTS:
                LambdaProcess = multiprocessing.Process(name="Lambda Worker", target=QueryLambda, args=(
                    AccountSession,
                    LambdaResourceList,
                    FnHandlerResourceList,
                    account
                )
                )
                MP_SERVICE_QUEUE.append(LambdaProcess)
                print("Starting Lambda Service Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                LambdaProcess.start()
            # -------------------------------
            # RAM Resource Shares
            # -------------------------------
            if "RAM_SHARE_ASSOCIATIONS" in ENABLED_REPORTS:
                RAMProcess = multiprocessing.Process(name="RAM Shares Worker", target=QueryRAM, args=(AccountSession, RAMResourceList, account))
                MP_SERVICE_QUEUE.append(RAMProcess)
                print("Starting RAM Shares Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                RAMProcess.start()
            # -------------------------------
            # Config Resource Shares
            # -------------------------------
            if "CONFIG_RULES" in ENABLED_REPORTS:
                CRProcess = multiprocessing.Process(name="Config Rule Worker", target=QueryConfigRules, args=(AccountSession, ConfigRuleResourceList, account))
                MP_SERVICE_QUEUE.append(CRProcess)
                print("Starting Config Rule Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                CRProcess.start()
            if "CONFIG_CONFORMANCE_PACKS" in ENABLED_REPORTS:
                CCPProcess = multiprocessing.Process(name="Config Conformance Pack Worker", target=QueryConfigCPs,
                                                     args=(AccountSession, ConfigCPResourceList, account))
                MP_SERVICE_QUEUE.append(CCPProcess)
                print("Starting Config ConformancePack Check Process...")
                print(f"{len(MP_SERVICE_QUEUE)} processes are currently open...")
                CCPProcess.start()

            # Close each process
            # Moved in 1 level to accommodate too many open processes.
            for proc in MP_SERVICE_QUEUE:
                proc.join()
                proc.close()
                MP_SERVICE_QUEUE.remove(proc)
                print(f"Closing {proc.name}")

        # =========================================
        # Generate Output Findings / Metrics
        # =========================================
        ReportSummary = f"\nOrganizations Dependency Report Summary:\n"
        ReportSummary += "-------------------------------------------\n"
        # Add S3 Reporting
        if "S3_BUCKETS" in ENABLED_REPORTS:
            ResourceList.extend(S3ResourceList)
            XLSReportObj.update(S3_BUCKETS=S3ResourceList)
            ReportSummary += (
                f"  * S3 Buckets: "
                f"{CountDeps(S3ResourceList)}/{len(S3ResourceList)}\n"
            )
        # Add SNS Reporting
        if "SNS_TOPICS" in ENABLED_REPORTS:
            ResourceList.extend(SNSResourceList)
            XLSReportObj.update(SNS_TOPICS=SNSResourceList)
            ReportSummary += (
                f"  * SNS Topics: "
                f"{CountDeps(SNSResourceList)}/{len(SNSResourceList)}\n"
            )
        # Add SQS Reporting
        if "SQS_QUEUES" in ENABLED_REPORTS:
            ResourceList.extend(SQSResourceList)
            XLSReportObj.update(SQS_QUEUES=SQSResourceList)
            ReportSummary += (
                f"  * SQS Queues: "
                f"{CountDeps(SQSResourceList)}/{len(SQSResourceList)}\n"
            )
        # Add CodeBuild Reporting
        if "CODEBUILD_PROJECTS" in ENABLED_REPORTS:
            ResourceList.extend(CBResourceList)
            XLSReportObj.update(CODEBUILD_PROJECTS=CBResourceList)
            ReportSummary += (
                f"  * CodeBuild Projects: "
                f"{CountDeps(CBResourceList)}/{len(CBResourceList)}\n"
            )
        # Add KMS Reporting
        if "KMS_KEYS" in ENABLED_REPORTS:
            ResourceList.extend(KMSResourceList)
            XLSReportObj.update(KMS_KEYS=KMSResourceList)
            ReportSummary += (
                f"  * KMS Keys: "
                f"{CountDeps(KMSResourceList)}/{len(KMSResourceList)}\n"
            )
        # Add ElasticSearch Reporting
        if "ELASTIC_SEARCH_DOMAINS" in ENABLED_REPORTS:
            ResourceList.extend(ESDResourceList)
            XLSReportObj.update(ELASTIC_SEARCH_DOMAINS=ESDResourceList)
            ReportSummary += (
                f"  * Elastic Search Domains: "
                f"{CountDeps(ESDResourceList)}/{len(ESDResourceList)}\n"
            )
        # Add EFS Reporting
        if "EFS_FILESYSTEMS" in ENABLED_REPORTS:
            ResourceList.extend(EFSResourceList)
            XLSReportObj.update(EFS_FILESYSTEMS=EFSResourceList)
            ReportSummary += (
                f"  * EFS FileSystems: "
                f"{CountDeps(EFSResourceList)}/{len(EFSResourceList)}\n"
            )
        # Add ECR Reporting
        if "ECR_REPOSITORIES" in ENABLED_REPORTS:
            ResourceList.extend(ECRResourceList)
            XLSReportObj.update(ECR_REPOSITORIES=ECRResourceList)
            ReportSummary += (
                f"  * ECR Repositories: "
                f"{CountDeps(ECRResourceList)}/{len(ECRResourceList)}\n"
            )
        # Add SES Reporting
        if "SES_IDENTITIES" in ENABLED_REPORTS:
            ResourceList.extend(SESResourceList)
            XLSReportObj.update(SES_IDENTITIES=SESResourceList)
            ReportSummary += (
                f"  * SES Identities: "
                f"{CountDeps(SESResourceList)}/{len(SESResourceList)}\n"
            )
        # Add Secrets Manager Reporting
        if "SECRETS_MANAGER_SECRETS" in ENABLED_REPORTS:
            ResourceList.extend(SMResourceList)
            XLSReportObj.update(SECRETS_MANAGER_SECRETS=SMResourceList)
            ReportSummary += (
                f"  * Secrets Manager Secrets: "
                f"{CountDeps(SMResourceList)}/{len(SMResourceList)}\n"
            )
        # Add MediaStore Reporting
        if "MEDIASTORE_CONTAINERS" in ENABLED_REPORTS:
            ResourceList.extend(MSCResourceList)
            XLSReportObj.update(MEDIASTORE_CONTAINERS=MSCResourceList)
            ReportSummary += (
                f"  * MediaStore Containers: "
                f"{CountDeps(MSCResourceList)}/{len(MSCResourceList)}\n"
            )
        # Add Glue Reporting
        if "GLUE_RESOURCE_POLICIES" in ENABLED_REPORTS:
            ResourceList.extend(GlueResourceList)
            XLSReportObj.update(GLUE_RESOURCE_POLICIES=GlueResourceList)
            ReportSummary += (
                f"  * Glue Resource Policies: "
                f"{CountDeps(GlueResourceList)}/{len(GlueResourceList)}\n"
            )
        # Add IoT Reporting
        if "IOT_POLICIES" in ENABLED_REPORTS:
            ResourceList.extend(IOTResourceList)
            XLSReportObj.update(IOT_POLICIES=IOTResourceList)
            ReportSummary += (
                f"  * IoT Resource Policies : "
                f"{CountDeps(IOTResourceList)}/{len(IOTResourceList)}\n"
            )
        # Add Glacier Reporting
        if "GLACIER_VAULTS" in ENABLED_REPORTS:
            ResourceList.extend(GVResourceList)
            XLSReportObj.update(GLACIER_VAULTS=GVResourceList)
            ReportSummary += (
                f"  * Glacier Vaults: "
                f"{CountDeps(GVResourceList)}/{len(GVResourceList)}\n"
            )
        # Add IAM Reporting
        if "IAM_POLICIES" in ENABLED_REPORTS:
            ResourceList.extend(IAMResourceList)
            XLSReportObj.update(IAM_POLICIES=IAMResourceList)
            ReportSummary += (
                f"  * IAM Policies: "
                f"{CountDeps(IAMResourceList)}/{len(IAMResourceList)}\n"
            )
        if "IAM_ROLES" in ENABLED_REPORTS:
            ResourceList.extend(RoleResourceList)
            XLSReportObj.update(IAM_ROLES=RoleResourceList)
            ReportSummary += (
                f"  * IAM Roles: "
                f"{CountDeps(RoleResourceList)}/{len(RoleResourceList)}\n"
            )
        # Add CloudFormation Reporting
        if "STACK_POLICIES" in ENABLED_REPORTS:
            ResourceList.extend(CFResourceList)
            XLSReportObj.update(STACK_POLICIES=CFResourceList)
            ReportSummary += (
                f"  * CloudFormation Stack Policies: "
                f"{CountDeps(CFResourceList)}/{len(CFResourceList)}\n"
            )
        # Add APIGateway Reporting
        if "API_GATEWAY_APIS" in ENABLED_REPORTS:
            ResourceList.extend(APIResourceList)
            XLSReportObj.update(API_GATEWAY_APIS=APIResourceList)
            ReportSummary += (
                f"  * APIGateway Rest API Policies: "
                f"{CountDeps(APIResourceList)}/{len(APIResourceList)}\n"
            )
        # Add MediaLive Reporting
        if "MEDIALIVE_CHANNELS" in ENABLED_REPORTS:
            ResourceList.extend(MLResourceList)
            XLSReportObj.update(MEDIALIVE_CHANNELS=MLResourceList)
            ReportSummary += (
                f"  * MediaLive Channel Policies: "
                f"{CountDeps(MLResourceList)}/{len(MLResourceList)}\n"
            )
        # Add CloudWatch Event Bus Reporting
        if "CLOUDWATCH_EVENTBUS_POLICIES" in ENABLED_REPORTS:
            ResourceList.extend(CWResourceList)
            XLSReportObj.update(CLOUDWATCH_EVENTBUS_POLICIES=CWResourceList)
            ReportSummary += (
                f"  * CloudWatch EventBus Policies: "
                f"{CountDeps(CWResourceList)}/{len(CWResourceList)}\n"
            )
        # Add Lambda Reporting
        if "LAMBDA_RESOURCE_POLICIES" in ENABLED_REPORTS:
            ResourceList.extend(LambdaResourceList)
            XLSReportObj.update(LAMBDA_RESOURCE_POLICIES=LambdaResourceList)
            ReportSummary += (
                f"  * Lambda Function/Layer Policies: "
                f"{CountDeps(LambdaResourceList)}/{len(LambdaResourceList)}\n"
            )
        if "LAMBDA_FN_HANDLER_CODE" in ENABLED_REPORTS:
            ResourceList.extend(FnHandlerResourceList)
            XLSReportObj.update(LAMBDA_FN_HANDLER_CODE=FnHandlerResourceList)
            ReportSummary += (
                f"  * Lambda Function/Layer Handler Code: "
                f"{CountDeps(FnHandlerResourceList)}/{len(FnHandlerResourceList)}\n"
            )
        # Add RAMS Shares Reporting
        if "RAM_SHARE_ASSOCIATIONS" in ENABLED_REPORTS:
            ResourceList.extend(RAMResourceList)
            XLSReportObj.update(RAM_SHARE_ASSOCIATIONS=RAMResourceList)
            ReportSummary += (
                f"  * RAM Resource Share Associations: "
                f"{CountDeps(RAMResourceList)}/{len(RAMResourceList)}\n"
            )
        # Add Config Reporting
        if "CONFIG_RULES" in ENABLED_REPORTS:
            ResourceList.extend(ConfigRuleResourceList)
            XLSReportObj.update(CONFIG_RULES=ConfigRuleResourceList)
            ReportSummary += (
                f"  * Config Rules: "
                f"{CountDeps(ConfigRuleResourceList)}/{len(ConfigRuleResourceList)}\n"
            )
        if "CONFIG_CONFORMANCE_PACKS" in ENABLED_REPORTS:
            ResourceList.extend(ConfigCPResourceList)
            XLSReportObj.update(CONFIG_CONFORMANCE_PACKS=ConfigCPResourceList)
            ReportSummary += (
                f"  * Config Conformance Packs: "
                f"{CountDeps(ConfigCPResourceList)}/{len(ConfigCPResourceList)}\n"
            )
    except Exception as e:
        log.error(str(e))
        raise(e)

    # Print Totals
    ReportSummary += (
        f"\n{CountDeps(ResourceList)}/{len(ResourceList)} resources in total "
        "identified with Organizations dependencies across all scanned "
        "accounts/regions."
    )
    ReportSummary += "\n"
    log.info(ReportSummary)
    print(ReportSummary)
    # print(json.dumps(ResourceList, indent=4))

    # Write the collected data to a CSV/Excel file
    CSVReportWriter(ResourceList)
    XlsReportWriter(XLSReportObj)
