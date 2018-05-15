from __future__ import print_function
import boto3
import json
from botocore.exceptions import ClientError
from datetime import datetime

# Get the service resource

tablename = "monitoring"
#datafile = "test_data_file.json"
datafile = "test_data_file_2.json"

session = boto3.session.Session(profile_name="opapps-sandbox", region_name='us-west-2')
dynamo = session.resource('dynamodb')
client = boto3.client('dynamodb', region_name='us-west-2')
route53 = session.client("route53")
table = dynamo.Table(tablename)

# Read the local data file.

with open(datafile, "r") as data_file:
    app_data = json.load(data_file)

# Clear - delete the database
clear = "false"
#clear = "true"
if clear == "true":
    delete_response = table.delete()
    print(delete_response)

# Look for the table.

try:
    table_status = table.table_status
except Exception as e:
    table_status = "ABSENT"

# If the table doesn't exist, make it.

if table_status == "ABSENT":
    print("Table {0} doesn't exist.  Creating.".format(tablename))
    # Create the table.
    table = dynamo.create_table(
        TableName=tablename,
        KeySchema=[
            {
                "AttributeName": "application_name",
                "KeyType": "HASH"
            }
        ],
        AttributeDefinitions=[
            {
                "AttributeName": "application_name",
                "AttributeType": "S"
            }
        ],
        ProvisionedThroughput={
            "ReadCapacityUnits": 3,
            "WriteCapacityUnits": 3
        }
    )

    # Wait until the table exists.
    table.meta.client.get_waiter('table_exists').wait(TableName=tablename)
    table_status = table.table_status

print("Status of table {0}: {1}".format(table, table_status))

# Populate the table.

for key, attribute in app_data.items():
    table.put_item(Item=app_data)

# Get the contents of the DB

try:
    get_response = table.get_item(
        Key={
            "application_name": "Testing-Application"
        }
    )
except ClientError as e:
    print(e)
else:
    print("DEBUG: " + str(get_response))
    item = get_response["Item"]
    print(item)


# Backup the database
timestamp = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
backup_response = client.create_backup(
    TableName=tablename,
    BackupName='Backup-' + timestamp
)

# Get the contents of the DB again.

try:
    get_response = table.get_item(
        Key={
            "application_name": "Testing-Application"
        }
    )
except ClientError as e:
    print(e)
else:
    item = get_response["Item"]
    print(item)

# Cleanup - delete the database
cleanup = "false"
#cleanup = "true"
if cleanup == "true":
    delete_response = table.delete()
    print(delete_response)
