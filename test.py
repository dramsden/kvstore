from __future__ import print_function
import boto3

tablename = "monitoring"
appname = "Testing-Application"
attrib_name = "container_instances"
attrib_value = 0
profile_name = "opapps-sandbox"
region_name = "us-west-2"
sess = boto3.session.Session(profile_name=profile_name, region_name=region_name)
dynamo = sess.resource("dynamodb")
table = dynamo.Table(tablename)

def update_application_info_1(table, appname, attrib_name, attrib_value):
    """Update an application's info DynamoDB data with the new data."""
    attr = attrib_name + "[" + str(attrib_value) + "]"
    print(attr)
    update_response = table.update_item(
                Key={
                    "application_name": appname
                },
                UpdateExpression="REMOVE container_instances[0]",
                ReturnValues="UPDATED_OLD"
            )
    print(str(update_response))

update_application_info_1(table, appname, attrib_name, attrib_value)
