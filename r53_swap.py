from __future__ import print_function
import boto3
from botocore.exceptions import ClientError
import time
import sys

# Configuration

debug = True
tablename = "monitoring"
application_name = "Test Application"
profile_name = "opapps-sandbox"
region_name = "us-west-2"


def check_table(table):
# Check that the configuration table is available.
    table_status = "UNAVAILABLE"
    for i in range(0, 10):
        try:
            print("Checking for {0} table, try {1}.".format(table.name, i + 1))
            table_status = table.table_status
            if table_status != "ACTIVE":
                print(table_status)
                time.sleep(1)
                continue
        except Exception as e:
            print("Exception while attempting to retrieve table data:")
            print(e)
            time.sleep(1)
            continue
        break
    return table_status


def get_table_data(table, appname):
    """Get the table data for this application."""
    try:
        get_response = table.get_item(
            Key={
                "Application": appname
            }
        )
        return get_response
    except ClientError as e:
        print(e["Error"]["Message"])


def make_record(action, name, recordtype, ttl, external_name):
    """Build the record change request to make to Route 53."""
    return {
        "Action": action,
        "ResourceRecordSet": {
            "Name": name,
            "Type": recordtype,
            "TTL": ttl,
            "ResourceRecords": [
                {
                    "Value": external_name
                }
            ]
        }
    }


def change_dns_record(route53_client, hosted_zone, batch):
    """Send the change request to Route53."""
    try:
        r53_upsert_response = route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone,
            ChangeBatch=batch
        )
    except Exception as e:
        sys.exit(e)
    return r53_upsert_response


def update_table_data(table, appname, new_record):
    """Change the 'current' values in table."""
    try:
        update_response = table.update_item(
            Key={
                "Application": appname
            },
            UpdateExpression="set current_location = :val1",
            ExpressionAttributeValues={
                ":val1": new_record,
            },
            ReturnValues="UPDATED_NEW"
        )
        return update_response
    except ClientError as e:
        print(e["Error"]["Message"])


def monitor_change_status(route53_client, change_id):
    """Checks on the status of a particular Route 53 batch change"""
    e = "No Exception Found"
    change_status = "UNKNOWN"
    for i in range(0, 300):
        try:
            r53_change_status_response = route53_client.get_change(
                Id=change_id
            )
            change_status = r53_change_status_response["ChangeInfo"]["Status"]
            if change_status == "INSYNC":
                return change_status
            else:
                time.sleep(1)
        except Exception as e:
            time.sleep(1)
        if (i % 10) == 0:
            print("{0} seconds since change request made.  Status: {1}".format(str(0), change_status))
    if e:
        print("Unable to determine change status; please check DNS status via manual testing.")
        print("Last exception:")
        print(e)
    return change_status


def lambda_handler(event, context):
    """Handles the trigger event in lambda"""

    # Create resources and sessions
    session = boto3.session.Session(profile_name=profile_name, region_name=region_name)
    dynamo = session.resource("dynamodb")
    route53 = session.client("route53")
    table = dynamo.Table(tablename)

    # Check the configuration table for availability.
    table_status = check_table(table)
    if table_status != "ACTIVE":
        sys.exit("Configuration table not available.  Status: {0}".format(table_status))

    # Retrieve the specified application's data from the table, and print the current values.
    table_data = get_table_data(table, application_name)
    if debug:
        import pprint
        pp = pprint.PrettyPrinter(indent=4)
        print("Complete table data:")
        pp.pprint(table_data)
    else:
        print("Initial record of primary location: " + table_data["Item"]["primary_location"])
        print("Initial record of failover location: " + table_data["Item"]["failover_location"])
        print("Initial record of current location: " + table_data["Item"]["current_location"])

    # Pull needed items from the application's data
    hosted_zone = table_data["Item"]["hosted_zone"]
    old_record = table_data["Item"]["primary_location"]
    new_record = table_data["Item"]["failover_location"]
    record_type = table_data["Item"]["hosted_zone_record_type"]
    external_name = table_data["Item"]["external_DNS_name"]
    ttl = int(table_data["Item"]["TTL"])

    # Create components of the Route 53 batch update request.
    comment = "Failing external {0} of {1} from {2} to {3}.".format(record_type, external_name, old_record, new_record)
    action_list = [
        make_record("DELETE", old_record, record_type, ttl, external_name),
        make_record("CREATE", new_record, record_type, ttl, external_name)
    ]
    batch = {"Comment": comment, "Changes": action_list}

    # Delete the old DNS record in Route 53, and create a new one with the failover value.
    print(batch["Comment"])
    route53_response = change_dns_record(route53, hosted_zone, batch)
    print("Route 53 change status: " + route53_response["ChangeInfo"]["Status"])

    # Extract the ID of the change batch request.
    change_id = route53_response["ChangeInfo"]["Id"]

    # Update the table data to reflect the current DNS value.
    update_table_data(table, application_name, new_record)

    # Get the updated table data and print the changes.
    new_table_data = get_table_data(table, application_name)
    print("Final record of primary location: " + new_table_data["Item"]["primary_location"])
    print("Final record of failover location: " + new_table_data["Item"]["failover_location"])
    print("Final record of current location: " + new_table_data["Item"]["current_location"])

    change_status = monitor_change_status(route53, change_id)
    print("Route 53 Status: {0}".format(change_status))


def main():
    """Call the lambda handler function with a default (unused) event and context."""
    lambda_handler("event", "context")


if __name__ == "__main__":
    # The inevitable call to main
    main()