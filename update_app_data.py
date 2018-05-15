from __future__ import print_function
import boto3
from botocore.exceptions import ClientError
import sys
import json

# Configuration
tablename = "monitoring"
profile_name = "opapps-sandbox"
region_name = "us-west-2"

# Events for testing!
test_event_1 = "test_event_1.json"  # EC2 Instance Changed
test_event_2 = "test_event_2.json"  # Autoscaling - Terminate Instance
test_event_3 = "test_event_3.json"  # Autoscaling - Successful Instance Launch
test_event_4 = "test_event_4.json"  # ECS - Task State Change
test_event_5 = "test_event_5.json"  # ECS - Container Instance State Change


def scan_dynamo_data(table):
    """Retrieve all of the application data in DynamoDB"""
    try:
        dynamo_data = table.scan()
        return dynamo_data["Items"]
    except ClientError as e:
        print(e["Error"]["Message"])
        sys.exit()


def find_attrib_index(data, attrib_list, attrib_key, attrib_value):
    """Finds the index of a given attribute in a particular list of a given data dict"""
    print("DATA : {0}".format(data))
    for item in data[attrib_list]:
        if attrib_key in item:
            if item[attrib_key] == attrib_value:
                return data[attrib_list].index(item)
    return None


def get_asg_instance_info(sess, instance_id, region):
    """Retrieves the ASG name an instance is associated with; returns string "None" if not found in AWS ASG"""
    asg_client = sess.client("autoscaling", region_name=region)
    try:
        asg_response = asg_client.describe_auto_scaling_instances(InstanceIds=[instance_id])
        if "AutoScalingInstances" in asg_response:
            asg = asg_response["AutoScalingInstances"][0]["AutoScalingGroupName"]
    except Exception:
        return "None"
    return asg


def fetch_instance_info(sess, instance_id, region):
    """Retrieves information about an instance from EC2 and AWS ASG"""
    #See if the instance can be retrieved via autoscaling so we know whether it's an ASG-controlled instance or not.
    asg = get_asg_instance_info(sess, instance_id, region)
    ec2_client = sess.client("ec2", region_name=region)
    try:
        ec2_response = ec2_client.describe_instances(InstanceIds=[instance_id])
    except Exception as e:
        print("Could not retrieve instance information for {0}".format(instance_id))
        sys.exit(e)
    full_instance_info = ec2_response["Reservations"][0]["Instances"][0]
    # Unpack the instance's security groups
    security_group_ids = []
    if "SecurityGroups" in full_instance_info:
        for sg in full_instance_info["SecurityGroups"]:
            security_group_ids.append(sg["GroupId"])
    # Unpack the instance's tags
    tags = {}
    if "Tags" in full_instance_info:
        for key, value in full_instance_info["Tags"].items():
            tags["key"] = value
    instance_info = {
        "instance_id": full_instance_info["InstanceId"],
        "asg": asg,
        "security_groups": security_group_ids,
        "tags": tags
    }
    return instance_info


def fetch_container_instance_info(c_instance_arn):
    """Retrieves information about a container instance."""
    instance_region = c_instance_arn.split(":")[3]
    ecs_client = boto3.client('ecs', region_name=instance_region)
    try:
        ecs_response = ecs_client.describe_container_instances(containerInstances=[c_instance_arn])
    except Exception as e:
        sys.exit(e)
    full_c_instance_info = ecs_response["containerInstances"][0]
    c_instance_id = full_c_instance_info["ec2InstanceId"]
    c_instance_info = {
        "c_instance_id": c_instance_id,
        "c_instance_arn": c_instance_arn
    }
    return c_instance_info


def get_data_for_insert(sess, region_name, attrib_name, attrib_value):
    if attrib_name == "instances":
        return fetch_instance_info(sess, attrib_value, region_name)
    elif attrib_name == "container_instances":
        return fetch_container_instance_info(attrib_value)
    elif attrib_name == "tasks":
        return {"task_arn": attrib_value}
    else:
        sys.exit("Could not determine lookup type for {0} {1}".format(attrib_name, attrib_value))


def handle_ecs_event(event_data, dynamo_items):
    """Determine what an ECS event is about, and return appropriate information to update the DB."""
    # Default to making no DB changes.
    app_name = "NONE"
    update_type = None
    container_instance_arn = event_data["detail"]["containerInstanceArn"]

    # Determine which application we're looking for by checking for matching Container Clusters.
    cluster_arn = event_data["detail"]["clusterArn"]
    application_info = determine_application(dynamo_items, "container_clusters", "cluster_arn", cluster_arn)

    # If we find a matching Container Cluster, we can't match it to an application.
    if application_info is False:
        message = "An application using for this event could not be found in the database."
        update_value = None
    else:
        app_name = application_info["application_name"]


    # If we're dealing with a change to a Container Instance
    if event_data["detail-type"] == "ECS Container Instance State Change":
        # Determine whether container instance already exists in our data.
        c_instance_record_index = find_attrib_index(application_info, "container_instances", "c_instance_arn", container_instance_arn)
        instance_status = event_data["detail"]["status"]
        if instance_status == "ACTIVE" and c_instance_record_index is None:  # Active instance, not in database
            update_type = "append"
            message = "Container instance {0} now active; adding to {1}'s application DB record.".format(container_instance_arn, app_name)
            update_value = container_instance_arn
        elif instance_status == "INACTIVE" and c_instance_record_index is not None:  # Inactive instance, but in database
            update_type = "remove"
            message = "Container instance {0} now inactive; removing from {1}'s application DB record.".format(container_instance_arn, app_name)
            update_value = c_instance_record_index
        else:
            message = "No DB change necessary to accomodate container instance {0}'s change to state {1}.".format(container_instance_arn, instance_status)
            update_value = None
        return [app_name, update_type, "container_instances", update_value, message]

    # If we're dealing with a change to a Task
    elif event_data["detail-type"] == "ECS Task State Change":
        # Determine whether the task already exists in our data.
        task_uuid = str(event_data["detail"]["taskArn"])[-36:]
        task_record_index = find_attrib_index(application_info, "tasks", "task_uuid", task_uuid)
        task_status = event_data["detail"]["lastStatus"]
        if task_status == "RUNNING" and task_record_index is None:  # Running task, not in database
            update_type = "append"
            message = "Task {0} running; adding to {1}'s application DB record.".format(task_uuid, app_name)
            update_value = task_uuid
        elif task_status == "STOPPED" and task_record_index is not None:  # Stopped task, but in database
            update_type = "remove"
            message = "Task {0} stopped; removing to application DB record.".format(task_uuid, app_name)
            update_value = task_record_index
        else:
            message = "No changes to {0}'s application DB record are necessary to accomodate task {1}'s current {2} state.".format(app_name, task_uuid, task_status)
            update_value = None
        return [app_name, update_type, "tasks", update_value, message]


def handle_autoscaling_event(event_data, dynamo_items):
    """Determine what an AWS autoscaling event is about, and return appropriate information to update the DB."""
    # Default to making no DB changes.
    app_name = "NONE"
    update_type = None
    # Determine which application this is for and find the instance in question in its DB item.
    instance_id = event_data["detail"]["EC2InstanceId"]
    asg_name = event_data["detail"]["AutoScalingGroupName"]
    application_info = determine_application(dynamo_items, "auto_scaling_groups", "asg_name", asg_name)
    if application_info is False:
        message = "An application using reported instance {0}'s asg {1} could not be found in the database.".format(instance_id, asg_name)
        return [app_name, update_type, "instances", None, message]
    else:
        app_name = application_info["application_name"]
    instance_record_index = find_attrib_index(application_info, "instances", "instance_id", instance_id)
    # Determine what kind of event occurred, and if it's one we care about, create a DB update for it.
    if event_data["detail-type"] == "EC2 Instance Launch Successful" and instance_record_index is None:
        message = "Instance {0} launched; adding to {1}'s application DB record.".format(instance_id, app_name)
        update_type = "append"
        attrib_value = instance_id
    elif event_data["detail-type"] == "EC2 Instance-terminate Lifecycle Action" and instance_record_index is not None:
        update_type = "remove"
        attrib_value = instance_record_index
        message = "Instance {0} terminated; removing from {1}'s application DB record.".format(instance_id, app_name)
    else:
        message = "No changes to {0}'s application DB record are necessary to accomodate instance {1}.".format(app_name, instance_id)
        attrib_value = None
    return [app_name, update_type, "instances", attrib_value, message]


def handle_ec2_event(event_data, dynamo_items):
    """Determine what an EC2 event is about, and return appropriate information to update the DB."""
    # Default to making no DB changes.
    app_name = "NONE"
    update_type = None
    message = "NONE"
    # Determine which application this is for and find the instance in question in its DB item.
    instance_id = event_data["detail"]["instance-id"]
    application_info = determine_application(dynamo_items, "instances", "instance_id", instance_id)
    if application_info is False:
        message = "An application using instance {0} could not be found in the database.".format(instance_id)
        return [app_name, update_type, "instances", None, message]
    else:
        app_name = application_info["application_name"]
    # Determine what kind of event occurred, and if it's one we care about, create a DB update for it.
    instance_record_index = find_attrib_index(application_info, "instances", "instance_id", instance_id)
    if event_data["detail-type"] == "EC2 Instance State-change Notification":
        if event_data["detail"]["state"] == "terminated":
            update_type = "remove"
            message = "Instance {0} terminated; removing from {1}'s application DB record.".format(instance_id, app_name)
    else:
        message = "No changes to {0}'s application DB record are necessary to accomodate instance {1}.".format(app_name, instance_id)
    return [app_name, update_type, "instances", instance_record_index, message]


def event_handler(event_data, dynamo_items):
    """Check the event to determine what happened.  Return a set of values to use to update the DB."""
    if event_data["source"] == "aws.autoscaling":
        update_info_list = handle_autoscaling_event(event_data, dynamo_items)
    elif event_data["source"] == "aws.ec2":
        update_info_list = handle_ec2_event(event_data, dynamo_items)
    elif event_data["source"] == "aws.ecs":
        update_info_list = handle_ecs_event(event_data, dynamo_items)
    else:
        sys.exit("Could not parse the indicated source ({0}) for event {1}".format(event_data["source"], event_data["id"]))
    return update_info_list


def determine_application(dynamo_items, item_type, item_key, event_value):
    """Determine which application has been changed and needs its data updated."""
    for application in dynamo_items:
        if item_type in application:
            for item in application[item_type]:
                if item[item_key] == event_value:
                    return application
    return False


def update_application_info(table, appname, update_type, attrib_name, attrib_value):
    """Update an application's info DynamoDB data with the new data."""
    try:
        if update_type == "remove":
            #update_expression = "REMOVE #attrib_name[:attrib_value]"
            update_expression = "REMOVE {0}[{1}]".format(attrib_name, attrib_value)
            update_response = table.update_item(
                Key={"application_name": appname},
                UpdateExpression=update_expression,
                ReturnValues="UPDATED_OLD"
            )
        elif update_type == "append":
            return_values = "UPDATED_NEW"
            update_expression = "SET #attrib_name = list_append(#attrib_name, :attrib_value)"
            update_response = table.update_item(
                Key={"application_name": appname},
                UpdateExpression=update_expression,
                ExpressionAttributeNames={
                    "#attrib_name": attrib_name
                },
                ExpressionAttributeValues={
                    ":attrib_value": [attrib_value]
                },
                ReturnValues=return_values
            )
        else:
            return None

        return update_response
    except ClientError as e:
        print(e)


def lambda_handler(event, context):
    """Handles the trigger event in lambda"""
    # Create resources and sessions
    sess = boto3.session.Session(profile_name=profile_name, region_name=region_name)
    dynamo = sess.resource("dynamodb")
    table = dynamo.Table(tablename)
    dynamo_items = scan_dynamo_data(table)

    # Figure out what to do with the event and get the parameters for an update
    appname, update_type, attrib_name, attrib_value, message = event_handler(event, dynamo_items)
    print(message)
    if update_type is not None:
        if update_type == "append":
            update_data = get_data_for_insert(sess, region_name, attrib_name, attrib_value)
        elif update_type == "remove":
            update_data = attrib_value
        update_response = update_application_info(table, appname, update_type, attrib_name, update_data)

        print("Updates to DB for event {0} complete.".format(event["id"]))
    else:
        print("No updates made to DB for event {0}:".format(event["id"]))


# Settings for testing
test_file = test_event_5
test_context = "context"


def main():
    """Call the lambda handler function with a default (unused) event and context."""
    with open(test_file) as event_file:
        test_event = json.load(event_file)
    lambda_handler(test_event, test_context)


if __name__ == "__main__":
    # The inevitable call to main
    main()