########################################
import os
import psutil
import json
import click
import platform
import sys
import traceback
import base64
import uuid
import boto3
import paramiko
import yaml
import logging
import re
import time
import requests
import subprocess
import copy
import crypt
import random
import string
import threading
import shutil
import smtplib
import botocore.exceptions


from flask import Flask
from cryptography.fernet import InvalidToken
from xml.dom import minidom
from getpass import getpass
from base64 import urlsafe_b64encode, urlsafe_b64decode
from datetime import datetime, timedelta
from tabulate import tabulate
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.hashes import SHA256
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from cryptography.fernet import Fernet
from click import echo, command, option

@click.group()
def cli():
    pass


#second section

BASE_DIR = os.path.expanduser("/etc/devops-bot")
AWS_CREDENTIALS_FILE = os.path.join(BASE_DIR, "aws_credentials.json")
KEY_FILE = os.path.join(BASE_DIR, "key.key")

###################################################
         ##aws screenplay #####

STATE_DIR = os.path.join(BASE_DIR, "state_files")
OUTPUT_STATE_DIR = os.path.join(BASE_DIR, "output_vars")
TOKEN_FILE = os.path.join(BASE_DIR, "token")
ENC_KEY_FILE = os.path.join(BASE_DIR, "enc_key.key")
DEVOPS_BOT_LOGS = os.path.join(BASE_DIR, "logs")
KEY_FILE_PATH = os.path.join(BASE_DIR, "enc_key.key")
LOG_FILE_PATH = os.path.join(DEVOPS_BOT_LOGS, "devops_bot.log")

#######################################

###################  extras  ###################

# Ensure the logs directory exists
os.makedirs(DEVOPS_BOT_LOGS, exist_ok=True)

# Define the log file path
LOG_FILE_PATH = os.path.join(DEVOPS_BOT_LOGS, "devops_bot.log")

# Configure logging
logging.basicConfig(
    filename=LOG_FILE_PATH,
    level=logging.DEBUG,  # Adjust log level for more detail
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


# Get logger and add the handler
logger = logging.getLogger("DevOpsBot")
logger.info("Logging has been configured successfully.")
SALT_SIZE = 16  # Salt size in bytes
ITERATIONS = 100000  # Number of iterations for the key derivation

def ensure_folder(path):
    if not os.path.exists(path):
        os.makedirs(path)

# Ensure folders are created at startup
ensure_folder(BASE_DIR)




# Generate a 32-byte encryption key
key = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
#print("Encryption Key:", key)

def save_key(key):
    ensure_folder(BASE_DIR)
    with open(KEY_FILE, 'w') as key_file:
        key_file.write(key)
    os.chmod(KEY_FILE, 0o600)  # Set file permissions to be readable and writable only by the owner

def get_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))


def generate_key():
    key = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
    save_key(key)
    return key

# Ensure the key file is present or generate a new key if not
if not os.path.exists(KEY_FILE):
    generate_key()

def load_key():
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError("Encryption key not found.")
    with open(KEY_FILE, 'r') as key_file:
        return key_file.read()


def encrypt_data(data, key):
    fernet = Fernet(key.encode('utf-8'))
    encrypted = fernet.encrypt(data.encode('utf-8'))
    return encrypted

def decrypt_data(encrypted_data, key):
    fernet = Fernet(key.encode('utf-8'))
    decrypted = fernet.decrypt(encrypted_data)
    return decrypted.decode('utf-8')
def load_aws_credentials():
    if os.path.exists(AWS_CREDENTIALS_FILE):
        key = load_key()
        with open(AWS_CREDENTIALS_FILE, 'rb') as cred_file:
            encrypted_credentials = cred_file.read()
        decrypted_credentials = decrypt_data(encrypted_credentials, key)
        credentials = json.loads(decrypted_credentials)

        # Look for 'region_name' (since that's how it's saved) instead of 'region'
        if 'region_name' not in credentials:
            raise KeyError("'region_name' not found in AWS credentials. Please ensure the region is specified.")

        return {
            'aws_access_key_id': credentials['aws_access_key_id'],
            'aws_secret_access_key': credentials['aws_secret_access_key'],
            'region_name': credentials['region_name']  # Ensure region is loaded properly
        }
    else:
        # Request credentials from the user if not found
        click.echo("AWS credentials not found. Please provide them.")
        access_key = click.prompt('AWS Access Key ID')
        secret_key = click.prompt('AWS Secret Access Key')
        region = click.prompt('AWS Region')
        save_aws_credentials(access_key, secret_key, region)
        return load_aws_credentials()



def save_aws_credentials(access_key, secret_key, region):
    ensure_folder(BASE_DIR)
    key = load_key()
    credentials = {
        'aws_access_key_id': access_key,
        'aws_secret_access_key': secret_key,
        'region_name': region
    }
    encrypted_credentials = encrypt_data(json.dumps(credentials), key)
    with open(AWS_CREDENTIALS_FILE, 'wb') as cred_file:
        cred_file.write(encrypted_credentials)
    os.chmod(AWS_CREDENTIALS_FILE, 0o600)
    click.echo("AWS credentials encrypted and saved locally.")

#section4

@click.group(invoke_without_command=True)
@click.option('--v', '--version', is_flag=True, help="Show version of the devops-bot tool.")
@click.option('--debug', is_flag=True, help="Enable debug mode to show full error tracebacks.")
@click.pass_context
def cli(ctx, v, debug):
    ctx.ensure_object(dict)
    ctx.obj['DEBUG'] = debug  # Store debug mode in the context

    if v:
        # Collect version details
        tool_version = "devops-bot, version 0.1"
        python_version = platform.python_version()
        os_info = platform.system()
        os_version = platform.release()

        # Display robust version information
        click.echo(f"{tool_version}\nPython Version: {python_version}\nOperating System: {os_info} {os_version}")
        ctx.exit()

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())

@cli.command(name="brood", help="Manage DevOps bot files.")
@click.option('--init', is_flag=True, help="Initialize the file structure.")
def brood(init):
    if init:
        initialize_files()  # Initialize files like pigeon.dob, etc.
        init_config_file()  # Initialize the pigeon.dob config file
    else:
        click.echo("No action specified. Use --init to initialize files.")

# List of filenames to be created
FILES = [
    "molt.dob", "roost.dob", "peacock.dob",
    "ostrich.dob", "crow.dob", "parrot.dob",
    "pelican.dob", "falcon.dob", "pigeon.dob", "macaw.dob",
    "eagle.dob", "goose.dob", "turkey.dob"
]


def initialize_files():
    """
    Initialize necessary files in the BASE_DIR directory.
    """
    # Ensure the base directory exists
    os.makedirs(BASE_DIR, exist_ok=True)

    # Create each file in the base directory
    for file_name in FILES:
        file_path = os.path.join(BASE_DIR, file_name)
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                f.write("")  # Create an empty file
            click.echo(click.style(f"Created file: {file_path}", fg="green"))
        else:
            click.echo(click.style(f"File already exists: {file_path}", fg="yellow"))


@cli.group(help="Commands to manage AWS resources.")
def aws():
    pass

# Add the config subcommand to the AWS group
@aws.command(name="config", help="Configure AWS credentials for the DevOps-bot tool.")
@click.option('--ak', '--access_key', 'aws_access_key_id', required=True, help="AWS Access Key ID")
@click.option('--sk', '--secret_key', 'aws_secret_access_key', required=True, help="AWS Secret Access Key")
@click.option('--r', '--region', 'region', required=True, help="AWS Region")
@click.pass_context
def aws_config(ctx, aws_access_key_id, aws_secret_access_key, region):
    try:
        save_aws_credentials(aws_access_key_id, aws_secret_access_key, region)
        click.echo("AWS credentials configured successfully.")
    except Exception as e:
        handle_error(ctx, e)



def replace_placeholders(data, outputs):
    """
    Replace placeholders in the YAML configuration with actual values.
    :param data: Original YAML data with placeholders.
    :param outputs: Dictionary of actual values to replace placeholders.
    :return: Updated YAML data with placeholders replaced.
    """
    if isinstance(data, dict):
        return {k: replace_placeholders(v, outputs) for k, v in data.items()}
    elif isinstance(data, list):
        return [replace_placeholders(item, outputs) for item in data]
    elif isinstance(data, str) and data.startswith("${") and data.endswith("}"):
        # Extract the placeholder name (e.g., ${vpc_id} -> vpc_id)
        placeholder = data[2:-1]
        # Replace with actual value if exists in outputs
        return outputs.get(placeholder, data)
    else:
        return data

def execute_task(task, loop_item=None):
    # Implement the logic to execute tasks, handling loops and conditions
    pass


def resolve_dependencies_and_outputs(data, execution_id, credentials):
    """
    Resolve dependencies between resources and dynamically substitute output values.

    :param data: The entire resource configuration data from the YAML file.
    :param execution_id: The execution ID for this configuration.
    :param credentials: AWS credentials for creating resources.
    :return: Updated data with substituted values for dependencies.
    """
    # Initialize a dictionary to hold resource outputs (e.g., VPC ID, Subnet ID)
    resource_outputs = {}


#################################################### dont touch this area ####################################################

                                       ###############aws screenplay#####################
@aws.command(name="screenplay", help="Create EC2 instances, S3 buckets, and/or execute tasks on remote instances listed in /etc/hosts.")
@click.argument('screenplay', type=click.Path(exists=True), required=False)
@click.option('--yes', '-y', is_flag=True, help="Automatic yes to prompts (short: -y)")
@click.option('--remote-config', '--rc', required=False, help="URL to a remote YAML config file (short: --rc)")
@click.pass_context  # Pass the Click context object
def screenplay(ctx, screenplay,  remote_config, reuse_id=None, yes=False):
    global output_variables
    resource_outputs = {}

    execution_id = reuse_id if reuse_id else str(uuid.uuid4())
    state_file_path = os.path.join(STATE_DIR, f'{execution_id}.yaml')
    state_exicution_path = os.path.join(STATE_DIR, f'{execution_id}.yml')
    table_data = []

    if remote_config:
        data = load_remote_yaml(remote_config)
    elif screenplay:
        if screenplay.endswith('.yaml') or screenplay.endswith('.yml'):
            with open(screenplay, 'r') as yaml_file:
                data = yaml.safe_load(yaml_file)




##########################################################################################################################
## this is the first stage  8 spaces from the left #####################
##################################   stage stage ########################################

        # Handle Transit Gateways
        if 'resources' in data and 'transit_gateways' in data['resources']:
            for idx, tgw in enumerate(data['resources']['transit_gateways']):
                table_data.append(["", "", ""])
                table_data.append([click.style("+", fg="blue"), "Transit Gateway", f"TGW {idx + 1}"])
                table_data.extend([
                    [click.style("+", fg="blue"), "Description", tgw.get('description', 'Not specified')],
                    [click.style("+", fg="blue"), "Amazon ASN", tgw.get('amazon_side_asn', 'Not specified')],
                    [click.style("+", fg="blue"), "Region", tgw.get('region', 'Not specified')],
                ])
                if 'tags' in tgw:
                    table_data.append([click.style("+", fg="blue"), "Tags", tgw['tags']])

#######################################  dont touch this area ###################################################

        # Phase 2: Display the Final Review
        click.echo("\nFinal Review of All Actions:")
        if table_data:
            click.echo(tabulate(table_data, headers=["", "Category", "Value"], tablefmt="grid"))
        else:
            click.echo("No resources defined in the screenplay.")

        # Phase 3: Confirm to proceed
        if not yes:
            if not click.confirm(click.style("Do you want to proceed with executing these actions?", fg="green"), default=True):
                click.echo("Execution aborted by the user.")
                return
        click.echo(f"Proceeding with the actions... (Execution ID: {execution_id})\n")

###########################################################################################################################
## this is the second stage 8 spaces from the left
###################################   exicution stage #########################################################

        # Transit Gateway creation
        if 'resources' in data and 'transit_gateways' in data['resources']:
            credentials = load_aws_credentials()
            for tgw in data['resources']['transit_gateways']:
                region = tgw.get('region')
                if not region:
                    raise ValueError("Region is required for creating a Transit Gateway.")

                completed, resource_id, status = is_task_completed(execution_id, 'transit_gateway_creation')

                if not completed:
                    ec2 = boto3.client('ec2', region_name=region, **{k: v for k, v in credentials.items() if k != 'region_name'})
                    tgw_id = create_transit_gateway(tgw, ec2, execution_id)
                    click.echo(f"Transit Gateway created with ID: {tgw_id}")
                else:
                    click.echo(f"Transit Gateway creation skipped, already completed. Existing TGW ID: {resource_id}")
                resource_outputs['tgw_id'] = tgw_id



#########################################################  dont touch this area ##############################################

        # Phase 5: Save State
        save_execution_state(data, execution_id, state_exicution_path)
        click.echo(f"Execution complete. State saved to: {state_exicution_path} (Execution ID: {execution_id})")

        click.echo(f"Execution completed. (Execution ID: {execution_id})\n")
    elif identifier and username and command:
        try:
            private_ip, _ = get_host_entry(identifier)
            success, message = execute_command_on_server(private_ip, username, command)
            if success:
                click.echo(f"{message}")
            else:
                click.echo(f"Failed to execute command on {identifier} ({private_ip}): {message}")
        except ValueError as ve:
            click.echo(str(ve))
        return
    else:
        click.echo("You must provide either a YAML screenplay file or the identifier, username, and command directly.")
        return

    click.echo(tabulate(table_data, headers=["#", "Resource Type", "Details"], tablefmt="fancy_grid"))
##################################################################################################################################
##  this is the last stage for creation, 0 space from the left


############################## def stage  ##################################################

def create_transit_gateway(tgw_data, ec2, execution_id):
    """Create a Transit Gateway."""
    try:
        response = ec2.create_transit_gateway(
            Description=tgw_data.get('description', 'Default Transit Gateway'),
            Options={
                "AmazonSideAsn": tgw_data['options'].get('AmazonSideAsn', 64512),
                "AutoAcceptSharedAttachments": tgw_data['options'].get('AutoAcceptSharedAttachments', 'disable'),
                "DefaultRouteTableAssociation": tgw_data['options'].get('DefaultRouteTableAssociation', 'enable'),
                "DefaultRouteTablePropagation": tgw_data['options'].get('DefaultRouteTablePropagation', 'enable')
            },
            TagSpecifications=[
                {
                    'ResourceType': 'transit-gateway',
                    'Tags': tgw_data.get('tags', [])
                }
            ]
        )
        tgw_id = response['TransitGateway']['TransitGatewayId']

        # Record the Transit Gateway creation in the snapshot (state file)
        record_task_state(execution_id, 'transit_gateway', 'success', resource_id=tgw_id)

        return tgw_id
    except Exception as e:
        click.echo(click.style(f"Failed to create Transit Gateway: {e}", fg="red"))
        return None

###########################################################################################################

      ########################   this is destroy stage ##################################

#############################################################################################################

####  stage for ############################## dont touch some part of this stage ####################

### destoy command  ###########################################


###############  you can touch this area ################################
#####  destroy  stage, 16 spaces from the left  ######################
@aws.command(name="destroy", help="Destroy resources based on execution ID.")
@click.argument('execution_id', type=str)
@click.option('--ignore-yml', '--iy', is_flag=True, help="Ignore the .yml file and only delete the .yaml file (short: --iy).")
def destroy(execution_id, ignore_yml):
    """Destroy resources based on the given execution ID and optionally remove state files."""

    state_file_path_yaml = os.path.join(STATE_DIR, f'{execution_id}.yaml')
    state_file_path_yml = os.path.join(STATE_DIR, f'{execution_id}.yml')

    if not os.path.exists(state_file_path_yaml):
        click.echo(f"No state file found for execution ID: {execution_id}. Unable to proceed with destruction.")
        return

    # Load the state file
    with open(state_file_path_yaml, 'r') as file:
        state_data = yaml.safe_load(file)

    # Initialize the EC2 client
    credentials = load_aws_credentials()
    ec2 = boto3.client('ec2', **credentials)

    # Go through the resources and destroy them
    destroy_resources(state_data, ec2, execution_id, credentials)
    click.echo(f"Destroy process completed for execution ID: {execution_id}")

    # Check if we should delete the state files after destruction
    try:
        # Delete the .yaml state file
        if os.path.exists(state_file_path_yaml):
            os.remove(state_file_path_yaml)
            click.echo(f"Deleted YAML state file: {state_file_path_yaml}")

        # Delete the .yml state file if --ignore-yml is not passed
        if not ignore_yml and os.path.exists(state_file_path_yml):
            os.remove(state_file_path_yml)
            click.echo(f"Deleted YML state file: {state_file_path_yml}")

    except Exception as e:
        click.echo(click.style(f"Error deleting state files: {e}", fg="red"))

# Priority mapping for resource destruction
RESOURCE_PRIORITY = {
    'ec2_instance': 10,
    'target_group': 20,
    'nat_gateway': 30,
    'elastic_ip': 40,
    'network_interface': 50,
    'subnet_creation': 70,  # Adjusting this priority to be after EC2
    'route_table': 80,
    'internet_gateway': 90,
    'security_group': 100,
    'vpc_creation': 110,
    'transit_gateway_multicast_creation': 120,
    'transit_gateway_route_table_creation': 130,
    'transit_gateway_policy_table_creation': 140,
}

def destroy_resources(state_data, ec2, execution_id, credentials):
    """Destroy resources recorded in the state file according to priority, with wait mechanisms for dependencies."""
    if 'tasks' in state_data:
        # Sort the tasks based on the predefined RESOURCE_PRIORITY mapping
        sorted_tasks = sorted(
            state_data['tasks'].items(),
            key=lambda item: RESOURCE_PRIORITY.get(re.sub(r'_\d+$', '', item[0]), 999)
        )

        for task_name, task_info in sorted_tasks:
            resource_id = task_info.get('resource_id')
            # Check if the resource is already marked as destroyed
            if task_info['status'] == 'destroyed':
                click.echo(f"Resource {resource_id} is already destroyed. Skipping...")
                continue

            if task_info['status'] == 'success' and resource_id:

                if 'target_registration' in task_name:
                    click.echo(f"Deregistering targets for Target Group: {resource_id}")
                    targets = task_info.get('targets', [])  # Ensure 'targets' list is retrieved from the task_info
                    deregister_targets(resource_id, targets, elb_client, execution_id)  # Corrected function call


                elif 'transit_gateway' in task_name:
                    click.echo(f"Destroying Transit Gateway: {resource_id}")
                    destroy_transit_gateway(resource_id, execution_id)
                    wait_for_tgw_deletion(resource_id, credentials)

    click.echo(f"Destroy process completed for execution ID: {execution_id}")








#######################################################################################################

###############  stage 5, 0 space from the left

################################ waiting stage, not all resurces need waiting  ###################
def wait_for_tgw_deletion(tgw_id, credentials):
    """Wait for the Transit Gateway to be deleted."""
    ec2 = boto3.client('ec2', **credentials)
    while True:
        try:
            response = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])
            # Check the Transit Gateway's state
            if response['TransitGateways']:
                state = response['TransitGateways'][0].get('State')
                if state.lower() == 'deleted':
                    click.echo(f"Transit Gateway {tgw_id} deleted successfully.")
                    break
                else:
                    click.echo(f"Transit Gateway {tgw_id} is in state: {state}. Waiting for deletion...")
            else:
                click.echo(f"Transit Gateway {tgw_id} no longer exists.")
                break
        except ec2.exceptions.ClientError as e:
            if 'InvalidTransitGatewayID.NotFound' in str(e):
                click.echo(f"Transit Gateway {tgw_id} no longer exists.")
                break
            else:
                click.echo(f"Unexpected error while waiting for Transit Gateway deletion: {e}")
                raise
        time.sleep(5)

def wait_for_route_table_deletion(route_table_id, credentials):
    """Wait for the route table to be deleted."""
    ec2 = boto3.client('ec2', **credentials)
    while True:
        try:
            response = ec2.describe_transit_gateway_route_tables(
                TransitGatewayRouteTableIds=[route_table_id]
            )
            # Check if the route table no longer exists
            if not response['TransitGatewayRouteTables']:
                break
        except ec2.exceptions.ClientError as e:
            # Handle 'not found' error as confirmation of deletion
            if 'InvalidRouteTableID.NotFound' in str(e):
                click.echo(f"Route Table {route_table_id} deleted successfully.")
                break
            else:
                click.echo(f"Unexpected error while waiting for Route Table deletion: {e}")
                raise
        click.echo(f"Waiting for Route Table {route_table_id} to be deleted...")
        time.sleep(5)



def clear_route_table_associations(route_table_id, credentials):
    ec2 = boto3.client('ec2', **credentials)
    try:
        associations = ec2.get_transit_gateway_route_table_associations(
            TransitGatewayRouteTableId=route_table_id
        )['Associations']
        for association in associations:
            ec2.disassociate_transit_gateway_route_table(
                TransitGatewayAttachmentId=association['TransitGatewayAttachmentId'],
                TransitGatewayRouteTableId=route_table_id
            )
            click.echo(f"Disassociated Route Table: {route_table_id}")
    except Exception as e:
        click.echo(click.style(f"Failed to clear associations for {route_table_id}: {e}", fg="red"))


def clear_route_table_propagations(route_table_id, credentials):
    """Remove all propagations from a Transit Gateway Route Table."""
    ec2 = boto3.client('ec2', **credentials)
    try:
        propagations = ec2.get_transit_gateway_route_table_propagations(
            TransitGatewayRouteTableId=route_table_id
        )['TransitGatewayRouteTablePropagations']

        for propagation in propagations:
            click.echo(f"Removing propagation from Route Table: {route_table_id}")
            ec2.disable_transit_gateway_route_table_propagation(
                TransitGatewayRouteTableId=route_table_id,
                TransitGatewayAttachmentId=propagation['TransitGatewayAttachmentId']
            )
    except Exception as e:
        click.echo(click.style(f"Failed to clear propagations for Route Table {route_table_id}: {e}", fg="red"))

def unset_default_route_tables(tgw_id, credentials):
    """Unset default propagation and association route tables for the Transit Gateway."""
    ec2 = boto3.client('ec2', **credentials)

    try:
        # Unset the default propagation route table
        click.echo(f"Unsetting default propagation route table for Transit Gateway: {tgw_id}")
        ec2.modify_transit_gateway(
            TransitGatewayId=tgw_id,
            Options={"DefaultRouteTablePropagation": "disable"}
        )
        click.echo("Successfully unset default propagation route table.")

        # Unset the default association route table
        click.echo(f"Unsetting default association route table for Transit Gateway: {tgw_id}")
        ec2.modify_transit_gateway(
            TransitGatewayId=tgw_id,
            Options={"DefaultRouteTableAssociation": "disable"}
        )
        click.echo("Successfully unset default association route table.")

    except Exception as e:
        click.echo(click.style(f"Failed to unset default route tables for {tgw_id}: {e}", fg="red"))


def unset_default_propagation_route_table(tgw_id, route_table_id, credentials):
    """Unset the default propagation route table for the Transit Gateway."""
    ec2 = boto3.client('ec2', **credentials)
    try:
        click.echo(f"Unsetting default propagation route table: {route_table_id} for Transit Gateway: {tgw_id}")
        ec2.modify_transit_gateway(
            TransitGatewayId=tgw_id,
            Options={
                "DefaultRouteTablePropagation": False
            }
        )
        click.echo(f"Successfully unset default propagation route table for Transit Gateway: {tgw_id}")
    except Exception as e:
        click.echo(click.style(f"Failed to unset default propagation route table for {tgw_id}: {e}", fg="red"))







#########################################################################################################
###  6 stage, 0 from the left
###############################  def for destroy ############################################
def destroy_transit_gateway(tgw_id, execution_id):
    """Delete Transit Gateway with dependency handling."""
    credentials = load_aws_credentials()
    ec2 = boto3.client('ec2', **credentials)
    try:
        # Handle Transit Gateway Route Tables
        route_tables = ec2.describe_transit_gateway_route_tables(
            Filters=[{'Name': 'transit-gateway-id', 'Values': [tgw_id]}]
        )['TransitGatewayRouteTables']

        for route_table in route_tables:
            route_table_id = route_table['TransitGatewayRouteTableId']
            click.echo(f"Clearing dependencies for Route Table: {route_table_id}")

            # Unset the default propagation and association route tables
            unset_default_route_tables(tgw_id, credentials)

            clear_route_table_associations(route_table_id, credentials)

            click.echo(f"Deleting Transit Gateway Route Table: {route_table_id}")
            ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_id)
            wait_for_route_table_deletion(route_table_id, credentials)

        # Handle Transit Gateway Attachments
        attachments = ec2.describe_transit_gateway_attachments(
            Filters=[{'Name': 'transit-gateway-id', 'Values': [tgw_id]}]
        )['TransitGatewayAttachments']

        for attachment in attachments:
            attachment_id = attachment['TransitGatewayAttachmentId']
            click.echo(f"Deleting Transit Gateway Attachment: {attachment_id}")
            ec2.delete_transit_gateway_attachment(TransitGatewayAttachmentId=attachment_id)
            wait_for_attachment_deletion(attachment_id, credentials)

        # Delete the Transit Gateway itself
        click.echo(f"Deleting Transit Gateway: {tgw_id}")
        ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
        wait_for_tgw_deletion(tgw_id, credentials)

        # Update state to mark as destroyed
        update_task_state(execution_id, 'transit_gateway_creation', 'destroyed', resource_id=tgw_id)

    except Exception as e:
        click.echo(click.style(f"Unexpected error during Transit Gateway deletion: {e}", fg="red"))

def destroy_transit_gateway_attachment(attachment_id, execution_id):
    credentials = load_aws_credentials()
    ec2 = boto3.client('ec2', **credentials)

    try:
        ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment_id)
        click.echo(f"Deleted Transit Gateway Attachment: {attachment_id}")
        update_task_state(execution_id, 'transit_gateway_attachment_creation', 'destroyed', resource_id=attachment_id)
    except ClientError as e:
        click.echo(f"Failed to delete Transit Gateway Attachment {attachment_id}: {e}")

def destroy_transit_gateway_policy_table(policy_table_id, execution_id):
    credentials = load_aws_credentials()
    ec2 = boto3.client('ec2', **credentials)

    try:
        ec2.delete_transit_gateway_policy_table(TransitGatewayPolicyTableId=policy_table_id)
        click.echo(f"Deleted Transit Gateway Policy Table: {policy_table_id}")
        update_task_state(execution_id, 'transit_gateway_policy_table_creation', 'destroyed', resource_id=policy_table_id)
    except ClientError as e:
        click.echo(f"Failed to delete Transit Gateway Policy Table {policy_table_id}: {e}")

def destroy_transit_gateway_route_table(route_table_id, execution_id):
    credentials = load_aws_credentials()
    ec2 = boto3.client('ec2', **credentials)

    try:
        ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_id)
        click.echo(f"Deleted Transit Gateway Route Table: {route_table_id}")
        update_task_state(execution_id, 'transit_gateway_route_table_creation', 'destroyed', resource_id=route_table_id)
    except ClientError as e:
        click.echo(f"Failed to delete Transit Gateway Route Table {route_table_id}: {e}")






##########################################   dont touch  ###################################################

# Define the is_task_completed function
def is_task_completed(execution_id, task_name):
    """
    Check if the specified task has been completed successfully or failed.

    :param execution_id: The execution ID to check in the state file.
    :param task_name: The name of the task to check (e.g., 'vpc_creation').
    :return: Tuple (True/False, resource_id, status) where:
             - True if the task status is 'success', False otherwise.
             - resource_id if the task is completed successfully, None otherwise.
             - status to indicate 'success', 'failed', or 'not_found'.
    """
    state_file_path = os.path.join(STATE_DIR, f'{execution_id}.yaml')
    if not os.path.exists(state_file_path):
        return False, None, 'not_found'  # Ensure 3 values are returned

    with open(state_file_path, 'r') as file:
        state_data = yaml.safe_load(file)

    # Check if the task is marked as 'success' or 'failed' in the state file
    tasks = state_data.get('tasks', {})
    task_info = tasks.get(task_name, {})
    status = task_info.get('status', 'not_found')
    resource_id = task_info.get('resource_id', None)  # Extract the resource ID if available

    if status == 'success':
        return True, resource_id, 'success'
    elif status == 'failed':
        return False, resource_id, 'failed'
    else:
        return False, None, 'not_found'

def check_dependencies(execution_id, dependencies):
    """
    Check if all dependencies are met before creating a resource.

    :param execution_id: The execution ID for checking the state.
    :param dependencies: List of dependencies (task names) that must be met.
    :return: Tuple (True/False, unmet_dependency) where:
             - True if all dependencies are met, False otherwise.
             - unmet_dependency returns the first unmet dependency or None.
    """
    state_file_path = os.path.join(STATE_DIR, f'{execution_id}.yaml')
    if not os.path.exists(state_file_path):
        click.echo(f"State file not found for Execution ID: {execution_id}")
        return False, "State file missing"

    with open(state_file_path, 'r') as file:
        state_data = yaml.safe_load(file)

    for dependency in dependencies:
        task_info = state_data.get('tasks', {}).get(dependency, {})
        if task_info.get('status') != 'success':
            return False, dependency  # Return the first unmet dependency

    return True, None

def save_instance_ips(instances):
    existing_names = set()

    # Read the existing names from the hosts file to avoid duplicates
    with open(HOSTS_FILE, 'r') as hosts_file:
        for line in hosts_file:
            parts = line.split()
            if len(parts) >= 2 and not line.startswith('#'):
                existing_names.add(parts[1])

    with open(HOSTS_FILE, 'a') as hosts_file:
        for idx, instance in enumerate(instances):
            ip = instance['private_ip']
            name = instance.get('name') or f"user{idx + 1}"

            if name in existing_names:
                print(f"Error: The hostname '{name}' already exists in {HOSTS_FILE}. Please change the name manually.")
            else:
                hosts_file.write(f"{ip}\t{name}\n")
                print(f"Added {name} with IP {ip} to {HOSTS_FILE}")

os.makedirs(STATE_DIR, exist_ok=True)

def update_task_state(execution_id, task_name, status, resource_id=None):
    """Update the task state in the state file."""
    state_file_path = os.path.join(STATE_DIR, f'{execution_id}.yaml')

    if os.path.exists(state_file_path):
        with open(state_file_path, 'r') as file:
            state_data = yaml.safe_load(file)
    else:
        state_data = {'tasks': {}}

    # Update the task status
    state_data['tasks'][task_name] = {
        'status': status,
        'resource_id': resource_id
    }

    # Save the updated state back to the file
    with open(state_file_path, 'w') as file:
        yaml.dump(state_data, file)

def record_task_state(execution_id, task_name, status, resource_id=None):
    """Update the state file for a given task."""
    state_file_path = os.path.join(STATE_DIR, f'{execution_id}.yaml')

    if os.path.exists(state_file_path):
        with open(state_file_path, 'r') as file:
            state_data = yaml.safe_load(file)
    else:
        state_data = {'tasks': {}}

    # Ensure task names are unique for each instance
    task_count = len([key for key in state_data['tasks'] if task_name in key])
    unique_task_name = f"{task_name}_{task_count}" if task_count > 0 else task_name

    # Update the task status
    state_data['tasks'][unique_task_name] = {
        'status': status,
        'resource_id': resource_id
    }

    # Save the updated state back to the file
    with open(state_file_path, 'w') as file:
        yaml.dump(state_data, file)

def save_execution_state(data, execution_id, state_exicution_path):
    """Save the state of the executed screenplay along with resource IDs for future reference."""
    # Create a copy of the data dictionary without the tasks section
    resources_data = data.copy()
    resources_data.pop('tasks', None)  # Remove the 'tasks' from the execution state if present

    # Ensure the 'resources' key is present in resources_data
    if 'resources' not in resources_data:
        click.echo(click.style(f"Warning: No resources found in the current screenplay.", fg="yellow"))
        resources_data['resources'] = {}

    # Attach the resource IDs to the original YAML structure
    state_data = {
        'execution_id': execution_id,
        'resources': resources_data['resources'],
    }

    # Order resources based on creation priority (reverse of destruction priority)
    ordered_resources = sorted(
        state_data['resources'].items(),
        key=lambda item: -RESOURCE_PRIORITY.get(item[0], 0)
    )

    state_data['resources'] = dict(ordered_resources)

    # If the file already exists (re-execution), load and update it instead of overwriting
    if os.path.exists(state_exicution_path):
        with open(state_exicution_path, 'r') as file:
            existing_data = yaml.safe_load(file)
        # Merge the new data with existing data
        existing_data.update(state_data)
        state_data = existing_data

    # Save the full YAML data (with resources) and the created resource IDs
    os.makedirs(STATE_DIR, exist_ok=True)  # Ensure the directory exists
    with open(state_exicution_path, 'w') as state_file:
        yaml.dump(state_data, state_file)

    click.echo(f"Execution state saved to: {state_exicution_path}")

def load_remote_yaml(remote_url):
    """
    Load a YAML config file from a remote URL.
    """
    try:
        response = requests.get(remote_url)
        response.raise_for_status()

        # Validate the content type
        content_type = response.headers.get('Content-Type')
        if 'yaml' not in content_type and 'text' not in content_type:
            print(f"Unexpected content type: {content_type}. Make sure the URL points to a raw YAML file.")
            return {}

        # Parse and return the YAML data
        try:
            yaml_data = yaml.safe_load(response.text)
            return yaml_data
        except yaml.YAMLError as e:
            print(f"Failed to parse YAML content from remote file: {e}")
            return {}

    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch remote YAML file: {e}")
        return {}



###########################################################################################################

