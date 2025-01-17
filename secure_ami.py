import boto3 # type: ignore
import os
import sys
import logging
from botocore.exceptions import ClientError # type: ignore
#from dotenv import load_dotenv
import time

# Load environment variables from .env file
#load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")


def create_kms_key():
    """Create or retrieve a KMS key for EBS encryption."""
    kms_client = boto3.client("kms", region_name=os.getenv("AWS_REGION"))
    alias_name = "alias/ami-encryption-key"

    try:
        response = kms_client.list_aliases()
        for alias in response.get("Aliases", []):
            if alias["AliasName"] == alias_name:
                logging.info(f"KMS key already exists: {alias_name} ({alias['TargetKeyId']})")
                return alias["TargetKeyId"]

        response = kms_client.create_key(Description="AMI Encryption Key")
        key_id = response["KeyMetadata"]["KeyId"]
        kms_client.create_alias(AliasName=alias_name, TargetKeyId=key_id)
        logging.info(f"KMS key created: {alias_name} ({key_id})")
        return key_id
    except ClientError as e:
        logging.error(f"Error managing KMS key: {e}")
        sys.exit(1)


def create_key_pair():
    """Create a key pair for SSH access."""
    ec2_client = boto3.client("ec2", region_name=os.getenv("AWS_REGION"))
    key_pair_name = os.getenv("KEY_PAIR_NAME")

    try:
        ec2_client.create_key_pair(KeyName=key_pair_name)
        logging.info(f"Key pair {key_pair_name} created.")
    except ClientError as e:
        if "InvalidKeyPair.Duplicate" in str(e):
            logging.info(f"Key pair {key_pair_name} already exists.")
        else:
            logging.error(f"Error creating key pair: {e}")
            sys.exit(1)


def create_security_group():
    """Create a security group with SSH access restricted to your IP."""
    ec2_client = boto3.client("ec2", region_name=os.getenv("AWS_REGION"))
    security_group_name = os.getenv("SECURITY_GROUP_NAME")
    my_public_ip = os.getenv("MY_PUBLIC_IP")

    try:
        response = ec2_client.create_security_group(
            Description="AMI Security Group", GroupName=security_group_name
        )
        sg_id = response["GroupId"]
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": f"{my_public_ip}/32"}],
                }
            ],
        )
        logging.info(f"Security group {security_group_name} created with ID: {sg_id}")
        return sg_id
    except ClientError as e:
        logging.error(f"Error managing security group: {e}")
        sys.exit(1)


def wait_for_instance_state(instance_id, desired_state="running", timeout=300):
    """Wait for the instance to reach the desired state."""
    ec2_client = boto3.client("ec2", region_name=os.getenv("AWS_REGION"))
    start_time = time.time()
    initial_wait = 10  # Wait before first query to handle propagation delays

    logging.info(f"Waiting for instance {instance_id} to reach state '{desired_state}'...")

    # Wait for a few seconds to allow AWS to register the instance ID
    logging.info(f"Waiting {initial_wait} seconds for instance ID propagation...")
    time.sleep(initial_wait)

    while time.time() - start_time < timeout:
        try:
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            state = response["Reservations"][0]["Instances"][0]["State"]["Name"]
            logging.info(f"Current state of instance {instance_id}: {state}")
            if state == desired_state:
                logging.info(f"Instance {instance_id} is now in state: {desired_state}")
                return
        except ClientError as e:
            if "InvalidInstanceID.NotFound" in str(e):
                logging.warning(f"Instance ID {instance_id} not yet found. Retrying...")
            else:
                logging.error(f"Unexpected error: {e}")
                sys.exit(1)
        time.sleep(10)

    logging.error(f"Instance {instance_id} did not reach state '{desired_state}' within {timeout} seconds.")
    sys.exit(1)


def launch_instance(sg_id, kms_key_id):
    """Launch an encrypted EC2 instance."""
    ec2_client = boto3.client("ec2", region_name=os.getenv("AWS_REGION"))
    try:
        response = ec2_client.run_instances(
            ImageId=os.getenv("BASE_AMI_ID"),
            InstanceType=os.getenv("INSTANCE_TYPE"),
            KeyName=os.getenv("KEY_PAIR_NAME"),
            SecurityGroupIds=[sg_id],
            MinCount=1,
            MaxCount=1,
            BlockDeviceMappings=[
                {
                    "DeviceName": "/dev/xvda",
                    "Ebs": {"VolumeSize": 10, "VolumeType": "gp3", "Encrypted": True, "KmsKeyId": kms_key_id},
                }
            ],
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": "SecureInstance"}],
                }
            ],
        )
        instance_id = response["Instances"][0]["InstanceId"]
        logging.info(f"Instance {instance_id} launched.")
        wait_for_instance_state(instance_id, "running")
        return instance_id
    except ClientError as e:
        logging.error(f"Error launching EC2 instance: {e}")
        sys.exit(1)


def create_ami(instance_id):
    """Create an AMI from the instance."""
    ec2_client = boto3.client("ec2", region_name=os.getenv("AWS_REGION"))
    try:
        ami_name = "SecureAMI"
        response = ec2_client.create_image(
            InstanceId=instance_id,
            Name=ami_name,
            Description="A secure AMI created from SecureInstance",
            NoReboot=True,
        )
        ami_id = response["ImageId"]
        logging.info(f"AMI creation initiated: {ami_id}")
        return ami_id
    except ClientError as e:
        logging.error(f"Error creating AMI: {e}")
        sys.exit(1)


def verify_ami_ownership(ami_id):
    """Verify that the created AMI is owned by your AWS account."""
    ec2_client = boto3.client("ec2", region_name=os.getenv("AWS_REGION"))
    try:
        response = ec2_client.describe_images(ImageIds=[ami_id])
        owner_id = response["Images"][0]["OwnerId"]
        logging.info(f"AMI {ami_id} is owned by account: {owner_id}")
    except ClientError as e:
        logging.error(f"Error verifying AMI ownership: {e}")
        sys.exit(1)


def main():
    # Validate required environment variables
    required_vars = [
        "AWS_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "INSTANCE_TYPE",
        "BASE_AMI_ID",
        "KEY_PAIR_NAME",
        "SECURITY_GROUP_NAME",
        "MY_PUBLIC_IP",
    ]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        logging.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        sys.exit(1)

    # Run the secure AMI creation process
    logging.info("Starting secure AMI creation process...")
    kms_key_id = create_kms_key()
    create_key_pair()
    sg_id = create_security_group()
    instance_id = launch_instance(sg_id, kms_key_id)
    ami_id = create_ami(instance_id)
    verify_ami_ownership(ami_id)
    logging.info("Secure AMI creation process completed successfully.")


if __name__ == "__main__":
    main()


























