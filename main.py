'''
AWS EC2 compliance checker
2019 Michele Grano
----------------------------------------------------------------------------------
Performs security group check against ec2 instances in an aws account
Currently checks for wide open security groups via wildcard ip addresses 0.0.0.0/0
as well as unspecified port ranges. Flags any open port that is not 80, 443, or 22
----------------------------------------------------------------------------------
Takes region parameter as command line argument --region <region>, will be expanded
with different kinds of inputs in the future
-----------------------------------------------------------------------------------
'''

import boto3
import argparse
from botocore.config import Config

# Lists for testing
# regions = ["us-east-1","ap-southeast-1","ap-southeast-2","ap-northeast-1","eu-central-1","eu-west-1"]
# regions = ["eu-central-1"]

#Initialize argparser
parser = argparse.ArgumentParser(description='EC2 compliance check')
parser.add_argument("--h", help="--q to quit, --region AWS region")
parser.add_argument("--region", type=str, help="AWS region")
args = parser.parse_args()
regions = [args.region]

#AWS configuration for retry
config = Config(
    retries = dict(
        max_attempts = 10
    )
)

#appends uncompliant security groups to list
uncompliant_security_groups = []

for region in regions:
    ec2 = boto3.resource('ec2', config=config, region_name=region)

    sgs = list(ec2.security_groups.all())

    for sg in sgs:
        for rule in sg.ip_permissions:
            # Check if list of IpRanges is not empty, source ip meets conditions
            if len(rule.get('IpRanges')) > 0 and rule.get('IpRanges')[0]['CidrIp'] == '0.0.0.0/0':
                if not rule.get('FromPort'):
                    uncompliant_security_groups.append(sg)

                if rule.get('FromPort') and rule.get('FromPort') < 1024 and rule.get('FromPort') != 80 and rule.get('FromPort') != 443 and rule.get('FromPort') != 22:
                    uncompliant_security_groups.append(sg)

#compares security groups assigned to instances to the ones in the uncompliant list
uncompliant_ec2_list = []

for region in regions:
    ec2 = boto3.client('ec2', config=config, region_name=region)

    response = ec2.describe_instances()
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            if instance["SecurityGroups"] not in uncompliant_security_groups:
                uncompliant_ec2 = {'Instance_ID': instance["InstanceId"], 'Public_IP': instance["PublicIpAddress"]}
                uncompliant_ec2_list.append(uncompliant_ec2)

#for table printing
def get_pretty_table(iterable, header):
    max_len = [len(x) for x in header]
    for row in iterable:
        row = [row] if type(row) not in (list, tuple) else row
        for index, col in enumerate(row):
            if max_len[index] < len(str(col)):
                max_len[index] = len(str(col))
    output = '-' * (sum(max_len) + 1) + '\n'
    output += '|' + ''.join([h + ' ' * (l - len(h)) + '|' for h, l in zip(header, max_len)]) + '\n'
    output += '-' * (sum(max_len) + 1) + '\n'
    for row in iterable:
        row = [row] if type(row) not in (list, tuple) else row
        output += '|' + ''.join([str(c) + ' ' * (l - len(str(c))) + '|' for c, l in zip(row, max_len)]) + '\n'
    output += '-' * (sum(max_len) + 1) + '\n'
    return output

print(get_pretty_table(uncompliant_ec2_list, ['Instance ID     |||   IP Address']))
