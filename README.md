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
