"""The regression fixture: one small, fictional AWS account in an incident window.

    python make_fixture.py out/seed.json [--credentials-out PATH] [--big]

`--big` adds bulk history in the proportions of a real OnCallWorlds seed (400 setup calls,
~150k datapoints, ~15k CloudTrail records, ~20k log lines) for the boot measurement.
"""

from __future__ import annotations

import argparse
import json
import os
import math
import random
import uuid
from datetime import datetime, timezone

from seedkit import SeedBuilder, ref

ACCOUNT = os.environ.get("OCW_FIXTURE_ACCOUNT", "418295736104")
REGION = "us-east-1"
# The pickup: 2026-03-19 15:00:00 UTC. The incident window is the six hours before it.
NOW = datetime(2026, 3, 19, 15, 0, 0, tzinfo=timezone.utc).timestamp()
ONSET = NOW - 40 * 60
DAY = 86400.0

VPC = "vpc-0a1b2c3d4e5f60718"
SUBNETS = {"a": "subnet-0aa11bb22cc33dd44", "b": "subnet-0bb22cc33dd44ee55",
           "c": "subnet-0cc33dd44ee55ff66"}
SUBNET_CIDR = {"a": "10.40.16.0/20", "b": "10.40.32.0/20", "c": "10.40.48.0/20"}
SG_ALB, SG_NODE, SG_DB = "sg-0a0a0a0a0a0a0a0a1", "sg-0b0b0b0b0b0b0b0b2", "sg-0c0c0c0c0c0c0c0c3"
NODES = [("i-0f1e2d3c4b5a69788", "a", "10.40.17.23"), ("i-0e2d3c4b5a6978877", "b", "10.40.33.41"),
         ("i-0d3c4b5a697887766", "c", "10.40.49.12")]
LB_ID, TG_ID = "8f1c2d3e4b5a6978", "3e4b5a69788f1c2d"
LB_ARN = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/larch-prod-edge/{LB_ID}"
TG_ARN = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:targetgroup/larch-api-tg/{TG_ID}"
ZONE = "Z0412345ABCDEFGHIJKLM"
SSO_ADMIN = {
    "type": "AssumedRole",
    "principalId": "AROAV7LARCHADMIN00001:dana.okafor@larch.example",
    "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/AWSReservedSSO_PlatformAdmin_5d1e2f3a4b5c6d7e/dana.okafor@larch.example",
    "accountId": ACCOUNT,
    "accessKeyId": "ASIAV7LARCHDANA00001",
    "sessionContext": {
        "sessionIssuer": {"type": "Role", "principalId": "AROAV7LARCHADMIN00001",
                          "arn": f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_PlatformAdmin_5d1e2f3a4b5c6d7e",
                          "accountId": ACCOUNT,
                          "userName": "AWSReservedSSO_PlatformAdmin_5d1e2f3a4b5c6d7e"},
        "attributes": {"creationDate": "2026-03-19T13:51:02Z", "mfaAuthenticated": "false"}},
}


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def trail(name: str, source: str, ts: float, params: dict, response=None, *, who=None,
          read_only=False, resources=None, lookup=None, ip="10.40.3.17",
          agent="aws-cli/2.27.31 md/awscrt#0.26.1 ua/2.1 os/macos#24.6.0 md/arch#arm64 lang/python#3.13.5 md/pyimpl#CPython m/E,N,b exec-env/OCW cfg/retry-mode#standard md/installer#source md/prompt#off md/command#ec2.revoke-security-group-ingress"):
    record = {
        "eventVersion": "1.11", "userIdentity": who or SSO_ADMIN, "eventTime": iso(ts),
        "eventSource": source, "eventName": name, "awsRegion": REGION,
        "sourceIPAddress": ip, "userAgent": agent, "requestParameters": params,
        "responseElements": response, "requestID": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"r{name}{ts}")),
        "eventID": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"e{name}{ts}")), "readOnly": read_only,
        "eventType": "AwsApiCall", "managementEvent": True, "recipientAccountId": ACCOUNT,
        "eventCategory": "Management",
        "tlsDetails": {"tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256",
                       "clientProvidedHostHeader": f"{source.split('.')[0]}.{REGION}.amazonaws.com"},
    }
    if resources:
        record["resources"] = resources
    if lookup:
        record["_lookup_resources"] = lookup
    return record


def build(credentials_out: str, big: bool) -> dict:
    s = SeedBuilder(account_id=ACCOUNT, now=NOW, region=REGION)
    born = NOW - 420 * DAY

    # --- network ---------------------------------------------------------------------
    s.call("ec2", "CreateVpc", {"CidrBlock": "10.40.0.0/16", "TagSpecifications": [
        {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": "larch-prod"}]}]},
        at=born, capture={"vpc": "VpcId"},
        ids={"vpc": [VPC], "acl": ["acl-0d1d2d3d4d5d6d7d8"], "rtb": ["rtb-0e1e2e3e4e5e6e7e8"],
             "sg": ["sg-0f1f2f3f4f5f6f7f8"]})
    for zone, subnet in SUBNETS.items():
        s.call("ec2", "CreateSubnet", {"VpcId": ref("vpc"), "CidrBlock": SUBNET_CIDR[zone],
                                       "AvailabilityZone": f"{REGION}{zone}"},
               at=born + 600, ids={"subnet": [subnet]})
    for name, sg, desc in (("larch-alb", SG_ALB, "public ALB"),
                           ("eks-nodegroup-general", SG_NODE, "EKS node group"),
                           ("larch-ledger-db", SG_DB, "ledger database")):
        s.call("ec2", "CreateSecurityGroup", {"GroupName": name, "Description": desc,
                                              "VpcId": ref("vpc")},
               at=born + 900, ids={"sg": [sg]})
    s.call("ec2", "AuthorizeSecurityGroupIngress", {"GroupId": SG_DB, "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
         "UserIdGroupPairs": [{"GroupId": SG_NODE, "Description": "eks nodes"}]}]},
        at=born + 1000, ids={"sgr": ["sgr-0123456789abcdef0"]})
    for i, (instance, zone, ip) in enumerate(NODES):
        s.call("ec2", "RunInstances", {
            "ImageId": "ami-0c1d2e3f4a5b6c7d8", "InstanceType": "m6i.2xlarge", "MinCount": 1,
            "MaxCount": 1, "SubnetId": SUBNETS[zone], "PrivateIpAddress": ip,
            "SecurityGroupIds": [SG_NODE],
            "TagSpecifications": [{"ResourceType": "instance", "Tags": [
                {"Key": "Name", "Value": "larch-prod-general"},
                {"Key": "eks:nodegroup-name", "Value": "general"}]}]},
            at=NOW - (20 - i) * DAY, ids={"i": [instance]})

    # --- load balancer ----------------------------------------------------------------
    s.call("elbv2", "CreateLoadBalancer", {"Name": "larch-prod-edge", "Subnets": list(SUBNETS.values()),
                                           "SecurityGroups": [SG_ALB], "Scheme": "internet-facing"},
           at=born + 2000, ids={"elbv2": [LB_ID]}, capture={"lb": "LoadBalancerArn"})
    s.call("elbv2", "CreateTargetGroup", {"Name": "larch-api-tg", "Protocol": "HTTP", "Port": 8080,
                                          "VpcId": ref("vpc"), "TargetType": "instance",
                                          "HealthCheckPath": "/healthz"},
           at=born + 2100, ids={"elbv2": [TG_ID]}, capture={"tg": "TargetGroupArn"})
    s.call("elbv2", "CreateListener", {"LoadBalancerArn": ref("lb"), "Protocol": "HTTP", "Port": 80,
                                       "DefaultActions": [{"Type": "forward", "TargetGroupArn": ref("tg")}]},
           at=born + 2200)
    s.call("elbv2", "RegisterTargets", {"TargetGroupArn": ref("tg"),
                                        "Targets": [{"Id": n[0], "Port": 8080} for n in NODES]},
           at=NOW - 17 * DAY)

    # --- identity ---------------------------------------------------------------------
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
        "Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/oidc.eks.{REGION}.amazonaws.com/id/5E1F9A"},
        "Action": "sts:AssumeRoleWithWebIdentity"}]})
    s.call("iam", "CreateRole", {"RoleName": "larch-ledger-api", "AssumeRolePolicyDocument": trust},
           at=born + 3000, ids={"AROA": ["AROAV7LARCHLEDGER0001"]})
    s.call("iam", "CreatePolicy", {"PolicyName": "larch-ledger-api-s3", "PolicyDocument": json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
                                                "Resource": "arn:aws:s3:::larch-statements-prod/*"}]})},
           at=born + 3100, ids={"ANPA": ["ANPAV7LARCHLEDGERS301"]}, capture={"pol": "Arn"})
    s.call("iam", "AttachRolePolicy", {"RoleName": "larch-ledger-api", "PolicyArn": ref("pol")}, at=born + 3200)
    ro_trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
        "AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole"}]})
    s.call("iam", "CreateRole", {"RoleName": "OnCallReadOnly", "AssumeRolePolicyDocument": ro_trust,
                                 "MaxSessionDuration": 43200}, at=born + 3300)
    s.call("iam", "AttachRolePolicy", {"RoleName": "OnCallReadOnly",
                                       "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
           at=born + 3300, expect_error="NoSuchEntity")

    # --- data stores ------------------------------------------------------------------
    s.call("rds", "CreateDBSubnetGroup", {"DBSubnetGroupName": "larch-data", "DBSubnetGroupDescription": "data",
                                          "SubnetIds": list(SUBNETS.values())}, at=born + 4000)
    s.call("rds", "CreateDBInstance", {
        "DBInstanceIdentifier": "larch-ledger", "DBInstanceClass": "db.r6g.xlarge", "Engine": "postgres",
        "EngineVersion": "16.4", "MasterUsername": "ledger_admin", "MasterUserPassword": "not-a-real-pw-1",
        "AllocatedStorage": 200, "MultiAZ": True, "DBSubnetGroupName": "larch-data",
        "VpcSecurityGroupIds": [SG_DB]},
        at=born + 4100, ids={"dbi": ["db-K7Q2M4X9W1Z5P3R8T6V0B2N4C8"], "rdshost": ["c8xq2kz1lmno"]})
    s.call("elasticache", "CreateReplicationGroup", {
        "ReplicationGroupId": "larch-sessions", "ReplicationGroupDescription": "sessions",
        "Engine": "redis", "CacheNodeType": "cache.r6g.large", "NumCacheClusters": 2,
        "AutomaticFailoverEnabled": True}, at=born + 4200)
    s.call("sqs", "CreateQueue", {"QueueName": "larch-statements"}, at=born + 4300)
    s.call("sns", "CreateTopic", {"Name": "larch-oncall"}, at=born + 4300, capture={"topic": "TopicArn"})
    s.call("s3", "CreateBucket", {"Bucket": "larch-statements-prod"}, at=born + 4400)
    s.call("s3", "CreateBucket", {"Bucket": "larch-cloudtrail"}, at=born + 4400)
    s.call("s3", "PutBucketPolicy", {"Bucket": "larch-cloudtrail", "Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:GetBucketAcl",
             "Resource": "arn:aws:s3:::larch-cloudtrail"},
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:PutObject",
             "Resource": f"arn:aws:s3:::larch-cloudtrail/AWSLogs/{ACCOUNT}/*",
             "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}}]})},
        at=born + 4500)
    s.call("dynamodb", "CreateTable", {"TableName": "larch-idempotency", "BillingMode": "PAY_PER_REQUEST",
                                       "AttributeDefinitions": [{"AttributeName": "k", "AttributeType": "S"}],
                                       "KeySchema": [{"AttributeName": "k", "KeyType": "HASH"}]}, at=born + 4600)
    s.call("route53", "CreateHostedZone", {"Name": "larch.internal", "CallerReference": "larch-internal-1",
                                           "VPC": {"VPCRegion": REGION, "VPCId": ref("vpc")},
                                           "HostedZoneConfig": {"PrivateZone": True}},
           at=born + 4700, ids={"Z": [ZONE], "C": ["C0912345ABCDEFGHIJK"]},
           capture={"zone": {"field": "Id", "strip_prefix": "/hostedzone/"}})
    s.call("route53", "ChangeResourceRecordSets", {"HostedZoneId": ref("zone"), "ChangeBatch": {"Changes": [
        {"Action": "CREATE", "ResourceRecordSet": {"Name": "ledger-db.larch.internal", "Type": "CNAME",
                                                   "TTL": 300, "ResourceRecords": [
                                                       {"Value": f"larch-ledger.c8xq2kz1lmno.{REGION}.rds.amazonaws.com"}]}}]}},
        at=born + 4800, ids={"C": ["C0923456BCDEFGHIJKL"]})

    # --- compute --------------------------------------------------------------------------
    s.call("ec2", "CreateLaunchTemplate", {"LaunchTemplateName": "eks-general", "LaunchTemplateData": {
        "ImageId": "ami-0c1d2e3f4a5b6c7d8", "InstanceType": "m6i.2xlarge", "SecurityGroupIds": [SG_NODE]}},
        at=born + 5000, ids={"lt": ["lt-0a9b8c7d6e5f40312"]})
    s.call("autoscaling", "CreateAutoScalingGroup", {
        "AutoScalingGroupName": "eks-general-7ac4b1f0", "MinSize": 0, "MaxSize": 6, "DesiredCapacity": 0,
        "LaunchTemplate": {"LaunchTemplateName": "eks-general", "Version": "$Latest"},
        "VPCZoneIdentifier": ",".join(SUBNETS.values())}, at=born + 5100)
    s.call("iam", "CreateRole", {"RoleName": "larch-eks-cluster", "AssumeRolePolicyDocument": json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"},
                                                "Action": "sts:AssumeRole"}]})}, at=born + 5150)
    s.call("eks", "CreateCluster", {"name": "larch-prod", "roleArn": f"arn:aws:iam::{ACCOUNT}:role/larch-eks-cluster",
                                    "resourcesVpcConfig": {"subnetIds": list(SUBNETS.values()),
                                                           "securityGroupIds": [SG_NODE]}},
           at=born + 5200)

    # --- monitoring -------------------------------------------------------------------------
    s.call("cloudwatch", "PutMetricAlarm", {
        "AlarmName": "larch-edge-elb-5xx", "Namespace": "AWS/ApplicationELB", "MetricName": "HTTPCode_ELB_5XX_Count",
        "Dimensions": [{"Name": "LoadBalancer", "Value": f"app/larch-prod-edge/{LB_ID}"}], "Statistic": "Sum",
        "Period": 60, "EvaluationPeriods": 3, "Threshold": 50, "ComparisonOperator": "GreaterThanThreshold",
        "AlarmActions": [ref("topic")], "TreatMissingData": "notBreaching"}, at=born + 6000)
    s.call("cloudwatch", "PutMetricAlarm", {
        "AlarmName": "larch-ledger-db-cpu", "Namespace": "AWS/RDS", "MetricName": "CPUUtilization",
        "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": "larch-ledger"}], "Statistic": "Average",
        "Period": 300, "EvaluationPeriods": 3, "Threshold": 80, "ComparisonOperator": "GreaterThanThreshold"},
        at=born + 6000)
    s.call("logs", "CreateLogGroup", {"logGroupName": "/aws/rds/instance/larch-ledger/postgresql"}, at=born + 6100)
    s.call("cloudtrail", "CreateTrail", {"Name": "larch-org-trail", "S3BucketName": "larch-cloudtrail",
                                         "IsMultiRegionTrail": True}, at=born + 6200)
    s.call("cloudtrail", "StartLogging", {"Name": "larch-org-trail"}, at=born + 6200)

    # --- history ----------------------------------------------------------------------
    start = NOW - 6 * 3600
    minutes = [start + 60 * m for m in range(360)]
    lb_dim = [{"Name": "LoadBalancer", "Value": f"app/larch-prod-edge/{LB_ID}"}]
    rng = random.Random(7)
    s.data["metrics"] += [
        {"namespace": "AWS/ApplicationELB", "name": "RequestCount", "unit": "Count", "dimensions": lb_dim,
         "values": [[t, round(900 + 300 * math.sin(t / 5400) + rng.uniform(-40, 40))] for t in minutes]},
        {"namespace": "AWS/ApplicationELB", "name": "HTTPCode_ELB_5XX_Count", "unit": "Count", "dimensions": lb_dim,
         "values": [[t, (220 + rng.randint(0, 40)) if t >= ONSET else rng.randint(0, 2)] for t in minutes]},
        {"namespace": "AWS/ApplicationELB", "name": "TargetResponseTime", "unit": "Seconds", "dimensions": lb_dim,
         "distribution": [[t, [0.012, 0.045, 0.31, 2.4 if t >= ONSET else 0.9], [700, 180, 18, 2]] for t in minutes]},
        {"namespace": "AWS/ApplicationELB", "name": "UnHealthyHostCount", "unit": "Count",
         "dimensions": lb_dim + [{"Name": "TargetGroup", "Value": f"targetgroup/larch-api-tg/{TG_ID}"}],
         "stats": [[t, 3, 3.0 if t >= ONSET else 0.0, 1.0 if t >= ONSET else 0.0, 1.0 if t >= ONSET else 0.0]
                   for t in minutes]},
        {"namespace": "AWS/RDS", "name": "CPUUtilization", "unit": "Percent",
         "dimensions": [{"Name": "DBInstanceIdentifier", "Value": "larch-ledger"}],
         "values": [[t, round(rng.uniform(20, 35), 2)] for t in minutes]},
        {"namespace": "AWS/RDS", "name": "DatabaseConnections", "unit": "Count",
         "dimensions": [{"Name": "DBInstanceIdentifier", "Value": "larch-ledger"}],
         "values": [[t, 0.0 if NOW - 30 * 60 <= t < NOW - 28 * 60 else 140.0] for t in minutes]},
        {"namespace": "AWS/EC2", "name": "CPUUtilization", "unit": "Percent",
         "dimensions": [{"Name": "InstanceId", "Value": NODES[0][0]}],
         "values": [[t, round(rng.uniform(30, 45), 2)] for t in minutes]},
    ]
    s.data["alarms"] = [
        {"name": "larch-edge-elb-5xx", "state": "ALARM",
         "reason": "Threshold Crossed: 3 out of the last 3 datapoints [231.0 (19/03/26 14:22:00), 244.0 (19/03/26 14:21:00), 219.0 (19/03/26 14:20:00)] were greater than the threshold (50.0) (minimum 3 datapoints for OK -> ALARM transition).",
         "reason_data": json.dumps({"version": "1.0", "queryDate": "2026-03-19T14:23:12.418+0000",
                                    "statistic": "Sum", "period": 60, "threshold": 50.0}),
         "updated": ONSET + 192, "history": [
             {"ts": NOW - 2 * DAY, "type": "ConfigurationUpdate", "summary": "Alarm \"larch-edge-elb-5xx\" updated",
              "data": json.dumps({"version": "1.0", "type": "Update"})},
             {"ts": ONSET + 192, "type": "StateUpdate", "summary": "Alarm updated from OK to ALARM",
              "data": json.dumps({"version": "1.0", "oldState": {"stateValue": "OK"},
                                  "newState": {"stateValue": "ALARM"}})},
             {"ts": ONSET + 193, "type": "Action",
              "summary": "Successfully executed action " + f"arn:aws:sns:{REGION}:{ACCOUNT}:larch-oncall",
              "data": json.dumps({"actionState": "Succeeded"})}]},
        {"name": "larch-ledger-db-cpu", "state": "OK",
         "reason": "Threshold Crossed: 3 datapoints [27.1, 26.3, 29.0] were not greater than the threshold (80.0).",
         "updated": NOW - 3 * DAY, "history": []},
    ]
    s.data["target_health"] = [{"target_group_arn": ref("tg"), "targets": [
        {"id": NODES[0][0], "port": 8080, "state": "healthy"},
        {"id": NODES[1][0], "port": 8080, "state": "unhealthy", "reason": "Target.ResponseCodeMismatch",
         "description": "Health checks failed with these codes: [404]"},
        {"id": NODES[2][0], "port": 8080, "state": "unhealthy", "reason": "Target.Timeout",
         "description": "Request timed out"}]}]
    sg_arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{SG_DB}"
    s.data["cloudtrail"] = [
        trail("RevokeSecurityGroupIngress", "ec2.amazonaws.com", ONSET - 95, {
            "groupId": SG_DB, "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 5432, "toPort": 5432,
                                                           "groups": {"items": [{"groupId": SG_NODE}]}}]}},
              {"requestId": "4f1a7c2e-0b6d-4e8f-9a3c-5d2e1f0a9b8c", "_return": True},
              resources=[{"accountId": ACCOUNT, "type": "AWS::EC2::SecurityGroup", "ARN": sg_arn}],
              lookup=[{"type": "AWS::EC2::SecurityGroup", "name": SG_DB}]),
        trail("ModifyTargetGroup", "elasticloadbalancing.amazonaws.com", ONSET - 600,
              {"targetGroupArn": TG_ARN, "healthCheckPath": "/healthz"}, None,
              lookup=[{"type": "AWS::ElasticLoadBalancingV2::TargetGroup", "name": TG_ARN}]),
        trail("PutRolePolicy", "iam.amazonaws.com", ONSET - 3 * 3600,
              {"roleName": "larch-ledger-api", "policyName": "kms-decrypt",
               "policyDocument": json.dumps({"Version": "2012-10-17", "Statement": []})}, None,
              lookup=[{"type": "AWS::IAM::Role", "name": "larch-ledger-api"}]),
        trail("ChangeResourceRecordSets", "route53.amazonaws.com", ONSET - 7200,
              {"hostedZoneId": ZONE, "changeBatch": {"changes": [{"action": "UPSERT", "resourceRecordSet": {
                  "name": "ledger-db.larch.internal", "type": "CNAME", "tTL": 300}}]}},
              {"changeInfo": {"id": "/change/C0934567CDEFGHIJKLM", "status": "PENDING"}},
              lookup=[{"type": "AWS::Route53::HostedZone", "name": ZONE}]),
        trail("DescribeInstances", "ec2.amazonaws.com", ONSET - 30, {"instancesSet": {}}, None, read_only=True,
              who={"type": "AssumedRole", "principalId": "AROAV7KARPENTER000001:1773929000",
                   "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/larch-prod-cluster-autoscaler/1773929000",
                   "accountId": ACCOUNT, "accessKeyId": "ASIAV7CLUSTERAUTOSCL"},
              agent="aws-sdk-go-v2/1.36.3 os/linux lang/go#1.24.4 api/ec2#1.224.0"),
    ]
    s.data["logs"] = [{"group": "/aws/rds/instance/larch-ledger/postgresql", "stream": "postgresql.log.2026-03-19-14",
                       "events": [[int((ONSET + 60 * k) * 1000),
                                   f"{iso(ONSET + 60 * k).replace('T', ' ').rstrip('Z')} UTC:10.40.33.41(51234):ledger_app@ledger:[{4100 + k}]:LOG:  could not receive data from client: Connection reset by peer"]
                                  for k in range(30)]}]
    s.data["rds_events"] = [
        {"source_identifier": "larch-ledger", "source_type": "db-instance",
         "source_arn": f"arn:aws:rds:{REGION}:{ACCOUNT}:db:larch-ledger", "date": NOW - 30 * 60,
         "message": "Multi-AZ instance failover started.", "event_categories": ["failover"]},
        {"source_identifier": "larch-ledger", "source_type": "db-instance",
         "source_arn": f"arn:aws:rds:{REGION}:{ACCOUNT}:db:larch-ledger", "date": NOW - 28 * 60,
         "message": "Multi-AZ instance failover completed.", "event_categories": ["failover"]},
    ]
    s.data["elasticache_events"] = [
        {"source_identifier": "larch-sessions-002", "source_type": "cache-cluster", "date": NOW - 25 * 60,
         "message": "Failover from master node larch-sessions-001 to replica node larch-sessions-002 completed"}]
    s.data["autoscaling_activities"] = [
        {"group": "eks-general-7ac4b1f0", "activity_id": "6f2b1c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
         "description": "Launching a new EC2 instance.  Status Reason: We currently do not have sufficient m6i.2xlarge capacity in the Availability Zone you requested (us-east-1b). Launching EC2 instance failed.",
         "cause": "At 2026-03-19T14:31:05Z an instance was started in response to a difference between desired and actual capacity, increasing the capacity from 3 to 4.",
         "start": NOW - 29 * 60, "end": NOW - 28 * 60, "status_code": "Failed", "progress": 100,
         "details": json.dumps({"Subnet ID": SUBNETS["b"], "Availability Zone": "us-east-1b"})}]
    s.data["instance_status"] = [
        {"instance_id": NODES[1][0], "system_status": "impaired", "instance_status": "ok",
         "system_details": [{"Name": "reachability", "Status": "failed", "ImpairedSince": ONSET - 60}],
         "instance_details": [{"Name": "reachability", "Status": "passed"}],
         "events": [{"code": "instance-retirement", "description": "The instance is running on degraded hardware",
                     "not_before": NOW + 3 * DAY}]}]
    s.data["instance_states"] = [
        {"instance_id": NODES[2][0], "state": "stopped", "transition_reason": "Server.InternalError",
         "reason_code": "Server.InternalError", "reason": "Server.InternalError: Internal error on launch"}]
    s.read_only = {"principal_arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/OnCallReadOnly/oncall",
                   "role_arn": f"arn:aws:iam::{ACCOUNT}:role/OnCallReadOnly",
                   "credentials_out": credentials_out}

    if big:
        add_bulk(s, minutes, rng)
    return s.to_dict()


def add_bulk(s: SeedBuilder, minutes, rng):
    """History in the proportions of a real world seed."""
    while len(s.setup) < 400:
        n = len(s.setup)
        s.call("ec2", "CreateSecurityGroup", {"GroupName": f"bulk-{n}", "Description": "bulk",
                                              "VpcId": ref("vpc")}, at=NOW - 100 * DAY)
    k = 0
    while sum(len(m.get("values", [])) for m in s.data["metrics"]) < 150_000:
        k += 1
        s.data["metrics"].append({"namespace": "AWS/EC2", "name": "NetworkIn", "unit": "Bytes",
                                  "dimensions": [{"Name": "InstanceId", "Value": f"i-0bulk{k:012x}"}],
                                  "values": [[t, rng.uniform(1e6, 5e6)] for t in minutes]})
    for j in range(15_000):
        ts = NOW - 6 * 3600 + j * (6 * 3600 / 15_000)
        s.data["cloudtrail"].append(trail("DescribeAutoScalingGroups", "autoscaling.amazonaws.com", ts, {},
                                          None, read_only=True,
                                          who={"type": "AssumedRole", "principalId": "AROAV7CA:1",
                                               "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/ca/1",
                                               "accountId": ACCOUNT}))
    s.data["logs"].append({"group": "/aws/eks/larch-prod/cluster", "stream": "kube-apiserver-audit-1",
                           "events": [[int((NOW - 6 * 3600 + j) * 1000), f"audit line {j}"] for j in range(20_000)]})


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("out")
    p.add_argument("--credentials-out", default="/tmp/ocw-regress/credentials")
    p.add_argument("--big", action="store_true")
    a = p.parse_args()
    with open(a.out, "w") as f:
        json.dump(build(a.credentials_out, a.big), f, default=str)
