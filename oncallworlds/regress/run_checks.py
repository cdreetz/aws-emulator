"""Investigator commands against a seeded emulator, with assertions.

    python run_checks.py --endpoint https://127.0.0.1:9411 --ca CA.pem --credentials CREDS \
        [--root-credentials ROOTCREDS] [--aws ~/.local/bin/aws] [--out results.tsv]

Every check runs the plain AWS CLI the way an on-call engineer would, as the read-only
principal the seed provisioned. Exit status is the number of failed checks.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

from make_fixture import (ACCOUNT, LB_ID, NODES, NOW, ONSET, SG_DB, SG_NODE, SUBNETS, TG_ID, VPC,
                          ZONE)

PRINCIPAL = f"arn:aws:sts::{ACCOUNT}:assumed-role/OnCallReadOnly/oncall"


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def epoch(text) -> float:
    if isinstance(text, (int, float)):
        return float(text)
    text = text.replace("Z", "+00:00")
    return datetime.fromisoformat(text).timestamp()


class Runner:
    def __init__(self, aws: str, env: dict):
        self.aws, self.env = aws, env
        self.rows: list[tuple[str, str, str]] = []

    def run(self, args: list[str], env: dict | None = None) -> tuple[int, str, str]:
        p = subprocess.run([self.aws, *args, "--output", "json"], capture_output=True, text=True,
                           env=env or self.env, timeout=120)
        return p.returncode, p.stdout, p.stderr

    def check(self, label: str, args: list[str], predicate=None, *, fails_with: str | None = None,
              env: dict | None = None):
        rc, out, err = self.run(args, env)
        try:
            if fails_with is not None:
                ok = rc != 0 and fails_with in err
                detail = err.strip().replace("\n", " ")[:240]
            else:
                data = json.loads(out) if out.strip() else {}
                ok = rc == 0 and (predicate is None or bool(predicate(data)))
                detail = (out if rc == 0 else err).strip().replace("\n", " ")[:240]
        except Exception as exc:  # noqa: BLE001 - a broken predicate is a failed check
            ok, detail = False, f"{type(exc).__name__}: {exc}; {(out or err)[:200]}"
        self.rows.append(("PASS" if ok else "FAIL", label, detail))
        return ok


def main() -> int:
    a = argparse.ArgumentParser()
    a.add_argument("--endpoint", required=True)
    a.add_argument("--ca", required=True)
    a.add_argument("--credentials", required=True)
    a.add_argument("--root-credentials")
    a.add_argument("--aws", default=os.path.expanduser("~/.local/bin/aws"))
    a.add_argument("--out", default="results.tsv")
    opts = a.parse_args()

    config = tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False)
    config.write("[default]\nregion = us-east-1\n")
    config.close()
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env.update({"AWS_ENDPOINT_URL": opts.endpoint, "AWS_CA_BUNDLE": opts.ca,
                "AWS_SHARED_CREDENTIALS_FILE": opts.credentials, "AWS_CONFIG_FILE": config.name,
                "AWS_DEFAULT_REGION": "us-east-1", "AWS_PAGER": "", "AWS_EC2_METADATA_DISABLED": "true"})
    r = Runner(opts.aws, env)
    c = r.check
    win_start, win_end = iso(NOW - 6 * 3600), iso(NOW)
    lb_dim = f"Name=LoadBalancer,Value=app/larch-prod-edge/{LB_ID}"
    tg_arn = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:targetgroup/larch-api-tg/{TG_ID}"

    # identity
    c("sts get-caller-identity is the read-only principal", ["sts", "get-caller-identity"],
      lambda d: d["Arn"] == PRINCIPAL and d["Account"] == ACCOUNT)

    # EC2 / VPC
    c("ec2 describe-vpcs: pinned id", ["ec2", "describe-vpcs", "--vpc-ids", VPC],
      lambda d: d["Vpcs"][0]["CidrBlock"] == "10.40.0.0/16")
    c("ec2 describe-subnets: 3 pinned, one per AZ", ["ec2", "describe-subnets", "--filters", f"Name=vpc-id,Values={VPC}"],
      lambda d: {s["SubnetId"] for s in d["Subnets"]} >= set(SUBNETS.values())
      and {s["AvailabilityZone"] for s in d["Subnets"] if s["SubnetId"] in SUBNETS.values()} == {"us-east-1a", "us-east-1b", "us-east-1c"})
    c("ec2 describe-security-groups: db group admits node group on 5432",
      ["ec2", "describe-security-groups", "--group-ids", SG_DB],
      lambda d: any(p.get("FromPort") == 5432 and any(g["GroupId"] == SG_NODE for g in p["UserIdGroupPairs"])
                    for p in d["SecurityGroups"][0]["IpPermissions"]))
    c("ec2 describe-security-group-rules: pinned rule id",
      ["ec2", "describe-security-group-rules", "--filters", f"Name=group-id,Values={SG_DB}"],
      lambda d: any(x["SecurityGroupRuleId"] == "sgr-0123456789abcdef0" for x in d["SecurityGroupRules"]))
    c("ec2 describe-network-acls: default NACL pinned", ["ec2", "describe-network-acls", "--filters", f"Name=vpc-id,Values={VPC}"],
      lambda d: any(n["NetworkAclId"] == "acl-0d1d2d3d4d5d6d7d8" for n in d["NetworkAcls"]))
    c("ec2 describe-route-tables: main table pinned", ["ec2", "describe-route-tables", "--filters", f"Name=vpc-id,Values={VPC}"],
      lambda d: any(t["RouteTableId"] == "rtb-0e1e2e3e4e5e6e7e8" for t in d["RouteTables"]))
    c("ec2 describe-instances: pinned ids, 10.40 IPs, launch times in the window's past",
      ["ec2", "describe-instances", "--instance-ids", *[n[0] for n in NODES]],
      lambda d: sorted((i["InstanceId"], i["PrivateIpAddress"]) for res in d["Reservations"] for i in res["Instances"])
      == sorted((n[0], n[2]) for n in NODES)
      and all(NOW - 25 * 86400 < epoch(i["LaunchTime"]) < NOW for res in d["Reservations"] for i in res["Instances"]))
    c("ec2 describe-instances: seeded stopped state with reason", ["ec2", "describe-instances", "--instance-ids", NODES[2][0]],
      lambda d: d["Reservations"][0]["Instances"][0]["State"]["Name"] == "stopped"
      and d["Reservations"][0]["Instances"][0]["StateReason"]["Code"] == "Server.InternalError")
    c("ec2 describe-instance-status: running only, impaired system check", ["ec2", "describe-instance-status"],
      lambda d: {s["InstanceId"]: s["SystemStatus"]["Status"] for s in d["InstanceStatuses"]}
      == {NODES[0][0]: "ok", NODES[1][0]: "impaired"})
    c("ec2 describe-instance-status --include-all-instances", ["ec2", "describe-instance-status", "--include-all-instances"],
      lambda d: len(d["InstanceStatuses"]) == 3 and any(s["InstanceState"]["Name"] == "stopped"
                                                         and s["SystemStatus"]["Status"] == "not-applicable"
                                                         for s in d["InstanceStatuses"]))
    c("ec2 describe-instance-status --filters system-status.status=impaired",
      ["ec2", "describe-instance-status", "--filters", "Name=system-status.status,Values=impaired"],
      lambda d: [s["InstanceId"] for s in d["InstanceStatuses"]] == [NODES[1][0]]
      and d["InstanceStatuses"][0]["Events"][0]["Code"] == "instance-retirement")
    c("ec2 describe-availability-zones", ["ec2", "describe-availability-zones"],
      lambda d: len(d["AvailabilityZones"]) >= 3)
    c("ec2 describe-launch-templates: pinned id", ["ec2", "describe-launch-templates"],
      lambda d: d["LaunchTemplates"][0]["LaunchTemplateId"] == "lt-0a9b8c7d6e5f40312")
    c("ec2 describe-launch-template-versions", ["ec2", "describe-launch-template-versions", "--launch-template-id", "lt-0a9b8c7d6e5f40312"],
      lambda d: d["LaunchTemplateVersions"][0]["LaunchTemplateData"]["InstanceType"] == "m6i.2xlarge")
    c("ec2 describe-vpc-endpoints", ["ec2", "describe-vpc-endpoints"], lambda d: "VpcEndpoints" in d)
    c("ec2 describe-nat-gateways", ["ec2", "describe-nat-gateways"], lambda d: "NatGateways" in d)
    c("ec2 describe-internet-gateways", ["ec2", "describe-internet-gateways"], lambda d: "InternetGateways" in d)
    c("ec2 describe-network-interfaces", ["ec2", "describe-network-interfaces"], lambda d: "NetworkInterfaces" in d)
    c("ec2 describe-flow-logs", ["ec2", "describe-flow-logs"], lambda d: "FlowLogs" in d)
    c("ec2 describe-volumes", ["ec2", "describe-volumes"], lambda d: "Volumes" in d)

    # ELBv2
    c("elbv2 describe-load-balancers: pinned ARN, created long ago", ["elbv2", "describe-load-balancers"],
      lambda d: d["LoadBalancers"][0]["LoadBalancerArn"].endswith(f"/larch-prod-edge/{LB_ID}")
      and epoch(d["LoadBalancers"][0]["CreatedTime"]) < NOW - 300 * 86400)
    c("elbv2 describe-target-groups: pinned ARN", ["elbv2", "describe-target-groups"],
      lambda d: d["TargetGroups"][0]["TargetGroupArn"] == tg_arn and d["TargetGroups"][0]["HealthCheckPath"] == "/healthz")
    c("elbv2 describe-target-health: seeded states and reasons", ["elbv2", "describe-target-health", "--target-group-arn", tg_arn],
      lambda d: {t["Target"]["Id"]: (t["TargetHealth"]["State"], t["TargetHealth"].get("Reason"))
                 for t in d["TargetHealthDescriptions"]}
      == {NODES[0][0]: ("healthy", None), NODES[1][0]: ("unhealthy", "Target.ResponseCodeMismatch"),
          NODES[2][0]: ("unhealthy", "Target.Timeout")})
    c("elbv2 describe-target-health: description", ["elbv2", "describe-target-health", "--target-group-arn", tg_arn,
                                                    "--targets", f"Id={NODES[1][0]},Port=8080"],
      lambda d: d["TargetHealthDescriptions"][0]["TargetHealth"]["Description"] == "Health checks failed with these codes: [404]")
    c("elbv2 describe-listeners", ["elbv2", "describe-listeners", "--load-balancer-arn",
                                   f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/larch-prod-edge/{LB_ID}"],
      lambda d: d["Listeners"][0]["Port"] == 80)
    c("elbv2 describe-target-group-attributes", ["elbv2", "describe-target-group-attributes", "--target-group-arn", tg_arn],
      lambda d: any(x["Key"] == "deregistration_delay.timeout_seconds" for x in d["Attributes"]))
    c("elbv2 describe-load-balancer-attributes", ["elbv2", "describe-load-balancer-attributes", "--load-balancer-arn",
                                                  f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/larch-prod-edge/{LB_ID}"],
      lambda d: len(d["Attributes"]) > 0)

    # IAM
    c("iam get-role: pinned RoleId, created in the past", ["iam", "get-role", "--role-name", "larch-ledger-api"],
      lambda d: d["Role"]["RoleId"] == "AROAV7LARCHLEDGER0001" and epoch(d["Role"]["CreateDate"]) < NOW - 300 * 86400)
    c("iam list-attached-role-policies", ["iam", "list-attached-role-policies", "--role-name", "larch-ledger-api"],
      lambda d: d["AttachedPolicies"][0]["PolicyName"] == "larch-ledger-api-s3")
    c("iam get-policy: pinned PolicyId", ["iam", "get-policy", "--policy-arn", f"arn:aws:iam::{ACCOUNT}:policy/larch-ledger-api-s3"],
      lambda d: d["Policy"]["PolicyId"] == "ANPAV7LARCHLEDGERS301")
    c("iam get-policy-version", ["iam", "get-policy-version", "--policy-arn", f"arn:aws:iam::{ACCOUNT}:policy/larch-ledger-api-s3",
                                 "--version-id", "v1"], lambda d: "s3:PutObject" in json.dumps(d))
    c("iam list-roles", ["iam", "list-roles"], lambda d: any(x["RoleName"] == "OnCallReadOnly" for x in d["Roles"]))
    c("iam list-role-policies", ["iam", "list-role-policies", "--role-name", "larch-ledger-api"], lambda d: "PolicyNames" in d)
    c("iam simulate-principal-policy runs", ["iam", "simulate-principal-policy", "--policy-source-arn",
                                             f"arn:aws:iam::{ACCOUNT}:role/larch-ledger-api", "--action-names", "s3:PutObject",
                                             "--resource-arns", "arn:aws:s3:::larch-statements-prod/x"],
      lambda d: d["EvaluationResults"][0]["EvalDecision"] in ("allowed", "implicitDeny", "explicitDeny"))

    # RDS
    c("rds describe-db-instances: pinned DbiResourceId and endpoint", ["rds", "describe-db-instances"],
      lambda d: d["DBInstances"][0]["DbiResourceId"] == "db-K7Q2M4X9W1Z5P3R8T6V0B2N4C8"
      and d["DBInstances"][0]["Endpoint"]["Address"] == "larch-ledger.c8xq2kz1lmno.us-east-1.rds.amazonaws.com"
      and d["DBInstances"][0]["MultiAZ"] is True)
    c("rds describe-events: seeded failover, default window from the shifted now",
      ["rds", "describe-events", "--source-type", "db-instance", "--source-identifier", "larch-ledger", "--duration", "60"],
      lambda d: [e["Message"] for e in d["Events"] if "failover" in e["Message"]]
      == ["Multi-AZ instance failover started.", "Multi-AZ instance failover completed."])
    c("rds describe-db-subnet-groups", ["rds", "describe-db-subnet-groups"],
      lambda d: "larch-data" in [g["DBSubnetGroupName"] for g in d["DBSubnetGroups"]])
    c("rds describe-db-parameter-groups", ["rds", "describe-db-parameter-groups"], lambda d: "DBParameterGroups" in d)

    # ElastiCache
    c("elasticache describe-replication-groups", ["elasticache", "describe-replication-groups"],
      lambda d: d["ReplicationGroups"][0]["ReplicationGroupId"] == "larch-sessions")
    c("elasticache describe-cache-clusters", ["elasticache", "describe-cache-clusters"], lambda d: len(d["CacheClusters"]) >= 1)
    c("elasticache describe-events: seeded failover", ["elasticache", "describe-events", "--duration", "60"],
      lambda d: any("Failover from master node" in e["Message"] for e in d["Events"]))

    # SQS / SNS / S3 / DynamoDB
    c("sqs list-queues", ["sqs", "list-queues"], lambda d: any(u.endswith("/larch-statements") for u in d["QueueUrls"]))
    c("sqs get-queue-attributes", ["sqs", "get-queue-attributes", "--queue-url",
                                   f"{opts.endpoint}/{ACCOUNT}/larch-statements", "--attribute-names", "All"],
      lambda d: "ApproximateNumberOfMessages" in d["Attributes"])
    c("sns list-topics", ["sns", "list-topics"], lambda d: d["Topics"][0]["TopicArn"].endswith(":larch-oncall"))
    c("sns get-topic-attributes", ["sns", "get-topic-attributes", "--topic-arn", f"arn:aws:sns:us-east-1:{ACCOUNT}:larch-oncall"],
      lambda d: "Attributes" in d)
    c("s3api list-buckets", ["s3api", "list-buckets"],
      lambda d: {b["Name"] for b in d["Buckets"]} >= {"larch-statements-prod", "larch-cloudtrail"})
    c("s3api get-bucket-policy", ["s3api", "get-bucket-policy", "--bucket", "larch-cloudtrail"],
      lambda d: "cloudtrail.amazonaws.com" in d["Policy"])
    c("s3api list-objects-v2", ["s3api", "list-objects-v2", "--bucket", "larch-statements-prod"], lambda d: True)
    c("s3api get-bucket-location", ["s3api", "get-bucket-location", "--bucket", "larch-statements-prod"], lambda d: True)
    c("dynamodb describe-table", ["dynamodb", "describe-table", "--table-name", "larch-idempotency"],
      lambda d: d["Table"]["TableStatus"] == "ACTIVE")
    c("dynamodb list-tables", ["dynamodb", "list-tables"], lambda d: "larch-idempotency" in d["TableNames"])
    c("dynamodb scan", ["dynamodb", "scan", "--table-name", "larch-idempotency"], lambda d: d["Count"] == 0)

    # Route 53
    c("route53 list-hosted-zones: pinned zone id", ["route53", "list-hosted-zones"],
      lambda d: d["HostedZones"][0]["Id"] == f"/hostedzone/{ZONE}")
    c("route53 list-resource-record-sets: CNAME and TTL", ["route53", "list-resource-record-sets", "--hosted-zone-id", ZONE],
      lambda d: any(r["Name"] == "ledger-db.larch.internal." and r["TTL"] == 300 for r in d["ResourceRecordSets"]))
    c("route53 get-hosted-zone", ["route53", "get-hosted-zone", "--id", ZONE], lambda d: d["HostedZone"]["Config"]["PrivateZone"])
    c("route53 get-change: pinned change id", ["route53", "get-change", "--id", "C0923456BCDEFGHIJKL"],
      lambda d: d["ChangeInfo"]["Id"].endswith("C0923456BCDEFGHIJKL"))

    # Auto Scaling / EKS
    c("autoscaling describe-auto-scaling-groups", ["autoscaling", "describe-auto-scaling-groups"],
      lambda d: d["AutoScalingGroups"][0]["AutoScalingGroupName"] == "eks-general-7ac4b1f0")
    c("autoscaling describe-scaling-activities: seeded failed launch",
      ["autoscaling", "describe-scaling-activities", "--auto-scaling-group-name", "eks-general-7ac4b1f0"],
      lambda d: any(x["StatusCode"] == "Failed" and "sufficient m6i.2xlarge capacity" in x.get("StatusMessage", x["Description"])
                    for x in d["Activities"]))
    c("eks list-clusters", ["eks", "list-clusters"], lambda d: d["clusters"] == ["larch-prod"])
    c("eks describe-cluster", ["eks", "describe-cluster", "--name", "larch-prod"], lambda d: d["cluster"]["name"] == "larch-prod")
    c("eks list-nodegroups", ["eks", "list-nodegroups", "--cluster-name", "larch-prod"], lambda d: "nodegroups" in d)

    # CloudWatch
    c("cloudwatch list-metrics: AWS/ApplicationELB metrics exist", ["cloudwatch", "list-metrics", "--namespace", "AWS/ApplicationELB"],
      lambda d: {m["MetricName"] for m in d["Metrics"]} >= {"RequestCount", "HTTPCode_ELB_5XX_Count", "TargetResponseTime"})
    c("cloudwatch get-metric-statistics: ELB 5xx after onset",
      ["cloudwatch", "get-metric-statistics", "--namespace", "AWS/ApplicationELB", "--metric-name", "HTTPCode_ELB_5XX_Count",
       "--dimensions", lb_dim, "--start-time", iso(NOW - 3600), "--end-time", win_end, "--period", "300", "--statistics", "Sum"],
      lambda d: max(p["Sum"] for p in d["Datapoints"]) > 1000 and min(p["Sum"] for p in d["Datapoints"]) < 50)
    c("cloudwatch get-metric-statistics: p99 from a distribution",
      ["cloudwatch", "get-metric-statistics", "--namespace", "AWS/ApplicationELB", "--metric-name", "TargetResponseTime",
       "--dimensions", lb_dim, "--start-time", iso(NOW - 600), "--end-time", win_end, "--period", "300",
       "--extended-statistics", "p99"],
      lambda d: all(abs(p["ExtendedStatistics"]["p99"] - 0.31) < 0.01 or p["ExtendedStatistics"]["p99"] > 0.3
                    for p in d["Datapoints"]) and len(d["Datapoints"]) >= 1)
    q = json.dumps([{"Id": "rc", "MetricStat": {"Metric": {"Namespace": "AWS/ApplicationELB", "MetricName": "RequestCount",
                                                              "Dimensions": [{"Name": "LoadBalancer", "Value": f"app/larch-prod-edge/{LB_ID}"}]},
                                                   "Period": 3600, "Stat": "Sum"}}])
    c("cloudwatch get-metric-data over the 6h window", ["cloudwatch", "get-metric-data", "--metric-data-queries", q,
                                                         "--start-time", win_start, "--end-time", win_end],
      lambda d: len(d["MetricDataResults"][0]["Values"]) == 6)
    c("cloudwatch get-metric-statistics: RDS connections dip to 0",
      ["cloudwatch", "get-metric-statistics", "--namespace", "AWS/RDS", "--metric-name", "DatabaseConnections",
       "--dimensions", "Name=DBInstanceIdentifier,Value=larch-ledger", "--start-time", win_start, "--end-time", win_end,
       "--period", "60", "--statistics", "Minimum"],
      lambda d: min(p["Minimum"] for p in d["Datapoints"]) == 0 and len(d["Datapoints"]) == 360)
    c("cloudwatch describe-alarms: seeded ALARM with its timestamp", ["cloudwatch", "describe-alarms", "--alarm-names", "larch-edge-elb-5xx"],
      lambda d: d["MetricAlarms"][0]["StateValue"] == "ALARM"
      and abs(epoch(d["MetricAlarms"][0]["StateUpdatedTimestamp"]) - (ONSET + 192)) < 1)
    c("cloudwatch describe-alarms --state-value ALARM", ["cloudwatch", "describe-alarms", "--state-value", "ALARM"],
      lambda d: [a["AlarmName"] for a in d["MetricAlarms"]] == ["larch-edge-elb-5xx"])
    c("cloudwatch describe-alarm-history: seeded transition", ["cloudwatch", "describe-alarm-history", "--alarm-name", "larch-edge-elb-5xx"],
      lambda d: any(h["HistorySummary"] == "Alarm updated from OK to ALARM" for h in d["AlarmHistoryItems"]))
    c("cloudwatch describe-alarm-history --history-item-type StateUpdate",
      ["cloudwatch", "describe-alarm-history", "--alarm-name", "larch-edge-elb-5xx", "--history-item-type", "StateUpdate"],
      lambda d: len(d["AlarmHistoryItems"]) == 1)
    c("cloudwatch describe-alarms-for-metric", ["cloudwatch", "describe-alarms-for-metric", "--namespace", "AWS/RDS",
                                                "--metric-name", "CPUUtilization", "--dimensions", "Name=DBInstanceIdentifier,Value=larch-ledger"],
      lambda d: d["MetricAlarms"][0]["StateValue"] == "OK")

    # Logs
    group = "/aws/rds/instance/larch-ledger/postgresql"
    c("logs describe-log-groups", ["logs", "describe-log-groups", "--log-group-name-prefix", "/aws/rds"],
      lambda d: d["logGroups"][0]["logGroupName"] == group)
    c("logs describe-log-streams", ["logs", "describe-log-streams", "--log-group-name", group],
      lambda d: d["logStreams"][0]["logStreamName"] == "postgresql.log.2026-03-19-14")
    c("logs filter-log-events: history older than PutLogEvents allows", ["logs", "filter-log-events", "--log-group-name", group,
                                                                          "--filter-pattern", "\"Connection reset\""],
      lambda d: len(d["events"]) == 30)
    c("logs get-log-events", ["logs", "get-log-events", "--log-group-name", group, "--log-stream-name",
                              "postgresql.log.2026-03-19-14", "--start-from-head"], lambda d: len(d["events"]) == 30)
    rc, out, _ = r.run(["logs", "start-query", "--log-group-name", group, "--start-time", str(int(NOW - 6 * 3600)),
                        "--end-time", str(int(NOW)), "--query-string", "fields @timestamp, @message | filter @message like /reset/ | stats count() as n"])
    qid = json.loads(out)["queryId"] if rc == 0 else "none"
    r.rows.append(("PASS" if rc == 0 else "FAIL", "logs start-query (Logs Insights)", out.strip()[:120]))
    import time
    for _ in range(20):
        rc, out, _ = r.run(["logs", "get-query-results", "--query-id", qid])
        if rc == 0 and json.loads(out).get("status") == "Complete":
            break
        time.sleep(0.5)
    c("logs get-query-results", ["logs", "get-query-results", "--query-id", qid],
      lambda d: d["status"] == "Complete" and any(f["field"] == "n" and f["value"] == "30" for row in d["results"] for f in row))

    # CloudTrail
    c("cloudtrail describe-trails", ["cloudtrail", "describe-trails"], lambda d: d["trailList"][0]["Name"] == "larch-org-trail")
    c("cloudtrail get-trail-status", ["cloudtrail", "get-trail-status", "--name", "larch-org-trail"], lambda d: d["IsLogging"])
    c("cloudtrail lookup-events: seeded history, newest first, no setup calls",
      ["cloudtrail", "lookup-events", "--max-results", "50"],
      lambda d: [e["EventName"] for e in d["Events"]][:2] == ["DescribeInstances", "RevokeSecurityGroupIngress"]
      and not any(e["EventName"] in ("CreateVpc", "CreateRole", "CreateDBInstance") for e in d["Events"]))
    c("cloudtrail lookup-events EventName: full record", ["cloudtrail", "lookup-events", "--lookup-attributes",
                                                         "AttributeKey=EventName,AttributeValue=RevokeSecurityGroupIngress"],
      lambda d: len(d["Events"]) == 1
      and json.loads(d["Events"][0]["CloudTrailEvent"])["requestParameters"]["groupId"] == SG_DB
      and json.loads(d["Events"][0]["CloudTrailEvent"])["sourceIPAddress"] == "10.40.3.17"
      and json.loads(d["Events"][0]["CloudTrailEvent"])["userIdentity"]["sessionContext"]["sessionIssuer"]["userName"].startswith("AWSReservedSSO_")
      and d["Events"][0]["Username"] == "dana.okafor@larch.example"
      and d["Events"][0]["Resources"][0]["ResourceName"] == SG_DB
      and "_lookup_resources" not in d["Events"][0]["CloudTrailEvent"])
    c("cloudtrail lookup-events ResourceName", ["cloudtrail", "lookup-events", "--lookup-attributes",
                                                f"AttributeKey=ResourceName,AttributeValue={SG_DB}"],
      lambda d: [e["EventName"] for e in d["Events"]] == ["RevokeSecurityGroupIngress"])
    c("cloudtrail lookup-events ReadOnly=false", ["cloudtrail", "lookup-events", "--lookup-attributes",
                                                  "AttributeKey=ReadOnly,AttributeValue=false"],
      lambda d: len(d["Events"]) == 4)
    c("cloudtrail lookup-events EventSource", ["cloudtrail", "lookup-events", "--lookup-attributes",
                                               "AttributeKey=EventSource,AttributeValue=iam.amazonaws.com"],
      lambda d: [e["EventName"] for e in d["Events"]] == ["PutRolePolicy"])
    c("cloudtrail lookup-events Username", ["cloudtrail", "lookup-events", "--lookup-attributes",
                                            "AttributeKey=Username,AttributeValue=dana.okafor@larch.example"],
      lambda d: len(d["Events"]) == 4)
    c("cloudtrail lookup-events time range", ["cloudtrail", "lookup-events", "--start-time", iso(ONSET - 700),
                                              "--end-time", iso(ONSET - 60)],
      lambda d: [e["EventName"] for e in d["Events"]] == ["RevokeSecurityGroupIngress", "ModifyTargetGroup"])
    c("cloudtrail log files delivered to the trail bucket", ["s3api", "list-objects-v2", "--bucket", "larch-cloudtrail",
                                                              "--prefix", f"AWSLogs/{ACCOUNT}/CloudTrail/us-east-1/2026/03/19/"],
      lambda d: len(d["Contents"]) >= 4 and all(o["Key"].endswith(".json.gz") for o in d["Contents"]))
    rc, out, _ = r.run(["s3api", "list-objects-v2", "--bucket", "larch-cloudtrail", "--prefix", f"AWSLogs/{ACCOUNT}/"])
    keys = [o["Key"] for o in json.loads(out).get("Contents", [])] if rc == 0 else []
    found = False
    for key in keys:
        target = os.path.join(tempfile.gettempdir(), "ocw-trail-file.json.gz")
        if r.run(["s3api", "get-object", "--bucket", "larch-cloudtrail", "--key", key, target])[0] == 0:
            import gzip
            with gzip.open(target) as g:
                records = json.load(g)["Records"]
            if any(x["eventName"] == "RevokeSecurityGroupIngress" and x["requestParameters"]["groupId"] == SG_DB
                   for x in records):
                found = True
                break
    r.rows.append(("PASS" if found else "FAIL", "cloudtrail log file holds the same record LookupEvents returns",
                   f"{len(keys)} files"))
    rc, out, _ = r.run(["cloudtrail", "lookup-events", "--max-items", "2"])
    page = json.loads(out) if rc == 0 else {}
    r.rows.append(("PASS" if rc == 0 and len(page.get("Events", [])) == 2 and page.get("NextToken") else "FAIL",
                   "cloudtrail lookup-events pages", out.strip()[:120]))

    # Sweep: further investigator reads must be implemented (an error a real account would
    # give, such as a missing resource, is fine; NotImplemented is not).
    sweep = [
        ["ec2", "describe-vpc-peering-connections"], ["ec2", "describe-transit-gateways"],
        ["ec2", "describe-managed-prefix-lists"], ["ec2", "describe-addresses"],
        ["ec2", "describe-instance-types", "--instance-types", "m6i.2xlarge"], ["ec2", "describe-tags"],
        ["ec2", "describe-security-group-references", "--group-id", SG_DB],
        ["ec2", "describe-instance-attribute", "--instance-id", NODES[0][0], "--attribute", "groupSet"],
        ["ec2", "get-console-output", "--instance-id", NODES[0][0]],
        ["ec2", "describe-vpc-attribute", "--vpc-id", VPC, "--attribute", "enableDnsHostnames"],
        ["ec2", "describe-key-pairs"], ["ec2", "describe-images", "--owners", "self"],
        ["elbv2", "describe-ssl-policies"], ["elbv2", "describe-tags", "--resource-arns", tg_arn],
        ["elbv2", "describe-account-limits"],
        ["iam", "get-role-policy", "--role-name", "larch-ledger-api", "--policy-name", "none"],
        ["iam", "list-instance-profiles"], ["iam", "list-policy-versions", "--policy-arn",
                                            f"arn:aws:iam::{ACCOUNT}:policy/larch-ledger-api-s3"],
        ["iam", "get-account-authorization-details", "--filter", "Role"], ["iam", "list-users"],
        ["iam", "list-open-id-connect-providers"], ["iam", "get-account-summary"],
        ["rds", "describe-db-clusters"], ["rds", "describe-db-log-files", "--db-instance-identifier", "larch-ledger"],
        ["rds", "describe-pending-maintenance-actions"], ["rds", "describe-db-snapshots"],
        ["rds", "describe-event-subscriptions"], ["rds", "describe-orderable-db-instance-options", "--engine", "postgres", "--max-records", "20"],
        ["elasticache", "describe-cache-subnet-groups"], ["elasticache", "describe-cache-parameter-groups"],
        ["elasticache", "describe-snapshots"],
        ["sqs", "list-dead-letter-source-queues", "--queue-url", f"{opts.endpoint}/{ACCOUNT}/larch-statements"],
        ["sns", "list-subscriptions"], ["sns", "list-subscriptions-by-topic", "--topic-arn",
                                        f"arn:aws:sns:us-east-1:{ACCOUNT}:larch-oncall"],
        ["s3api", "get-bucket-versioning", "--bucket", "larch-statements-prod"],
        ["s3api", "get-public-access-block", "--bucket", "larch-statements-prod"],
        ["s3api", "get-bucket-logging", "--bucket", "larch-statements-prod"],
        ["s3api", "get-bucket-notification-configuration", "--bucket", "larch-statements-prod"],
        ["s3api", "get-bucket-encryption", "--bucket", "larch-statements-prod"],
        ["dynamodb", "describe-continuous-backups", "--table-name", "larch-idempotency"],
        ["dynamodb", "describe-time-to-live", "--table-name", "larch-idempotency"],
        ["dynamodb", "describe-limits"],
        ["route53", "list-health-checks"], ["route53", "get-hosted-zone-count"],
        ["route53", "test-dns-answer", "--hosted-zone-id", ZONE, "--record-name", "ledger-db.larch.internal",
         "--record-type", "CNAME"],
        ["autoscaling", "describe-lifecycle-hooks", "--auto-scaling-group-name", "eks-general-7ac4b1f0"],
        ["autoscaling", "describe-scheduled-actions"], ["autoscaling", "describe-policies"],
        ["autoscaling", "describe-auto-scaling-instances"], ["autoscaling", "describe-launch-configurations"],
        ["autoscaling", "describe-warm-pool", "--auto-scaling-group-name", "eks-general-7ac4b1f0"],
        ["eks", "list-addons", "--cluster-name", "larch-prod"], ["eks", "list-fargate-profiles", "--cluster-name", "larch-prod"],
        ["cloudwatch", "list-dashboards"], ["cloudwatch", "describe-anomaly-detectors"],
        ["cloudwatch", "describe-insight-rules"],
        ["logs", "describe-metric-filters"], ["logs", "describe-subscription-filters", "--log-group-name", group],
        ["logs", "describe-queries"], ["logs", "describe-query-definitions"],
        ["cloudtrail", "get-event-selectors", "--trail-name", "larch-org-trail"], ["cloudtrail", "list-trails"],
        ["cloudtrail", "get-insight-selectors", "--trail-name", "larch-org-trail"],
        ["sts", "get-session-token"], ["kms", "list-keys"], ["secretsmanager", "list-secrets"],
        ["ssm", "describe-parameters"], ["acm", "list-certificates"], ["health", "describe-events"],
        ["servicequotas", "list-services"], ["resourcegroupstaggingapi", "get-resources"],
    ]
    for args in sweep:
        rc, out, err = r.run(args)
        implemented = "NotImplemented" not in err and "scaffolded but not implemented" not in err
        r.rows.append(("PASS" if implemented else "FAIL", "implemented: " + " ".join(args[:2]),
                       (err.strip() or out.strip()).replace("\n", " ")[:200]))

    # Read-only: every write is refused in the service's own words
    def refused(label, args, code):
        c(f"refused: {label}", args, fails_with=code)
    refused("ec2 revoke-security-group-ingress", ["ec2", "revoke-security-group-ingress", "--group-id", SG_DB,
                                                  "--protocol", "tcp", "--port", "5432", "--source-group", SG_NODE],
            "(UnauthorizedOperation) when calling the RevokeSecurityGroupIngress operation: You are not authorized to perform this operation. User: "
            f"{PRINCIPAL} is not authorized to perform: ec2:RevokeSecurityGroupIngress on resource: arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/{SG_DB}")
    refused("ec2 terminate-instances", ["ec2", "terminate-instances", "--instance-ids", NODES[0][0]], "UnauthorizedOperation")
    refused("ec2 create-vpc", ["ec2", "create-vpc", "--cidr-block", "10.9.0.0/16"], "UnauthorizedOperation")
    refused("iam put-role-policy", ["iam", "put-role-policy", "--role-name", "larch-ledger-api", "--policy-name", "x",
                                    "--policy-document", "{}"],
            f"(AccessDenied) when calling the PutRolePolicy operation: User: {PRINCIPAL} is not authorized to perform: iam:PutRolePolicy on resource: arn:aws:iam::{ACCOUNT}:role/larch-ledger-api")
    refused("iam create-access-key", ["iam", "create-access-key"], "AccessDenied")
    refused("s3api put-object", ["s3api", "put-object", "--bucket", "larch-statements-prod", "--key", "x"],
            'is not authorized to perform: s3:PutObject on resource: "arn:aws:s3:::larch-statements-prod/x"')
    refused("s3api delete-bucket-policy", ["s3api", "delete-bucket-policy", "--bucket", "larch-cloudtrail"], "AccessDenied")
    refused("dynamodb put-item", ["dynamodb", "put-item", "--table-name", "larch-idempotency", "--item", '{"k":{"S":"x"}}'],
            "(AccessDeniedException) when calling the PutItem operation: User: " + PRINCIPAL)
    refused("elbv2 modify-target-group", ["elbv2", "modify-target-group", "--target-group-arn", tg_arn,
                                          "--health-check-path", "/"], "(AccessDenied) when calling the ModifyTargetGroup")
    refused("elbv2 deregister-targets", ["elbv2", "deregister-targets", "--target-group-arn", tg_arn,
                                         "--targets", f"Id={NODES[0][0]}"], "AccessDenied")
    refused("route53 change-resource-record-sets", ["route53", "change-resource-record-sets", "--hosted-zone-id", ZONE,
                                                    "--change-batch", '{"Changes":[{"Action":"DELETE","ResourceRecordSet":{"Name":"ledger-db.larch.internal","Type":"CNAME","TTL":300,"ResourceRecords":[{"Value":"x"}]}}]}'],
            f"on resource: arn:aws:route53:::hostedzone/{ZONE}")
    refused("rds reboot-db-instance --force-failover", ["rds", "reboot-db-instance", "--db-instance-identifier", "larch-ledger",
                                                        "--force-failover"], f"arn:aws:rds:us-east-1:{ACCOUNT}:db:larch-ledger")
    refused("elasticache test-failover", ["elasticache", "test-failover", "--replication-group-id", "larch-sessions",
                                          "--node-group-id", "0001"], "AccessDenied")
    refused("sqs send-message", ["sqs", "send-message", "--queue-url", f"{opts.endpoint}/{ACCOUNT}/larch-statements",
                                 "--message-body", "x"], "AccessDenied")
    refused("sns publish", ["sns", "publish", "--topic-arn", f"arn:aws:sns:us-east-1:{ACCOUNT}:larch-oncall",
                            "--message", "x"], "AuthorizationError")
    refused("logs put-log-events", ["logs", "put-log-events", "--log-group-name", group, "--log-stream-name", "x",
                                    "--log-events", "timestamp=1,message=x"], "AccessDeniedException")
    refused("cloudwatch set-alarm-state", ["cloudwatch", "set-alarm-state", "--alarm-name", "larch-edge-elb-5xx",
                                           "--state-value", "OK", "--state-reason", "x"], "cloudwatch:SetAlarmState")
    refused("cloudwatch put-metric-data", ["cloudwatch", "put-metric-data", "--namespace", "X", "--metric-name", "m",
                                           "--value", "1"], "cloudwatch:PutMetricData")
    refused("autoscaling set-desired-capacity", ["autoscaling", "set-desired-capacity", "--auto-scaling-group-name",
                                                 "eks-general-7ac4b1f0", "--desired-capacity", "3"], "AccessDenied")
    refused("eks update-nodegroup-config", ["eks", "update-cluster-config", "--name", "larch-prod",
                                            "--logging", '{"clusterLogging":[{"types":["api"],"enabled":true}]}'], "AccessDeniedException")
    refused("cloudtrail stop-logging", ["cloudtrail", "stop-logging", "--name", "larch-org-trail"], "cloudtrail:StopLogging")
    refused("sts assume-role", ["sts", "assume-role", "--role-arn", f"arn:aws:iam::{ACCOUNT}:role/larch-ledger-api",
                                "--role-session-name", "probe"], "sts:AssumeRole")
    if opts.root_credentials:
        root_env = dict(env, AWS_SHARED_CREDENTIALS_FILE=opts.root_credentials)
        c("refused even with the emulator's root keys", ["ec2", "delete-security-group", "--group-id", SG_DB],
          fails_with="UnauthorizedOperation", env=root_env)

    with open(opts.out, "w") as f:
        for row in r.rows:
            f.write("\t".join(row) + "\n")
    passed = sum(1 for row in r.rows if row[0] == "PASS")
    for status, label, detail in r.rows:
        print(f"{status}\t{label}" + ("" if status == "PASS" else f"\t{detail}"))
    print(f"\n{passed}/{len(r.rows)} passed")
    return len(r.rows) - passed


if __name__ == "__main__":
    sys.exit(main())
