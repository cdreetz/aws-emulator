# OnCallWorlds patch

Branch `oncallworlds` of this fork, on top of upstream `32b3cf39b` (AWS Emulator v1.0.338).
It lets OnCallWorlds load one incident's AWS account into the emulator at startup and hand
an investigator the plain `aws` CLI against it, read-only:

```
CARGO_BUILD_JOBS=4 nice -n 19 cargo build --release -p aws-emulator-ocw -j 4
target/release/aws-emulator-ocw --seed /root/ocw-aws/seed.json -p 9311 -t off
```

The binary is package `core/ocw-emulator` (bin `aws-emulator-ocw`): upstream's
`core/router/src/main.rs` plus two hooks. `core/router` itself is left exactly as upstream
ships it, so a change to the seed loader rebuilds this small binary and not the router
library (which takes ~35 minutes at `nice -n 19 -j 4`).

The investigator's `aws` then needs only:

```
AWS_ENDPOINT_URL=https://127.0.0.1:9311
AWS_CA_BUNDLE=<emulator home>/.aws/emulator/9311/ca.pem     # copy it somewhere readable
AWS_SHARED_CREDENTIALS_FILE=<seed read_only.credentials_out>
AWS_DEFAULT_REGION=us-east-1
```

## What the patch does

| # | change | where |
|---|---|---|
| 1 | `--seed <file>` / `EMULATOR_SEED`: the seed is read and applied in process **before the listener serves anyone**. There is no admin route; nothing about seeding is reachable over the wire. A failing setup call aborts the boot (exit 3) unless the seed says `"setup_errors": "warn"`, which logs each failure (`ocw-seed: setup call failed, continuing: setup[i] svc.Op: HTTP s Code: body`), skips calls whose tokens name a failed capture, and lists them all under `setup_failures` in the summary line. | `core/ocw-seed`, `core/ocw-emulator` (new) |
| 2 | **Clock.** Every `clock_gettime` in the binary is linked to `ocw_clock::__wrap_clock_gettime` (`-Wl,--wrap=clock_gettime`), which adds an offset to `CLOCK_REALTIME` only. Each setup call runs at its `at`; after seeding the clock reads `clock.now` and runs on in real time. So `CreateTime`/`LaunchTime`, LookupEvents' 90-day window, RDS/ElastiCache `Duration` windows, metric retention, alarm timestamps all sit in the incident window. SigV4 skew and presign expiry keep the **real** clock (`ocw_clock::real_now`), because the CLI signs with it. The TLS CA does not depend on the time (rcgen's fixed 1975-4096 validity). | `core/ocw-clock` (new), `core/ocw-emulator/build.rs`, `vendor/server/src/request_authentication.rs` (2 lines) |
| 3 | **Setup replay.** `setup` entries are wire requests (as botocore serializes them; `oncallworlds/regress/seedkit.py` is the reference serializer) replayed through the router as the account root (SigV4 skipped only while seeding), with `ocwref__<name>__` tokens filled from earlier `capture`s and ids pinned per call (`ids`). | `vendor/smithy-server-runtime/src/multi_service_router.rs` (1 hook) |
| 4 | **Pinned ids.** While a setup call runs, a mint of a pinned kind takes the next pinned id. Kinds: EC2 — any `next_id` prefix (`vpc`, `subnet`, `sg`, `sgr`, `acl`, `rtb`, `igw`, `nat`, `eipalloc`, `eni`, `lt`, `vpce`, `vol`, ...) plus `i` (instance) and `r` (reservation); ELBv2 — `elbv2` (the 16-hex ARN tail of a load balancer, target group, listener or rule; `CreateListener` mints two: listener, then its default rule); Route 53 — `Z` (hosted zone) and `C` (change); IAM — the unique-id prefix (`AROA` role, `ANPA` policy, `AIPA` instance profile, `AIDA` user, `AGPA` group); RDS — `dbi` (`DbiResourceId`) and `rdshost` (the 12-character endpoint token). Association ids are `next_id` prefixes too: `aclassoc` (`CreateSubnet` mints the subnet's default-NACL association), `rtbassoc` (`AssociateRouteTable`). A pin a call does not use is reported on stderr. Two things make pins exact: the account's default VPC (with its subnets, ACL, route table and group) is materialised by the first EC2 call a Region sees, so the loader makes one unpinned `DescribeVpcs` before setup — otherwise the first pinned `CreateVpc` handed its pins to the default network; and EC2 reads long-form instance ids back against its instance counter, so a pinned `i-` id raises it. | one line each in the EC2, ELBv2, Route 53, IAM and RDS mints |
| 5 | **CloudWatch** datapoints in any namespace (`AWS/*` included) with past timestamps, as plain values, statistic sets or value/count distributions (percentiles work). Read by `GetMetricData`, `GetMetricStatistics`, `ListMetrics` and alarm evaluation. | `core/ocw-seed` |
| 6 | **Alarms**: created by setup (`PutMetricAlarm`), then given the seed's state, reason, reason data, timestamps and history. A seeded alarm is not re-evaluated: the seed's data ends where the capture ended, and evaluating periods after it would move the alarm on data that was never missing. Alarms without an `alarms` entry evaluate live on the seeded data. | `core/ocw-seed` |
| 7 | **CloudTrail**: seeded records are the account's history. `LookupEvents` returns each record verbatim as `CloudTrailEvent`, filters on every lookup attribute (`EventName`, `EventSource`, `ReadOnly`, `Username`, `ResourceType`, `ResourceName`, `AccessKeyId`, `EventId`), time range and paging. `Username` is `userIdentity.userName`, else the session name of an assumed role. Lookup resources come from the record's `resources` (name = the ARN's last segment) or from an optional `_lookup_resources: [{type, name}]` key, which is stripped from the record. The same records are delivered as log files (`AWSLogs/<acct>/CloudTrail/<region>/YYYY/MM/DD/..._CloudTrail_..json.gz`) to the bucket of every trail setup made logging, one file per trail, region and five minutes, written five minutes after the span it covers (files not due yet at `clock.now` are absent). The emulator's own partial recording of the calls it serves is **off** for a seeded process (setup calls included), so nothing contradicts the seed. | `services/common/src/management_events.rs` (3 small hooks + `insert_seeded`), `core/ocw-seed` |
| 8 | **Target health** with state, reason and description (`DescribeTargetHealth`), for targets registered by setup. | `ELBv2 describe_target_health.rs` (1 hook) |
| 9 | **CloudWatch Logs** history: events of any age, groups/streams created as needed (no `PutLogEvents` 14-day/2-hour window). `FilterLogEvents`, `GetLogEvents` and Logs Insights read them. | `core/ocw-seed` |
| 10 | **Event feeds**: RDS `DescribeEvents`, ElastiCache `DescribeEvents`, Auto Scaling `DescribeScalingActivities` (a `Failed` activity reports its description as `StatusMessage`, as upstream does). | `core/ocw-seed` |
| 11 | **EC2 status**: `DescribeInstanceStatus` is implemented (was a 501): running instances pass their checks unless the seed says otherwise; `--include-all-instances`; filters `availability-zone`, `instance-state-name/code`, `system-status.status/reachability`, `instance-status.status/reachability`, `event.code/description`. `instance_states` sets an instance stopped/terminated with `StateTransitionReason` and `StateReason`. | `EC2 describe_instance_status.rs` |
| 12 | **Read-only after seeding.** A session on the read-only role is minted (`sts:AssumeRole`, 12 h; the role is created, with the path its ARN names, if setup did not). The mint stands in for the investigator's SSO sign-in, so it is not decided by the role's trust policy (an Identity Center role trusts its SAML provider): for the one call the role trusts the account and allows a 12-hour session, and both are put back exactly as setup left them. The emulator evaluates a session's identity policies, so the loader first puts an inline policy `AwsSSOInlinePolicy` on the role — what an Identity Center permission set puts on its role — allowing the read actions of ~40 services plus `allow_extra` (`read_only.inline_policy: false` leaves the role's policies to the seed; AWS-managed policies such as `ReadOnlyAccess` do not exist in the emulator) and written to `read_only.credentials_out`; `aws sts get-caller-identity` returns the principal. From then on every operation whose name does not read (`Describe*`, `List*`, `Get*`, `Lookup*`, `Search*`, `Query`, `Scan`, `BatchGet*`, `Head*`, `Select*`, `Filter*`, `Simulate*`, `Test*`, `Check*`, `Validate*`, `Download*`, `Decode*` — except `TestFailover`, `TestMigration`, `StartFailover` — plus `logs:StartQuery/StopQuery`, `iam:GenerateCredentialReport`, and `read_only.allow_extra`) is refused **whatever the credentials** — the emulator's root keys included — in the service's own shape: EC2 `UnauthorizedOperation` (with an encoded authorization failure message), SNS `AuthorizationError`, JSON protocols `AccessDeniedException`, everything else `AccessDenied`, all HTTP 403, worded `User: <principal> is not authorized to perform: <svc>:<Op> on resource: <arn> because no identity-based policy allows the <svc>:<Op> action` (the resource is derived from the request where it can be: EC2 ids, IAM roles/policies, ELB ARNs, RDS/ElastiCache ids, ASG, alarm, S3 bucket/key, Route 53 zone, DynamoDB table, log group, SQS queue, EKS cluster). | `vendor/smithy-server-runtime/src/operation.rs` (1 hook + `ocw_refusal`), `core/ocw-clock` |
| 13 | **Account id** is a build-time constant, `418295736104` on this branch (`OCW_ACCOUNT_ID=<12 digits>` at `cargo build` overrides it; upstream's placeholder was `000000000000`). A seed naming another account is refused at boot. Making it a runtime value would touch ~50 `EMULATOR_ACCOUNT_ID` sites. | `vendor/server/src/lib.rs` (1 line) |
| 14 | **Instance type offerings.** Upstream withholds every current-generation type from a Region's last zone (`us-east-1c`), so `RunInstances` of an `m6i.2xlarge` node there is `Unsupported`. A world's cluster runs its node group in all three zones, so in a seeded process every zone offers every type; a capacity shortfall is stated as a seeded Auto Scaling activity instead. | `EC2 instance_ids_and_instance_types.rs` (1 hook) |
| 15 | **Auto Scaling `AttachInstances`** is implemented (was a 501): each instance must be one of the account's running EC2 instances; it joins the group `InService`/`Healthy`, `DesiredCapacity` grows by the number attached (refused past `MaxSize`), and each attachment is a `Successful` activity. | `autoscaling attach_instances.rs` |
| 16 | **Lifecycles across setup calls.** The clock jumps days between setup calls, but EC2 (`pending`→`running`, 500 ms) and RDS (`creating`→`available`, 300 ms) move a resource's state on the *monotonic* clock, which the shift does not touch. The loader applies EC2's due transitions before every setup call and waits out the real delay before an operation that reads such a state (`AttachInstances`, `RegisterTargets`, `CreateNodegroup`, `AssociateAddress`, ...; `CreateDBInstanceReadReplica`, `ModifyDBInstance`, `RebootDBInstance`, ...) and once before sealing. ElastiCache, EKS, DynamoDB and ACM lifecycles run on the wall clock and follow seeded time as they are. | `core/ocw-seed` |
| 17 | **RDS endpoints.** Upstream serves some engines on a local listener and reports *its* address as the instance's `Endpoint.Address` (`127.0.0.1`). A seeded account reports what AWS would — `<id>.<token>.<region>.rds.amazonaws.com`, the configured port, and the `cluster-`/`cluster-ro-` names for clusters — so the Route 53 records a world points at its databases resolve to what `describe-db-instances` says. | `RDS state/instances.rs`, `state/clusters.rs` (1 line each) |
| 18 | **More reads implemented** (were 501s): EC2 `DescribeTags` (instances, VPCs, subnets, security groups, route tables, gateways, interfaces, endpoints, launch templates, addresses, images; filters `key`, `value`, `resource-id`, `resource-type`, `tag:<key>`; paging), Auto Scaling `DescribeAutoScalingInstances`, `DescribeScheduledActions` and `DescribeWarmPool` (this emulator stores neither, so both answer none, and refuse an unknown group), EKS `ListFargateProfiles`. | one op file each |

Files touched outside the new crates (core/ocw-clock, core/ocw-seed, core/ocw-emulator): 19, all hooks of a few lines, each marked
`OnCallWorlds patch`. `git diff 32b3cf39b -- . ':!core/ocw-*' ':!oncallworlds' ':!PATCHES.md'`
shows exactly them.

## The seed (`ocw-aws-seed/1`)

```jsonc
{
  "format": "ocw-aws-seed/1",
  "account_id": "418295736104",
  "region": "us-east-1",
  "clock": {"now": 1773932400.0},
  "setup": [{"at": 1737000000.0, "service": "ec2", "operation": "CreateVpc",
             "request": {"method": "POST", "path": "/", "query": "", "headers": {...}, "body": "Action=CreateVpc&..."},
             "params": {...},                                  // informational
             "capture": {"vpc": "VpcId",                       // first <VpcId>/"VpcId" in the response
                         "zone": {"field": "Id", "strip_prefix": "/hostedzone/", "index": 0}},
             "ids": {"vpc": ["vpc-0a1b2c3d4e5f60718"], "acl": [...], "rtb": [...], "sg": [...]},
             "expect_error": "NoSuchEntity"}],                 // optional: tolerate this error code
  "metrics": [{"namespace", "name", "unit", "dimensions": [{"Name","Value"}], "storage_resolution": 60,
               "values": [[ts, v]] | "stats": [[ts, n, sum, min, max]] | "distribution": [[ts, [values], [counts]]]}],
  "alarms": [{"name", "state", "reason", "reason_data", "updated", "transitioned"?,
              "history": [{"ts", "type", "summary", "data"}]}],
  "target_health": [{"target_group_arn", "targets": [{"id", "port", "state", "reason", "description"}]}],
  "cloudtrail": [<full CloudTrail record>, ... (optional "_lookup_resources": [{"type","name"}])],
  "logs": [{"group", "stream", "created_ms"?, "events": [[ts_ms, "message"]]}],
  "rds_events": [{"source_identifier", "source_type", "source_arn", "date", "message", "event_categories"}],
  "elasticache_events": [{"source_identifier", "source_type", "date", "message"}],
  "autoscaling_activities": [{"group", "group_arn"?, "activity_id", "description", "cause", "start", "end",
                              "status_code", "progress", "details"}],
  "instance_status": [{"instance_id", "system_status", "instance_status", "system_details": [{"Name","Status","ImpairedSince"}],
                       "instance_details": [...], "events": [{"code", "description", "not_before", "not_after"}]}],
  "instance_states": [{"instance_id", "state", "transition_reason", "reason_code", "reason"}],
  "read_only": {"principal_arn": "arn:aws:sts::<acct>:assumed-role/OnCallReadOnly/oncall",
                "role_arn": "arn:aws:iam::<acct>:role/OnCallReadOnly",
                "credentials_out": "/etc/ocw-aws/credentials", "allow_extra": ["svc:Operation"]}
}
```

`ocwref__<name>__` tokens are filled in every section, not only setup requests. A setup call
that fails aborts the boot (exit 3) with its index, operation and the error body.

## Upgrading

1. `git fetch upstream && git rebase <new release> oncallworlds`. The hooks are anchored on
   small, stable spots (an id mint, the operation dispatch sequence, the SigV4 skew check,
   `ManagementEventLog::record_answered`); `git grep -n "OnCallWorlds patch"` lists them.
2. Build: `cargo build --release -p aws-emulator-ocw`, and
   check the clock shim is linked: `nm target/release/aws-emulator-ocw | grep __wrap_clock_gettime`
   should show the binary *importing* it only through `__wrap_` (the seed loader also warns
   at boot if the shift is not effective).
3. Run `oncallworlds/regress/run.sh target/release/aws-emulator-ocw` and compare with the table
   below. A failure that is an upstream behaviour change gets its check updated here, with
   the reason in the commit.

## Regression suite

`oncallworlds/regress/`: `seedkit.py` is the reference serializer for setup calls (botocore);
`dry_run_setup.py` replays a seed's setup calls against an *unpatched* emulator (`-a off`),
mapping pinned ids to the minted ones, to smoke-test request shapes without the patch;
`make_fixture.py` writes a small fictional account in an incident
window (VPC, 3 subnets, SGs, NACL, 3 instances, ALB/target group/listener, IAM roles and
policies, RDS Multi-AZ, ElastiCache, SQS, SNS, S3 with a policy, DynamoDB, a private Route 53
zone, a launch template and ASG, EKS, two alarms, a log group, a trail) with history in every
seeded section; `run_checks.py` runs the investigator commands with the AWS CLI v2 as the
read-only principal; `run.sh` boots the binary and runs them. `run.sh BIN --big` boots on a
seed of realistic size (400 setup calls, ~150k datapoints, 15k CloudTrail records, 20k log
lines) and reports boot time and RSS.

### Results

Fixture (41 setup calls, 3,600 datapoints, alarms with history, target health, 5 CloudTrail
records and their 4 trail log files, 30 log events, RDS/ElastiCache events, a failed scaling
activity, status checks): boots in ~1.4 s, 366 MB RSS.

| binary | result |
|---|---|
| 2026-11-13 04:41 | 178/184: RDS `Endpoint.Address` was the local listener; `ec2 describe-tags`, `autoscaling describe-auto-scaling-instances / describe-scheduled-actions / describe-warm-pool`, `eks list-fargate-profiles` were scaffolded |
| 2026-11-13 05:29 (rows 17-18) | **192/192** |

The binary is 1.39 GB (1.01 GB stripped).

OnCallWorlds' six world accounts (dev-loop seeds, 245-275 setup calls each): all boot with
0 failing setup calls in 1.5-1.9 s at ~390 MB RSS; `sts get-caller-identity` returns the
`AWSReservedSSO_OnCallReadOnly_*` session; `describe-instance-status` reports the 6 nodes.

`--big` (a 22 MB seed: 400 setup calls, 151,920 datapoints, 15,005 CloudTrail records and
their 71 trail log files, 20,030 log lines): seeded in 1.6 s, healthy 2.5 s after exec,
737 MB RSS.
