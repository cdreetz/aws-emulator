// SPDX-License-Identifier: CC0-1.0
//! OnCallWorlds patch: the process-wide switches a seeded emulator runs under.
//!
//! * **The clock.** A seeded emulator lives in an incident window that is months in the
//!   past. Its handlers read the time from ~6,500 `SystemTime::now()` call sites, so the
//!   shift is applied below all of them: the router binary is linked with
//!   `-Wl,--wrap=clock_gettime` (`core/router/build.rs`), which sends every call the
//!   program makes to `clock_gettime` -- std's `SystemTime::now()` included -- to
//!   [`__wrap_clock_gettime`], which adds [`offset`] to `CLOCK_REALTIME` and leaves every
//!   other clock (tokio's `Instant`s) alone. The few places that must keep the REAL time
//!   (SigV4 skew and presign expiry, since the AWS CLI signs with the real clock) call
//!   [`real_now`].
//! * **The phase.** `boot` -> `seeding` (setup calls are served without SigV4, as the
//!   account root, and nothing they do is recorded as CloudTrail) -> `sealed` (every
//!   mutating operation is refused; see [`refusal`]).
//! * **Pinned ids.** While a setup call runs, an id mint that would create an id of a
//!   pinned kind takes the next pinned value instead ([`take_pinned`]).
//!
//! Nothing here is reachable over the wire: the seed is a file read at startup.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ------------------------------------------------------------------ clock --

/// Nanoseconds added to `CLOCK_REALTIME`.
static OFFSET_NS: AtomicI64 = AtomicI64::new(0);

/// The C library's own `clock_gettime`, found at run time (`--wrap` renames link-time
/// references only), so the shim keeps the vDSO fast path. 0 = not looked up yet,
/// 1 = unavailable (use the raw syscall).
static REAL_CLOCK_GETTIME: AtomicUsize = AtomicUsize::new(0);

type ClockGettime = unsafe extern "C" fn(libc::clockid_t, *mut libc::timespec) -> libc::c_int;

#[allow(unsafe_code)]
unsafe fn real_clock_gettime(clock: libc::clockid_t, tp: *mut libc::timespec) -> libc::c_int {
    let mut found = REAL_CLOCK_GETTIME.load(Ordering::Relaxed);
    if found == 0 {
        let symbol = libc::dlsym(libc::RTLD_NEXT, c"clock_gettime".as_ptr());
        found = if symbol.is_null() { 1 } else { symbol as usize };
        REAL_CLOCK_GETTIME.store(found, Ordering::Relaxed);
    }
    if found > 1 {
        let real: ClockGettime = std::mem::transmute::<usize, ClockGettime>(found);
        real(clock, tp)
    } else {
        libc::syscall(libc::SYS_clock_gettime, libc::c_long::from(clock), tp) as libc::c_int
    }
}

/// What every `clock_gettime` call in the binary resolves to under `--wrap`.
///
/// # Safety
///
/// The C contract of `clock_gettime`: `tp` is null or points to a writable `timespec`.
#[allow(unsafe_code)]
#[no_mangle]
pub unsafe extern "C" fn __wrap_clock_gettime(
    clock: libc::clockid_t,
    tp: *mut libc::timespec,
) -> libc::c_int {
    let rc = real_clock_gettime(clock, tp);
    if rc == 0 && !tp.is_null() && (clock == libc::CLOCK_REALTIME || clock == libc::CLOCK_REALTIME_COARSE)
    {
        let offset = OFFSET_NS.load(Ordering::Relaxed);
        if offset != 0 {
            let total = i128::from((*tp).tv_sec) * 1_000_000_000 + i128::from((*tp).tv_nsec)
                + i128::from(offset);
            (*tp).tv_sec = total.div_euclid(1_000_000_000) as libc::time_t;
            (*tp).tv_nsec = total.rem_euclid(1_000_000_000) as libc::c_long;
        }
    }
    rc
}

/// The real wall clock, whatever the emulator's clock says.
#[allow(unsafe_code)]
pub fn real_now() -> SystemTime {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid, writable timespec.
    let rc = unsafe { real_clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if rc != 0 {
        return SystemTime::now();
    }
    UNIX_EPOCH + Duration::new(ts.tv_sec.max(0) as u64, ts.tv_nsec.clamp(0, 999_999_999) as u32)
}

fn secs_of(at: SystemTime) -> f64 {
    match at.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs_f64(),
        Err(e) => -e.duration().as_secs_f64(),
    }
}

/// The current shift, in nanoseconds.
pub fn offset() -> i64 {
    OFFSET_NS.load(Ordering::Relaxed)
}

/// Make the emulator's clock read `epoch_secs` now (it keeps running from there).
pub fn set_now(epoch_secs: f64) {
    let shift = (epoch_secs - secs_of(real_now())) * 1e9;
    OFFSET_NS.store(shift as i64, Ordering::Relaxed);
}

/// Whether the binary really runs on the shifted clock (the link-time wrap is in place).
pub fn shift_effective() -> bool {
    let before = offset();
    let probe = secs_of(real_now()) - 86_400.0 * 365.0;
    set_now(probe);
    let seen = secs_of(SystemTime::now());
    OFFSET_NS.store(before, Ordering::Relaxed);
    (seen - probe).abs() < 60.0
}

// ------------------------------------------------------------------ phase --

const BOOT: u8 = 0;
const SEEDING: u8 = 1;
const SEALED: u8 = 2;

static PHASE: AtomicU8 = AtomicU8::new(BOOT);

/// Setup calls are being replayed: requests are served without SigV4, as the account root.
pub fn seeding() -> bool {
    PHASE.load(Ordering::Relaxed) == SEEDING
}

/// A seed was loaded. The seed is the account's CloudTrail of record, so the emulator's own
/// recording of the calls it serves is off for the life of the process.
pub fn seeded() -> bool {
    PHASE.load(Ordering::Relaxed) != BOOT
}

pub fn begin_seeding() {
    PHASE.store(SEEDING, Ordering::Relaxed);
}

/// Who the investigator is, once the account is sealed.
#[derive(Debug, Clone)]
pub struct ReadOnly {
    pub principal_arn: String,
    pub account_id: String,
    pub region: String,
    /// Extra `prefix:Operation` actions allowed although their names read as writes.
    pub allow: Vec<String>,
}

static READ_ONLY: OnceLock<ReadOnly> = OnceLock::new();

/// End seeding: from now on every mutating call is refused for `who`.
pub fn seal(who: ReadOnly) {
    let _ = READ_ONLY.set(who);
    PHASE.store(SEALED, Ordering::Relaxed);
}

pub fn sealed() -> Option<&'static ReadOnly> {
    (PHASE.load(Ordering::Relaxed) == SEALED).then(|| READ_ONLY.get()).flatten()
}

// ------------------------------------------------------------- pinned ids --

static PINNED: Mutex<Option<HashMap<String, VecDeque<String>>>> = Mutex::new(None);

/// Pin ids for the setup call about to run: kind -> ids, taken in order.
pub fn pin(ids: HashMap<String, Vec<String>>) {
    let mut slot = PINNED.lock().unwrap_or_else(|e| e.into_inner());
    *slot = Some(ids.into_iter().map(|(k, v)| (k, v.into())).collect());
}

/// Drop whatever the last setup call did not use.
pub fn unpin() -> Vec<String> {
    let mut slot = PINNED.lock().unwrap_or_else(|e| e.into_inner());
    let left = slot
        .take()
        .map(|m| m.into_iter().filter(|(_, v)| !v.is_empty()).map(|(k, _)| k).collect())
        .unwrap_or_default();
    left
}

/// The next pinned id of `kind` (`i`, `sg`, `subnet`, `tg`, ...), if the running setup call
/// pinned one. Every id mint the patch hooks asks this first.
pub fn take_pinned(kind: &str) -> Option<String> {
    if !seeding() {
        return None;
    }
    let mut slot = PINNED.lock().unwrap_or_else(|e| e.into_inner());
    slot.as_mut()?.get_mut(kind)?.pop_front()
}

// --------------------------------------------------------------- read-only --

/// Operation-name prefixes that read and never write.
const READ_PREFIXES: &[&str] = &[
    "Describe", "List", "Get", "Lookup", "Search", "Query", "Scan", "BatchGet", "Head",
    "Select", "Filter", "Simulate", "Test", "Check", "Validate", "Download", "Decode",
];

/// Actions a read-only on-call role holds although their names do not read as reads.
const READ_EXTRA: &[&str] = &[
    "logs:StartQuery", "logs:StopQuery", "logs:StartLiveTail", "iam:GenerateCredentialReport",
    "iam:GenerateServiceLastAccessedDetails", "athena:StartQueryExecution",
    "cloudtrail:StartQuery", "sts:GetCallerIdentity",
];

/// The IAM action prefix of a signing name, where the two differ.
pub fn action_prefix(signing_name: &str) -> &str {
    match signing_name {
        "monitoring" => "cloudwatch",
        "elasticloadbalancingv2" => "elasticloadbalancing",
        "email" => "ses",
        other => other,
    }
}

/// Operations whose names read as reads but act (`elasticache test-failover` fails a
/// primary over).
const NOT_READ: &[&str] = &["TestFailover", "TestMigration", "StartFailover"];

pub fn is_read(prefix: &str, operation: &str, extra: &[String]) -> bool {
    let action = format!("{prefix}:{operation}");
    if NOT_READ.contains(&operation) && !extra.iter().any(|a| a == &action) {
        return false;
    }
    READ_PREFIXES.iter().any(|p| operation.starts_with(p))
        || READ_EXTRA.contains(&action.as_str())
        || extra.iter().any(|a| a == &action)
}

/// How the refused request was framed, which decides the error code a client sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    Ec2Query,
    Query,
    Json,
    RestXml,
}

/// A refusal, in the service's own words.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub code: &'static str,
    pub message: String,
}

/// The refusal for `operation` once the account is sealed, `None` when it may run.
pub fn refusal(
    signing_name: &str,
    operation: &str,
    framing: Framing,
    path_and_query: &str,
    body: &[u8],
) -> Option<Refusal> {
    let who = sealed()?;
    let prefix = action_prefix(signing_name);
    if is_read(prefix, operation, &who.allow) {
        return None;
    }
    let action = format!("{prefix}:{operation}");
    let region = who.region.as_str();
    // S3 quotes the resource in its refusal; the other services do not.
    let resource = resource_of(prefix, framing, path_and_query, body, region, &who.account_id)
        .map(|arn| if prefix == "s3" { format!(" on resource: \"{arn}\"") } else { format!(" on resource: {arn}") })
        .unwrap_or_default();
    let because = format!(
        "User: {} is not authorized to perform: {action}{resource} because no \
         identity-based policy allows the {action} action",
        who.principal_arn
    );
    Some(match (prefix, framing) {
        ("ec2", _) => Refusal {
            code: "UnauthorizedOperation",
            message: format!(
                "You are not authorized to perform this operation. {because}. Encoded \
                 authorization failure message: {}",
                encoded_failure(&action)
            ),
        },
        ("sns", _) => Refusal { code: "AuthorizationError", message: because },
        ("s3", _) => Refusal { code: "AccessDenied", message: because },
        (_, Framing::Json) => Refusal { code: "AccessDeniedException", message: because },
        _ => Refusal { code: "AccessDenied", message: because },
    })
}

/// An opaque blob in the shape EC2 appends to a refusal (`sts decode-authorization-message`
/// decodes the real thing; this one decodes to nothing).
fn encoded_failure(action: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15
        ^ (secs_of(real_now()) * 1e6) as u64
        ^ action.bytes().fold(0u64, |h, b| h.wrapping_mul(131).wrapping_add(u64::from(b)));
    (0..412)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ALPHABET[(x % 64) as usize] as char
        })
        .collect()
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `key=value` pairs of a query string or a form body, decoded.
pub fn form_pairs(text: &str) -> Vec<(String, String)> {
    text.split('&')
        .filter(|item| !item.is_empty())
        .map(|item| {
            let (k, v) = item.split_once('=').unwrap_or((item, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

/// The first `"key": "value"` string member anywhere in a JSON document.
pub fn json_string(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let at = body.find(&needle)? + needle.len();
    let rest = body[at..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => out.push(chars.next()?),
            c => out.push(c),
        }
    }
    None
}

fn resource_of(
    prefix: &str,
    framing: Framing,
    path_and_query: &str,
    body: &[u8],
    region: &str,
    account: &str,
) -> Option<String> {
    let body = String::from_utf8_lossy(body);
    let (path, query) = path_and_query.split_once('?').unwrap_or((path_and_query, ""));
    let mut pairs = form_pairs(query);
    if matches!(framing, Framing::Query | Framing::Ec2Query) {
        pairs.extend(form_pairs(&body));
    }
    let param = |names: &[&str]| {
        names.iter().find_map(|name| {
            pairs
                .iter()
                .find(|(k, _)| k == name || k.strip_suffix(".1") == Some(name)
                    || k.strip_suffix(".member.1") == Some(name))
                .map(|(_, v)| v.clone())
        })
    };
    let json = |name: &str| json_string(&body, name);
    match prefix {
        "ec2" => {
            const KINDS: &[(&str, &str)] = &[
                ("GroupId", "security-group"), ("InstanceId", "instance"),
                ("SubnetId", "subnet"), ("VpcId", "vpc"), ("NetworkAclId", "network-acl"),
                ("RouteTableId", "route-table"), ("LaunchTemplateId", "launch-template"),
                ("NatGatewayId", "natgateway"), ("NetworkInterfaceId", "network-interface"),
                ("VolumeId", "volume"), ("VpcEndpointId", "vpc-endpoint"),
            ];
            KINDS.iter().find_map(|(name, kind)| {
                param(&[name]).map(|id| format!("arn:aws:ec2:{region}:{account}:{kind}/{id}"))
            })
        }
        "iam" => param(&["PolicyArn"]).or_else(|| {
            param(&["RoleName"]).map(|n| format!("arn:aws:iam::{account}:role/{n}"))
        }).or_else(|| param(&["UserName"]).map(|n| format!("arn:aws:iam::{account}:user/{n}")))
            .or_else(|| param(&["InstanceProfileName"])
                .map(|n| format!("arn:aws:iam::{account}:instance-profile/{n}"))),
        "elasticloadbalancing" => {
            param(&["TargetGroupArn", "LoadBalancerArn", "ListenerArn", "RuleArn", "ResourceArns"])
        }
        "rds" => param(&["DBInstanceIdentifier"])
            .map(|n| format!("arn:aws:rds:{region}:{account}:db:{n}"))
            .or_else(|| param(&["DBClusterIdentifier"])
                .map(|n| format!("arn:aws:rds:{region}:{account}:cluster:{n}"))),
        "elasticache" => param(&["ReplicationGroupId"])
            .map(|n| format!("arn:aws:elasticache:{region}:{account}:replicationgroup:{n}"))
            .or_else(|| param(&["CacheClusterId"])
                .map(|n| format!("arn:aws:elasticache:{region}:{account}:cluster:{n}"))),
        "autoscaling" => param(&["AutoScalingGroupName"]).map(|n| {
            format!("arn:aws:autoscaling:{region}:{account}:autoScalingGroup:*:autoScalingGroupName/{n}")
        }),
        "cloudwatch" => param(&["AlarmName", "AlarmNames"])
            .or_else(|| json("AlarmName"))
            .map(|n| format!("arn:aws:cloudwatch:{region}:{account}:alarm:{n}")),
        "s3" => {
            let rest = path.trim_start_matches('/');
            (!rest.is_empty()).then(|| format!("arn:aws:s3:::{}", percent_decode(rest)))
        }
        "route53" => path.split("/hostedzone/").nth(1).map(|tail| {
            format!("arn:aws:route53:::hostedzone/{}", tail.split('/').next().unwrap_or(""))
        }),
        "dynamodb" => json("TableName")
            .map(|n| format!("arn:aws:dynamodb:{region}:{account}:table/{n}")),
        "logs" => json("logGroupName")
            .map(|n| format!("arn:aws:logs:{region}:{account}:log-group:{n}")),
        "sqs" => json("QueueUrl").or_else(|| param(&["QueueUrl"])).and_then(|url| {
            url.rsplit('/').next().map(|q| format!("arn:aws:sqs:{region}:{account}:{q}"))
        }),
        "eks" => path.split("/clusters/").nth(1).map(|tail| {
            format!("arn:aws:eks:{region}:{account}:cluster/{}", tail.split('/').next().unwrap_or(""))
        }),
        "sns" => param(&["TopicArn"]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_writes_are_told_apart() {
        assert!(is_read("ec2", "DescribeSecurityGroups", &[]));
        assert!(is_read("logs", "StartQuery", &[]));
        assert!(!is_read("ec2", "RevokeSecurityGroupIngress", &[]));
        assert!(!is_read("dynamodb", "BatchWriteItem", &[]));
        assert!(is_read("dynamodb", "BatchGetItem", &[]));
        assert!(!is_read("elasticache", "TestFailover", &[]));
    }

    #[test]
    fn form_and_json_members_are_read() {
        let pairs = form_pairs("Action=RevokeSecurityGroupIngress&GroupId=sg-0abc&X=a%2Fb+c");
        assert_eq!(pairs[1], ("GroupId".to_string(), "sg-0abc".to_string()));
        assert_eq!(pairs[2].1, "a/b c");
        assert_eq!(json_string(r#"{"TableName" : "orders"}"#, "TableName").as_deref(), Some("orders"));
    }
}

// ------------------------------------------------------------ seeded facts --
//
// Facts a seed states that no operation of the service can produce (a health verdict with
// its reason, an impaired status check). They live in the shared engine under these types
// (`engine.state::<SeededTargetHealth>()`), so a service reads them without the seed loader
// and the service sharing any other type.

/// One target's health as a seed states it.
#[derive(Debug, Clone, Default)]
pub struct TargetHealthSeed {
    pub state: String,
    pub reason: Option<String>,
    pub description: Option<String>,
}

/// Target group ARN -> (target id, port) -> health.
#[derive(Debug, Default)]
pub struct SeededTargetHealth {
    pub by_group: HashMap<String, HashMap<(String, Option<i32>), TargetHealthSeed>>,
}

/// One status check line (`reachability`), as `InstanceStatusDetails` reports it.
#[derive(Debug, Clone, Default)]
pub struct StatusDetailSeed {
    pub name: String,
    pub status: String,
    pub impaired_since: Option<f64>,
}

/// One scheduled event on an instance (`instance-retirement`, `system-reboot`, ...).
#[derive(Debug, Clone, Default)]
pub struct StatusEventSeed {
    pub code: String,
    pub description: String,
    pub not_before: Option<f64>,
    pub not_after: Option<f64>,
}

#[derive(Debug, Clone, Default)]
pub struct InstanceStatusSeed {
    pub system_status: String,
    pub instance_status: String,
    pub system_details: Vec<StatusDetailSeed>,
    pub instance_details: Vec<StatusDetailSeed>,
    pub events: Vec<StatusEventSeed>,
}

/// Instance id -> status checks.
#[derive(Debug, Default)]
pub struct SeededInstanceStatus {
    pub by_instance: HashMap<String, InstanceStatusSeed>,
}
