// SPDX-License-Identifier: CC0-1.0
//! OnCallWorlds patch: load an `ocw-aws-seed/1` file into the emulator at startup.
//!
//! `aws-emulator --seed /root/ocw-aws/seed.json` (or `EMULATOR_SEED=...`). The seed is
//! applied in process, before the listener serves anyone, and there is no route to it:
//!
//! 1. `setup` -- wire requests (as botocore serializes them) replayed through the router as
//!    the account root, each with the emulator clock set to its `at`, ids pinned where the
//!    entry pins them, and `ocwref__<name>__` tokens filled from earlier captures. Setup calls
//!    are the account's history, so none of them is recorded as a CloudTrail event.
//! 2. History no API call can write: CloudWatch datapoints in any namespace, alarm state and
//!    history, target health with reasons, CloudTrail records, CloudWatch Logs events, RDS and
//!    ElastiCache events, Auto Scaling activities, EC2 status checks and instance states.
//! 3. The investigator: a session on the read-only role, written as a credentials file.
//! 4. The clock is set to `clock.now` and the account is sealed: every mutating call is
//!    refused from here on (`ocw_clock::refusal`).
//!
//! The file format is documented in `PATCHES.md`.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use emulator_server::EmulatorService;
use engine::InMemoryEngine;
use serde_json::Value;

use service_com_amazonaws_autoscaling_autoscaling_2011_01_01 as autoscaling;
use service_com_amazonaws_cloudwatch_graniteserviceversion20100801 as cloudwatch;
use service_com_amazonaws_cloudwatchlogs_logs_20140328 as logs;
use service_com_amazonaws_ec2_amazonec2 as ec2;
use service_com_amazonaws_elasticache_amazonelasticachev9 as elasticache;
use service_com_amazonaws_rds_amazonrdsv19 as rds;

const FORMAT: &str = "ocw-aws-seed/1";
/// A little over RDS's `STATUS_TRANSITION_DELAY` (300 ms, on the monotonic clock).
const RDS_SETTLE: Duration = Duration::from_millis(350);
/// A little over EC2's `TRANSITION_DELAY` (500 ms, on the monotonic clock).
const EC2_SETTLE: Duration = Duration::from_millis(550);

/// Setup operations that read an EC2 instance's state (it must be `running`).
const READS_INSTANCE_STATE: &[&str] = &[
    "AttachInstances", "RegisterTargets", "CreateNodegroup", "AttachLoadBalancerTargetGroups",
    "AttachTrafficSources", "AssociateAddress", "CreateImage", "StopInstances", "ModifyInstanceAttribute",
];
/// Setup operations that read a DB instance's status (it must be `available`).
const READS_DB_STATE: &[&str] = &[
    "CreateDBInstanceReadReplica", "ModifyDBInstance", "RebootDBInstance", "CreateDBSnapshot",
    "AddRoleToDBInstance", "PromoteReadReplica", "StopDBInstance", "CreateDBProxy",
];

/// Sleep until `settle` of real time has passed since `since`.
fn wait_out(since: Option<Instant>, settle: Duration) {
    if let Some(elapsed) = since.map(|at| at.elapsed()) {
        if elapsed < settle {
            std::thread::sleep(settle - elapsed);
        }
    }
}
const TOKEN: &str = "ocwref__";

static SEED_PATH: OnceLock<String> = OnceLock::new();

/// Take `--seed <file>` / `--seed=<file>` out of the command line (the CLI parser does not
/// know it); `EMULATOR_SEED` is the fallback.
pub fn take_seed_arg(args: Vec<String>) -> Vec<String> {
    let mut rest = Vec::with_capacity(args.len());
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "--seed" {
            if let Some(path) = iter.next() {
                let _ = SEED_PATH.set(path);
            }
        } else if let Some(path) = arg.strip_prefix("--seed=") {
            let _ = SEED_PATH.set(path.to_string());
        } else {
            rest.push(arg);
        }
    }
    if SEED_PATH.get().is_none() {
        if let Ok(path) = std::env::var("EMULATOR_SEED") {
            if !path.is_empty() {
                let _ = SEED_PATH.set(path);
            }
        }
    }
    rest
}

/// Apply the seed named on the command line, if one was.
pub async fn apply_if_given<R: EmulatorService>(
    engine: &Arc<InMemoryEngine>,
    router: &R,
) -> Result<(), String> {
    let Some(path) = SEED_PATH.get() else {
        return Ok(());
    };
    let started = Instant::now();
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let seed: Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    drop(text);
    let summary = apply(engine, router, seed).await?;
    eprintln!(
        "{}",
        serde_json::json!({"ocw_seed": path, "seconds": started.elapsed().as_secs_f64(),
                           "applied": summary})
    );
    Ok(())
}

fn str_of<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn f64_of(value: &Value, key: &str) -> Option<f64> {
    value.get(key).and_then(Value::as_f64)
}

fn at(secs: f64) -> SystemTime {
    if secs >= 0.0 {
        UNIX_EPOCH + Duration::from_secs_f64(secs)
    } else {
        UNIX_EPOCH
    }
}

fn wire_time(secs: f64) -> aws_smithy_types::DateTime {
    aws_smithy_types::DateTime::from_secs_f64(secs)
}

fn leak(text: &str) -> &'static str {
    Box::leak(text.to_string().into_boxed_str())
}

/// Replace every `ocwref__<name>__` in `text` by its capture.
fn fill(text: &str, captures: &HashMap<String, String>) -> Result<String, String> {
    if !text.contains(TOKEN) {
        return Ok(text.to_string());
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(TOKEN) {
        out.push_str(&rest[..start]);
        let after = &rest[start + TOKEN.len()..];
        let Some(end) = after.find("__") else {
            out.push_str(&rest[start..]);
            return Ok(out);
        };
        let name = &after[..end];
        let value = captures
            .get(name)
            .ok_or_else(|| format!("token {TOKEN}{name}__ names no capture made before it"))?;
        out.push_str(value);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// `fill` over every string of a JSON document.
fn fill_value(value: &mut Value, captures: &HashMap<String, String>) -> Result<(), String> {
    match value {
        Value::String(text) => {
            if text.contains(TOKEN) {
                *text = fill(text, captures)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                fill_value(item, captures)?;
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                fill_value(item, captures)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// `fill_value`, keeping any token whose capture does not exist.
fn fill_value_lenient(value: &mut Value, captures: &HashMap<String, String>) {
    match value {
        Value::String(text) if text.contains(TOKEN) => {
            let mut out = text.clone();
            for (name, real) in captures {
                out = out.replace(&format!("{TOKEN}{name}__"), real);
            }
            *text = out;
        }
        Value::Array(items) => items.iter_mut().for_each(|v| fill_value_lenient(v, captures)),
        Value::Object(map) => map.values_mut().for_each(|v| fill_value_lenient(v, captures)),
        _ => {}
    }
}

/// The `index`-th `<field>text</field>` (XML) or `"field": "text"` (JSON) of a response, or of
/// its lowerCamel form (EC2 answers `<vpcId>`).
fn find_field(body: &str, field: &str, index: usize) -> Option<String> {
    find_exact(body, field, index).or_else(|| {
        let mut chars = field.chars();
        let lower: String = chars
            .next()
            .map(|c| c.to_ascii_lowercase().to_string() + chars.as_str())
            .unwrap_or_default();
        (lower != field).then(|| find_exact(body, &lower, index)).flatten()
    })
}

fn find_exact(body: &str, field: &str, index: usize) -> Option<String> {
    let mut found = Vec::new();
    let open = format!("<{field}>");
    let close = format!("</{field}>");
    let mut rest = body;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else { break };
        found.push(xml_unescape(&after[..end]));
        rest = &after[end + close.len()..];
    }
    if found.is_empty() {
        let key = format!("\"{field}\"");
        let mut rest = body;
        while let Some(start) = rest.find(&key) {
            let after = rest[start + key.len()..].trim_start();
            rest = &rest[start + key.len()..];
            let Some(after) = after.strip_prefix(':') else { continue };
            if let Some(text) = ocw_clock::json_string(&format!("{{\"k\":{}", after.trim_start()), "k")
            {
                found.push(text);
            }
        }
    }
    found.into_iter().nth(index)
}

fn xml_unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The error code a response names, in whichever envelope it came.
fn error_code(body: &str) -> Option<String> {
    find_field(body, "Code", 0).or_else(|| {
        find_field(body, "__type", 0).map(|t| t.rsplit('#').next().unwrap_or(&t).to_string())
    })
}

fn akid() -> String {
    emulator_server::SigV4Authenticator::for_this_process()
        .access_key_id
        .clone()
}

/// The `Authorization` header with the account root's key id in its scope, so the operation
/// resolves the root as its caller. (SigV4 is not verified while seeding.)
fn as_root(authorization: &str) -> String {
    match authorization.split_once("Credential=") {
        Some((head, tail)) => match tail.split_once('/') {
            Some((_, scope)) => format!("{head}Credential={}/{scope}", akid()),
            None => authorization.to_string(),
        },
        None => authorization.to_string(),
    }
}

fn root_authorization(signing_name: &str, region: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential={}/20260101/{region}/{signing_name}/aws4_request, \
         SignedHeaders=host;x-amz-date, Signature=00",
        akid()
    )
}

/// Serve one request through the router, in process.
async fn serve<R: EmulatorService>(
    router: &R,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
) -> Result<(u16, String), String> {
    let mut builder = http::Request::builder().method(method).uri(path);
    let mut has_host = false;
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if lower == "content-length" {
            continue;
        }
        if lower == "host" {
            has_host = true;
        }
        let value = if lower == "authorization" { as_root(value) } else { value.clone() };
        builder = builder.header(name.as_str(), value);
    }
    if !has_host {
        builder = builder.header("host", "localhost");
    }
    builder = builder.header("content-length", body.len().to_string());
    let request = builder
        .body(bytes::Bytes::from(body))
        .map_err(|e| format!("bad request: {e}"))?;
    let response = router.handle_request(request).await;
    let status = response.status().as_u16();
    let text = String::from_utf8_lossy(response.body()).into_owned();
    Ok((status, text))
}

fn headers_of(request: &Value) -> Vec<(String, String)> {
    request
        .get("headers")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

type BuiltRequest = (String, String, Vec<(String, String)>, String, Option<HashMap<String, Vec<String>>>);

/// One setup entry's wire request, with its tokens filled, and the ids it pins.
fn build_setup_request(call: &Value, captures: &HashMap<String, String>) -> Result<BuiltRequest, String> {
    let request = call.get("request").ok_or("no request")?;
    let method = str_of(request, "method").unwrap_or("POST").to_string();
    let mut path = fill(str_of(request, "path").unwrap_or("/"), captures)?;
    if let Some(query) = str_of(request, "query").filter(|q| !q.is_empty()) {
        let query = fill(query, captures)?;
        path = format!("{path}{}{query}", if path.contains('?') { "&" } else { "?" });
    }
    let mut headers = headers_of(request);
    for header in &mut headers {
        header.1 = fill(&header.1, captures)?;
    }
    let body = match request.get("body") {
        Some(Value::String(text)) => fill(text, captures)?,
        _ => String::new(),
    };
    let mut pins = None;
    if let Some(ids) = call.get("ids").and_then(Value::as_object) {
        let mut map = HashMap::new();
        for (kind, list) in ids {
            let mut values = Vec::new();
            for v in list.as_array().into_iter().flatten() {
                if let Some(v) = v.as_str() {
                    values.push(fill(v, captures)?);
                }
            }
            map.insert(kind.clone(), values);
        }
        pins = Some(map);
    }
    Ok((method, path, headers, body, pins))
}

/// Apply a parsed seed.
pub async fn apply<R: EmulatorService>(
    engine: &Arc<InMemoryEngine>,
    router: &R,
    mut seed: Value,
) -> Result<Value, String> {
    if str_of(&seed, "format") != Some(FORMAT) {
        return Err(format!("seed format must be {FORMAT:?}"));
    }
    if let Some(account) = str_of(&seed, "account_id") {
        if account != emulator_server::EMULATOR_ACCOUNT_ID {
            return Err(format!(
                "the seed names account {account}, this binary serves {}: build with \
                 OCW_ACCOUNT_ID={account}",
                emulator_server::EMULATOR_ACCOUNT_ID
            ));
        }
    }
    let region = str_of(&seed, "region").unwrap_or("us-east-1").to_string();
    let now = seed
        .get("clock")
        .and_then(|c| f64_of(c, "now"))
        .ok_or("seed needs clock.now")?;

    ocw_clock::begin_seeding();
    if !ocw_clock::shift_effective() {
        eprintln!("ocw-seed: WARNING the clock shim is not linked in; times will be real");
    }

    // 1. setup ------------------------------------------------------------------------
    let mut captures: HashMap<String, String> = HashMap::new();
    let setup = seed.get_mut("setup").map(Value::take).unwrap_or(Value::Array(vec![]));
    let setup = setup.as_array().cloned().unwrap_or_default();
    let mut unused_pins = 0usize;
    // The account's default VPC (and its subnets, ACL, route table and security group) is
    // materialised by the first EC2 call a Region sees. Made here, before any setup call
    // pins ids, so the first pinned CreateVpc does not hand its pins to the default network.
    if setup.iter().any(|call| str_of(call, "service") == Some("ec2")) {
        ocw_clock::set_now(f64_of(&setup[0], "at").unwrap_or(now));
        query_call(router, "ec2", &region, &[("Action", "DescribeVpcs"), ("Version", "2016-11-15")]).await?;
    }
    // `"setup_errors": "warn"` logs a failing setup call and goes on; the default aborts.
    let warn_only = str_of(&seed, "setup_errors") == Some("warn");
    let mut failures: Vec<Value> = Vec::new();
    // EC2 (`TRANSITION_DELAY`, 500 ms: pending -> running) and RDS (`STATUS_TRANSITION_DELAY`,
    // 300 ms: creating -> available) move a resource's state on the MONOTONIC clock, which
    // the shifted wall clock does not move. So a setup call that reads such a state waits
    // out that much real time after the last call that set one going: an instance launched
    // by one call is otherwise still `pending` when the next attaches it to a group.
    let mut last_ec2: Option<Instant> = None;
    let mut last_rds: Option<Instant> = None;
    for (index, call) in setup.iter().enumerate() {
        let label = format!(
            "setup[{index}] {}.{}",
            str_of(call, "service").unwrap_or("?"),
            str_of(call, "operation").unwrap_or("?")
        );
        let built = build_setup_request(call, &captures);
        let (method, path, headers, body, pins) = match built {
            Ok(built) => built,
            Err(e) if warn_only => {
                eprintln!("ocw-seed: setup call skipped, continuing: {label}: {e}");
                failures.push(serde_json::json!({"index": index, "operation": label, "skipped": e}));
                continue;
            }
            Err(e) => return Err(format!("{label}: {e}")),
        };
        if let Some(pins) = pins {
            ocw_clock::pin(pins);
        }
        let operation = str_of(call, "operation").unwrap_or("");
        if READS_INSTANCE_STATE.contains(&operation) {
            wait_out(last_ec2, EC2_SETTLE);
        }
        if READS_DB_STATE.contains(&operation) {
            wait_out(last_rds, RDS_SETTLE);
        }
        match str_of(call, "service").unwrap_or("") {
            "ec2" => last_ec2 = Some(Instant::now()),
            "rds" => last_rds = Some(Instant::now()),
            _ => {}
        }
        ocw_clock::set_now(f64_of(call, "at").unwrap_or(now));
        settle_ec2(engine);
        let (status, text) = serve(router, &method, &path, &headers, body.into_bytes()).await?;
        let left = ocw_clock::unpin();
        if !left.is_empty() {
            unused_pins += 1;
            eprintln!("ocw-seed: {label}: pinned ids not used for kinds {left:?}");
        }
        if !(200..300).contains(&status) {
            let code = error_code(&text).unwrap_or_default();
            if str_of(call, "expect_error") != Some(code.as_str()) {
                let excerpt: String = text.chars().take(600).collect();
                let failure = format!("{label}: HTTP {status} {code}: {excerpt}");
                if !warn_only {
                    return Err(failure);
                }
                eprintln!("ocw-seed: setup call failed, continuing: {failure}");
                failures.push(serde_json::json!({"index": index, "operation": label, "status": status,
                                                 "code": code}));
                continue;
            }
        }
        if let Some(wanted) = call.get("capture").and_then(Value::as_object) {
            for (name, how) in wanted {
                let (field, strip, nth) = match how {
                    Value::String(field) => (field.as_str(), None, 0),
                    other => (
                        str_of(other, "field").unwrap_or(""),
                        str_of(other, "strip_prefix"),
                        other.get("index").and_then(Value::as_u64).unwrap_or(0) as usize,
                    ),
                };
                let found = find_field(&text, field, nth).ok_or_else(|| {
                    let excerpt: String = text.chars().take(400).collect();
                    format!("{label}: capture {name}: no {field} in the response: {excerpt}")
                });
                let mut value = match found {
                    Ok(value) => value,
                    Err(failure) if warn_only => {
                        eprintln!("ocw-seed: capture failed, continuing: {failure}");
                        failures.push(serde_json::json!({"index": index, "operation": label,
                                                         "capture": name}));
                        continue;
                    }
                    Err(failure) => return Err(failure),
                };
                if let Some(prefix) = strip {
                    value = value.strip_prefix(prefix).unwrap_or(&value).to_string();
                }
                captures.insert(name.clone(), value);
            }
        }
    }
    ocw_clock::set_now(now);

    // Every later section may name captured ids. With `setup_errors: warn`, a token whose
    // capture failed is left as it is (and said so) rather than aborting the boot.
    if let Err(e) = fill_value(&mut seed, &captures) {
        if !warn_only {
            return Err(e);
        }
        eprintln!("ocw-seed: {e}; tokens without a capture are left unfilled");
        fill_value_lenient(&mut seed, &captures);
    }

    // 2. history ------------------------------------------------------------------------
    let mut counts = serde_json::Map::new();
    counts.insert("setup".into(), setup.len().into());
    counts.insert("captures".into(), captures.len().into());
    counts.insert("setup_calls_with_unused_pins".into(), unused_pins.into());
    counts.insert("setup_failures".into(), Value::Array(failures));
    counts.insert("datapoints".into(), seed_metrics(engine, &seed)?.into());
    counts.insert("alarms".into(), seed_alarms(engine, &seed, now)?.into());
    counts.insert("target_health".into(), seed_target_health(engine, &seed).into());
    counts.insert("cloudtrail".into(), seed_cloudtrail(engine, &seed, &region)?.into());
    counts.insert("cloudtrail_log_files".into(), deliver_trail_files(engine, router, &seed, now).await?.into());
    counts.insert("log_events".into(), seed_logs(engine, &seed, &region)?.into());
    counts.insert("rds_events".into(), seed_rds_events(engine, &seed, &region)?.into());
    counts.insert("elasticache_events".into(), seed_elasticache_events(engine, &seed)?.into());
    counts.insert("autoscaling_activities".into(), seed_activities(engine, &seed)?.into());
    counts.insert("instance_status".into(), seed_instance_status(engine, &seed).into());
    counts.insert("instance_states".into(), seed_instance_states(engine, &seed)?.into());

    // 3. the investigator ---------------------------------------------------------------
    wait_out(last_rds, RDS_SETTLE);
    wait_out(last_ec2, EC2_SETTLE);
    ocw_clock::set_now(now);
    settle_ec2(engine);
    let read_only = seed.get("read_only").cloned().unwrap_or(Value::Null);
    let principal = str_of(&read_only, "principal_arn").map(str::to_string).unwrap_or_else(|| {
        format!(
            "arn:aws:sts::{}:assumed-role/OnCallReadOnly/oncall",
            emulator_server::EMULATOR_ACCOUNT_ID
        )
    });
    if let Some(out) = str_of(&read_only, "credentials_out") {
        let creds = investigator_session(router, &principal, &read_only, &region).await?;
        write_credentials(out, &creds, &region)?;
        counts.insert("credentials_out".into(), out.into());
    }
    let allow = read_only
        .get("allow_extra")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default();

    // 4. seal ---------------------------------------------------------------------------
    ocw_clock::set_now(now);
    ocw_clock::seal(ocw_clock::ReadOnly {
        principal_arn: principal,
        account_id: emulator_server::EMULATOR_ACCOUNT_ID.to_string(),
        region,
        allow,
    });
    Ok(Value::Object(counts))
}

/// Apply the EC2 state transitions the (shifted) clock already owes -- a launched instance
/// that has finished booting is `running` -- so a setup call that reads an instance's
/// state (AttachInstances, RegisterTargets) and the first read after boot see it settled.
fn settle_ec2(engine: &Arc<InMemoryEngine>) {
    if let Some(state) = ec2::state::service_state(&**engine) {
        state.lock().materialize_due_transitions();
    }
}

// ------------------------------------------------------------------- metrics --

fn seed_metrics(engine: &Arc<InMemoryEngine>, seed: &Value) -> Result<usize, String> {
    let Some(series) = seed.get("metrics").and_then(Value::as_array) else {
        return Ok(0);
    };
    let state = cloudwatch::state::service_state(&**engine).ok_or("no CloudWatch store")?;
    let mut store = state.lock();
    let mut total = 0;
    for one in series {
        let namespace = str_of(one, "namespace").ok_or("metric without namespace")?;
        let name = str_of(one, "name").ok_or("metric without name")?;
        let mut dimensions = BTreeMap::new();
        for dim in one.get("dimensions").and_then(Value::as_array).into_iter().flatten() {
            if let (Some(k), Some(v)) = (str_of(dim, "Name"), str_of(dim, "Value")) {
                dimensions.insert(k.to_string(), v.to_string());
            }
        }
        let unit = str_of(one, "unit").map(str::to_string);
        let resolution = one
            .get("storage_resolution")
            .and_then(Value::as_i64)
            .unwrap_or(60) as i32;
        let datum = |ts: f64, n: f64, sum: f64, min: f64, max: f64| cloudwatch::state::StoredDatum {
            timestamp_secs: ts,
            sample_count: n,
            sum,
            minimum: min,
            maximum: max,
            unit: unit.clone(),
            storage_resolution: resolution,
        };
        let mut data = Vec::new();
        for row in one.get("values").and_then(Value::as_array).into_iter().flatten() {
            let row = row.as_array().ok_or("values rows are [ts, value]")?;
            let (ts, v) = (num(row, 0)?, num(row, 1)?);
            data.push(datum(ts, 1.0, v, v, v));
        }
        for row in one.get("stats").and_then(Value::as_array).into_iter().flatten() {
            let row = row.as_array().ok_or("stats rows are [ts, n, sum, min, max]")?;
            data.push(datum(num(row, 0)?, num(row, 1)?, num(row, 2)?, num(row, 3)?, num(row, 4)?));
        }
        for row in one.get("distribution").and_then(Value::as_array).into_iter().flatten() {
            let row = row.as_array().ok_or("distribution rows are [ts, values, counts]")?;
            let ts = num(row, 0)?;
            let values = row.get(1).and_then(Value::as_array).ok_or("distribution values")?;
            let counts = row.get(2).and_then(Value::as_array);
            for (i, v) in values.iter().enumerate() {
                let v = v.as_f64().ok_or("distribution value")?;
                let n = counts
                    .and_then(|c| c.get(i))
                    .and_then(Value::as_f64)
                    .unwrap_or(1.0);
                data.push(datum(ts, n, v * n, v, v));
            }
        }
        data.sort_by(|a, b| a.timestamp_secs.total_cmp(&b.timestamp_secs));
        total += data.len();
        let key = cloudwatch::state::MetricKey {
            namespace: namespace.to_string(),
            metric_name: name.to_string(),
            dimensions,
        };
        store
            .append_datapoints(key, data)
            .map_err(|_| "CloudWatch series limit reached".to_string())?;
    }
    Ok(total)
}

fn num(row: &[Value], i: usize) -> Result<f64, String> {
    row.get(i)
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("expected a number at position {i}"))
}

// -------------------------------------------------------------------- alarms --

/// Seeded alarms report the seed's state and history and are not evaluated again: the
/// seed's datapoints end where the incident's capture ended, and evaluating periods past
/// them would move the alarm on data that was never missing.
fn seed_alarms(engine: &Arc<InMemoryEngine>, seed: &Value, now: f64) -> Result<usize, String> {
    let Some(alarms) = seed.get("alarms").and_then(Value::as_array) else {
        return Ok(0);
    };
    let state = cloudwatch::state::service_state(&**engine).ok_or("no CloudWatch store")?;
    let mut store = state.lock();
    let mut n = 0;
    for one in alarms {
        let name = str_of(one, "name").ok_or("alarm without name")?;
        let Some(stored) = store.alarms.get_mut(name) else {
            return Err(format!("alarm {name} is not created by any setup call"));
        };
        if let Some(value) = str_of(one, "state") {
            stored.alarm.state_value = Some(value.to_string());
        }
        if let Some(reason) = str_of(one, "reason") {
            stored.alarm.state_reason = Some(reason.to_string());
        }
        stored.alarm.state_reason_data = str_of(one, "reason_data").map(str::to_string);
        if let Some(updated) = f64_of(one, "updated") {
            stored.alarm.state_updated_timestamp = Some(wire_time(updated));
            stored.alarm.state_transitioned_timestamp = Some(wire_time(
                f64_of(one, "transitioned").unwrap_or(updated),
            ));
        }
        stored.evaluation_due_secs = 1.0e15;
        stored.forced_state_until_secs = 1.0e15;
        let alarm_type = "MetricAlarm";
        store.alarm_history.remove(name);
        let mut history: Vec<&Value> = one
            .get("history")
            .and_then(Value::as_array)
            .map(|h| h.iter().collect())
            .unwrap_or_default();
        history.sort_by(|a, b| {
            f64_of(a, "ts").unwrap_or(0.0).total_cmp(&f64_of(b, "ts").unwrap_or(0.0))
        });
        for item in history {
            store.record_history(
                name,
                now,
                cloudwatch::ops::types::AlarmHistoryItem {
                    alarm_name: Some(name.to_string()),
                    alarm_contributor_id: None,
                    alarm_type: Some(alarm_type.to_string()),
                    timestamp: Some(wire_time(f64_of(item, "ts").unwrap_or(now))),
                    history_item_type: Some(str_of(item, "type").unwrap_or("StateUpdate").to_string()),
                    history_summary: str_of(item, "summary").map(str::to_string),
                    history_data: str_of(item, "data").map(str::to_string),
                    alarm_contributor_attributes: None,
                },
            );
        }
        n += 1;
    }
    Ok(n)
}

// ------------------------------------------------------------- target health --

fn seed_target_health(engine: &Arc<InMemoryEngine>, seed: &Value) -> usize {
    let Some(groups) = seed.get("target_health").and_then(Value::as_array) else {
        return 0;
    };
    let state = engine.state::<ocw_clock::SeededTargetHealth>();
    let mut store = state.lock();
    let mut n = 0;
    for group in groups {
        let Some(arn) = str_of(group, "target_group_arn") else { continue };
        let entry = store.by_group.entry(arn.to_string()).or_default();
        for target in group.get("targets").and_then(Value::as_array).into_iter().flatten() {
            let Some(id) = str_of(target, "id") else { continue };
            let port = target.get("port").and_then(Value::as_i64).map(|p| p as i32);
            entry.insert(
                (id.to_string(), port),
                ocw_clock::TargetHealthSeed {
                    state: str_of(target, "state").unwrap_or("healthy").to_string(),
                    reason: str_of(target, "reason").map(str::to_string),
                    description: str_of(target, "description").map(str::to_string),
                },
            );
            n += 1;
        }
    }
    n
}

// ---------------------------------------------------------------- CloudTrail --

fn parse_iso8601(text: &str) -> Option<f64> {
    // 2026-03-19T14:02:11Z or 2026-03-19T14:02:11.123Z
    let text = text.trim_end_matches('Z');
    let (date, time) = text.split_once('T')?;
    let mut d = date.split('-').map(|p| p.parse::<i64>());
    let (y, m, day) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let mut t = time.split(':');
    let (hh, mm) = (t.next()?.parse::<i64>().ok()?, t.next()?.parse::<i64>().ok()?);
    let ss: f64 = t.next()?.parse().ok()?;
    // days from civil (Howard Hinnant)
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((days * 86_400 + hh * 3600 + mm * 60) as f64 + ss)
}

fn seed_cloudtrail(engine: &Arc<InMemoryEngine>, seed: &Value, region: &str) -> Result<usize, String> {
    use service_common::management_events::{
        AuditedResource, ManagementEventLog, ServedApiCall,
    };
    let Some(records) = seed.get("cloudtrail").and_then(Value::as_array) else {
        return Ok(0);
    };
    let state = engine.state::<ManagementEventLog>();
    let mut log = state.lock();
    for (i, original) in records.iter().enumerate() {
        let mut record = original.clone();
        let lookup = record
            .as_object_mut()
            .and_then(|m| m.remove("_lookup_resources"));
        let when = str_of(&record, "eventTime")
            .and_then(parse_iso8601)
            .ok_or_else(|| format!("cloudtrail[{i}]: eventTime is not ISO 8601"))?;
        let identity = record.get("userIdentity").cloned().unwrap_or(Value::Null);
        let principal_type = str_of(&identity, "type").unwrap_or("Unknown").to_string();
        let user_name = str_of(&identity, "userName").map(str::to_string).or_else(|| {
            match principal_type.as_str() {
                "AssumedRole" | "FederatedUser" => str_of(&identity, "arn")
                    .and_then(|arn| arn.rsplit('/').next())
                    .map(str::to_string),
                "Root" => Some("root".to_string()),
                _ => None,
            }
        });
        let resources: Vec<AuditedResource> = match lookup {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|r| Some(AuditedResource::new(str_of(r, "type")?, str_of(r, "name")?)))
                .collect(),
            _ => record
                .get("resources")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|r| {
                    let arn = str_of(r, "ARN")?;
                    let name = arn.rsplit(['/', ':']).next().unwrap_or(arn);
                    Some(AuditedResource::new(str_of(r, "type").unwrap_or(""), name))
                })
                .collect(),
        };
        let read_only = match record.get("readOnly") {
            Some(Value::Bool(b)) => *b,
            Some(Value::String(s)) => s == "true",
            _ => false,
        };
        let call = ServedApiCall {
            event_name: str_of(&record, "eventName").unwrap_or("").to_string(),
            event_source: str_of(&record, "eventSource").unwrap_or("").to_string(),
            aws_region: str_of(&record, "awsRegion").unwrap_or(region).to_string(),
            read_only,
            access_key_id: str_of(&identity, "accessKeyId").map(str::to_string),
            user_name,
            principal_type,
            principal_id: str_of(&identity, "principalId").map(str::to_string),
            identity_provider: None,
            session: None,
            account_id: str_of(&record, "recipientAccountId")
                .unwrap_or(emulator_server::EMULATOR_ACCOUNT_ID)
                .to_string(),
            user_agent: str_of(&record, "userAgent").map(str::to_string),
            resources,
            request_parameters: record.get("requestParameters").cloned().unwrap_or(Value::Null),
            response_elements: record.get("responseElements").cloned(),
            error_code: str_of(&record, "errorCode").map(str::to_string),
            error_message: str_of(&record, "errorMessage").map(str::to_string),
        };
        let event_id = str_of(&record, "eventID").unwrap_or("").to_string();
        let request_id = str_of(&record, "requestID").unwrap_or("").to_string();
        log.insert_seeded(record, call, at(when), event_id, request_id);
    }
    Ok(records.len())
}

/// The same records as log files in each logging trail's bucket, one file per trail, region
/// and five minutes, delivered (and stamped) five minutes after the span they cover. Files
/// whose delivery would fall after `now` are not there yet.
async fn deliver_trail_files<R: EmulatorService>(
    engine: &Arc<InMemoryEngine>,
    router: &R,
    seed: &Value,
    now: f64,
) -> Result<usize, String> {
    use service_common::management_events::ManagementEventLog;
    use service_common::trail_log_files::{log_file_key, unique_field, DeliveredLogFile};
    const SPAN_S: f64 = 300.0;
    const DELAY_S: f64 = 300.0;
    let Some(records) = seed.get("cloudtrail").and_then(Value::as_array) else {
        return Ok(0);
    };
    let trails = engine.state::<ManagementEventLog>().lock().delivering_trails().to_vec();
    if trails.is_empty() {
        return Ok(0);
    }
    let account = emulator_server::EMULATOR_ACCOUNT_ID;
    let mut files: BTreeMap<(usize, String, i64), Vec<Value>> = BTreeMap::new();
    for original in records {
        let mut record = original.clone();
        if let Some(map) = record.as_object_mut() {
            map.remove("_lookup_resources");
        }
        let Some(when) = str_of(&record, "eventTime").and_then(parse_iso8601) else { continue };
        let region = str_of(&record, "awsRegion").unwrap_or("us-east-1").to_string();
        let read_only = matches!(record.get("readOnly"), Some(Value::Bool(true)))
            || str_of(&record, "readOnly") == Some("true");
        let span = (when / SPAN_S).floor() as i64;
        for (i, trail) in trails.iter().enumerate() {
            if trail.logs(&region, read_only) && (span as f64 + 1.0) * SPAN_S + DELAY_S <= now {
                files.entry((i, region.clone(), span)).or_default().push(record.clone());
            }
        }
    }
    let n = files.len();
    for ((i, region, span), records) in files {
        let trail = &trails[i];
        let delivered = (span as f64 + 1.0) * SPAN_S + DELAY_S;
        let key = log_file_key(trail.s3_key_prefix.as_deref(), account, &region, at(delivered), &unique_field());
        let file = DeliveredLogFile { bucket: trail.s3_bucket_name.clone(), key, region, records };
        let body = file.body().ok_or("could not gzip a trail log file")?;
        ocw_clock::set_now(delivered);
        let headers = vec![
            ("Content-Type".to_string(), "application/x-gzip".to_string()),
            ("X-Amz-Date".to_string(), "20260101T000000Z".to_string()),
            ("X-Amz-Content-Sha256".to_string(), "UNSIGNED-PAYLOAD".to_string()),
            ("Authorization".to_string(), root_authorization("s3", &file.region)),
        ];
        let path = format!("/{}/{}", file.bucket, file.key);
        let (status, text) = serve(router, "PUT", &path, &headers, body).await?;
        if !(200..300).contains(&status) {
            return Err(format!("trail log file {path}: HTTP {status}: {}", text.chars().take(300).collect::<String>()));
        }
    }
    ocw_clock::set_now(now);
    Ok(n)
}

// ---------------------------------------------------------------------- logs --

fn seed_logs(engine: &Arc<InMemoryEngine>, seed: &Value, region: &str) -> Result<usize, String> {
    let Some(streams) = seed.get("logs").and_then(Value::as_array) else {
        return Ok(0);
    };
    let state = logs::state::service_state(&**engine).ok_or("no CloudWatch Logs store")?;
    let mut store = state.lock();
    let mut n = 0;
    for one in streams {
        let group_name = str_of(one, "group").ok_or("logs entry without group")?;
        let stream_name = str_of(one, "stream").ok_or("logs entry without stream")?;
        let events: Vec<(i64, String)> = one
            .get("events")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|e| {
                let e = e.as_array()?;
                Some((e.first()?.as_i64()?, e.get(1)?.as_str()?.to_string()))
            })
            .collect();
        let first_ms = events.iter().map(|e| e.0).min().unwrap_or(0);
        let created_ms = one
            .get("created_ms")
            .and_then(Value::as_i64)
            .unwrap_or(first_ms);
        let mut seq = store.next_ingestion_seq;
        let group = store
            .log_groups
            .entry(group_name.to_string())
            .or_insert_with(|| logs::state::LogGroupRecord::new(region, group_name, created_ms));
        let stream = group.streams.entry(stream_name.to_string()).or_insert_with(|| {
            logs::state::LogStreamRecord::new(region, group_name, stream_name, created_ms)
        });
        for (ts, message) in events {
            seq += 1;
            stream.events.push(logs::state::StoredEvent {
                timestamp: ts,
                message,
                masked_message: None,
                ingestion_time: ts + 180,
                ingestion_seq: seq,
            });
            n += 1;
        }
        stream.events.sort_by_key(|e| (e.timestamp, e.ingestion_seq));
        stream.refresh_event_times();
        stream.last_ingestion_time = stream.events.last().map(|e| e.ingestion_time);
        stream.enforce_storage_ceiling();
        group.stored_bytes = group
            .streams
            .values()
            .map(logs::state::LogStreamRecord::stored_bytes)
            .sum();
        store.next_ingestion_seq = seq;
    }
    Ok(n)
}

// -------------------------------------------------------------- event feeds --

fn seed_rds_events(engine: &Arc<InMemoryEngine>, seed: &Value, region: &str) -> Result<usize, String> {
    let Some(events) = seed.get("rds_events").and_then(Value::as_array) else {
        return Ok(0);
    };
    let state = rds::state::service_state(&**engine).ok_or("no RDS store")?;
    let mut store = state.lock();
    let mut sorted: Vec<&Value> = events.iter().collect();
    sorted.sort_by(|a, b| f64_of(a, "date").unwrap_or(0.0).total_cmp(&f64_of(b, "date").unwrap_or(0.0)));
    let log = store.events.entry(region.to_string()).or_default();
    for one in sorted {
        let categories: Vec<&str> = one
            .get("event_categories")
            .and_then(Value::as_array)
            .map(|c| c.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        log.record(
            rds::state::LifecycleEvent {
                source_type: leak(str_of(one, "source_type").unwrap_or("db-instance")),
                category: leak(categories.first().copied().unwrap_or("notification")),
                message: leak(str_of(one, "message").unwrap_or("")),
            },
            str_of(one, "source_identifier").unwrap_or(""),
            str_of(one, "source_arn").unwrap_or("").to_string(),
        );
        if let Some(last) = log.entries.last_mut() {
            last.date = wire_time(f64_of(one, "date").unwrap_or(0.0));
        }
    }
    log.entries
        .sort_by(|a, b| a.date.as_secs_f64().total_cmp(&b.date.as_secs_f64()));
    Ok(events.len())
}

fn seed_elasticache_events(engine: &Arc<InMemoryEngine>, seed: &Value) -> Result<usize, String> {
    let Some(events) = seed.get("elasticache_events").and_then(Value::as_array) else {
        return Ok(0);
    };
    let state = elasticache::state::service_state(&**engine).ok_or("no ElastiCache store")?;
    let mut store = state.lock();
    for one in events {
        store.event_seq += 1;
        let when = at(f64_of(one, "date").unwrap_or(0.0));
        let key = elasticache::state::event_key(when, store.event_seq);
        store.events.insert(
            key,
            elasticache::state::EventRecord {
                source_identifier: str_of(one, "source_identifier").unwrap_or("").to_string(),
                source_type: str_of(one, "source_type").unwrap_or("cache-cluster").to_string(),
                message: str_of(one, "message").unwrap_or("").to_string(),
                at: when,
            },
        );
    }
    Ok(events.len())
}

fn seed_activities(engine: &Arc<InMemoryEngine>, seed: &Value) -> Result<usize, String> {
    let Some(activities) = seed.get("autoscaling_activities").and_then(Value::as_array) else {
        return Ok(0);
    };
    let state = autoscaling::state::service_state(&**engine).ok_or("no Auto Scaling store")?;
    let mut store = state.lock();
    for one in activities {
        let group = str_of(one, "group").ok_or("activity without group")?;
        store.activities.push(autoscaling::state::StoredActivity {
            activity_id: str_of(one, "activity_id").unwrap_or("").to_string(),
            auto_scaling_group_name: group.to_string(),
            auto_scaling_group_arn: str_of(one, "group_arn").map(str::to_string),
            description: str_of(one, "description").map(str::to_string),
            cause: str_of(one, "cause").unwrap_or("").to_string(),
            start_time: at(f64_of(one, "start").unwrap_or(0.0)),
            end_time: f64_of(one, "end").map(at),
            status_code: str_of(one, "status_code").unwrap_or("Successful").to_string(),
            progress: one.get("progress").and_then(Value::as_i64).unwrap_or(100) as i32,
            details: str_of(one, "details").map(str::to_string),
            auto_scaling_group_state: None,
            completes_at: None,
        });
    }
    store.activities.sort_by_key(|a| a.start_time);
    Ok(activities.len())
}

fn details_of(value: Option<&Value>) -> Vec<ocw_clock::StatusDetailSeed> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|d| ocw_clock::StatusDetailSeed {
            name: str_of(d, "Name").or_else(|| str_of(d, "name")).unwrap_or("reachability").to_string(),
            status: str_of(d, "Status").or_else(|| str_of(d, "status")).unwrap_or("passed").to_string(),
            impaired_since: f64_of(d, "ImpairedSince").or_else(|| f64_of(d, "impaired_since")),
        })
        .collect()
}

fn seed_instance_status(engine: &Arc<InMemoryEngine>, seed: &Value) -> usize {
    let Some(rows) = seed.get("instance_status").and_then(Value::as_array) else {
        return 0;
    };
    let state = engine.state::<ocw_clock::SeededInstanceStatus>();
    let mut store = state.lock();
    for one in rows {
        let Some(id) = str_of(one, "instance_id") else { continue };
        store.by_instance.insert(
            id.to_string(),
            ocw_clock::InstanceStatusSeed {
                system_status: str_of(one, "system_status").unwrap_or("ok").to_string(),
                instance_status: str_of(one, "instance_status").unwrap_or("ok").to_string(),
                system_details: details_of(one.get("system_details")),
                instance_details: details_of(one.get("instance_details")),
                events: one
                    .get("events")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|e| ocw_clock::StatusEventSeed {
                        code: str_of(e, "code").unwrap_or("").to_string(),
                        description: str_of(e, "description").unwrap_or("").to_string(),
                        not_before: f64_of(e, "not_before"),
                        not_after: f64_of(e, "not_after"),
                    })
                    .collect(),
            },
        );
    }
    rows.len()
}

fn seed_instance_states(engine: &Arc<InMemoryEngine>, seed: &Value) -> Result<usize, String> {
    use ec2::state::InstanceStateName;
    let Some(rows) = seed.get("instance_states").and_then(Value::as_array) else {
        return Ok(0);
    };
    let state = ec2::state::service_state(&**engine).ok_or("no EC2 store")?;
    let mut store = state.lock();
    for one in rows {
        let id = str_of(one, "instance_id").ok_or("instance_states entry without instance_id")?;
        let record = store
            .instances
            .get_mut(id)
            .ok_or_else(|| format!("instance_states: no instance {id}"))?;
        record.state = match str_of(one, "state").unwrap_or("running") {
            "pending" => InstanceStateName::Pending,
            "running" => InstanceStateName::Running,
            "shutting-down" => InstanceStateName::ShuttingDown,
            "terminated" => InstanceStateName::Terminated,
            "stopping" => InstanceStateName::Stopping,
            "stopped" => InstanceStateName::Stopped,
            other => return Err(format!("instance_states: unknown state {other}")),
        };
        record.pending_transition = None;
        if let Some(reason) = str_of(one, "transition_reason") {
            record.state_transition_reason = Some(reason.to_string());
        }
        if let (Some(code), Some(message)) = (str_of(one, "reason_code"), str_of(one, "reason")) {
            record.state_reason = Some((code.to_string(), message.to_string()));
        }
    }
    Ok(rows.len())
}

// -------------------------------------------------------------- investigator --

struct Session {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
}

fn form(pairs: &[(&str, &str)]) -> String {
    let encode = |s: &str| {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

async fn query_call<R: EmulatorService>(
    router: &R,
    signing_name: &str,
    region: &str,
    pairs: &[(&str, &str)],
) -> Result<(u16, String), String> {
    let headers = vec![
        ("Content-Type".to_string(), "application/x-www-form-urlencoded; charset=utf-8".to_string()),
        ("X-Amz-Date".to_string(), "20260101T000000Z".to_string()),
        ("Authorization".to_string(), root_authorization(signing_name, region)),
    ];
    serve(router, "POST", "/", &headers, form(pairs).into_bytes()).await
}

/// A session on the read-only role, as the account root assumes it for the investigator.
async fn investigator_session<R: EmulatorService>(
    router: &R,
    principal: &str,
    read_only: &Value,
    region: &str,
) -> Result<Session, String> {
    // arn:aws:sts::<acct>:assumed-role/<role>/<session>
    let tail = principal.split(":assumed-role/").nth(1).ok_or("principal_arn must be an assumed-role ARN")?;
    let (role, session) = tail.split_once('/').ok_or("principal_arn needs a session name")?;
    let account = emulator_server::EMULATOR_ACCOUNT_ID;
    let role_arn = str_of(read_only, "role_arn")
        .map(str::to_string)
        .unwrap_or_else(|| format!("arn:aws:iam::{account}:role/{role}"));
    let root_trust = format!(
        "{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Allow\",\"Principal\":\
         {{\"AWS\":\"arn:aws:iam::{account}:root\"}},\"Action\":\"sts:AssumeRole\"}}]}}"
    );
    let (status, text) =
        query_call(router, "iam", region, &[("Action", "GetRole"), ("Version", "2010-05-08"), ("RoleName", role)])
            .await?;
    // The role as setup left it: its trust policy (an Identity Center role trusts the SAML
    // provider, not this account) and session ceiling. The mint below stands in for the
    // investigator's SSO sign-in, so for its duration the role trusts the account and
    // allows a 12-hour session; both are put back exactly as they were afterwards.
    let mut restore: Option<(String, String)> = None;
    if status != 200 {
        // The path the role ARN names (`role/aws-reserved/sso.amazonaws.com/<name>`).
        let path = role_arn
            .split(":role")
            .nth(1)
            .and_then(|tail| tail.rsplit_once('/'))
            .map(|(path, _)| format!("{path}/"))
            .filter(|path| path != "/")
            .unwrap_or_else(|| "/".to_string());
        let (status, text) = query_call(router, "iam", region, &[
            ("Action", "CreateRole"), ("Version", "2010-05-08"), ("RoleName", role), ("Path", &path),
            ("AssumeRolePolicyDocument", &root_trust), ("MaxSessionDuration", "43200"),
        ])
        .await?;
        if status != 200 {
            return Err(format!("create role {role}: HTTP {status}: {text}"));
        }
    } else {
        let trust = find_field(&text, "AssumeRolePolicyDocument", 0)
            .map(|doc| percent_decode(&doc))
            .unwrap_or_default();
        let ceiling = find_field(&text, "MaxSessionDuration", 0).unwrap_or_else(|| "3600".to_string());
        for (action, pairs) in [
            ("UpdateAssumeRolePolicy", vec![("PolicyDocument", root_trust.as_str())]),
            ("UpdateRole", vec![("MaxSessionDuration", "43200")]),
        ] {
            let mut all = vec![("Action", action), ("Version", "2010-05-08"), ("RoleName", role)];
            all.extend(pairs);
            let (status, text) = query_call(router, "iam", region, &all).await?;
            if status != 200 {
                return Err(format!("{action} on {role}: HTTP {status}: {text}"));
            }
        }
        restore = Some((trust, ceiling));
    }
    // The role's permissions, as an Identity Center permission set puts them on its role:
    // an inline policy named AwsSSOInlinePolicy granting the read side of every service the
    // investigator uses (the emulator evaluates a session's identity policies). The seal
    // refuses every write whatever this says; `read_only.inline_policy: false` leaves the
    // role's policies to the seed.
    if read_only.get("inline_policy") != Some(&Value::Bool(false)) {
        let policy = read_only_policy(read_only);
        let (status, text) = query_call(router, "iam", region, &[
            ("Action", "PutRolePolicy"), ("Version", "2010-05-08"), ("RoleName", role),
            ("PolicyName", "AwsSSOInlinePolicy"), ("PolicyDocument", &policy),
        ])
        .await?;
        if status != 200 {
            return Err(format!("put the read-only policy on {role}: HTTP {status}: {text}"));
        }
    }
    let session = assume(router, &role_arn, session, region).await;
    if let Some((trust, ceiling)) = restore {
        for (action, pairs) in [
            ("UpdateAssumeRolePolicy", vec![("PolicyDocument", trust.as_str())]),
            ("UpdateRole", vec![("MaxSessionDuration", ceiling.as_str())]),
        ] {
            if action == "UpdateAssumeRolePolicy" && trust.is_empty() {
                continue;
            }
            let mut all = vec![("Action", action), ("Version", "2010-05-08"), ("RoleName", role)];
            all.extend(pairs);
            let (status, text) = query_call(router, "iam", region, &all).await?;
            if status != 200 {
                return Err(format!("restore {action} on {role}: HTTP {status}: {text}"));
            }
        }
    }
    session
}

async fn assume<R: EmulatorService>(
    router: &R,
    role_arn: &str,
    session: &str,
    region: &str,
) -> Result<Session, String> {
    let mut last = String::new();
    for duration in ["43200", "3600"] {
        let (status, text) = query_call(router, "sts", region, &[
            ("Action", "AssumeRole"), ("Version", "2011-06-15"), ("RoleArn", role_arn),
            ("RoleSessionName", session), ("DurationSeconds", duration),
        ])
        .await?;
        if status == 200 {
            let field = |name: &str| {
                find_field(&text, name, 0).ok_or_else(|| format!("AssumeRole answered no {name}"))
            };
            return Ok(Session {
                access_key_id: field("AccessKeyId")?,
                secret_access_key: field("SecretAccessKey")?,
                session_token: field("SessionToken")?,
            });
        }
        last = format!("HTTP {status}: {text}");
    }
    Err(format!("assume {role_arn}: {last}"))
}

/// The read side of the services an investigator reaches, in IAM's own action patterns.
const READ_ACTIONS: &[&str] = &[
    "acm:Describe*", "acm:Get*", "acm:List*", "athena:Get*", "athena:List*", "athena:StartQueryExecution",
    "autoscaling:Describe*", "cloudformation:Describe*", "cloudformation:Get*", "cloudformation:List*",
    "cloudfront:Get*", "cloudfront:List*", "cloudtrail:Describe*", "cloudtrail:Get*", "cloudtrail:List*",
    "cloudtrail:LookupEvents", "cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*",
    "dynamodb:BatchGetItem", "dynamodb:Describe*", "dynamodb:Get*", "dynamodb:List*", "dynamodb:Query",
    "dynamodb:Scan", "ec2:Describe*", "ec2:Get*", "ecr:BatchGet*", "ecr:Describe*", "ecr:Get*", "ecr:List*",
    "eks:Describe*", "eks:List*", "elasticache:Describe*", "elasticache:List*",
    "elasticloadbalancing:Describe*", "events:Describe*", "events:List*", "health:Describe*",
    "iam:Generate*", "iam:Get*", "iam:List*", "iam:Simulate*", "kms:Describe*", "kms:Get*", "kms:List*",
    "lambda:Get*", "lambda:List*", "logs:Describe*", "logs:FilterLogEvents", "logs:Get*", "logs:List*",
    "logs:StartQuery", "logs:StopQuery", "logs:TestMetricFilter", "rds:Describe*", "rds:Download*",
    "rds:List*", "route53:Get*", "route53:List*", "route53:TestDNSAnswer", "s3:Get*", "s3:List*",
    "secretsmanager:Describe*", "secretsmanager:List*", "servicequotas:Get*", "servicequotas:List*",
    "sns:Get*", "sns:List*", "sqs:Get*", "sqs:List*", "ssm:Describe*", "ssm:List*",
    "sts:DecodeAuthorizationMessage", "sts:GetCallerIdentity", "tag:Get*",
];

fn read_only_policy(read_only: &Value) -> String {
    let mut actions: Vec<String> = READ_ACTIONS.iter().map(|a| (*a).to_string()).collect();
    for extra in read_only.get("allow_extra").and_then(Value::as_array).into_iter().flatten() {
        if let Some(extra) = extra.as_str() {
            if !actions.iter().any(|a| a == extra) {
                actions.push(extra.to_string());
            }
        }
    }
    serde_json::json!({"Version": "2012-10-17", "Statement": [
        {"Sid": "ReadOnly", "Effect": "Allow", "Action": actions, "Resource": "*"}]})
    .to_string()
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(b) = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn write_credentials(path: &str, creds: &Session, region: &str) -> Result<(), String> {
    let path = std::path::Path::new(path);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let text = format!(
        "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\naws_session_token = {}\n\
         region = {region}\n",
        creds.access_key_id, creds.secret_access_key, creds.session_token
    );
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_filled_and_unknown_ones_refused() {
        let mut caps = HashMap::new();
        caps.insert("vpcmain".to_string(), "vpc-0abc".to_string());
        assert_eq!(fill("VpcId=ocwref__vpcmain__&x=1", &caps).unwrap(), "VpcId=vpc-0abc&x=1");
        assert!(fill("ocwref__nope__", &caps).is_err());
    }

    #[test]
    fn fields_are_found_in_xml_and_json() {
        assert_eq!(find_field("<a><VpcId>vpc-1</VpcId><VpcId>vpc-2</VpcId></a>", "VpcId", 1).as_deref(), Some("vpc-2"));
        assert_eq!(find_field(r#"{"QueueUrl": "https://x/q"}"#, "QueueUrl", 0).as_deref(), Some("https://x/q"));
        assert_eq!(find_field("<vpc><vpcId>vpc-9</vpcId></vpc>", "VpcId", 0).as_deref(), Some("vpc-9"));
    }

    #[test]
    fn iso_times_parse() {
        assert_eq!(parse_iso8601("1970-01-02T00:00:01Z"), Some(86_401.0));
        assert_eq!(parse_iso8601("2026-03-19T14:02:11Z"), Some(1_773_928_931.0));
    }
}
