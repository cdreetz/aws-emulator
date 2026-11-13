// SPDX-License-Identifier: CC0-1.0

//! Engine state for the com-amazonaws-route53-awsdnsv20130401 service.
//!
//! Route 53 is a control plane over the hosted zone and, inside it, the
//! resource record set, plus the traffic policy a record set can be generated
//! from, the health check a record set can be routed by, the reusable
//! delegation set a zone's name servers can come from, and the CIDR collection
//! an IP-based record set routes a client's address through. They all live here,
//! in ONE store, so every operation reads the records
//! another operation wrote. The helpers in this module are the
//! shared vocabulary the handlers in `src/ops/` use for them — DNS name
//! normalization, the sort key `ListResourceRecordSets` orders by, the
//! `/hostedzone/`, `/change/` and `/delegationset/` id prefixes the API wraps
//! ids in, and the id minting every create needs.
//!
//! Beside those caller-owned resources this store also holds the SERVICE-owned
//! records the API reports: the CIDR blocks Route 53's health checkers send
//! their checks from ([`CHECKER_IP_RANGES`]), and the geographic locations it
//! supports for geolocation routing ([`geo_location`]). No operation creates,
//! changes or deletes one — they belong to the service, not to the account — so
//! they are built into this struct's [`Default`], which the engine constructs
//! the first time a handler reaches the store. Seeding them there, rather than
//! on the first read, is what keeps `GetCheckerIpRanges`, `ListGeoLocations`
//! and `GetGeoLocation` pure reporting operations: they read the records and
//! write nothing, so a read can never change what a later caller sees.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The periodic assessment of a health check, and the CloudWatch series Route 53
/// publishes that assessment as.
pub mod health_check_status;

/// Where a simulated DNS query appears to come from, which is what a geolocation
/// record set is selected by.
pub mod client_location;

/// The geographic locations the service supports for geolocation routing, which
/// is what `ListGeoLocations` reports and `GetGeoLocation` resolves.
pub mod geo_location;

/// The CloudWatch alarm an alarm-reading health check monitors, as the reported
/// health check carries it.
pub mod monitored_alarm;

/// The VPCs the calling account holds, which a request naming a VPC is resolved
/// against.
pub mod account_vpcs;

use crate::ops::types::create_cidr_collection_types::CidrCollection;
use crate::ops::types::list_cidr_blocks_types::CidrBlockSummary;
use crate::ops::types::create_reusable_delegation_set_types::HostedZoneNotFound;
use crate::ops::types::delete_vpc_association_authorization_types::VPCAssociationAuthorizationNotFound;
use crate::ops::types::get_change_types::NoSuchChange;
use crate::ops::types::shared_types::{
    ChangeInfo, CloudWatchAlarmConfiguration, ConflictingDomainExists, DelegationSet, HealthCheck,
    HealthCheckConfig,
    HealthCheckObservation, HostedZone, HostedZoneConfig, HostedZoneFeatures,
    InvalidPaginationToken, InvalidTrafficPolicyDocument, KeySigningKey, NoSuchCidrCollectionException,
    NoSuchDelegationSet,
    NoSuchHealthCheck, NoSuchHostedZone, NoSuchTrafficPolicy, NoSuchTrafficPolicyInstance,
    GeoLocationDetails,
    ResourceRecordSet, ResourceTagSet, StatusReport, Tag, TrafficPolicy, TrafficPolicyInstance, VPC,
    HEALTH_CHECK_REGION_VALUES, R_R_TYPE_VALUES, V_P_C_REGION_VALUES,
};

/// How long after a change is submitted it reaches `INSYNC`.
///
/// `CreateHostedZone`'s own model documentation: "When you submit a
/// CreateHostedZone request, the initial status of the hosted zone is PENDING. …
/// When the NS and SOA records are available, the status of the zone changes to
/// INSYNC." Real propagation takes up to a minute; the emulator owes the same
/// transition, so the span is short but NEVER zero — a caller that reads the
/// change straight back still observes `PENDING`, exactly as it would against
/// Route 53.
pub const CHANGE_PROPAGATION: Duration = Duration::from_millis(500);

/// The `Status` of a change that has not propagated yet (`ChangeStatus` enum).
pub const STATUS_PENDING: &str = "PENDING";
/// The `Status` of a change that has propagated (`ChangeStatus` enum).
pub const STATUS_INSYNC: &str = "INSYNC";

/// How long after an accepted features update a hosted zone's accelerated
/// recovery reaches the setting that update asked for.
///
/// `AcceleratedRecoveryStatus` carries `ENABLING` and `DISABLING` beside
/// `ENABLED` and `DISABLED`, so the zone is reported MOVING to a setting before
/// it is reported holding it. Nothing in the model documents how long that move
/// takes, so the span is this emulator's own: short, but never zero, so a caller
/// that reads the zone straight back still observes the transition it started.
pub const ACCELERATED_RECOVERY_PROPAGATION: Duration = Duration::from_millis(500);

/// The status of a zone whose accelerated recovery is moving to on
/// (`AcceleratedRecoveryStatus$ENABLING`).
pub const ACCELERATED_RECOVERY_ENABLING: &str = "ENABLING";

/// The status of a zone whose accelerated recovery is on
/// (`AcceleratedRecoveryStatus$ENABLED`).
pub const ACCELERATED_RECOVERY_ENABLED: &str = "ENABLED";

/// The status of a zone whose accelerated recovery is moving to off
/// (`AcceleratedRecoveryStatus$DISABLING`).
pub const ACCELERATED_RECOVERY_DISABLING: &str = "DISABLING";

/// The status of a zone whose accelerated recovery is off
/// (`AcceleratedRecoveryStatus$DISABLED`).
pub const ACCELERATED_RECOVERY_DISABLED: &str = "DISABLED";

/// The signing status of a hosted zone Route 53 signs.
///
/// `DNSSECStatus$ServeSignature`'s own documentation: "SIGNING: DNSSEC signing
/// is enabled for the hosted zone."
pub const SERVE_SIGNATURE_SIGNING: &str = "SIGNING";

/// The signing status of a hosted zone Route 53 does not sign.
///
/// `DNSSECStatus$ServeSignature`'s own documentation: "NOT_SIGNING: DNSSEC
/// signing is not enabled for the hosted zone."
pub const SERVE_SIGNATURE_NOT_SIGNING: &str = "NOT_SIGNING";

/// The `Status` of a key-signing key Route 53 signs with.
///
/// `KeySigningKey$Status`'s own documentation: "ACTIVE: The KSK is being used
/// for signing."
pub const SIGNING_KEY_STATUS_ACTIVE: &str = "ACTIVE";

/// The `Status` of a key-signing key a failed request left in error.
///
/// `KeySigningKey$Status`'s own documentation: "INTERNAL_FAILURE: There was an
/// error during a request. Before you can continue to work with DNSSEC signing,
/// including actions that involve this KSK, you must correct the problem."
pub const SIGNING_KEY_STATUS_INTERNAL_FAILURE: &str = "INTERNAL_FAILURE";

/// The most hosted zones the account may hold.
///
/// A zone is created with a caller-chosen `CallerReference`, so without a cap a
/// caller could add zones without end, each of them allowed to reach
/// [`MAX_RECORD_SETS_PER_ZONE`]. This is Route 53's own documented account
/// quota ("Hosted zones: 500 per account"), and the model declares
/// `TooManyHostedZones` for exactly this refusal: "This operation can't be
/// completed either because the current account has reached the limit on the
/// number of hosted zones".
pub const MAX_HOSTED_ZONES: usize = 500;

/// The most changes one `ChangeBatch` may carry.
///
/// The model puts no length constraint on `Changes`, so nothing upstream of the
/// handler bounds it. This is Route 53's own documented service quota — "Maximum
/// number of changes in a single ChangeResourceRecordSets request: 1,000" — so
/// the work one call can ask of the handler is bounded by the same number the
/// real service bounds it by.
pub const MAX_CHANGES_PER_BATCH: usize = 1_000;

/// The most record sets one hosted zone may hold.
///
/// Route 53's documented per-zone quota ("Records per hosted zone: 10,000"), so
/// repeated CREATE/UPSERT cannot grow a zone without end.
pub const MAX_RECORD_SETS_PER_ZONE: usize = 10_000;

/// The most `InvalidChangeBatch` messages one refusal reports.
///
/// A refusal names the changes that were wrong, and a batch may be a thousand
/// changes long, so the message list is capped and the refusal says how many
/// more there were: the error body cannot be amplified by the batch size.
pub const MAX_REPORTED_CHANGE_PROBLEMS: usize = 32;

/// The most changes the ledger retains.
///
/// Every mutating operation appends one, and no API operation deletes one, so
/// without a cap the ledger would grow for the life of the process. Past this
/// many the oldest are evicted (see [`Route53State::retain_recent_changes`]);
/// the cap is far above any single client session's change count, so a change a
/// caller is polling is never the one evicted.
const MAX_RETAINED_CHANGES: usize = 10_000;

/// How long a change stays readable once it has reached `INSYNC`.
///
/// A change is interesting until it has propagated and the caller has seen that
/// it did; an hour past `INSYNC` is far longer than any client waits, and it
/// gives the ledger a retention answer rather than unbounded growth.
const CHANGE_RETENTION: Duration = Duration::from_secs(3_600);

/// The most tags one taggable resource may carry.
///
/// `ChangeTagsForResource$AddTags`'s own documentation: "You can add a maximum
/// of 10 tags to a health check or a hosted zone", and the modelled `TagList`
/// behind `ResourceTagSet$Tags` is `len 1..10`, so a resource holding more than
/// ten tags could not even be reported on the wire.
pub const MAX_TAGS_PER_RESOURCE: usize = 10;

/// The most health checks the account may hold.
///
/// Route 53's documented account quota ("Health checks: 200 per account"), and
/// the model declares `TooManyHealthChecks` for the refusal that enforces it.
pub const MAX_HEALTH_CHECKS: usize = 200;

/// The most deleted health checks' `CallerReference`s the store keeps holding.
///
/// A reference outlives the health check that used it (see
/// [`ComAmazonawsRoute53Awsdnsv20130401State::retain_deleted_health_check_reference`]),
/// and a caller chooses the reference freely, so without a cap a create/delete
/// loop would grow the index for the life of the process. Past this many the
/// oldest reference is released, which is the eviction policy the live
/// population already gets from [`MAX_HEALTH_CHECKS`]; the cap is far above the
/// number of health checks any one client session creates and deletes.
const MAX_RETAINED_HEALTH_CHECK_REFERENCES: usize = 10_000;

/// The most deleted traffic policies the store keeps holding.
///
/// A deleted policy's record OUTLIVES the delete — `GetTrafficPolicy` still
/// reports it ([`StoredTrafficPolicyVersion::deleted`]) — and the delete frees
/// the account's quota slot, so without a cap a create/delete loop would grow
/// the store for the life of the process. Past this many deleted policies the
/// oldest one's record is released
/// ([`ComAmazonawsRoute53Awsdnsv20130401State::retain_deleted_traffic_policies`]),
/// which is the eviction policy the live population already gets from
/// [`MAX_TRAFFIC_POLICIES`]; the cap is far above the number of policies any one
/// client session creates and deletes, so a policy a caller still holds the id
/// of is never the one released.
const MAX_RETAINED_DELETED_TRAFFIC_POLICIES: usize = 10_000;

/// The `HealthCheckType` values that check an endpoint of the caller's, rather
/// than reading a CloudWatch alarm, combining other health checks or following a
/// routing control (`HealthCheckType` enum).
///
/// These are the types whose `HealthCheckConfig` is about reaching an endpoint,
/// so they are the ones that need an endpoint to reach and that carry the
/// `RequestInterval` / `FailureThreshold` defaults below.
pub const ENDPOINT_HEALTH_CHECK_TYPES: &[&str] =
    &["HTTP", "HTTPS", "HTTP_STR_MATCH", "HTTPS_STR_MATCH", "TCP"];

/// The `HealthCheckType` values that search the response body for a string
/// (`HealthCheckType` enum).
pub const STRING_MATCH_HEALTH_CHECK_TYPES: &[&str] = &["HTTP_STR_MATCH", "HTTPS_STR_MATCH"];

/// The `HealthCheckType` values whose probe negotiates TLS with the endpoint
/// (`HealthCheckType` enum).
///
/// `HealthCheckType`'s own documentation: an `HTTPS` check "submits an HTTPS
/// request" and an `HTTPS_STR_MATCH` check "submits an HTTPS request and
/// searches ... the response body" — and "if you specify HTTPS for the value of
/// Type, the endpoint must support TLS". These are therefore the types a
/// `client_hello` is sent for at all, which is what `EnableSNI` is about.
pub const TLS_HEALTH_CHECK_TYPES: &[&str] = &["HTTPS", "HTTPS_STR_MATCH"];

/// The `HealthCheckType` that checks a TCP connection to the endpoint, rather
/// than a response to a request (`HealthCheckType` enum).
pub const HEALTH_CHECK_TYPE_TCP: &str = "TCP";
/// The `HealthCheckType` that reads a CloudWatch alarm (`HealthCheckType` enum).
pub const HEALTH_CHECK_TYPE_CLOUDWATCH_METRIC: &str = "CLOUDWATCH_METRIC";
/// The `HealthCheckType` that combines other health checks (`HealthCheckType` enum).
pub const HEALTH_CHECK_TYPE_CALCULATED: &str = "CALCULATED";
/// The `HealthCheckType` that follows a routing control (`HealthCheckType` enum).
pub const HEALTH_CHECK_TYPE_RECOVERY_CONTROL: &str = "RECOVERY_CONTROL";

/// The most `ChildHealthChecks` entries a `CALCULATED` health check may name.
///
/// The member's own published maximum (`HealthCheckConfig$ChildHealthChecks`
/// targets `ChildHealthCheckList`, `len 0..256`). Stated here as well as in the
/// model because the list is walked for every assessment of the check, so its
/// length is a bound the service enforces rather than one it assumes.
pub const MAX_CHILD_HEALTH_CHECKS: usize = 256;

/// The `RequestInterval`, in seconds, a health check that asks for none gets.
///
/// `HealthCheckConfig$RequestInterval`'s own documentation: "If you don't specify
/// a value for RequestInterval, the default value is 30 seconds."
pub const DEFAULT_REQUEST_INTERVAL: i32 = 30;

/// The `FailureThreshold` a health check that asks for none gets.
///
/// `HealthCheckConfig$FailureThreshold`'s own documentation: "if you don't
/// specify a value for FailureThreshold, the default value is three health
/// checks."
pub const DEFAULT_FAILURE_THRESHOLD: i32 = 3;

/// Whether Route 53 measures the latency to the endpoint of a health check that
/// asks for nothing either way.
///
/// `HealthCheckConfig$MeasureLatency` asks the service to "measure the latency
/// between health checkers in multiple Amazon Web Services regions and your
/// endpoint, and to display CloudWatch latency graphs" — extra work on the
/// check, so it is done only for a check that asks for it.
pub const DEFAULT_MEASURE_LATENCY: bool = false;

/// Whether the status of a health check that asks for nothing either way is
/// inverted.
///
/// `HealthCheckConfig$Inverted` asks the service "to invert the status of a
/// health check, for example, to consider a health check unhealthy when it
/// otherwise would be considered healthy", so a check that asks for nothing
/// reports the status it was assessed to have.
pub const DEFAULT_INVERTED: bool = false;

/// Whether a health check that asks for nothing either way is stopped.
///
/// `HealthCheckConfig$Disabled` "stops Route 53 from performing health checks",
/// and a check the account just asked for is one Route 53 performs.
pub const DEFAULT_DISABLED: bool = false;

/// The version a newly created health check carries.
///
/// `HealthCheckVersion` is `range 1..`, and `UpdateHealthCheck` moves it on, so a
/// health check starts at the bottom of that range.
pub const FIRST_HEALTH_CHECK_VERSION: i64 = 1;

/// The most Amazon VPCs one private hosted zone may be associated with.
///
/// Route 53's documented per-zone quota ("Amazon VPCs that you can associate
/// with a private hosted zone: 100"), which is the limit
/// `HostedZoneLimitType`'s `MAX_VPCS_ASSOCIATED_BY_ZONE` reports and which
/// `AssociateVPCWithHostedZone`'s modelled `LimitsExceeded` refuses past, so
/// repeated associations cannot grow one zone's association list without end.
pub const MAX_VPCS_PER_HOSTED_ZONE: usize = 100;

/// The most VPC association authorizations one hosted zone may hold.
///
/// Route 53's documented per-zone quota ("Authorizations for associating VPCs
/// with a private hosted zone: 1,000 per hosted zone"), and the model declares
/// `TooManyVPCAssociationAuthorizations` for exactly this refusal: "You've
/// created the maximum number of authorizations that can be created for the
/// specified hosted zone. To authorize another VPC to be associated with the
/// hosted zone, submit a DeleteVPCAssociationAuthorization request to remove an
/// existing authorization." Without it a caller could grow one zone's
/// authorization list without end.
pub const MAX_VPC_ASSOCIATION_AUTHORIZATIONS: usize = 1_000;

/// The most VPC association authorizations one response carries.
///
/// `ListVPCAssociationAuthorizations$MaxResults`'s own documentation: "If you
/// don't specify a value for MaxResults, Route 53 returns up to 50 VPCs per
/// page."
pub const MAX_VPC_AUTHORIZATIONS_PER_PAGE: i32 = 50;

/// The page size a `maxitems`-paged listing serves, and reports in its required
/// `MaxItems`, when the request names no `maxitems` of its own.
///
/// Route 53 pages a listing of account resources a hundred items at a time
/// unless the caller asks for a size: the `maxitems` ceilings the individual
/// operations publish ("Amazon Route 53 returns a maximum of 1000 items" on
/// `ListHealthChecksRequest$MaxItems`, say) CAP what a request may ask for, they
/// are not the size a request that asks for nothing is served. Shared by every
/// listing in this service, so the default page size is stated once rather than
/// reinvented per operation; a listing whose own documentation publishes a
/// different default (`ListResourceRecordSets`' "returns up to 300 resource
/// record sets at a time", `ListVPCAssociationAuthorizations`' 50 per page) uses
/// the documented one instead.
pub const DEFAULT_PAGE_SIZE: i32 = 100;

/// The most reusable delegation sets the account may hold.
///
/// Route 53's documented account quota ("Reusable delegation sets: 100 per
/// account"), which the model's `LimitsExceeded` refusal reports.
pub const MAX_REUSABLE_DELEGATION_SETS: usize = 100;

/// The most hosted zones one reusable delegation set may carry.
///
/// Route 53's documented per-set quota ("Hosted zones that can use the same
/// reusable delegation set: 100"), which is the limit `CreateHostedZone`'s own
/// `TooManyHostedZones` names beside the account one ("because you've reached
/// the limit on the number of hosted zones that can be associated with a
/// reusable delegation set"), so one set cannot take on zones without end.
pub const MAX_HOSTED_ZONES_PER_DELEGATION_SET: usize = 100;

/// The most traffic policies the account may hold.
///
/// Route 53's documented account quota ("Traffic policies: 50 per account"),
/// and the model declares `TooManyTrafficPolicies` for the refusal that
/// enforces it.
pub const MAX_TRAFFIC_POLICIES: usize = 50;

/// The most traffic policy instances the account may hold.
///
/// Route 53's documented account quota ("Traffic policy records: 50 per
/// account"), and the model declares `TooManyTrafficPolicyInstances` for the
/// refusal that enforces it.
pub const MAX_TRAFFIC_POLICY_INSTANCES: usize = 50;

/// The most CIDR collections the account may hold.
///
/// A caller picks a collection's `Name` freely, so without a bound the store
/// would take on a record for every distinct name a request carries. The number
/// is this emulator's own — it is generous enough that no faithful workload
/// reaches it — and `LimitsExceeded`, the error `CreateCidrCollection` models
/// for an account that "has reached the limit on the resource you are trying to
/// create", is what a create past it answers.
pub const MAX_CIDR_COLLECTIONS: usize = 100;

/// The `Version` a freshly created CIDR collection carries.
///
/// `CidrCollection$Version`'s own documentation: "A sequential counter that
/// Route 53 sets to 1 when you create a CIDR collection and increments by 1
/// each time you update settings for the CIDR collection."
pub const FIRST_CIDR_COLLECTION_VERSION: i64 = 1;

/// The most CIDR blocks one collection may hold.
///
/// Route 53's documented quota for a collection ("CIDR blocks per CIDR
/// collection: 1,000"), which is also the bound the model puts on the blocks one
/// change may carry (`CidrList`'s `@length(min: 1, max: 1000)`), and
/// `LimitsExceeded` is the error `ChangeCidrCollection` models for a change past
/// it.
pub const MAX_CIDR_BLOCKS_PER_COLLECTION: usize = 1000;

/// The `AccountLimitType` naming the hosted-zone quota (`AccountLimitType` enum).
pub const ACCOUNT_LIMIT_MAX_HOSTED_ZONES: &str = "MAX_HOSTED_ZONES_BY_OWNER";
/// The `AccountLimitType` naming the health-check quota (`AccountLimitType` enum).
pub const ACCOUNT_LIMIT_MAX_HEALTH_CHECKS: &str = "MAX_HEALTH_CHECKS_BY_OWNER";
/// The `AccountLimitType` naming the reusable-delegation-set quota
/// (`AccountLimitType` enum).
pub const ACCOUNT_LIMIT_MAX_REUSABLE_DELEGATION_SETS: &str =
    "MAX_REUSABLE_DELEGATION_SETS_BY_OWNER";
/// The `AccountLimitType` naming the traffic-policy quota (`AccountLimitType` enum).
pub const ACCOUNT_LIMIT_MAX_TRAFFIC_POLICIES: &str = "MAX_TRAFFIC_POLICIES_BY_OWNER";
/// The `AccountLimitType` naming the traffic-policy-instance quota
/// (`AccountLimitType` enum).
pub const ACCOUNT_LIMIT_MAX_TRAFFIC_POLICY_INSTANCES: &str =
    "MAX_TRAFFIC_POLICY_INSTANCES_BY_OWNER";

/// The `HostedZoneLimitType` naming one zone's record-set quota
/// (`HostedZoneLimitType` enum).
pub const HOSTED_ZONE_LIMIT_MAX_RRSETS: &str = "MAX_RRSETS_BY_ZONE";
/// The `HostedZoneLimitType` naming one private zone's VPC-association quota
/// (`HostedZoneLimitType` enum).
pub const HOSTED_ZONE_LIMIT_MAX_VPCS_ASSOCIATED: &str = "MAX_VPCS_ASSOCIATED_BY_ZONE";

/// The `ReusableDelegationSetLimitType` naming one reusable delegation set's
/// hosted-zone quota (`ReusableDelegationSetLimitType` enum, whose only value
/// this is).
pub const REUSABLE_DELEGATION_SET_LIMIT_MAX_ZONES: &str = "MAX_ZONES_BY_REUSABLE_DELEGATION_SET";

/// The `TagResourceType` naming a hosted zone (`TagResourceType` enum).
pub const TAG_RESOURCE_TYPE_HOSTED_ZONE: &str = "hostedzone";
/// The `TagResourceType` naming a health check (`TagResourceType` enum).
pub const TAG_RESOURCE_TYPE_HEALTH_CHECK: &str = "healthcheck";

/// The refusal text `CreateHostedZone` answers a `CallerReference` that already
/// names a zone with (`HostedZoneAlreadyExists`, HTTP 409).
///
/// A CONSTANT, naming neither the caller reference nor the zone the reference
/// already names: the shape's own documentation states the rule without either
/// ("Amazon Route 53 returns this error when a hosted zone has already been
/// created with the specified CallerReference"), and the zone's id is
/// server-generated, so a refusal quoting it would differ on every run and tell
/// a caller nothing it can act on. The zone the reference names is in state,
/// where `ListHostedZones` reads it.
pub const HOSTED_ZONE_ALREADY_EXISTS_MESSAGE: &str =
    "A hosted zone has already been created with the specified caller reference.";

/// The refusal text `CreateReusableDelegationSet` answers a `CallerReference`
/// that already names a reusable delegation set with
/// (`DelegationSetAlreadyCreated`).
///
/// A CONSTANT, naming neither the caller reference nor the set the reference
/// already names, for the same reason [`HOSTED_ZONE_ALREADY_EXISTS_MESSAGE`] is
/// one: the shape's own documentation states the rule without either ("A
/// delegation set with the same owner and caller reference combination has
/// already been created"), and the set's id is server-generated. The set the
/// reference names is in state, where a delegation-set read reports it.
pub const DELEGATION_SET_ALREADY_CREATED_MESSAGE: &str =
    "A delegation set with the same owner and caller reference combination has already been \
     created.";

/// The refusal text `CreateReusableDelegationSet` answers a hosted zone whose
/// name servers already belong to a reusable delegation set with
/// (`DelegationSetAlreadyReusable`).
///
/// The shape's own documentation, which states the rule naming nothing of the
/// request's: "The specified delegation set has already been marked as
/// reusable."
pub const DELEGATION_SET_ALREADY_REUSABLE_MESSAGE: &str =
    "The specified delegation set has already been marked as reusable.";

/// The refusal text `DeleteReusableDelegationSet` answers a set hosted zones
/// were still created in with (`DelegationSetInUse`, HTTP 400).
///
/// A CONSTANT naming neither the set nor the zones still delegating to it, like
/// [`DELEGATION_SET_ALREADY_REUSABLE_MESSAGE`] above it: the operation's own
/// documentation states the rule without either ("You can delete a reusable
/// delegation set only if it isn't associated with any hosted zones"), and the
/// zones that hold it are in state, where `ListHostedZones` filtered by the set
/// reports them.
pub const DELEGATION_SET_IN_USE_MESSAGE: &str =
    "The specified delegation set contains associated hosted zones.";

/// The refusal text `DeleteHostedZone` answers a zone that still holds records
/// of the caller's with (`HostedZoneNotEmpty`, HTTP 400).
///
/// A CONSTANT naming no zone, and it ends with what the caller has to do next —
/// the operation's own documentation states both halves ("You can delete a
/// hosted zone only if it contains only the default SOA and NS records" / "If
/// the hosted zone contains other resource record sets, you must delete them
/// before you can delete the hosted zone").
pub const HOSTED_ZONE_NOT_EMPTY_MESSAGE: &str =
    "The specified hosted zone contains resource record sets other than the default SOA and NS \
     records and so cannot be deleted. Delete all non-default records and try again.";

/// The refusal text `DisassociateVPCFromHostedZone` answers a request that would
/// take the LAST VPC out of a private hosted zone's association set with
/// (`LastVPCAssociation`, HTTP 400).
///
/// A CONSTANT, like [`HOSTED_ZONE_NOT_EMPTY_MESSAGE`] beside it: it names
/// neither the VPC the request asked to remove nor the zone it asked about, so a
/// caller telling this boundary apart from the other 4xx refusals of the same
/// operation matches one fixed sentence rather than a per-request one.
pub const LAST_VPC_ASSOCIATION_MESSAGE: &str =
    "Cannot remove last VPC association for private zone";

/// The version number a traffic policy's first version carries.
///
/// `TrafficPolicy$Version`'s own documentation: "For a new traffic policy, the
/// value of Version is always 1."
pub const FIRST_TRAFFIC_POLICY_VERSION: i32 = 1;

/// The creation position the account's first traffic policy takes, which orders
/// a listing of them (see [`StoredTrafficPolicy::created_position`]).
pub const FIRST_TRAFFIC_POLICY_POSITION: u64 = 1;

/// The highest version number one traffic policy can reach.
///
/// `CreateTrafficPolicyVersion`'s own documentation: "You can create a maximum
/// of 1000 versions of a traffic policy. If you reach the limit and need to
/// create another version, you'll need to start a new traffic policy" — the
/// limit the model's `TooManyTrafficPolicyVersionsForCurrentPolicy` reports, and
/// the same ceiling `TrafficPolicyVersion` (`range 1..1000`) allows a version
/// number to carry.
pub const MAX_TRAFFIC_POLICY_VERSION: i32 = 1000;

/// How long after a traffic policy instance is created or updated Route 53 has
/// finished creating the resource record sets it generates.
///
/// `CreateTrafficPolicyInstance`'s own model documentation: "After you submit an
/// CreateTrafficPolicyInstance request, there's a brief delay while Amazon Route
/// 53 creates the resource record sets that are specified in the traffic policy
/// definition. Use GetTrafficPolicyInstance with the id of new traffic policy
/// instance to confirm that the CreateTrafficPolicyInstance request completed
/// successfully." Nothing publishes how long that delay is, so the span is this
/// emulator's own: short, but NEVER zero — a caller that reads the instance
/// straight back still observes the `Creating` state the documentation tells it
/// to poll out of, exactly as it would against Route 53.
pub const TRAFFIC_POLICY_INSTANCE_PROPAGATION: Duration = Duration::from_millis(500);

/// The `State` of a traffic policy instance whose record sets are still being
/// created.
///
/// `TrafficPolicyInstance$State`'s own documentation: "Creating: Route 53 is
/// creating the resource record sets. Use GetTrafficPolicyInstance to confirm
/// that the CreateTrafficPolicyInstance request completed successfully."
pub const TRAFFIC_POLICY_INSTANCE_CREATING: &str = "Creating";

/// The `State` of a traffic policy instance whose record sets are in place.
///
/// `TrafficPolicyInstance$State`'s own documentation: "Applied: Amazon Route 53
/// has finished creating resource record sets, and changes have propagated to
/// all Route 53 edge locations."
pub const TRAFFIC_POLICY_INSTANCE_APPLIED: &str = "Applied";

/// The `AWSPolicyFormatVersion` a traffic policy document declares.
///
/// The "Traffic Policy Document Format" reference this operation's own
/// documentation points at publishes exactly one format version, so a document
/// declaring any other names a format this API version does not define.
pub const TRAFFIC_POLICY_FORMAT_VERSION: &str = "2015-10-01";

/// The IPv4 CIDR blocks Route 53's health checkers send their health checks
/// from, as the service publishes them TODAY.
///
/// `GetCheckerIpRanges`'s own model documentation points at the published
/// source: "we recommend that you download ip-ranges.json, which includes IP
/// address ranges for all Amazon Web Services services" — this is the set that
/// file publishes under the Route 53 health-checks service, which has two parts
/// since the checkers were consolidated:
///
/// * the `/23` sub-blocks of the single `15.177.0.0/18` allocation the checkers
///   now source from — two per `/21` inside it, at the `/21`'s third and
///   seventh `/23`, so sixteen blocks across the `/18`;
/// * one single-address `/32` left in each of the sixteen legacy regional
///   blocks, at the first address of that block's upper half, which is what the
///   regions that have not been migrated still probe from.
///
/// The retired per-region `/26` blocks themselves are NOT published here any
/// more: a caller programmes a firewall from this set, so publishing a block no
/// checker sources from would have it allow traffic Route 53 never sends and
/// (worse) omit the addresses it does.
///
/// The entries are spelled out in no particular order, because the ORDER the
/// wire carries is computed by [`checker_ip_ranges`] rather than being a
/// property of this table; duplicates in it collapse there too.
pub const CHECKER_IP_RANGES: &[&str] = &[
    // The consolidated 15.177.0.0/18 allocation, two /23s per /21.
    "15.177.2.0/23",
    "15.177.6.0/23",
    "15.177.10.0/23",
    "15.177.14.0/23",
    "15.177.18.0/23",
    "15.177.22.0/23",
    "15.177.26.0/23",
    "15.177.30.0/23",
    "15.177.34.0/23",
    "15.177.38.0/23",
    "15.177.42.0/23",
    "15.177.46.0/23",
    "15.177.50.0/23",
    "15.177.54.0/23",
    "15.177.58.0/23",
    "15.177.62.0/23",
    // One checker address left in each legacy regional block.
    "54.183.255.160/32",
    "54.228.16.32/32",
    "54.232.40.96/32",
    "54.241.32.96/32",
    "54.243.31.224/32",
    "54.244.52.224/32",
    "54.245.168.32/32",
    "54.248.220.32/32",
    "54.250.253.224/32",
    "54.251.31.160/32",
    "54.252.79.160/32",
    "54.252.254.224/32",
    "54.255.254.224/32",
    "107.23.255.32/32",
    "176.34.159.224/32",
    "177.71.207.160/32",
];

/// The health-checker CIDR blocks in the order the API reports them, with any
/// duplicate collapsed.
///
/// `CheckerIpRanges`'s own documentation: "A complex type that contains sorted
/// list of IP ranges in CIDR format". A CIDR block's order is its numeric
/// position in the address space, not the spelling of its text — `107.23.255.0`
/// comes after `54.255.254.192`, where a string comparison would put it first —
/// so the list is ordered by network address and then by prefix length.
pub fn checker_ip_ranges() -> Vec<String> {
    let mut ranges: Vec<&str> = CHECKER_IP_RANGES.to_vec();
    ranges.sort_unstable_by_key(|cidr| cidr_sort_key(cidr));
    ranges.dedup();
    ranges.into_iter().map(str::to_string).collect()
}

/// `(network address, prefix length)` for an `a.b.c.d/nn` block: the pair a CIDR
/// block's numeric position in the address space is, and so the key
/// [`checker_ip_ranges`] orders by.
///
/// A block that is not a well-formed IPv4 CIDR sorts last rather than
/// panicking, which keeps the order total whatever the table holds.
fn cidr_sort_key(cidr: &str) -> (u32, u8) {
    let (address, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
    (
        address.parse::<Ipv4Addr>().map_or(u32::MAX, u32::from),
        prefix.parse::<u8>().unwrap_or(u8::MAX),
    )
}

/// The `/hostedzone/` prefix the API wraps a hosted-zone id in.
pub const HOSTED_ZONE_PREFIX: &str = "/hostedzone/";
/// The `/change/` prefix the API wraps a change id in.
pub const CHANGE_PREFIX: &str = "/change/";
/// The `/delegationset/` prefix the API wraps a reusable delegation set's id
/// in, the same way it wraps a hosted zone's in [`HOSTED_ZONE_PREFIX`].
pub const DELEGATION_SET_PREFIX: &str = "/delegationset/";

/// A reusable delegation set, as `CreateReusableDelegationSet` persists it and
/// every delegation-set read reports it.
///
/// The id is stored BARE (`N…`); [`StoredDelegationSet::to_delegation_set`]
/// adds the `/delegationset/` prefix the wire carries, exactly as
/// [`StoredZone::to_hosted_zone`] adds `/hostedzone/`.
#[derive(Debug, Clone)]
pub struct StoredDelegationSet {
    /// The bare delegation set id, which is also this set's key in
    /// [`ComAmazonawsRoute53Awsdnsv20130401State::delegation_sets`].
    pub id: String,
    /// The `CallerReference` the set was created with.
    pub caller_reference: String,
    /// The four name servers the set delegates to — minted for the set, or
    /// taken from the hosted zone whose delegation set was marked reusable.
    pub name_servers: Vec<String>,
}

impl StoredDelegationSet {
    /// The modelled `DelegationSet` for this set: its prefixed `Id`, the
    /// `CallerReference` it was created with, and its name servers.
    pub fn to_delegation_set(&self) -> DelegationSet {
        DelegationSet {
            id: Some(format!("{DELEGATION_SET_PREFIX}{}", self.id)),
            caller_reference: Some(self.caller_reference.clone()),
            name_servers: self.name_servers.clone(),
        }
    }
}

/// A change request, as `GetChange` reports it.
///
/// The id is stored BARE (`C…`); [`StoredChange::to_change_info`] adds the
/// `/change/` prefix the wire carries.
#[derive(Debug, Clone)]
pub struct StoredChange {
    /// The bare change id, which is also this record's key in [`Route53State::changes`].
    pub id: String,
    /// When the change was submitted, in milliseconds since the Unix epoch.
    pub submitted_at_millis: i64,
    /// The instant the change becomes `INSYNC`; see [`CHANGE_PROPAGATION`].
    pub insync_at: Instant,
    /// The `ChangeBatch` comment, when the submitter gave one.
    pub comment: Option<String>,
}

impl StoredChange {
    /// `PENDING` until [`StoredChange::insync_at`], `INSYNC` from then on.
    ///
    /// Derived from the clock rather than stored, so no caller has to poll the
    /// change for it to make progress.
    pub fn status(&self) -> &'static str {
        if Instant::now() < self.insync_at {
            STATUS_PENDING
        } else {
            STATUS_INSYNC
        }
    }

    /// The modelled `ChangeInfo` for this change.
    pub fn to_change_info(&self) -> ChangeInfo {
        ChangeInfo {
            id: format!("{CHANGE_PREFIX}{}", self.id),
            status: self.status().to_string(),
            submitted_at: ::aws_smithy_types::DateTime::from_millis(self.submitted_at_millis),
            comment: self.comment.clone(),
        }
    }
}

/// A hosted zone's accelerated recovery setting, as one accepted
/// `UpdateHostedZoneFeatures` left it.
///
/// Holds the setting the caller asked for plus the instant the zone finishes
/// moving to it, so the status a read reports is DERIVED from the clock (see
/// [`AcceleratedRecovery::status`]) rather than advanced by whoever reads it.
#[derive(Debug, Clone)]
pub struct AcceleratedRecovery {
    /// Whether the last accepted update asked for accelerated recovery ON.
    pub enabled: bool,
    /// The instant the zone finishes moving to that setting; see
    /// [`ACCELERATED_RECOVERY_PROPAGATION`].
    pub settles_at: Instant,
}

impl AcceleratedRecovery {
    /// The `AcceleratedRecoveryStatus` a hosted-zone read reports: the moving
    /// status until [`AcceleratedRecovery::settles_at`], the settled one from
    /// then on.
    pub fn status(&self) -> &'static str {
        match (self.enabled, self.settled()) {
            (true, false) => ACCELERATED_RECOVERY_ENABLING,
            (true, true) => ACCELERATED_RECOVERY_ENABLED,
            (false, false) => ACCELERATED_RECOVERY_DISABLING,
            (false, true) => ACCELERATED_RECOVERY_DISABLED,
        }
    }

    /// Whether the move this setting started has completed.
    pub fn settled(&self) -> bool {
        Instant::now() >= self.settles_at
    }
}

/// The identity of a resource record set within a zone.
///
/// Route 53 keys a record set by (name, type, set identifier), and
/// `ListResourceRecordSets` returns them "sorted first by DNS name with the
/// labels reversed … When multiple records have the same DNS name,
/// ListResourceRecordSets sorts results by the record type" (the operation's own
/// documentation). Deriving `Ord` over the fields in that order makes a
/// `BTreeMap` keyed by this type give both the uniqueness rule and the list
/// order for free.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordKey {
    /// The record name's octets with its labels reversed and a trailing dot,
    /// lowercased: `www.example.com` sorts as `com.example.www.`. See
    /// [`DnsNameKey`]: every spelling of one name gives one key, so this is
    /// the name half of a record set's identity as well as its sort position.
    pub name_sort_key: DnsNameKey,
    /// The `RRType` of the record set.
    pub rr_type: String,
    /// The `SetIdentifier`, which distinguishes the members of a routing group.
    pub set_identifier: Option<String>,
}

impl RecordKey {
    /// The key for a record set, as the wire presents it.
    pub fn of(name: &str, rr_type: &str, set_identifier: Option<&str>) -> Self {
        Self {
            name_sort_key: dns_sort_key(name),
            rr_type: rr_type.to_string(),
            set_identifier: set_identifier.map(str::to_string),
        }
    }

    /// The key for an already-built record set.
    pub fn of_record(record: &ResourceRecordSet) -> Self {
        Self::of(
            &record.name,
            &record.r#type,
            record.set_identifier.as_deref(),
        )
    }
}

/// A hosted zone and the record sets it holds.
#[derive(Debug, Clone)]
pub struct StoredZone {
    /// The bare zone id (`Z…`), which is also this zone's key in [`Route53State::zones`].
    pub id: String,
    /// The domain name in the canonical form [`canonical_dns_name`] gives.
    pub name: String,
    /// The `CallerReference` the zone was created with.
    pub caller_reference: String,
    /// The `Comment` from `HostedZoneConfig`, when one was given.
    pub comment: Option<String>,
    /// Whether this is a private hosted zone.
    pub private_zone: bool,
    /// The four authoritative name servers Route 53 assigned to this zone.
    pub name_servers: Vec<String>,
    /// The VPCs associated with a private hosted zone.
    pub vpcs: Vec<VPC>,
    /// The VPCs another account has been authorized to associate with this
    /// zone, in the order they were authorized — the list
    /// `ListVPCAssociationAuthorizations` pages over and
    /// `DeleteVPCAssociationAuthorization` removes from.
    ///
    /// An authorization is held ON the zone, like the association list beside
    /// it, so deleting the zone takes its authorizations with it and the two
    /// lists cannot disagree about which zone they belong to. It is SEPARATE
    /// from `vpcs`: an authorization only permits a later
    /// `AssociateVPCWithHostedZone`, and associating the VPC does not consume
    /// it (Route 53 keeps it listed until it is deleted). Bounded by
    /// [`MAX_VPC_ASSOCIATION_AUTHORIZATIONS`].
    pub vpc_authorizations: Vec<VPC>,
    /// This zone's record sets, keyed (and therefore ordered) by [`RecordKey`].
    pub records: BTreeMap<RecordKey, ResourceRecordSet>,
    /// The zone's tags, keyed by tag key — the set `ChangeTagsForResource`
    /// edits and `ListTagsForResource` reports. Held ON the zone, so deleting
    /// the zone takes its tags with it and no second map can disagree about
    /// them. Bounded by [`MAX_TAGS_PER_RESOURCE`].
    pub tags: BTreeMap<String, String>,
    /// Whether DNSSEC signing is enabled for this zone — the state a DNSSEC
    /// read reports as `ServeSignature`.
    ///
    /// A zone is created with signing OFF: `CreateHostedZone` carries no DNSSEC
    /// input, so a new zone is one "DNSSEC signing is not enabled for"
    /// (`DNSSECStatus$ServeSignature`'s `NOT_SIGNING`). `EnableHostedZoneDNSSEC`
    /// turns it on and `DisableHostedZoneDNSSEC` turns it back off; both are
    /// still scaffolds, so every zone this store holds reports it off, exactly
    /// as Route 53 reports a zone nobody enabled signing for. It is held on the
    /// zone rather than answered as a constant by the read, so the day one of
    /// those operations sets it, the read already reports what was set.
    pub dnssec_signing_enabled: bool,
    /// This zone's key-signing keys (KSKs), keyed — and therefore ordered — by
    /// the `Name` that is unique within one zone (`KeySigningKey$Name`: "Name
    /// must be unique for each key-signing key in the same hosted zone").
    ///
    /// Held ON the zone, like the record sets and tags beside it, so deleting
    /// the zone takes its KSKs with it and no second map can disagree about
    /// which zone they belong to. `CreateKeySigningKey` is the operation that
    /// adds one and `DeleteKeySigningKey` the one that removes it; both are
    /// still scaffolds, so a zone in this store holds none of them, exactly as
    /// Route 53 reports a zone no KSK was created for.
    pub key_signing_keys: BTreeMap<String, KeySigningKey>,
    /// Whether deletion protection is enabled for this zone, as a hosted-zone
    /// read reports it.
    ///
    /// A zone is created WITHOUT deletion protection, and this API version
    /// (2013-04-01) carries no operation that turns it on, so every zone this
    /// store holds reports it off — exactly as Route 53 reports a zone created
    /// without it. It is held on the zone rather than answered as a constant by
    /// the read, so the day an operation can set it, the read already reports
    /// what was set.
    pub deletion_protection_enabled: bool,
    /// The bare id of the reusable delegation set this zone's name servers come
    /// from, when it was created in one (`CreateHostedZone$DelegationSetId`).
    ///
    /// The ASSOCIATION, and nothing else: the set's own caller reference and
    /// name servers are read off the set in
    /// [`ComAmazonawsRoute53Awsdnsv20130401State::delegation_sets`], so the two
    /// records cannot disagree about them. `None` for a zone Route 53 minted
    /// name servers of its own for.
    pub delegation_set_id: Option<String>,
    /// The zone's accelerated recovery setting, once `UpdateHostedZoneFeatures`
    /// has configured it — the state a hosted-zone read reports as `Features`.
    ///
    /// `None` for a zone nobody has configured the feature on, which is how
    /// every zone is created: `CreateHostedZone` carries no features input, so a
    /// new zone has no features configuration to report and accelerated
    /// recovery is OFF for it. Held ON the zone, like the signing flag and the
    /// tags beside it, so deleting the zone takes its features with it and no
    /// second record can disagree about them.
    pub accelerated_recovery: Option<AcceleratedRecovery>,
}

impl StoredZone {
    /// The modelled `HostedZone`, with a LIVE `ResourceRecordSetCount`.
    ///
    /// `Config` is ALWAYS present: `HostedZoneConfig$PrivateZone` is a boolean
    /// with `@default false`, so the zone's private flag always has a value to
    /// report, and Route 53 answers every hosted-zone read with the `Config`
    /// container carrying it — including for a public zone created with no
    /// `HostedZoneConfig` at all. `Comment`, which has no default, is reported
    /// only when the zone holds one; that is the member the `HostedZone$Config`
    /// documentation ("the Config and Comment elements don't appear in the
    /// response") is about.
    pub fn to_hosted_zone(&self) -> HostedZone {
        let config = Some(HostedZoneConfig {
            comment: self.comment.clone(),
            private_zone: self.private_zone,
        });
        HostedZone {
            id: format!("{HOSTED_ZONE_PREFIX}{}", self.id),
            name: self.name.clone(),
            caller_reference: self.caller_reference.clone(),
            config,
            resource_record_set_count: Some(self.records.len() as i64),
            linked_service: None,
            // Read off the zone, so what the last accepted features update left
            // is what every hosted-zone read reports.
            features: Some(self.to_hosted_zone_features()),
        }
    }

    /// The `Features` a hosted-zone read reports for this zone.
    ///
    /// The container itself is ALWAYS reported — Route 53 projects the
    /// `Features` structure on every hosted zone it answers with — so a client
    /// deserialising `HostedZone` into a strict shape always finds the member,
    /// and "no feature configured" is distinguishable from "not reported". Its
    /// MEMBERS are what the zone's state decides: `AcceleratedRecoveryStatus`
    /// has no default, so it is reported only once `UpdateHostedZoneFeatures`
    /// has configured the zone and the container is otherwise empty, and
    /// `FailureReasons` stays absent because no features change this store
    /// accepts fails.
    pub fn to_hosted_zone_features(&self) -> HostedZoneFeatures {
        HostedZoneFeatures {
            accelerated_recovery_status: self
                .accelerated_recovery
                .as_ref()
                .map(|feature| feature.status().to_string()),
            failure_reasons: None,
        }
    }

    /// Whether accelerated recovery is the setting the zone holds or is moving
    /// to: `true` from an accepted enable until a disable is accepted. A zone
    /// whose features were never configured has it off.
    pub fn accelerated_recovery_enabled(&self) -> bool {
        self.accelerated_recovery
            .as_ref()
            .is_some_and(|feature| feature.enabled)
    }

    /// The zone's own name servers as a `DelegationSet`.
    ///
    /// `Id` and `CallerReference` are absent: they belong to a REUSABLE
    /// delegation set, so a zone created in one is reported through
    /// [`ComAmazonawsRoute53Awsdnsv20130401State::zone_delegation_set`], which
    /// reads the set the zone names.
    pub fn to_delegation_set(&self) -> DelegationSet {
        DelegationSet {
            id: None,
            caller_reference: None,
            name_servers: self.name_servers.clone(),
        }
    }

    /// This zone's tag set as `ResourceTagSet$Tags` carries it; see
    /// [`tags_to_list`].
    pub fn to_tag_list(&self) -> Vec<Tag> {
        tags_to_list(&self.tags)
    }

    /// The `ServeSignature` a DNSSEC read reports for this zone: `SIGNING`
    /// while signing is enabled for it, `NOT_SIGNING` while it is not.
    ///
    /// Derived from the zone's own signing state, so enabling or disabling
    /// signing moves what the read reports by itself.
    pub fn serve_signature(&self) -> &'static str {
        if self.dnssec_signing_enabled {
            SERVE_SIGNATURE_SIGNING
        } else {
            SERVE_SIGNATURE_NOT_SIGNING
        }
    }

    /// This zone's key-signing keys as a DNSSEC read's `KeySigningKeys` carries
    /// them: one entry per KSK the zone holds, in `Name` order.
    pub fn to_key_signing_keys(&self) -> Vec<KeySigningKey> {
        self.key_signing_keys.values().cloned().collect()
    }

    /// The per-zone quota for one `HostedZoneLimitType` and how much of it this
    /// zone currently holds, as `(limit value, current count)`. `None` for a
    /// value outside `HostedZoneLimitType`.
    ///
    /// The count is COUNTED off the zone on every call rather than tracked
    /// beside it, for the same reason
    /// [`ComAmazonawsRoute53Awsdnsv20130401State::account_limit_usage`] counts:
    /// adding or removing a record set or a VPC association moves the count by
    /// itself, so no reporting operation has to be told about it and none can
    /// disagree with what a read of the zone reports. The quota is the same
    /// constant the mutating path refuses at, so a count that has reached the
    /// reported limit is exactly the point at which the next create is refused.
    pub fn limit_usage(&self, limit_type: &str) -> Option<(i64, i64)> {
        let (limit, count) = match limit_type {
            HOSTED_ZONE_LIMIT_MAX_RRSETS => (MAX_RECORD_SETS_PER_ZONE, self.records.len()),
            HOSTED_ZONE_LIMIT_MAX_VPCS_ASSOCIATED => (MAX_VPCS_PER_HOSTED_ZONE, self.vpcs.len()),
            _ => return None,
        };
        Some((count_as_i64(limit), count_as_i64(count)))
    }

    /// Whether this zone holds a key-signing key Route 53 could sign with: one
    /// in `ACTIVE` status ("The KSK is being used for signing").
    pub fn has_active_key_signing_key(&self) -> bool {
        self.key_signing_keys
            .values()
            .any(|ksk| ksk.status.as_deref() == Some(SIGNING_KEY_STATUS_ACTIVE))
    }

    /// Whether one of this zone's key-signing keys is in `INTERNAL_FAILURE`,
    /// the status that has to be corrected "before you can continue to work
    /// with DNSSEC signing" (`KeySigningKey$Status`).
    pub fn has_key_signing_key_in_internal_failure(&self) -> bool {
        self.key_signing_keys
            .values()
            .any(|ksk| ksk.status.as_deref() == Some(SIGNING_KEY_STATUS_INTERNAL_FAILURE))
    }

    /// Whether this zone holds any DNSSEC resource at all: a key-signing key,
    /// or signing enabled over one.
    ///
    /// `DNSSECNotFound`'s own documentation — "The hosted zone doesn't have any
    /// DNSSEC resources" — describes exactly the zone this answers `false` for.
    pub fn holds_dnssec_resources(&self) -> bool {
        self.dnssec_signing_enabled || !self.key_signing_keys.is_empty()
    }

    /// Whether the zone still holds a record other than the default SOA and NS
    /// records at its apex.
    ///
    /// `DeleteHostedZone`'s documentation: "You can delete a hosted zone only if
    /// it contains only the default SOA and NS records."
    pub fn holds_user_records(&self) -> bool {
        let apex = dns_sort_key(&self.name);
        self.records.keys().any(|key| {
            key.name_sort_key != apex
                || key.set_identifier.is_some()
                || !matches!(key.rr_type.as_str(), "SOA" | "NS")
        })
    }

    /// The record sets that answer for one name and type: the single simple
    /// record set there, or every member of the routing group that shares that
    /// name and type, in `SetIdentifier` order.
    ///
    /// A `BTreeMap` keyed by [`RecordKey`] holds them as a CONTIGUOUS range —
    /// the key order is name, then type, then set identifier, and `None` sorts
    /// before every `Some` — so the walk is bounded by the group rather than by
    /// the zone. Every spelling of a name gives one [`DnsNameKey`], so the
    /// lookup is insensitive to case, to the trailing dot and to a presentation
    /// escape.
    pub fn records_at(&self, name: &str, rr_type: &str) -> Vec<&ResourceRecordSet> {
        let group = RecordKey::of(name, rr_type, None);
        self.records
            .range(group.clone()..)
            .take_while(|(key, _)| {
                key.name_sort_key == group.name_sort_key && key.rr_type == group.rr_type
            })
            .map(|(_, record)| record)
            .collect()
    }

    /// Whether this zone holds a record set at `name`, whatever its type.
    ///
    /// The DNS answer for a name the zone holds no record of the asked-for type
    /// at depends on this: a name the zone knows exists and a name it does not
    /// hold at all are two different answers.
    pub fn holds_record_name(&self, name: &str) -> bool {
        let from = RecordKey {
            name_sort_key: dns_sort_key(name),
            // The empty type sorts before every `RRType`, so the range opens at
            // the first record set carrying this name.
            rr_type: String::new(),
            set_identifier: None,
        };
        self.records
            .range(from.clone()..)
            .next()
            .is_some_and(|(key, _)| key.name_sort_key == from.name_sort_key)
    }

    /// Where this zone's association list holds the VPC named by `vpc_id`, if it
    /// holds it at all.
    ///
    /// An Amazon VPC id identifies the VPC on its own, so it alone is the
    /// identity of an association; the region is carried ALONGSIDE it (it is
    /// what a reader needs to find the VPC again), never part of that identity.
    /// A zone therefore holds at most one association per VPC id, which is what
    /// makes associating a VPC a second time a no-op rather than a duplicate.
    pub fn vpc_position(&self, vpc_id: &str) -> Option<usize> {
        vpc_position_in(&self.vpcs, vpc_id)
    }

    /// Where this zone's authorization list holds the VPC named by `vpc_id`, if
    /// it holds it at all.
    ///
    /// Keyed by VPC id for the same reason [`StoredZone::vpc_position`] is: the
    /// id identifies the VPC on its own, so a zone holds at most one
    /// authorization per VPC and authorizing the same VPC again is a no-op
    /// rather than a duplicate.
    pub fn vpc_authorization_position(&self, vpc_id: &str) -> Option<usize> {
        vpc_position_in(&self.vpc_authorizations, vpc_id)
    }
}

/// Where `vpcs` holds the VPC named by `vpc_id`, if it holds it at all.
///
/// The one lookup both of a zone's VPC lists use, so the association list and
/// the authorization list cannot drift apart on what identifies a VPC.
pub fn vpc_position_in(vpcs: &[VPC], vpc_id: &str) -> Option<usize> {
    vpcs.iter()
        .position(|vpc| vpc.vpc_id.as_deref() == Some(vpc_id))
}

/// A health check of the account's, as `GetHealthCheck` reports it.
///
/// The configuration is held as the modelled `HealthCheckConfig`, with the
/// defaults the service fills in already applied (see
/// [`health_check_config_with_defaults`]), so the create that persisted it and
/// every later read report the same configuration.
///
/// Beside the configuration sits the periodic ASSESSMENT of the thing it
/// describes ([`StoredHealthCheck::evaluation`]): a health check is not only a
/// record, it is evaluated, and that assessment is what
/// [`health_check_status`] publishes as the health check's CloudWatch series.
#[derive(Debug, Clone)]
pub struct StoredHealthCheck {
    /// The health check id, which is also this record's key in
    /// [`ComAmazonawsRoute53Awsdnsv20130401State::health_checks`].
    pub id: String,
    /// The `CallerReference` the health check was created with.
    pub caller_reference: String,
    /// The health check's configuration, as the service holds it.
    pub config: HealthCheckConfig,
    /// The `HealthCheckVersion`, starting at [`FIRST_HEALTH_CHECK_VERSION`].
    pub version: i64,
    /// When the health check was created, in milliseconds since the Unix epoch:
    /// the instant Route 53's checkers started checking its endpoint, and so the
    /// base of the probe cadence [`StoredHealthCheck::last_checked_at_millis`]
    /// reports a `CheckedTime` from.
    pub created_at_millis: i64,
    /// The tags on this health check, keyed by tag key so one key carries one
    /// value (`ChangeTagsForResource`).
    pub tags: BTreeMap<String, String>,
    /// This health check's periodic assessment, or `None` for a type that has no
    /// probe schedule at all; see
    /// [`health_check_status::HealthCheckEvaluation`].
    pub evaluation: Option<health_check_status::HealthCheckEvaluation>,
}

impl StoredHealthCheck {
    /// The modelled `HealthCheck` for this record, reporting
    /// `monitored_alarm` as the configuration of the CloudWatch alarm this check
    /// is monitoring ([`monitored_alarm::configuration`] reads it, since that
    /// alarm lives in CloudWatch's store rather than this one).
    ///
    /// The ONE projection every health-check response is built from, so a create
    /// and a later read cannot report one health check differently.
    pub fn to_health_check(
        &self,
        monitored_alarm: Option<CloudWatchAlarmConfiguration>,
    ) -> HealthCheck {
        HealthCheck {
            id: self.id.clone(),
            caller_reference: self.caller_reference.clone(),
            // `LinkedService` is "If the health check was created by another
            // service, the service that created the health check": a health
            // check this API created for the account was created by no other
            // service, so the member is absent.
            linked_service: None,
            health_check_config: self.config.clone(),
            health_check_version: self.version,
            // The alarm's own configuration belongs to CloudWatch, which is
            // where Route 53 reads it from; this store holds the alarm's
            // identity (`HealthCheckConfig$AlarmIdentifier`), not its settings.
            // So the caller reads it out of CloudWatch's store and hands it in
            // ([`monitored_alarm::configuration`]), with this service's own
            // guard already released.
            cloud_watch_alarm_configuration: monitored_alarm,
        }
    }

    /// This health check's tags as the modelled `Tag` list.
    pub fn to_tag_list(&self) -> Vec<Tag> {
        tags_to_list(&self.tags)
    }

    /// The status Route 53 reports for this health check right now, or `None`
    /// when nothing assesses it (a type with no probe schedule).
    ///
    /// This is the AGGREGATE assessment — the debounced one
    /// [`health_check_status`] publishes as the check's CloudWatch series — and
    /// not the single-probe observation one checker reports
    /// ([`StoredHealthCheck::reported_status`]), which is a different plane of
    /// the API.
    ///
    /// The assessment, then the two members that override it: `Disabled` first
    /// ("After you disable a health check, Route 53 considers the status of the
    /// health check to always be healthy"), `Inverted` after it ("whether you
    /// want Amazon Route 53 to invert the status of a health check") — the order
    /// the `Disabled` documentation implies when it tells a caller to "change the
    /// value of Inverted" to stop traffic reaching a disabled check's resource.
    pub fn reported_healthy(&self) -> Option<bool> {
        let assessed = self.evaluation.as_ref()?.is_healthy();
        let base = self.config.disabled == Some(true) || assessed;
        Some(if self.config.inverted == Some(true) {
            !base
        } else {
            base
        })
    }

    /// Whether Route 53's health checkers are checking this health check's
    /// endpoint at all.
    ///
    /// Two conditions, both from the model. The type: only the types that probe
    /// an endpoint ([`ENDPOINT_HEALTH_CHECK_TYPES`]) have an endpoint for a
    /// checker to report about — the others read a CloudWatch alarm, combine
    /// child health checks or follow a routing control, and
    /// `HealthCheckObservations` is "one HealthCheckObservation element for each
    /// Amazon Route 53 health checker that is reporting a status about the
    /// health check endpoint". And `Disabled`: "Route 53 stops submitting
    /// requests to your application, server, or other resource", so a disabled
    /// check has no checker reporting on it either.
    pub fn endpoint_is_being_checked(&self) -> bool {
        ENDPOINT_HEALTH_CHECK_TYPES.contains(&self.config.r#type.as_str())
            && !self.config.disabled.unwrap_or(false)
    }

    /// The health-checking Regions this health check is checked from, in the
    /// modelled `HealthCheckRegion` order.
    ///
    /// `HealthCheckConfig$Regions` is "one Region element for each region from
    /// which you want Amazon Route 53 health checkers to check the specified
    /// endpoint", and "if you don't specify any regions, Route 53 health
    /// checkers automatically performs checks from all of the regions that are
    /// listed under Valid Values" — the `HealthCheckRegion` values. Ordering by
    /// that value list rather than by the request keeps two reads of one health
    /// check in the same order, and drops a Region the enum does not carry.
    pub fn checker_regions(&self) -> Vec<&'static str> {
        let requested = self.config.regions.as_deref().unwrap_or(&[]);
        HEALTH_CHECK_REGION_VALUES
            .iter()
            .copied()
            .filter(|region| {
                requested.is_empty() || requested.iter().any(|asked| asked == region)
            })
            .collect()
    }

    /// The instant of the most recent probe of this health check's endpoint, in
    /// milliseconds since the Unix epoch.
    ///
    /// The checkers probe the endpoint every `RequestInterval` seconds from the
    /// moment the health check was created, so the probe a read reports is the
    /// last one that interval has come round for — DERIVED from the clock, so
    /// reading the status neither starts a probe nor moves one on, and two reads
    /// inside one interval report the same `CheckedTime`.
    pub fn last_checked_at_millis(&self, now_millis: i64) -> i64 {
        let seconds = self
            .config
            .request_interval
            .unwrap_or(DEFAULT_REQUEST_INTERVAL)
            .max(1);
        let interval = i64::from(seconds) * MILLIS_PER_SECOND;
        let elapsed = now_millis.saturating_sub(self.created_at_millis).max(0);
        self.created_at_millis + (elapsed / interval) * interval
    }

    /// What one health checker reports about this health check's endpoint.
    ///
    /// The description names the criterion the check's `Type` sets — a TCP
    /// connection for a `TCP` check, a response for the types that send a
    /// request — and reports it as met. The emulator reaches a caller's endpoint
    /// over no network, and its own world holds nothing that drops a connection,
    /// answers a non-success status or withholds the body a string-match check
    /// searches, so a checker of an endpoint this service is checking has no
    /// failure to report. What the stored configuration decides is WHICH
    /// checkers report ([`StoredHealthCheck::checker_regions`]), WHETHER any do
    /// ([`StoredHealthCheck::endpoint_is_being_checked`]) and WHEN they last did
    /// ([`StoredHealthCheck::last_checked_at_millis`]).
    pub fn reported_status(&self) -> &'static str {
        if self.config.r#type == HEALTH_CHECK_TYPE_TCP {
            return STATUS_TCP_CONNECTION_ESTABLISHED;
        }
        STATUS_HTTP_OK
    }

    /// The modelled `HealthCheckObservation` list `GetHealthCheckStatus`
    /// reports: one observation per health checker checking this endpoint, or
    /// none when nothing is checking it (see
    /// [`StoredHealthCheck::endpoint_is_being_checked`]).
    pub fn to_health_check_observations(&self, now_millis: i64) -> Vec<HealthCheckObservation> {
        if !self.endpoint_is_being_checked() {
            return Vec::new();
        }
        let report = StatusReport {
            status: Some(self.reported_status().to_string()),
            checked_time: Some(::aws_smithy_types::DateTime::from_millis(
                self.last_checked_at_millis(now_millis),
            )),
        };
        self.checker_regions()
            .into_iter()
            .map(|region| HealthCheckObservation {
                region: Some(region.to_string()),
                ip_address: checker_address(region),
                status_report: Some(report.clone()),
            })
            .collect()
    }

    /// The modelled `HealthCheckObservation` list
    /// `GetHealthCheckLastFailureReason` reports: "one Observation element for
    /// each Amazon Route 53 health checker that is reporting a last failure
    /// reason".
    ///
    /// Read out of the SAME observations `GetHealthCheckStatus` reports
    /// ([`StoredHealthCheck::to_health_check_observations`]), kept to the
    /// checkers whose latest observation is a failure
    /// ([`STATUS_FAILURE_PREFIX`]) — so the two readers of a health check's
    /// status cannot disagree about what one checker observed, and a checker with
    /// nothing to report about a failure is absent rather than reported with an
    /// empty reason. A health check none of whose checkers has observed a failure
    /// therefore has no observation to report at all, which is also what the
    /// operation answers for a check nothing is checking.
    pub fn to_last_failure_observations(&self, now_millis: i64) -> Vec<HealthCheckObservation> {
        self.to_health_check_observations(now_millis)
            .into_iter()
            .filter(|observation| {
                observation
                    .status_report
                    .as_ref()
                    .and_then(|report| report.status.as_deref())
                    .is_some_and(|status| status.starts_with(STATUS_FAILURE_PREFIX))
            })
            .collect()
    }
}

/// Milliseconds in a second, for the `RequestInterval` (seconds) a probe cadence
/// is computed from.
const MILLIS_PER_SECOND: i64 = 1_000;

/// What a health checker reports for an endpoint that answered the request an
/// `HTTP`, `HTTPS`, `HTTP_STR_MATCH` or `HTTPS_STR_MATCH` check sends it.
///
/// `StatusReport$Status` is "a description of the status of the health check
/// endpoint as reported by one of the Amazon Route 53 health checkers" — free
/// text the model constrains in no way — and Route 53 writes such a description
/// as a sentence that opens with `Success: ` or `Failure: ` and names what the
/// checker observed.
pub const STATUS_HTTP_OK: &str = "Success: HTTP Status Code 200, OK";

/// What a health checker reports for an endpoint that accepted the connection a
/// `TCP` check opens.
pub const STATUS_TCP_CONNECTION_ESTABLISHED: &str = "Success: TCP connection established";

/// What a checker's `StatusReport$Status` opens with when the probe it describes
/// FAILED, as opposed to the `Success: ` the descriptions above open with.
///
/// The one place that distinction is drawn, so the reader of a check's last
/// failure reason ([`StoredHealthCheck::to_last_failure_observations`]) and the
/// reader of its current status describe one probe the same way.
pub const STATUS_FAILURE_PREFIX: &str = "Failure: ";

/// The address the health checker in `region` reports from, when `region` is one
/// the service checks from.
///
/// `HealthCheckObservation$IPAddress` is "the IP address of the Amazon Route 53
/// health checker that provided the failure reason in StatusReport", and the
/// published table of health-checking blocks ([`CHECKER_IP_RANGES`]) says which
/// blocks the checks come from but not which block belongs to which Region. So
/// the pairing is this emulator's own: the Regions in the modelled
/// `HealthCheckRegion` order each take one block in the order
/// [`checker_ip_ranges`] reports them, and the checker's address is the first
/// address inside that block. It is a function of those two tables alone, so
/// every read of one health check reports the same checker address, and every
/// address it reports is inside a block `GetCheckerIpRanges` publishes.
pub fn checker_address(region: &str) -> Option<String> {
    let position = HEALTH_CHECK_REGION_VALUES
        .iter()
        .position(|value| *value == region)?;
    let blocks = checker_ip_ranges();
    if blocks.is_empty() {
        return None;
    }
    first_address_in(&blocks[position % blocks.len()])
}

/// The first address inside an `a.b.c.d/nn` block: the one after its network
/// address, which is the first an interface in the block can carry — except in a
/// block that has no host bits to spare, where the single address the block
/// names IS that address.
fn first_address_in(cidr: &str) -> Option<String> {
    let (address, prefix) = cidr.split_once('/')?;
    let network = address.parse::<Ipv4Addr>().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    // A /31 holds two addresses and a /32 one, so stepping past the network
    // address would leave the block the caller allow-listed.
    if prefix >= 31 {
        return Some(network.to_string());
    }
    let first = u32::from(network).checked_add(1)?;
    Some(Ipv4Addr::from(first).to_string())
}

/// `config` with the values the service fills in for a member the caller left
/// out, so what the store holds is what the service would report.
///
/// A `HealthCheckConfig` member the service decides the behaviour of is
/// MATERIALISED here, with the value that behaviour amounts to, and every member
/// a check's `Type` has no behaviour for is left absent:
///
/// * `RequestInterval` and `FailureThreshold` carry the intervals their own
///   documentation names ("If you don't specify a value for RequestInterval, the
///   default value is 30 seconds", "if you don't specify a value for
///   FailureThreshold, the default value is three health checks"), and both are
///   "not supported when you specify a value for Type of RECOVERY_CONTROL" —
///   so they belong to the types that probe an endpoint
///   ([`ENDPOINT_HEALTH_CHECK_TYPES`]).
/// * `MeasureLatency` ("whether you want Amazon Route 53 to measure the latency
///   between health checkers ... and your endpoint") describes a probe of an
///   endpoint, is likewise "not supported ... for Type of RECOVERY_CONTROL", and
///   a check that measures nothing by itself is one that does not measure
///   latency.
/// * `EnableSNI` ("whether you want Amazon Route 53 to send the value of
///   FullyQualifiedDomainName to the endpoint in the client_hello message during
///   TLS negotiation") belongs to the same probing types, and the behaviour it
///   describes is what a probe that negotiates TLS does unless it is turned off
///   ([`TLS_HEALTH_CHECK_TYPES`]); a probe that negotiates none sends no
///   `client_hello` at all.
/// * `Inverted` ("whether you want Amazon Route 53 to invert the status of a
///   health check") and `Disabled` ("stops Route 53 from performing health
///   checks") are about the check's own status, which every type has, and a
///   check neither inverted nor stopped is one whose status is reported as
///   assessed.
/// * `ChildHealthChecks` is "(CALCULATED Health Checks Only) ... one
///   ChildHealthCheck element for each health check that you want to associate
///   with a CALCULATED health check", so the check whose health is a function of
///   that list carries the list — empty when it names none, which is a different
///   answer from a type that has no child list at all.
pub fn health_check_config_with_defaults(config: &HealthCheckConfig) -> HealthCheckConfig {
    let mut filled = config.clone();
    let kind = filled.r#type.clone();
    if ENDPOINT_HEALTH_CHECK_TYPES.contains(&kind.as_str()) {
        filled.request_interval = Some(filled.request_interval.unwrap_or(DEFAULT_REQUEST_INTERVAL));
        filled.failure_threshold =
            Some(filled.failure_threshold.unwrap_or(DEFAULT_FAILURE_THRESHOLD));
        filled.measure_latency = Some(filled.measure_latency.unwrap_or(DEFAULT_MEASURE_LATENCY));
        filled.enable_sni = Some(
            filled
                .enable_sni
                .unwrap_or_else(|| TLS_HEALTH_CHECK_TYPES.contains(&kind.as_str())),
        );
    }
    filled.inverted = Some(filled.inverted.unwrap_or(DEFAULT_INVERTED));
    filled.disabled = Some(filled.disabled.unwrap_or(DEFAULT_DISABLED));
    if kind == HEALTH_CHECK_TYPE_CALCULATED && filled.child_health_checks.is_none() {
        filled.child_health_checks = Some(Vec::new());
    }
    filled
}

/// Whether a string member of a `HealthCheckConfig` carries a value at all.
///
/// Every one of those members is modelled with a minimum length of 0, so an
/// empty (or whitespace-only) value reaches a handler; it names no endpoint, no
/// path and no string to search for, so it counts as absent wherever a rule asks
/// whether the member was given. The ONE predicate every health-check rule asks
/// that question through, so the create that persists a configuration and the
/// update that changes one cannot disagree about what "given" means.
pub fn health_check_member_given(member: Option<&str>) -> bool {
    member.map(str::trim).is_some_and(|value| !value.is_empty())
}

/// Why `config` could not be used, or `None` when it holds together.
///
/// `HealthCheckConfig`'s members are conditional on its `Type`: the model
/// constrains each member on its own, so the rules that relate them — an
/// endpoint type needs an endpoint to check, a string-match type needs the
/// string to search for, an alarm-backed type needs the alarm, a
/// routing-control type needs the routing control, and the two types that check
/// no endpoint take no port — are the service's to enforce, under the
/// `InvalidInput` its model declares.
///
/// Shared by every operation that persists a configuration, so a configuration
/// an update leaves behind holds together exactly as one a create persisted
/// does.
pub fn health_check_config_problem(config: &HealthCheckConfig) -> Option<String> {
    let given = |member: &Option<String>| health_check_member_given(member.as_deref());
    let kind = config.r#type.as_str();
    // The children a CALCULATED check adds up are read on every assessment of it,
    // so the list's published maximum is held to here, whatever a request sends.
    let children = config.child_health_checks.as_deref().unwrap_or_default().len();
    if children > MAX_CHILD_HEALTH_CHECKS {
        return Some(format!(
            "HealthCheckConfig.ChildHealthChecks can name at most \
             {MAX_CHILD_HEALTH_CHECKS} child health checks; got {children}"
        ));
    }
    if ENDPOINT_HEALTH_CHECK_TYPES.contains(&kind) {
        // `IPAddress`: "If you don't specify a value for IPAddress, Route 53
        // sends a DNS request to resolve the domain name that you specify in
        // FullyQualifiedDomainName" — so one of the two has to be there for
        // there to be an endpoint at all.
        if !given(&config.ip_address) && !given(&config.fully_qualified_domain_name) {
            return Some(format!(
                "a {kind} health check must specify HealthCheckConfig.IPAddress or \
                 HealthCheckConfig.FullyQualifiedDomainName"
            ));
        }
        // `SearchString`: "If the value of Type is HTTP_STR_MATCH or
        // HTTPS_STR_MATCH, the string that you want Amazon Route 53 to search
        // for in the response body".
        if STRING_MATCH_HEALTH_CHECK_TYPES.contains(&kind) && !given(&config.search_string) {
            return Some(format!(
                "a {kind} health check must specify HealthCheckConfig.SearchString"
            ));
        }
        return None;
    }
    // "Don't specify a value for Port when you specify a value for Type of
    // CLOUDWATCH_METRIC or CALCULATED."
    if matches!(
        kind,
        HEALTH_CHECK_TYPE_CLOUDWATCH_METRIC | HEALTH_CHECK_TYPE_CALCULATED
    ) && config.port.is_some()
    {
        return Some(format!(
            "HealthCheckConfig.Port cannot be specified for a {kind} health check"
        ));
    }
    match kind {
        // `AlarmIdentifier` "identifies the CloudWatch alarm that you want
        // Amazon Route 53 health checkers to use to determine whether the
        // specified health check is healthy", which is the whole of a
        // CLOUDWATCH_METRIC check's input.
        HEALTH_CHECK_TYPE_CLOUDWATCH_METRIC if config.alarm_identifier.is_none() => Some(format!(
            "a {kind} health check must specify HealthCheckConfig.AlarmIdentifier"
        )),
        // "The Amazon Resource Name (ARN) for the Route 53 Application Recovery
        // Controller routing control", which is what a RECOVERY_CONTROL check
        // follows.
        HEALTH_CHECK_TYPE_RECOVERY_CONTROL if !given(&config.routing_control_arn) => {
            Some(format!(
                "a {kind} health check must specify HealthCheckConfig.RoutingControlArn"
            ))
        }
        _ => None,
    }
}

/// The refusal text a read of a CALCULATED health check's checker observations
/// is answered with (`InvalidInput`, HTTP 400).
///
/// A CALCULATED health check has no endpoint and no checkers: "for health checks
/// that monitor the status of other health checks, Route 53 adds up the number
/// of health checks that Route 53 health checkers consider to be healthy and
/// compares that number with the value of HealthThreshold"
/// (`HealthCheckConfig$Type`). Its health is therefore a function of its
/// children, published as a CloudWatch metric, and not an observation any
/// checker made — so the operations that report per-checker observations refuse
/// it rather than answering with a list.
///
/// A CONSTANT: the sentence carries no request or state value at all, and it
/// names the status reader on BOTH of those paths — one refusal, one wording,
/// whichever of the two readers was called.
pub const CALCULATED_HEALTH_CHECK_OBSERVATIONS_MESSAGE: &str =
    "Invalid parameter : To get the status of a calculated health check, use either the Route 53 \
     console or the CloudWatch console. The GetHealthCheckStatus action can't return the health \
     of calculated health checks.";

/// Whether `config` is a health check whose health is computed from other health
/// checks rather than observed by Route 53's checkers.
///
/// The ONE predicate the two observation readers gate on, so they cannot
/// disagree about which health checks have checker observations to report.
pub fn health_check_is_calculated(config: &HealthCheckConfig) -> bool {
    config.r#type == HEALTH_CHECK_TYPE_CALCULATED
}

/// One version of a traffic policy: the document that version holds, and the
/// values read off it.
///
/// A version's document is immutable once created — only its comment is
/// editable (`UpdateTrafficPolicyComment`) — so the `RRType` the document names
/// is read off it once, when the version is created, rather than on every read.
#[derive(Debug, Clone)]
pub struct StoredTrafficPolicyVersion {
    /// The `RRType` the document's `RecordType` names, as
    /// [`traffic_policy_record_type`] read it off the document.
    pub record_type: String,
    /// The traffic policy document, exactly as the caller sent it.
    pub document: String,
    /// This version's comment, when it was created with one.
    pub comment: Option<String>,
    /// Whether a delete has flagged this version deleted.
    ///
    /// `DeleteTrafficPolicy`'s own documentation: "When you delete a traffic
    /// policy, Route 53 sets a flag on the policy to indicate that it has been
    /// deleted. However, Route 53 never fully deletes the traffic policy …
    /// Deleted traffic policies aren't listed if you run ListTrafficPolicies …
    /// If you retain the ID of the policy, you can get information about the
    /// policy, including the traffic policy document, by running
    /// GetTrafficPolicy." So the delete is this FLAG rather than the removal of
    /// the record: a flagged version is no longer one of the account's traffic
    /// policy versions — nothing lists it, nothing new is built on it, and
    /// addressing that VERSION is the same 404 as a version that never existed —
    /// while `GetTrafficPolicy`, the one reader the documentation keeps, still
    /// reports the document it held. The version number stays taken either way
    /// ([`StoredTrafficPolicy::next_version`]).
    ///
    /// The flag is per VERSION and never unmakes the POLICY: the record keyed by
    /// `Id` is what "Route 53 never fully deletes" keeps, so the id stays
    /// resolvable for every operation addressed at it, with its version set then
    /// reported as a possibly-empty collection.
    pub deleted: bool,
}

/// A traffic policy and every version of it.
///
/// A traffic policy is addressed by `(Id, Version)` — `GetTrafficPolicy` takes
/// both — so the versions live ON the policy, keyed by version number: one
/// policy's id and name cannot then disagree between two of its versions, and
/// the highest LIVE key is its latest version.
#[derive(Debug, Clone)]
pub struct StoredTrafficPolicy {
    /// The policy id, which is also this record's key in
    /// [`ComAmazonawsRoute53Awsdnsv20130401State::traffic_policies`].
    pub id: String,
    /// The `Name` the policy was created with, shared by every version of it.
    pub name: String,
    /// This policy's place in the order the account's policies were created in,
    /// which is the order `ListTrafficPolicies` reports them in ("Policies are
    /// listed in the order that they were created in").
    ///
    /// A policy id is minted opaque, so the order of the ids is NOT the order of
    /// the creates: the position has to be recorded when the policy is created
    /// ([`ComAmazonawsRoute53Awsdnsv20130401State::next_traffic_policy_position`]).
    pub created_position: u64,
    /// This policy's versions, keyed (and therefore ordered) by version number.
    pub versions: BTreeMap<i32, StoredTrafficPolicyVersion>,
}

impl StoredTrafficPolicy {
    /// The modelled `TrafficPolicy` for one version of this policy, or `None`
    /// when the policy holds no such version.
    ///
    /// The ONE projection every traffic-policy response is built from, so a
    /// create and a later read cannot report one policy version differently.
    pub fn to_traffic_policy(&self, version: i32) -> Option<TrafficPolicy> {
        let stored = self.versions.get(&version)?;
        // Reported whether or not the version is flagged deleted: the retained
        // record IS what `GetTrafficPolicy` reports for a deleted version, and
        // every other reader selects the versions it reports through
        // [`Self::live_versions`] before projecting them.
        Some(TrafficPolicy {
            id: self.id.clone(),
            version,
            name: self.name.clone(),
            r#type: stored.record_type.clone(),
            document: stored.document.clone(),
            comment: stored.comment.clone(),
        })
    }

    /// The version number the policy's NEXT version carries: one past the
    /// highest it has ever reached, or [`FIRST_TRAFFIC_POLICY_VERSION`] for a
    /// policy holding none.
    ///
    /// Counted from the highest version rather than from how many versions the
    /// policy holds, so a version number is never handed out twice — a version
    /// that has been deleted does not free its number for the next create.
    pub fn next_version(&self) -> i32 {
        self.versions
            .keys()
            .next_back()
            .map_or(FIRST_TRAFFIC_POLICY_VERSION, |highest| highest + 1)
    }

    /// Every version of this policy a delete has NOT flagged, in numerical
    /// order by version number, as `(version number, version)`.
    ///
    /// The ONE place this service decides which versions of a policy still
    /// count, so a listing, a version create and a delete cannot disagree about
    /// it: a flagged version is retained only for `GetTrafficPolicy`
    /// ([`StoredTrafficPolicyVersion::deleted`]).
    pub fn live_versions(
        &self,
    ) -> impl DoubleEndedIterator<Item = (i32, &StoredTrafficPolicyVersion)> {
        self.versions
            .iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(&version, stored)| (version, stored))
    }

    /// The version `version` of this policy, if the policy holds it and a
    /// delete has not flagged it.
    pub fn live_version(&self, version: i32) -> Option<&StoredTrafficPolicyVersion> {
        self.versions
            .get(&version)
            .filter(|stored| !stored.deleted)
    }

    /// Whether every version this policy ever held is flagged deleted, which is
    /// what keeps the POLICY out of the account's listings and out of its quota:
    /// a policy with no live version is not one `ListTrafficPolicies` reports
    /// ("Deleted traffic policies aren't listed").
    ///
    /// It does NOT make the id unresolvable: the record itself survives, so an
    /// operation addressed at the id still finds the policy — this is only about
    /// which policies the account is reported as HOLDING.
    pub fn is_deleted(&self) -> bool {
        self.live_versions().next().is_none()
    }

    /// The highest version number this policy still holds — its LATEST version,
    /// the one a listing reports — or `None` for a policy holding no live
    /// version, which a listing does not report at all.
    pub fn latest_version(&self) -> Option<i32> {
        self.live_versions().next_back().map(|(version, _)| version)
    }

    /// How many versions this policy still holds, as the
    /// `TrafficPolicyVersion` the count shapes carry (`range 1..1000`, which is
    /// also [`MAX_TRAFFIC_POLICY_VERSION`], so the count cannot leave that
    /// range).
    pub fn version_count(&self) -> i32 {
        i32::try_from(self.live_versions().count()).unwrap_or(MAX_TRAFFIC_POLICY_VERSION)
    }
}

/// A traffic policy instance: the hosted zone, DNS name and TTL one version of
/// one traffic policy was applied to, and the instant its record sets are in
/// place.
///
/// The POLICY is not copied in — only its id, version and the `RRType` that
/// version's document names, which is the type the generated record sets carry
/// (`TrafficPolicyInstance$TrafficPolicyType`): the document itself stays in
/// [`ComAmazonawsRoute53Awsdnsv20130401State::traffic_policies`], so an instance
/// and the policy it was created from cannot disagree about it.
#[derive(Debug, Clone)]
pub struct StoredTrafficPolicyInstance {
    /// The instance id, which is also this record's key in
    /// [`ComAmazonawsRoute53Awsdnsv20130401State::traffic_policy_instances`].
    pub id: String,
    /// The BARE id of the hosted zone the record sets were created in.
    pub hosted_zone_id: String,
    /// The DNS name the record sets answer for, in the canonical form
    /// [`canonical_dns_name`] gives — the same form the record sets themselves
    /// are stored under.
    pub name: String,
    /// The `TTL` the generated record sets are cached for.
    pub ttl: i64,
    /// The id of the traffic policy the record sets were generated from.
    pub traffic_policy_id: String,
    /// The version of that policy the record sets were generated from.
    pub traffic_policy_version: i32,
    /// The `RRType` that policy version's document names, which is the type of
    /// every record set generated for this instance.
    pub traffic_policy_type: String,
    /// The instant the generated record sets are in place; see
    /// [`TRAFFIC_POLICY_INSTANCE_PROPAGATION`].
    pub applied_at: Instant,
}

impl StoredTrafficPolicyInstance {
    /// The modelled `TrafficPolicyInstance` for this record.
    ///
    /// The ONE projection every traffic-policy-instance response is built from,
    /// so a create and a later read cannot report one instance differently.
    pub fn to_traffic_policy_instance(&self) -> TrafficPolicyInstance {
        TrafficPolicyInstance {
            id: self.id.clone(),
            hosted_zone_id: self.hosted_zone_id.clone(),
            name: self.name.clone(),
            ttl: self.ttl,
            state: self.state().to_string(),
            // "If `State` is `Failed`, an explanation of the reason for the
            // failure. If `State` is another value, `Message` is empty"
            // (`TrafficPolicyInstance$Message`). No instance this store holds
            // failed — a request whose record sets cannot be created is refused
            // before the instance exists — so the explanation is empty.
            message: String::new(),
            traffic_policy_id: self.traffic_policy_id.clone(),
            traffic_policy_version: self.traffic_policy_version,
            traffic_policy_type: self.traffic_policy_type.clone(),
        }
    }

    /// The `State` a read reports: `Creating` until the record sets are in
    /// place, `Applied` from then on.
    ///
    /// Derived from the clock, so the transition the create owes comes due by
    /// itself: no read has to be told about it, and reporting the state leaves
    /// the store exactly as it was.
    pub fn state(&self) -> &'static str {
        if Instant::now() >= self.applied_at {
            TRAFFIC_POLICY_INSTANCE_APPLIED
        } else {
            TRAFFIC_POLICY_INSTANCE_CREATING
        }
    }
}

/// The place one traffic policy instance takes in a listing of them: the
/// hosted zone its record sets live in, the IDENTITY of the DNS name they
/// answer for, and their record type — the three members a listing's markers
/// carry.
///
/// The key of a STORED instance; a listing positions a marker by comparing the
/// marker's own members against it, which is why the zone id and the type are
/// borrowed rather than copied into it.
pub fn traffic_policy_instance_order_key(
    instance: &StoredTrafficPolicyInstance,
) -> (&str, DnsNameKey, &str) {
    (
        instance.hosted_zone_id.as_str(),
        dns_sort_key(&instance.name),
        instance.traffic_policy_type.as_str(),
    )
}

/// A CIDR collection: the named group of CIDR blocks an IP-based record set
/// routes a client's address through.
///
/// The record carries the collection's IDENTITY — the id Route 53 minted for it,
/// the name and caller reference the create carried, and the version counter a
/// later change moves — plus the BLOCKS it holds, which
/// [`crate::ops::change_cidr_collection`] puts there one location at a time.
#[derive(Debug, Clone)]
pub struct StoredCidrCollection {
    /// The collection id, which is also this record's key in
    /// [`ComAmazonawsRoute53Awsdnsv20130401State::cidr_collections`].
    pub id: String,
    /// The `Name` the collection was created with, unique across the account's
    /// collections ([`ComAmazonawsRoute53Awsdnsv20130401State::cidr_collection_with_name`]).
    pub name: String,
    /// The `CallerReference` the create carried, which is what tells a RETRY of
    /// that create apart from a second create over the same name.
    pub caller_reference: String,
    /// This collection's version counter, [`FIRST_CIDR_COLLECTION_VERSION`] from
    /// the create on.
    pub version: i64,
    /// The CIDR blocks the collection holds, keyed by the LOCATION they are
    /// associated with: "Name of the location that is associated with the CIDR
    /// collection" (`CidrCollectionChange$LocationName`).
    ///
    /// A `BTreeMap` of `BTreeSet`s, so `ListCidrBlocks` pages over a stable total
    /// order and a block put twice is held once — a collection associates a
    /// location with a SET of blocks.
    pub locations: BTreeMap<String, BTreeSet<String>>,
}

impl StoredCidrCollection {
    /// The modelled `CidrCollection` for this record.
    ///
    /// The ONE projection every CIDR-collection response is built from, so a
    /// create and a later read cannot report one collection differently.
    pub fn to_cidr_collection(&self) -> CidrCollection {
        CidrCollection {
            arn: Some(cidr_collection_arn(&self.id)),
            id: Some(self.id.clone()),
            name: Some(self.name.clone()),
            version: Some(self.version),
        }
    }

    /// Whether the collection holds no CIDR block at all.
    ///
    /// What `DeleteCidrCollection` is held to: `CidrCollectionInUseException` is
    /// "this CIDR collection is in use, and isn't empty", so a collection that
    /// still holds a block is not one a delete takes away.
    pub fn is_empty(&self) -> bool {
        self.locations.values().all(BTreeSet::is_empty)
    }

    /// Every block the collection holds, as the `CidrBlockSummary` rows
    /// `ListCidrBlocks` reports — each block beside the location it belongs to,
    /// in location order and then block order.
    pub fn to_cidr_block_summaries(&self) -> Vec<CidrBlockSummary> {
        self.locations
            .iter()
            .flat_map(|(location, blocks)| {
                blocks.iter().map(move |block| CidrBlockSummary {
                    cidr_block: Some(block.clone()),
                    location_name: Some(location.clone()),
                })
            })
            .collect()
    }
}

/// Per-service state for com-amazonaws-route53-awsdnsv20130401. A handler reaches it through [`service_state`].
#[derive(Debug)]
pub struct ComAmazonawsRoute53Awsdnsv20130401State {
    /// Every hosted zone, keyed by its bare id. A `BTreeMap` so
    /// `ListHostedZones` pages over a stable total order of zone ids. Bounded by
    /// [`MAX_HOSTED_ZONES`].
    pub zones: BTreeMap<String, StoredZone>,
    /// `CallerReference` -> bare zone id, the index `CreateHostedZone` answers
    /// `HostedZoneAlreadyExists` from.
    pub zone_by_caller_reference: HashMap<String, String>,
    /// The retained changes, keyed by bare id, as `GetChange` reads them. Bounded
    /// by [`MAX_RETAINED_CHANGES`] and [`CHANGE_RETENTION`].
    pub changes: HashMap<String, StoredChange>,
    /// The ids in [`ComAmazonawsRoute53Awsdnsv20130401State::changes`] in
    /// submission order, so the oldest can be evicted first.
    change_order: VecDeque<String>,
    /// Every traffic policy, keyed by its id. A `BTreeMap` so a listing pages
    /// over a stable total order of policy ids. The policies the ACCOUNT holds
    /// are bounded by [`MAX_TRAFFIC_POLICIES`]; a record OUTLIVES the delete
    /// that flagged its last version, and those records are bounded by
    /// [`MAX_RETAINED_DELETED_TRAFFIC_POLICIES`].
    pub traffic_policies: BTreeMap<String, StoredTrafficPolicy>,
    /// The ids of the deleted traffic policies in deletion order, so the oldest
    /// record can be released first.
    deleted_traffic_policy_order: VecDeque<String>,
    /// Every traffic policy instance of the account's, keyed by its id. A
    /// `BTreeMap` so a listing pages over a stable total order of instance ids.
    /// Bounded by [`MAX_TRAFFIC_POLICY_INSTANCES`].
    pub traffic_policy_instances: BTreeMap<String, StoredTrafficPolicyInstance>,
    /// Every health check of the account's, keyed by its id. A `BTreeMap` so a
    /// listing pages over a stable total order of health-check ids. Bounded by
    /// [`MAX_HEALTH_CHECKS`].
    pub health_checks: BTreeMap<String, StoredHealthCheck>,
    /// `CallerReference` -> health-check id, the index `CreateHealthCheck`
    /// recognises a repeated request by. An entry OUTLIVES the health check it
    /// names, because the reference of a deleted health check stays held; those
    /// entries are bounded by [`MAX_RETAINED_HEALTH_CHECK_REFERENCES`].
    pub health_check_by_caller_reference: HashMap<String, String>,
    /// The references of deleted health checks in deletion order, so the oldest
    /// can be released first.
    deleted_health_check_references: VecDeque<String>,
    /// Every reusable delegation set of the account's, keyed by its bare id. A
    /// `BTreeMap` so a listing pages over a stable total order of set ids.
    /// Bounded by [`MAX_REUSABLE_DELEGATION_SETS`].
    pub delegation_sets: BTreeMap<String, StoredDelegationSet>,
    /// `CallerReference` -> delegation set id, the index
    /// `CreateReusableDelegationSet` answers `DelegationSetAlreadyCreated`
    /// from.
    pub delegation_set_by_caller_reference: HashMap<String, String>,
    /// Every CIDR collection of the account's, keyed by its id. A `BTreeMap` so
    /// a listing pages over a stable total order of collection ids. Bounded by
    /// [`MAX_CIDR_COLLECTIONS`].
    pub cidr_collections: BTreeMap<String, StoredCidrCollection>,
    /// The id generator, kept here so ids stay unique across calls.
    ids: IdMinter,
    /// The health-checker CIDR blocks `GetCheckerIpRanges` reports, in the order
    /// it reports them. SERVICE-owned: seeded from [`CHECKER_IP_RANGES`] when
    /// this store is created and only ever read afterwards, so every call
    /// answers the same list.
    checker_ip_ranges: Vec<String>,
    /// The geographic locations `ListGeoLocations` reports and `GetGeoLocation`
    /// resolves, in the order the API reports them. SERVICE-owned in exactly the
    /// way the checker ranges above are: seeded from
    /// [`geo_location::catalog`] when this store is created and only ever read
    /// afterwards, so every call answers the same catalog and a read of it can
    /// never change what a later caller sees.
    geo_locations: Vec<GeoLocationDetails>,
    /// Whether the one checker clock that publishes the health checks' status
    /// series ([`health_check_status::drive_health_check_metrics`]) is running, so
    /// a second write does not start a second one.
    pub(crate) checker_clock_running: bool,
    /// The claim the running checker clock holds, so a clock that ends on its
    /// wake-up cap releases only its OWN claim.
    pub(crate) checker_clock_generation: u64,
    /// The running checker clock's task handle, held so the task a write started
    /// stays stoppable and so a replaced one is aborted rather than left running.
    pub(crate) checker_clock: Option<::tokio::task::JoinHandle<()>>,
}

/// The store a fresh engine starts with: no zones and no changes, and the
/// service-owned health-checker ranges already in place (see the module docs).
impl Default for ComAmazonawsRoute53Awsdnsv20130401State {
    fn default() -> Self {
        Self {
            zones: BTreeMap::new(),
            zone_by_caller_reference: HashMap::new(),
            changes: HashMap::new(),
            change_order: VecDeque::new(),
            traffic_policies: BTreeMap::new(),
            deleted_traffic_policy_order: VecDeque::new(),
            traffic_policy_instances: BTreeMap::new(),
            health_checks: BTreeMap::new(),
            health_check_by_caller_reference: HashMap::new(),
            deleted_health_check_references: VecDeque::new(),
            delegation_sets: BTreeMap::new(),
            delegation_set_by_caller_reference: HashMap::new(),
            cidr_collections: BTreeMap::new(),
            ids: IdMinter::default(),
            checker_ip_ranges: checker_ip_ranges(),
            geo_locations: geo_location::catalog(),
            checker_clock_running: false,
            checker_clock_generation: 0,
            checker_clock: None,
        }
    }
}

impl ComAmazonawsRoute53Awsdnsv20130401State {
    /// Mint a hosted-zone id: `Z` plus 14 uppercase alphanumerics, the shape
    /// Route 53 returns (`Z1D633PJN98FT9`). Retried until it is unused.
    pub fn mint_zone_id(&mut self) -> String {
        loop {
            let id = self.ids.mint('Z', ID_BODY_LEN);
            if !self.zones.contains_key(&id) {
                return id;
            }
        }
    }

    /// Mint a traffic policy id: 8-4-4-4-12 lowercase hex, the form Route 53
    /// returns for one (`TrafficPolicyId` is `len 1..36`, which is that form's
    /// length). Retried until it is unused.
    pub fn mint_traffic_policy_id(&mut self) -> String {
        loop {
            let id = self.ids.mint_uuid();
            if !self.traffic_policies.contains_key(&id) {
                return id;
            }
        }
    }

    /// Mint a traffic policy instance id: 8-4-4-4-12 lowercase hex, the form
    /// Route 53 returns for one (`TrafficPolicyInstanceId` is `len 1..36`,
    /// which is that form's length). Retried until it is unused.
    pub fn mint_traffic_policy_instance_id(&mut self) -> String {
        loop {
            let id = self.ids.mint_uuid();
            if !self.traffic_policy_instances.contains_key(&id) {
                return id;
            }
        }
    }

    /// Mint a health-check id: 8-4-4-4-12 lowercase hex, the form Route 53
    /// returns for one. Retried until it is unused.
    pub fn mint_health_check_id(&mut self) -> String {
        loop {
            let id = self.ids.mint_uuid();
            if !self.health_checks.contains_key(&id) {
                return id;
            }
        }
    }

    /// Mint a CIDR collection id: 8-4-4-4-12 lowercase hex, which is the form
    /// the model fixes for one (`UUID`, `pattern
    /// ^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`). Retried until it is
    /// unused.
    pub fn mint_cidr_collection_id(&mut self) -> String {
        loop {
            let id = self.ids.mint_uuid();
            if !self.cidr_collections.contains_key(&id) {
                return id;
            }
        }
    }

    /// The CIDR collection carrying `name`, if the account holds one.
    ///
    /// `CidrCollectionAlreadyExistsException`'s own documentation — "A CIDR
    /// collection with this name and a different caller reference already
    /// exists in this account" — makes the NAME the identity a create collides
    /// on, so the lookup is by name, and it is searched off the store rather
    /// than tracked beside it: a collection that is deleted frees its name by
    /// itself.
    pub fn cidr_collection_with_name(&self, name: &str) -> Option<&StoredCidrCollection> {
        self.cidr_collections
            .values()
            .find(|collection| collection.name == name)
    }

    /// Record that the health check holding `caller_reference` was deleted, so
    /// `CreateHealthCheck` still recognises that reference: a reference stays
    /// held after the health check that used it is gone.
    ///
    /// The index entry is left in place and the reference is remembered in
    /// deletion order; past [`MAX_RETAINED_HEALTH_CHECK_REFERENCES`] the oldest
    /// one is released, so the index cannot grow without end.
    pub fn retain_deleted_health_check_reference(&mut self, caller_reference: String) {
        self.deleted_health_check_references
            .push_back(caller_reference);
        while self.deleted_health_check_references.len() > MAX_RETAINED_HEALTH_CHECK_REFERENCES {
            if let Some(released) = self.deleted_health_check_references.pop_front() {
                self.health_check_by_caller_reference.remove(&released);
            }
        }
    }

    /// Record that the traffic policy `id` has no version the account still
    /// holds, so its retained record can be released once the store holds too
    /// many of them.
    ///
    /// The record itself is LEFT IN PLACE — the id stays resolvable, so
    /// `GetTrafficPolicy` still reports every version of it and a further
    /// version can still be added to it — and the policy is remembered in
    /// deletion order; past [`MAX_RETAINED_DELETED_TRAFFIC_POLICIES`] the oldest
    /// such policy's record is dropped, so the store cannot grow without end for
    /// a caller that creates and deletes policies in a loop. Called from the
    /// delete that flags the policy's last version, never from a read.
    ///
    /// A policy is remembered ONCE however often it reaches this state, and only
    /// a policy that still holds no live version is ever released: one that took
    /// a further version after its last was flagged is a policy the account
    /// holds again, and the live population's own bound
    /// ([`MAX_TRAFFIC_POLICIES`]) is what caps those.
    pub fn retain_deleted_traffic_policy(&mut self, id: String) {
        self.deleted_traffic_policy_order.retain(|held| held != &id);
        self.deleted_traffic_policy_order.push_back(id);
        while self.deleted_traffic_policy_order.len() > MAX_RETAINED_DELETED_TRAFFIC_POLICIES {
            let Some(released) = self.deleted_traffic_policy_order.pop_front() else {
                break;
            };
            if self
                .traffic_policies
                .get(&released)
                .is_some_and(StoredTrafficPolicy::is_deleted)
            {
                self.traffic_policies.remove(&released);
            }
        }
    }

    /// Mint a reusable delegation set id: `N` plus 14 uppercase alphanumerics,
    /// the shape Route 53 returns (`N1PA6795SAMPLE`). Retried until it is
    /// unused.
    pub fn mint_delegation_set_id(&mut self) -> String {
        loop {
            let id = self.ids.mint('N', ID_BODY_LEN);
            if !self.delegation_sets.contains_key(&id) {
                return id;
            }
        }
    }

    /// The reusable delegation set whose name servers are exactly
    /// `name_servers`, if the account holds one.
    ///
    /// A delegation set IS its four name servers, so a set already delegating
    /// to them is the set those name servers are reusable as — which is what
    /// `DelegationSetAlreadyReusable` ("The specified delegation set has
    /// already been marked as reusable") is about. Searched off the store
    /// rather than tracked beside it, so a set that is deleted stops answering
    /// by itself. The comparison is order-insensitive: the four name servers
    /// are a SET, and the order a response lists them in is not part of which
    /// delegation they are.
    pub fn delegation_set_delegating_to(
        &self,
        name_servers: &[String],
    ) -> Option<&StoredDelegationSet> {
        let wanted: BTreeSet<&str> = name_servers.iter().map(String::as_str).collect();
        self.delegation_sets.values().find(|set| {
            set.name_servers
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<&str>>()
                == wanted
        })
    }

    /// The `DelegationSet` a hosted-zone read reports for `zone`: the reusable
    /// set the zone was created in when it names one, and the zone's own name
    /// servers otherwise.
    ///
    /// Read off the SET, so the `Id` and `CallerReference` a zone reports are
    /// the ones the delegation set itself reports.
    pub fn zone_delegation_set(&self, zone: &StoredZone) -> DelegationSet {
        zone.delegation_set_id
            .as_ref()
            .and_then(|id| self.delegation_sets.get(id))
            .map_or_else(
                || zone.to_delegation_set(),
                StoredDelegationSet::to_delegation_set,
            )
    }

    /// How many hosted zones were created in the reusable delegation set `id`.
    ///
    /// COUNTED off the zones, so a zone that is deleted releases the set by
    /// itself: this is what makes a set still carrying zones the one
    /// `DeleteReusableDelegationSet` refuses, and what
    /// `ListHostedZones$DelegationSetId` filters on.
    pub fn zones_in_delegation_set(&self, id: &str) -> usize {
        self.zones
            .values()
            .filter(|zone| zone.delegation_set_id.as_deref() == Some(id))
            .count()
    }

    /// The first `ChildHealthChecks` entry of `config` that names no health
    /// check in this store, or `None` when every entry names one.
    ///
    /// A CALCULATED health check is "healthy" as a function of its children
    /// (`HealthCheckConfig$ChildHealthChecks`), so a child it names has to be a
    /// health check the account holds — the same rule on the create that
    /// persists the list and on the update that replaces it. A configuration of
    /// any other type names no children, so there is nothing to resolve.
    pub fn missing_child_health_check(&self, config: &HealthCheckConfig) -> Option<String> {
        if config.r#type != HEALTH_CHECK_TYPE_CALCULATED {
            return None;
        }
        config
            .child_health_checks
            .iter()
            .flatten()
            .find(|child| !self.health_checks.contains_key(child.as_str()))
            .cloned()
    }

    /// How many traffic policies the account holds right now.
    ///
    /// COUNTED off the store, and over the policies that are not flagged
    /// deleted: the quota is on the policies the account HAS, so a delete
    /// releases a slot by itself even though the deleted policy's record is
    /// retained for `GetTrafficPolicy`.
    pub fn traffic_policy_count(&self) -> usize {
        self.traffic_policies
            .values()
            .filter(|policy| !policy.is_deleted())
            .count()
    }

    /// The traffic policy instance that already answers for `name` at
    /// `rr_type` in the hosted zone `zone_id`, if the account holds one.
    ///
    /// An instance OWNS the record sets it generated
    /// (`ResourceRecordSet$TrafficPolicyInstanceId`), and a zone holds at most
    /// one record set at a given name and type, so a second instance over the
    /// same name and type in the same zone would have no record set to create:
    /// that is the request `TrafficPolicyInstanceAlreadyExists` refuses.
    /// Compared by the name's IDENTITY, so every spelling of one DNS name finds
    /// the same instance, and searched off the store rather than tracked beside
    /// it, so an instance that is deleted frees its name by itself.
    pub fn traffic_policy_instance_for(
        &self,
        zone_id: &str,
        name: &str,
        rr_type: &str,
    ) -> Option<&StoredTrafficPolicyInstance> {
        let name_key = dns_sort_key(name);
        self.traffic_policy_instances.values().find(|instance| {
            instance.hosted_zone_id == zone_id
                && instance.traffic_policy_type == rr_type
                && dns_sort_key(&instance.name) == name_key
        })
    }

    /// The creation position the account's NEXT traffic policy takes: one past
    /// the highest any policy it holds carries.
    ///
    /// Read off the policies rather than tracked in a counter beside them, so
    /// the positions cannot disagree with the policies the account actually
    /// holds. A deleted policy's record is retained
    /// ([`StoredTrafficPolicyVersion::deleted`]), so its position is never
    /// handed out again and the ORDER of the surviving policies is untouched:
    /// every one of them was created before the policy taking the new position.
    pub fn next_traffic_policy_position(&self) -> u64 {
        self.traffic_policies
            .values()
            .map(|policy| policy.created_position)
            .max()
            .map_or(FIRST_TRAFFIC_POLICY_POSITION, |highest| highest + 1)
    }

    /// Every traffic policy record this store holds, in the order they were
    /// created in — the order `ListTrafficPolicies` reports them in.
    ///
    /// The creation position is unique among the policies the account holds, so
    /// the id breaks a tie only for completeness: the order is TOTAL, which is
    /// what lets a page resume at one place. The RETAINED record of a deleted
    /// policy ([`StoredTrafficPolicy::is_deleted`]) is in the walk as well, so
    /// the caller decides what to do with it: a listing has none to report for
    /// it and skips it, which is what keeps a deleted policy out of
    /// `ListTrafficPolicies` without moving where the surviving ones resume.
    pub fn traffic_policies_in_creation_order(&self) -> Vec<&StoredTrafficPolicy> {
        let mut ordered: Vec<&StoredTrafficPolicy> = self.traffic_policies.values().collect();
        ordered.sort_by(|left, right| {
            left.created_position
                .cmp(&right.created_position)
                .then_with(|| left.id.cmp(&right.id))
        });
        ordered
    }

    /// Every traffic policy instance the account holds, in the order a listing
    /// of them reports them in: by the hosted zone the instance's record sets
    /// live in, then by the DNS name they answer for, then by their record
    /// type.
    ///
    /// That triple is what a listing's markers are made of — an account-wide
    /// page resumes at a `(HostedZoneIdMarker,
    /// TrafficPolicyInstanceNameMarker, TrafficPolicyInstanceTypeMarker)`
    /// triple, a per-zone page at the pair of it inside one zone — so an
    /// instance's place in the listing is exactly what those markers name. The
    /// name is compared by its IDENTITY ([`dns_sort_key`], the order DNS itself
    /// gives and the one `ListResourceRecordSets` reports in), and the triple is
    /// unique among the account's instances
    /// ([`ComAmazonawsRoute53Awsdnsv20130401State::traffic_policy_instance_for`]),
    /// so the order is TOTAL: a marker always resumes at the same place.
    pub fn traffic_policy_instances_in_listing_order(&self) -> Vec<&StoredTrafficPolicyInstance> {
        let mut ordered: Vec<&StoredTrafficPolicyInstance> =
            self.traffic_policy_instances.values().collect();
        ordered.sort_by(|left, right| {
            traffic_policy_instance_order_key(left).cmp(&traffic_policy_instance_order_key(right))
        });
        ordered
    }

    /// Record a newly submitted change and return it, so the caller can render
    /// the `ChangeInfo` it just persisted. The id is `C` plus 14 uppercase
    /// alphanumerics, the shape Route 53 returns (`C2682N5HXP0BZ4`).
    pub fn submit_change(&mut self, comment: Option<String>) -> StoredChange {
        let id = loop {
            let id = self.ids.mint('C', ID_BODY_LEN);
            if !self.changes.contains_key(&id) {
                break id;
            }
        };
        let change = StoredChange {
            id: id.clone(),
            submitted_at_millis: now_millis(),
            insync_at: Instant::now() + CHANGE_PROPAGATION,
            comment,
        };
        self.change_order.push_back(id.clone());
        self.changes.insert(id, change.clone());
        self.retain_recent_changes();
        change
    }

    /// Drop the changes the ledger no longer retains: the oldest past
    /// [`MAX_RETAINED_CHANGES`], and any that reached `INSYNC` more than
    /// [`CHANGE_RETENTION`] ago.
    ///
    /// Called from the mutating path that appends a change, never from a read,
    /// so reading a change never changes what a later caller sees.
    fn retain_recent_changes(&mut self) {
        let now = Instant::now();
        while let Some(oldest) = self.change_order.front().cloned() {
            let over_cap = self.change_order.len() > MAX_RETAINED_CHANGES;
            let expired = self.changes.get(&oldest).is_none_or(|change| {
                now.saturating_duration_since(change.insync_at) > CHANGE_RETENTION
            });
            if !over_cap && !expired {
                break;
            }
            self.change_order.pop_front();
            self.changes.remove(&oldest);
        }
    }

    /// The account quota for one `AccountLimitType` and how much of it this
    /// store currently holds, as `(limit value, current count)`. `None` for a
    /// value outside `AccountLimitType`.
    ///
    /// The count is COUNTED off the store on every call rather than tracked
    /// beside it, so it cannot disagree with the resources the account actually
    /// holds: creating or deleting one moves the count by itself, and no read
    /// has to be told about it. The quota is the same constant the create path
    /// refuses at, so a count that has reached the reported limit is exactly
    /// the point at which the next create is refused.
    pub fn account_limit_usage(&self, limit_type: &str) -> Option<(i64, i64)> {
        let (limit, count) = match limit_type {
            ACCOUNT_LIMIT_MAX_HOSTED_ZONES => (MAX_HOSTED_ZONES, self.zones.len()),
            ACCOUNT_LIMIT_MAX_TRAFFIC_POLICIES => {
                (MAX_TRAFFIC_POLICIES, self.traffic_policy_count())
            }
            ACCOUNT_LIMIT_MAX_HEALTH_CHECKS => (MAX_HEALTH_CHECKS, self.health_checks.len()),
            ACCOUNT_LIMIT_MAX_REUSABLE_DELEGATION_SETS => {
                (MAX_REUSABLE_DELEGATION_SETS, self.delegation_sets.len())
            }
            ACCOUNT_LIMIT_MAX_TRAFFIC_POLICY_INSTANCES => (
                MAX_TRAFFIC_POLICY_INSTANCES,
                self.traffic_policy_instances.len(),
            ),
            _ => return None,
        };
        Some((count_as_i64(limit), count_as_i64(count)))
    }

    /// The per-set quota for one `ReusableDelegationSetLimitType` and how much
    /// of it the reusable delegation set `id` holds right now, as
    /// `(limit value, current count)`. `None` for a value outside
    /// `ReusableDelegationSetLimitType`.
    ///
    /// `id` is the BARE set id. The count is COUNTED off the zones on every
    /// call, for the same reason [`Self::account_limit_usage`] counts: a zone
    /// created in the set or deleted from it moves the count by itself, so no
    /// read has to be told about it and none can disagree with the zones
    /// `ListHostedZones` reports for that set. The quota is the same constant
    /// `CreateHostedZone` refuses at, so a count that has reached the reported
    /// limit is exactly the point at which the next create in that set is
    /// refused.
    pub fn delegation_set_limit_usage(&self, id: &str, limit_type: &str) -> Option<(i64, i64)> {
        let (limit, count) = match limit_type {
            REUSABLE_DELEGATION_SET_LIMIT_MAX_ZONES => (
                MAX_HOSTED_ZONES_PER_DELEGATION_SET,
                self.zones_in_delegation_set(id),
            ),
            _ => return None,
        };
        Some((count_as_i64(limit), count_as_i64(count)))
    }

    /// How many hosted zones the account holds right now, public and private
    /// together, as the `long` a count shape carries.
    ///
    /// COUNTED off the store on every call rather than tracked beside it, for
    /// the same reason [`Self::account_limit_usage`] counts: creating or
    /// deleting a zone moves the number by itself, so no reporting operation
    /// has to be told about it and none can disagree with the zones a listing
    /// returns. A borrow, not a mutation — reporting the count leaves the store
    /// exactly as it was.
    pub fn hosted_zone_count(&self) -> i64 {
        count_as_i64(self.zones.len())
    }

    /// How many traffic policy instances the account holds right now, as the
    /// `integer` the `TrafficPolicyInstanceCount` shape carries — every
    /// instance of every policy and every hosted zone, whatever `State` each
    /// one is reported in.
    ///
    /// COUNTED off the store on every call rather than tracked beside it, for
    /// the same reason [`Self::account_limit_usage`] counts: creating or
    /// deleting an instance moves the number by itself, so no reporting
    /// operation has to be told about it and none can disagree with the
    /// instances a read or a listing reports. A borrow, not a mutation —
    /// reporting the count leaves the store exactly as it was. Saturating
    /// rather than wrapping on a population no store this size can reach; the
    /// create path refuses past [`MAX_TRAFFIC_POLICY_INSTANCES`], far below
    /// that.
    pub fn traffic_policy_instance_count(&self) -> i32 {
        i32::try_from(self.traffic_policy_instances.len()).unwrap_or(i32::MAX)
    }

    /// The zone OTHER than `excluding_zone_id` that carries the same DNS name
    /// as `zone_name` and is already associated with `vpc_id`, if there is one.
    ///
    /// `ConflictingDomainExists`'s own documentation, for the case "Associate
    /// VPCs with a private hosted zone": "The VPC that you specified is already
    /// associated with another hosted zone that has the same name." One VPC
    /// resolving one name through two zones has no answer, so the association
    /// that would create the ambiguity is the one refused.
    pub fn zone_with_name_associated_to_vpc(
        &self,
        zone_name: &str,
        excluding_zone_id: &str,
        vpc_id: &str,
    ) -> Option<&StoredZone> {
        let name_key = dns_sort_key(zone_name);
        self.zones.values().find(|zone| {
            zone.id != excluding_zone_id
                && dns_sort_key(&zone.name) == name_key
                && zone.vpc_position(vpc_id).is_some()
        })
    }

    /// The health-checker CIDR blocks this store holds, in the order
    /// `GetCheckerIpRanges` reports them.
    ///
    /// A borrow, not a mutation: the set is service-owned, so reporting it
    /// leaves the store exactly as it was.
    pub fn checker_ip_ranges(&self) -> &[String] {
        &self.checker_ip_ranges
    }

    /// The supported geographic locations this store holds, in the order
    /// `ListGeoLocations` reports them.
    ///
    /// A borrow, not a mutation: the catalog is service-owned, so reporting it
    /// or resolving one entry of it leaves the store exactly as it was.
    pub fn geo_locations(&self) -> &[GeoLocationDetails] {
        &self.geo_locations
    }

    /// Mint the four authoritative name servers for a new hosted zone.
    ///
    /// The Route 53 Developer Guide ("NS and SOA Records that Route 53 Creates
    /// for a Hosted Zone") describes the delegation set as four name servers,
    /// one in each of the `com`, `net`, `org` and `co.uk` top-level domains, so
    /// a resolver failure in one TLD cannot take all four out.
    pub fn mint_name_servers(&mut self) -> Vec<String> {
        const TLDS: [&str; 4] = ["com", "net", "org", "co.uk"];
        TLDS.iter()
            .map(|tld| {
                let host = self.ids.next_u64() % 2048 + 1;
                let set = self.ids.next_u64() % 64;
                format!("ns-{host}.awsdns-{set:02}.{tld}")
            })
            .collect()
    }
}

/// The number of characters after the single-letter prefix in a Route 53
/// resource id (`Z1D633PJN98FT9`, `C2682N5HXP0BZ4`).
const ID_BODY_LEN: usize = 14;

/// A count or a quota as the `long` the count and limit shapes carry
/// (`HealthCheckCount` and `HostedZoneCount` are `long`, `UsageCount` is
/// `range 0..`, `LimitValue` is `range 1..`), saturating rather than wrapping on
/// a count no store this size can reach.
pub fn count_as_i64(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

/// Milliseconds since the Unix epoch, for a `SubmittedAt` timestamp.
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// The octets of a DNS name, one `Vec<u8>` per label, with every presentation
/// escape resolved and the root label dropped.
///
/// A name reaches the API in PRESENTATION form, where an octet may be spelled
/// either literally, as `\DDD` (three octal digits — `\052` is `*`, octet 42),
/// or as a backslash in front of the octet itself (`\.` is a dot INSIDE a label
/// rather than a label separator). Resolving all three spellings down to octets
/// is what makes two spellings of one name the same name, so it is the basis of
/// both [`canonical_dns_name`] and [`dns_sort_key`].
///
/// An empty name has no labels, so it keys and renders as the empty name rather
/// than as the root.
fn dns_labels(name: &str) -> Vec<Vec<u8>> {
    let bytes = name.trim().as_bytes();
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut label: Vec<u8> = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'.' => {
                labels.push(std::mem::take(&mut label));
                index += 1;
            }
            b'\\' => {
                if let Some(octet) = octal_escape_at(bytes, index) {
                    label.push(octet);
                    index += 4;
                } else if let Some(&escaped) =
                    bytes.get(index + 1).filter(|byte| !byte.is_ascii_digit())
                {
                    label.push(escaped);
                    index += 2;
                } else {
                    // Either nothing follows, or what follows is a digit run
                    // that is no escape code of this form (`\777` is above one
                    // octet, `\8` is not octal): the backslash is then an octet
                    // of its own, and the digits are ordinary octets after it.
                    label.push(b'\\');
                    index += 1;
                }
            }
            octet => {
                label.push(octet);
                index += 1;
            }
        }
    }
    labels.push(label);
    // A trailing dot spells the root label, which names nothing of its own.
    if labels.len() > 1 && labels.last().is_some_and(Vec::is_empty) {
        labels.pop();
    }
    labels
}

/// The octet a `\DDD` escape at `index` stands for, if one starts there.
///
/// Route 53 writes these codes in OCTAL ("the escape code \\three-digit octal
/// code" of the DNS domain-name format), so `\052` is the asterisk, octet 42.
/// A code that is not three octal digits, or that is above one octet, is not an
/// escape of this kind.
fn octal_escape_at(bytes: &[u8], index: usize) -> Option<u8> {
    let digits = bytes.get(index + 1..index + 4)?;
    if !digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
        return None;
    }
    let value = digits
        .iter()
        .fold(0u32, |value, digit| value * 8 + u32::from(digit - b'0'));
    u8::try_from(value).ok()
}

/// Whether this octet is one a DNS name carries literally in Route 53's
/// presentation of it.
///
/// The characters a name is spelled with are `a-z`, `0-9`, `-` (hyphen) and `_`
/// (underscore); every other octet is presented as an octal escape code (the
/// DNS domain-name format the `Name` member's documentation points at).
fn is_plain_dns_octet(octet: u8) -> bool {
    octet.is_ascii_lowercase() || octet.is_ascii_digit() || octet == b'-' || octet == b'_'
}

/// A DNS name in the ONE canonical form this service stores and returns it in:
/// lower-cased, every octet outside the plain set escaped as `\DDD`, and
/// terminated by the root dot.
///
/// Two parts of the same documented rule. The trailing dot: "The trailing dot
/// is optional; Amazon Route 53 assumes that the domain name is fully
/// qualified. This means that Route 53 treats www.example.com (without a
/// trailing dot) and www.example.com. (with a trailing dot) as identical."
/// The spelling: a name may only be written with `a-z`, `0-9`, `-` and `_`, so
/// any other octet — the `*` of a wildcard label above all — comes back as its
/// octal escape code, and a name's letters come back folded to lower case
/// however they were sent.
///
/// Because the form is canonical, EVERY spelling of a name maps onto it: the
/// escaped and the literal spelling of an octet, and either case of a letter,
/// all name one resource.
pub fn canonical_dns_name(name: &str) -> String {
    let mut canonical = String::new();
    for label in dns_labels(name) {
        for octet in label {
            let octet = octet.to_ascii_lowercase();
            if is_plain_dns_octet(octet) {
                canonical.push(char::from(octet));
            } else {
                let _ = write!(canonical, "\\{octet:03o}");
            }
        }
        canonical.push('.');
    }
    canonical
}

/// A name's labels, lower-cased, as [`dns_labels`] resolves them.
///
/// DNS names are case-insensitive, so folding here is what makes `WWW.example.com`
/// and `www.example.com` one name.
fn dns_lower_labels(name: &str) -> Vec<Vec<u8>> {
    let mut labels = dns_labels(name);
    for label in &mut labels {
        label.make_ascii_lowercase();
    }
    labels
}

/// The order key `ListResourceRecordSets` sorts by, which is also a record
/// set's name IDENTITY.
///
/// The sort position, from the operation's documentation: "ListResourceRecordSets
/// sorts results first by DNS name with the labels reversed, for example:
/// `com.example.www.` Note the trailing dot, which can change the sort order
/// when the record name contains characters that appear before . (decimal 46) in
/// the ASCII table. These characters include the following: ! " # $ % & ' ( ) *
/// + , -". So `dotted` is the reversed labels' OCTETS, not their escaped
/// spelling, joined by dots: those characters then sort where the documentation
/// says they do. It is a byte string because an octet of a DNS name need not be
/// text at all.
///
/// A name has ONE canonical spelling, so `WWW.example.com`, `www.example.com.`
/// and `\167ww.example.com` give the same key and name the same record set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DnsNameKey {
    /// The reversed labels' octets joined by `.` — the documented sort position.
    dotted: Vec<u8>,
    /// How long each of those reversed labels is, which the dotted form alone
    /// does not pin down: a label may CONTAIN a dot octet (`a\.b` is one label),
    /// so `a\.b.example.com` and `b.a.example.com` share a sort position while
    /// being different names. Compared only after `dotted`, so it breaks exactly
    /// those ties and leaves the documented order alone.
    label_lengths: Vec<usize>,
}

/// The [`DnsNameKey`] of a name.
pub fn dns_sort_key(name: &str) -> DnsNameKey {
    let labels = dns_lower_labels(name);
    let mut dotted = Vec::with_capacity(name.len() + 1);
    let mut label_lengths = Vec::with_capacity(labels.len());
    for label in labels.iter().rev() {
        dotted.extend_from_slice(label);
        dotted.push(b'.');
        label_lengths.push(label.len());
    }
    DnsNameKey {
        dotted,
        label_lengths,
    }
}

/// The most octets one DNS label may carry.
///
/// The DNS domain name format every `DNSName` member's documentation points at:
/// "The maximum length of each label is 63 characters." The octets are counted
/// AFTER the presentation escapes are resolved, because an escape code spells
/// one octet however many characters it is written with.
pub const MAX_DNS_LABEL_OCTETS: usize = 63;

/// The most octets a whole DNS name may carry, counting the dot after each
/// label.
///
/// The same documented format: "The total DNS name can't exceed 255
/// characters", dots included.
pub const MAX_DNS_NAME_OCTETS: usize = 255;

/// A rule of the DNS domain-name format a name can break.
///
/// The format every `DNSName` member's documentation points at fixes what a
/// name may be made of, independently of where the name was submitted: as the
/// name of a record set, as the domain name an alias routes to, or inside a
/// record's own data. Each variant carries the measurement that broke the rule,
/// so a caller can word its own refusal from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsNameFault {
    /// A label longer than [`MAX_DNS_LABEL_OCTETS`], with its length.
    LabelTooLong(usize),
    /// A whole name longer than [`MAX_DNS_NAME_OCTETS`], with its length.
    NameTooLong(usize),
    /// A label with no octets at all, which spells no component of a name —
    /// the empty name included, which has no labels to spell one with.
    EmptyLabel,
}

/// Which rule of the domain-name format `name` breaks, or `None` when it breaks
/// none.
///
/// Measured in resolved OCTETS, so a name spelled with escape codes is judged
/// by the name it spells. The length rules are checked before the empty label,
/// so a name that breaks a documented BOUND is reported by that bound.
pub fn dns_name_fault(name: &str) -> Option<DnsNameFault> {
    let labels = dns_labels(name);
    if let Some(label) = labels.iter().find(|label| label.len() > MAX_DNS_LABEL_OCTETS) {
        return Some(DnsNameFault::LabelTooLong(label.len()));
    }
    // Every label is followed by the dot that ends it, the root dot included,
    // which is the canonical form the name is stored and compared in.
    let octets: usize = labels.iter().map(|label| label.len() + 1).sum();
    if octets > MAX_DNS_NAME_OCTETS {
        return Some(DnsNameFault::NameTooLong(octets));
    }
    if labels.is_empty() || labels.iter().any(Vec::is_empty) {
        return Some(DnsNameFault::EmptyLabel);
    }
    None
}

/// The problem clause this service states one [`DnsNameFault`] as: the fault's
/// own code and the parenthesised sentence beside it.
///
/// ONE vocabulary for every path that judges a submitted DNS name — the record
/// data of a `CNAME`, `NS` or `PTR` record set, and the `DNSName` a listing is
/// positioned at — so one broken rule of the domain-name format is stated
/// identically whichever operation was asked to accept the name.
pub fn dns_name_fault_clause(fault: DnsNameFault) -> &'static str {
    match fault {
        DnsNameFault::EmptyLabel => "DomainLabelEmpty (Domain label is empty)",
        DnsNameFault::LabelTooLong(_) => "DomainLabelTooLong (Domain label is too long)",
        DnsNameFault::NameTooLong(_) => "DomainTooLong (Domain name is too long)",
    }
}

/// The refusal text a request submitting the unusable domain name `name` is
/// answered with (`InvalidDomainName`, HTTP 400), or `None` when `name` breaks
/// no rule of the domain-name format.
///
/// The modelled `@length` on a `DNSName` member bounds the REQUEST field (up to
/// 1024 characters), which is far looser than what DNS itself allows, so a name
/// that satisfies every modelled constraint can still be unusable as a domain
/// name — and that is the refusal `InvalidDomainName` names. Every rule of the
/// format counts, as [`dns_name_fault`] measures them: the documented label and
/// whole-name lengths, and a label with no octets at all.
///
/// The sentence states the rule that was broken ([`dns_name_fault_clause`]) and
/// quotes the name that broke it verbatim from the request, so it is built
/// wholly from the request.
pub fn invalid_domain_name_message(name: &str) -> Option<String> {
    let fault = dns_name_fault(name)?;
    Some(format!(
        "FATAL problem: {} encountered with '{name}'",
        dns_name_fault_clause(fault)
    ))
}

/// Whether `name` is inside `zone_name` — the same name, or a subdomain of it.
///
/// `ChangeResourceRecordSets` only accepts records for the zone it is called
/// on, so this is what separates a record the zone owns from one it does not.
/// Compared LABEL by label, so a name is in the zone only when the zone's whole
/// labels are its suffix: `evil-example.com` is not inside `example.com`.
pub fn name_is_in_zone(name: &str, zone_name: &str) -> bool {
    let name_labels = dns_lower_labels(name);
    let zone_labels = dns_lower_labels(zone_name);
    let Some(offset) = name_labels.len().checked_sub(zone_labels.len()) else {
        return false;
    };
    name_labels[offset..] == zone_labels[..]
}

/// A resource's tag set as the wire carries it, in tag-key order.
///
/// The list is the resource's WHOLE tag set, and it is empty when the resource
/// carries no tags: a tag read reports the `Tags` container unconditionally, so
/// a client walking `ResourceTagSet/Tags` to enumerate tags finds an empty
/// collection rather than a missing node once every tag has been removed. (The
/// `@length min 1` on `TagList` bounds what a REQUEST may send — the modelled
/// constraints are enforced on input only — not what a tag set may hold.)
pub fn tags_to_list(tags: &BTreeMap<String, String>) -> Vec<Tag> {
    tags.iter()
        .map(|(key, value)| Tag {
            key: Some(key.clone()),
            value: Some(value.clone()),
        })
        .collect()
}

/// Why a tag read could not resolve the resource one `ResourceId` names.
///
/// A tag read addresses a resource by `ResourceType` plus `ResourceId`, and the
/// resource type decides which not-found the refusal reports. Both tag reads
/// resolve an id through [`resource_tag_set`] and lift this into their OWN
/// modelled error enum, because a modelled error belongs to the operation that
/// declares it.
#[derive(Debug)]
pub enum MissingTagResource {
    /// The id names no hosted zone in this store.
    HostedZone(NoSuchHostedZone),
    /// The id names no health check in this store.
    HealthCheck(NoSuchHealthCheck),
    /// The `ResourceType` names neither taggable resource type. Unreachable
    /// through the API — `TagResourceType` is a modelled enum, so a value
    /// outside it is refused at the request boundary — and carried here so the
    /// resolution has one total answer rather than a per-handler fallback.
    UnknownResourceType(String),
}

/// The `ResourceTagSet` a tag read reports for ONE resource of this store.
///
/// The one place this service resolves `ResourceType` + `ResourceId` to a tag
/// set, so the single-resource read and the batch read cannot report one
/// resource's tags differently or refuse a missing one differently. A pure
/// READ: it takes the store by shared reference, so nothing a tag read does can
/// change what a later caller sees.
///
/// The reported `ResourceId` is the resource's OWN id, not the spelling the
/// request addressed it by, so a zone asked for as `/hostedzone/<id>` is
/// reported as the bare id every other response names it with.
pub fn resource_tag_set(
    store: &ComAmazonawsRoute53Awsdnsv20130401State,
    resource_type: &str,
    resource_id: &str,
) -> Result<ResourceTagSet, MissingTagResource> {
    match resource_type {
        TAG_RESOURCE_TYPE_HOSTED_ZONE => {
            // The caller may pass the bare id or the `/hostedzone/`-prefixed
            // `Id` a HostedZone handed it back; both name the same zone.
            let zone = store
                .zones
                .get(normalize_zone_id(resource_id))
                .ok_or_else(|| {
                    MissingTagResource::HostedZone(no_such_hosted_zone(resource_id))
                })?;
            Ok(ResourceTagSet {
                resource_type: Some(resource_type.to_string()),
                resource_id: Some(zone.id.clone()),
                // The `Tags` container is always reported, empty when the
                // resource carries no tags, so a client walking it reads an
                // empty collection rather than a missing node.
                tags: Some(zone.to_tag_list()),
            })
        }
        TAG_RESOURCE_TYPE_HEALTH_CHECK => {
            // A health check is addressed by the bare id `CreateHealthCheck`
            // assigned it, which is the id the store is keyed by.
            let health_check = store.health_checks.get(resource_id).ok_or_else(|| {
                MissingTagResource::HealthCheck(no_such_health_check(resource_id))
            })?;
            Ok(ResourceTagSet {
                resource_type: Some(resource_type.to_string()),
                resource_id: Some(health_check.id.clone()),
                tags: Some(health_check.to_tag_list()),
            })
        }
        other => Err(MissingTagResource::UnknownResourceType(other.to_string())),
    }
}

/// Apply one `ChangeTagsForResource` batch to a resource's tag set.
///
/// A tag set is a MAP from key to value, which is what makes the operation
/// "adds, edits, or deletes tags" (its own documentation): adding a key the
/// resource already carries edits that key's value, and removing a key it does
/// not carry leaves the set as it was. `RemoveTagKeys` is applied FIRST, so a
/// key named in both lists ends up with the value `AddTags` gives it rather
/// than being dropped.
///
/// The batch is applied to a COPY and committed only once it is wholly valid,
/// so a refused batch leaves the resource's tags exactly as they were. `Err`
/// carries the refusal text for the caller's `InvalidInput`.
pub fn apply_tag_changes(
    tags: &mut BTreeMap<String, String>,
    add_tags: Option<&[Tag]>,
    remove_tag_keys: Option<&[String]>,
) -> Result<(), String> {
    if add_tags.is_none() && remove_tag_keys.is_none() {
        return Err(
            "the request must specify AddTags, RemoveTagKeys, or both: it asks for no change"
                .to_string(),
        );
    }

    let mut updated = tags.clone();
    for key in remove_tag_keys.unwrap_or_default() {
        updated.remove(key);
    }
    for tag in add_tags.unwrap_or_default() {
        // `Tag$Key` is not required by the model, but a tag with no key names
        // nothing to add, edit or delete.
        let key = tag
            .key
            .clone()
            .ok_or_else(|| "every Tag in AddTags must carry a Key".to_string())?;
        updated.insert(key, tag.value.clone().unwrap_or_default());
    }

    if updated.len() > MAX_TAGS_PER_RESOURCE {
        return Err(format!(
            "a resource can carry at most {MAX_TAGS_PER_RESOURCE} tags; this request would \
             leave it with {}",
            updated.len()
        ));
    }

    *tags = updated;
    Ok(())
}

/// The sentence Route 53 refuses a traffic policy it does not hold with.
///
/// Entirely fixed text: it states the rule the refusal reports and carries nothing the
/// request named — neither the `Id` nor the `Version` it asked about — so a caller learns
/// WHAT it asked about from its own request.
pub const NO_SUCH_TRAFFIC_POLICY_MESSAGE: &str = "The policy does not exist.";

/// The modelled `NoSuchTrafficPolicy` (HTTP 404) for a request that names no
/// traffic policy in this store.
///
/// The ONE place this service words that refusal, so every operation addressed
/// at a traffic policy answers a missing one identically — whichever half of
/// `(Id, Version)` the store does not hold, and whether the request named a
/// version at all — carrying [`NO_SUCH_TRAFFIC_POLICY_MESSAGE`].
pub fn no_such_traffic_policy() -> NoSuchTrafficPolicy {
    NoSuchTrafficPolicy {
        message: Some(NO_SUCH_TRAFFIC_POLICY_MESSAGE.to_string()),
    }
}

/// The modelled `NoSuchTrafficPolicyInstance` (HTTP 404) for a request that
/// names no traffic policy instance in this store.
///
/// The ONE place this service words that refusal, beside
/// [`no_such_traffic_policy`], so every operation addressed at a traffic policy
/// instance answers a missing one identically.
///
/// MESSAGELESS, unlike the policy refusal beside it: Route 53 reports a traffic policy
/// INSTANCE it does not hold as the error's identity alone — the `Error` element carries
/// `Type` and `Code` and no `Message` child — so this shape's optional `message` member is
/// left unset and the serializer emits no element for it. It takes no argument because a
/// refusal with no message has nothing to take from the request: a caller learns WHAT it
/// asked about from its own request.
pub fn no_such_traffic_policy_instance() -> NoSuchTrafficPolicyInstance {
    NoSuchTrafficPolicyInstance { message: None }
}

/// The one sentence this service refuses a DNS name that the hosted zone the
/// request names does not own with.
///
/// A zone answers only for names inside it ([`name_is_in_zone`]), so a record
/// set — whether a change batch writes it or a traffic policy instance
/// generates it — can only be created at a name the zone owns. REQUEST-DERIVED:
/// it names the name that was asked for and the zone that does not own it. One
/// sentence, so the change path and the traffic-policy-instance path cannot
/// word one rule differently.
pub fn name_not_permitted_in_zone_message(name: &str, zone_name: &str) -> String {
    format!("RRSet with DNS name {name} is not permitted in zone {zone_name}")
}

/// How a refusal names the record set it is about: `[name='<name>',
/// type='<type>']`, and `set-identifier='<id>'` as well when the record set
/// carries one.
///
/// A record set is named by what IDENTIFIES it — the name it answers for, its
/// record type and, for a member of a routing group, the identifier that tells
/// it from its siblings. One helper, so every refusal about a record set names
/// it the same way, whichever operation raises it.
pub fn record_set_label(name: &str, rr_type: &str, set_identifier: Option<&str>) -> String {
    let set_identifier = set_identifier
        .filter(|id| !id.is_empty())
        .map(|id| format!(", set-identifier='{id}'"))
        .unwrap_or_default();
    format!("[name='{name}', type='{rr_type}'{set_identifier}]")
}

/// The one sentence this service refuses a create over a record set a zone
/// already holds with.
///
/// A zone holds at most one record set per `(name, type, set identifier)`, so a
/// create over one that is already there has nothing to create — whether a
/// change batch or a traffic policy instance asked for it. REQUEST-DERIVED: it
/// names the record set that was asked for and nothing else.
pub fn record_set_already_exists_message(
    name: &str,
    rr_type: &str,
    set_identifier: Option<&str>,
) -> String {
    format!(
        "Tried to create resource record set {} but it already exists",
        record_set_label(name, rr_type, set_identifier)
    )
}

/// The one sentence this service refuses a zone that would be grown past
/// [`MAX_RECORD_SETS_PER_ZONE`] with.
///
/// The zone's own quota, whichever operation would add the record set, so both
/// the change path and the traffic-policy-instance create word it identically.
/// REQUEST-DERIVED: it names the zone id as the request wrote it and how many
/// record sets that request would leave the zone holding.
pub fn zone_record_set_limit_message(requested_zone_id: &str, would_hold: usize) -> String {
    format!(
        "The hosted zone {requested_zone_id} would hold {would_hold} resource record sets, more \
         than the maximum of {MAX_RECORD_SETS_PER_ZONE} per hosted zone"
    )
}

/// The modelled `InvalidTrafficPolicyDocument` (HTTP 400) for a document the
/// traffic policy document format does not define.
///
/// A document is checked against EVERY structural constraint of the format and
/// the refusal enumerates every one it violates — one clause per violated
/// constraint, in this service's own fixed clause order, joined with `;` — so a
/// caller authoring a document learns all of its faults from one request
/// instead of one fault per round trip. The ONE place this service words that
/// refusal, so every operation that takes a document (the create, and the
/// version create built on the same validator) reports a faulty one
/// identically.
pub fn invalid_traffic_policy_document(violations: &[String]) -> InvalidTrafficPolicyDocument {
    InvalidTrafficPolicyDocument {
        message: Some(violations.join(";")),
    }
}

/// The `RRType` a traffic policy document records, or every constraint of the
/// document format the document violates (`InvalidTrafficPolicyDocument`,
/// HTTP 400).
///
/// The document is the traffic policy's definition, and `TrafficPolicy$Type` is
/// "the DNS type of the resource record sets that Amazon Route 53 creates when
/// you use a traffic policy to create a traffic policy instance" — so the type
/// is READ OFF the document rather than taken from the request, which carries
/// no type at all. The structure checked here is the one the "Traffic Policy
/// Document Format" reference defines: a JSON object declaring its
/// `AWSPolicyFormatVersion`, the `RecordType` it creates, the `Endpoints` it can
/// route to, and exactly one entry point — `StartEndpoint`, naming one of those
/// endpoints, or `StartRule`, naming one of the `Rules`.
///
/// `Err` carries ONE CLAUSE PER VIOLATED CONSTRAINT rather than stopping at the
/// first: a document can break several of these rules at once and a caller
/// validating a document by submitting it has to learn about all of them.
/// Each clause states the constraint that was broken (and, where a value was
/// the problem, that value); the document itself is never quoted back. The
/// clause order is FIXED — it does not follow the order the members happen to
/// appear in the document — and the record-type clause
/// ([`RECORD_TYPE_CLAUSE`]) comes last, after the endpoint and entry-point
/// clauses. The two faults a document can have before anything else can be
/// checked — it is not JSON, or it is JSON that is not an object — are the whole
/// refusal on their own, because no constraint below them can be evaluated at
/// all.
pub fn traffic_policy_record_type(document: &str) -> Result<String, Vec<String>> {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(document) else {
        return Err(vec![
            "The traffic policy document must be declared as valid JSON.".to_string(),
        ]);
    };
    let Some(root) = parsed.as_object() else {
        return Err(vec![
            "The traffic policy document must be declared as a JSON object.".to_string(),
        ]);
    };

    let mut violations: Vec<String> = Vec::new();

    match root
        .get("AWSPolicyFormatVersion")
        .and_then(serde_json::Value::as_str)
    {
        Some(TRAFFIC_POLICY_FORMAT_VERSION) => {}
        Some(other) => violations.push(format!(
            "AWSPolicyFormatVersion {other} is not a supported traffic policy document format \
             version, the supported version is {TRAFFIC_POLICY_FORMAT_VERSION}."
        )),
        None => violations.push("AWSPolicyFormatVersion must be declared.".to_string()),
    }

    let record_type = match root.get("RecordType").and_then(serde_json::Value::as_str) {
        Some(value) if R_R_TYPE_VALUES.contains(&value) => Some(value.to_string()),
        // The record-type constraint is reported by ONE clause, at the END of
        // the message: see [`RECORD_TYPE_CLAUSE`]. The clause is pushed after
        // every other check has run, so the constraints a document breaks are
        // reported in the order this service reports them in whichever
        // combination they are broken.
        _ => None,
    };

    // A document declares the endpoints it can route to in `Endpoints`, which
    // maps an endpoint's name to its definition. A block that is absent or
    // empty declares no endpoint at all, which is the same violation however
    // it is spelled.
    let endpoints = match root.get("Endpoints") {
        None => {
            violations.push("At least one endpoint must be declared.".to_string());
            None
        }
        Some(value) => match value.as_object() {
            Some(endpoints) => {
                if endpoints.is_empty() {
                    violations.push("At least one endpoint must be declared.".to_string());
                }
                Some(endpoints)
            }
            None => {
                violations.push("Endpoints must be declared as a JSON object.".to_string());
                None
            }
        },
    };
    for name in named_entries_that_are_not_objects(endpoints) {
        violations.push(format!(
            "The endpoint {name} must be declared as a JSON object."
        ));
    }

    // Exactly one entry point: the document starts at one endpoint or at one
    // rule, never at both and never at neither.
    let start_endpoint = root
        .get("StartEndpoint")
        .and_then(serde_json::Value::as_str);
    let start_rule = root.get("StartRule").and_then(serde_json::Value::as_str);
    if matches!((start_endpoint, start_rule), (Some(_), Some(_)) | (None, None)) {
        violations.push(
            "Either StartRule or StartEndpoint must be declared, but not both".to_string(),
        );
    }

    // An entry point names the endpoint or rule the document starts at, so the
    // document has to declare the one it names. A block that is not an object
    // declares nothing, and has already been reported as the fault it is, so
    // the reference is checked against the entries the document really
    // declares.
    let undeclared_start_endpoint = start_endpoint
        .filter(|name| endpoints.is_some_and(|endpoints| !endpoints.contains_key(*name)));
    if let Some(name) = undeclared_start_endpoint {
        violations.push(format!(
            "StartEndpoint {name} does not reference a declared endpoint."
        ));
    }
    let rules = match root.get("Rules") {
        None => None,
        Some(value) => match value.as_object() {
            Some(rules) => Some(rules),
            None => {
                violations.push("Rules must be declared as a JSON object.".to_string());
                None
            }
        },
    };
    for name in named_entries_that_are_not_objects(rules) {
        violations.push(format!("The rule {name} must be declared as a JSON object."));
    }
    let undeclared_start_rule =
        start_rule.filter(|name| rules.is_none_or(|rules| !rules.contains_key(*name)));
    if let Some(name) = undeclared_start_rule {
        violations.push(format!(
            "StartRule {name} does not reference a declared rule."
        ));
    }

    match record_type {
        // A document that declares a record type the service supports and
        // breaks nothing else IS the policy's record type; anything else is the
        // refusal, which always carries at least one clause — the record-type
        // clause this last arm appends when the type itself is the fault.
        Some(record_type) if violations.is_empty() => Ok(record_type),
        Some(_) => Err(violations),
        None => {
            // The record-type clause is the LAST one reported, whatever else
            // the document breaks.
            violations.push(RECORD_TYPE_CLAUSE.to_string());
            Err(violations)
        }
    }
}

/// The ONE clause a traffic policy document whose `RecordType` the format does
/// not accept is refused with.
///
/// One clause for BOTH ways the constraint is broken — the member is absent, or
/// it names something that is not a DNS record type a traffic policy can create
/// — because the constraint is that the document declares a record type the
/// service supports, and the sentence states exactly that; which of the two it
/// was is visible in the document the caller submitted. It is reported after
/// every other clause the document earns.
const RECORD_TYPE_CLAUSE: &str = "Policy RecordType is missing or not supported.";

/// The names of the entries of a traffic policy document's `Endpoints` or
/// `Rules` block that are not themselves JSON objects: both blocks map a name
/// to a definition, so an entry that is not an object defines nothing. Every
/// such entry is its OWN violated constraint, so every one is named.
fn named_entries_that_are_not_objects(
    entries: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Vec<&String> {
    entries
        .into_iter()
        .flatten()
        .filter(|(_, definition)| !definition.is_object())
        .map(|(name, _)| name)
        .collect()
}

/// The endpoint host a `Location` URL falls back to when the request carried no
/// `Host` header to build one from.
const DEFAULT_ENDPOINT_HOST: &str = "route53.amazonaws.com";

/// The absolute URL of a resource a create answers with, as its `Location`
/// carries it.
///
/// Built from the endpoint the caller actually addressed, so the URL it gets
/// back is one it can follow; `path` is the resource's path BELOW the API
/// version prefix (`hostedzone/<id>`, `trafficpolicy/<id>/<version>`) — the
/// same path the operation that reads the resource back is bound to. One
/// helper, so two creates cannot word the same URL differently.
pub fn resource_location(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    path: &str,
) -> String {
    let host = ctx
        .parts()
        .headers
        .get(::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_ENDPOINT_HOST);
    format!("https://{host}/2013-04-01/{path}")
}

/// The ARN of the CIDR collection `id`, as `CidrCollection$Arn` reports it.
///
/// Route 53 is a global service, so its resource ARNs name no region; the
/// account is the one every ARN this emulator mints carries
/// ([`::engine::emulator_arn`]). The resource half is the collection's own
/// `cidrcollection/<id>`, which is what makes the ARN usable "to reference the
/// collection in IAM policy or in another Amazon Web Services account"
/// (`CidrCollection$Arn`).
pub fn cidr_collection_arn(id: &str) -> String {
    ::engine::emulator_arn(ARN_SERVICE, "", &format!("cidrcollection/{id}"))
}

/// The service segment of every ARN this service mints, which is this service's
/// own name in an ARN.
const ARN_SERVICE: &str = "route53";

/// The modelled `VPCAssociationAuthorizationNotFound` (HTTP 404) for a
/// `(hosted zone, VPC)` pair the zone's authorization ledger does not hold.
///
/// REQUEST-DERIVED, and worded for the LEDGER it reports on: an authorization
/// entry is identified by the VPC's id together with the region that VPC was
/// created in, so the refusal names the zone, the id and the region the request
/// asked about and states that no authorization exists for them — which is what
/// tells a caller "this VPC was never authorized for this zone" apart from "this
/// association attempt is not authorized". The zone id is reported BARE, as
/// [`normalize_zone_id`] resolves it, for the same reason
/// [`no_such_hosted_zone`] reports it bare.
pub fn vpc_association_authorization_not_found(
    requested_zone_id: &str,
    vpc_id: &str,
    vpc_region: &str,
) -> VPCAssociationAuthorizationNotFound {
    VPCAssociationAuthorizationNotFound {
        message: Some(format!(
            "No authorization exists for hosted zone: {} and vpc: {vpc_id}, {vpc_region}",
            normalize_zone_id(requested_zone_id)
        )),
    }
}

/// The modelled `ConflictingDomainExists` (HTTP 400) for an association that
/// would leave one VPC resolving one DNS name through two hosted zones.
///
/// Built from the request plus the conflict the store resolved: the VPC's id and
/// the region it was created in come from the request, and
/// `conflicting_zone_id` is the zone ALREADY associated with that VPC under the
/// same name. The conflicting zone's id is the actionable half — the caller
/// already knows the name it asked for, and what it does not know is which zone
/// holds the VPC — so the refusal names the zone rather than the name.
pub fn conflicting_domain_exists(
    vpc_id: &str,
    vpc_region: &str,
    conflicting_zone_id: &str,
) -> ConflictingDomainExists {
    ConflictingDomainExists {
        message: Some(format!(
            "The VPC {vpc_id} in region {vpc_region} has already been associated with the hosted \
             zone {conflicting_zone_id} with the same domain name."
        )),
    }
}

/// The modelled `InvalidPaginationToken` (HTTP 400) for a `NextToken` that
/// identifies no page of results.
///
/// The ONE place this service words that refusal, so every paginated operation
/// answers a token it did not mint identically. REQUEST-DERIVED from the token
/// ALONE: the sentence names the token that arrived and makes no claim about
/// what a token stands for, because what a token encodes is the service's own
/// business and a caller can only act on which token it sent.
pub fn invalid_pagination_token(token: &str) -> InvalidPaginationToken {
    InvalidPaginationToken {
        message: Some(format!("Invalid pagination token: {token}")),
    }
}

/// The modelled `NoSuchCidrCollectionException` (HTTP 404) for a collection id
/// that names no CIDR collection in this store.
///
/// The ONE place this service words that refusal, so every collection-addressed
/// operation answers a missing collection identically. It carries NO message at
/// all: the error CODE is the whole of what Route 53 says about a collection it
/// does not hold, so a client reads the class and the collection id it sent —
/// which is the one thing the request named.
pub fn no_such_cidr_collection() -> NoSuchCidrCollectionException {
    NoSuchCidrCollectionException { message: None }
}

/// The modelled `NoSuchHostedZone` (HTTP 404) for a zone id that names no zone
/// in this store.
///
/// The ONE place this service words that refusal, so every zone-addressed
/// operation answers a missing zone identically. The message is
/// REQUEST-DERIVED — it names the zone id the request asked about — which is
/// what lets a caller tell which of a batch of ids was the missing one:
/// `No hosted zone found with ID: <the requested id>`. The id is reported BARE,
/// as [`normalize_zone_id`] resolves it, because the bare id and the
/// `/hostedzone/`-prefixed form a response hands back name the same zone and the
/// refusal reports the zone that was looked for, not the spelling it arrived in.
pub fn no_such_hosted_zone(requested_id: &str) -> NoSuchHostedZone {
    NoSuchHostedZone {
        message: Some(missing_hosted_zone_message(requested_id)),
    }
}

/// The modelled `HostedZoneNotFound` (HTTP 400) for a zone id that names no
/// zone in this store.
///
/// A DIFFERENT shape from [`no_such_hosted_zone`] — the one
/// `CreateReusableDelegationSet` declares for the zone its `HostedZoneId` names
/// — reporting the same thing, so it is worded by the same rule and through the
/// same sentence: request-derived, naming the bare zone id that was looked for.
pub fn hosted_zone_not_found(requested_id: &str) -> HostedZoneNotFound {
    HostedZoneNotFound {
        message: Some(missing_hosted_zone_message(requested_id)),
    }
}

/// The one sentence this service reports a zone id that names no zone with,
/// whichever modelled shape carries it.
fn missing_hosted_zone_message(requested_id: &str) -> String {
    format!(
        "No hosted zone found with ID: {}",
        normalize_zone_id(requested_id)
    )
}

/// The modelled `NoSuchDelegationSet` for an id that names no reusable
/// delegation set in this store.
///
/// The ONE place this service words that refusal, beside
/// [`no_such_hosted_zone`], so every operation that takes a delegation set id —
/// the delegation-set reads and writes and the hosted-zone operations that name
/// one — answers a missing set identically. The message is ENTIRELY
/// request-derived and carries no fixed text at all: Route 53 reports a
/// delegation set id that resolves to nothing as that id alone, in its bare
/// form, however the request spelled it.
pub fn no_such_delegation_set(requested_id: &str) -> NoSuchDelegationSet {
    NoSuchDelegationSet {
        message: Some(normalize_delegation_set_id(requested_id).to_string()),
    }
}

/// The modelled `NoSuchChange` (HTTP 404) for a change id that names no change
/// in this store.
///
/// The ONE place this service words that refusal, beside
/// [`no_such_hosted_zone`]. Route 53 reports an id that resolves to no change
/// through its generic resource-lookup wording, built FROM the request — it
/// names the id the request asked about, as the request wrote it:
/// `Could not find resource with ID: <the requested id>`.
pub fn no_such_change(requested_id: &str) -> NoSuchChange {
    NoSuchChange {
        message: Some(format!("Could not find resource with ID: {requested_id}")),
    }
}

/// The modelled `NoSuchHealthCheck` (HTTP 404) for a health-check id that names
/// no health check in this store.
///
/// The ONE place this service words that refusal, beside
/// [`no_such_hosted_zone`] and [`no_such_change`], so every health-check-addressed
/// operation answers a missing health check identically. The message is
/// REQUEST-DERIVED and has one variable part: Route 53 states the fact about the
/// id the request asked about, as the request wrote it, in the fixed form
/// `A health check with id <id> does not exist.` — which is what lets a caller
/// tell a missing health check apart from the other refusals that share this
/// status, and read back which of a batch of ids was the missing one. The error
/// shape's own documentation states the RULE the refusal reports, not the
/// sentence it reports it in, so the sentence is not built from it.
pub fn no_such_health_check(requested_id: &str) -> NoSuchHealthCheck {
    NoSuchHealthCheck {
        message: Some(format!(
            "A health check with id {requested_id} does not exist."
        )),
    }
}

/// Mint the request id ONE response names the request it answers with — the
/// `RequestId` element of this service's `<ErrorResponse>` envelope (see
/// [`crate::service::envelope`]).
///
/// 8-4-4-4-12 lowercase hex, the form an AWS request id takes. The VALUE is
/// per-response and is not a requirement: nothing can predict it and no caller
/// may depend on a particular one. What it must do is name ONE response, so it
/// is drawn from a per-process counter mixed with the instant the response was
/// answered through the maintained `sha2` digest — the counter is what makes two
/// ids minted in the same nanosecond differ, and the instant is what keeps two
/// runs of this emulator from minting the same sequence. It is an identifier for
/// correlation, never a secret: nothing authenticates with it.
///
/// A free function rather than a mint on the store: a failure the request
/// boundary refused never reaches a handler, so the envelope that answers it has
/// no state to reach.
pub fn new_request_id() -> String {
    use sha2::{Digest, Sha256};

    static MINTED: AtomicU64 = AtomicU64::new(0);

    let counter = MINTED.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since_epoch| since_epoch.as_nanos());
    let mut digest = Sha256::new();
    digest.update(counter.to_be_bytes());
    digest.update(nanos.to_be_bytes());
    let hex: String = digest.finalize()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Whether `vpc_id` has the form of an Amazon VPC id.
///
/// A VPC id is the literal `vpc-` followed by the resource's lowercase
/// hexadecimal identifier — 8 characters in the original form, 17 in the long
/// form issued today — and nothing else names a VPC. `InvalidVPCId`'s own
/// documentation is the refusal for anything else: "The VPC ID that you
/// specified either isn't a valid ID or the current account is not authorized
/// to access this VPC."
pub fn vpc_id_is_well_formed(vpc_id: &str) -> bool {
    let Some(body) = vpc_id.strip_prefix("vpc-") else {
        return false;
    };
    matches!(body.len(), 8 | 17)
        && body
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `region` is one of the regions the model's `VPCRegion` enum names.
///
/// `VPC$VPCRegion` targets that enum, so a value outside it names no region a
/// VPC can have been created in.
pub fn vpc_region_is_modelled(region: &str) -> bool {
    V_P_C_REGION_VALUES.contains(&region)
}

/// A hosted-zone id with the `/hostedzone/` prefix stripped, so a caller may
/// pass either the bare id or the prefixed `Id` a response handed it back.
pub fn normalize_zone_id(id: &str) -> &str {
    strip_id_prefix(id, "hostedzone")
}

/// A change id with the `/change/` prefix stripped, for the same reason
/// [`normalize_zone_id`] strips `/hostedzone/`.
pub fn normalize_change_id(id: &str) -> &str {
    strip_id_prefix(id, "change")
}

/// A reusable delegation set id with the `/delegationset/` prefix stripped, for
/// the same reason [`normalize_zone_id`] strips `/hostedzone/`.
pub fn normalize_delegation_set_id(id: &str) -> &str {
    strip_id_prefix(id, "delegationset")
}

/// Strip a leading `/`, then a leading `<collection>/`, from a resource id.
fn strip_id_prefix<'a>(id: &'a str, collection: &str) -> &'a str {
    let without_slash = id.strip_prefix('/').unwrap_or(id);
    without_slash
        .strip_prefix(collection)
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or(without_slash)
}

/// The id generator behind every minted zone and change id.
///
/// A plain xorshift64 sequence, seeded from the wall clock on first use: ids
/// have to be unique and opaque, not cryptographically unpredictable, and
/// keeping the generator in the state struct is what makes them unique ACROSS
/// calls rather than per handler.
#[derive(Debug, Default)]
struct IdMinter {
    seed: u64,
}

impl IdMinter {
    /// The alphabet Route 53 ids are drawn from: uppercase letters and digits.
    const ALPHABET: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    fn next_u64(&mut self) -> u64 {
        if self.seed == 0 {
            // Any non-zero seed will do; the clock keeps two emulator runs from
            // minting the same first id. The constant is the fallback for a
            // clock that reads before the epoch.
            self.seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0x2545_F491_4F6C_DD1D, |d| d.as_nanos() as u64)
                | 1;
        }
        let mut x = self.seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.seed = x;
        x
    }

    /// 8-4-4-4-12 lowercase hex, the form of the ids Route 53 mints for the
    /// resources it does not give a letter-prefixed id (a traffic policy).
    fn mint_uuid(&mut self) -> String {
        let hex = format!("{:016x}{:016x}", self.next_u64(), self.next_u64());
        format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        )
    }

    /// `prefix` followed by `len` characters from [`IdMinter::ALPHABET`].
    fn mint(&mut self, prefix: char, len: usize) -> String {
        // OnCallWorlds patch: an id the seed pinned for this setup call.
        if let Some(id) = ocw_clock::take_pinned(prefix.encode_utf8(&mut [0; 4])) {
            return id;
        }
        let mut id = String::with_capacity(len + 1);
        id.push(prefix);
        for _ in 0..len {
            let pick = (self.next_u64() % Self::ALPHABET.len() as u64) as usize;
            id.push(char::from(Self::ALPHABET[pick]));
        }
        id
    }
}

/// This service's store in the shared engine: call it with a handler's `&*self.engine`.
///
/// Answer `None` with a modelled server error, never with a fresh engine.
pub fn service_state<Eng: Send + Sync + 'static>(
    engine: &Eng,
) -> Option<::engine::ServiceState<ComAmazonawsRoute53Awsdnsv20130401State>> {
    (engine as &dyn ::std::any::Any)
        .downcast_ref::<::engine::InMemoryEngine>()
        .map(::engine::InMemoryEngine::state::<ComAmazonawsRoute53Awsdnsv20130401State>)
}
