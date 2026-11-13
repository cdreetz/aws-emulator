// SPDX-License-Identifier: CC0-1.0

//! Engine state for the com-amazonaws-elasticloadbalancingv2-elasticloadbalancing-v10 service.
//!
//! Everything the ELBv2 provisioning loop persists lives in the ONE guarded
//! [`ComAmazonawsElasticloadbalancingv2ElasticloadbalancingV10State`] value, so every
//! handler in this crate sees the same store across requests: load balancers, their
//! listeners, target groups and the targets registered with them, and the trust
//! stores a mutual-TLS listener authenticates against.
//!
//! Records are the service's own storage shape; each one converts to its modelled
//! Smithy shape through a `to_shape` method, so a describe answers exactly what the
//! create persisted instead of re-deriving it.
//!
//! One set of facts a request is resolved against is NOT this service's: the account's
//! VPCs, subnets, security groups and instances. [`network`] resolves those against EC2,
//! which owns them.
//!
//! And two facts this service's resources create are read by ANOTHER service: a
//! TLS-terminating listener presents a certificate Certificate Manager holds, so which
//! certificates a load balancer presents is recorded in the shared directory that service
//! reads ([`certificate_consumers`]); and a load balancer with zonal-shift integration
//! enabled is a managed resource of Amazon Application Recovery Controller, which is
//! recorded in the shared registry that service reads
//! ([`zonal_shift_registration`]).

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, SystemTime};

pub mod network;

/// Which Certificate Manager certificates a load balancer presents, recorded where the
/// service that holds those certificates can read it.
mod certificate_consumers;

pub use certificate_consumers::{certificate_association_directory, record_certificate_consumers};

/// Whether a load balancer is a managed resource of Amazon Application Recovery
/// Controller, recorded where the service that reports managed resources can read it.
mod zonal_shift_registration;

pub use zonal_shift_registration::{
    managed_resource_registry, record_zonal_shift_registration, ZonalShiftRegistration,
    ZonePlacement, ZONAL_SHIFT_ATTRIBUTE,
};

/// The unit tests of [`network`]'s pure half — where an address falls relative to a VPC.
#[cfg(test)]
mod vpc_topology;

/// The page walk every paginated read of this service shares, and the opaque `NextMarker`
/// it hands back.
pub mod pagination;

pub use pagination::{paginate, PageError, PageTokenKey, PagedCollection};

/// What a redirect action's target URI is read as, and what makes one an action this
/// service refuses.
///
/// Public because the data plane that RENDERS a redirect reads the same reserved keywords
/// (`crate::service::data_plane`).
pub mod rule_actions;

pub use rule_actions::{check_redirect_actions, redirects_to_itself, REDIRECT_LOOP_MESSAGE};

/// The health state machine of a target group's registrations: the states a read reports
/// and the two spans the clock owes a registration.
pub mod target_health;

pub use target_health::{
    deregistration_delay, SchedulerRegistration, ServedPorts, TargetProbe,
    DEREGISTRATION_DELAY_ATTRIBUTE,
};

/// Whether the security groups of a target's own network interface let a health check of it
/// arrive at all.
pub mod health_check_firewall;

pub use health_check_firewall::{interface_admits_check, CheckSource, GuardingGroups};

/// The periodic health check of the registrations a load balancer routes to, and the
/// host-count series that check is published as.
pub mod host_counts;

pub use host_counts::{check_registrations, drive_host_count_metrics, HostCountPublisher};

/// The load balancer's OWN network interfaces, which live in the inventory EC2 holds.
pub mod service_interfaces;

pub use service_interfaces::{
    apply_load_balancer_security_groups, place_load_balancer_interfaces,
    reconcile_load_balancer_interfaces, release_load_balancer_interfaces,
};

/// What this store released WITH ITS CONTAINER, which is what makes a delete of it
/// idempotent.
pub mod cascaded_releases;

pub use cascaded_releases::CascadedReleases;

/// The TRUST-STORE half of this store: the associations a trust store derives from the
/// listeners that authenticate against it, and the wording its refusals share.
pub mod trust_stores;

pub use trust_stores::{
    delete_association_same_account_message, duplicate_trust_store_name_message,
    too_many_trust_stores_message, trust_store_active_at, trust_store_arn_not_found_message,
    trust_store_association_not_found_message, trust_store_in_use_message,
    trust_store_name_not_found_message, TRUST_STORE_QUOTA,
};

/// Where a trust store's CA certificates come from: the Amazon S3 object a create or a
/// modification names, and what reading it established.
pub mod ca_certificates_bundle;

pub use ca_certificates_bundle::{
    ca_certificates_in, counted_ca_certificates, resolve_ca_certificates_bundle,
    CaCertificatesBundle, CaCertificatesBundleLocation, CaCertificatesBundleRefusal,
    CA_CERTIFICATES_BUNDLE_NOT_FOUND_MESSAGE, INVALID_CA_CERTIFICATES_BUNDLE_MESSAGE,
};

/// Whether the two members that TIME a target group's health check fit together, read
/// once for every operation that writes a health check.
pub mod health_check_schedule;

pub use health_check_schedule::{check_health_check_schedule, HEALTH_CHECK_SCHEDULE_MESSAGE};

/// The ADDRESS a load balancer publishes as its `DNSName`, and the socket of this
/// emulator's own that answers there.
pub mod load_balancer_endpoint;

pub use load_balancer_endpoint::{
    certificate_key_material_directory, open_load_balancer_endpoint, LoadBalancerEndpoint,
};

use crate::ops::types::{
    Action, AvailabilityZone, Certificate, ForwardActionConfig, IpamPools, Listener,
    ListenerAttribute, LoadBalancer, LoadBalancerAddress, LoadBalancerAttribute, LoadBalancerState,
    Matcher, MutualAuthenticationAttributes, Rule, RuleCondition, RuleTransform, SubnetMapping,
    TargetGroup, TargetGroupAttribute, TargetGroupTuple, TrustStore,
};

/// How long after the call that starts it a load balancer owes its move out of
/// `provisioning`, and a freshly registered target its move out of `initial`.
///
/// A chosen span (AWS takes minutes): the emulator only has to make the transient
/// state observable to a caller acting straight after the call, so it is inside the
/// 250–750 ms band the project fixes for a clock-owed transition. The due instant is
/// stored on the record; nothing ever sleeps for it.
pub const SETTLE_AFTER: Duration = Duration::from_millis(500);

/// The default region for a request that carries no SigV4 credential scope to read
/// one from.
pub const DEFAULT_REGION: &str = "us-east-1";

/// How many capacity units one request can ask `ModifyCapacityReservation` to reserve for
/// a load balancer before it refuses with the modelled
/// `CapacityUnitsLimitExceededException`.
///
/// The per-Region default Elastic Load Balancing publishes for the capacity units of one
/// load balancer, which `DescribeAccountLimits` reports under
/// `application-load-balancer-capacity-units` — and under the Network and Gateway Load
/// Balancer names beside it, at the same number, so one constant serves every family and
/// the bound does not depend on which load balancer the request names. Reported there and
/// enforced here, so the number a caller reads is the number it hits.
pub const CAPACITY_UNITS_PER_LOAD_BALANCER: i32 = 3_000;

/// How many capacity-reservation DECREASES an account may make for one load balancer in a
/// day, which is the allowance `DecreaseRequestsRemaining` ("the amount of daily capacity
/// decreases remaining") counts down from.
///
/// The figure the "Elastic Load Balancing endpoints and quotas" tables publish for
/// capacity-reservation decreases per load balancer per day — a quota of the service, like
/// [`CAPACITY_UNITS_PER_LOAD_BALANCER`] above, not a number taken from any one call. It is
/// an allowance of the DAY rather than of a reservation, so it is reported for every load
/// balancer — including one that reserves no minimum capacity and so has nothing to
/// decrease yet.
///
/// Nothing in this emulator spends it: a decrease lowers a minimum capacity already
/// reserved, and reserving one is what `ModifyCapacityReservation` refuses for this
/// account, so the whole allowance is what every read reports.
pub const DAILY_CAPACITY_DECREASES: i32 = 2;

/// How many load balancers this store holds before `CreateLoadBalancer` refuses with
/// the modelled `TooManyLoadBalancersException`.
///
/// AWS publishes an adjustable per-account, per-Region quota, and this emulator models
/// neither Service Quotas nor an account's adjustments — so this is the emulator's OWN
/// bound on the store rather than a claim about any account's limit. It is far above any
/// workflow an emulator serves, and it is what stops the store growing without end:
/// every record it holds is released by `DeleteLoadBalancer`.
pub const LOAD_BALANCER_QUOTA: usize = 1_000;

/// How many target groups this store holds before `CreateTargetGroup` refuses with the
/// modelled `TooManyTargetGroupsException`. The emulator's own bound, as
/// [`LOAD_BALANCER_QUOTA`].
pub const TARGET_GROUP_QUOTA: usize = 1_000;

/// How many listeners one load balancer carries before `CreateListener` refuses with
/// the modelled `TooManyListenersException`. The emulator's own bound, as
/// [`LOAD_BALANCER_QUOTA`]; a listener exists only under a load balancer, so the
/// listener store is bounded by this times [`LOAD_BALANCER_QUOTA`], and deleting a load
/// balancer releases its listeners.
pub const LISTENERS_PER_LOAD_BALANCER: usize = 100;

/// How many rules one load balancer carries across its listeners before `CreateRule`
/// refuses with the modelled `TooManyRulesException`: the published default
/// `DescribeAccountLimits` reports as `rules-per-application-load-balancer` (and as
/// `rules-per-network-load-balancer`), which counts the rules a caller added and not the
/// default rule every listener carries.
///
/// A rule exists only under a listener, so the store's rules are bounded by this times
/// [`LOAD_BALANCER_QUOTA`], and deleting a listener or its load balancer releases them.
pub const RULES_PER_LOAD_BALANCER: usize = 100;

/// How many values one condition of a rule carries, from the published default
/// `DescribeAccountLimits` reports as `condition-values-per-alb-rule`.
pub const CONDITION_VALUES_PER_RULE: usize = 5;

/// How many CONDITIONS one rule carries — a bound of its own, beside the number of VALUES
/// those conditions match on ([`CONDITION_VALUES_PER_RULE`]).
///
/// Elastic Load Balancing states this bound in the refusal itself ("You can specify up to
/// 5 conditions"), which is the only place it is published: no `DescribeAccountLimits`
/// name carries it, so a rule's condition COUNT is judged against this number and its
/// condition VALUES against the quota beside it.
pub const CONDITIONS_PER_RULE: usize = 5;

/// How many targets one target group of an APPLICATION Load Balancer holds before
/// `RegisterTargets` refuses with the modelled `TooManyTargetsException`: the per-Region
/// default Elastic Load Balancing publishes for "targets per target group", which
/// `DescribeAccountLimits` reports under that name. Registrations live on their target
/// group, so the store's targets are bounded by this times [`TARGET_GROUP_QUOTA`].
pub const TARGETS_PER_TARGET_GROUP: usize = 1_000;

/// How many targets one target group of a NETWORK Load Balancer holds, from the published
/// default `DescribeAccountLimits` reports as
/// `targets-per-availability-zone-per-network-load-balancer`.
///
/// AWS publishes that number PER Availability Zone, and this emulator models no per-zone
/// accounting, so it is applied to the group as a whole: an approximation that is never
/// more permissive than the published quota, and the number a caller reads for that name.
pub const TARGETS_PER_NETWORK_TARGET_GROUP: usize = 500;

/// How many targets one target group of a GATEWAY Load Balancer holds, from the published
/// default `DescribeAccountLimits` reports as
/// `targets-per-availability-zone-per-gateway-load-balancer`, applied to the group as a
/// whole for the reason [`TARGETS_PER_NETWORK_TARGET_GROUP`] gives.
pub const TARGETS_PER_GATEWAY_TARGET_GROUP: usize = 300;

/// How many targets a target group whose targets are not addressed by the load balancer
/// at all holds: ONE.
///
/// A `lambda` target group carries a single function (`TargetGroup$TargetType`: "lambda -
/// Register a single Lambda function as a target") and an `alb` one a single Application
/// Load Balancer ("alb - Register a single Application Load Balancer as a target").
pub const TARGETS_PER_SINGLETON_TARGET_GROUP: usize = 1;

/// How many targets `group` holds before `RegisterTargets` refuses the registration that
/// would exceed it, which is the quota of the load balancer family the group serves — see
/// [`TARGETS_PER_TARGET_GROUP`], [`TARGETS_PER_NETWORK_TARGET_GROUP`],
/// [`TARGETS_PER_GATEWAY_TARGET_GROUP`] and [`TARGETS_PER_SINGLETON_TARGET_GROUP`].
pub fn targets_per_target_group(group: &TargetGroupRecord) -> usize {
    if matches!(group.target_type.as_str(), "lambda" | "alb") {
        return TARGETS_PER_SINGLETON_TARGET_GROUP;
    }
    match group.family() {
        LoadBalancerFamily::Application => TARGETS_PER_TARGET_GROUP,
        LoadBalancerFamily::Network => TARGETS_PER_NETWORK_TARGET_GROUP,
        LoadBalancerFamily::Gateway => TARGETS_PER_GATEWAY_TARGET_GROUP,
    }
}

/// The prefix every EC2 instance id carries, which is what a target of an `instance`
/// target group is written as.
const INSTANCE_ID_PREFIX: &str = "i-";

/// The lengths an EC2 instance id's hexadecimal part has: AWS writes an instance id as
/// `i-` and either 8 or 17 hexadecimal characters, and a value of any other length is no
/// instance id at all.
const INSTANCE_ID_DIGITS: [usize; 2] = [8, 17];

/// A Lambda function's ARN, which is what a target of a `lambda` target group is written
/// as (`TargetDescription$Id`: "if the target type is lambda, specify the ARN of the
/// Lambda function").
const LAMBDA_FUNCTION: ::service_common::arn::Requirement = ::service_common::arn::Requirement {
    vendor: "lambda",
    resource_type: Some("function"),
    label: "a Lambda function ARN",
};

/// An Application Load Balancer's ARN, which is what a target of an `alb` target group is
/// written as (`TargetDescription$Id`: "if the target type is alb, specify the ARN of the
/// Application Load Balancer target").
const LOAD_BALANCER_TARGET: ::service_common::arn::Requirement =
    ::service_common::arn::Requirement {
        vendor: SERVICE_NAMESPACE,
        resource_type: Some("loadbalancer"),
        label: "an Application Load Balancer ARN",
    };

/// Whether `id` is written the way a target of a `target_type` target group is written,
/// and — when it is not — the rule it broke.
///
/// What a target id NAMES depends on the group's target type, and `TargetDescription$Id`
/// states the form for each: "if the target type of the target group is instance, specify
/// an instance ID. If the target type is ip, specify an IP address. If the target type is
/// lambda, specify the ARN of the Lambda function. If the target type is alb, specify the
/// ARN of the Application Load Balancer target." A value of none of those forms names no
/// target of ANY account — it is the request that has to be fixed rather than a target the
/// service could not find — so the operation that carries it refuses with this service's
/// `ValidationError`, before anything is resolved against the service that owns the
/// target.
///
/// An `ip` target's form is read by [`network::parse_ip_target`], which answers the
/// address itself, so it is not restated here; the model puts no form on an id this
/// service does not resolve at all.
pub fn check_target_id(target_type: &str, id: &str) -> Result<(), String> {
    let refuse = |form: &str| Err(format!("'{id}' in Targets is not {form}"));
    match target_type {
        "instance" => {
            let digits = id.strip_prefix(INSTANCE_ID_PREFIX).unwrap_or_default();
            if !INSTANCE_ID_DIGITS.contains(&digits.len())
                || !digits
                    .chars()
                    .all(|digit| digit.is_ascii_digit() || ('a'..='f').contains(&digit))
            {
                return refuse("an instance ID");
            }
            Ok(())
        }
        "lambda" if !LAMBDA_FUNCTION.admits(id) => refuse(LAMBDA_FUNCTION.label),
        "alb" if !LOAD_BALANCER_TARGET.admits(id) => refuse(LOAD_BALANCER_TARGET.label),
        _ => Ok(()),
    }
}

/// The message a registration naming instance ids EC2 holds no instance for is refused
/// with: the ids it could not resolve, each quoted, in the order the request named them.
///
/// Elastic Load Balancing words this refusal about the TARGETS of the request — the ids are
/// what the caller corrects — and states nothing about the target group or the account.
pub fn invalid_instance_targets_message<'a>(ids: impl IntoIterator<Item = &'a str>) -> String {
    let quoted: Vec<String> = ids.into_iter().map(|id| format!("'{id}'")).collect();
    format!(
        "The following targets are not valid instances: {}",
        quoted.join(", ")
    )
}

/// How many tags one Elastic Load Balancing resource carries before a tag write refuses
/// with the modelled `TooManyTagsException`: the maximum number of tags per resource
/// Elastic Load Balancing publishes in its tag restrictions (50), which applies to every
/// taggable kind alike.
///
/// Tags live on the record of the resource they are on, so what the store holds for them
/// is bounded by this times the resource quotas above.
pub const TAGS_PER_RESOURCE: usize = 50;

/// The message a tag write past [`TAGS_PER_RESOURCE`] is refused with, for every
/// operation that answers the modelled `TooManyTagsException`.
///
/// Elastic Load Balancing words this refusal as a FIXED sentence about the resource: it
/// states neither the quota nor the count the request carried, so nothing of the request
/// is interpolated into it.
pub const TOO_MANY_TAGS_MESSAGE: &str = "The specified resource contains too many tags";

/// The message a tag write that names one key twice is refused with, stated once for every
/// operation that takes a `Tags` list.
///
/// `DuplicateTagKeysException` is documented "A tag key was specified more than once", and a
/// list that names a key twice does not say which value that key takes — so the refusal
/// names the key FROM THE REQUEST and states the rule it broke: a tag key carries exactly
/// one value.
pub fn duplicate_tag_key_message(key: &str) -> String {
    format!("Tag key '{key}' has two values, but tag keys must have exactly one value")
}

/// The ARN/endpoint namespace for this service (`sigv4Name` / `arnNamespace` in the
/// model's `aws.api#service` trait).
pub const SERVICE_NAMESPACE: &str = "elasticloadbalancing";

/// The region this request was signed for, which is the region every ARN and DNS
/// name minted while serving it belongs to.
pub fn request_region(ctx: &smithy_server_runtime::OperationContext<'_>) -> String {
    emulator_server::sigv4_credential_scope(&ctx.parts().headers)
        .map(|scope| scope.region)
        .unwrap_or_else(|| DEFAULT_REGION.to_string())
}

/// One availability zone a load balancer is attached to, as the subnet that put it
/// there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AvailabilityZoneRecord {
    pub zone_name: String,
    pub subnet_id: String,
    pub outpost_id: Option<String>,
    pub addresses: Vec<LoadBalancerAddressRecord>,
}

impl AvailabilityZoneRecord {
    /// This zone as the modelled shape, which `DescribeLoadBalancers` reports and
    /// `SetSubnets` answers with.
    pub fn to_shape(&self) -> AvailabilityZone {
        AvailabilityZone {
            zone_name: Some(self.zone_name.clone()),
            subnet_id: Some(self.subnet_id.clone()),
            outpost_id: self.outpost_id.clone(),
            load_balancer_addresses: Some(self.addresses.iter().map(|a| a.to_shape()).collect()),
            source_nat_ipv6_prefixes: None,
        }
    }
}

/// An address a caller pinned to one of the load balancer's zones through
/// `SubnetMappings`. Only what the caller supplied is kept: the emulator does not
/// model an address pool, so it never invents an `IpAddress`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadBalancerAddressRecord {
    pub allocation_id: Option<String>,
    pub private_ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
}

impl LoadBalancerAddressRecord {
    /// Whether the caller pinned nothing on this address, so there is nothing to
    /// report for the zone.
    pub fn is_empty(&self) -> bool {
        self.allocation_id.is_none()
            && self.private_ipv4_address.is_none()
            && self.ipv6_address.is_none()
    }

    fn to_shape(&self) -> LoadBalancerAddress {
        LoadBalancerAddress {
            ip_address: None,
            allocation_id: self.allocation_id.clone(),
            private_i_pv4_address: self.private_ipv4_address.clone(),
            i_pv6_address: self.ipv6_address.clone(),
        }
    }
}

/// A persisted load balancer.
#[derive(Debug, Clone)]
pub struct LoadBalancerRecord {
    pub arn: String,
    /// The 16-hex id that both the ARN and the DNS name carry.
    pub id: String,
    pub name: String,
    /// The Region the load balancer was created in — the one its ARN and its DNS name
    /// carry, and the one whose published hosted zone a read reports
    /// ([`Self::canonical_hosted_zone_id`]).
    pub region: String,
    pub dns_name: String,
    pub created_time: SystemTime,
    pub scheme: String,
    pub vpc_id: Option<String>,
    pub state_code: String,
    /// When the clock owes this load balancer its move to `active`.
    pub active_at: SystemTime,
    pub lb_type: String,
    pub availability_zones: Vec<AvailabilityZoneRecord>,
    pub security_groups: Vec<String>,
    pub ip_address_type: String,
    pub customer_owned_ipv4_pool: Option<String>,
    /// Whether inbound security group rules are evaluated for PrivateLink traffic, as a
    /// caller last set it through `SetSecurityGroups`. `None` until one does, which is
    /// when the documented default applies
    /// ([`Self::enforce_security_group_inbound_rules_on_private_link_traffic`]).
    pub enforce_security_group_inbound_rules_on_private_link_traffic: Option<String>,
    /// Whether an IPv6 prefix of each subnet is used for source NAT, as `SetSubnets`
    /// last set it. `None` until it does: the member's documented default is `off`.
    pub enable_prefix_for_ipv6_source_nat: Option<String>,
    /// The IPAM pool the load balancer draws its IPv4 addresses from
    /// (`IpamPools$Ipv4IpamPoolId`), as `CreateLoadBalancer` or `ModifyIpPools` last set
    /// it; `None` for a load balancer using no pool.
    pub ipv4_ipam_pool_id: Option<String>,
    /// When a capacity-reservation write last changed this load balancer's reservation,
    /// which `DescribeCapacityReservation` reports as `LastModifiedTime`. `None` until
    /// one does: a load balancer nobody has written a reservation for has no such
    /// instant to report.
    pub capacity_reservation_modified_at: Option<SystemTime>,
    /// The elastic network interfaces this load balancer holds in the account's EC2
    /// inventory, one per subnet it is attached to ([`service_interfaces`]). Empty for a
    /// load balancer placed where there was no inventory to put one in.
    pub network_interface_ids: Vec<String>,
    pub attributes: HashMap<String, String>,
    pub tags: HashMap<String, String>,
    pub listener_arns: Vec<String>,
}

impl LoadBalancerRecord {
    /// The settings `CreateLoadBalancer` is idempotent over: the model documents
    /// that creating the same load balancer twice with the same settings succeeds,
    /// so a repeat call compares these and returns the stored resource.
    pub fn has_settings_of(&self, other: &LoadBalancerRecord) -> bool {
        self.scheme == other.scheme
            && self.lb_type == other.lb_type
            && self.ip_address_type == other.ip_address_type
            && self.customer_owned_ipv4_pool == other.customer_owned_ipv4_pool
            && self.ipv4_ipam_pool_id == other.ipv4_ipam_pool_id
            && self.availability_zones == other.availability_zones
            && sorted(&self.security_groups) == sorted(&other.security_groups)
            && self.tags == other.tags
    }

    pub fn to_shape(&self) -> LoadBalancer {
        LoadBalancer {
            load_balancer_arn: Some(self.arn.clone()),
            dns_name: Some(self.dns_name.clone()),
            canonical_hosted_zone_id: self.canonical_hosted_zone_id(),
            created_time: Some(::aws_smithy_types::DateTime::from(self.created_time)),
            load_balancer_name: Some(self.name.clone()),
            scheme: Some(self.scheme.clone()),
            vpc_id: self.vpc_id.clone(),
            state: Some(LoadBalancerState {
                code: Some(self.state_code.clone()),
                reason: None,
            }),
            r#type: Some(self.lb_type.clone()),
            availability_zones: Some(
                self.availability_zones
                    .iter()
                    .map(AvailabilityZoneRecord::to_shape)
                    .collect(),
            ),
            security_groups: Some(self.security_groups.clone()),
            ip_address_type: Some(self.ip_address_type.clone()),
            customer_owned_ipv4_pool: self.customer_owned_ipv4_pool.clone(),
            enforce_security_group_inbound_rules_on_private_link_traffic: self
                .enforce_security_group_inbound_rules_on_private_link_traffic(),
            enable_prefix_for_ipv6_source_nat: Some(self.enable_prefix_for_ipv6_source_nat()),
            ipam_pools: self.ipam_pools_shape(),
        }
    }

    /// Which family of load balancer this is, which decides the attributes it carries
    /// and the IP address types and security groups it accepts.
    pub fn family(&self) -> LoadBalancerFamily {
        load_balancer_family(&self.lb_type)
    }

    /// The hosted zone a client aliases this load balancer's DNS name through
    /// (`LoadBalancer$CanonicalHostedZoneId`): the one published for the Region the load
    /// balancer is in and the family it belongs to — see [`canonical_hosted_zone_id`].
    pub fn canonical_hosted_zone_id(&self) -> Option<String> {
        canonical_hosted_zone_id(&self.region, self.family()).map(str::to_string)
    }

    /// The IPAM pools this load balancer draws from, as the modelled shape, or `None`
    /// for one that draws from no pool — the member is then left unreported rather than
    /// reported as an empty structure.
    pub fn ipam_pools_shape(&self) -> Option<IpamPools> {
        self.ipv4_ipam_pool_id
            .clone()
            .map(|pool| IpamPools {
                ipv4_ipam_pool_id: Some(pool),
            })
    }

    /// Whether an IPv6 prefix of each subnet is used for source NAT: what a caller set,
    /// else the value the member's own documentation fixes as its default
    /// ([`ENABLE_PREFIX_FOR_IPV6_SOURCE_NAT_DEFAULT`]).
    ///
    /// A member whose documentation states a default is carried AT that default from the
    /// moment the resource exists, so every load balancer reports one and a client reading
    /// it never has to supply the default itself.
    pub fn enable_prefix_for_ipv6_source_nat(&self) -> String {
        self.enable_prefix_for_ipv6_source_nat
            .clone()
            .unwrap_or_else(|| ENABLE_PREFIX_FOR_IPV6_SOURCE_NAT_DEFAULT.to_string())
    }

    /// Whether inbound security group rules are evaluated for PrivateLink traffic: what
    /// a caller set, else the documented default for a load balancer the member applies
    /// to at all.
    ///
    /// `SetSecurityGroupsInput$EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic`:
    /// "Indicates whether to evaluate inbound security group rules for traffic sent to a
    /// Network Load Balancer through Amazon Web Services PrivateLink. Applies only if the
    /// load balancer has an associated security group. The default is on." So it is
    /// reported for a Network Load Balancer carrying a security group, and for no other.
    pub fn enforce_security_group_inbound_rules_on_private_link_traffic(&self) -> Option<String> {
        if let Some(set) = self
            .enforce_security_group_inbound_rules_on_private_link_traffic
            .clone()
        {
            return Some(set);
        }
        (self.family() == LoadBalancerFamily::Network && !self.security_groups.is_empty())
            .then(|| PRIVATE_LINK_INBOUND_RULES_DEFAULT.to_string())
    }

    /// This load balancer's WHOLE attribute collection: every attribute the catalog
    /// carries for a load balancer of this family, each holding what a caller wrote or,
    /// failing that, the value it is carried at — which is what both a read and a write
    /// of these attributes answers with.
    ///
    /// In [`LOAD_BALANCER_ATTRIBUTES`] order, which is the order the service reports
    /// them in, so two reads of one load balancer answer alike.
    pub fn effective_attributes(&self) -> Vec<(String, String)> {
        LOAD_BALANCER_ATTRIBUTES
            .iter()
            .filter(|spec| spec.applies_to(self))
            .filter_map(|spec| {
                let value = self
                    .attributes
                    .get(spec.key)
                    .cloned()
                    .or_else(|| spec.default_for(self))?;
                Some((spec.key.to_string(), value))
            })
            .collect()
    }

    /// [`Self::effective_attributes`] as the modelled shape.
    pub fn attribute_shapes(&self) -> Vec<LoadBalancerAttribute> {
        self.effective_attributes()
            .into_iter()
            .map(|(key, value)| LoadBalancerAttribute {
                key: Some(key),
                value: Some(value),
            })
            .collect()
    }

    /// Whether this load balancer may not be deleted: the value its attribute collection
    /// carries `deletion_protection.enabled` at — an attribute every family has, whose
    /// documentation defaults it to `false`. The catalog is the one source of that value,
    /// here as in the collection.
    pub fn deletion_protection_enabled(&self) -> bool {
        self.attributes
            .get(DELETION_PROTECTION_ATTRIBUTE)
            .cloned()
            .or_else(|| {
                load_balancer_attribute(DELETION_PROTECTION_ATTRIBUTE)
                    .and_then(|spec| spec.default_for(self))
            })
            .as_deref()
            == Some("true")
    }
}

/// The health-check settings of a target group, with every default materialized at
/// create time so a later read reports the same values AWS would.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub protocol: Option<String>,
    pub port: Option<String>,
    pub path: Option<String>,
    pub interval_seconds: i32,
    pub timeout_seconds: i32,
    pub healthy_threshold: i32,
    pub unhealthy_threshold: i32,
    pub matcher: Option<MatcherRecord>,
}

/// The success codes of an HTTP/HTTPS health check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatcherRecord {
    pub http_code: Option<String>,
    pub grpc_code: Option<String>,
}

impl MatcherRecord {
    /// Whether this matcher names a return code at all — an HTTP one or a gRPC one.
    ///
    /// The model gives `Matcher` two optional members (`HttpCode`, `GrpcCode`), so a
    /// matcher carrying neither states no success criterion and is no matcher as far as
    /// a health check is concerned.
    pub fn names_a_return_code(&self) -> bool {
        self.http_code.is_some() || self.grpc_code.is_some()
    }

    fn to_shape(&self) -> Matcher {
        Matcher {
            http_code: self.http_code.clone(),
            grpc_code: self.grpc_code.clone(),
        }
    }
}

/// Whether a layer-7 (HTTP-semantic) health check made of `path` and `matcher` is
/// complete — it has a destination to request and a return code that counts as success —
/// and, when it is not, the rule it broke.
///
/// Both members are documented as belonging to such a check alone (`HealthCheckPath`:
/// "[HTTP/HTTPS health checks] The destination for health checks on the targets";
/// `Matcher`: "[HTTP/HTTPS health checks] The HTTP or gRPC codes to use when checking
/// for a successful response from a target"), and a check that requests nothing, or
/// accepts no response as success, cannot be evaluated at all. Only a path for the load
/// balancer to request and a code to compare its answer against make one, so the two are
/// required TOGETHER of any configuration that is not filling their documented defaults.
///
/// The message states the rule rather than the request, because neither member is
/// identified by a value the caller sent: what is missing is a member, not a bad value.
pub fn check_layer_7_health_check(
    path: Option<&str>,
    matcher: Option<&MatcherRecord>,
) -> Result<(), String> {
    if path.is_some() && matcher.is_some_and(MatcherRecord::names_a_return_code) {
        return Ok(());
    }
    Err("Path and return code are required for layer 7 health checks.".to_string())
}

/// The path an HTTP-semantic health check checks when the request names none, from
/// `HealthCheckPath`'s own documentation: "[HTTP1 or HTTP2 protocol version] The ping
/// path. The default is /. [GRPC protocol version] The path of a custom health check
/// method with the format /package.service/method. The default is
/// /AWS.ALB/healthcheck."
pub fn default_health_check_path(protocol_version: Option<&str>) -> String {
    if protocol_version == Some("GRPC") {
        "/AWS.ALB/healthcheck".to_string()
    } else {
        "/".to_string()
    }
}

/// The response codes an HTTP-semantic health check accepts when the request names
/// none: the gRPC success code `12` for a gRPC target group, else the default
/// `Matcher$HttpCode` documents for the load balancer family the group serves — "For
/// Application Load Balancers, you can specify values between 200 and 499, with the
/// default value being 200. For Network Load Balancers, you can specify values between
/// 200 and 599, with the default value being 200-399. For Gateway Load Balancers, this
/// must be "200-399"".
///
/// A health check's response codes therefore do NOT follow the protocol the check speaks:
/// a Network Load Balancer's target group whose health check is an HTTP one still accepts
/// that family's whole success range.
pub fn default_health_check_matcher(
    protocol_version: Option<&str>,
    family: LoadBalancerFamily,
) -> MatcherRecord {
    if protocol_version == Some("GRPC") {
        return MatcherRecord {
            http_code: None,
            grpc_code: Some("12".to_string()),
        };
    }
    let http_code = match family {
        LoadBalancerFamily::Application => "200",
        LoadBalancerFamily::Network | LoadBalancerFamily::Gateway => "200-399",
    };
    MatcherRecord {
        http_code: Some(http_code.to_string()),
        grpc_code: None,
    }
}

/// The message Elastic Load Balancing answers a `TargetGroupNotFound` with for an
/// operation naming the target group it acts on — one `TargetGroupArn`: the identifier
/// the request carried, quoted, under a PLURAL noun whatever its number.
///
/// Built from the request, because the identifier it names is the only thing the caller
/// can act on. The recorded answer to a `DescribeTargetGroupAttributes` of a deleted
/// target group is `Target groups
/// 'arn:aws:elasticloadbalancing:…:targetgroup/…/…' not found` — one identifier under
/// the plural noun.
pub fn target_groups_not_found_message<'a>(
    identifiers: impl IntoIterator<Item = &'a str>,
) -> String {
    let named: Vec<&str> = identifiers.into_iter().collect();
    format!("Target groups '{}' not found", named.join(", "))
}

/// The message Elastic Load Balancing answers a `TargetGroupNotFound` with for a read
/// over a LIST of identifiers (`DescribeTargetGroups`, whose `TargetGroupArns` and
/// `Names` are both lists).
///
/// There the refusal is about the request's whole selection rather than one entry of it,
/// and the service names no value — the same shape of message its sibling list reads
/// answer ('One or more listeners not found'), and what the recorded
/// `DescribeTargetGroups` of an absent ARN answers (a replay of that step accepts this
/// sentence and rejects one naming the ARN, which is why the two wordings differ).
pub fn target_group_selection_not_found_message() -> String {
    "One or more target groups not found".to_string()
}

/// The message Elastic Load Balancing answers a `ListenerNotFound` with for an
/// operation that addresses ONE listener through its own required `ListenerArn` —
/// `ModifyListener`, `DeleteListener`, the certificate writes and the attribute read and
/// write.
///
/// Built from the request: the identifier it names is the only thing the caller can act
/// on, and the recorded answers to a `ModifyListener` and a `DescribeListenerAttributes`
/// of an absent listener quote that ARN back under the singular noun.
pub fn listener_not_found_message(arn: &str) -> String {
    format!("Listener '{arn}' not found")
}

/// The message Elastic Load Balancing answers a `ListenerNotFound` with for a read over
/// a LIST of listeners, or over the rules or certificates of one: there the refusal is
/// about the selection the request asked for rather than one listener the call
/// addresses.
///
/// The service names no value there — the same shape of message its sibling target
/// group reads answer ([`target_group_selection_not_found_message`]), and what the
/// recorded `DescribeListeners`, `DescribeListenerCertificates` and `DescribeRules` of
/// an absent listener answer.
pub fn listener_selection_not_found_message() -> String {
    "One or more listeners not found".to_string()
}

/// The message Elastic Load Balancing answers a `RuleNotFound` with for a read over a
/// LIST of rule identifiers (`DescribeRules`, whose `RuleArns` is a list): the selection
/// the request asked for is what could not be resolved, and the service names no value
/// in it, exactly as its sibling list reads do.
pub fn rule_selection_not_found_message() -> String {
    "One or more rules not found".to_string()
}

/// The message Elastic Load Balancing answers a `RuleNotFound` with for an operation
/// that addresses ONE rule through its own required `RuleArn` (`DeleteRule`).
///
/// Built from the request: the identifier it names is the only thing the caller can act
/// on, exactly as the listener-addressing operations quote their `ListenerArn` back
/// ([`listener_not_found_message`]), while a read over a LIST of rule identifiers names
/// no value ([`rule_selection_not_found_message`]).
pub fn rule_not_found_message(arn: &str) -> String {
    format!("Rule '{arn}' not found")
}

/// The message `SetRulePriorities` refuses a request it cannot place the asked-for
/// priorities with: that operation addresses a LIST (`RulePriorities`, one
/// `RulePriorityPair` per rule) rather than one rule, so the refusal is about the SET of
/// priorities the request asked for and names no value — the collection-level wording every
/// list-addressing read of this service answers, worded for the member the list carries.
///
/// ONE sentence for the two reasons that set cannot be placed — a pair naming a rule this
/// store does not hold, and a priority a rule outside the request already evaluates at —
/// which the ERROR CODE tells apart (`RuleNotFound` and `PriorityInUse`), exactly as the
/// recorded answers do.
pub fn rule_priorities_refusal_message() -> String {
    "One or more priorities not found".to_string()
}

/// The message Elastic Load Balancing answers a `PriorityInUse` with: the priority the
/// request asked for, and nothing else.
///
/// The message of `CreateRule`, which places ONE rule at ONE priority, so the value the
/// caller has to change is the one the refusal states. `SetRulePriorities` places a SET of
/// them and words its own refusal about that set
/// ([`rule_priorities_refusal_message`]).
pub fn priority_in_use_message(priority: i32) -> String {
    format!("Priority '{priority}' is currently in use")
}

/// The message a `SetRulePriorities` request that names one priority twice is refused
/// with: the priority the list repeated, which is the value the caller has to change.
///
/// A list that asks for two rules at one priority does not say which of them evaluates
/// there, so the refusal is about the REQUEST and states the repeated value and nothing
/// else — neither the rules it named nor the listeners they belong to.
pub fn repeated_priority_message(priority: i32) -> String {
    format!("Priority '{priority}' was provided multiple times")
}

/// The message a request that asks to DELETE a listener's default rule is refused with,
/// naming the rule from the request.
///
/// A listener's default rule is created and released with the listener, so the three
/// operations that address a rule state the one thing a caller can act on: that the rule
/// it named is a default rule, and which of this rule's properties it may therefore not
/// change (see [`default_rule_modification_message`] and
/// [`DEFAULT_RULE_PRIORITY_MESSAGE`]).
pub fn default_rule_deletion_message(arn: &str) -> String {
    format!("Default rule '{arn}' cannot be deleted")
}

/// The message a request that asks to MODIFY a listener's default rule is refused with,
/// naming the rule from the request — the default rule's actions are the listener's own
/// default actions, which `ModifyListener` owns.
pub fn default_rule_modification_message(arn: &str) -> String {
    format!("Default rule '{arn}' cannot be modified")
}

/// The message a request that asks to move a listener's default rule to another priority
/// is refused with.
///
/// A default rule has no numeric priority to move — it is reported as `default` — so the
/// refusal states the rule of the service and names no rule: it is the same whichever
/// default rule the request listed.
pub const DEFAULT_RULE_PRIORITY_MESSAGE: &str =
    "The priority of a default rule cannot be changed";

/// The message a `DuplicateListener` states: the load balancer whose port the request
/// asked for is already taken on.
///
/// One message for `CreateListener` and for a `ModifyListener` that moves a listener onto
/// a taken port, because "one listener per port of a load balancer" is ONE rule of the
/// service. The PORT is not named — the request carries it — and neither is the listener
/// that holds it: the identifier of the resource that happens to hold the port is not
/// part of the refusal.
pub fn duplicate_listener_message(load_balancer_arn: &str) -> String {
    format!("A listener already exists on this port for this load balancer '{load_balancer_arn}'")
}

/// The published maximum length of a load balancer name, from `CreateLoadBalancer`'s
/// `Name` documentation: "can have a maximum of 32 characters".
pub const LOAD_BALANCER_NAME_MAX_LENGTH: usize = 32;

/// The prefix a load balancer name may not begin with, from `CreateLoadBalancerInput$Name`:
/// "must not begin with \"internal-\"". It is the prefix the service itself puts on the DNS
/// name of an internal load balancer, so a name carrying it could never be told apart from
/// one the service generated.
pub const RESERVED_LOAD_BALANCER_NAME_PREFIX: &str = "internal-";

/// Whether `name` is a load balancer NAME this service can address — see
/// [`check_load_balancer_name`], which is the one reading of that rule.
///
/// Read by [`check_listener_arn`]: a load balancer name this service could never have
/// minted is not a name any ARN of this service can carry.
pub fn is_load_balancer_name(name: &str) -> bool {
    check_load_balancer_name(name).is_ok()
}

/// Whether `name` is a load balancer name this service accepts and — when it is not — the
/// clause it broke, so a refusal can name the value and the rule the caller has to satisfy.
///
/// Every clause is one of `CreateLoadBalancerInput$Name`'s own: "This name must be unique
/// per region per account, can have a maximum of 32 characters, must contain only
/// alphanumeric characters or hyphens, must not begin or end with a hyphen, and must not
/// begin with \"internal-\"." Uniqueness is the only one that needs the store, so it is
/// the create's own (a name already taken is `DuplicateLoadBalancerName`); the rest are
/// read off the value alone, which is why they are stated here once for every operation
/// that takes or parses a load balancer name.
pub fn check_load_balancer_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Load balancer name cannot be empty".to_string());
    }
    if name.chars().count() > LOAD_BALANCER_NAME_MAX_LENGTH {
        return Err(format!(
            "Load balancer name '{name}' cannot be longer than '{LOAD_BALANCER_NAME_MAX_LENGTH}' \
             characters"
        ));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(format!(
            "Load balancer name '{name}' can only contain characters that are alphanumeric \
             characters or hyphens"
        ));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(format!(
            "Load balancer name '{name}' cannot begin or end with a hyphen"
        ));
    }
    if name.starts_with(RESERVED_LOAD_BALANCER_NAME_PREFIX) {
        return Err(format!(
            "Load balancer name '{name}' cannot begin with \
             '{RESERVED_LOAD_BALANCER_NAME_PREFIX}'"
        ));
    }
    Ok(())
}

/// The ARN segments [`load_balancer_type_code`] mints, which are the only load balancer
/// type codes an Elastic Load Balancing ARN carries.
pub const LOAD_BALANCER_TYPE_CODES: &[&str] = &["app", "net", "gwy"];

/// Whether `value` is a resource id of the form every load balancer, listener and rule
/// ARN of this service carries: the 16 hex characters
/// `ComAmazonawsElasticloadbalancingv2ElasticloadbalancingV10State::mint_id` produces.
fn is_resource_id(value: &str) -> bool {
    value.len() == 16 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Whether `arn` is a well-formed LISTENER ARN — one this API could address at all —
/// and, when it is not, the refusal naming the value, which is the only thing the caller
/// can act on.
///
/// A listener ARN is `listener/<type>/<load-balancer-name>/<load-balancer-id>/<id>` with
/// a type code this service mints ([`LOAD_BALANCER_TYPE_CODES`]), a load balancer name
/// that satisfies the documented name rule ([`is_load_balancer_name`]) and two resource
/// ids of the form every ARN here carries. A value that breaks any of those names no
/// listener this API can have, whatever the store holds, and is refused as an invalid
/// ARN rather than reported as a missing listener — while a well-formed ARN that simply
/// names nothing is the `ListenerNotFound` of the operation that was called. The
/// partition, Region and account are deliberately NOT checked: an ARN of another Region
/// is well formed and simply names no listener this store holds.
pub fn check_listener_arn(arn: &str) -> Result<(), String> {
    let malformed = || Err(format!("'{arn}' is not a valid listener ARN"));
    let Some(parsed) = ::service_common::arn::parse_of(arn, SERVICE_NAMESPACE) else {
        return malformed();
    };
    let Some(resource_id) = parsed.resource.strip_prefix("listener/") else {
        return malformed();
    };
    let segments: Vec<&str> = resource_id.split('/').collect();
    let [type_code, name, load_balancer_id, listener_id] = segments[..] else {
        return malformed();
    };
    if !LOAD_BALANCER_TYPE_CODES.contains(&type_code)
        || !is_load_balancer_name(name)
        || !is_resource_id(load_balancer_id)
        || !is_resource_id(listener_id)
    {
        return malformed();
    }
    Ok(())
}

/// The listener protocols that terminate TLS at the load balancer, and so are the ones
/// the model brackets the certificate and security-policy members for.
///
/// From this model's own documentation of `CreateListenerInput$Certificates` — "[HTTPS
/// and TLS listeners] The default certificate for the listener. You must provide exactly
/// one certificate." — and of `SslPolicy`, bracketed the same way. `ProtocolEnum`'s other
/// values (GENEVE, HTTP, QUIC, TCP, TCP_QUIC, TCP_UDP, UDP) are outside that bracket, as
/// is a listener that names no protocol at all — the model: "You can't specify a protocol
/// for a Gateway Load Balancer".
pub const TLS_TERMINATING_PROTOCOLS: &[&str] = &["HTTPS", "TLS"];

/// Whether a listener on `protocol` terminates TLS, which is what decides whether it
/// carries a default certificate, a certificate list and a security policy at all.
pub fn terminates_tls(protocol: Option<&str>) -> bool {
    protocol.is_some_and(|value| TLS_TERMINATING_PROTOCOLS.contains(&value))
}

/// The protocol a listener's MUTUAL AUTHENTICATION configuration belongs to, from the
/// bracket the model puts on the member wherever it is set:
/// `CreateListenerInput$MutualAuthentication` and `ModifyListenerInput$MutualAuthentication`
/// are both documented "[HTTPS listeners] The mutual authentication configuration
/// information". Narrower than [`TLS_TERMINATING_PROTOCOLS`]: a TLS listener terminates TLS
/// but carries no client-certificate handling.
pub const MUTUAL_AUTHENTICATION_PROTOCOL: &str = "HTTPS";

/// The client certificate handling method a listener is carried at when nothing configured
/// one, from `MutualAuthenticationAttributes$Mode`'s own documentation: "Options are `off`,
/// `passthrough` or `verify`. The default value is `off`."
pub const DEFAULT_MUTUAL_AUTHENTICATION_MODE: &str = "off";

/// Whether a listener on `protocol` carries a mutual authentication configuration at all
/// ([`MUTUAL_AUTHENTICATION_PROTOCOL`]).
pub fn handles_client_certificates(protocol: Option<&str>) -> bool {
    protocol == Some(MUTUAL_AUTHENTICATION_PROTOCOL)
}

/// How a refusal about a listener's protocol brackets NAMES what it judged, for a listener
/// that names no protocol as well as for one that does. One phrasing for every such
/// refusal, so the certificate bracket and the mutual authentication bracket cannot drift
/// on how they name the listener they judged.
pub fn named_listener(protocol: Option<&str>) -> String {
    match protocol {
        Some(value) => format!("{value} listeners"),
        None => "a listener with no protocol".to_string(),
    }
}

/// Enforce the bracket the model puts on a listener's MUTUAL AUTHENTICATION: the member
/// belongs to the listeners [`MUTUAL_AUTHENTICATION_PROTOCOL`] names and to no other, so a
/// request configuring client certificate handling on a listener of any other protocol is
/// refused rather than accepted and dropped.
///
/// Judged against the protocol the call LEAVES the listener on, by the create that first
/// sets the configuration and by the modification that replaces it. The model states the
/// bracket in the member's own documentation and declares no error shape for it, so the
/// refusal is this service's own input validation (`400` `ValidationError`) with a message
/// naming the member and the protocol it was judged against — exactly as the default
/// certificate's bracket is stated.
pub fn check_mutual_authentication(
    protocol: Option<&str>,
    mutual_authentication: Option<&MutualAuthenticationAttributes>,
) -> Result<(), String> {
    if mutual_authentication.is_none() || handles_client_certificates(protocol) {
        return Ok(());
    }
    Err(format!(
        "MutualAuthentication cannot be specified for {}: the mutual authentication \
         configuration applies only to {MUTUAL_AUTHENTICATION_PROTOCOL} listeners",
        named_listener(protocol)
    ))
}

/// How many certificates one listener's certificate list holds before
/// `AddListenerCertificates` refuses with the modelled `TooManyCertificatesException`.
/// The emulator's own bound, as [`LOAD_BALANCER_QUOTA`]: the list lives on the listener
/// record, so it is released with the listener.
pub const CERTIFICATES_PER_LISTENER: usize = 25;

/// The message a call that would take a listener's certificate list past
/// [`CERTIFICATES_PER_LISTENER`] is refused with.
///
/// Elastic Load Balancing words the modelled `TooManyCertificatesException` as a FIXED
/// sentence with no variable part: neither the bound nor the listener is in it, so a
/// caller reads the same text whichever listener it filled.
pub const TOO_MANY_CERTIFICATES_MESSAGE: &str =
    "The maximum number of certificates has been reached";

/// The message a request to remove a listener's DEFAULT certificate is refused with.
///
/// The default certificate lives outside the certificate list and is replaced through
/// `ModifyListener`, and Elastic Load Balancing states that as a fixed sentence: neither
/// the certificate nor the listener the request named is part of it.
pub const DEFAULT_CERTIFICATE_REMOVAL_MESSAGE: &str = "Default certificate cannot be removed";

/// How many certificate ARNs ONE request may carry, which the model fixes at one for
/// every operation that takes a `Certificates` list: `CreateListenerInput$Certificates`
/// and `ModifyListenerInput$Certificates` are "The default certificate for the listener.
/// You must provide exactly one certificate", and
/// `AddListenerCertificatesInput$Certificates` is "The certificate to add. You can
/// specify one certificate per call."
pub const CERTIFICATES_PER_CALL: usize = 1;

/// The message a request carrying more certificate ARNs than one call may name is refused
/// with: the limit the model fixes, and how many the request carried.
///
/// Both halves are stated because a caller has to fix the request from this text alone,
/// and the count is the request's own rather than one recorded call's.
pub fn certificate_count_message(limit: usize, requested: usize) -> String {
    format!("Up to '{limit}' certificate ARNs can be specified, but '{requested}' were specified")
}

/// A server certificate uploaded to IAM, `arn:aws:iam::<account>:server-certificate/<name>`
/// — the second place the certificates a TLS-terminating listener serves live, beside
/// Certificate Manager. Stated as a requirement of the shared ARN reader, which already
/// carries the Certificate Manager one (`service_common::arn::ACM_CERTIFICATE`), so both
/// forms are read by the workspace's one parse of a caller-supplied ARN.
const IAM_SERVER_CERTIFICATE: ::service_common::arn::Requirement =
    ::service_common::arn::Requirement {
        vendor: "iam",
        resource_type: Some("server-certificate"),
        label: "an IAM server certificate",
    };

/// Whether `arn` NAMES a certificate at all — the ARN of a Certificate Manager
/// certificate or of a server certificate uploaded to IAM, which are the forms
/// `Certificate$CertificateArn` ("The Amazon Resource Name (ARN) of the certificate")
/// carries.
///
/// A value of no other form resolves to no certificate of the account whatever those
/// services hold, so the operation that named it answers the modelled
/// `CertificateNotFoundException` with [`certificate_not_found_message`] and stores
/// nothing. The partition, Region and account are deliberately NOT checked, exactly as
/// [`check_listener_arn`] leaves them: a certificate of another Region is well formed.
pub fn names_a_certificate(arn: &str) -> bool {
    ::service_common::arn::ACM_CERTIFICATE.admits(arn) || IAM_SERVER_CERTIFICATE.admits(arn)
}

/// The refusal a certificate ARN that resolves to no certificate earns, naming the value
/// the request carried — the only thing the caller can act on.
pub fn certificate_not_found_message(arn: &str) -> String {
    format!("Certificate '{arn}' not found")
}

/// The first `CertificateArn` of `certificates` that names no certificate, if any: what
/// an operation resolving a requested certificate refuses on, read off the request in the
/// order it listed them.
///
/// An entry carrying NO ARN, or an empty one, names no certificate either — but that is a
/// missing MEMBER rather than an unresolvable certificate, and each operation states that
/// refusal itself, so it is passed over here.
pub fn unresolvable_certificate(certificates: &[Certificate]) -> Option<&str> {
    certificates
        .iter()
        .filter_map(|certificate| certificate.certificate_arn.as_deref())
        .filter(|arn| !arn.is_empty())
        .find(|arn| !names_a_certificate(arn))
}

/// The redirect-action protocol that sends the client to cleartext, from
/// `RedirectActionConfig$Protocol`: "You can specify HTTP, HTTPS, or #{protocol}."
pub const HTTP_REDIRECT_PROTOCOL: &str = "HTTP";

/// Whether an action list attached to a listener on `listener_protocol` redirects to
/// cleartext HTTP from a listener that terminates TLS — the one combination
/// `RedirectActionConfig$Protocol` rules out: "You can redirect HTTP to HTTP, HTTP to
/// HTTPS, and HTTPS to HTTPS. You can't redirect HTTPS to HTTP."
///
/// The judgement is a RELATIONSHIP between the action and the listener the action is
/// attached to, not a constraint on the request alone: the same configuration is admitted
/// on a listener that terminates no TLS. A redirect naming no protocol keeps the
/// request's own (`#{protocol}`), and `HTTPS` is no downgrade, so neither is judged here.
pub fn downgrades_to_http(listener_protocol: Option<&str>, actions: &[Action]) -> bool {
    terminates_tls(listener_protocol)
        && actions.iter().any(|action| {
            action
                .redirect_config
                .as_ref()
                .is_some_and(|config| config.protocol.as_deref() == Some(HTTP_REDIRECT_PROTOCOL))
        })
}

/// The refusal such a redirect earns. Fixed text: the rule is about the two protocols
/// themselves, so there is nothing of the request to name in it.
pub const HTTPS_TO_HTTP_REDIRECT_MESSAGE: &str = "You cannot redirect HTTPS to HTTP.";

/// The refusal a request pairing a listener with a target group of another kind of traffic
/// earns, naming every target group that does not pair with it — the only thing the caller
/// can act on.
///
/// Elastic Load Balancing's own wording for this refusal, which the recorded
/// `IncompatibleProtocols` answer to such a create states: `The listener and the following
/// target groups have incompatible protocols: <arn>` — the sentence fixed, the target groups
/// read off the request.
pub fn incompatible_protocols_message<'a>(
    target_group_arns: impl IntoIterator<Item = &'a str>,
) -> String {
    let named: Vec<&str> = target_group_arns.into_iter().collect();
    format!(
        "The listener and the following target groups have incompatible protocols: {}",
        named.join(", ")
    )
}

/// Every listener attribute this service models, with the load balancer families whose
/// listeners carry it, the values it accepts and the value it is carried at until a write
/// — each one a sentence of the model's own `ListenerAttribute$Key` documentation
/// (`smithy_query(query="doc",shape="ListenerAttribute",member="Key")`), which is the
/// only catalog of them; the Smithy shape itself is an unconstrained key/value pair, so
/// nothing else in the model lists them.
///
/// The ORDER of this list is the order a listener's attribute collection is reported in
/// ([`ListenerRecord::effective_attributes`]).
pub static LISTENER_ATTRIBUTES: &[ListenerAttributeSpec] = &[
    // "The following attribute is supported by Network Load Balancers, and Gateway Load
    // Balancers: tcp.idle_timeout.seconds - The tcp idle timeout value, in seconds. The
    // valid range is 60-6000 seconds. The default is 350 seconds."
    ListenerAttributeSpec {
        key: "tcp.idle_timeout.seconds",
        domain: AttributeDomain::Integer { min: 60, max: 6000 },
        families: &[LoadBalancerFamily::Network, LoadBalancerFamily::Gateway],
        default: Some("350"),
    },
    // "The following attribute is only supported by Gateway Load Balancers:
    // send_tcp_reset.on_idle_timeout.enabled – ... The value is true or false. The
    // default is false."
    ListenerAttributeSpec {
        key: "send_tcp_reset.on_idle_timeout.enabled",
        domain: AttributeDomain::Boolean,
        families: &[LoadBalancerFamily::Gateway],
        default: Some("false"),
    },
    // "The following attributes are only supported by Application Load Balancers": the
    // mutual-TLS and TLS request header names, each of which the documentation describes
    // as a header NAME the caller chooses, so the model states no domain and no value for
    // any of them. An Application Load Balancer listener's attribute collection is the
    // response-header set below, so none of these is in it: each is reported once a
    // caller has written it.
    ListenerAttributeSpec {
        key: "routing.http.request.x_amzn_mtls_clientcert_serial_number.header_name",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: None,
    },
    ListenerAttributeSpec {
        key: "routing.http.request.x_amzn_mtls_clientcert_issuer.header_name",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: None,
    },
    ListenerAttributeSpec {
        key: "routing.http.request.x_amzn_mtls_clientcert_subject.header_name",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: None,
    },
    ListenerAttributeSpec {
        key: "routing.http.request.x_amzn_mtls_clientcert_validity.header_name",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: None,
    },
    ListenerAttributeSpec {
        key: "routing.http.request.x_amzn_mtls_clientcert_leaf.header_name",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: None,
    },
    ListenerAttributeSpec {
        key: "routing.http.request.x_amzn_mtls_clientcert.header_name",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: None,
    },
    ListenerAttributeSpec {
        key: "routing.http.request.x_amzn_tls_version.header_name",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: None,
    },
    ListenerAttributeSpec {
        key: "routing.http.request.x_amzn_tls_cipher_suite.header_name",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: None,
    },
    // "routing.http.response.server.enabled - Enables you to allow or remove the HTTP
    // response server header." Allowed or removed: the two states the sentence names,
    // and the header is allowed until a caller removes it.
    ListenerAttributeSpec {
        key: "routing.http.response.server.enabled",
        domain: AttributeDomain::Boolean,
        families: &[LoadBalancerFamily::Application],
        default: Some("true"),
    },
    // The response header VALUES, each documented as the value of one HTTP response
    // header — again a caller's string, with no domain and no value stated for it, so the
    // collection carries each at the empty string until a caller sets a header value.
    ListenerAttributeSpec {
        key: "routing.http.response.strict_transport_security.header_value",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: Some(""),
    },
    ListenerAttributeSpec {
        key: "routing.http.response.access_control_allow_origin.header_value",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: Some(""),
    },
    ListenerAttributeSpec {
        key: "routing.http.response.access_control_allow_methods.header_value",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: Some(""),
    },
    ListenerAttributeSpec {
        key: "routing.http.response.access_control_allow_headers.header_value",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: Some(""),
    },
    ListenerAttributeSpec {
        key: "routing.http.response.access_control_allow_credentials.header_value",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: Some(""),
    },
    ListenerAttributeSpec {
        key: "routing.http.response.access_control_expose_headers.header_value",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: Some(""),
    },
    // "Specifies how long the results of a preflight request can be cached, in seconds."
    ListenerAttributeSpec {
        key: "routing.http.response.access_control_max_age.header_value",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: Some(""),
    },
    ListenerAttributeSpec {
        key: "routing.http.response.content_security_policy.header_value",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: Some(""),
    },
    ListenerAttributeSpec {
        key: "routing.http.response.x_content_type_options.header_value",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: Some(""),
    },
    ListenerAttributeSpec {
        key: "routing.http.response.x_frame_options.header_value",
        domain: AttributeDomain::Text,
        families: &[LoadBalancerFamily::Application],
        default: Some(""),
    },
];

/// One listener attribute: which listeners carry it, what it accepts, and the value it
/// reports until something sets it.
#[derive(Debug)]
pub struct ListenerAttributeSpec {
    pub key: &'static str,
    pub domain: AttributeDomain,
    /// The load balancer families whose listeners carry the attribute, as the model's
    /// `ListenerAttribute$Key` documentation groups them.
    pub families: &'static [LoadBalancerFamily],
    /// The value the attribute COLLECTION carries this attribute at until a caller
    /// writes one: its documented default, and the empty string for a header-value
    /// attribute the documentation states no value for. `None` marks an attribute the
    /// collection does not carry at all, which a write of it is what puts there.
    pub default: Option<&'static str>,
}

impl ListenerAttributeSpec {
    /// Whether a listener of a load balancer in `family` carries this attribute.
    pub fn applies_to(&self, family: LoadBalancerFamily) -> bool {
        self.families.contains(&family)
    }
}

/// The attribute `key` names, or `None` when no listener attribute carries that name.
pub fn listener_attribute(key: &str) -> Option<&'static ListenerAttributeSpec> {
    LISTENER_ATTRIBUTES.iter().find(|spec| spec.key == key)
}

/// Whose attribute set a key was judged against, for the refusal that names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeOwner {
    LoadBalancer,
    Listener,
    TargetGroup,
}

impl AttributeOwner {
    /// How the refusal names the resource whose attributes the key was looked for among,
    /// in the words the API's own `…Attribute` shapes name them by
    /// (`LoadBalancerAttribute`, `ListenerAttribute`, `TargetGroupAttribute`).
    fn noun(self) -> &'static str {
        match self {
            Self::LoadBalancer => "Load balancer",
            Self::Listener => "Listener",
            Self::TargetGroup => "Target group",
        }
    }
}

/// The refusal an attribute key this service defines no attribute under earns: a value the
/// request has to fix, which Elastic Load Balancing answers as [`Refusal::Validation`]
/// naming the key it did not recognise.
///
/// Every attribute write judges its key against a fixed set of names — the ones its
/// resource's documentation lists — so a key outside that set is the same failure whichever
/// of the three resources it was named for, and this is the ONE reading of it, called by
/// `ModifyLoadBalancerAttributes`, `ModifyListenerAttributes` and
/// `ModifyTargetGroupAttributes`.
pub fn unrecognized_attribute_key(owner: AttributeOwner, key: &str) -> Refusal {
    Refusal::Validation(format!(
        "{} attribute key '{key}' is not recognized",
        owner.noun()
    ))
}

/// How a refusal names a load balancer of `family` in PROSE, with the article that fits
/// the display name AWS writes it with — as opposed to the `LoadBalancerTypeEnum` value a
/// refusal quotes ([`family_type_name`]).
pub fn family_prose_name(family: LoadBalancerFamily) -> &'static str {
    match family {
        LoadBalancerFamily::Application => "an Application Load Balancer",
        LoadBalancerFamily::Network => "a Network Load Balancer",
        LoadBalancerFamily::Gateway => "a Gateway Load Balancer",
    }
}

/// The message a write of a load balancer attribute whose value the documentation FIXES
/// for this kind of load balancer is refused with: the key, the one value it has, and the
/// kind of load balancer it has it on.
pub fn fixed_attribute_message(key: &str, fixed: &str, family: LoadBalancerFamily) -> String {
    format!(
        "The value for '{key}' must always be '{fixed}' for {}",
        family_prose_name(family)
    )
}

/// The message a write of a load balancer attribute the addressed load balancer's TYPE
/// does not carry is refused with: the key the request named, and the type of the load
/// balancer it was asked of.
///
/// Which attributes a load balancer carries is decided by its type, so that is what the
/// refusal states — the key tells the caller which of the attributes it sent was rejected,
/// and the type tells it why.
pub fn load_balancer_attribute_unsupported_message(key: &str, family: LoadBalancerFamily) -> String {
    format!(
        "Load balancer attribute key '{key}' is not supported on load balancers with type '{}'",
        family_type_name(family)
    )
}

/// How Elastic Load Balancing refuses a key the addressed load balancer's TYPE does not
/// carry, which that type decides.
///
/// Which attributes exist AT ALL is per type, so a Network or Gateway Load Balancer does
/// not recognise another type's key any more than it recognises a key no documentation
/// lists at all: both earn [`unrecognized_attribute_key`]. An Application Load Balancer
/// tells the two apart — it answers a key of another type as a configuration it cannot
/// hold, naming the key and its own type ([`Refusal::Configuration`], the modelled
/// `InvalidConfigurationRequest`).
///
/// Recorded behaviour: the answers this service is checked against refuse a Network-only
/// key on an Application Load Balancer with the "not supported on load balancers with
/// type" sentence, and an Application-only key on a Network Load Balancer with the "not
/// recognized" one.
pub fn load_balancer_attribute_unsupported(key: &str, family: LoadBalancerFamily) -> Refusal {
    match family {
        LoadBalancerFamily::Application => Refusal::Configuration(
            load_balancer_attribute_unsupported_message(key, family),
        ),
        LoadBalancerFamily::Network | LoadBalancerFamily::Gateway => {
            unrecognized_attribute_key(AttributeOwner::LoadBalancer, key)
        }
    }
}

/// The message a write of a listener attribute the listener's load balancer family does
/// not carry is refused with.
///
/// Elastic Load Balancing words the listener form of that refusal as a fixed sentence
/// about the attribute the request provided, naming neither the key nor the family — unlike
/// the load balancer form beside it ([`load_balancer_attribute_unsupported_message`]).
pub const LISTENER_ATTRIBUTE_UNSUPPORTED_MESSAGE: &str =
    "The provided listener attribute is not supported";

/// Which family of load balancer a `Type` names, which is what decides WHICH listener
/// attributes its listeners carry. The pairing is the model's own `LoadBalancerTypeEnum`
/// (`application`, `network`, `gateway`), as [`load_balancer_type_code`] reads it.
pub fn load_balancer_family(lb_type: &str) -> LoadBalancerFamily {
    match lb_type {
        "network" => LoadBalancerFamily::Network,
        "gateway" => LoadBalancerFamily::Gateway,
        // `application` is the modelled default for `Type`.
        _ => LoadBalancerFamily::Application,
    }
}

/// One Region's published Route 53 hosted zones: the Region, the zone an Application Load
/// Balancer of it is aliased through, and the zone a Network Load Balancer of it is
/// aliased through.
struct HostedZoneEntry {
    region: &'static str,
    application: &'static str,
    network: &'static str,
}

/// The Route 53 hosted zone ids Elastic Load Balancing publishes per Region and load
/// balancer family, which `LoadBalancer$CanonicalHostedZoneId` reports ("the ID of the
/// Amazon Route 53 hosted zone associated with the load balancer").
///
/// These are the service's own published identifiers — the "Elastic Load Balancing
/// endpoints and quotas" table of hosted zone ids, which a client needs to alias a record
/// at the load balancer — not anything derived from a request or minted per run: the same
/// Region and family always answer the same id, for every account and every load balancer.
/// Application Load Balancers share their Region's zone with Classic load balancers, and
/// Network Load Balancers have their own.
///
/// A Region this table does not carry reports no hosted zone rather than a made-up one: an
/// id of the right shape that resolves to nothing would be worse than an absent member.
///
/// The `application` column is the SAME published column as the Classic endpoint's, which
/// `services/service-com-amazonaws-elasticloadbalancing-elasticloadbalancing-v7`'s
/// `CLASSIC_ELB_HOSTED_ZONE_IDS` carries for its own model: the two tables must agree on
/// every Region both cover, and they do. They cannot be ONE table in a shared crate
/// without a dependency cycle — that crate already depends on this one, for the shared
/// endpoint's API-version dispatch — so this is the cross-reference that keeps them in
/// step, and a Region added to either belongs in both.
const HOSTED_ZONES: &[HostedZoneEntry] = &[
    HostedZoneEntry {
        region: "af-south-1",
        application: "Z268VQBMOI5EKX",
        network: "Z203XCE67M25HM",
    },
    HostedZoneEntry {
        region: "ap-east-1",
        application: "Z3DQVH9N71FHZ0",
        network: "Z12Y7K3UBGUAD1",
    },
    HostedZoneEntry {
        region: "me-south-1",
        application: "ZS929ML54UICD",
        network: "Z3QSRYVP46NYYV",
    },
    HostedZoneEntry {
        region: "us-east-1",
        application: "Z35SXDOTRQ7X7K",
        network: "Z26RNL4JYFTOTI",
    },
    HostedZoneEntry {
        region: "us-east-2",
        application: "Z3AADJGX6KTTL2",
        network: "ZLMOA37VPKANP",
    },
    HostedZoneEntry {
        region: "us-west-1",
        application: "Z368ELLRRE2KJ0",
        network: "Z24FKFUX50B4VV",
    },
    HostedZoneEntry {
        region: "us-west-2",
        application: "Z1H1FL5HABSF5",
        network: "Z18D5FSROUN65G",
    },
    HostedZoneEntry {
        region: "ca-central-1",
        application: "ZQSVJUPU6J1EY",
        network: "Z2EPGBW3API2WT",
    },
    HostedZoneEntry {
        region: "eu-west-1",
        application: "Z32O12XQLNTSW2",
        network: "Z2IFOLAFXWLO4F",
    },
    HostedZoneEntry {
        region: "eu-west-2",
        application: "ZHURV8PSTC4K8",
        network: "ZD4D7Y8KGAS4G",
    },
    HostedZoneEntry {
        region: "eu-west-3",
        application: "Z3Q77PNBQS71R4",
        network: "Z1CMS0P5QUZ6D5",
    },
    HostedZoneEntry {
        region: "eu-central-1",
        application: "Z215JYRZR1TBD5",
        network: "Z3F0SRJ5LGBH90",
    },
    HostedZoneEntry {
        region: "eu-north-1",
        application: "Z23TAZ6LKFMNIO",
        network: "Z1UDT6IFJ4EJM",
    },
    HostedZoneEntry {
        region: "eu-south-1",
        application: "Z3ULH7SSC9OV64",
        network: "Z23146JA1KNAFP",
    },
    HostedZoneEntry {
        region: "ap-south-1",
        application: "ZP97RAFLXTNZK",
        network: "ZVDDRBQ08TROA",
    },
    HostedZoneEntry {
        region: "ap-northeast-1",
        application: "Z14GRHDCWA56QT",
        network: "Z31USIVHYNEOWT",
    },
    HostedZoneEntry {
        region: "ap-northeast-2",
        application: "ZWKZPGTI48KDX",
        network: "ZIBE1TIR4HY56",
    },
    HostedZoneEntry {
        region: "ap-northeast-3",
        application: "Z5LXEXXYQ4HTP",
        network: "Z1GWIQ4HH19I5X",
    },
    HostedZoneEntry {
        region: "ap-southeast-1",
        application: "Z1LMS91P8CMLE5",
        network: "ZKVM4W9LS7TM",
    },
    HostedZoneEntry {
        region: "ap-southeast-2",
        application: "Z1GM3OXH4ZPM65",
        network: "ZCT6FZBF4DROD",
    },
    HostedZoneEntry {
        region: "sa-east-1",
        application: "Z2P70J7HTTTPLU",
        network: "ZTK26PT1VY4CU",
    },
];

/// The published hosted zone of a load balancer of `family` in `region`, or `None` when
/// the service publishes none for it — a Region [`HOSTED_ZONES`] does not carry, or a
/// Gateway Load Balancer, which is reached through its own VPC endpoints rather than
/// through a DNS name a hosted zone resolves.
pub fn canonical_hosted_zone_id(region: &str, family: LoadBalancerFamily) -> Option<&'static str> {
    let entry = HOSTED_ZONES.iter().find(|entry| entry.region == region)?;
    match family {
        LoadBalancerFamily::Application => Some(entry.application),
        LoadBalancerFamily::Network => Some(entry.network),
        LoadBalancerFamily::Gateway => None,
    }
}

/// The value `EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic` has until a caller
/// sets it, from that member's own documentation: "The default is on."
pub const PRIVATE_LINK_INBOUND_RULES_DEFAULT: &str = "on";

/// The value `LoadBalancer$EnablePrefixForIpv6SourceNat` has until a caller sets it, from
/// that member's own documentation: "The default value is `off`." One of the two values
/// the model's `EnablePrefixForIpv6SourceNatEnum` names
/// (`smithy_query(query="shape",shape="EnablePrefixForIpv6SourceNatEnum")`: `on`, `off`).
pub const ENABLE_PREFIX_FOR_IPV6_SOURCE_NAT_DEFAULT: &str = "off";

/// How many decimal digits the id in the host of an APPLICATION Load Balancer has, from
/// the form that family's guide publishes
/// (`my-load-balancer-1234567890.us-west-2.elb.amazonaws.com`) — see
/// [`load_balancer_dns_name`].
pub const APPLICATION_DNS_ID_DIGITS: u32 = 10;

/// The host a load balancer publishes as its `DNSName` ("the public DNS name of the load
/// balancer"), in the form Elastic Load Balancing publishes for the FAMILY it belongs to.
///
/// The two forms differ in three ways, and the family decides all three:
///
/// * an Application Load Balancer's host puts the Region ahead of the `elb` label —
///   `<name>-<id>.<region>.elb.amazonaws.com`, as the Application Load Balancer guide
///   publishes it (`my-load-balancer-1234567890.us-west-2.elb.amazonaws.com`) — while a
///   Network or Gateway Load Balancer's puts them the other way round —
///   `<name>-<id>.elb.<region>.amazonaws.com`, as those guides publish it
///   (`my-network-load-balancer-1234567890abcdef.elb.us-west-2.amazonaws.com`);
/// * the id beside the name is a DECIMAL number for an Application Load Balancer
///   ([`APPLICATION_DNS_ID_DIGITS`] digits), minted for the host alone and not the id its
///   ARN carries, while a Network or Gateway Load Balancer's host carries the very
///   hexadecimal id its own ARN does;
/// * an INTERNAL Application Load Balancer's host carries
///   [`RESERVED_LOAD_BALANCER_NAME_PREFIX`] ahead of the name — which is why that prefix
///   is one no caller may begin a load balancer name with — while a Network or Gateway
///   Load Balancer's host states its scheme nowhere: the published form for those families
///   carries the name alone, and the host of an INTERNAL one of them carries no prefix
///   either, so the name restriction is the Application form's and the reserved prefix is
///   refused for every family only because a name is a name of any of them.
///
/// Each of the three was settled against the answers Elastic Load Balancing itself gave,
/// one at a time: the `elb`-first order and the ARN's own id still left the host of an
/// internal Network Load Balancer differing from the answered one, and the host matched
/// only once the scheme prefix came off it — so the prefix's absence from these two
/// families is read off that answer rather than inferred from the Application form.
///
/// `dns_id` is the id for the family, which
/// [`ComAmazonawsElasticloadbalancingv2ElasticloadbalancingV10State::dns_id`] answers.
pub fn load_balancer_dns_name(
    name: &str,
    scheme: &str,
    family: LoadBalancerFamily,
    dns_id: &str,
    region: &str,
) -> String {
    match family {
        LoadBalancerFamily::Application => {
            let prefix = if scheme == INTERNAL_SCHEME {
                RESERVED_LOAD_BALANCER_NAME_PREFIX
            } else {
                ""
            };
            format!("{prefix}{name}-{dns_id}.{region}.elb.amazonaws.com")
        }
        LoadBalancerFamily::Network | LoadBalancerFamily::Gateway => {
            format!("{name}-{dns_id}.elb.{region}.amazonaws.com")
        }
    }
}

/// Whether the published host of a load balancer of `family` carries a DECIMAL id minted
/// for the host alone, rather than the hexadecimal id of its ARN — see
/// [`load_balancer_dns_name`].
pub fn dns_id_is_minted(family: LoadBalancerFamily) -> bool {
    family == LoadBalancerFamily::Application
}

/// One load balancer attribute: which load balancers carry it, what it accepts, the
/// value it reports until something sets it, and the value its documentation FIXES for
/// some load balancers.
pub struct LoadBalancerAttributeSpec {
    pub key: &'static str,
    pub domain: AttributeDomain,
    /// The load balancer families that carry the attribute, as the model's
    /// `LoadBalancerAttribute$Key` documentation groups them.
    families: &'static [LoadBalancerFamily],
    /// The value the attribute COLLECTION carries this attribute at until a caller
    /// writes one: its documented default, and the empty string for a string-valued
    /// attribute whose documentation states no value. `None` marks an attribute the
    /// collection does not carry at all, which a write of it is what puts there.
    default: fn(&LoadBalancerRecord) -> Option<String>,
    /// The ONE value this attribute has on a load balancer whose documentation states it
    /// cannot be changed, or `None` where a caller may set it freely.
    fixed: fn(&LoadBalancerRecord) -> Option<String>,
}

impl std::fmt::Debug for LoadBalancerAttributeSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadBalancerAttributeSpec")
            .field("key", &self.key)
            .field("domain", &self.domain)
            .field("families", &self.families)
            .finish_non_exhaustive()
    }
}

impl LoadBalancerAttributeSpec {
    /// Whether `load_balancer` carries this attribute at all.
    pub fn applies_to(&self, load_balancer: &LoadBalancerRecord) -> bool {
        self.families.contains(&load_balancer.family())
    }

    /// The value `load_balancer` reports for this attribute until something sets it.
    pub fn default_for(&self, load_balancer: &LoadBalancerRecord) -> Option<String> {
        (self.default)(load_balancer)
    }

    /// The value this attribute is fixed at on `load_balancer`, or `None` when a caller
    /// may set it. A write of anything else is a configuration the service refuses.
    pub fn fixed_for(&self, load_balancer: &LoadBalancerRecord) -> Option<String> {
        (self.fixed)(load_balancer)
    }
}

/// Every load balancer attribute this service models, with the families that carry it,
/// the values it accepts and the value it is carried at until a write — each one a
/// sentence of the model's own `LoadBalancerAttribute$Key` documentation
/// (`smithy_query(query="doc",shape="LoadBalancerAttribute",member="Key")`), which is the
/// only catalog of them; the Smithy shape itself is an unconstrained key/value pair, so
/// nothing else in the model lists them.
///
/// The ORDER of this list is the order a load balancer's attribute collection is reported
/// in ([`LoadBalancerRecord::effective_attributes`]), which is the service's own and
/// neither alphabetical nor the documentation's grouping: the log destinations first, then
/// the connection and routing settings, then the connection logs.
pub static LOAD_BALANCER_ATTRIBUTES: &[LoadBalancerAttributeSpec] = &[
    // "access_logs.s3.enabled - Indicates whether access logs are enabled. The value is
    // true or false. The default is false." Documented "supported by both Application
    // Load Balancers and Network Load Balancers", as the two beside it are.
    LoadBalancerAttributeSpec {
        key: "access_logs.s3.enabled",
        domain: AttributeDomain::Boolean,
        families: APPLICATION_AND_NETWORK,
        default: |_| Some("false".to_string()),
        fixed: |_| None,
    },
    // "access_logs.s3.bucket - The name of the S3 bucket for the access logs." A name
    // the caller chooses, with no domain and no value stated for it: the collection
    // carries it at the empty string until a caller names a bucket.
    LoadBalancerAttributeSpec {
        key: "access_logs.s3.bucket",
        domain: AttributeDomain::Text,
        families: APPLICATION_AND_NETWORK,
        default: |_| Some(String::new()),
        fixed: |_| None,
    },
    // "access_logs.s3.prefix - The prefix for the location in the S3 bucket for the
    // access logs."
    LoadBalancerAttributeSpec {
        key: "access_logs.s3.prefix",
        domain: AttributeDomain::Text,
        families: APPLICATION_AND_NETWORK,
        default: |_| Some(String::new()),
        fixed: |_| None,
    },
    // "The following attributes are supported by only Application Load Balancers:"
    //
    // "health_check_logs.s3.enabled - Indicates whether health check logs are enabled.
    // The value is true or false. The default is false."
    LoadBalancerAttributeSpec {
        key: "health_check_logs.s3.enabled",
        domain: AttributeDomain::Boolean,
        families: APPLICATION_ONLY,
        default: |_| Some("false".to_string()),
        fixed: |_| None,
    },
    // "health_check_logs.s3.bucket - The name of the S3 bucket for the health check
    // logs."
    LoadBalancerAttributeSpec {
        key: "health_check_logs.s3.bucket",
        domain: AttributeDomain::Text,
        families: APPLICATION_ONLY,
        default: |_| Some(String::new()),
        fixed: |_| None,
    },
    // "health_check_logs.s3.prefix - The prefix for the location in the S3 bucket for
    // the health check logs."
    LoadBalancerAttributeSpec {
        key: "health_check_logs.s3.prefix",
        domain: AttributeDomain::Text,
        families: APPLICATION_ONLY,
        default: |_| Some(String::new()),
        fixed: |_| None,
    },
    // "idle_timeout.timeout_seconds - The idle timeout value, in seconds. The valid
    // range is 1-4000 seconds. The default is 60 seconds."
    LoadBalancerAttributeSpec {
        key: "idle_timeout.timeout_seconds",
        domain: AttributeDomain::Integer { min: 1, max: 4000 },
        families: APPLICATION_ONLY,
        default: |_| Some("60".to_string()),
        fixed: |_| None,
    },
    // "The following attributes are supported by all load balancers:"
    //
    // "deletion_protection.enabled - Indicates whether deletion protection is enabled.
    // The value is true or false. The default is false."
    LoadBalancerAttributeSpec {
        key: "deletion_protection.enabled",
        domain: AttributeDomain::Boolean,
        families: EVERY_FAMILY,
        default: |_| Some("false".to_string()),
        fixed: |_| None,
    },
    // "routing.http2.enabled - ... The default is true."
    LoadBalancerAttributeSpec {
        key: "routing.http2.enabled",
        domain: AttributeDomain::Boolean,
        families: APPLICATION_ONLY,
        default: |_| Some("true".to_string()),
        fixed: |_| None,
    },
    // "routing.http.drop_invalid_header_fields.enabled - ... The default is false."
    LoadBalancerAttributeSpec {
        key: "routing.http.drop_invalid_header_fields.enabled",
        domain: AttributeDomain::Boolean,
        families: APPLICATION_ONLY,
        default: |_| Some("false".to_string()),
        fixed: |_| None,
    },
    // "routing.http.xff_client_port.enabled - ... The default is false."
    LoadBalancerAttributeSpec {
        key: "routing.http.xff_client_port.enabled",
        domain: AttributeDomain::Boolean,
        families: APPLICATION_ONLY,
        default: |_| Some("false".to_string()),
        fixed: |_| None,
    },
    // "routing.http.xff_header_processing.mode - ... The possible values are append,
    // preserve, and remove. The default is append."
    LoadBalancerAttributeSpec {
        key: "routing.http.xff_header_processing.mode",
        domain: AttributeDomain::OneOf(&["append", "preserve", "remove"]),
        families: APPLICATION_ONLY,
        default: |_| Some("append".to_string()),
        fixed: |_| None,
    },
    // "routing.http.preserve_host_header.enabled - ... The default is false."
    LoadBalancerAttributeSpec {
        key: "routing.http.preserve_host_header.enabled",
        domain: AttributeDomain::Boolean,
        families: APPLICATION_ONLY,
        default: |_| Some("false".to_string()),
        fixed: |_| None,
    },
    // "routing.http.x_amzn_tls_version_and_cipher_suite.enabled - ... The default is
    // false."
    LoadBalancerAttributeSpec {
        key: "routing.http.x_amzn_tls_version_and_cipher_suite.enabled",
        domain: AttributeDomain::Boolean,
        families: APPLICATION_ONLY,
        default: |_| Some("false".to_string()),
        fixed: |_| None,
    },
    // "routing.http.desync_mitigation_mode - ... The possible values are monitor,
    // defensive, and strictest. The default is defensive."
    LoadBalancerAttributeSpec {
        key: "routing.http.desync_mitigation_mode",
        domain: AttributeDomain::OneOf(&["monitor", "defensive", "strictest"]),
        families: APPLICATION_ONLY,
        default: |_| Some("defensive".to_string()),
        fixed: |_| None,
    },
    // "load_balancing.cross_zone.enabled - ... The default for Network Load Balancers
    // and Gateway Load Balancers is false. The default for Application Load Balancers is
    // true, and can't be changed." Documented "supported by all load balancers".
    LoadBalancerAttributeSpec {
        key: "load_balancing.cross_zone.enabled",
        domain: AttributeDomain::Boolean,
        families: EVERY_FAMILY,
        default: |load_balancer| {
            Some(
                match load_balancer.family() {
                    LoadBalancerFamily::Application => "true",
                    LoadBalancerFamily::Network | LoadBalancerFamily::Gateway => "false",
                }
                .to_string(),
            )
        },
        fixed: |load_balancer| {
            (load_balancer.family() == LoadBalancerFamily::Application)
                .then(|| "true".to_string())
        },
    },
    // "client_keep_alive.seconds - The client keep alive value, in seconds. The valid
    // range is 60-604800 seconds. The default is 3600 seconds."
    LoadBalancerAttributeSpec {
        key: "client_keep_alive.seconds",
        domain: AttributeDomain::Integer {
            min: 60,
            max: 604_800,
        },
        families: APPLICATION_ONLY,
        default: |_| Some("3600".to_string()),
        fixed: |_| None,
    },
    // "waf.fail_open.enabled - ... The default is false."
    LoadBalancerAttributeSpec {
        key: "waf.fail_open.enabled",
        domain: AttributeDomain::Boolean,
        families: APPLICATION_ONLY,
        default: |_| Some("false".to_string()),
        fixed: |_| None,
    },
    // "zonal_shift.config.enabled - Indicates whether zonal shift is enabled. The
    // possible values are true and false. The default is false." Documented for both
    // Application and Network Load Balancers.
    LoadBalancerAttributeSpec {
        key: "zonal_shift.config.enabled",
        domain: AttributeDomain::Boolean,
        families: APPLICATION_AND_NETWORK,
        default: |_| Some("false".to_string()),
        fixed: |_| None,
    },
    // "connection_logs.s3.enabled - Indicates whether connection logs are enabled. The
    // value is true or false. The default is false."
    LoadBalancerAttributeSpec {
        key: "connection_logs.s3.enabled",
        domain: AttributeDomain::Boolean,
        families: APPLICATION_ONLY,
        default: |_| Some("false".to_string()),
        fixed: |_| None,
    },
    // "connection_logs.s3.bucket - The name of the S3 bucket for the connection logs."
    LoadBalancerAttributeSpec {
        key: "connection_logs.s3.bucket",
        domain: AttributeDomain::Text,
        families: APPLICATION_ONLY,
        default: |_| Some(String::new()),
        fixed: |_| None,
    },
    // "connection_logs.s3.prefix - The prefix for the location in the S3 bucket for the
    // connection logs."
    LoadBalancerAttributeSpec {
        key: "connection_logs.s3.prefix",
        domain: AttributeDomain::Text,
        families: APPLICATION_ONLY,
        default: |_| Some(String::new()),
        fixed: |_| None,
    },
    // "ipv6.deny_all_igw_traffic - Blocks internet gateway (IGW) access to the load
    // balancer. It is set to false for internet-facing load balancers and true for
    // internal load balancers". A write of it is accepted on the families the
    // documentation lists it under, but the value follows the scheme rather than being
    // held per load balancer, and the attribute collection a read and a write answer with
    // does not carry it — so it is reported only once a caller has written one.
    LoadBalancerAttributeSpec {
        key: "ipv6.deny_all_igw_traffic",
        domain: AttributeDomain::Boolean,
        families: APPLICATION_AND_NETWORK,
        default: |_| None,
        fixed: |_| None,
    },
    // "The following attributes are supported by only Network Load Balancers:"
    //
    // "dns_record.client_routing_policy - Indicates how traffic is distributed among the
    // load balancer Availability Zones. The possible values are
    // availability_zone_affinity ..., partial_availability_zone_affinity ... and
    // any_availability_zone ..." — three values and no documented default, so it is
    // reported once a caller has set one.
    LoadBalancerAttributeSpec {
        key: "dns_record.client_routing_policy",
        domain: AttributeDomain::OneOf(&[
            "availability_zone_affinity",
            "partial_availability_zone_affinity",
            "any_availability_zone",
        ]),
        families: NETWORK_ONLY,
        default: |_| None,
        fixed: |_| None,
    },
    // "secondary_ips.auto_assigned.per_subnet - The number of secondary IP addresses to
    // configure for your load balancer nodes. ... The valid range is 0 to 7. The default
    // is 0."
    LoadBalancerAttributeSpec {
        key: "secondary_ips.auto_assigned.per_subnet",
        domain: AttributeDomain::Integer { min: 0, max: 7 },
        families: NETWORK_ONLY,
        default: |_| Some("0".to_string()),
        fixed: |_| None,
    },
];

/// The attribute whose documentation decides whether a load balancer can be deleted:
/// "deletion_protection.enabled - Indicates whether deletion protection is enabled."
pub const DELETION_PROTECTION_ATTRIBUTE: &str = "deletion_protection.enabled";

/// The families of an attribute the documentation lists under "supported by all load
/// balancers".
const EVERY_FAMILY: &[LoadBalancerFamily] = &[
    LoadBalancerFamily::Application,
    LoadBalancerFamily::Network,
    LoadBalancerFamily::Gateway,
];

/// The families of an attribute "supported by both Application Load Balancers and
/// Network Load Balancers".
const APPLICATION_AND_NETWORK: &[LoadBalancerFamily] =
    &[LoadBalancerFamily::Application, LoadBalancerFamily::Network];

/// The families of an attribute "supported by only Application Load Balancers".
const APPLICATION_ONLY: &[LoadBalancerFamily] = &[LoadBalancerFamily::Application];

/// The families of an attribute "supported by only Network Load Balancers".
const NETWORK_ONLY: &[LoadBalancerFamily] = &[LoadBalancerFamily::Network];

/// The attribute `key` names, or `None` when no load balancer attribute carries that
/// name.
pub fn load_balancer_attribute(key: &str) -> Option<&'static LoadBalancerAttributeSpec> {
    LOAD_BALANCER_ATTRIBUTES.iter().find(|spec| spec.key == key)
}

/// The `Scheme` of a load balancer that is not reachable from the internet, from the
/// model's `LoadBalancerSchemeEnum` (`internal`, `internet-facing`).
pub const INTERNAL_SCHEME: &str = "internal";

/// The one IP address type `IpAddressType` documents for every load balancer family.
pub const IPV4_ADDRESS_TYPE: &str = "ipv4";

/// The IP address type only an Application Load Balancer accepts, from
/// `SetIpAddressTypeInput$IpAddressType`: "[Application Load Balancers] The possible
/// values are ipv4 ..., dualstack ..., and dualstack-without-public-ipv4 ... [Network
/// Load Balancers and Gateway Load Balancers] The possible values are ipv4 ... and
/// dualstack".
pub const APPLICATION_ONLY_ADDRESS_TYPE: &str = "dualstack-without-public-ipv4";

/// How Elastic Load Balancing classifies a refusal of a rule its model declares no error
/// shape for — which is the thing a client branches on, so each rule below carries its own
/// class and answers under the same code wherever it is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The request's own values do not satisfy a rule this service documents in prose: a
    /// required number of subnets, an attribute key it defines no attribute under, the
    /// IPv6 ranges a placement that asks for IPv6 addresses needs. Elastic Load Balancing
    /// answers these under `ValidationError`
    /// ([`crate::scaffolded::Scaffolded::validation_error`]), whatever the operation's own
    /// model declares, so the caller is told to fix the request.
    Validation(String),
    /// The resources the request names cannot hold the configuration together: subnets of
    /// two VPCs or two subnets of one Availability Zone, an address member the family or
    /// scheme does not carry, a security group that cannot govern this load balancer's
    /// traffic. That is the modelled "the requested configuration is not valid".
    Configuration(String),
}

impl Refusal {
    /// What the caller has to fix, as the refusal states it.
    pub fn message(self) -> String {
        match self {
            Self::Validation(message) | Self::Configuration(message) => message,
        }
    }
}

/// The `EnablePrefixForIpv6SourceNatEnum` value that turns source NAT prefixes on, from
/// that enum's own values (`off`, `on`).
pub const SOURCE_NAT_PREFIX_ON: &str = "on";

/// The `IpAddressType` an IPv6 source NAT prefix requires, from
/// `EnablePrefixForIpv6SourceNat`'s documentation: "The IP address type must be
/// dualstack."
pub const DUALSTACK_ADDRESS_TYPE: &str = "dualstack";

/// Whether a load balancer carrying `ip_address_type` can have the source NAT prefix
/// `prefix` asks for, and — when it cannot — the rule it broke.
///
/// `EnablePrefixForIpv6SourceNat`'s own documentation pairs the two: "[Network Load
/// Balancers with UDP listeners] Indicates whether to use an IPv6 prefix from each subnet
/// for source NAT. The IP address type must be `dualstack`." One reading of that pairing,
/// which `CreateLoadBalancer` and `SetSubnets` — the two operations that take the member —
/// both apply, so a create cannot start a load balancer in a configuration the other would
/// refuse to set.
pub fn check_source_nat_prefix(
    prefix: Option<&str>,
    ip_address_type: &str,
) -> Result<(), Refusal> {
    if prefix == Some(SOURCE_NAT_PREFIX_ON) && ip_address_type != DUALSTACK_ADDRESS_TYPE {
        return Err(Refusal::Configuration(format!(
            "EnablePrefixForIpv6SourceNat can only be '{SOURCE_NAT_PREFIX_ON}' for a load \
             balancer whose IP address type is '{DUALSTACK_ADDRESS_TYPE}', and this one is \
             '{ip_address_type}'"
        )));
    }
    Ok(())
}

/// Whether a load balancer of `family` can use `ip_address_type`, and — when it cannot —
/// the rule it broke, so a refusal can name the value and the rule the caller has to
/// satisfy.
///
/// One rule, from `IpAddressType`'s own documentation on the operations that set it:
/// `dualstack-without-public-ipv4` is bracketed for Application Load Balancers alone,
/// while the other two values are listed for every family. Nothing here is decided on the
/// load balancer's SCHEME: an internal load balancer carries IPv6 addresses like any
/// other once its subnets have IPv6 ranges, which is [`check_subnet_ipv6_cidrs`].
pub fn check_ip_address_type(
    family: LoadBalancerFamily,
    ip_address_type: &str,
) -> Result<(), Refusal> {
    if ip_address_type == APPLICATION_ONLY_ADDRESS_TYPE && family != LoadBalancerFamily::Application
    {
        // Elastic Load Balancing words this refusal about the LOAD BALANCER's type: the
        // fixed frame below, with the type of the load balancer the request addressed —
        // the address type the caller asked for is not restated in it.
        return Err(Refusal::Configuration(format!(
            "The specified IP address type is not supported on load balancers with type \
             '{}'.",
            family_type_name(family)
        )));
    }
    Ok(())
}

/// What a placement asking for IPv6 addresses needs of the subnets it names, in the words
/// Elastic Load Balancing refuses one without it with.
pub const IPV6_CIDR_REQUIRED: &str = "You must specify subnets with an associated IPv6 CIDR block.";

/// Whether the subnets a load balancer is placed in can carry `ip_address_type`, and — when
/// they cannot — the rule the request broke.
///
/// Every `IpAddressType` but [`IPV4_ADDRESS_TYPE`] gives the load balancer IPv6 addresses,
/// and those come out of the IPv6 range of the subnet each node sits in, so a placement
/// asking for one needs subnets that have an IPv6 CIDR block associated with them — every
/// one of them, since a node is placed in each. The load balancer's scheme does not enter
/// into it.
///
/// Which ranges a subnet holds is EC2's to say, so the rule is judged on what EC2 reported
/// (`resolved`); with no EC2 to ask nothing is known and nothing is refused, because a
/// refusal has to be grounded in what EC2 reported rather than assumed from silence.
///
/// The ONE reading of that rule, called by `CreateLoadBalancer` for the subnets a load
/// balancer starts in, by `SetSubnets` for the subnets that replace them and by
/// `SetIpAddressType` for the subnets it already has.
pub fn check_subnet_ipv6_cidrs(
    ip_address_type: &str,
    resolved: Option<&[network::SubnetFacts]>,
) -> Result<(), Refusal> {
    if ip_address_type == IPV4_ADDRESS_TYPE {
        return Ok(());
    }
    let Some(resolved) = resolved else {
        return Ok(());
    };
    if resolved
        .iter()
        .any(|subnet| !subnet.has_ipv6_cidr())
    {
        return Err(Refusal::Validation(IPV6_CIDR_REQUIRED.to_string()));
    }
    Ok(())
}

/// How many subnets an Application Load Balancer is placed in at least, from
/// `Subnets`/`SubnetMappings`' own documentation: "[Application Load Balancers] You must
/// specify subnets from at least two Availability Zones" — one subnet per zone, so two
/// subnets.
pub const SUBNETS_PER_APPLICATION_LOAD_BALANCER: usize = 2;

/// The words Elastic Load Balancing refuses a placement with fewer subnets than an
/// Application Load Balancer needs with — the rule itself, with nothing from the request
/// in it: what the caller has to fix is which subnets the request names.
pub const SUBNETS_IN_TWO_ZONES_REQUIRED: &str =
    "At least two subnets in two different Availability Zones must be specified";

/// Whether a load balancer of `family` can be placed in `count` subnets and — when it
/// cannot — the rule it broke.
///
/// `count` is how many PLACEMENTS the request asks for: every entry of `Subnets` and every
/// entry of `SubnetMappings`, each of which places the load balancer in one subnet whether
/// or not it spells that subnet's id out. Counting the entries rather than the ids is what
/// makes this bound dominate every per-entry step that follows it — the zone records
/// persisted on the load balancer, and the addresses resolved against EC2 — so no request
/// can ask for more of them than a Region has zones.
///
/// Both bounds come from the same documentation, and they are refused under different codes
/// because they are different kinds of failure. The ceiling is `Subnets`' "you can specify
/// only one subnet per Availability Zone", so at most the [`SUBNETS_PER_LOAD_BALANCER`]
/// zones this emulator's Regions have: a request past it names two subnets in one zone
/// whatever those subnets are, which is a placement no load balancer can hold —
/// [`Refusal::Configuration`]. The floor belongs to the Application family alone — its
/// subnets must come "from at least two Availability Zones", while a Network or Gateway Load
/// Balancer "can specify subnets from one or more Availability Zones", so one is enough —
/// and it is a count the request itself has to satisfy, which Elastic Load Balancing
/// answers as [`Refusal::Validation`].
///
/// The ONE reading of both, called by `CreateLoadBalancer` for the subnets a new load
/// balancer starts in and by `SetSubnets` for the subnets that replace them, BEFORE either
/// does any work proportional to what the request named.
pub fn check_placement_count(family: LoadBalancerFamily, count: usize) -> Result<(), Refusal> {
    if count > SUBNETS_PER_LOAD_BALANCER {
        return Err(Refusal::Configuration(format!(
            "You can specify only one subnet per Availability Zone, so at most \
             {SUBNETS_PER_LOAD_BALANCER} subnets, and this request names {count}"
        )));
    }
    if family == LoadBalancerFamily::Application && count < SUBNETS_PER_APPLICATION_LOAD_BALANCER {
        return Err(Refusal::Validation(
            SUBNETS_IN_TWO_ZONES_REQUIRED.to_string(),
        ));
    }
    Ok(())
}

/// Whether the addresses a `SubnetMapping` pins can be pinned on a load balancer of
/// `family` with this `scheme`, and — when they cannot — the rule the request broke.
///
/// Each member of `SubnetMapping` is documented for ONE family, and two of them for one
/// scheme of it: `AllocationId` is "[Network Load Balancers] the allocation ID of the
/// Elastic IP address for an internet-facing load balancer", `PrivateIPv4Address` is
/// "[Network Load Balancers] the private IPv4 address for an internal load balancer", and
/// `IPv6Address` and `SourceNatIpv6Prefix` are "[Network Load Balancers]" — which
/// `SubnetMappings`' own documentation states as the same rule from the other side:
/// "[Application Load Balancers] ... You can't specify Elastic IP addresses for your
/// subnets", "[Gateway Load Balancers] ... You can't specify Elastic IP addresses for your
/// subnets", and "[Network Load Balancers] ... You can specify one Elastic IP address per
/// subnet ... for your internet-facing load balancer. For internal load balancers, you can
/// specify one private IP address per subnet ... For internet-facing load balancer, you can
/// specify one IPv6 address per subnet."
///
/// So a member the request pins on a load balancer it is not documented for is refused
/// rather than stored on a load balancer that could never carry it. The ONE reading of
/// that rule, called by `CreateLoadBalancer` and `SetSubnets`.
pub fn check_subnet_mapping(
    family: LoadBalancerFamily,
    scheme: &str,
    mapping: &SubnetMapping,
) -> Result<(), String> {
    let internal = scheme == INTERNAL_SCHEME;
    // (how a refusal about the SCHEME names what the member pins — the opening of that
    // sentence, so it is capitalised — how a refusal about the load balancer's TYPE names
    // it, whether the request pins it, and whether this load balancer carries it).
    let pinned: [(&str, &str, bool, bool); 4] = [
        (
            "Elastic IPs",
            "Elastic IP addresses",
            mapping.allocation_id.is_some(),
            family == LoadBalancerFamily::Network && !internal,
        ),
        (
            "Private IPv4 addresses",
            "private IP addresses",
            mapping.private_i_pv4_address.is_some(),
            family == LoadBalancerFamily::Network && internal,
        ),
        (
            "IPv6 addresses",
            "IPv6 addresses",
            mapping.i_pv6_address.is_some(),
            family == LoadBalancerFamily::Network && !internal,
        ),
        (
            "IPv6 source NAT prefixes",
            "IPv6 source NAT prefixes",
            mapping.source_nat_ipv6_prefix.is_some(),
            family == LoadBalancerFamily::Network,
        ),
    ];
    for (by_scheme, by_type, requested, carried) in pinned {
        if !requested || carried {
            continue;
        }
        // WHICH of the two the caller has to fix: a family that carries the member for no
        // scheme at all, or the scheme of a family that carries it for the other one.
        // The scheme half is worded as AWS words it — what is not supported, and the
        // scheme of the load balancer it was asked for.
        return Err(if family == LoadBalancerFamily::Network {
            format!("{by_scheme} are not supported for load balancers with scheme '{scheme}'")
        } else {
            format!(
                "You cannot specify {by_type} with a load balancer of type '{}'",
                family_type_name(family)
            )
        });
    }
    Ok(())
}

/// The VPC a load balancer placed in these subnets is in: the one every subnet EC2
/// reported belongs to.
///
/// A load balancer's network interfaces all live in one VPC, so subnets that do not agree
/// on one — or that EC2 could not be asked about — resolve no VPC and the member is left
/// unreported rather than guessed from the first of them.
pub fn subnets_vpc(resolved: Option<&[network::SubnetFacts]>) -> Option<String> {
    let mut vpcs = resolved?
        .iter()
        .filter_map(|subnet| subnet.vpc_id.as_deref());
    let first = vpcs.next()?;
    vpcs.all(|vpc| vpc == first).then(|| first.to_string())
}

/// Whether every subnet a request places a load balancer in belongs to ONE VPC — the one
/// the load balancer already carries when it carries one — and, when one does not, the
/// rule the request broke.
///
/// A load balancer's network interfaces live in the subnets it is placed in and a network
/// interface belongs to exactly one VPC, so a placement that spans two VPCs is a
/// configuration no load balancer can hold: the whole request is refused rather than
/// leaving the load balancer straddling two VPCs or silently moved out of its own. Which
/// VPC each subnet is in is EC2's to say, so the comparison is made on what EC2 reported
/// (`resolved`); with no EC2 to ask nothing is known and nothing is refused, because a
/// refusal has to be grounded in what EC2 reported rather than assumed from silence.
///
/// `carried` is the VPC the load balancer is already in, for a call that REPLACES its
/// subnets; a load balancer that carries none yet — and a create, which has none — is
/// judged against the VPC of the FIRST subnet the request names, the VPC the placement
/// would put it in.
///
/// The ONE reading of that rule, called by `CreateLoadBalancer` for the subnets a load
/// balancer starts in and by `SetSubnets` for the subnets that replace them.
///
/// `resolved` is what EC2 answered about `requested_subnets` — the facts of exactly those
/// ids, because a read naming one the account holds no subnet for is refused WHOLE — so
/// every fact in it is a subnet this placement names, and `requested_subnets` is what says
/// in which ORDER the request named them.
pub fn check_subnet_vpcs(
    carried: Option<&str>,
    requested_subnets: &[String],
    resolved: Option<&[network::SubnetFacts]>,
) -> Result<(), String> {
    let Some(resolved) = resolved else {
        return Ok(());
    };
    let reported_vpc = |subnet_id: &str| -> Option<&str> {
        resolved
            .iter()
            .find(|subnet| subnet.subnet_id == subnet_id)?
            .vpc_id
            .as_deref()
    };
    let Some(vpc_id) = carried.or_else(|| {
        requested_subnets
            .iter()
            .find_map(|subnet_id| reported_vpc(subnet_id))
    }) else {
        return Ok(());
    };
    if resolved
        .iter()
        .any(|subnet| subnet.vpc_id.as_deref().is_some_and(|held| held != vpc_id))
    {
        return Err(format!("All subnets must belong to the same VPC: '{vpc_id}'"));
    }
    Ok(())
}

/// The refusal the security groups a request names earn when they cannot be applied to the
/// load balancer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityGroupRefusal {
    /// The request named a value that is not a security group id at all, so no security
    /// group exists under it in any account: the modelled "the specified security group
    /// does not exist", stated in the words [`SECURITY_GROUP_NOT_FOUND`] carries.
    NotFound,
    /// The groups the request named cannot govern THIS load balancer's traffic: one of them
    /// is a group id this account holds no group for, or one that governs traffic in
    /// another VPC than the one the load balancer's network interfaces live in. Either way
    /// the request is a configuration that cannot hold together, which the modelled
    /// `InvalidConfigurationRequest` states in the words Elastic Load Balancing words it
    /// ([`INVALID_SECURITY_GROUPS`]).
    Invalid,
}

/// The words Elastic Load Balancing refuses a request whose security groups cannot be
/// applied to the load balancer's network interfaces with.
///
/// A fixed sentence, because what the caller has to fix is WHICH groups the request names
/// rather than anything about one value: no one of them is more at fault than another.
pub const INVALID_SECURITY_GROUPS: &str = "One or more security groups are invalid";

/// What the modelled refusal for a value that names no security group at all states, which
/// is the sentence the model itself gives `InvalidSecurityGroupException`
/// (`smithy_query(query="shape",shape="InvalidSecurityGroupException")`). It names no
/// value, because a request may carry several and none of them is more at fault.
pub const SECURITY_GROUP_NOT_FOUND: &str = "The specified security group does not exist";

/// The prefix of a security group id, from EC2's own ids.
const SECURITY_GROUP_ID_PREFIX: &str = "sg-";

/// Whether `id` is shaped like a security group id: [`SECURITY_GROUP_ID_PREFIX`] followed
/// by 8 or 17 hexadecimal digits — the short and the long form EC2 mints ids in.
///
/// A value outside that form names no security group of ANY account, so it is judged here
/// rather than asked about: it is a value the request carries, not an id to look for.
pub fn security_group_id_is_well_formed(id: &str) -> bool {
    let Some(suffix) = id.strip_prefix(SECURITY_GROUP_ID_PREFIX) else {
        return false;
    };
    matches!(suffix.len(), 8 | 17) && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether the security groups a request names can be applied to a load balancer in
/// `vpc_id`, and — when they cannot — the refusal the request earns.
///
/// A load balancer's security groups govern traffic to its network interfaces, which live
/// in the subnets it is placed in and belong to one VPC, so there are two ways a request's
/// groups can fail and Elastic Load Balancing answers them differently. A value that is not
/// a security group id at all is no group of ANY account, which is the modelled "the
/// specified security group does not exist". An id that IS one but names no group of this
/// account — or names a group governing traffic in another VPC — is a group this load
/// balancer cannot be given, so the request is a configuration that cannot hold together:
/// the modelled `InvalidConfigurationRequest`, in the words [`INVALID_SECURITY_GROUPS`].
///
/// `named` is what the request listed, judged on its own form; `lookup` is what EC2
/// answered about those ids. Whether a group exists and which VPC it governs traffic in is
/// EC2's to say, so those two readings are of what EC2 ANSWERED: nothing is refused on them
/// when there is no EC2 to ask ([`network::SecurityGroupLookup::Unknown`], which is also
/// the answer for a request that names no group at all), and a load balancer whose own VPC
/// is not known yet is judged on existence alone.
///
/// The ONE reading of that rule, called by `CreateLoadBalancer` for the groups a new load
/// balancer starts with — BEFORE it judges the name, because a caller told to rename cannot
/// discover that its groups are the problem — and by `SetSecurityGroups` for the groups
/// that replace them.
pub fn check_security_groups(
    vpc_id: Option<&str>,
    named: &[String],
    lookup: &network::SecurityGroupLookup,
) -> Result<(), SecurityGroupRefusal> {
    if named
        .iter()
        .any(|id| !security_group_id_is_well_formed(id))
    {
        return Err(SecurityGroupRefusal::NotFound);
    }
    match lookup {
        network::SecurityGroupLookup::Absent(_) => Err(SecurityGroupRefusal::Invalid),
        network::SecurityGroupLookup::Unknown => Ok(()),
        network::SecurityGroupLookup::Resolved(groups) => {
            let Some(vpc_id) = vpc_id else {
                return Ok(());
            };
            if groups.iter().any(|group| {
                group
                    .vpc_id
                    .as_deref()
                    .is_some_and(|holding| holding != vpc_id)
            }) {
                return Err(SecurityGroupRefusal::Invalid);
            }
            Ok(())
        }
    }
}

/// The `LoadBalancerTypeEnum` value a family is named by, for a refusal that states which
/// kind of load balancer the request asked for.
///
/// Public because the refusals an attribute write answers name the type the same way
/// ([`load_balancer_attribute_unsupported_message`]).
pub fn family_type_name(family: LoadBalancerFamily) -> &'static str {
    match family {
        LoadBalancerFamily::Application => "application",
        LoadBalancerFamily::Network => "network",
        LoadBalancerFamily::Gateway => "gateway",
    }
}

/// The letters AWS appends to a region to name an Availability Zone.
const ZONE_LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

/// How many subnets one load balancer is placed in at most.
///
/// `Subnets`/`SubnetMappings` are caller-chosen lists whose length the model bounds
/// nowhere, and the rule that bounds them is `Subnets`' own documentation: "you can
/// specify only one subnet per Availability Zone" — so the ceiling is the number of zones
/// a Region has. This emulator names those zones with the 26 letters [`ZONE_LETTERS`]
/// carries, far above the handful any AWS Region publishes, so that is the number: a
/// request past it cannot be one subnet per zone whatever its subnets are.
pub const SUBNETS_PER_LOAD_BALANCER: usize = ZONE_LETTERS.len();

/// The zones a load balancer placed in these subnets is attached to, one per requested
/// subnet, taken from `Subnets` or `SubnetMappings` (the model: "you must specify either
/// subnets or subnet mappings, but not both").
///
/// Which zone a subnet is in is EC2's to say, so it is the zone EC2 reported for that
/// subnet (`resolved`). A subnet EC2 could not be asked about — no EC2 is mounted, or it
/// holds no such subnet — is given a zone of the request's region that no other subnet of
/// this load balancer is in, so two subnets never read as the same zone whether their
/// zones were resolved or stood in for: the zones already taken are held in a set, and
/// the stand-in walks a cursor that never goes back, so every subnet is named in one
/// step. Either way the mapping is persisted on the load balancer, so every later read
/// reports the same zone for the same subnet.
///
/// The ONE reading of a request's subnets, called by `CreateLoadBalancer` for the zones a
/// new load balancer starts in and by `SetSubnets` for the zones that replace them. The
/// caller's list is bounded by [`SUBNETS_PER_LOAD_BALANCER`] before this runs.
pub fn availability_zone_records(
    subnets: &[String],
    subnet_mappings: &[SubnetMapping],
    region: &str,
    resolved: Option<&[network::SubnetFacts]>,
) -> Vec<AvailabilityZoneRecord> {
    let reported_zone = |subnet_id: &str| -> Option<String> {
        resolved?
            .iter()
            .find(|subnet| subnet.subnet_id == subnet_id)?
            .availability_zone
            .clone()
    };
    // Each requested subnet, in the order the request listed it, with the zone EC2
    // reported for it when it reported one.
    let mut requested: Vec<(String, Vec<LoadBalancerAddressRecord>, Option<String>)> = Vec::new();
    for subnet_id in subnets {
        let zone = reported_zone(subnet_id);
        requested.push((subnet_id.clone(), Vec::new(), zone));
    }
    for mapping in subnet_mappings {
        // Only what the caller pinned is kept: the emulator models no address pool,
        // so it never invents an `IpAddress`.
        let address = LoadBalancerAddressRecord {
            allocation_id: mapping.allocation_id.clone(),
            private_ipv4_address: mapping.private_i_pv4_address.clone(),
            ipv6_address: mapping.i_pv6_address.clone(),
        };
        let addresses = if address.is_empty() {
            Vec::new()
        } else {
            vec![address]
        };
        let subnet_id = mapping.subnet_id.clone().unwrap_or_default();
        let zone = reported_zone(&subnet_id);
        requested.push((subnet_id, addresses, zone));
    }

    let mut taken: std::collections::HashSet<String> = requested
        .iter()
        .filter_map(|(_, _, zone)| zone.clone())
        .collect();
    let mut cursor = 0usize;
    requested
        .into_iter()
        .map(|(subnet_id, addresses, zone)| {
            let zone_name = zone.unwrap_or_else(|| loop {
                let letter = char::from(ZONE_LETTERS[cursor % ZONE_LETTERS.len()]);
                let wrap = cursor / ZONE_LETTERS.len();
                cursor += 1;
                let candidate = if wrap == 0 {
                    format!("{region}{letter}")
                } else {
                    format!("{region}{letter}{wrap}")
                };
                if taken.insert(candidate.clone()) {
                    return candidate;
                }
            });
            AvailabilityZoneRecord {
                zone_name,
                subnet_id,
                outpost_id: None,
                addresses,
            }
        })
        .collect()
}

/// The message Elastic Load Balancing answers a `ResourceNotFound` with for a policy read
/// whose `ResourceArn` names no policy to report.
///
/// Built from the request: the ARN it names is the only thing the caller can act on, and
/// what the caller has to fix is that ARN — whether it named a trust store this account
/// does not have, one no policy is attached to, or a resource that carries no resource
/// policy at all. It is the same sentence every refusal about a trust store ADDRESSED BY
/// ARN carries ([`trust_store_arn_not_found_message`]), read from there rather than spelled
/// again, so one endpoint cannot word that one fact two ways.
pub fn trust_store_policy_not_found_message(arn: &str) -> String {
    trust_store_arn_not_found_message(arn)
}

/// The message Elastic Load Balancing answers a `LoadBalancerNotFound` with for an
/// operation that addresses ONE load balancer through its own required
/// `LoadBalancerArn` — the attribute read and write, the network writes
/// (`SetIpAddressType`, `SetSecurityGroups`, `SetSubnets`, `ModifyIpPools`), the
/// capacity-reservation read and write, and the creates and reads that hang a resource
/// off one.
///
/// Built from the request: the identifier it names is the only thing the caller can act
/// on, exactly as the listener-addressing operations quote their `ListenerArn` back
/// ([`listener_not_found_message`]), while a read over a LIST of load balancers names
/// either the identifiers it could not resolve ([`load_balancers_not_found_message`]) or
/// no value at all ([`load_balancer_selection_not_found_message`]).
pub fn load_balancer_not_found_message(arn: &str) -> String {
    format!("Load balancer '{arn}' not found")
}

/// The message Elastic Load Balancing answers a delete of a load balancer whose
/// deletion protection is on with, under the modelled "this operation is not allowed":
/// `DeleteLoadBalancer` documents "You can't delete a load balancer if deletion
/// protection is enabled".
///
/// Built from the request, like the not-found messages beside it: the ARN the caller
/// named, under the rule it broke.
pub fn deletion_protection_message(arn: &str) -> String {
    format!("Load balancer '{arn}' cannot be deleted because deletion protection is enabled")
}

/// The message Elastic Load Balancing answers a `LoadBalancerNotFound` with for a read
/// over a LIST of identifiers (`DescribeLoadBalancers`, whose `LoadBalancerArns` and
/// `Names` are both lists).
///
/// Built from the request, like every other not-found message here: the identifiers that
/// did not resolve, under the PLURAL noun, rendered as the LIST the request carried —
/// `Load balancers '[my-alb]' not found` for one name, and the same form with more
/// entries for more of them. The brackets are what makes it a list rather than one
/// resource, which is what the recorded answer to a `DescribeLoadBalancers(Names=[...])`
/// of an absent name carries.
pub fn load_balancers_not_found_message<'a>(
    identifiers: impl IntoIterator<Item = &'a str>,
) -> String {
    let named: Vec<&str> = identifiers.into_iter().collect();
    format!("Load balancers '[{}]' not found", named.join(", "))
}

/// The message Elastic Load Balancing answers a `LoadBalancerNotFound` with for a read
/// that selected by ARN (`DescribeLoadBalancers`' `LoadBalancerArns`).
///
/// The same read's two selectors are refused in different words: a selection by NAME
/// lists the names that did not resolve ([`load_balancers_not_found_message`]), while a
/// selection by ARN names no value at all — the shape of message this service's sibling
/// list reads answer ([`listener_selection_not_found_message`],
/// [`target_group_selection_not_found_message`]), and what the recorded answer to a
/// `DescribeLoadBalancers(LoadBalancerArns=[...])` of an absent ARN carries.
pub fn load_balancer_selection_not_found_message() -> String {
    "One or more load balancers not found".to_string()
}

/// Whether a protocol carries HTTP semantics, which is what decides whether a health
/// check has a path and a response-code matcher and whether a target group reports a
/// `ProtocolVersion`.
pub fn is_http_protocol(protocol: Option<&str>) -> bool {
    matches!(protocol, Some("HTTP") | Some("HTTPS"))
}

/// The protocols a HEALTH CHECK may use, from `HealthCheckProtocol`'s own
/// documentation: "The GENEVE, TLS, UDP, TCP_UDP, QUIC, and TCP_QUIC protocols are not
/// supported for health checks" — leaving HTTP, HTTPS and TCP.
pub const HEALTH_CHECK_PROTOCOLS: &[&str] = &["HTTP", "HTTPS", "TCP"];

/// The protocols a health check of a target group whose own protocol is `protocol` may
/// use, from `HealthCheckProtocol`'s own documentation: [`HEALTH_CHECK_PROTOCOLS`] are the
/// ones health checks support at all, and "the TCP protocol is not supported for health
/// checks if the protocol of the target group is HTTP or HTTPS" takes TCP out for an HTTP
/// target group.
pub fn health_check_protocols_for(protocol: Option<&str>) -> &'static [&'static str] {
    if is_http_protocol(protocol) {
        return &["HTTP", "HTTPS"];
    }
    HEALTH_CHECK_PROTOCOLS
}

/// Whether `health_check_protocol` is one a health check of a target group whose protocol
/// is `protocol` may use, and — when it is not — the message the write is refused with.
///
/// ONE reading of the two rules `HealthCheckProtocol`'s documentation states, applied by
/// the create that first stores a health check and by the modify that changes it: a value
/// outside [`health_check_protocols_for`] is refused naming the value and the protocols
/// that target group's health check may use, which is what the caller has to choose from.
pub fn check_health_check_protocol(
    health_check_protocol: Option<&str>,
    protocol: Option<&str>,
) -> Result<(), String> {
    let Some(health_check_protocol) = health_check_protocol else {
        return Ok(());
    };
    let admitted = health_check_protocols_for(protocol);
    if admitted.contains(&health_check_protocol) {
        return Ok(());
    }
    Err(format!(
        "Health check protocol '{health_check_protocol}' must be one of '{}'",
        admitted.join(", ")
    ))
}

/// The one `HealthCheckPort` value that is not a port number: the model documents it as
/// that member's default — "traffic-port, which is the port on which each target
/// receives traffic from the load balancer".
pub const TRAFFIC_PORT: &str = "traffic-port";

/// The ports a health check may name. `HealthCheckPort` is modelled as a bare string
/// (`smithy_query(query="shape",shape="HealthCheckPort")` -> `{"type": "string"}`), so
/// the model constrains nothing about it and the handler that accepts it is the only
/// gate; the bound is the one the model puts on every port member it does type as an
/// integer (`Port` and `TargetControlPort`: `range 1..65535`).
pub const HEALTH_CHECK_PORT_RANGE: std::ops::RangeInclusive<u32> = 1..=65535;

/// Whether `value` is a health-check port this service accepts — the literal
/// [`TRAFFIC_PORT`], or a port inside [`HEALTH_CHECK_PORT_RANGE`] — and, when it is
/// not, the rule it broke, so the refusal can name the member, the value and the
/// bound the caller has to fix.
pub fn check_health_check_port(value: &str) -> Result<(), String> {
    if value == TRAFFIC_PORT
        || value
            .parse::<u32>()
            .is_ok_and(|port| HEALTH_CHECK_PORT_RANGE.contains(&port))
    {
        return Ok(());
    }
    Err(format!(
        "Health check port '{value}' must be within '{}-{}' or '{TRAFFIC_PORT}'",
        HEALTH_CHECK_PORT_RANGE.start(),
        HEALTH_CHECK_PORT_RANGE.end(),
    ))
}

/// The published maximum length of a target group name, from `CreateTargetGroup`'s
/// `Name` documentation: "can have a maximum of 32 characters".
pub const TARGET_GROUP_NAME_MAX_LENGTH: usize = 32;

/// The maximum length of a health-check path, from the `@length` the model puts on the
/// `Path` shape `HealthCheckPath` targets (`smithy_query(query="shape",shape="Path")` ->
/// `length 1..1024`).
pub const HEALTH_CHECK_PATH_MAX_LENGTH: usize = 1024;

/// Whether `value` is a health-check path this service accepts — a destination the load
/// balancer can request: an absolute path, so it begins with `/`, written in printable
/// ASCII with no spaces, within the length the model bounds it to — and, when it is not,
/// the rule it broke, so the refusal can name the member, the value and the rule the
/// caller has to fix.
///
/// The model types `HealthCheckPath` as `Path` with a length alone, so every other clause
/// is server-side and this is the only gate: a path the load balancer cannot send is a
/// probe that can never match, which is why it is refused at the create rather than
/// stored.
pub fn check_health_check_path(value: &str) -> Result<(), String> {
    let printable_ascii_without_spaces = value
        .chars()
        .all(|character| character.is_ascii_graphic());
    // The character rule first, so a value that is no absolute printable-ASCII path is
    // told that rather than a length it may well be inside.
    if !value.starts_with('/') || !printable_ascii_without_spaces {
        return Err(format!(
            "Health check path '{value}' must begin with a '/' character and can only \
             contain printable ASCII characters, without spaces"
        ));
    }
    // The model's `@length` counts CHARACTERS, not bytes.
    if value.chars().count() > HEALTH_CHECK_PATH_MAX_LENGTH {
        return Err(format!(
            "Health check path '{value}' cannot be longer than \
             '{HEALTH_CHECK_PATH_MAX_LENGTH}' characters"
        ));
    }
    Ok(())
}

/// Which family of load balancer a target group serves, which is what decides WHICH
/// attributes it carries (the families the model's `TargetGroupAttribute$Key`
/// documentation groups the attributes by) and what its health check defaults to.
///
/// Derived from the target group's own protocol, as the model's `Protocol`
/// documentation pairs them: "For Application Load Balancers, the supported protocols
/// are HTTP and HTTPS. For Network Load Balancers, the supported protocols are TCP,
/// TLS, UDP, TCP_UDP, QUIC, or TCP_QUIC. For Gateway Load Balancers, the supported
/// protocol is GENEVE." A `lambda` target group has no protocol at all and is an
/// Application Load Balancer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalancerFamily {
    Application,
    Network,
    Gateway,
}

/// The family a target group whose protocol is `protocol` serves — see
/// [`LoadBalancerFamily`]. The ONE reading of that pairing, which
/// [`TargetGroupRecord::family`] answers from the stored record and a create calls
/// before there is a record to ask.
pub fn protocol_family(protocol: Option<&str>) -> LoadBalancerFamily {
    match protocol {
        Some("GENEVE") => LoadBalancerFamily::Gateway,
        Some("TCP") | Some("TLS") | Some("UDP") | Some("TCP_UDP") | Some("QUIC")
        | Some("TCP_QUIC") => LoadBalancerFamily::Network,
        // HTTP, HTTPS, and a `lambda` target group, which carries no protocol.
        _ => LoadBalancerFamily::Application,
    }
}

/// The set of values one attribute accepts, as its own documentation states it
/// (`smithy_query(query="doc",shape="TargetGroupAttribute",member="Key")` for a target
/// group's, `shape="ListenerAttribute"` for a listener's).
#[derive(Debug, Clone, Copy)]
pub enum AttributeDomain {
    /// "The value is `true` or `false`."
    Boolean,
    /// Any string: what the documentation describes as a name or a header value the
    /// caller chooses, stating no set of values to check it against.
    Text,
    /// An integer in the documented inclusive range.
    Integer { min: i64, max: i64 },
    /// The literal `off`, or an integer in the documented inclusive range.
    IntegerOrOff { min: i64, max: i64 },
    /// `0` (the documented "disabled"), or an integer in the documented range.
    ZeroOrInteger { min: i64, max: i64 },
    /// One of a documented set of literals.
    OneOf(&'static [&'static str]),
    /// A cookie name: any value whose prefix is not one the load balancer reserves.
    CookieName,
}

/// The cookie-name prefixes `stickiness.app_cookie.cookie_name` may not carry:
/// "Names that start with the following prefixes are not allowed: AWSALB, AWSALBAPP,
/// and AWSALBTG; they're reserved for use by the load balancer."
const RESERVED_COOKIE_PREFIXES: &[&str] = &["AWSALB", "AWSALBAPP", "AWSALBTG"];

impl AttributeDomain {
    /// Whether `value` is in this domain and — when it is not — the message the write of
    /// `key` on an `owner`'s attributes is refused with, in the words Elastic Load
    /// Balancing refuses that CLASS of value with.
    ///
    /// Which sentence it is depends on HOW the value misses the domain, because that is
    /// what the caller has to act on:
    ///
    /// * a value that is no integer at all: "The value of '<key>' must be a valid integer",
    ///   with the literal the domain also admits named where it has one;
    /// * an integer outside the documented range: the bound it missed — "The value of
    ///   '<key>' cannot be less than <min> characters" and the `greater than <max>` form
    ///   beside it — except on a LISTENER's attributes, whose own validator states the
    ///   whole range instead: "'<key>' value '<value>' must be between '<min>-<max>'
    ///   inclusive";
    /// * a value outside an enumerated set, of which a boolean is the two-value case: "The
    ///   value of '<key>' must be 'true' or 'false', but was '<value>'".
    ///
    /// The one difference between the owners is the range sentence, and it is recorded
    /// behaviour: the answers this service is checked against word a load balancer
    /// attribute's bound and a listener attribute's range that way.
    pub fn check(&self, owner: AttributeOwner, key: &str, value: &str) -> Result<(), String> {
        // An integer domain misses in two ways, and each has its own sentence: the value
        // is not an integer, or it is one the range does not admit. `alternative` names
        // the literal the domain admits beside the range, for the domains that have one.
        let integer = |min: i64, max: i64, alternative: Option<&str>| -> Result<(), String> {
            let Ok(parsed) = value.parse::<i64>() else {
                return Err(match alternative {
                    Some(literal) => {
                        format!("The value of '{key}' must be '{literal}' or a valid integer")
                    }
                    None => format!("The value of '{key}' must be a valid integer"),
                });
            };
            if parsed >= min && parsed <= max {
                return Ok(());
            }
            Err(match (owner, parsed < min) {
                (AttributeOwner::Listener, _) => {
                    format!("'{key}' value '{value}' must be between '{min}-{max}' inclusive")
                }
                (_, true) => format!("The value of '{key}' cannot be less than {min} characters"),
                (_, false) => {
                    format!("The value of '{key}' cannot be greater than {max} characters")
                }
            })
        };
        // The sentence a value outside an enumerated set earns, listing what the set holds.
        let one_of = |values: &[&str]| -> String {
            let listed: Vec<String> = values.iter().map(|value| format!("'{value}'")).collect();
            format!(
                "The value of '{key}' must be {}, but was '{value}'",
                listed.join(" or ")
            )
        };
        match *self {
            Self::Boolean => match value {
                "true" | "false" => Ok(()),
                _ => Err(one_of(&["true", "false"])),
            },
            // Nothing to check: the documentation states no domain for it, so refusing
            // a value here would be this emulator's own rule rather than the service's.
            Self::Text => Ok(()),
            Self::Integer { min, max } => integer(min, max, None),
            Self::IntegerOrOff { min, max } => {
                if value == "off" {
                    return Ok(());
                }
                integer(min, max, Some("off"))
            }
            Self::ZeroOrInteger { min, max } => {
                if value == "0" {
                    return Ok(());
                }
                integer(min, max, Some("0"))
            }
            Self::OneOf(values) => {
                if values.contains(&value) {
                    return Ok(());
                }
                Err(one_of(values))
            }
            Self::CookieName => {
                if RESERVED_COOKIE_PREFIXES
                    .iter()
                    .any(|prefix| value.starts_with(prefix))
                {
                    return Err(format!(
                        "The value of '{key}' must not start with {}, which are reserved for \
                         use by the load balancer",
                        RESERVED_COOKIE_PREFIXES.join(", ")
                    ));
                }
                Ok(())
            }
        }
    }

    /// The largest integer this domain admits, for a domain stated as a RANGE; `None` for
    /// one that is not a range at all.
    ///
    /// What it is for: a SPAN read out of an attribute is bounded by the attribute's own
    /// documented range, which is the range [`Self::check`] refuses a write outside — so a
    /// span taken from the collection cannot exceed what a write could have stored, and
    /// the ceiling is read from the catalog rather than restated beside it.
    pub fn integer_ceiling(&self) -> Option<i64> {
        match *self {
            Self::Integer { max, .. }
            | Self::IntegerOrOff { max, .. }
            | Self::ZeroOrInteger { max, .. } => Some(max),
            Self::Boolean | Self::Text | Self::OneOf(_) | Self::CookieName => None,
        }
    }
}

/// One target group attribute: which target groups carry it, what it accepts, and the
/// value it reports until something sets it.
pub struct AttributeSpec {
    pub key: &'static str,
    pub domain: AttributeDomain,
    /// Whether a target group of this shape carries the attribute at all.
    applies: fn(&TargetGroupRecord) -> bool,
    /// The value the attribute COLLECTION carries this attribute at until a caller
    /// writes one: its documented default, and the empty string for a string-valued
    /// attribute whose documentation states no value. `None` marks an attribute the
    /// collection does not carry at all, which a write of it is what puts there.
    default: fn(&TargetGroupRecord) -> Option<String>,
}

impl std::fmt::Debug for AttributeSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttributeSpec")
            .field("key", &self.key)
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

impl AttributeSpec {
    /// Whether `group` carries this attribute.
    pub fn applies_to(&self, group: &TargetGroupRecord) -> bool {
        (self.applies)(group)
    }

    /// The value `group` reports for this attribute until something sets it.
    pub fn default_for(&self, group: &TargetGroupRecord) -> Option<String> {
        (self.default)(group)
    }
}

/// Every target group attribute this service models, with the family it belongs to,
/// the values it accepts and the value it is carried at until a write — each one a
/// sentence of the model's own `TargetGroupAttribute$Key` documentation
/// (`smithy_query(query="doc",shape="TargetGroupAttribute",member="Key")`), which is
/// the only catalog of them; the Smithy shape itself is an unconstrained key/value
/// pair, so nothing else in the model lists them.
///
/// The ORDER of this list is the documentation's own, and the order a target group's
/// attribute collection is reported in
/// ([`TargetGroupRecord::effective_attributes`]).
pub static TARGET_GROUP_ATTRIBUTES: &[AttributeSpec] = &[
    // Supported by all load balancers.
    AttributeSpec {
        key: "deregistration_delay.timeout_seconds",
        domain: AttributeDomain::Integer { min: 0, max: 3600 },
        // "If the target is a Lambda function, this attribute is not supported."
        applies: |group| !group.is_lambda(),
        default: |_| Some("300".to_string()),
    },
    AttributeSpec {
        key: "stickiness.enabled",
        domain: AttributeDomain::Boolean,
        applies: |group| !group.is_lambda(),
        default: |_| Some("false".to_string()),
    },
    AttributeSpec {
        key: "stickiness.type",
        domain: AttributeDomain::OneOf(&[
            "lb_cookie",
            "app_cookie",
            "source_ip",
            "source_ip_dest_ip",
            "source_ip_dest_ip_proto",
        ]),
        applies: |group| !group.is_lambda(),
        // "lb_cookie and app_cookie for Application Load Balancers. source_ip for
        // Network Load Balancers. source_ip_dest_ip and source_ip_dest_ip_proto for
        // Gateway Load Balancers."
        default: |group| {
            Some(
                match group.family() {
                    LoadBalancerFamily::Application => "lb_cookie",
                    LoadBalancerFamily::Network => "source_ip",
                    LoadBalancerFamily::Gateway => "source_ip_dest_ip",
                }
                .to_string(),
            )
        },
    },
    // Supported by Application Load Balancers and Network Load Balancers — and so by
    // neither a Gateway Load Balancer's target group nor a Lambda one (see
    // [`TargetGroupRecord::carries_connection_attributes`]).
    AttributeSpec {
        key: "load_balancing.cross_zone.enabled",
        domain: AttributeDomain::OneOf(&["true", "false", "use_load_balancer_configuration"]),
        applies: TargetGroupRecord::carries_connection_attributes,
        default: |_| Some("use_load_balancer_configuration".to_string()),
    },
    AttributeSpec {
        key: "target_group_health.dns_failover.minimum_healthy_targets.count",
        domain: AttributeDomain::IntegerOrOff { min: 1, max: i64::MAX },
        applies: TargetGroupRecord::carries_connection_attributes,
        default: |_| Some("1".to_string()),
    },
    AttributeSpec {
        key: "target_group_health.dns_failover.minimum_healthy_targets.percentage",
        domain: AttributeDomain::IntegerOrOff { min: 1, max: 100 },
        applies: TargetGroupRecord::carries_connection_attributes,
        default: |_| Some("off".to_string()),
    },
    AttributeSpec {
        key: "target_group_health.unhealthy_state_routing.minimum_healthy_targets.count",
        domain: AttributeDomain::Integer { min: 1, max: i64::MAX },
        applies: TargetGroupRecord::carries_connection_attributes,
        default: |_| Some("1".to_string()),
    },
    AttributeSpec {
        key: "target_group_health.unhealthy_state_routing.minimum_healthy_targets.percentage",
        domain: AttributeDomain::IntegerOrOff { min: 1, max: 100 },
        applies: TargetGroupRecord::carries_connection_attributes,
        default: |_| Some("off".to_string()),
    },
    // Supported only if the load balancer is an Application Load Balancer and the
    // target is an instance or an IP address.
    AttributeSpec {
        key: "load_balancing.algorithm.type",
        domain: AttributeDomain::OneOf(&[
            "round_robin",
            "least_outstanding_requests",
            "weighted_random",
        ]),
        applies: TargetGroupRecord::is_application_with_addressable_targets,
        default: |_| Some("round_robin".to_string()),
    },
    AttributeSpec {
        key: "load_balancing.algorithm.anomaly_mitigation",
        domain: AttributeDomain::OneOf(&["on", "off"]),
        applies: TargetGroupRecord::is_application_with_addressable_targets,
        default: |_| Some("off".to_string()),
    },
    AttributeSpec {
        key: "slow_start.duration_seconds",
        // "The range is 30-900 seconds (15 minutes). The default is 0 seconds
        // (disabled)."
        domain: AttributeDomain::ZeroOrInteger { min: 30, max: 900 },
        applies: TargetGroupRecord::is_application_with_addressable_targets,
        default: |_| Some("0".to_string()),
    },
    AttributeSpec {
        key: "stickiness.app_cookie.cookie_name",
        domain: AttributeDomain::CookieName,
        applies: TargetGroupRecord::is_application_with_addressable_targets,
        // A cookie name the caller chooses, with no value stated for it: the collection
        // carries it at the empty string until a caller names a cookie.
        default: |_| Some(String::new()),
    },
    AttributeSpec {
        key: "stickiness.app_cookie.duration_seconds",
        domain: AttributeDomain::Integer { min: 1, max: 604_800 },
        applies: TargetGroupRecord::is_application_with_addressable_targets,
        default: |_| Some("86400".to_string()),
    },
    AttributeSpec {
        key: "stickiness.lb_cookie.duration_seconds",
        domain: AttributeDomain::Integer { min: 1, max: 604_800 },
        applies: TargetGroupRecord::is_application_with_addressable_targets,
        default: |_| Some("86400".to_string()),
    },
    // Supported only if the load balancer is an Application Load Balancer and the
    // target is a Lambda function.
    AttributeSpec {
        key: "lambda.multi_value_headers.enabled",
        domain: AttributeDomain::Boolean,
        applies: TargetGroupRecord::is_lambda,
        default: |_| Some("false".to_string()),
    },
    // Supported only by Network Load Balancers.
    AttributeSpec {
        key: "deregistration_delay.connection_termination.enabled",
        domain: AttributeDomain::Boolean,
        applies: |group| group.family() == LoadBalancerFamily::Network,
        // "For new UDP/TCP_UDP target groups the default is true. Otherwise, the
        // default is false."
        default: |group| {
            Some(
                match group.protocol.as_deref() {
                    Some("UDP") | Some("TCP_UDP") => "true",
                    _ => "false",
                }
                .to_string(),
            )
        },
    },
    AttributeSpec {
        key: "preserve_client_ip.enabled",
        domain: AttributeDomain::Boolean,
        applies: |group| group.family() == LoadBalancerFamily::Network,
        // "The default is disabled if the target group type is IP address and the
        // target group protocol is TCP or TLS. Otherwise, the default is enabled."
        default: |group| {
            let ip_tcp = group.target_type == "ip"
                && matches!(group.protocol.as_deref(), Some("TCP") | Some("TLS"));
            Some(if ip_tcp { "false" } else { "true" }.to_string())
        },
    },
    AttributeSpec {
        key: "proxy_protocol_v2.enabled",
        domain: AttributeDomain::Boolean,
        applies: |group| group.family() == LoadBalancerFamily::Network,
        default: |_| Some("false".to_string()),
    },
    AttributeSpec {
        key: "target_health_state.unhealthy.connection_termination.enabled",
        domain: AttributeDomain::Boolean,
        applies: |group| group.family() == LoadBalancerFamily::Network,
        default: |_| Some("true".to_string()),
    },
    AttributeSpec {
        key: "target_health_state.unhealthy.draining_interval_seconds",
        domain: AttributeDomain::Integer { min: 0, max: 360_000 },
        applies: |group| group.family() == LoadBalancerFamily::Network,
        default: |_| Some("0".to_string()),
    },
    // Supported only by Gateway Load Balancers.
    AttributeSpec {
        key: "target_failover.on_deregistration",
        domain: AttributeDomain::OneOf(&["rebalance", "no_rebalance"]),
        applies: |group| group.family() == LoadBalancerFamily::Gateway,
        default: |_| Some("no_rebalance".to_string()),
    },
    AttributeSpec {
        key: "target_failover.on_unhealthy",
        domain: AttributeDomain::OneOf(&["rebalance", "no_rebalance"]),
        applies: |group| group.family() == LoadBalancerFamily::Gateway,
        default: |_| Some("no_rebalance".to_string()),
    },
    AttributeSpec {
        key: "send_tcp_reset.on_unhealthy.enabled",
        domain: AttributeDomain::Boolean,
        applies: |group| group.family() == LoadBalancerFamily::Gateway,
        default: |_| Some("false".to_string()),
    },
    AttributeSpec {
        key: "send_tcp_reset.on_deregistration.enabled",
        domain: AttributeDomain::Boolean,
        applies: |group| group.family() == LoadBalancerFamily::Gateway,
        default: |_| Some("false".to_string()),
    },
];

/// The attribute `key` names, or `None` when no target group attribute carries that
/// name.
pub fn target_group_attribute(key: &str) -> Option<&'static AttributeSpec> {
    TARGET_GROUP_ATTRIBUTES.iter().find(|spec| spec.key == key)
}

/// One target registered with a target group.
#[derive(Debug, Clone)]
pub struct RegisteredTarget {
    pub id: String,
    /// The port the target receives traffic on: the one `RegisterTargets` gave, else
    /// the target group's own port.
    pub port: Option<i32>,
    pub availability_zone: Option<String>,
    pub registered_at: SystemTime,
    /// When the clock owes this registration its move out of `initial` — the instant
    /// health checking on it began plus [`SETTLE_AFTER`].
    pub healthy_at: SystemTime,
    /// When the clock owes this registration its REMOVAL from the target group, for a
    /// registration `DeregisterTargets` put in `draining`; `None` for one nothing has
    /// deregistered ([`target_health`]).
    pub draining_until: Option<SystemTime>,
    /// Where the periodic health check of this registration has got to, and the verdict it
    /// has reached ([`target_health::TargetProbe`]).
    pub probe: TargetProbe,
    /// The workload whose own scheduler registered this target, when another emulated
    /// service owns the registration rather than a `RegisterTargets` caller: the identifier
    /// of the task, instance or function it stands for.
    ///
    /// `None` for every registration a caller made through this service's own API, which is
    /// what keeps the two apart: a scheduler that reconciles its workload's registrations
    /// (an Amazon ECS service registering the tasks its `loadBalancers` bind) may add and
    /// remove the registrations it owns and must leave a caller's own alone.
    pub registered_for: Option<String>,
    /// The ports the workload behind this registration LISTENS on, as the scheduler that
    /// runs it declares them — empty for a registration nothing declares ports for, which
    /// is every `RegisterTargets` caller's own ([`ServedPorts`]).
    ///
    /// What a health check of this registration can get an answer on: the check connects to
    /// the group's effective health-check port ([`TargetGroupRecord::health_check_port_of`]),
    /// and a port the workload does not listen on is answered by nothing.
    pub serves_ports: ServedPorts,
    /// The security groups GOVERNING the address this registration names, as the scheduler
    /// that runs the workload declares them — `AwsVpcConfiguration$securityGroups`, "the IDs
    /// of the security groups associated with the task or service", for an Amazon ECS task.
    ///
    /// Empty for a registration nothing declares them for, which is every `RegisterTargets`
    /// caller's own: the groups of such a target are read off the network interface holding
    /// its address instead ([`health_check_firewall`]).
    ///
    /// What decides whether a health check of this registration ARRIVES: the groups' own
    /// inbound rules, which are Amazon EC2's records, are read against the load balancer
    /// performing the check.
    pub guarded_by: GuardingGroups,
}

/// How a registration is keyed in a target group: the target id and the port the target
/// receives traffic on, so "you can register each EC2 instance or IP address with the same
/// target group multiple times using different ports" holds.
pub type TargetKey = (String, Option<i32>);

/// A persisted target group.
#[derive(Debug, Clone, Default)]
pub struct TargetGroupRecord {
    pub arn: String,
    pub name: String,
    pub protocol: Option<String>,
    pub protocol_version: Option<String>,
    pub port: Option<i32>,
    pub vpc_id: Option<String>,
    pub target_type: String,
    pub ip_address_type: Option<String>,
    pub target_control_port: Option<i32>,
    pub health_check: HealthCheckConfig,
    /// The load balancers whose listeners (or rules) forward to this target group.
    pub load_balancer_arns: Vec<String>,
    pub attributes: HashMap<String, String>,
    pub tags: HashMap<String, String>,
    /// Registrations keyed by target id and effective port, so registering the same
    /// id on two ports keeps two registrations and re-registering one replaces it.
    pub targets: BTreeMap<TargetKey, RegisteredTarget>,
}

impl TargetGroupRecord {
    /// Whether this target group's targets are Lambda functions, which is what several
    /// defaults and one whole attribute family key on.
    pub fn is_lambda(&self) -> bool {
        self.target_type == "lambda"
    }

    /// Which load balancer family this target group serves — see
    /// [`LoadBalancerFamily`].
    pub fn family(&self) -> LoadBalancerFamily {
        protocol_family(self.protocol.as_deref())
    }

    /// Whether the attributes documented "only if the load balancer is an Application
    /// Load Balancer and the target is an instance or an IP address" apply here.
    pub fn is_application_with_addressable_targets(&self) -> bool {
        self.family() == LoadBalancerFamily::Application
            && matches!(self.target_type.as_str(), "instance" | "ip")
    }

    /// Whether the attributes that describe how the load balancer CONNECTS to this
    /// group's targets — stickiness, cross-zone load balancing, the target-group-health
    /// thresholds — apply here.
    ///
    /// They are documented for an Application or a Network Load Balancer, which rules
    /// out a Gateway Load Balancer's group; and they presume a target the load balancer
    /// opens connections to, which a Lambda function is not. The model documents
    /// exactly ONE attribute for a Lambda target
    /// (`lambda.multi_value_headers.enabled`), and the recorded
    /// `DescribeTargetGroupAttributes` of a Lambda target group answers a set this
    /// service matched only once the rest were left out of it.
    pub fn carries_connection_attributes(&self) -> bool {
        self.family() != LoadBalancerFamily::Gateway && !self.is_lambda()
    }

    /// Whether this target group's health check has a path and a response-code matcher.
    ///
    /// The model binds both to an HTTP/HTTPS health check ("[HTTP/HTTPS health checks]
    /// The destination for health checks on the targets"). A `lambda` target group
    /// reports no health-check protocol at all — the load balancer invokes the function
    /// rather than connecting to a port — and its health check is an HTTP one, so it
    /// carries them too.
    pub fn health_check_is_http(&self) -> bool {
        self.is_lambda() || is_http_protocol(self.health_check.protocol.as_deref())
    }

    /// Materialize the health-check members that exist only for an HTTP-semantic health
    /// check: fill the documented default of each one nothing has set, and drop both
    /// when the health check is not an HTTP one (a TCP check has neither a path nor a
    /// response-code matcher to report).
    ///
    /// Called after a create or a modify resolves the health check, so the stored
    /// record \u2014 and therefore every later read of it \u2014 carries exactly the members AWS
    /// reports for a group of this shape.
    pub fn settle_health_check_http_members(&mut self) {
        if self.health_check_is_http() {
            let protocol_version = self.protocol_version.clone();
            if self.health_check.path.is_none() {
                self.health_check.path = Some(default_health_check_path(protocol_version.as_deref()));
            }
            if self.health_check.matcher.is_none() {
                self.health_check.matcher = Some(default_health_check_matcher(
                    protocol_version.as_deref(),
                    self.family(),
                ));
            }
        } else {
            self.health_check.path = None;
            self.health_check.matcher = None;
        }
    }

    /// This target group's WHOLE attribute collection: every attribute the catalog
    /// carries for a group of this shape, each holding what a caller wrote or, failing
    /// that, the value it is carried at — which is what both a read and a write of these
    /// attributes answers with.
    ///
    /// In [`TARGET_GROUP_ATTRIBUTES`] order, which is the order the service reports them
    /// in, so two reads of one target group answer alike.
    pub fn effective_attributes(&self) -> Vec<(String, String)> {
        TARGET_GROUP_ATTRIBUTES
            .iter()
            .filter(|spec| spec.applies_to(self))
            .filter_map(|spec| {
                let value = self
                    .attributes
                    .get(spec.key)
                    .cloned()
                    .or_else(|| spec.default_for(self))?;
                Some((spec.key.to_string(), value))
            })
            .collect()
    }

    /// [`Self::effective_attributes`] as the modelled shape.
    pub fn attribute_shapes(&self) -> Vec<TargetGroupAttribute> {
        self.effective_attributes()
            .into_iter()
            .map(|(key, value)| TargetGroupAttribute {
                key: Some(key),
                value: Some(value),
            })
            .collect()
    }

    /// The settings `CreateTargetGroup` is idempotent over — see
    /// [`LoadBalancerRecord::has_settings_of`].
    pub fn has_settings_of(&self, other: &TargetGroupRecord) -> bool {
        self.protocol == other.protocol
            && self.protocol_version == other.protocol_version
            && self.port == other.port
            && self.vpc_id == other.vpc_id
            && self.target_type == other.target_type
            && self.ip_address_type == other.ip_address_type
            && self.target_control_port == other.target_control_port
            && self.health_check == other.health_check
            && self.tags == other.tags
    }

    pub fn to_shape(&self) -> TargetGroup {
        TargetGroup {
            target_group_arn: Some(self.arn.clone()),
            target_group_name: Some(self.name.clone()),
            protocol: self.protocol.clone(),
            port: self.port,
            vpc_id: self.vpc_id.clone(),
            health_check_protocol: self.health_check.protocol.clone(),
            health_check_port: self.health_check.port.clone(),
            health_check_enabled: Some(self.health_check.enabled),
            health_check_interval_seconds: Some(self.health_check.interval_seconds),
            health_check_timeout_seconds: Some(self.health_check.timeout_seconds),
            healthy_threshold_count: Some(self.health_check.healthy_threshold),
            unhealthy_threshold_count: Some(self.health_check.unhealthy_threshold),
            health_check_path: self.health_check.path.clone(),
            matcher: self.health_check.matcher.as_ref().map(MatcherRecord::to_shape),
            load_balancer_arns: Some(self.load_balancer_arns.clone()),
            target_type: Some(self.target_type.clone()),
            protocol_version: self.protocol_version.clone(),
            ip_address_type: self.ip_address_type.clone(),
            target_control_port: self.target_control_port,
        }
    }

    /// The port a health check of `target` runs against: the configured health-check
    /// port, or — for the modelled default [`TRAFFIC_PORT`] — the port the target
    /// receives traffic on.
    pub fn health_check_port_of(&self, target: &RegisteredTarget) -> Option<String> {
        self.health_check_port_for(target.port)
    }

    /// The port a health check runs against for a target whose own traffic port is
    /// `target_port` (`None` where the target names none and the group's own port stands
    /// for it): the configured health-check port, or — for the modelled default
    /// [`TRAFFIC_PORT`] — the port that target receives traffic on.
    ///
    /// Keyed on the PORT rather than on a registration, because what
    /// `TargetHealthDescription$HealthCheckPort` reports ("the port to use to connect with
    /// the target") follows from the group's health-check configuration and the target the
    /// read was asked about — which every described target has, whether or not the group
    /// holds a registration for it.
    pub fn health_check_port_for(&self, target_port: Option<i32>) -> Option<String> {
        match self.health_check.port.as_deref() {
            Some(TRAFFIC_PORT) | None => target_port.or(self.port).map(|p| p.to_string()),
            Some(port) => Some(port.to_string()),
        }
    }

    // The health of one registered target, the description of one that is not registered
    // and the description of one that is all live in [`target_health`]: the health STATE
    // MACHINE is one concern, read by the operation that reports it and by the data plane
    // that decides which targets may be sent a request. Both descriptions report the
    // health-check port [`Self::health_check_port_for`] answers for the target the read
    // was asked about.
}

/// The statuses the model's `TrustStoreStatus` enum names
/// (`smithy_query(query="shape",shape="TrustStoreStatus")`: `ACTIVE`, `CREATING`).
/// A trust store AWS returns from `CreateTrustStore` is not ready yet, so it starts
/// at `CREATING` and the clock owes it [`TRUST_STORE_ACTIVE`] at [`SETTLE_AFTER`].
pub const TRUST_STORE_CREATING: &str = "CREATING";
/// The status of a trust store whose settling span is over.
pub const TRUST_STORE_ACTIVE: &str = "ACTIVE";

/// A persisted trust store: everything `DescribeTrustStores` reports about one, plus
/// the two instants that decide the order it is reported in and when the clock owes it
/// its move to [`TRUST_STORE_ACTIVE`].
///
/// `CreateTrustStore` mints one — counting `number_of_ca_certificates` from the CA
/// certificates bundle it is given ([`ca_certificates_bundle`]) — `ModifyTrustStore`
/// rotates that bundle, and `DescribeTrustStores` reads the record back.
#[derive(Debug, Clone)]
pub struct TrustStoreRecord {
    pub arn: String,
    pub name: String,
    pub status: String,
    /// When the clock owes this trust store its move to [`TRUST_STORE_ACTIVE`].
    pub active_at: SystemTime,
    /// Creation order, which is the order a paginated read walks it in. Not reported:
    /// the `TrustStore` shape models no creation time.
    pub created_at: SystemTime,
    /// How many CA certificates the trust store's bundle holds — counted from that
    /// bundle's bytes when it is stored, never guessed.
    pub number_of_ca_certificates: i32,
    /// WHERE those certificates came from: the Amazon S3 object the create named, as the
    /// modification that rotates the bundle leaves it. `None` for a record no bundle
    /// address was stored with.
    pub ca_certificates_bundle: Option<CaCertificatesBundleLocation>,
    /// How many revoked certificates the trust store's revocation lists hold. Written
    /// by `AddTrustStoreRevocations`/`RemoveTrustStoreRevocations`, both still scaffold
    /// stubs, so the shape is read off this field rather than restated: it follows the
    /// store the day a revocation can be added.
    pub total_revoked_entries: i64,
    /// The tags on this trust store, which `DescribeTags` reports. A trust store is a
    /// taggable Elastic Load Balancing resource — `AddTags`/`RemoveTags` both model
    /// `TrustStoreNotFoundException` — so the tags live on the record beside every
    /// other taggable resource's, and a read answers what is stored rather than
    /// assuming a trust store can carry none.
    pub tags: HashMap<String, String>,
    /// The resource-based policy attached to this trust store, which
    /// `GetResourcePolicy` reports. `None` for a trust store no policy was attached to:
    /// a policy is what SHARING a trust store with another account writes, and this
    /// model declares no operation that writes one — it only reads a policy and deletes
    /// a share's association — so the record carries what was attached and a read
    /// answers from it rather than from a policy made up per call.
    pub resource_policy: Option<String>,
}

impl TrustStoreRecord {
    pub fn to_shape(&self) -> TrustStore {
        TrustStore {
            name: Some(self.name.clone()),
            trust_store_arn: Some(self.arn.clone()),
            status: Some(self.status.clone()),
            number_of_ca_certificates: Some(self.number_of_ca_certificates),
            // "The number of revoked certificates in the trust store" — what the
            // record holds, never a figure computed here.
            total_revoked_entries: Some(self.total_revoked_entries),
        }
    }
}

/// A persisted listener RULE: one a caller added with `CreateRule`, which is every rule
/// of a listener except the default rule the listener itself carries
/// ([`ListenerRecord::default_rule`]).
///
/// A rule belongs to exactly one listener and is stored on that listener's record, so
/// releasing the listener releases its rules with it and no second store can disagree
/// about which listener a rule belongs to.
#[derive(Debug, Clone, Default)]
pub struct RuleRecord {
    pub arn: String,
    /// "Rules are evaluated in priority order, from the lowest value to the highest
    /// value" — which is the order a read walks them in. Modelled as an integer on the
    /// way in (`RulePriority`) and as text on the way out (`Rule$Priority`), so the
    /// record keeps the number and the shape renders it.
    pub priority: i32,
    pub conditions: Vec<RuleCondition>,
    pub actions: Vec<Action>,
    /// The transforms applied to a request this rule matches. A rule carrying none is
    /// reported with the member PRESENT and empty, never with the member left out.
    pub transforms: Vec<RuleTransform>,
    /// The tags this rule was created with, which `DescribeTags` reports: a listener
    /// rule is a taggable Elastic Load Balancing resource.
    pub tags: HashMap<String, String>,
}

impl RuleRecord {
    pub fn to_shape(&self) -> Rule {
        Rule {
            rule_arn: Some(self.arn.clone()),
            priority: Some(self.priority.to_string()),
            // Each condition is reported under every spelling the model gives its
            // field, which is not always the spelling the create used
            // ([`reported_condition`]), and a redirect reports the components it leaves
            // unmodified as the keywords that retain them ([`reported_action`]).
            conditions: Some(self.conditions.iter().map(reported_condition).collect()),
            actions: Some(reported_actions(&self.actions)),
            // Only the rule a listener mints with itself is the default one.
            is_default: Some(false),
            // `Rule$Transforms` is a list member every reported rule carries: a rule with
            // no transform answers the empty list, which is a different answer from an
            // absent member.
            transforms: Some(self.transforms.clone()),
        }
    }
}

/// One rule CONDITION as a read reports it: the arrays it matches on under every
/// spelling the model gives that field, and nothing under a spelling the field has none
/// of.
///
/// `RuleCondition` carries a condition's values twice over — at the top level (`Values`,
/// `RegexValues`) and inside the field's own configuration shape — and the model
/// documents the top-level member as the ALTERNATIVE to the configuration one for the
/// fields it names: `Values` is to be specified "only when Field is host-header or
/// path-pattern. Alternatively, to specify multiple host names or multiple path patterns,
/// use HostHeaderConfig or PathPatternConfig", and `RegexValues` "only when Field is
/// http-header, host-header, or path-pattern". Two spellings of ONE array, so a read
/// answers both of the spellings a field has whichever one the create carried, and
/// reports a member the field has no top-level spelling for not at all — absent, which is
/// a different answer from an empty list.
fn reported_condition(condition: &RuleCondition) -> RuleCondition {
    let mut reported = condition.clone();
    let field = condition.field.clone().unwrap_or_default();
    match field.as_str() {
        "host-header" => {
            let mut config = reported.host_header_config.take().unwrap_or_default();
            mirror_condition_values(&mut reported.values, &mut config.values);
            mirror_condition_values(&mut reported.regex_values, &mut config.regex_values);
            reported.host_header_config =
                (config.values.is_some() || config.regex_values.is_some()).then_some(config);
        }
        "path-pattern" => {
            let mut config = reported.path_pattern_config.take().unwrap_or_default();
            mirror_condition_values(&mut reported.values, &mut config.values);
            mirror_condition_values(&mut reported.regex_values, &mut config.regex_values);
            reported.path_pattern_config =
                (config.values.is_some() || config.regex_values.is_some()).then_some(config);
        }
        "http-header" => {
            // This field has a top-level spelling for its REGULAR EXPRESSIONS and none
            // for its values: the header a condition matches on and the strings it
            // compares against are named together, inside the configuration shape.
            reported.values = None;
            let mut config = reported.http_header_config.take().unwrap_or_default();
            mirror_condition_values(&mut reported.regex_values, &mut config.regex_values);
            reported.http_header_config = (config.http_header_name.is_some()
                || config.values.is_some()
                || config.regex_values.is_some())
            .then_some(config);
        }
        // Every other documented field — `query-string`, `http-request-method` and
        // `source-ip` — the model gives no top-level spelling at all, so neither member
        // is reported for it.
        _ => {
            reported.values = None;
            reported.regex_values = None;
        }
    }
    reported
}

/// Fill in whichever of the two spellings of one condition array was left out, leaving a
/// spelling the caller gave exactly as it was given.
///
/// An EMPTY array is not mirrored: the model states that "the value for a condition can't
/// be empty", so there is nothing in it to answer under the other spelling, and a member
/// the request carried empty stays empty rather than turning into an absent one.
fn mirror_condition_values(direct: &mut Option<Vec<String>>, configured: &mut Option<Vec<String>>) {
    match (direct.as_deref(), configured.as_deref()) {
        (Some(values), None) if !values.is_empty() => *configured = direct.clone(),
        (None, Some(values)) if !values.is_empty() => *direct = configured.clone(),
        _ => {}
    }
}

/// The condition fields a rule may match on, from `RuleCondition$Field`'s documented
/// list: `http-header`, `http-request-method`, `host-header`, `path-pattern`,
/// `query-string` and `source-ip`. The model types that member as a plain string, so a
/// value outside the list is refused by [`check_rule_conditions`] rather than by the
/// boundary validator.
pub const CONDITION_FIELDS: &[&str] = &[
    "host-header",
    "http-header",
    "http-request-method",
    "path-pattern",
    "query-string",
    "source-ip",
];

/// The condition fields a rule carries AT MOST ONE of: "each rule can optionally include
/// up to one of each of the following conditions: `http-request-method`, `host-header`,
/// `path-pattern`, and `source-ip`" — while `http-header` and `query-string` may repeat.
pub const SINGLE_USE_CONDITION_FIELDS: &[&str] = &[
    "host-header",
    "http-request-method",
    "path-pattern",
    "source-ip",
];

/// The condition fields the model says to specify the top-level `Values` member for:
/// "The condition value. Specify only when `Field` is `host-header` or `path-pattern`.
/// Alternatively, to specify multiple host names or multiple path patterns, use
/// `HostHeaderConfig` or `PathPatternConfig`." A field outside this list has no top-level
/// spelling for its values, so naming the member for one states a value the condition has
/// nowhere to carry.
pub const FIELDS_WITH_TOP_LEVEL_VALUES: &[&str] = &["host-header", "path-pattern"];

/// The condition fields the model says to specify the top-level `RegexValues` member for:
/// "The regular expressions to match against the condition field. … Specify only when
/// `Field` is `http-header`, `host-header`, or `path-pattern`."
pub const FIELDS_WITH_TOP_LEVEL_REGEX_VALUES: &[&str] =
    &["host-header", "http-header", "path-pattern"];

/// The refusal a condition naming a top-level member its field has no spelling for earns:
/// the MEMBER the request carried and the field it carried it on, which together are all
/// the caller has to fix the request from.
pub fn unsupported_condition_member_message(member: &str, field: &str) -> String {
    format!("'{member}' is not supported for a condition of type '{field}'")
}

/// Enforce what the model states about a rule's CONDITIONS in prose and declares no
/// error shape for: every condition names a field this service matches on, a field that
/// may appear only once appears at most once, a condition names only the members its
/// field has a spelling for, and the values the whole rule carries stay inside the
/// published bound ([`CONDITION_VALUES_PER_RULE`]). Each refusal names the
/// value and the rule it broke, because that text is all the caller has to fix the
/// request from.
///
/// A rule's conditions are judged by the same clauses wherever they are SET — on the
/// create that first stores them and on the modification that replaces them — so one
/// reading of those clauses serves both.
pub fn check_rule_conditions(conditions: &[RuleCondition]) -> Result<(), String> {
    // How many conditions the rule carries is judged before what any of them matches on:
    // the COUNT is a bound of its own ([`CONDITIONS_PER_RULE`]), and Elastic Load
    // Balancing states it as the number a caller may specify.
    if conditions.len() > CONDITIONS_PER_RULE {
        return Err(format!("You can specify up to {CONDITIONS_PER_RULE} conditions"));
    }
    let mut values = 0usize;
    let mut single_use_seen: Vec<&str> = Vec::new();
    for condition in conditions {
        let field = condition.field.as_deref().unwrap_or_default();
        if !CONDITION_FIELDS.contains(&field) {
            return Err(format!(
                "Condition field '{field}' is not valid; it must be one of {}",
                CONDITION_FIELDS.join(", ")
            ));
        }
        if SINGLE_USE_CONDITION_FIELDS.contains(&field) {
            if single_use_seen.contains(&field) {
                // AWS's own wording for this refusal, built from the field the request
                // repeated: "A rule can only have one '<field>' condition".
                return Err(format!("A rule can only have one '{field}' condition"));
            }
            single_use_seen.push(field);
        }
        // The two members the model gives only SOME fields a top-level spelling for. A
        // condition that names one on a field without it is refused rather than silently
        // matching on nothing, because the values it carries would be reported — and
        // evaluated — under no spelling of that field at all.
        if condition.values.is_some() && !FIELDS_WITH_TOP_LEVEL_VALUES.contains(&field) {
            return Err(unsupported_condition_member_message("Values", field));
        }
        if condition.regex_values.is_some()
            && !FIELDS_WITH_TOP_LEVEL_REGEX_VALUES.contains(&field)
        {
            return Err(unsupported_condition_member_message("RegexValues", field));
        }
        values += condition_values(condition);
    }
    if values > CONDITION_VALUES_PER_RULE {
        // AWS's own wording for this refusal, which states the published limit and names
        // neither the count the request carried nor the condition it sat in: "A rule can
        // only have '<limit>' condition values and regex values".
        return Err(format!(
            "A rule can only have '{CONDITION_VALUES_PER_RULE}' condition values and \
             regex values"
        ));
    }
    Ok(())
}

/// How many values one condition matches on, whether they were given directly in
/// `Values` or through the field's own configuration shape.
fn condition_values(condition: &RuleCondition) -> usize {
    let listed = |values: Option<&Vec<String>>| values.map_or(0, Vec::len);
    let direct = listed(condition.values.as_ref()) + listed(condition.regex_values.as_ref());
    let configured = condition.host_header_config.as_ref().map_or(0, |config| {
        listed(config.values.as_ref()) + listed(config.regex_values.as_ref())
    }) + condition.path_pattern_config.as_ref().map_or(0, |config| {
        listed(config.values.as_ref()) + listed(config.regex_values.as_ref())
    }) + condition.http_header_config.as_ref().map_or(0, |config| {
        listed(config.values.as_ref()) + listed(config.regex_values.as_ref())
    }) + condition
        .query_string_config
        .as_ref()
        .map_or(0, |config| config.values.as_ref().map_or(0, Vec::len))
        + condition
            .http_request_method_config
            .as_ref()
            .map_or(0, |config| listed(config.values.as_ref()))
        + condition
            .source_ip_config
            .as_ref()
            .map_or(0, |config| listed(config.values.as_ref()));
    direct + configured
}

/// The action types that ROUTE a request, of which a rule carries exactly one: "Each rule
/// must include exactly one of the following routing actions: `forward`,
/// `fixed-response`, or `redirect`, and it must be the last action to be performed"
/// (`smithy_query(query="doc",shape="Action")`).
pub const ROUTING_ACTION_TYPES: &[&str] = &["forward", "fixed-response", "redirect"];

/// The action types that AUTHENTICATE a request, of which a rule carries at most one:
/// "Optionally, a rule for an HTTPS listener can also include one of the following user
/// authentication actions: `authenticate-oidc`, `authenticate-cognito`, or
/// `jwt-validation`" (`smithy_query(query="doc",shape="Action")`).
pub const AUTHENTICATION_ACTION_TYPES: &[&str] =
    &["authenticate-oidc", "authenticate-cognito", "jwt-validation"];

/// How many actions one rule carries: the ONE routing action it must include, and the one
/// user-authentication action it may include before it — the two sentences
/// [`ROUTING_ACTION_TYPES`] and [`AUTHENTICATION_ACTION_TYPES`] quote, which is where this
/// count comes from (no `DescribeAccountLimits` name carries it).
///
/// It is the FIRST thing [`check_rule_actions`] judges, so the work that walk does is
/// bounded by this number rather than by the length of the list a caller chose to send.
pub const ACTIONS_PER_RULE: usize = 2;

/// Enforce what the model states about a rule's ACTIONS and declares no error shape for: a
/// rule carries at most [`ACTIONS_PER_RULE`] of them, no action TYPE is specified twice,
/// exactly one routing action is present, that action is LAST, and at most one
/// user-authentication action precedes it.
///
/// A rule's actions are judged by the same clauses wherever they are SET — on the create
/// that first stores them and on the modification that replaces them — so one reading of
/// those clauses serves both, exactly as a rule's conditions are read once
/// ([`check_rule_conditions`]).
pub fn check_rule_actions(actions: &[Action]) -> Result<(), String> {
    // The COUNT is judged before what the actions ARE, as a rule's conditions are: past the
    // bound no list can hold together, and nothing below walks more actions than this.
    if actions.len() > ACTIONS_PER_RULE {
        return Err(format!("You can specify up to {ACTIONS_PER_RULE} actions"));
    }
    let kinds: Vec<&str> = actions.iter().map(|action| action.r#type.as_str()).collect();
    // An action list that names one TYPE twice does not say which of the two is performed —
    // the repeated type is what the refusal states, because it is what the caller removes.
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for kind in &kinds {
        if !seen.insert(kind) {
            return Err(format!(
                "You cannot specify multiple of the following action type: '{kind}'"
            ));
        }
    }
    let routing = kinds
        .iter()
        .filter(|kind| ROUTING_ACTION_TYPES.contains(kind))
        .count();
    if routing != 1 {
        return Err(format!(
            "A rule must include exactly one of the following actions: {}",
            ROUTING_ACTION_TYPES.join(", ")
        ));
    }
    // "...and it must be the last action to be performed": an action AFTER the routing one
    // would never run, so a list that puts one there asks for something the rule cannot do.
    if !kinds
        .last()
        .is_some_and(|kind| ROUTING_ACTION_TYPES.contains(kind))
    {
        return Err(format!(
            "The last action of a rule must be one of the following actions: {}",
            ROUTING_ACTION_TYPES.join(", ")
        ));
    }
    if kinds
        .iter()
        .filter(|kind| AUTHENTICATION_ACTION_TYPES.contains(kind))
        .count()
        > 1
    {
        return Err(format!(
            "A rule can only have one of the following actions: {}",
            AUTHENTICATION_ACTION_TYPES.join(", ")
        ));
    }
    Ok(())
}

/// How many transforms one rule carries: the one host header rewrite and the one URL
/// rewrite the model's sentence allows, which are also the two values
/// `TransformTypeEnum` declares (`smithy_query(query="shape",
/// shape="TransformTypeEnum")`: `host-header-rewrite`, `url-rewrite`).
///
/// It is what bounds [`check_rule_transforms`]: a list longer than the types there ARE must
/// repeat one of them, so the walk reads no further than this many entries plus the one that
/// repeats — the work is bounded by the enum rather than by the length of the list a caller
/// chose to send, the way [`ACTIONS_PER_RULE`] bounds a rule's actions.
pub const TRANSFORMS_PER_RULE: usize = 2;

/// Enforce what the model states about a rule's TRANSFORMS and declares no error shape
/// for: "You can add one host header rewrite transform and one URL rewrite transform" —
/// so a rule carries at most one transform of each type `TransformTypeEnum` declares, and
/// therefore at most [`TRANSFORMS_PER_RULE`] of them.
///
/// Judged wherever a rule's transforms are SET, by the create that first stores them and
/// by the modification that replaces them, exactly as its conditions are
/// ([`check_rule_conditions`]).
///
/// BOUNDED by the enum: every entry carries one of the two types, so a list past
/// [`TRANSFORMS_PER_RULE`] repeats a type inside its first [`TRANSFORMS_PER_RULE`] + 1
/// entries and is refused there. Nothing further is read, and the duplicate is found through
/// a set rather than by scanning what was accepted so far, so neither the number of
/// comparisons nor the work of one call grows with the length a request chose.
pub fn check_rule_transforms(transforms: &[RuleTransform]) -> Result<(), String> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for transform in transforms.iter().take(TRANSFORMS_PER_RULE + 1) {
        let kind = transform.r#type.as_str();
        if !seen.insert(kind) {
            return Err(format!("A rule carries at most one '{kind}' transform"));
        }
    }
    Ok(())
}

/// A persisted listener.
#[derive(Debug, Clone, Default)]
pub struct ListenerRecord {
    pub arn: String,
    pub load_balancer_arn: String,
    pub port: Option<i32>,
    pub protocol: Option<String>,
    pub ssl_policy: Option<String>,
    /// The listener's DEFAULT certificate — "[HTTPS and TLS listeners] The default
    /// certificate for the listener. You must provide exactly one certificate." — which
    /// is the one `CreateListener` and `ModifyListener` set and the only one a `Listener`
    /// shape reports.
    pub certificate_arns: Vec<String>,
    /// The listener's CERTIFICATE LIST: the additional certificates
    /// `AddListenerCertificates` puts on an HTTPS or TLS listener for SNI, in the order
    /// they were added. Separate from the default certificate above, because the two are
    /// managed by different operations and `DescribeListenerCertificates` reports them
    /// apart (`Certificate$IsDefault`).
    pub list_certificate_arns: Vec<String>,
    pub default_actions: Vec<Action>,
    pub alpn_policy: Vec<String>,
    /// The MUTUAL AUTHENTICATION the listener was configured with, as the create or the
    /// modification that set it carried it, and `None` for a listener nothing configured it
    /// on. A listener outside [`MUTUAL_AUTHENTICATION_PROTOCOL`] carries none at all.
    pub mutual_authentication: Option<MutualAuthenticationAttributes>,
    pub attributes: HashMap<String, String>,
    pub tags: HashMap<String, String>,
    /// The resource id of this listener's DEFAULT rule, minted with the listener: every
    /// listener has one, it carries the listener's default actions, and it is what
    /// `DescribeRules` reports for a listener nothing else has added a rule to.
    pub default_rule_id: String,
    /// The rules a caller added to this listener with `CreateRule`, in the order they
    /// were added; a read orders them by priority
    /// ([`ComAmazonawsElasticloadbalancingv2ElasticloadbalancingV10State::rules_of`]).
    pub rules: Vec<RuleRecord>,
}

impl ListenerRecord {
    /// The settings `CreateListener` is idempotent over. Actions are compared by the
    /// members this slice models — their type and the target group they forward to —
    /// because the whole action tree is stored but not all of it is comparable.
    pub fn has_settings_of(&self, other: &ListenerRecord) -> bool {
        self.protocol == other.protocol
            && self.ssl_policy == other.ssl_policy
            && sorted(&self.certificate_arns) == sorted(&other.certificate_arns)
            && self.alpn_policy == other.alpn_policy
            // The client certificate handling is one of the listener's settings, so two
            // listeners differing only in it are not "the same settings": they are compared
            // by what each is EFFECTIVELY under, so a request naming the mode the service
            // defaults is the idempotent repeat of one that named none.
            && self.effective_mutual_authentication() == other.effective_mutual_authentication()
            && action_summary(&self.default_actions) == action_summary(&other.default_actions)
    }

    pub fn to_shape(&self) -> Listener {
        Listener {
            listener_arn: Some(self.arn.clone()),
            load_balancer_arn: Some(self.load_balancer_arn.clone()),
            port: self.port,
            protocol: self.protocol.clone(),
            certificates: Some(
                self.certificate_arns
                    .iter()
                    .map(|arn| Certificate {
                        certificate_arn: Some(arn.clone()),
                        // `Certificate$IsDefault`: "This value is not included in the
                        // output when describing a listener, but is included when
                        // describing listener certificates."
                        is_default: None,
                    })
                    .collect(),
            ),
            ssl_policy: self.ssl_policy.clone(),
            default_actions: Some(reported_actions(&self.default_actions)),
            alpn_policy: Some(self.alpn_policy.clone()),
            // A WRITE answers with the listener it left behind as the request configured
            // it, so the member is there when a request set it and absent when none did;
            // a READ answers the listener's effective configuration
            // ([`Self::described_shape`]). The record holds a configuration only for a
            // listener the member belongs to — the write that sets it refuses it on any
            // other, and the modification that moves a listener off that protocol clears
            // it — so there is nothing to mask here.
            mutual_authentication: self.mutual_authentication.clone(),
        }
    }

    /// This listener as a READ of it reports it: [`Self::to_shape`] carrying the mutual
    /// authentication the listener EFFECTIVELY handles client certificates under
    /// ([`Self::effective_mutual_authentication`]).
    pub fn described_shape(&self) -> Listener {
        Listener {
            mutual_authentication: self.effective_mutual_authentication(),
            ..self.to_shape()
        }
    }

    /// The mutual authentication this listener EFFECTIVELY handles client certificates
    /// under: the configuration it was given, with every setting the configuration left
    /// out carried at the value the service carries it at — the mode a listener nothing
    /// configured mTLS on handles client certificates under being
    /// [`DEFAULT_MUTUAL_AUTHENTICATION_MODE`].
    ///
    /// A listener the member does not belong to has none at all
    /// ([`handles_client_certificates`]).
    pub fn effective_mutual_authentication(&self) -> Option<MutualAuthenticationAttributes> {
        if !self.handles_client_certificates() {
            return None;
        }
        let mut effective = self.mutual_authentication.clone().unwrap_or_default();
        if effective.mode.is_none() {
            effective.mode = Some(DEFAULT_MUTUAL_AUTHENTICATION_MODE.to_string());
        }
        Some(effective)
    }

    /// Whether this listener carries a mutual authentication configuration at all.
    pub fn handles_client_certificates(&self) -> bool {
        handles_client_certificates(self.protocol.as_deref())
    }

    /// Whether this listener terminates TLS, and so carries certificates at all.
    pub fn terminates_tls(&self) -> bool {
        terminates_tls(self.protocol.as_deref())
    }

    /// What `DescribeListenerCertificates` reports: the default certificate, then the
    /// certificate list.
    ///
    /// The operation is documented as describing "the default certificate and the
    /// certificate list for the specified HTTPS or TLS listener", and `IsDefault`
    /// distinguishes them, so a certificate that is in both appears twice — once as the
    /// default and once as a list entry — rather than being collapsed.
    pub fn certificate_shapes(&self) -> Vec<Certificate> {
        self.certificate_arns
            .iter()
            .map(|arn| Certificate {
                certificate_arn: Some(arn.clone()),
                is_default: Some(true),
            })
            .chain(self.list_certificate_arns.iter().map(|arn| Certificate {
                certificate_arn: Some(arn.clone()),
                is_default: Some(false),
            }))
            .collect()
    }

    /// The ARN a rule of this listener carrying the resource id `rule_id` has.
    ///
    /// A listener rule's ARN is its listener's with the resource type `listener-rule` and
    /// the rule's own id appended — the segments this service's ARNs carry
    /// (`listener/<type>/<name>/<lb-id>/<id>` and
    /// `listener-rule/<type>/<name>/<lb-id>/<listener-id>/<id>`), so it is derived from
    /// the stored listener ARN rather than rebuilt from parts. Every rule of a listener,
    /// the default one included, is named through here, so one place decides the form.
    pub fn rule_arn(&self, rule_id: &str) -> String {
        format!(
            "{}/{rule_id}",
            self.arn.replacen(":listener/", ":listener-rule/", 1)
        )
    }

    /// The ARN of this listener's default rule.
    pub fn default_rule_arn(&self) -> String {
        self.rule_arn(&self.default_rule_id)
    }

    /// This listener's default rule: the rule that forwards everything the listener's
    /// own rules do not match, which is why its actions ARE the listener's default
    /// actions and it matches on no condition.
    pub fn default_rule(&self) -> Rule {
        Rule {
            rule_arn: Some(self.default_rule_arn()),
            // The one priority AWS reports for a default rule; every other rule's is a
            // number.
            priority: Some("default".to_string()),
            conditions: Some(Vec::new()),
            actions: Some(reported_actions(&self.default_actions)),
            is_default: Some(true),
            // A default rule carries no transform, and reports that as the empty list
            // exactly as every other rule does ([`RuleRecord::to_shape`]).
            transforms: Some(Vec::new()),
        }
    }

    /// This listener's WHOLE attribute collection, for a listener of a load balancer in
    /// `family`: every attribute the catalog carries for such a listener, each holding
    /// the value stored for it or the value it is carried at — which is what both a read
    /// and a write of these attributes answers with — and nothing for an attribute this
    /// family's listeners do not carry or that the collection does not carry.
    ///
    /// In [`LISTENER_ATTRIBUTES`] order, which is the order the service reports them in.
    pub fn effective_attributes(&self, family: LoadBalancerFamily) -> Vec<(String, String)> {
        LISTENER_ATTRIBUTES
            .iter()
            .filter(|spec| spec.applies_to(family))
            .filter_map(|spec| {
                let value = self
                    .attributes
                    .get(spec.key)
                    .cloned()
                    .or_else(|| spec.default.map(str::to_string))?;
                Some((spec.key.to_string(), value))
            })
            .collect()
    }

    /// [`Self::effective_attributes`] as the modelled shapes a describe answers with.
    pub fn attribute_shapes(&self, family: LoadBalancerFamily) -> Vec<ListenerAttribute> {
        self.effective_attributes(family)
            .into_iter()
            .map(|(key, value)| ListenerAttribute {
                key: Some(key),
                value: Some(value),
            })
            .collect()
    }

    /// Every target group an ACTION of this listener forwards to: its default actions,
    /// and the actions of every rule a caller added to it.
    ///
    /// One place answers "what does this listener route to", because two questions are
    /// decided by it — which load balancers a target group reports under
    /// `LoadBalancerArns`, and whether a target group is "referenced by any actions" and
    /// so cannot be deleted.
    pub fn forwarded_target_group_arns(&self) -> Vec<String> {
        let mut arns = action_target_group_arns(&self.default_actions);
        for rule in &self.rules {
            arns.extend(action_target_group_arns(&rule.actions));
        }
        arns
    }
}

/// Every target group ARN an action forwards to, whether named directly or through a
/// `ForwardConfig`.
pub fn action_target_group_arns(actions: &[Action]) -> Vec<String> {
    let mut arns = Vec::new();
    for action in actions {
        if let Some(arn) = action.target_group_arn.as_ref() {
            arns.push(arn.clone());
        }
        if let Some(config) = action.forward_config.as_ref() {
            for tuple in config.target_groups.iter().flatten() {
                if let Some(arn) = tuple.target_group_arn.as_ref() {
                    arns.push(arn.clone());
                }
            }
        }
    }
    arns
}

/// The comparable projection of an action list: each action's type, order and the
/// target groups it forwards to.
fn action_summary(actions: &[Action]) -> Vec<(String, Option<i32>, Vec<String>)> {
    actions
        .iter()
        .map(|action| {
            (
                action.r#type.clone(),
                action.order,
                action_target_group_arns(std::slice::from_ref(action)),
            )
        })
        .collect()
}

/// The value `FixedResponseActionConfig$ContentType` takes when a fixed-response action
/// names none: "The content type. … If the value is not specified, the default value is
/// `text/plain`." One of that member's own documented valid values, so an action created
/// without it is reported — and served — carrying it.
pub const DEFAULT_FIXED_RESPONSE_CONTENT_TYPE: &str = "text/plain";

/// The `ActionTypeEnum` value of the action that passes a request to a target group —
/// "Specify only when `Type` is `forward`" brackets both spellings of the target groups it
/// distributes among.
pub const FORWARD_ACTION_TYPE: &str = "forward";

/// The weight a forward action's target group is DISTRIBUTED AT when the configuration
/// named none. `TargetGroupTuple$Weight` is "[t]he weight. The range is 0 to 999", and the
/// weights of a forward's groups are relative to one another, so one group carried at the
/// weight the service defaults takes every request the action matches — which is what a
/// forward to a single target group does.
pub const DEFAULT_TARGET_GROUP_WEIGHT: i32 = 1;

/// Whether target group stickiness is on for a forward action whose configuration did not
/// turn it on: `TargetGroupStickinessConfig$Enabled` "[i]ndicates whether target group
/// stickiness is enabled", and a forward distributes each request on its own until a
/// request enables it.
pub const DEFAULT_TARGET_GROUP_STICKINESS: bool = false;

/// A forward action's `ForwardConfig` as a read reports it: the target groups it
/// distributes among, each carried at the weight the configuration gave it or at
/// [`DEFAULT_TARGET_GROUP_WEIGHT`], and the stickiness the configuration gave it or
/// [`DEFAULT_TARGET_GROUP_STICKINESS`]. `None` for a forward action naming no target group
/// at all, which has no distribution to report.
///
/// `Action$TargetGroupArn` and `ForwardActionConfig$TargetGroups` are TWO SPELLINGS of one
/// forward's distribution — "Specify only when `Type` is `forward` and you want to route to
/// a single target group. To route to multiple target groups, you must use `ForwardConfig`
/// instead", and "[i]f you specify both `ForwardConfig` and `TargetGroupArn`, you can
/// specify only one target group using `ForwardConfig` and it must be the same target group
/// specified in `TargetGroupArn`" — so the configuration is read off whichever spelling the
/// request carried.
/// `pub(crate)` because the data plane DISTRIBUTES a request by exactly this reading: the
/// groups and weights a read reports are the ones a forward performs against
/// (`crate::service::target_group_selection`).
pub(crate) fn reported_forward_config(action: &Action) -> Option<ForwardActionConfig> {
    let mut config = action.forward_config.clone().unwrap_or_default();
    let mut groups = config.target_groups.take().unwrap_or_default();
    if groups.is_empty() {
        groups.push(TargetGroupTuple {
            target_group_arn: Some(action.target_group_arn.clone()?),
            weight: None,
        });
    }
    for group in &mut groups {
        if group.weight.is_none() {
            group.weight = Some(DEFAULT_TARGET_GROUP_WEIGHT);
        }
    }
    config.target_groups = Some(groups);
    let mut stickiness = config.target_group_stickiness_config.take().unwrap_or_default();
    if stickiness.enabled.is_none() {
        stickiness.enabled = Some(DEFAULT_TARGET_GROUP_STICKINESS);
    }
    config.target_group_stickiness_config = Some(stickiness);
    Some(config)
}

/// One action as a read reports it: a forward's distribution answered under BOTH spellings
/// the model gives it, with the weight and the stickiness the service carries it at
/// ([`reported_forward_config`]), a redirect's unmodified components answered as the
/// keywords that retain them ([`rule_actions`]), a fixed response's content
/// type answered as the one the service defaults when the action named none
/// ([`DEFAULT_FIXED_RESPONSE_CONTENT_TYPE`]), every other action exactly as it was given.
///
/// The ONE normalisation of an action, so a rule's actions, a listener's default actions
/// and the default rule carrying them all report the same configuration — the stored
/// action is what the caller gave, and this is what a read makes of it, exactly as
/// [`reported_condition`] does for a condition's two spellings.
fn reported_action(action: &Action) -> Action {
    let mut reported = action.clone();
    if reported.r#type == FORWARD_ACTION_TYPE {
        if let Some(config) = reported_forward_config(&reported) {
            // A forward to a SINGLE target group is reported under the single-group
            // spelling too, whichever one the request carried; a forward distributing
            // among several has no single-group spelling, so that member stays absent for
            // it.
            if reported.target_group_arn.is_none() {
                if let [only] = config.target_groups.as_deref().unwrap_or_default() {
                    reported.target_group_arn = only.target_group_arn.clone();
                }
            }
            reported.forward_config = Some(config);
        }
    }
    if let Some(config) = reported.fixed_response_config.as_mut() {
        if config.content_type.is_none() {
            config.content_type = Some(DEFAULT_FIXED_RESPONSE_CONTENT_TYPE.to_string());
        }
    }
    if let Some(config) = reported.redirect_config.as_mut() {
        let kept = |value: &mut Option<String>, keyword: &str| {
            if value.is_none() {
                *value = Some(keyword.to_string());
            }
        };
        kept(&mut config.protocol, rule_actions::KEEP_PROTOCOL);
        kept(&mut config.host, rule_actions::KEEP_HOST);
        kept(&mut config.port, rule_actions::KEEP_PORT);
        kept(&mut config.path, rule_actions::KEEP_PATH);
        kept(&mut config.query, rule_actions::KEEP_QUERY);
    }
    reported
}

/// Every action of a list as a read reports it ([`reported_action`]).
pub fn reported_actions(actions: &[Action]) -> Vec<Action> {
    actions.iter().map(reported_action).collect()
}

/// The kind of Elastic Load Balancing resource an ARN names.
///
/// Every taggable resource of this service has its own `NotFound` error, so an ARN that
/// names nothing is refused with the one belonging to the kind the ARN itself declares
/// — which is the resource segment of the ARN, not anything the store holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaggableResource {
    LoadBalancer,
    TargetGroup,
    Listener,
    Rule,
    TrustStore,
}

/// The kind of resource `arn` names, read from the resource TYPE of the ARN — the
/// segments AWS publishes for this service's ARNs (`loadbalancer/<type>/<name>/<id>`,
/// `targetgroup/<name>/<id>`, `listener/<type>/<name>/<lb-id>/<id>`,
/// `listener-rule/<type>/<name>/<lb-id>/<listener-id>/<id>`, `truststore/<name>/<id>`),
/// which are the forms the create handlers in `src/ops/` mint.
///
/// The ARN itself is read through `service_common::arn`, the workspace's ONE parse of a
/// caller-supplied resource ARN, narrowed to this service's own vendor: an ARN of
/// another vendor, or a value that is not a well-formed ARN, names nothing this API can
/// address, which is a malformed request rather than a missing resource — so this
/// answers `None` for it. The partition, Region and account are deliberately NOT
/// checked: an ARN of another Region is well formed and simply names no resource this
/// store holds.
pub fn taggable_resource(arn: &str) -> Option<TaggableResource> {
    match ::service_common::arn::parse_of(arn, SERVICE_NAMESPACE)?.resource_type() {
        "loadbalancer" => Some(TaggableResource::LoadBalancer),
        "targetgroup" => Some(TaggableResource::TargetGroup),
        "listener" => Some(TaggableResource::Listener),
        "listener-rule" => Some(TaggableResource::Rule),
        "truststore" => Some(TaggableResource::TrustStore),
        _ => None,
    }
}

/// The message a tag operation answers the `NotFound` of `kind` with when the ARN list it
/// was given names a resource this store does not hold.
///
/// Elastic Load Balancing words this refusal by the KIND of the ARN it could not resolve,
/// not by the operation that carried it, so each kind keeps its own template and the three
/// tag operations (`AddTags`/`RemoveTags`/`DescribeTags`, which all take `ResourceArns`)
/// answer the same words for the same kind. Two of the templates are pinned by what the
/// service answers:
///
/// * the load balancer kind names NO value — the collection-level wording
///   ([`load_balancer_selection_not_found_message`]), which is the recorded answer to a tag
///   write naming a load balancer that was deleted;
/// * the target group kind QUOTES the identifier that did not resolve, under its plural
///   noun ([`target_groups_not_found_message`]) — the recorded answer to a tag removal
///   naming a target group ARN with nothing behind it, and the same template every
///   operation addressing one target group through its own `TargetGroupArn` answers with.
///
/// The listener, rule and trust store kinds keep the collection-level wording their own
/// list reads answer ([`listener_selection_not_found_message`],
/// [`rule_selection_not_found_message`], [`trust_store_selection_not_found_message`]).
///
/// `arn` is the entry of `ResourceArns` that did not resolve — the same entry that picks
/// which `NotFound` the call is refused with — so a kind whose template carries an
/// identifier carries the caller's own value, taken from the request verbatim.
///
/// One function for every tag operation, so a read and a write of the tags of one absent
/// resource cannot be refused in different words. The operations that address exactly ONE
/// resource through their own required identifier name it the same way
/// ([`load_balancer_not_found_message`], [`listener_not_found_message`],
/// [`rule_not_found_message`], [`target_groups_not_found_message`]).
pub fn taggable_not_found_message(kind: TaggableResource, arn: &str) -> String {
    match kind {
        TaggableResource::LoadBalancer => load_balancer_selection_not_found_message(),
        TaggableResource::TargetGroup => target_groups_not_found_message([arn]),
        TaggableResource::Listener => listener_selection_not_found_message(),
        TaggableResource::Rule => rule_selection_not_found_message(),
        TaggableResource::TrustStore => trust_store_selection_not_found_message(),
    }
}

/// The message Elastic Load Balancing answers a `TrustStoreNotFound` with for a refusal
/// about a LIST of trust stores rather than one the call addresses: the collection-level
/// wording of the kind, built the same way as every other collection-level wording of
/// this service — "One or more" and the PLURAL noun, naming no value.
pub fn trust_store_selection_not_found_message() -> String {
    "One or more trust stores not found".to_string()
}

/// The ARN segment AWS uses for each load balancer type: `app` for an Application
/// Load Balancer, `net` for a Network Load Balancer, `gwy` for a Gateway Load
/// Balancer. Both load balancer and listener ARNs carry it.
pub fn load_balancer_type_code(lb_type: &str) -> &'static str {
    match lb_type {
        "network" => "net",
        "gateway" => "gwy",
        // `application` is the modelled default for `Type`.
        _ => "app",
    }
}

fn sorted(values: &[String]) -> Vec<String> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted
}

/// Per-service state for com-amazonaws-elasticloadbalancingv2-elasticloadbalancing-v10. A handler reaches it through [`service_state`].
#[derive(Debug, Default)]
pub struct ComAmazonawsElasticloadbalancingv2ElasticloadbalancingV10State {
    /// Load balancers by ARN.
    pub load_balancers: HashMap<String, LoadBalancerRecord>,
    /// Load balancer name to ARN, so a name is unique and `Names` lookups are direct.
    pub name_to_lb_arn: HashMap<String, String>,
    /// Target groups by ARN.
    pub target_groups: HashMap<String, TargetGroupRecord>,
    /// Target group name to ARN.
    pub name_to_tg_arn: HashMap<String, String>,
    /// Listeners by ARN.
    pub listeners: HashMap<String, ListenerRecord>,
    /// Trust stores by ARN.
    pub trust_stores: HashMap<String, TrustStoreRecord>,
    /// Trust store name to ARN: the model documents a trust store's name as unique
    /// per region, so `Names` lookups resolve through it directly.
    pub name_to_trust_store_arn: HashMap<String, String>,
    /// The counter the resource-id generator mixes, so an ARN is stable and unique
    /// within a run. A counter and a seed, not a store: nothing accumulates here.
    next_id: u64,
    id_seed: std::collections::hash_map::RandomState,
    /// The secret this store's page markers are authenticated under, drawn from the
    /// system's randomness when the store is created ([`PageTokenKey`]). A key, not a
    /// store: nothing accumulates here either, because a marker carries the position it
    /// names rather than pointing at a page kept on the side.
    page_token_key: PageTokenKey,
    /// The listeners and rules this store released WITH THEIR CONTAINER, which is what
    /// makes a delete of one of them idempotent ([`CascadedReleases`]). A bounded window,
    /// so it does not grow with the number of calls.
    pub cascaded_releases: CascadedReleases,
    /// Where the host-count series of each routed `(load balancer, target group)` pair has
    /// got to, and the one clock that advances them ([`host_counts`]). A series per pair
    /// being checked, so it does not grow with the number of calls either.
    pub host_counts: HostCountPublisher,
    /// The ADDRESS each load balancer answers on, by load balancer ARN: the socket of this
    /// emulator's own whose `host:port` the load balancer publishes as its `DNSName`
    /// ([`LoadBalancerEndpoint`]). One entry per load balancer that serves traffic of its
    /// own, so it is bounded by the load balancer quota the create enforces; dropping an
    /// entry closes the port and severs every connection in flight on it.
    pub load_balancer_endpoints: HashMap<String, LoadBalancerEndpoint>,
}

impl ComAmazonawsElasticloadbalancingv2ElasticloadbalancingV10State {
    /// The key this store's page markers are minted and recognised under. `Copy`, so a
    /// read takes it off the store and goes on to borrow the records it is about to
    /// report in the same call.
    pub fn page_token_key(&self) -> PageTokenKey {
        self.page_token_key
    }

    /// A fresh 16-hex resource id, carried by no resource this store holds. AWS
    /// resource ids are opaque, so this mixes a per-store seed with a counter rather
    /// than exposing the counter itself.
    ///
    /// Uniqueness is checked against the LIVE resources — which the quotas above
    /// bound — rather than against a ledger of every id ever minted, so nothing here
    /// grows with the number of calls.
    pub fn mint_id(&mut self) -> String {
        use std::hash::{BuildHasher, Hasher};
        // OnCallWorlds patch: an id the seed pinned for this setup call.
        if let Some(id) = ocw_clock::take_pinned("elbv2") {
            return id;
        }
        loop {
            self.next_id = self.next_id.wrapping_add(1);
            let mut hasher = self.id_seed.build_hasher();
            hasher.write_u64(self.next_id);
            let id = format!("{:016x}", hasher.finish());
            if !self.id_in_use(&id) {
                return id;
            }
        }
    }

    /// The id the DNS name of a load balancer of `family` carries beside its name, for a
    /// load balancer whose ARN carries `arn_id`.
    ///
    /// Which of the two it is belongs to the published host form
    /// ([`load_balancer_dns_name`], [`dns_id_is_minted`]): an Application Load Balancer's
    /// host carries a decimal number minted for the host alone, belonging to no other load
    /// balancer this store holds, while a Network or Gateway Load Balancer's carries the
    /// very hexadecimal id its ARN does.
    pub fn dns_id(&mut self, family: LoadBalancerFamily, arn_id: &str) -> String {
        if dns_id_is_minted(family) {
            return self.mint_dns_number();
        }
        arn_id.to_string()
    }

    /// A fresh decimal number for the published host of an Application Load Balancer,
    /// carried by no load balancer this store holds.
    ///
    /// Minted the way [`Self::mint_id`] mints an ARN id — a per-store seed mixed with the
    /// counter, never the counter itself — and reduced to the published width
    /// ([`APPLICATION_DNS_ID_DIGITS`]) with its leading digit kept non-zero, so every host
    /// carries a number of that width.
    fn mint_dns_number(&mut self) -> String {
        use std::hash::{BuildHasher, Hasher};
        let floor = 10u64.pow(APPLICATION_DNS_ID_DIGITS - 1);
        loop {
            self.next_id = self.next_id.wrapping_add(1);
            let mut hasher = self.id_seed.build_hasher();
            hasher.write_u64(self.next_id);
            let number = floor + hasher.finish() % (floor * 9);
            let candidate = number.to_string();
            if !self.dns_number_in_use(&candidate) {
                return candidate;
            }
        }
    }

    /// Whether the DNS name of a load balancer this store holds already carries `number`
    /// as the id beside its name.
    fn dns_number_in_use(&self, number: &str) -> bool {
        let label = format!("-{number}.");
        self.load_balancers
            .values()
            .any(|lb| lb.dns_name.contains(&label))
    }

    /// Whether any load balancer, target group, listener or rule in the store already
    /// carries `id`.
    fn id_in_use(&self, id: &str) -> bool {
        let suffix = format!("/{id}");
        self.load_balancers.values().any(|lb| lb.id == id)
            || self.target_groups.keys().any(|arn| arn.ends_with(&suffix))
            || self.listeners.keys().any(|arn| arn.ends_with(&suffix))
            || self.listeners.values().any(|listener| {
                listener.default_rule_id == id
                    || listener.rules.iter().any(|rule| rule.arn.ends_with(&suffix))
            })
            || self.trust_stores.keys().any(|arn| arn.ends_with(&suffix))
    }

    /// Materialize the state moves the clock already made due.
    ///
    /// A reporting operation calls this before it reads: a load balancer's move from
    /// `provisioning` to `active`, and a trust store's from `CREATING` to `ACTIVE`,
    /// were owed at [`SETTLE_AFTER`] past the create, even if nobody had called
    /// since.
    pub fn settle(&mut self, now: SystemTime) {
        for lb in self.load_balancers.values_mut() {
            if lb.state_code == "provisioning" && now >= lb.active_at {
                lb.state_code = "active".to_string();
            }
        }
        for store in self.trust_stores.values_mut() {
            if store.status == TRUST_STORE_CREATING && now >= store.active_at {
                store.status = TRUST_STORE_ACTIVE.to_string();
            }
        }
    }

    /// The tags stored on the resource `arn` names, or `None` when this store holds no
    /// resource with that ARN.
    ///
    /// Every taggable resource keeps its tags on its own record, so one lookup per store
    /// finds them whatever kind the ARN names. A listener rule's record lives on its
    /// listener, which [`Self::rule_record`] resolves through the ARN itself rather than
    /// through a scan.
    pub fn tags_of(&self, arn: &str) -> Option<&HashMap<String, String>> {
        self.load_balancers
            .get(arn)
            .map(|record| &record.tags)
            .or_else(|| self.target_groups.get(arn).map(|record| &record.tags))
            .or_else(|| self.listeners.get(arn).map(|record| &record.tags))
            .or_else(|| self.trust_stores.get(arn).map(|record| &record.tags))
            .or_else(|| self.rule_record(arn).map(|record| &record.tags))
    }

    /// The tags stored on the resource `arn` names, to WRITE, or `None` when this store
    /// holds no resource with that ARN — the mutable half of [`Self::tags_of`], which a
    /// tag write goes through.
    ///
    /// The kind the ARN itself declares picks the store to look in ([`taggable_resource`]),
    /// so one lookup resolves the record and an ARN of no kind this service knows
    /// resolves nothing to write to.
    pub fn tags_of_mut(&mut self, arn: &str) -> Option<&mut HashMap<String, String>> {
        match taggable_resource(arn)? {
            TaggableResource::LoadBalancer => {
                self.load_balancers.get_mut(arn).map(|rec| &mut rec.tags)
            }
            TaggableResource::TargetGroup => {
                self.target_groups.get_mut(arn).map(|rec| &mut rec.tags)
            }
            TaggableResource::Listener => self.listeners.get_mut(arn).map(|rec| &mut rec.tags),
            TaggableResource::TrustStore => {
                self.trust_stores.get_mut(arn).map(|rec| &mut rec.tags)
            }
            TaggableResource::Rule => self.rule_record_mut(arn).map(|rec| &mut rec.tags),
        }
    }

    /// Load balancers in a stable order (oldest first, ARN breaking ties), which is
    /// the order pagination walks.
    pub fn load_balancers_in_order(&self) -> Vec<&LoadBalancerRecord> {
        let mut records: Vec<&LoadBalancerRecord> = self.load_balancers.values().collect();
        records.sort_by(|a, b| {
            a.created_time
                .cmp(&b.created_time)
                .then_with(|| a.arn.cmp(&b.arn))
        });
        records
    }

    /// Target groups in a stable order (by ARN).
    pub fn target_groups_in_order(&self) -> Vec<&TargetGroupRecord> {
        let mut records: Vec<&TargetGroupRecord> = self.target_groups.values().collect();
        records.sort_by(|a, b| a.arn.cmp(&b.arn));
        records
    }

    /// Trust stores in a stable order (oldest first, ARN breaking ties), which is the
    /// order pagination walks.
    pub fn trust_stores_in_order(&self) -> Vec<&TrustStoreRecord> {
        let mut records: Vec<&TrustStoreRecord> = self.trust_stores.values().collect();
        records.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.arn.cmp(&b.arn))
        });
        records
    }

    /// Listeners in a stable order (by ARN).
    pub fn listeners_in_order(&self) -> Vec<&ListenerRecord> {
        let mut records: Vec<&ListenerRecord> = self.listeners.values().collect();
        records.sort_by(|a, b| a.arn.cmp(&b.arn));
        records
    }

    /// Every target group an action list forwards to whose traffic the load balancer
    /// `load_balancer_arn` does not serve, in the order the actions name them.
    ///
    /// A load balancer and the target groups its listeners forward to must carry the same
    /// KIND of traffic: `TargetGroup$Protocol` pairs each protocol with the load balancer
    /// it belongs to — "For Application Load Balancers, the supported protocols are HTTP
    /// and HTTPS. For Network Load Balancers, the supported protocols are TCP, TLS, UDP,
    /// TCP_UDP, QUIC, and TCP_QUIC. … For Gateway Load Balancers, the supported protocol is
    /// GENEVE" ([`protocol_family`]) — so forwarding to a target group of another kind is a
    /// pairing no load balancer can serve. The operation that made it answers the modelled
    /// `IncompatibleProtocolsException`, worded as [`incompatible_protocols_message`] does.
    ///
    /// Judged wherever an action is ATTACHED to a listener — the create and the
    /// modification of a listener's default actions, and of a rule's — so one reading of
    /// that pairing serves them all. A target group this store does not hold is passed
    /// over: that one is the modelled `TargetGroupNotFoundException` instead, and so is a
    /// load balancer it does not hold `LoadBalancerNotFoundException`.
    pub fn incompatible_target_groups(
        &self,
        load_balancer_arn: &str,
        actions: &[Action],
    ) -> Vec<String> {
        let Some(load_balancer) = self.load_balancers.get(load_balancer_arn) else {
            return Vec::new();
        };
        let family = load_balancer.family();
        let mut incompatible = Vec::new();
        for target_group_arn in action_target_group_arns(actions) {
            let Some(group) = self.target_groups.get(&target_group_arn) else {
                continue;
            };
            // A `lambda` target group carries no protocol, so there is no pairing to
            // judge: it is reached by an Application Load Balancer, which is what
            // [`protocol_family`] reads a group with no protocol as.
            if group.family() != family && !incompatible.contains(&target_group_arn) {
                incompatible.push(target_group_arn);
            }
        }
        incompatible
    }

    /// Record that `load_balancer_arn` forwards to `target_group_arn`.
    ///
    /// The association is what starts the HEALTH CHECKS on the group's targets, so a
    /// group that was forwarded to by nothing begins checking them here
    /// ([`TargetGroupRecord::begin_health_checking`]): before this, nothing was checking
    /// them and their reported state was `unused`.
    pub fn associate_target_group(
        &mut self,
        target_group_arn: &str,
        load_balancer_arn: &str,
        now: SystemTime,
    ) {
        if let Some(group) = self.target_groups.get_mut(target_group_arn) {
            if !group
                .load_balancer_arns
                .iter()
                .any(|arn| arn == load_balancer_arn)
            {
                let was_in_use = !group.load_balancer_arns.is_empty();
                group.load_balancer_arns.push(load_balancer_arn.to_string());
                if !was_in_use {
                    group.begin_health_checking(now);
                }
            }
        }
    }

    /// Remove a load balancer, its listeners and every association its listeners
    /// made, answering whether it was there.
    ///
    /// "Deleting a load balancer also deletes its listeners" — and a listener's rules go
    /// with the listener — so each RULE the cascade releases is recorded as released with
    /// its container: a delete of one of them afterwards asks for something this cascade
    /// already performed ([`cascaded_releases`]). The listeners themselves are not:
    /// `DeleteListener` models `ListenerNotFoundException` and answers it for a listener a
    /// cascade removed.
    pub fn remove_load_balancer(&mut self, arn: &str) -> bool {
        let Some(removed) = self.load_balancers.remove(arn) else {
            return false;
        };
        self.name_to_lb_arn.remove(&removed.name);
        // The ADDRESS it answered on goes with it: dropping the handle closes the port and
        // severs every connection in flight on it, so nothing is listening on the name a
        // deleted load balancer published ([`LoadBalancerEndpoint`]).
        self.load_balancer_endpoints.remove(arn);
        for listener_arn in &removed.listener_arns {
            if let Some(listener) = self.listeners.remove(listener_arn) {
                for rule in &listener.rules {
                    self.cascaded_releases.record(&rule.arn);
                }
                self.cascaded_releases.record(&listener.default_rule_arn());
            }
        }
        for group in self.target_groups.values_mut() {
            group.load_balancer_arns.retain(|lb| lb != arn);
        }
        true
    }

    /// Remove ONE listener — from the store, from its load balancer's listener list and
    /// from every target group no remaining listener of that load balancer forwards to —
    /// answering whether it was there.
    pub fn remove_listener(&mut self, arn: &str, now: SystemTime) -> bool {
        let Some(removed) = self.listeners.remove(arn) else {
            return false;
        };
        // The listener's rules go with the listener — the ones a caller added and the
        // default rule it minted with itself — so a delete of one of them afterwards asks
        // for something this removal already performed ([`cascaded_releases`]).
        for rule in &removed.rules {
            self.cascaded_releases.record(&rule.arn);
        }
        self.cascaded_releases.record(&removed.default_rule_arn());
        let load_balancer_arn = removed.load_balancer_arn.clone();
        if let Some(load_balancer) = self.load_balancers.get_mut(&load_balancer_arn) {
            load_balancer.listener_arns.retain(|listener| listener != arn);
        }
        self.refresh_target_group_associations(&load_balancer_arn, now);
        true
    }

    /// Make every target group's `LoadBalancerArns` agree with the listeners this store
    /// holds for `load_balancer_arn`: a target group some listener of it forwards to
    /// lists it, and one no listener forwards to does not.
    ///
    /// Called after a listener's actions change or a listener goes away, so the
    /// association a target group reports is derived from the listeners that exist
    /// rather than accumulated. The association is dropped only when nothing else keeps
    /// it: a second listener of the same load balancer still forwarding there does, and
    /// so does a RULE of one — a load balancer routes to a target group an action of any
    /// of its rules forwards to, not only one its default actions name.
    pub fn refresh_target_group_associations(
        &mut self,
        load_balancer_arn: &str,
        now: SystemTime,
    ) {
        let forwarded: Vec<String> = self
            .listeners
            .values()
            .filter(|listener| listener.load_balancer_arn == load_balancer_arn)
            .flat_map(ListenerRecord::forwarded_target_group_arns)
            .collect();
        for (arn, group) in &mut self.target_groups {
            let holds = group
                .load_balancer_arns
                .iter()
                .any(|lb| lb == load_balancer_arn);
            if forwarded.contains(arn) {
                if !holds {
                    let was_in_use = !group.load_balancer_arns.is_empty();
                    group.load_balancer_arns.push(load_balancer_arn.to_string());
                    if !was_in_use {
                        group.begin_health_checking(now);
                    }
                }
            } else if holds {
                group.load_balancer_arns.retain(|lb| lb != load_balancer_arn);
            }
        }
    }

    /// The load balancer family of the listener `arn` names, or `None` when the store
    /// holds no such listener. Which attributes a listener carries follows from it.
    pub fn listener_family(&self, arn: &str) -> Option<LoadBalancerFamily> {
        let listener = self.listeners.get(arn)?;
        let load_balancer = self.load_balancers.get(&listener.load_balancer_arn)?;
        Some(load_balancer_family(&load_balancer.lb_type))
    }

    /// Every rule of one listener, in the order a paginated read walks them.
    ///
    /// A listener's rules are the ones a caller added, in EVALUATION order — "rules are
    /// evaluated in priority order, from the lowest value to the highest value" — and
    /// then its DEFAULT rule, which is last because it is what runs when no other rule's
    /// conditions are met. Two rules of one listener never share a priority
    /// (`CreateRule` refuses that), so the order is total; the ARN breaks a tie only so
    /// that a page walk is stable whatever the store's iteration order.
    pub fn rules_of(&self, listener: &ListenerRecord) -> Vec<Rule> {
        let mut rules: Vec<Rule> = rules_in_evaluation_order(listener)
            .into_iter()
            .map(RuleRecord::to_shape)
            .collect();
        rules.push(listener.default_rule());
        rules
    }

    /// The record of the rule `arn` names, or `None` when the listener it belongs to
    /// holds no such rule. The listener's DEFAULT rule has no record: it is derived from
    /// the listener itself ([`ListenerRecord::default_rule`]).
    ///
    /// ONE listener lookup, never a scan over the store: a rule ARN is its listener's
    /// with the resource type `listener-rule` and the rule's own id appended
    /// ([`ListenerRecord::default_rule_arn`]), so the owning listener is a pure string
    /// transform of the value asked for.
    pub fn rule_record(&self, arn: &str) -> Option<&RuleRecord> {
        let listener = self.listeners.get(&rule_listener_arn(arn)?)?;
        listener.rules.iter().find(|rule| rule.arn == arn)
    }

    /// The record of the rule `arn` names, to WRITE: the mutable half of
    /// [`Self::rule_record`], resolved through the same one listener lookup.
    pub fn rule_record_mut(&mut self, arn: &str) -> Option<&mut RuleRecord> {
        let listener = self.listeners.get_mut(&rule_listener_arn(arn)?)?;
        listener.rules.iter_mut().find(|rule| rule.arn == arn)
    }

    /// The rule `arn` names, or `None` when no listener in this store holds it.
    ///
    /// Resolved through the same one listener lookup [`Self::rule_record`] uses, so the
    /// cost of resolving one rule does not grow with the number of listeners the store
    /// holds; the listener's own rule list is bounded by [`RULES_PER_LOAD_BALANCER`].
    pub fn rule_by_arn(&self, arn: &str) -> Option<Rule> {
        let listener = self.listeners.get(&rule_listener_arn(arn)?)?;
        self.rules_of(listener)
            .into_iter()
            .find(|rule| rule.rule_arn.as_deref() == Some(arn))
    }

    /// Remove ONE rule a caller added — from the listener that holds it, and with it
    /// every target group association no remaining action of its load balancer keeps
    /// alive — answering whether it was there.
    ///
    /// The owning listener is resolved from the rule ARN itself, as [`Self::rule_record`]
    /// resolves it, so nothing scans the store. A listener's DEFAULT rule is NOT removed
    /// here: it has no record of its own, being derived from the listener
    /// ([`ListenerRecord::default_rule`]), and the operation that would remove it refuses
    /// instead.
    pub fn remove_rule(&mut self, arn: &str, now: SystemTime) -> bool {
        let Some(listener_arn) = rule_listener_arn(arn) else {
            return false;
        };
        let Some(listener) = self.listeners.get_mut(&listener_arn) else {
            return false;
        };
        let held = listener.rules.len();
        listener.rules.retain(|rule| rule.arn != arn);
        if listener.rules.len() == held {
            return false;
        }
        // A load balancer routes to a target group an action of any of its rules forwards
        // to, so the rule going away can be what releases that association — and what
        // lets the target group be deleted.
        let load_balancer_arn = listener.load_balancer_arn.clone();
        self.refresh_target_group_associations(&load_balancer_arn, now);
        true
    }

    /// How many rules a caller has added across every listener of `load_balancer_arn`,
    /// which is what [`RULES_PER_LOAD_BALANCER`] bounds.
    pub fn rule_count_of_load_balancer(&self, load_balancer_arn: &str) -> usize {
        self.listeners
            .values()
            .filter(|listener| listener.load_balancer_arn == load_balancer_arn)
            .map(|listener| listener.rules.len())
            .sum()
    }
}

/// The ARN of the listener the rule `arn` belongs to, or `None` when `arn` carries no
/// rule id at all. A pure string transform of the rule ARN: the two differ in their
/// resource type and in the rule id the rule ARN appends.
///
/// Public because a rule's PRIORITY lives in its listener's own namespace, so an
/// operation that re-prioritises rules has to group what it was asked for by listener
/// ([`crate::ops::set_rule_priorities`]).
pub fn rule_listener_arn(arn: &str) -> Option<String> {
    let (listener_part, _rule_id) = arn.rsplit_once('/')?;
    Some(listener_part.replacen(":listener-rule/", ":listener/", 1))
}

/// The RULES a caller added to one listener, in the order they are evaluated in: "rules
/// are evaluated in priority order, from the lowest value to the highest value". Two rules
/// of one listener never share a priority (`CreateRule` refuses that), so the order is
/// total; the ARN breaks a tie only so a walk is stable whatever the store's iteration
/// order.
///
/// The ONE definition of that order, for both the read that REPORTS the rules
/// ([`ComAmazonawsElasticloadbalancingv2ElasticloadbalancingV10State::rules_of`], which
/// appends the listener's default rule after them) and the data plane that EVALUATES them
/// (`crate::service::data_plane`), so the documented evaluation order cannot differ between
/// what a caller reads and what answers its traffic.
pub fn rules_in_evaluation_order(listener: &ListenerRecord) -> Vec<&RuleRecord> {
    let mut added: Vec<&RuleRecord> = listener.rules.iter().collect();
    added.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.arn.cmp(&right.arn))
    });
    added
}

/// This service's store in the shared engine: call it with a handler's `&*self.engine`.
///
/// Answer `None` with a modelled server error, never with a fresh engine.
pub fn service_state<Eng: Send + Sync + 'static>(
    engine: &Eng,
) -> Option<::engine::ServiceState<ComAmazonawsElasticloadbalancingv2ElasticloadbalancingV10State>> {
    (engine as &dyn ::std::any::Any)
        .downcast_ref::<::engine::InMemoryEngine>()
        .map(::engine::InMemoryEngine::state::<ComAmazonawsElasticloadbalancingv2ElasticloadbalancingV10State>)
}

/// The account's MANAGEMENT-EVENT (audit) log in the SAME shared engine — the one store
/// CloudTrail's `LookupEvents` reads: call it with `&*engine`.
///
/// A SHARED type ([`::service_common::management_events::ManagementEventLog`]) and not a
/// field of this service's own state, because the service that SERVES a call is the one
/// that knows the call happened while the service that REPORTS it is CloudTrail; the engine
/// keys state by TYPE, so a copy of its own here would be invisible to the reader.
///
/// Answer `None` by leaving the call unrecorded: the record is the account's audit trail,
/// never part of this operation's own answer, so an engine carrying no log still serves the
/// call.
pub fn management_event_log<Eng: Send + Sync + 'static>(
    engine: &Eng,
) -> Option<::engine::ServiceState<::service_common::management_events::ManagementEventLog>> {
    (engine as &dyn ::std::any::Any)
        .downcast_ref::<::engine::InMemoryEngine>()
        .map(
            ::engine::InMemoryEngine::state::<
                ::service_common::management_events::ManagementEventLog,
            >,
        )
}

/// The account's SESSION directory in that same shared engine: the sessions STS minted,
/// each keyed by the access key id it was minted under, which is what lets a record of a
/// call made with one name the session it was made by.
///
/// A SHARED type, for the same reason as the log above: the service that MINTS a session
/// and the services that record the calls made WITH it are not the same service.
pub fn session_audit_directory<Eng: Send + Sync + 'static>(
    engine: &Eng,
) -> Option<::engine::ServiceState<::service_common::management_events::SessionAuditDirectory>> {
    (engine as &dyn ::std::any::Any)
        .downcast_ref::<::engine::InMemoryEngine>()
        .map(
            ::engine::InMemoryEngine::state::<
                ::service_common::management_events::SessionAuditDirectory,
            >,
        )
}
