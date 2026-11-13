// SPDX-License-Identifier: CC0-1.0

//! Instance-id and tag-key validation, and the instance-type catalog every type's facts are
//! derived from its name through.
//!
//! Split out of the [`crate::state`] module root so each file holds one concern, and
//! re-exported from it, so a handler reaches these as `crate::state::<item>` like every
//! other primitive there.

use super::*;

impl ComAmazonawsEc2Amazonec2State {
    /// The tags of the resource `resource_id` names, whatever kind of resource that is, or
    /// `None` when this store holds no resource under that id.
    ///
    /// `CreateTags` and `DeleteTags` act on a resource id without being told its kind, so
    /// this is where an id is resolved against every store that holds a taggable resource.
    /// Both reach a resource's tags ONLY through here, so neither can accept an id the
    /// other refuses, and a store added to the list below becomes taggable for both at
    /// once.
    pub fn resource_tags_mut(&mut self, resource_id: &str) -> Option<ResourceTagsMut<'_>> {
        let store = self;
        // The instance record keeps its tags as a map rather than as the modelled list,
        // so it is resolved on its own.
        if let Some(instance) = store.instances.get_mut(resource_id) {
            return Some(ResourceTagsMut::Map(&mut instance.tags));
        }
        // A network interface's modelled tag member is `TagSet` (`NetworkInterface$TagSet`)
        // rather than `Tags`, so it is resolved on its own too — the tags are the same
        // modelled list either way.
        if let Some(interface) = store.network_interfaces.get_mut(resource_id) {
            return Some(ResourceTagsMut::List(&mut interface.tag_set));
        }
        resource_tag_lists!(
            store,
            resource_id,
            addresses,
            capacity_reservation_fleets => view,
            capacity_reservation_cancellation_quotes => view,
            capacity_reservations => view,
            carrier_gateways,
            client_vpn_endpoints,
            coip_pools,
            customer_gateways => view,
            dedicated_hosts,
            dhcp_options,
            export_image_tasks => view,
            export_tasks => view,
            fleets => fleet,
            fpga_images => view,
            images,
            import_image_tasks => view,
            import_snapshot_tasks,
            internet_gateways,
            ipam_policies => view,
            ipam_pools,
            ipam_resource_discoveries,
            ipam_resource_discovery_associations,
            ipam_scopes,
            ipams,
            launch_templates => template,
            local_gateway_route_table_virtual_interface_group_associations => view,
            local_gateway_route_table_vpc_associations => view,
            local_gateway_route_tables => view,
            mac_modification_tasks => view,
            managed_prefix_lists => view,
            nat_gateways,
            network_insights_access_scope_analyses => view,
            network_insights_access_scopes,
            network_insights_analyses => view,
            network_insights_paths,
            placement_groups,
            replace_root_volume_tasks => view,
            reserved_instances,
            route_server_endpoints,
            route_server_peers,
            route_servers => view,
            route_tables,
            secondary_interfaces,
            secondary_networks => view,
            secondary_subnets,
            security_groups,
            snapshots => view,
            spot_instance_requests => view,
            spot_fleet_requests => view,
            subnet_cidr_reservations,
            subnets,
            traffic_mirror_filters,
            traffic_mirror_sessions,
            transit_gateway_connect_peers => view,
            transit_gateway_metering_policies,
            transit_gateway_policy_tables => view,
            transit_gateway_route_tables,
            transit_gateways,
            verified_access_endpoints => view,
            verified_access_groups => view,
            volumes => view,
            vpc_block_public_access_exclusions => view,
            vpc_endpoint_services,
            vpc_endpoints,
            vpc_peering_connections => view,
            vpcs,
            vpn_connections => view,
            vpn_gateways => view,
        );
        None
    }
}

/// The refusal a tagging call answers for a resource id that names no resource this account
/// holds.
///
/// `CreateTags` and `DeleteTags` act on an id without being told its kind, and the kind is
/// what decides the refusal: a WELL-FORMED id of a kind EC2 publishes names a resource that
/// does not exist, which is that kind's own `Invalid<Kind>.NotFound` — the same refusal every
/// operation of that resource answers for the id, so a client that deleted a subnet and then
/// tagged it reads `InvalidSubnetID.NotFound` whichever call it made. A value that is not an
/// id of any such kind is no id at all, which is `InvalidID` ("The specified ID for the
/// resource you are trying to tag is not valid"): the refusal these calls answer for a
/// malformed value, and the one this falls back to.
///
/// The kinds are the ones this store holds a taggable resource of
/// ([`ComAmazonawsEc2Amazonec2State::resource_tags_mut`]) whose own not-found refusal this
/// crate words, keyed by the printed prefix of their ids.
pub fn untaggable_resource_id<E>(resource_id: &str) -> crate::scaffolded::Scaffolded<E> {
    // An instance id is read through its own form check, which refuses the placeholder and
    // the long forms EC2 never mints ([`instance_id_is_well_formed`]).
    if instance_id_is_well_formed(resource_id) {
        return crate::scaffolded::Scaffolded::invalid_instance_id_not_found(resource_id);
    }
    /// The not-found refusal of one taggable kind, as the catalogue below holds it.
    type NotFound<E> = fn(&str) -> crate::scaffolded::Scaffolded<E>;
    let kinds: [(&str, NotFound<E>); 12] = [
        ("vpc", invalid_vpc_id_not_found),
        ("subnet", invalid_subnet_id_not_found),
        ("sg", invalid_group_not_found),
        ("eni", invalid_network_interface_id_not_found),
        ("vol", invalid_volume_id_not_found),
        ("snap", invalid_snapshot_id_not_found),
        ("igw", invalid_internet_gateway_id_not_found),
        ("rtb", invalid_route_table_id_not_found),
        ("acl", invalid_network_acl_id_not_found),
        ("dopt", invalid_dhcp_option_id_not_found),
        // The launch-template wording that NAMES the id the request sent: a tagging call
        // names one resource per id, so the refusal states which template is absent rather
        // than that at least one of several is ([`invalid_launch_template_id_not_found`]
        // carries that other sentence, which names none of them).
        ("lt", specified_launch_template_id_not_found),
        ("ami", invalid_ami_id_not_found),
    ];
    for (prefix, not_found) in kinds {
        if prefixed_id_is_well_formed(prefix, resource_id) {
            return not_found(resource_id);
        }
    }
    crate::scaffolded::Scaffolded::invalid_id(resource_id)
}

/// Refuse a tag key longer than EC2 documents ([`MAX_TAG_KEY_CHARS`]).
///
/// Split out of [`validate_tag_size`] so a caller that carries a KEY and no value — the
/// scheduled event notification tag key registration names keys alone — checks exactly the
/// key rule rather than passing a value it does not have.
pub fn validate_tag_key<E>(key: &str) -> Result<(), crate::scaffolded::Scaffolded<E>> {
    if key.chars().count() > MAX_TAG_KEY_CHARS {
        return Err(crate::scaffolded::Scaffolded::invalid_parameter_value(format!(
            "A tag key accepts at most {MAX_TAG_KEY_CHARS} characters"
        )));
    }
    Ok(())
}

/// Refuse a tag whose key or value is longer than EC2 documents.
pub fn validate_tag_size<E>(
    key: &str,
    value: &str,
) -> Result<(), crate::scaffolded::Scaffolded<E>> {
    validate_tag_key(key)?;
    if value.chars().count() > MAX_TAG_VALUE_CHARS {
        return Err(crate::scaffolded::Scaffolded::invalid_parameter_value(format!(
            "The value of tag key '{key}' accepts at most {MAX_TAG_VALUE_CHARS} characters"
        )));
    }
    Ok(())
}

/// How many hexadecimal digits the LONG EC2 resource id form carries, the form every
/// id this service mints uses (`i-00000000000000001`): "the form
/// `i-xxxxxxxxxxxxxxxxx`" of AWS's `InvalidInstanceID.Malformed` error-code entry,
/// seventeen digits.
pub const LONG_RESOURCE_ID_DIGITS: usize = 17;

/// How many hexadecimal digits the SHORT EC2 resource id form carries — the form EC2
/// issued resource ids in before the long one and still READS, as the model's own id
/// patterns spell it (`^vpc-([0-9a-f]{8}|[0-9a-f]{17})$`, quoted on
/// [`prefixed_id_is_well_formed`]): eight digits.
pub const SHORT_RESOURCE_ID_DIGITS: usize = 8;

/// Whether `id` is a well-formed EC2 instance id — one EC2 could have ISSUED.
///
/// An instance id is `i-` followed by EITHER of the two forms EC2 has issued resource ids
/// in ([`issued_id_is_well_formed`]): [`SHORT_RESOURCE_ID_DIGITS`] lowercase hexadecimal
/// digits, or [`LONG_RESOURCE_ID_DIGITS`] of them under a leading `0`; and it is not the
/// all-zero placeholder. EC2 answers `InvalidInstanceID.Malformed` for anything else,
/// BEFORE it looks the id up, which is a different answer from
/// `InvalidInstanceID.NotFound` for a well-formed id nothing was launched for: a client
/// that cannot tell a typo from a missing instance goes on polling for an instance that
/// can never appear.
///
/// Two things put an id outside the form EC2 issues, so that it is malformed rather
/// than missing:
///
/// * A LEADING DIGIT ABOVE ZERO IN THE LONG FORM. That form carries 17 hexadecimal digits
///   — 68 bits — for a 64-bit internal identifier, so its leading digit is always `0`:
///   every long-form instance id EC2 issues reads `i-0…`, which is also what this
///   service's own mint produces ([`ComAmazonawsEc2Amazonec2State::mint_instance_id`]) and
///   what every instance id seeded elsewhere in this emulator looks like. AWS answers an
///   id whose leading digit is above zero — the `i-1234567890abcdef0` shape that
///   documentation examples and hand-written probes use — with
///   `InvalidInstanceID.Malformed`. The SHORT form carries no such spare bit, so nothing
///   constrains its leading digit.
/// * The ALL-ZERO id, the value every client reaches for as a placeholder: AWS answers
///   `i-00000000000000000` with `InvalidInstanceID.Malformed` too, and the mint counts
///   from one, so no instance can ever hold the null id.
///
/// The SHORT form is a form EC2 READS even though it no longer ISSUES it: EC2 stopped
/// handing out short resource ids when the long form was introduced, which is why nothing
/// this service mints is in it, but the id parser still accepts it — so a short-form id is
/// LOOKED UP, and an account holding no instance for it is told `NotFound` rather than that
/// its id is unreadable. That is the generic EC2 id form the rest of this crate's readers
/// take ([`prefixed_id_is_well_formed`], whose doc quotes the model's own
/// `^vpc-([0-9a-f]{8}|[0-9a-f]{17})$`), and the describes of this account's images were
/// recorded answering a short-form `ami-` id `NotFound` the same way.
///
/// The clauses above are the rule of SOME EC2 id kinds, not of every one
/// ([`issued_long_id_is_well_formed`], which a Capacity Reservation Fleet id reads through
/// on its own recorded evidence): the same all-zero suffix on a network interface
/// (`eni-00000000000000000`) IS answered `NotFound`, so they are not generalised to the
/// other id readers here.
///
/// ## Where each clause's evidence is, so the rule can be re-checked
///
/// * The TWO forms: the recorded unit
///   `cloudtrail__ec2.obs-ec2-3-rejected-ec2-calls-audit-client-error-codes-with-no-response-elements`
///   refuses `DescribeInstances` for a short-form id that names no instance and asserts
///   `InvalidInstanceID.NotFound`, so the short form is inside the form EC2 reads; the
///   long form is AWS's `InvalidInstanceID.Malformed` error-code entry ("Ensure that you
///   provide the full instance ID in the request, in the form `i-xxxxxxxxxxxxxxxxx`").
///   `tests/all/instance_id_forms.rs` pins both over a table of forms.
/// * The LEADING DIGIT: the recorded unit `ec2.op-contract-get-password-data` (run#12,
///   `assert code == "InvalidInstanceID.Malformed"`) probes a 17-hexadecimal-digit id
///   that is neither the short form nor the null id — an id whose leading digit is
///   above zero, the `i-1234567890abcdef0` shape — and AWS answered it
///   `InvalidInstanceID.Malformed`. The `tests/all/get_password_data.rs` rows "a leading
///   digit above zero" and "every digit above zero" pin it.
/// * The NULL id: the recorded units behind
///   `issues/.../20261022T235108Z-ec2-misclassifies-rejections-and-skips-validation-malformed-ids.md`
///   (cause 5, `i-00000000000000000` -> `InvalidInstanceID.Malformed`) and
///   `issues/.../20261022T235108Z-ec2-sql-ha-application-status-check-fast-launch.md`
///   (cause 1, the same id under `DryRun`), whose cause 7 is also where the
///   `eni-00000000000000000` -> `NotFound` counter-example comes from.
pub fn instance_id_is_well_formed(id: &str) -> bool {
    issued_id_is_well_formed(INSTANCE_ID_PREFIX, id)
}

/// Whether `id` READS as an instance id: `i-` followed by 8 or 17 lowercase hexadecimal
/// digits, the two forms EC2 publishes, with NO clause on the digits themselves.
///
/// Weaker than [`instance_id_is_well_formed`], which also refuses the all-zero placeholder
/// and a long form whose leading digit is above zero. The gap between the two is a value EC2
/// can READ as an instance id but never minted one of, and WHICH of the two readings an
/// operation takes is a fact of that operation rather than of the id kind: the SQL Server
/// High Availability describes are recorded LOOKING UP an id in that gap and answering
/// `InvalidInstanceID.NotFound` for it, while `Enable`/`DisableInstanceSqlHaStandbyDetections`
/// and `CreateMacSystemIntegrityProtectionModificationTask` are recorded answering
/// `InvalidInstanceID.Malformed` for the very same value. So an operation reads ids through
/// the one it was recorded answering, and neither reading is generalised to the other's
/// operations.
pub fn instance_id_reads_as_one(id: &str) -> bool {
    prefixed_id_is_well_formed(INSTANCE_ID_PREFIX, id)
}

/// The identifier a LONG-form EC2 resource id carries, or `None` for a value in any other
/// form.
///
/// A long-form id is `<prefix>-` and [`LONG_RESOURCE_ID_DIGITS`] lowercase hexadecimal
/// digits, which EC2 hands out as an OBFUSCATED identifier: the service decodes it back to
/// the resource it names before it looks anything up, which is why a value it cannot decode
/// is answered `Invalid<Kind>.Malformed` and not as a resource that does not exist. The
/// digits are what this service's own mints count in
/// ([`ComAmazonawsEc2Amazonec2State::next_id`],
/// [`ComAmazonawsEc2Amazonec2State::mint_instance_id`]), so reading them back is how this
/// emulator decodes one.
///
/// The all-zero identifier is `None`: no mint counts from zero, so it is no identifier at
/// all and the id-form readers already refuse it.
pub fn long_form_identifier(id: &str) -> Option<u128> {
    let (_prefix, suffix) = id.rsplit_once('-')?;
    if suffix.len() != LONG_RESOURCE_ID_DIGITS {
        return None;
    }
    if !suffix
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    u128::from_str_radix(suffix, 16).ok().filter(|id| *id != 0)
}

impl ComAmazonawsEc2Amazonec2State {
    /// Whether `instance_id` is a LONG-form id whose identifier this service has already
    /// issued to a resource of a DIFFERENT kind — a value that is no instance id at all.
    ///
    /// EC2's long id form is an OBFUSCATED identifier, decoded by the service before it
    /// looks anything up: the digits are not free text a caller may compose, they name a
    /// resource ("Unable to unobfuscate ID." is the sentence EC2 words for one it cannot
    /// decode, [`crate::scaffolded::Scaffolded::instance_id_could_not_be_unobfuscated`]).
    /// So a value in another resource's PRINTED prefix is not an id of the kind a member
    /// declares (`i-…` sent as an `ImageId` is `InvalidAMIID.Malformed`), and neither is one
    /// whose IDENTIFIER names another resource — the same answer for the same reason, one
    /// step further in.
    ///
    /// The identifiers this service has issued are the ones its mints have counted:
    /// [`Self::mint_instance_id`] counts INSTANCES, so an identifier at or below it is an
    /// instance's own, whatever became of the instance; [`Self::next_id`] counts every other
    /// kind, so an identifier at or below THAT one and above the instance mint was spent on
    /// another resource. An identifier neither mint has reached is one this service has
    /// issued to nothing at all, which is left to the lookup — the same conservative
    /// direction [`Self::id_was_issued`] takes: a value the service may yet issue is
    /// reported as a resource that does not exist rather than as an id it cannot read.
    ///
    /// The retired SHORT form carries no identifier to decode (EC2 reads it without
    /// unobfuscation, [`instance_id_is_well_formed`]), so it is never refused here: a
    /// short-form id the account holds no instance for is simply absent.
    pub fn instance_id_identifies_another_resource(&self, instance_id: &str) -> bool {
        long_form_identifier(instance_id).is_some_and(|identifier| {
            identifier > u128::from(self.next_instance) && identifier <= u128::from(self.id_counter)
        })
    }
}

/// Whether `value` is readable as an instance id where a FILTER selects on one.
///
/// A filter that selects on an instance id has its values read through the service's own id
/// parser before anything is narrowed, which is the same decode
/// [`require_decoded_instance_record`] makes for an `InstanceIds` member: the value is inside
/// one of the two published forms ([`instance_id_is_well_formed`]), and a LONG-form value is an
/// identifier this service has issued rather than one merely spelled in that form — EC2's long
/// id form is an OBFUSCATED identifier, so a value it cannot decode is no instance id at all.
/// A caller that mistypes such a value is refused ([`invalid_filter_id_value`]) rather than
/// handed an empty result set, which it could not tell from an association that is not there.
///
/// WHICH filter values an operation parses as ids is a fact of that operation, recorded by its
/// caller — the same split [`instance_id_reads_as_one`] states for the `InstanceIds` readers —
/// so this is the reading of the operations recorded answering that refusal, not of every
/// describe that documents an `instance-id` filter.
pub fn instance_id_filter_value_is_readable(
    store: &ComAmazonawsEc2Amazonec2State,
    value: &str,
) -> bool {
    instance_id_is_well_formed(value)
        && !long_form_identifier(value)
            .is_some_and(|identifier| identifier > u128::from(store.next_instance))
}

/// Refuse an instance id the request named that this service cannot resolve: a
/// malformed one before an unknown one, the way the service orders the two.
pub fn require_known_instance<E>(
    store: &ComAmazonawsEc2Amazonec2State,
    instance_id: &str,
) -> Result<(), crate::scaffolded::Scaffolded<E>> {
    require_instance_record(store, instance_id).map(|_| ())
}

/// The stored instance `instance_id` names for an operation that DECODES a long-form id
/// before it looks anything up: a long-form id this service never issued is
/// `InvalidInstanceID.Malformed`, where a short-form one it holds no instance for is
/// `InvalidInstanceID.NotFound`.
///
/// EC2's long id form is an OBFUSCATED identifier, so an id the service cannot decode is
/// answered "Unable to unobfuscate ID." rather than as a resource that is not there — the
/// reading [`ComAmazonawsEc2Amazonec2State::id_was_issued`] states for the kinds recorded
/// taking it. The ids this service has issued as an instance's own are the ones
/// [`ComAmazonawsEc2Amazonec2State::mint_instance_id`] has counted, so a long-form
/// identifier above that counter is a value no instance of this account was ever given and
/// the describe cannot decode it. The retired SHORT form carries no identifier to decode
/// ([`instance_id_is_well_formed`]), so it is looked up and reported absent, which is what
/// `DescribeInstances` was recorded answering for one.
///
/// WHICH of the two readings an operation takes is a fact of that operation rather than of
/// the id kind ([`instance_id_reads_as_one`]), so this is not generalised to the operations
/// recorded answering `NotFound` for a long-form id.
///
/// ## Where each reading's evidence is, so they can be re-checked
///
/// * THIS reading: the recorded unit
///   `ec2.ec2mr-xrg-absent-instance-id-rejected-but-filter-returns-empty` names an absent
///   long-form instance id on `DescribeInstances` and asserts
///   `InvalidInstanceID.Malformed`, while
///   `cloudtrail__ec2.obs-ec2-3-rejected-ec2-calls-audit-client-error-codes-with-no-response-elements`
///   names a SHORT-form id on the same operation and asserts `InvalidInstanceID.NotFound` —
///   the two halves this function separates.
/// * The LOOKUP reading, which the other instance-id readers keep: the SQL Server High
///   Availability describes are recorded answering `InvalidInstanceID.NotFound` for a
///   long-form id in that same gap (cited on [`instance_id_reads_as_one`]), so answering
///   malformed there would contradict a recording.
pub fn require_decoded_instance_record<'store, E>(
    store: &'store ComAmazonawsEc2Amazonec2State,
    instance_id: &str,
) -> Result<&'store InstanceRecord, crate::scaffolded::Scaffolded<E>> {
    if long_form_identifier(instance_id)
        .is_some_and(|identifier| identifier > u128::from(store.next_instance))
    {
        return Err(crate::scaffolded::Scaffolded::invalid_instance_id_malformed(
            instance_id,
        ));
    }
    require_instance_record(store, instance_id)
}

/// The stored instance `instance_id` names, refusing an id this service cannot resolve
/// exactly as [`require_known_instance`] does — the ONE reading of those two refusals,
/// for a caller that needs the record it resolved and not only the fact that it
/// resolves, so no handler has to look the same id up twice.
pub fn require_instance_record<'store, E>(
    store: &'store ComAmazonawsEc2Amazonec2State,
    instance_id: &str,
) -> Result<&'store InstanceRecord, crate::scaffolded::Scaffolded<E>> {
    require_instance_record_worded(
        store,
        instance_id,
        crate::scaffolded::Scaffolded::invalid_instance_id_malformed,
    )
}

/// [`require_instance_record`] with the MALFORMED half worded by `malformed`.
///
/// EC2's per-operation validators do not agree about how they WORD an instance id they
/// cannot read — the two sentences are [`crate::scaffolded::Scaffolded`]'s
/// `invalid_instance_id_malformed` and `instance_id_is_malformed`, and which one an
/// operation answers is a fact of that operation, recorded by its caller. The RULE those
/// refusals follow is one, so it lives here once and the sentence is passed in: an id
/// outside the form EC2 issues, and a long-form id whose identifier this service spent on
/// another kind of resource, are malformed before any lookup; anything else that resolves to
/// no instance is the not-found half.
pub fn require_instance_record_worded<'store, E>(
    store: &'store ComAmazonawsEc2Amazonec2State,
    instance_id: &str,
    malformed: impl Fn(&str) -> crate::scaffolded::Scaffolded<E>,
) -> Result<&'store InstanceRecord, crate::scaffolded::Scaffolded<E>> {
    if !instance_id_is_well_formed(instance_id) {
        return Err(malformed(instance_id));
    }
    store.instances.get(instance_id).ok_or_else(|| {
        // The long form is an identifier the service DECODES before it looks anything up, so
        // one it spent on another kind of resource is no instance id and is refused as
        // malformed; one it has issued to nothing, or issued as an instance's own, names an
        // instance that is not there, which is the not-found half.
        if store.instance_id_identifies_another_resource(instance_id) {
            malformed(instance_id)
        } else {
            crate::scaffolded::Scaffolded::invalid_instance_id_not_found(instance_id)
        }
    })
}

/// The id prefix of an EC2 instance, as [`instance_id_is_well_formed`] reads one and as a
/// refusal that names the form it expected spells it (`Expected: 'i-...'.`).
pub const INSTANCE_ID_PREFIX: &str = "i";

/// The name EC2 gives an `InstanceIds` list when it refuses one of its entries at the
/// PARAMETER layer — "Value (…) for parameter instanceId is invalid. Expected: 'i-...'." —
/// the way [`VOLUME_IDS_PARAMETER`] names a volume-id list there.
///
/// The member's wire name is `InstanceId.N` (`InstanceIdStringList`'s `xmlName`), and
/// `instanceId` is what that layer calls the parameter those values make up.
pub const INSTANCE_IDS_PARAMETER: &str = "instanceId";

/// The stored instance `instance_id` names, for an operation that validates its
/// `InstanceIds` list as a request PARAMETER rather than resolving one named instance.
///
/// The same two refusals in the same order as [`require_instance_record`], differing only
/// in the CLASS of the first: a value outside the instance-id form is
/// [`invalid_id_parameter_value`] — `InvalidParameterValue`, naming the parameter and the
/// form it expected — where [`require_instance_record`] answers the resource-level
/// `InvalidInstanceID.Malformed`. WHICH layer an operation validates an id in is a fact of
/// that operation, recorded by its caller (the split
/// [`crate::scaffolded::Scaffolded::instance_id_is_malformed`] records for the other
/// wordings of that code), so an operation reads ids through the one it was recorded
/// answering. A well-formed id this account holds no instance for is
/// `InvalidInstanceID.NotFound` either way: the parameter layer refuses the FORM, and only
/// a value inside it is looked up.
pub fn require_instance_record_by_parameter<'store, E>(
    store: &'store ComAmazonawsEc2Amazonec2State,
    instance_id: &str,
) -> Result<&'store InstanceRecord, crate::scaffolded::Scaffolded<E>> {
    if !instance_id_is_well_formed(instance_id) {
        // The value comes from the request, so the echo is bounded the way every other
        // echoed resource id here is bounded.
        return Err(invalid_id_parameter_value(
            INSTANCE_IDS_PARAMETER,
            &echoed_resource_id(instance_id),
            INSTANCE_ID_PREFIX,
        ));
    }
    store.instances.get(instance_id).ok_or_else(|| {
        crate::scaffolded::Scaffolded::invalid_instance_id_not_found(instance_id)
    })
}

/// `ids` in request order with repeats dropped.
///
/// One instance gets one answer however many times a batch names it; processing a
/// repeat twice would report a state change from a state the caller never saw.
pub fn deduplicate_ids(ids: &[String]) -> Vec<String> {
    let mut seen = ::std::collections::HashSet::new();
    ids.iter()
        .filter(|id| seen.insert((*id).clone()))
        .cloned()
        .collect()
}

/// The modelled `Tag` list for a stored tag map, ordered by key.
pub fn tag_list(tags: &BTreeMap<String, String>) -> Vec<Tag> {
    tags.iter()
        .map(|(key, value)| Tag {
            key: Some(key.clone()),
            value: Some(value.clone()),
        })
        .collect()
}

/// The bytes a modelled `DhcpConfiguration` list holds: every option name and every value
/// of it, which in a caller-created set are all caller-chosen strings.
pub fn dhcp_configuration_list_bytes(configurations: &[DhcpConfiguration]) -> usize {
    configurations
        .iter()
        .map(|configuration| {
            configuration.key.as_ref().map_or(0, String::len)
                + configuration
                    .values
                    .iter()
                    .flatten()
                    .map(|value| value.value.as_ref().map_or(0, String::len))
                    .sum::<usize>()
        })
        .sum()
}

/// The bytes a Region's default DHCP option set record holds, for the store's byte budget.
///
/// Every string of the record is either a word this crate chose or the Region's private DNS
/// domain ([`private_dns_domain`]), which is the one caller-influenced part — the Region of
/// the request's credential scope, which [`request_region`] holds to 64 characters.
pub fn default_dhcp_options_payload_bytes(region: &str) -> usize {
    DHCP_OPTION_DOMAIN_NAME.len()
        + DHCP_OPTION_DOMAIN_NAME_SERVERS.len()
        + AMAZON_PROVIDED_DNS.len()
        + private_dns_domain(region).len()
}

/// The private DNS domain of a Region: the suffix of every Amazon-provided private
/// hostname in it, and the `domain-name` of the Region's default DHCP option set.
///
/// AWS uses `ec2.internal` in `us-east-1` and `<region>.compute.internal` in every other
/// Region (Amazon VPC User Guide, "DHCP option sets").
pub fn private_dns_domain(region: &str) -> String {
    if region == EC2_INTERNAL_REGION {
        "ec2.internal".to_string()
    } else {
        format!("{region}.compute.internal")
    }
}

/// The private IPv4 DNS hostname EC2 gives an instance for its primary private
/// address.
///
/// AWS builds the `ip-name` style hostname as `ip-<dash-separated address>`
/// followed by the Region's private DNS domain ([`private_dns_domain`]).
pub fn private_dns_name(private_ip: &str, region: &str) -> String {
    let host = private_ip.replace('.', "-");
    format!("ip-{host}.{domain}", domain = private_dns_domain(region))
}

/// The `ArchitectureValues` member every Apple silicon Mac instance type reports: the
/// catalog's `arm64_mac` (the generated catalog is
/// `crate::ops::types::ARCHITECTURE_VALUES_VALUES`), which [`architecture_for`] answers for
/// every `mac` family but the Intel `mac1`.
pub const ARCHITECTURE_ARM64_MAC: &str = "arm64_mac";

/// The public DNS domain of a Region: the suffix of every Amazon-provided PUBLIC hostname
/// in it, the public counterpart of [`private_dns_domain`].
///
/// AWS uses `compute-1.amazonaws.com` in `us-east-1` and `<region>.compute.amazonaws.com`
/// in every other Region (Amazon EC2 User Guide, "Amazon EC2 instance hostname types").
pub fn public_dns_domain(region: &str) -> String {
    if region == EC2_INTERNAL_REGION {
        "compute-1.amazonaws.com".to_string()
    } else {
        format!("{region}.compute.amazonaws.com")
    }
}

/// The public IPv4 DNS hostname EC2 gives an instance for a public address it holds.
///
/// The public counterpart of [`private_dns_name`]: AWS builds it as `ec2-<dash-separated
/// address>` followed by the Region's public DNS domain ([`public_dns_domain`]).
pub fn public_dns_name(public_ip: &str, region: &str) -> String {
    let host = public_ip.replace('.', "-");
    format!("ec2-{host}.{domain}", domain = public_dns_domain(region))
}

/// The processor architecture an instance type runs on.
///
/// AWS names an instance type `<family><generation><capabilities>.<size>` and
/// defines `g` among the capability letters as "AWS Graviton processor", which is
/// `arm64`; `a1` is the first Graviton family and predates that letter, and the
/// `mac` families run Apple silicon from their second generation on. Every other
/// family is `x86_64`. The value is one of `ARCHITECTURE_VALUES_VALUES` in
/// `ops/types/shared_types.rs`.
pub fn architecture_for(instance_type: &str) -> String {
    let family = instance_type.split('.').next().unwrap_or_default();
    if family.starts_with("mac") {
        return if family == "mac1" {
            "x86_64_mac".to_string()
        } else {
            ARCHITECTURE_ARM64_MAC.to_string()
        };
    }
    if family == "a1" {
        return "arm64".to_string();
    }
    let capabilities: String = family
        .chars()
        .skip_while(char::is_ascii_alphabetic)
        .skip_while(char::is_ascii_digit)
        .collect();
    if capabilities.contains('g') {
        "arm64".to_string()
    } else {
        "x86_64".to_string()
    }
}

/// The reason EC2 records on a state change a caller asked for, naming the
/// instant it happened.
pub fn user_initiated_reason(at: SystemTime) -> String {
    format!("User initiated ({})", iso8601_utc(at))
}

/// The `StateReason$Code` EC2 records on an instance a caller asked to shut down.
pub const INSTANCE_STATE_REASON_USER_INITIATED_SHUTDOWN: &str = "Client.UserInitiatedShutdown";

/// The `StateReason$Message` that goes with [`INSTANCE_STATE_REASON_USER_INITIATED_SHUTDOWN`]:
/// "the message for the state change" EC2 spells as the code followed by its description
/// (`StateReason$Message`).
pub const INSTANCE_STATE_REASON_MESSAGE_USER_INITIATED_SHUTDOWN: &str =
    "Client.UserInitiatedShutdown: User initiated shutdown";

/// The `StateReason$Code` and `$Message` of an instance that is still being launched.
///
/// "The reason for the most recent state transition" (`Instance$StateReason`): the most
/// recent transition of an instance nobody has moved yet is its own launch, which is still
/// in progress — so the reason is the state it is in, reported for both members, which is
/// what a launch's answer carries for the instance it just minted.
pub const INSTANCE_STATE_REASON_PENDING: &str = "pending";

/// `at` as an RFC 3339 / ISO 8601 UTC timestamp.
pub fn iso8601_utc(at: SystemTime) -> String {
    system_time_to_date_time(at)
        .fmt(::aws_smithy_types::date_time::Format::DateTime)
        .unwrap_or_default()
}

/// A `SystemTime` as the modelled timestamp type.
pub fn system_time_to_date_time(at: SystemTime) -> ::aws_smithy_types::DateTime {
    let seconds = at
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    ::aws_smithy_types::DateTime::from_secs_f64(seconds)
}

/// The `Operator` a resource of THIS account reports: no service provider manages it.
///
/// "Describes whether the resource is managed by a service provider and, if so, describes
/// the service provider that manages it" (`OperatorResponse`), where "if `true`, the
/// resource is managed by a service provider" (`$Managed`) and "if `managed` is `true`,
/// then the principal is returned" (`$Principal`). So a resource the caller created for
/// itself answers the question with `false` and names no principal — the member reports
/// the ANSWER, and a resource nobody manages still has one.
///
/// The ONE reading of that answer for the records THIS module stores with an operator —
/// the account's EBS volumes and its network interfaces — so those cannot report it two
/// ways. It is not forced on a record whose own writer decides the member from the
/// request: `CreateLaunchTemplate` takes an `OperatorRequest` from the caller and reports
/// the operator it was given or none at all, which is that operation's rule rather than
/// this one.
pub fn unmanaged_operator() -> OperatorResponse {
    OperatorResponse {
        managed: Some(false),
        principal: None,
        // "If `true`, the resource is hidden by default based on the managed resource
        // visibility settings for the account" (`$HiddenByDefault`): a resource no service
        // provider manages is not hidden by any such setting, which is an answer of
        // `false` rather than no answer at all.
        hidden_by_default: Some(false),
    }
}

/// One Availability Zone of one Region, as the describe reads it.
///
/// `zone_type`, `state` and `opt_in_status` are `&'static str` because this emulator
/// serves standard Availability Zones only: each is one fixed value of its modelled
/// enum rather than something a request can move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityZoneRecord {
    /// `us-east-1a` — the Region name with the zone's letter appended.
    pub zone_name: String,
    /// `use1-az1` — the Region's zone-id prefix with the zone's number appended.
    pub zone_id: String,
    /// The Region this zone belongs to.
    pub region_name: String,
    /// The zone group this zone belongs to.
    pub group_name: String,
    /// The network border group this zone's addresses are advertised from.
    pub network_border_group: String,
    /// `availability-zone`, `local-zone` or `wavelength-zone`.
    pub zone_type: &'static str,
    /// `available`, `unavailable`, `constrained`, …
    pub state: &'static str,
    /// `opt-in-not-required`, `opted-in` or `not-opted-in`.
    pub opt_in_status: &'static str,
    /// Any messages about this zone; empty when the zone is serving normally.
    pub messages: Vec<String>,
    /// `US West (Oregon) 1` — the long name of the zone group this zone belongs to, as
    /// AWS publishes it for the zone's Region ([`zone_group_long_name`]), or `None` for a
    /// Region that publishes no display name.
    pub group_long_name: Option<String>,
    /// `United States of America` — the country the zone's Region sits in
    /// ([`region_display`]), or `None` for a Region that publishes no display data.
    pub geography: Option<String>,
    /// `Oregon` — the location inside that country the zone's Region names, when it names
    /// one ([`region_display`]).
    pub sub_geography: Option<String>,
}

impl AvailabilityZoneRecord {
    /// This zone as the modelled `AvailabilityZone` shape.
    ///
    /// `ParentZoneName`/`ParentZoneId` are absent because only a Local Zone or a
    /// Wavelength Zone has a parent zone. `GroupLongName`, `Geography` and
    /// `SubGeography` are the display data AWS publishes for the zone's Region
    /// ([`super::availability_zone_display`]), reported as the model shapes them — each
    /// geography as the one-entry LIST the model declares (`AvailabilityZone$Geography`:
    /// "the geography is returned as a list") — and absent only for a Region that
    /// publishes none.
    pub fn to_availability_zone(&self) -> AvailabilityZone {
        AvailabilityZone {
            zone_name: Some(self.zone_name.clone()),
            zone_id: Some(self.zone_id.clone()),
            region_name: Some(self.region_name.clone()),
            group_name: Some(self.group_name.clone()),
            network_border_group: Some(self.network_border_group.clone()),
            zone_type: Some(self.zone_type.to_string()),
            state: Some(self.state.to_string()),
            opt_in_status: Some(self.opt_in_status.to_string()),
            messages: Some(
                self.messages
                    .iter()
                    .map(|message| AvailabilityZoneMessage {
                        message: Some(message.clone()),
                    })
                    .collect(),
            ),
            parent_zone_name: None,
            parent_zone_id: None,
            group_long_name: self.group_long_name.clone(),
            geography: self.geography.clone().map(|name| {
                vec![AvailabilityZoneGeography {
                    name: Some(name),
                }]
            }),
            sub_geography: self.sub_geography.clone().map(|name| {
                vec![AvailabilityZoneSubGeography {
                    name: Some(name),
                }]
            }),
        }
    }

    /// The values the EC2 filter `name` compares against this zone, or `None` when
    /// `name` is not one of [`AVAILABILITY_ZONE_FILTERS`].
    ///
    /// A filter naming a member this zone does not carry compares against NO values,
    /// so it selects nothing — the same answer AWS gives for, say, `parent-zone-id`
    /// on an Availability Zone.
    pub fn filter_values(&self, name: &str) -> Option<Vec<&str>> {
        let values = match name {
            "group-name" => vec![self.group_name.as_str()],
            // The long name a zone DOES carry once its Region publishes one, so the filter
            // compares against the same value the report carries; a zone of a Region that
            // publishes none has no long name to compare, so it matches nothing.
            "group-long-name" => self
                .group_long_name
                .as_deref()
                .map_or_else(Vec::new, |long_name| vec![long_name]),
            "message" => self.messages.iter().map(String::as_str).collect(),
            "opt-in-status" => vec![self.opt_in_status],
            "parent-zone-id" | "parent-zone-name" => Vec::new(),
            "region-name" => vec![self.region_name.as_str()],
            "state" => vec![self.state],
            "zone-id" => vec![self.zone_id.as_str()],
            "zone-name" => vec![self.zone_name.as_str()],
            "zone-type" => vec![self.zone_type],
            _ => return None,
        };
        Some(values)
    }
}

/// The Availability Zones Region `region` has.
///
/// Zone `n` (counting from 1) is named `<region><letter>` with the letters running
/// from `a` — `us-east-1a` — and carries the zone id `<prefix>-az<n>` built from
/// [`zone_id_prefix`]; both forms are the ones the operation's `Filters` doc gives
/// for the `zone-name` and `zone-id` filters. Every zone is an
/// `availability-zone`, which is `opt-in-not-required`, so it is reported whether or
/// not the request sets `AllAvailabilityZones`.
pub fn availability_zones_in_region(region: &str) -> Vec<AvailabilityZoneRecord> {
    let prefix = zone_id_prefix(region);
    let display = region_display(region);
    (0..AVAILABILITY_ZONES_PER_REGION)
        .map(|index| {
            let letter = char::from(b'a' + u8::try_from(index).unwrap_or(0));
            // The model's `group-name` filter doc gives the zone group of an
            // Availability Zone as `<region>-zg-1` (its example: `us-east-1-zg-1`).
            let group_name = format!("{region}-zg-1");
            AvailabilityZoneRecord {
                zone_name: format!("{region}{letter}"),
                zone_id: format!("{prefix}-az{}", index + 1),
                region_name: region.to_string(),
                group_long_name: zone_group_long_name(region, &group_name),
                group_name,
                // A standard Availability Zone's network border group is the Region.
                network_border_group: region.to_string(),
                zone_type: ZONE_TYPE_AVAILABILITY_ZONE,
                state: ZONE_STATE_AVAILABLE,
                opt_in_status: OPT_IN_NOT_REQUIRED,
                messages: Vec::new(),
                geography: display.map(|display| display.geography.to_string()),
                sub_geography: display
                    .and_then(|display| display.sub_geography)
                    .map(str::to_string),
            }
        })
        .collect()
}

/// The Availability Zone of `zones` whose `select`ed form is `value`, or the refusal EC2
/// answers for a zone the Region does not have.
///
/// ONE lookup for both spellings of a zone — its name
/// ([`AvailabilityZoneRecord::zone_name`]) and its id ([`AvailabilityZoneRecord::zone_id`])
/// — so the two members a request may name a zone by cannot resolve it two ways, and
/// `member` only says which one a refusal is about. `zones` is the Region's zones, as
/// [`availability_zones_in_region`] gives them.
pub fn availability_zone_of_region<'zones, E>(
    zones: &'zones [AvailabilityZoneRecord],
    region: &str,
    member: &str,
    value: &str,
    select: fn(&AvailabilityZoneRecord) -> &str,
) -> Result<&'zones AvailabilityZoneRecord, Scaffolded<E>> {
    availability_zone_refused_with(zones, value, select, || {
        invalid_parameter_value(format!(
            "Invalid value '{value}' for {member}. \
             Region '{region}' has no such Availability Zone"
        ))
    })
}

/// The same lookup as [`availability_zone_of_region`], refused with the sentence `refusal`
/// builds.
///
/// The LOOKUP is one fact of a Region while the REFUSAL is a fact of the operation: an
/// operation whose recorded answer for a zone the Region does not have is not the
/// parameter-value one — `AllocateHosts`, where the zone is part of a host configuration the
/// request could not have — passes its own constructor here rather than keeping a second
/// copy of the search, so the two cannot drift in which zone list they consult.
pub fn availability_zone_refused_with<'zones, E>(
    zones: &'zones [AvailabilityZoneRecord],
    value: &str,
    select: fn(&AvailabilityZoneRecord) -> &str,
    refusal: impl FnOnce() -> Scaffolded<E>,
) -> Result<&'zones AvailabilityZoneRecord, Scaffolded<E>> {
    zones
        .iter()
        .find(|zone| select(zone) == value)
        .ok_or_else(refusal)
}

/// A Region's zone-id prefix: its leading component, then every further component
/// abbreviated by [`abbreviate_region_component`] — `us-east-1` -> `use1`,
/// `ap-northeast-2` -> `apne2`, `us-gov-west-1` -> `usgw1`.
///
/// The form is the one the operation's `Filters` doc gives for the `zone-id` filter
/// (`use1-az1` in `us-east-1`).
pub fn zone_id_prefix(region: &str) -> String {
    let parts: Vec<&str> = region.split('-').filter(|part| !part.is_empty()).collect();
    let Some((first, rest)) = parts.split_first() else {
        return region.replace('-', "");
    };
    let mut prefix = String::from(*first);
    for part in rest {
        prefix.push_str(&abbreviate_region_component(part));
    }
    prefix
}

/// One component of a Region name as it appears in a zone id: a number is kept whole,
/// a compound cardinal direction keeps one letter per direction (`northeast` -> `ne`),
/// and anything else keeps its first character.
pub(super) fn abbreviate_region_component(part: &str) -> String {
    if part.bytes().all(|byte| byte.is_ascii_digit()) {
        return part.to_string();
    }
    match part {
        "northeast" => "ne".to_string(),
        "northwest" => "nw".to_string(),
        "southeast" => "se".to_string(),
        "southwest" => "sw".to_string(),
        other => other.chars().take(1).collect(),
    }
}

/// Every filter `DescribeInstanceTypeOfferings` documents, as its `Filters` member
/// lists them
/// (`smithy_query(query="doc",shape="DescribeInstanceTypeOfferingsRequest",member="Filters")`).
/// A filter outside this set is refused; each filter inside it compares against ONE
/// field of an offering — `instance-type` against its instance type, `location`
/// against its location — which is what lets a describe narrow each field before
/// building the offerings themselves.
pub const INSTANCE_TYPE_OFFERING_FILTERS: [&str; 2] = ["instance-type", "location"];

/// The `LocationType` a `DescribeInstanceTypeOfferings` request that names none asks
/// about: the operation's own doc says "If no location is specified, the default is to
/// list the instance types that are offered in the current Region".
pub const DEFAULT_LOCATION_TYPE: &str = "region";

/// One instance type offered in one location, as the describe reads it.
///
/// `instance_type` and `location_type` are `&'static str` because each is one value of
/// its modelled enum, taken from that enum's generated value list rather than from a
/// request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceTypeOfferingRecord {
    /// `t3.micro` — a value of the modelled `InstanceType` enum.
    pub instance_type: &'static str,
    /// `region`, `availability-zone`, `availability-zone-id` or `outpost`.
    pub location_type: &'static str,
    /// The identifier of the location, in the form `location_type` selects: a Region
    /// name, a zone name, a zone id or an Outpost ARN.
    pub location: String,
}

impl InstanceTypeOfferingRecord {
    /// This offering as the modelled `InstanceTypeOffering` shape.
    pub fn to_instance_type_offering(&self) -> InstanceTypeOffering {
        InstanceTypeOffering {
            instance_type: Some(self.instance_type.to_string()),
            location_type: Some(self.location_type.to_string()),
            location: Some(self.location.clone()),
        }
    }
}

/// The modelled `LocationType` `requested` names — [`DEFAULT_LOCATION_TYPE`] when it
/// names none — or `None` when it is not one of the enum's values
/// (`crate::ops::types::LOCATION_TYPE_VALUES`, generated from the model).
pub fn location_type(requested: Option<&str>) -> Option<&'static str> {
    let requested = requested.unwrap_or(DEFAULT_LOCATION_TYPE);
    LOCATION_TYPE_VALUES
        .iter()
        .copied()
        .find(|value| *value == requested)
}

/// The locations of type `location_type` that Region `region` has.
///
/// Each form is the one the `LocationType` member's own doc gives for that value: the
/// current Region for `region`, an Availability Zone of the Region for
/// `availability-zone`, an AZ ID of the Region for `availability-zone-id` — both taken
/// from [`availability_zones_in_region`], so one zone list serves every operation —
/// and an Outpost ARN for `outpost`.
///
/// An Outpost is hardware AWS installs in a customer's own facility and no operation
/// of this service creates one, so a Region here has no Outpost locations and reports
/// no offering in one.
pub fn locations_of_type(region: &str, location_type: &str) -> Vec<String> {
    match location_type {
        "region" => vec![region.to_string()],
        "availability-zone" => availability_zones_in_region(region)
            .into_iter()
            .map(|zone| zone.zone_name)
            .collect(),
        "availability-zone-id" => availability_zones_in_region(region)
            .into_iter()
            .map(|zone| zone.zone_id)
            .collect(),
        "outpost" => Vec::new(),
        // Unreachable through [`location_type`], which answers only values of the
        // modelled enum: a value outside it names no location of any kind, so it is
        // reported as no locations rather than as the Region's.
        _ => Vec::new(),
    }
}

/// The instance types this emulator offers, in the catalog's own order.
///
/// The catalog is the modelled `InstanceType` enum's generated value list
/// (`crate::ops::types::INSTANCE_TYPE_VALUES`, from
/// `smithy_query(query="shape",shape="InstanceType")`), so an instance type is offered
/// exactly when the model declares it. AWS offers a Region-specific subset of them,
/// and neither the model nor a request carries WHICH subset a Region has, so the set
/// is the same in every Region rather than a per-Region subset invented here.
///
/// WITHIN a Region the zones differ, which is a fact the describe of offerings reports per
/// zone: see [`location_offers_instance_type`] for which of these a given Availability Zone
/// offers.
pub fn offered_instance_types() -> &'static [&'static str] {
    INSTANCE_TYPE_VALUES
}

/// Every offering of `instance_types` in `locations` of `region`, reported as
/// `location_type`.
///
/// The caller passes the locations and the instance types that the request's filters
/// leave, which is what keeps the cost of a filtered describe proportional to
/// locations + types rather than to their product: a filter on this operation compares
/// against one field of an offering, so narrowing each field BEFORE the product is
/// built answers exactly what testing every built offering would.
///
/// Not every pair is an offering: an instance type is offered in a location only when
/// [`location_offers_instance_type`] says that location has it, which is what makes the
/// offerings of a Region's Availability Zones differ from one another.
///
/// The result is in cursor order — location first, then instance type, as
/// [`offering_page_cursor`] joins them — which is the order a `NextToken` walk resumes
/// in, so it is sorted here rather than inherited from the order `locations` or
/// `instance_types` happen to arrive in.
pub fn instance_type_offerings(
    region: &str,
    locations: &[String],
    instance_types: &[&'static str],
    location_type: &'static str,
) -> Vec<InstanceTypeOfferingRecord> {
    let mut offerings: Vec<InstanceTypeOfferingRecord> = locations
        .iter()
        .flat_map(|location| {
            instance_types
                .iter()
                .filter(move |instance_type| {
                    location_offers_instance_type(region, location, location_type, instance_type)
                })
                .map(move |instance_type| InstanceTypeOfferingRecord {
                    instance_type,
                    location_type,
                    location: location.clone(),
                })
        })
        .collect();
    offerings.sort_by_cached_key(offering_page_cursor);
    offerings
}

/// The `LocationType` value naming a Region's Availability Zones by NAME, as
/// [`locations_of_type`] reads it — a member of the modelled `LocationType` enum.
pub const LOCATION_TYPE_AVAILABILITY_ZONE: &str = "availability-zone";

/// The `LocationType` value naming them by AZ ID.
pub const LOCATION_TYPE_AVAILABILITY_ZONE_ID: &str = "availability-zone-id";

/// Whether `location` of `region`, named as `location_type`, offers `instance_type`.
///
/// "The results can be filtered by location" and
/// `DescribeInstanceTypeOfferings(LocationType='availability-zone')` reports an offering per
/// ZONE precisely because the answer differs between the zones of one Region: AWS does not
/// offer every instance type in every Availability Zone, which is why a launch into a zone
/// that lacks the requested type is refused `Unsupported` and a capacity-aware client
/// enumerates offerings to choose a zone.
///
/// WHICH zone lacks which type is per-account, per-Region data neither the model nor a
/// request carries, so where the boundary falls is CHOSEN and derived, not invented per
/// call: a Region's LAST Availability Zone in zone order does not offer the
/// CURRENT-generation instance types ([`InstanceTypeName::current_generation`], which reads
/// AWS's own "Previous generation instances" list), while every other zone of the Region
/// offers the whole catalog. So the offerings of a Region are a strict subset relation
/// between its zones, the newest families being the ones a zone can lack, and the previous
/// generations — the ones every zone has had since it was built — are offered everywhere.
///
/// A whole REGION offers a type whenever any of its zones does, which every type satisfies,
/// so a `region` location offers the whole catalog; a location kind that names no zone
/// (`outpost`) has no offerings to narrow in the first place.
pub fn location_offers_instance_type(
    region: &str,
    location: &str,
    location_type: &str,
    instance_type: &str,
) -> bool {
    // OnCallWorlds patch: upstream withholds every current-generation type from a Region's
    // last zone. A seeded account runs the fleet its world describes in all three zones, so
    // in a seeded process every zone offers every type (a capacity shortfall is a seeded
    // Auto Scaling activity instead).
    if ocw_clock::seeded() {
        return true;
    }
    if unoffering_location(region, location_type).as_deref() != Some(location) {
        return true;
    }
    InstanceTypeName::parse(instance_type).is_none_or(|name| !name.current_generation())
}

/// The location of `region`'s LAST Availability Zone as `location_type` names it, or `None`
/// when that kind of location names no single zone.
///
/// The ONE place the Region's offering boundary is placed, so [`location_offers_instance_type`]
/// answers the same for a zone whether the request named it by name or by AZ ID.
fn unoffering_location(region: &str, location_type: &str) -> Option<String> {
    let zones = availability_zones_in_region(region);
    let last = zones.last()?;
    match location_type {
        LOCATION_TYPE_AVAILABILITY_ZONE => Some(last.zone_name.clone()),
        LOCATION_TYPE_AVAILABILITY_ZONE_ID => Some(last.zone_id.clone()),
        _ => None,
    }
}

/// Whether the Availability Zone named `zone_name` offers `instance_type`.
///
/// [`location_offers_instance_type`] for the zone's own Region, so a launch's offering check
/// and `DescribeInstanceTypeOfferings` cannot disagree about one zone.
pub fn zone_offers_instance_type(zone_name: &str, instance_type: &str) -> bool {
    location_offers_instance_type(
        region_of_zone_name(zone_name),
        zone_name,
        LOCATION_TYPE_AVAILABILITY_ZONE,
        instance_type,
    )
}

/// EC2's error code for a request asking for something the location it named cannot serve —
/// "the requested configuration is currently not supported" (EC2 API error codes), which is
/// what a launch of an instance type an Availability Zone does not offer is refused with.
pub const UNSUPPORTED: &str = "Unsupported";

/// Refuse a launch of `instance_type` into `zone_name`, which does not offer it: HTTP 400
/// [`UNSUPPORTED`].
///
/// Every variable part comes from the request and from this emulator's own offerings — the
/// type the launch asked for, the zone it asked for, and the zones of that Region that DO
/// offer the type ([`zones_offering_instance_type`]) — so the sentence states the rule and
/// names what a caller can retry with rather than carrying one run's values.
pub fn unsupported_instance_type_in_zone<E>(
    instance_type: &str,
    zone_name: &str,
) -> crate::scaffolded::Scaffolded<E> {
    let offered =
        zones_offering_instance_type(region_of_zone_name(zone_name), instance_type).join(", ");
    crate::scaffolded::Scaffolded::service_error(
        UNSUPPORTED,
        400,
        format!(
            "Your requested instance type ({instance_type}) is not supported in your requested \
             Availability Zone ({zone_name}). Please retry your request by not specifying an \
             Availability Zone or choosing {offered}."
        ),
    )
}

/// The names of `region`'s Availability Zones that DO offer `instance_type`, in zone order.
///
/// What a refusal names the caller back as the zones to retry in, read through the same
/// predicate the describe reports.
pub fn zones_offering_instance_type(region: &str, instance_type: &str) -> Vec<String> {
    availability_zones_in_region(region)
        .into_iter()
        .map(|zone| zone.zone_name)
        .filter(|zone_name| zone_offers_instance_type(zone_name, instance_type))
        .collect()
}

/// The pagination cursor naming `offering`: its location and its instance type, joined
/// by a space.
///
/// Paging is by cursor rather than by index, the way [`encode_page_token`] and
/// `DescribeVpcs` do it, so a token names the offering the next page starts at instead
/// of a position a changed filter would shift. A cursor sorts the same way
/// [`instance_type_offerings`] orders the offerings themselves — location first, then
/// instance type — because the separator sorts ahead of every character a location or
/// an instance type can carry, so one location being a prefix of another cannot
/// reorder the two.
pub fn offering_page_cursor(offering: &InstanceTypeOfferingRecord) -> String {
    format!("{} {}", offering.location, offering.instance_type)
}

// =============================================================================
// Instance types: what the catalog publishes about each type
// =============================================================================

/// The parts of an instance type name: `m5d.24xlarge` is the family `m5d` — the family
/// letters `m`, the generation `5` and the capability letters `d` — at the size
/// `24xlarge`.
///
/// AWS documents the form in "Instance type naming conventions" (Amazon EC2 User
/// Guide): the instance family, the generation number, additional capability letters
/// (`a` AMD, `g` AWS Graviton, `i` Intel, `d` instance store volumes, `n` network and
/// EBS optimized, `b` block storage optimized, `e` extra capacity, `z` high frequency,
/// `flex` flexible), then the size. A `-` inside the family introduces a sub-model
/// rather than more capabilities (`m7i-flex`, `u7i-12tb`, `mac2-m2pro`, `p6-b200`), so
/// the capability letters stop there.
///
/// Every fact this module derives about an instance type is derived from these parts
/// and the published per-family ratios below, so one rule answers the whole catalog
/// ([`offered_instance_types`]) rather than a table that covers the types somebody
/// happened to list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceTypeName<'a> {
    /// `m5d` — everything before the dot.
    pub family: &'a str,
    /// `m` — the family's leading letters, which name the family itself.
    pub root: &'a str,
    /// `5` — the generation number, absent in the families that carry none
    /// (`u-6tb1`, `mac-m4`).
    pub generation: Option<u32>,
    /// `d` — the capability letters between the generation and any `-`.
    pub attributes: &'a str,
    /// `24xlarge`, `large`, `metal`, `metal-48xl` — everything after the dot.
    pub size: &'a str,
}

impl<'a> InstanceTypeName<'a> {
    /// `instance_type` split into its parts, or `None` when it is not of the form
    /// `<family>.<size>`.
    ///
    /// The family is the one [`instance_family_of`] reports; this also needs the size,
    /// and a value carrying none is not an instance type, so both are read here.
    pub fn parse(instance_type: &'a str) -> Option<Self> {
        let (family, size) = instance_type.split_once('.')?;
        if family.is_empty() || size.is_empty() {
            return None;
        }
        let letters = family
            .find(|c: char| !c.is_ascii_alphabetic())
            .unwrap_or(family.len());
        let (root, rest) = family.split_at(letters);
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let (generation, rest) = rest.split_at(digits);
        Some(Self {
            family,
            root,
            generation: generation.parse().ok(),
            attributes: rest.split('-').next().unwrap_or_default(),
            size,
        })
    }

    /// Does the family carry the capability letter `letter`?
    pub fn has_attribute(&self, letter: char) -> bool {
        self.attributes.contains(letter)
    }

    /// Is this a bare metal size — `metal`, or one of the sized `metal-<N>xl` forms?
    pub fn bare_metal(&self) -> bool {
        self.size == "metal" || self.size.starts_with("metal-")
    }

    /// Is this a "burstable performance T instance type"
    /// (`DescribeInstanceTypesRequest$Filters`), which is what the `t` family letter
    /// names?
    pub fn burstable(&self) -> bool {
        self.root == BURSTABLE_ROOT
    }

    /// Is this an AWS Graviton instance type?
    ///
    /// The naming conventions define the `g` capability letter as "AWS Graviton
    /// processor", and [`FIRST_GRAVITON_FAMILY`] is the first Graviton family, which
    /// predates the letter. Every Graviton instance type runs on the Nitro System.
    pub fn graviton(&self) -> bool {
        self.has_attribute('g') || self.family == FIRST_GRAVITON_FAMILY
    }

    /// Is this instance type current generation — "the latest generation instance type
    /// of an instance family" (`DescribeInstanceTypesRequest$Filters`)?
    ///
    /// AWS publishes the answer as a list of the families that are NOT:
    /// [`PREVIOUS_GENERATION_FAMILIES`], its "Previous generation instances" page. The
    /// generation NUMBER cannot stand in for that list — the modern families whose
    /// ladder is still young (`z1d`, `inf1`, `trn1`, `x2gd`) carry a low one, and the
    /// long-lived `t2` carries a lower one than families that page does list.
    pub fn current_generation(&self) -> bool {
        !PREVIOUS_GENERATION_FAMILIES.contains(&self.family)
    }

    /// Does this instance type run on the AWS Nitro System?
    ///
    /// The Nitro System carries every instance type from [`FIRST_NITRO_GENERATION`] on,
    /// every Graviton type, every EC2 Mac, the burstable families from their third
    /// generation ([`FIRST_NITRO_BURSTABLE_GENERATION`], the T3 generation that moved
    /// them onto it), and the earlier families the EC2 User Guide's list of instances
    /// built on the Nitro System names ([`EARLY_NITRO_FAMILIES`]).
    ///
    /// This is NOT the same line as [`Self::current_generation`]: `t2` is current and
    /// runs on the Xen hypervisor, while `a1` runs on Nitro and is previous generation.
    pub fn nitro(&self) -> bool {
        if self.burstable() {
            return self
                .generation
                .is_none_or(|generation| generation >= FIRST_NITRO_BURSTABLE_GENERATION);
        }
        self.graviton()
            || self.root == MAC_INSTANCE_FAMILY_PREFIX
            || EARLY_NITRO_FAMILIES.contains(&self.family)
            || self
                .generation
                .is_none_or(|generation| generation >= FIRST_NITRO_GENERATION)
    }

    /// Does this instance type automatically encrypt in-transit traffic between
    /// instances — the modelled `NetworkInfo$EncryptionInTransitSupported`?
    ///
    /// "Encryption in transit" in the Amazon EC2 User Guide: the traffic between two
    /// instances built on the 4th version of the Nitro System and later is encrypted
    /// automatically, which is every Nitro type from
    /// [`FIRST_ENCRYPTING_INSTANCE_GENERATION`] on, plus the earlier types that page
    /// names one by one ([`ENCRYPTING_INSTANCE_FAMILIES`]) and the high-memory family it
    /// names as a whole ([`HIGH_MEMORY_ROOT`]).
    ///
    /// The Graviton ladder reaches that version of the Nitro System one generation later
    /// than the Intel and AMD families do ([`FIRST_ENCRYPTING_GRAVITON_GENERATION`]): a
    /// Graviton2 type is a sixth-generation type on the version before it. Its
    /// network-optimized (`n`) sizes are the exception the same page makes for them — they
    /// carry the newer network card, which is what does the encrypting — so the delay is
    /// for the Graviton families WITHOUT that letter.
    ///
    /// A family carrying no generation at all (`u-6tb1`, whose digits state a memory
    /// size) is answered by those names alone, the way [`Self::nitro`] answers the
    /// facts it cannot read off a generation.
    pub fn encrypts_in_transit(&self) -> bool {
        let first = if self.graviton() && !self.has_attribute('n') {
            FIRST_ENCRYPTING_GRAVITON_GENERATION
        } else {
            FIRST_ENCRYPTING_INSTANCE_GENERATION
        };
        ENCRYPTING_INSTANCE_FAMILIES.contains(&self.family)
            || self.root == HIGH_MEMORY_ROOT
            || (self.nitro()
                && self
                    .generation
                    .is_some_and(|generation| generation >= first))
    }
}

/// The first Graviton generation whose types encrypt traffic in transit: the Graviton3
/// families, the seventh generation of their ladder — see
/// [`InstanceTypeName::encrypts_in_transit`].
pub const FIRST_ENCRYPTING_GRAVITON_GENERATION: u32 = 7;

/// The first generation that runs on the AWS Nitro System: the fifth generation of each
/// family moved onto it wholesale.
pub const FIRST_NITRO_GENERATION: u32 = 5;

/// The burstable generation that moved onto the AWS Nitro System: T3, two generations
/// before the ladder's fifth, while T1 and T2 ran on the Xen hypervisor.
pub const FIRST_NITRO_BURSTABLE_GENERATION: u32 = 3;

/// The families AWS lists on its "Previous generation instances" page — the ones that are
/// NOT current generation. Everything else is, including the fourth generation families
/// (`c4`, `m4`, `r4`) and the modern families whose ladder has not reached a fifth
/// generation yet.
pub(super) const PREVIOUS_GENERATION_FAMILIES: [&str; 16] = [
    "a1", "c1", "c3", "cc1", "cc2", "cg1", "cr1", "g2", "hi1", "hs1", "i2", "m1", "m2", "m3",
    "r3", "t1",
];

/// The families that run on the Nitro System from BEFORE their fifth generation, as the
/// EC2 User Guide's list of "instances built on the Nitro System" names them. The
/// Graviton families, the EC2 Macs and the burstable families from T3 on are answered by
/// [`InstanceTypeName::nitro`] itself rather than listed here.
pub(super) const EARLY_NITRO_FAMILIES: [&str; 24] = [
    "d3", "d3en", "dl1", "dl2q", "f2", "g4ad", "g4dn", "i3en", "i4g", "i4i", "im4gn", "inf1",
    "inf2", "is4gen", "p3dn", "p4d", "p4de", "trn1", "trn1n", "vt1", "x2idn", "x2iedn",
    "x2iezn", "z1d",
];

/// The first generation that can hibernate, among the families the hibernation
/// prerequisites name (C, M, R and T): the prerequisites list those families from their
/// third generation on, and the burstable ones from their second.
pub(super) const FIRST_HIBERNATION_GENERATION: u32 = 3;

/// The first burstable generation the hibernation prerequisites name (T2).
pub(super) const FIRST_HIBERNATION_BURSTABLE_GENERATION: u32 = 2;

/// The family of the first AWS Graviton instance type.
pub(super) const FIRST_GRAVITON_FAMILY: &str = "a1";

/// The family letters of the burstable performance instance types.
pub(super) const BURSTABLE_ROOT: &str = "t";

/// The family letters of the HPC instance types, which ship with simultaneous
/// multithreading disabled and carry an Elastic Fabric Adapter at every size.
pub(super) const HPC_ROOT: &str = "hpc";

/// One `large` size, in the sixteenths [`instance_size_sixteenths`] counts in.
pub(super) const SIZE_UNIT: u32 = 16;

/// One `xlarge` size, in those same sixteenths: the step of the size ladder AWS's
/// EBS-optimized performance table is read per ([`ebs_optimized_info`]).
pub(super) const XLARGE_SIXTEENTHS: u32 = 2 * SIZE_UNIT;

/// The sustained EBS bandwidth, in Mbps, one `xlarge` of size carries — the slope of the
/// baseline column of AWS's "Amazon EBS-optimized instance types" table below the size at
/// which a family reaches its ceiling.
pub(super) const EBS_BASELINE_MBPS_PER_XLARGE: i64 = 1_150;

/// The sustained EBS IOPS one `xlarge` of size carries: the same column's IOPS slope.
pub(super) const EBS_BASELINE_IOPS_PER_XLARGE: i64 = 6_000;

/// The EBS bandwidth ceiling, in Mbps, every size of a family can reach — the full-size row
/// of that table, which the smaller sizes of the family burst up to.
pub(super) const EBS_BURST_FLOOR_MBPS: i64 = 4_750;

/// The EBS IOPS ceiling every size can reach: the same row's IOPS figure.
pub(super) const EBS_BURST_FLOOR_IOPS: i64 = 18_750;

/// The EBS bandwidth ceiling, in Mbps, one `xlarge` of size carries ABOVE the full size:
/// the shallower slope the table's larger rows follow, where a size no longer bursts
/// because it already has the host's share.
pub(super) const EBS_BURST_MBPS_PER_XLARGE: i64 = 850;

/// The EBS IOPS ceiling one `xlarge` of size carries above the full size.
pub(super) const EBS_BURST_IOPS_PER_XLARGE: i64 = 3_750;

/// The megabits in a megabyte, which is all that separates `EbsOptimizedInfo`'s Mbps
/// columns from its MB/s ones.
pub(super) const EBS_MEGABITS_PER_MEGABYTE: f64 = 8.0;

/// The vCPUs one `large` unit of size carries: AWS's `large` is a two-vCPU instance and
/// the ladder doubles from there, so every size of every family follows from this.
pub(super) const VCPUS_PER_SIZE_UNIT: u32 = 2;

/// The largest single local device an instance store is presented as; a bigger store is
/// more devices of this size rather than one larger device (the disk counts published
/// in "Instance store volumes", where a 15,200 GB store is 8 devices of 1,900 GB).
pub(super) const MAX_INSTANCE_STORE_DISK_GB: u64 = 1_900;

/// The least vCPUs AWS Nitro Enclaves needs: "the instance type must have at least 4
/// vCPUs" (Nitro Enclaves User Guide).
pub(super) const MIN_ENCLAVE_VCPUS: i32 = 4;

/// The most memory an instance type may have and still hibernate: the hibernation
/// prerequisites give "instance RAM size — must be less than 150 GiB".
pub(super) const MAX_HIBERNATION_MEMORY_MIB: i64 = 150 * 1024;

/// The generation from which Amazon EBS encryption is supported; the oldest families
/// predate it.
pub(super) const FIRST_EBS_ENCRYPTION_GENERATION: u32 = 3;

/// The generation from which an NVMe instance store appears, on the storage optimized
/// families: the I3 family and everything after it presents local NVMe devices, while
/// the older families present SATA SSDs or magnetic disks.
pub(super) const FIRST_NVME_STORAGE_GENERATION: u32 = 3;

/// The generation from which the AMD families support AMD SEV-SNP (the memory
/// encryption feature `processor-info.supported-features` reports).
pub(super) const FIRST_SEV_SNP_GENERATION: u32 = 6;

/// The smallest size, in sixteenths, that an Elastic Fabric Adapter is offered on: EFA
/// is an option of the largest sizes of a family (EC2 User Guide, "Elastic Fabric
/// Adapter"), which from the 16xlarge up is what this names.
pub(super) const EFA_MINIMUM_SIXTEENTHS: u32 = 16 * 2 * SIZE_UNIT;

/// The NitroTPM version a Nitro instance type offers — "the supported NitroTPM version
/// (2.0)" (`DescribeInstanceTypesRequest$Filters`).
pub(super) const NITRO_TPM_VERSION: &str = "2.0";

/// The EBS attachments a Nitro instance type has, shared between its EBS volumes, its
/// network interfaces and its NVMe instance store devices: "most Nitro instances
/// support a maximum of 28 attachments" (EC2 User Guide, "Instance volume limits").
pub(super) const NITRO_ATTACHMENT_LIMIT: i32 = 28;

/// The EBS volumes a pre-Nitro (Xen) instance type can have attached, a limit of its
/// own rather than one shared with its interfaces (same page).
pub(super) const XEN_EBS_VOLUME_LIMIT: i32 = 27;

/// The default connection tracking idle timeouts, in seconds, that a Nitro instance
/// type reports — the values the EC2 User Guide publishes under "Connection tracking
/// timeouts": 432,000 s for an established TCP connection, 30 s for UDP and 180 s for
/// a UDP stream.
pub(super) const CONNECTION_TRACKING_TIMEOUTS: (i32, i32, i32) = (432_000, 30, 180);

/// The instance types the Amazon Web Services Free Tier covers: "750 hours per month of
/// Linux, RHEL or SLES t2.micro or t3.micro instance usage" (AWS Free Tier).
pub(super) const FREE_TIER_INSTANCE_TYPES: [&str; 2] = ["t2.micro", "t3.micro"];

/// The instance types that run 32-bit AMIs, each of which also runs 64-bit ones: the
/// four previous generation sizes the EC2 User Guide lists for `i386`.
pub(super) const I386_INSTANCE_TYPES: [&str; 4] = ["c1.medium", "m1.medium", "m1.small", "t1.micro"];

/// The previous generation families whose AMIs are paravirtual and never HVM (EC2 User
/// Guide, "Linux AMI virtualization types").
pub(super) const PARAVIRTUAL_ONLY_FAMILIES: [&str; 4] = ["c1", "m1", "m2", "t1"];

/// The previous generation families that run both paravirtual and HVM AMIs (same page).
pub(super) const PARAVIRTUAL_AND_HVM_FAMILIES: [&str; 10] = [
    "c3", "cc1", "cc2", "cg1", "cr1", "g2", "hi1", "hs1", "i2", "m3",
];

/// The family letters whose instance storage IS the family: the storage optimized
/// families, which carry local devices at every size rather than only in their `d`
/// sizes ("Instance store volumes").
pub(super) const LOCAL_STORAGE_ROOTS: [&str; 7] = ["d", "h", "hi", "hs", "i", "im", "is"];

/// The families outside [`LOCAL_STORAGE_ROOTS`] whose names do not end in the `d`
/// capability letter and that still ship local devices: the accelerated families with
/// local NVMe and the previous generation families that came with instance store
/// volumes (same page).
pub(super) const LOCAL_STORAGE_FAMILIES: [&str; 23] = [
    "c1", "c3", "cc1", "cc2", "cg1", "cr1", "dl1", "dl2q", "f1", "f2", "g2", "g5", "g5g", "g6",
    "g6e", "g7", "g7e", "m1", "m2", "m3", "r3", "x1", "x1e",
];

/// The families whose instance store is magnetic rather than solid state — the dense
/// HDD storage families and the oldest general purpose and compute families (same
/// page). Every other instance store is `ssd`.
pub(super) const HDD_STORAGE_FAMILIES: [&str; 9] =
    ["c1", "d2", "d3", "d3en", "h1", "hs1", "m1", "m2", "m3"];

/// The vCPUs and memory (GiB) of each EC2 Mac host, whose only size is `metal` so the
/// size ladder gives neither: the configurations published in "Amazon EC2 Mac
/// instances" — `mac1` an Intel Mac mini, the rest Apple silicon Macs.
pub(super) const MAC_HOSTS: [(&str, i32, i64); 9] = [
    ("mac1", 12, 32),
    ("mac2", 8, 16),
    ("mac2-m2", 8, 24),
    ("mac2-m2pro", 12, 32),
    ("mac2-m1ultra", 20, 128),
    ("mac-m3ultra", 28, 96),
    ("mac-m4", 10, 24),
    ("mac-m4pro", 14, 48),
    ("mac-m4max", 16, 128),
];

/// The largest multiple of `xlarge` this module will read out of a size component.
///
/// AWS's published ladder tops out at `112xlarge` (`u7i-12tb.112xlarge`), so a multiple
/// above this ceiling names no size AWS offers. The ceiling is what BOUNDS the arithmetic
/// below: the size component is TEXT, so a multiple near `u32::MAX` would otherwise
/// overflow the conversion into sixteenths — a panic where overflow checks are on, a
/// wrapped count where they are off — and then the vCPU ([`default_vcpus`]) and memory
/// ([`memory_mib_of`]) derivations built on it. It sits well above the published ladder so
/// a new AWS size does not need it changed.
pub const MAX_SIZE_MULTIPLE: u32 = 512;

/// The largest High Memory size, in TiB, this module will read out of a family token.
///
/// AWS's published High Memory families top out at 32 TiB (`u7in-32tb`), so a token above
/// this ceiling names no instance type AWS offers. The ceiling is what BOUNDS the
/// arithmetic in [`stated_memory_gib`], exactly as [`MAX_SIZE_MULTIPLE`] bounds the size
/// component's: the family token is TEXT, so a figure near `i64::MAX` would otherwise
/// overflow the conversion into GiB and then into MiB — a panic where overflow checks are
/// on, a wrapped figure where they are off, reported as `MemoryInfo`. It sits well above
/// the published families so a larger one does not need it changed.
pub const MAX_STATED_MEMORY_TIB: i64 = 256;

/// The size component of an instance type name, in SIXTEENTHS of the family's `large`
/// size.
///
/// AWS's size ladder doubles at each step — `large`, `xlarge`, `2xlarge`, … — and the
/// sizes below `large` are fractions of it: `medium` a half, `small` a quarter, `micro`
/// an eighth and `nano` a sixteenth. Counting in sixteenths is what lets ONE published
/// per-family ratio describe every size of that family in whole numbers.
///
/// `metal-48xl` is the 48xlarge-sized bare metal size, so it is on the ladder. A plain
/// `metal` names the whole host, whose size the name itself does not give, so it is
/// answered `None` here and resolved by [`instance_size_sixteenths_of`]. A multiple above
/// [`MAX_SIZE_MULTIPLE`] is answered `None` too: it is not a size AWS offers.
pub fn instance_size_sixteenths(size: &str) -> Option<u32> {
    match size {
        "nano" => Some(SIZE_UNIT / 16),
        "micro" => Some(SIZE_UNIT / 8),
        "small" => Some(SIZE_UNIT / 4),
        "medium" => Some(SIZE_UNIT / 2),
        "large" => Some(SIZE_UNIT),
        "xlarge" => Some(2 * SIZE_UNIT),
        "metal" => None,
        _ => {
            let multiple = size.strip_suffix("xlarge").or_else(|| {
                size.strip_prefix("metal-")
                    .and_then(|sized| sized.strip_suffix("xl"))
            })?;
            // A multiple above the ladder's ceiling is not a size at all, so it is answered
            // `None` the way any other unreadable size component is, rather than multiplied
            // out; `checked_mul` is what makes the bound structural rather than a comment.
            multiple
                .parse::<u32>()
                .ok()
                .filter(|multiple| *multiple <= MAX_SIZE_MULTIPLE)
                .and_then(|multiple| multiple.checked_mul(2 * SIZE_UNIT))
        }
    }
}

/// The size of `name`, in sixteenths of a `large`, with a plain `metal` resolved.
///
/// A bare metal instance is the WHOLE host its family's virtualized sizes are carved
/// out of, so its size is the largest of those sizes; a family with none at all (an EC2
/// Mac, whose vCPUs and memory come from [`MAC_HOSTS`] instead) falls back to one unit.
pub(super) fn instance_size_sixteenths_of(name: &InstanceTypeName<'_>) -> u32 {
    if let Some(sixteenths) = instance_size_sixteenths(name.size) {
        return sixteenths;
    }
    largest_virtualized_sixteenths(name.family).unwrap_or(SIZE_UNIT)
}

/// The size of the largest size of `family` that is not bare metal, in sixteenths.
pub(super) fn largest_virtualized_sixteenths(family: &str) -> Option<u32> {
    largest_virtualized_sizes().get(family).copied()
}

/// The largest virtualized size of every family of the catalog, in sixteenths, computed
/// ONCE.
///
/// The catalog is a constant, so this is too: without it, every bare metal type would
/// re-scan and re-parse all of [`offered_instance_types`], making a describe of the whole
/// catalog cost bare metal types x catalog instead of one pass.
pub(super) fn largest_virtualized_sizes() -> &'static HashMap<&'static str, u32> {
    static SIZES: OnceLock<HashMap<&'static str, u32>> = OnceLock::new();
    SIZES.get_or_init(|| {
        let mut sizes: HashMap<&'static str, u32> = HashMap::new();
        for instance_type in offered_instance_types().iter().copied() {
            let Some(parsed) = InstanceTypeName::parse(instance_type) else {
                continue;
            };
            let Some(sixteenths) = instance_size_sixteenths(parsed.size) else {
                continue;
            };
            let largest = sizes.entry(parsed.family).or_default();
            *largest = (*largest).max(sixteenths);
        }
        sizes
    })
}

/// The memory, in MiB per `large` unit of size, of the families whose published
/// memory-to-vCPU ratio differs from their family letter's — the Haswell and Broadwell
/// era storage and accelerated families at 7.625 GiB per vCPU (so 15.25 GiB per unit),
/// the X1 and X1e pair at 15.25 and 30.5, and the storage families a later generation
/// moved off their letter's ratio. Each figure is the one that family's page in the EC2
/// User Guide's "Instance types" chapter publishes.
pub(super) const MEMORY_MIB_PER_SIZE_UNIT: [(&str, i64); 9] = [
    ("d2", 15_616),
    ("d3en", 8_192),
    ("f1", 31_232),
    ("i2", 15_616),
    ("i3", 15_616),
    ("p2", 31_232),
    ("p3", 15_616),
    ("x1", 31_232),
    ("x1e", 62_464),
];

/// The memory, in MiB per `large` unit of size, of the family `name` belongs to.
///
/// This is that family's published memory-to-vCPU ratio, with two vCPUs to a `large`
/// unit: 4 GiB per vCPU for the general purpose families, 2 for the compute optimized
/// ones, 8 for the memory optimized ones, and the ratio each storage and accelerated
/// family publishes on its own page of the EC2 User Guide's "Instance types" chapter.
/// It is applied to the size ladder, which is what makes `m5.large` 8 GiB and
/// `m5.24xlarge` 384 GiB from one number.
///
/// A family whose published ratio is not its family letter's — including the ones that
/// are not a whole number of GiB per unit — has its own entry in
/// [`MEMORY_MIB_PER_SIZE_UNIT`], so `i3.large` is described with the published 15.25 GiB
/// rather than its letter's 16.
pub(super) fn memory_mib_per_size_unit(name: &InstanceTypeName<'_>) -> i64 {
    if let Some((_, mib_per_unit)) = MEMORY_MIB_PER_SIZE_UNIT
        .iter()
        .find(|(family, _)| *family == name.family)
    {
        return *mib_per_unit;
    }
    let gib_per_unit = match name.root {
        "a" => 4,
        "c" | HPC_ROOT => 4,
        "vt" => 4,
        "g" | "inf" | "trn" | "cc" | "cg" => 8,
        "im" => 8,
        "h" | "hi" | "hs" => 8,
        "is" => 12,
        "d" | "dl" | "f" | "gr" | "i" | "r" | "z" | "cr" => 16,
        "p" => 24,
        "x" => 32,
        // The general purpose and burstable families, and anything a later model adds.
        _ => 8,
    };
    gib_per_unit * 1024
}

/// The memory a High Memory family's name states, in GiB.
///
/// The `u-*` and `u7*` families are the ones whose name carries their memory size
/// rather than deriving it from the size ladder — `u-6tb1` is a 6 TiB instance and
/// `u7i-12tb` a 12 TiB one — and every size of one such family has the same memory.
pub(super) fn stated_memory_gib(family: &str) -> Option<i64> {
    let token = family.split('-').nth(1)?;
    let digits = token.find(|c: char| !c.is_ascii_digit())?;
    if !token[digits..].starts_with("tb") {
        return None;
    }
    token[..digits]
        .parse::<i64>()
        .ok()
        // A figure above the ceiling is not a High Memory size at all, so it is answered
        // `None` the way any other unreadable token is, rather than multiplied out;
        // `checked_mul` is what makes the bound structural rather than a comment, the same
        // pair `instance_size_sixteenths` holds the size component to.
        .filter(|tib| *tib <= MAX_STATED_MEMORY_TIB)
        .and_then(|tib| tib.checked_mul(1024))
}

/// The vCPUs and memory of the EC2 Mac host `family` names, if it is one.
pub(super) fn mac_host(family: &str) -> Option<(i32, i64)> {
    MAC_HOSTS
        .iter()
        .find(|(host, _, _)| *host == family)
        .map(|(_, vcpus, memory_gib)| (*vcpus, *memory_gib))
}

/// The default vCPUs of one size of one family.
pub(super) fn default_vcpus(name: &InstanceTypeName<'_>, sixteenths: u32) -> i32 {
    // The burstable sizes below `xlarge` do not follow the ladder: the T3 and later
    // families are offered with two vCPUs from `nano` up to `large`, and the T1 and T2
    // sizes below `medium` with one (the vCPU counts published in "Burstable
    // performance instances").
    if name.burstable() && sixteenths < 2 * SIZE_UNIT {
        let smallest = sixteenths <= SIZE_UNIT / 4;
        let single = smallest && name.generation.is_some_and(|generation| generation < 3);
        return if single { 1 } else { 2 };
    }
    // `sixteenths` is bounded by `MAX_SIZE_MULTIPLE`, so this product cannot overflow; the
    // saturating form is what keeps that true if the ceiling ever moves.
    let mut vcpus = (sixteenths.saturating_mul(VCPUS_PER_SIZE_UNIT) / SIZE_UNIT).max(1);
    // An HPC family ships with simultaneous multithreading DISABLED, so where the
    // hardware has a second thread per core the ladder's threads arrive as half as many
    // vCPUs: `hpc6a.48xlarge` has 96 vCPUs, not 192. A Graviton HPC family has no second
    // thread to disable, so its ladder count is already its vCPU count.
    if name.root == HPC_ROOT && !name.graviton() {
        vcpus = (vcpus / 2).max(1);
    }
    i32::try_from(vcpus).unwrap_or(i32::MAX)
}

/// The threads per core one instance type runs.
///
/// AWS Graviton and Apple silicon processors have one thread per core, and the HPC
/// families ship with simultaneous multithreading disabled ("Hpc instances ... have
/// hyper-threading disabled"); every Intel and AMD family runs two — including the Intel
/// `mac1`, which is why the single-thread rule is the ARM one rather than every Mac. A
/// type with a single vCPU has a single thread on a single core whatever the processor.
pub(super) fn default_threads_per_core(
    name: &InstanceTypeName<'_>,
    architecture: &str,
    default_vcpus: i32,
) -> i32 {
    let single =
        default_vcpus < 2 || architecture.starts_with("arm64") || name.root == HPC_ROOT;
    if single { 1 } else { 2 }
}

/// The memory of one size of one family, in MiB.
pub(super) fn memory_mib_of(name: &InstanceTypeName<'_>, sixteenths: u32) -> i64 {
    if let Some(gib) = stated_memory_gib(name.family) {
        // Bounded by `MAX_STATED_MEMORY_TIB`, so this product cannot overflow; the
        // saturating form is what keeps that true if the ceiling ever moves, like the arm
        // below.
        return gib.saturating_mul(1024);
    }
    // Bounded by `MAX_SIZE_MULTIPLE` like the vCPU count above, and saturating for the same
    // reason.
    memory_mib_per_size_unit(name).saturating_mul(i64::from(sixteenths)) / i64::from(SIZE_UNIT)
}

/// Does this instance type come with local instance storage?
///
/// The `d` capability letter means "instance store volumes" (the naming conventions),
/// the storage optimized families carry devices at every size, and
/// [`LOCAL_STORAGE_FAMILIES`] are the ones outside both that still ship them.
pub(super) fn has_instance_storage(name: &InstanceTypeName<'_>) -> bool {
    name.has_attribute('d')
        || LOCAL_STORAGE_ROOTS.contains(&name.root)
        || LOCAL_STORAGE_FAMILIES.contains(&name.family)
        || name.root == "trn"
        || (name.root == "p" && name.generation.is_some_and(|generation| generation >= 5))
}

/// The GB of local instance storage one `large` unit of size carries, in QUARTERS of a GB,
/// for the family `name` belongs to — the published instance store size of that family's
/// `large` size ("Instance store volumes"), applied to the size ladder the same way the
/// memory ratio is.
///
/// The unit is a quarter of a GB because the ratio of the `d` families from
/// [`FIRST_LARGE_NVME_STORAGE_GENERATION`] on is not a whole number of GB: their local
/// device is 118.75 GB per `large` unit (59.375 GB per vCPU), which is what makes that
/// family's published ladder 59, 118, 237, 950 and 1,900 GB.
pub(super) fn instance_storage_gb_quarters_per_size_unit(name: &InstanceTypeName<'_>) -> u64 {
    // The `d` capability letter on a family that is not storage optimized: from the sixth
    // generation on, those families carry one local NVMe device per two vCPUs of 118.75 GB,
    // where the fifth-generation `d` families carry 75 GB.
    if name.has_attribute('d')
        && !LOCAL_STORAGE_ROOTS.contains(&name.root)
        && name
            .generation
            .is_some_and(|generation| generation >= FIRST_LARGE_NVME_STORAGE_GENERATION)
    {
        return LARGE_NVME_STORAGE_GB_QUARTERS_PER_SIZE_UNIT;
    }
    4 * match name.root {
        "c" => 50,
        "x" => 118,
        "g" | "gr" => 125,
        "vt" => 100,
        "f" | "p" | "trn" => 250,
        "h" | "dl" => 500,
        "hi" | "hs" => 1_000,
        "d" => 3_000,
        "i" => 475,
        "im" => 937,
        "is" => 1_250,
        // The general purpose, memory optimized and high frequency `d` sizes.
        _ => 75,
    }
}

/// The first generation whose `d` families carry the larger local NVMe device: the sixth,
/// where `m5d.large`'s 75 GB device becomes `m6gd.large`'s 118 GB one ("Instance store
/// volumes").
pub(super) const FIRST_LARGE_NVME_STORAGE_GENERATION: u32 = 6;

/// That device's size per `large` unit of size, in quarters of a GB: 118.75 GB.
pub(super) const LARGE_NVME_STORAGE_GB_QUARTERS_PER_SIZE_UNIT: u64 = 475;

/// Is this instance type's instance store NVMe?
///
/// NVMe instance stores arrive with the Nitro System and, before it, with the
/// [`FIRST_NVME_STORAGE_GENERATION`] storage optimized family; the older families
/// present SATA SSDs or magnetic disks.
pub(super) fn nvme_instance_storage(name: &InstanceTypeName<'_>) -> bool {
    name.nitro()
        || (name.root == "i"
            && name
                .generation
                .is_some_and(|generation| generation >= FIRST_NVME_STORAGE_GENERATION))
}

/// Can this instance type hibernate?
///
/// The hibernation prerequisites name the supported families — the C, M and R families
/// from their third generation on and the T families from their second — and bound the
/// instance's RAM at [`MAX_HIBERNATION_MEMORY_MIB`]. Hibernation saves the instance's
/// memory to its EBS root volume, which a bare metal instance has no hypervisor to do, so
/// a bare metal size of a supported family cannot hibernate.
///
/// Local instance storage does NOT disqualify a type: the prerequisites list the `d`
/// variants of those same families beside the plain ones, so hibernation is a fact of the
/// family, the generation, the size and the RAM alone. What the instance store does lose is
/// its DATA, which is a property of the hibernated instance rather than of the type.
pub(super) fn hibernation_supported(name: &InstanceTypeName<'_>, memory_mib: i64) -> bool {
    let first = if name.burstable() {
        FIRST_HIBERNATION_BURSTABLE_GENERATION
    } else {
        FIRST_HIBERNATION_GENERATION
    };
    matches!(name.root, "c" | "m" | "r" | "t")
        && name.generation.is_some_and(|generation| generation >= first)
        && !name.bare_metal()
        && memory_mib < MAX_HIBERNATION_MEMORY_MIB
}

/// The maximum network interfaces, and private IPv4 addresses per interface, of one
/// size.
///
/// Both grow with the size of the instance, which is the shape of the published "IP
/// addresses per network interface per instance type" table, read here one row per step
/// of the size ladder: 2 interfaces of 2 addresses at `nano` and `micro`, 3 of 4 at
/// `small`, 3 of 6 at `medium`, 3 of 10 at `large`, 4 of 15 through the
/// `xlarge`–`3xlarge` sizes, 8 of 30 through the `4xlarge`–`12xlarge` sizes and 15 of
/// 50 from the `16xlarge` up. The bounds are in the sixteenths
/// [`instance_size_sixteenths`] counts in, so `large` is 16 and each arm covers the
/// ladder steps up to the next row's size.
pub(super) fn network_limits(sixteenths: u32) -> (i32, i32) {
    match sixteenths {
        ..=2 => (2, 2),
        3..=4 => (3, 4),
        5..=8 => (3, 6),
        9..=31 => (3, 10),
        32..=127 => (4, 15),
        128..=511 => (8, 30),
        _ => (15, 50),
    }
}

/// The Elastic Fabric Adapters one instance type may carry.
///
/// EFA is offered on the HPC families and on the largest sizes of the network optimized
/// (`n`) and accelerated families (EC2 User Guide, "Elastic Fabric Adapter"), each of
/// which carries one on its default network card. A type that is not offered one
/// reports no EFA at all.
pub(super) fn efa_interfaces(name: &InstanceTypeName<'_>, sixteenths: u32) -> i32 {
    let accelerated = matches!(name.root, "p" | "trn" | "dl" | "inf");
    let offered = name.root == HPC_ROOT
        || ((name.has_attribute('n') || accelerated) && sixteenths >= EFA_MINIMUM_SIXTEENTHS);
    i32::from(offered)
}

/// The local instance storage of one instance type, as the describe reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceStorageFacts {
    /// The total size of every local device, in GB.
    pub total_size_gb: i64,
    /// How many local devices the instance has.
    pub disk_count: i32,
    /// The size of each one, in GB.
    pub disk_size_gb: i64,
    /// `ssd` or `hdd`.
    pub disk_type: &'static str,
    /// Is the store presented as NVMe devices?
    pub nvme: bool,
}

impl InstanceStorageFacts {
    /// This instance store as the modelled `InstanceStorageInfo` shape.
    ///
    /// "Instance store volumes on Nitro-based instances are encrypted" with a key the
    /// host holds and the caller never sees, so encryption is `required` exactly where
    /// the devices are NVMe, and not offered at all on the older SATA and magnetic
    /// stores.
    pub fn to_instance_storage_info(&self) -> InstanceStorageInfo {
        let support = if self.nvme { "required" } else { "unsupported" };
        InstanceStorageInfo {
            total_size_in_gb: Some(self.total_size_gb),
            disks: Some(vec![DiskInfo {
                size_in_gb: Some(self.disk_size_gb),
                count: Some(self.disk_count),
                r#type: Some(self.disk_type.to_string()),
            }]),
            nvme_support: Some(support.to_string()),
            encryption_support: Some(support.to_string()),
        }
    }
}

/// The local instance storage of one size of one family, or `None` when the type has
/// none.
pub(super) fn instance_storage_facts(
    name: &InstanceTypeName<'_>,
    sixteenths: u32,
) -> Option<InstanceStorageFacts> {
    if !has_instance_storage(name) {
        return None;
    }
    let total_gb = (instance_storage_gb_quarters_per_size_unit(name) * u64::from(sixteenths)
        / (4 * u64::from(SIZE_UNIT)))
    .max(1);
    // AWS presents an instance store as equal-sized devices, each at most
    // [`MAX_INSTANCE_STORE_DISK_GB`], so a bigger store is more devices rather than a
    // bigger one — and the total is the sum of the devices the instance actually has.
    let disk_count = total_gb.div_ceil(MAX_INSTANCE_STORE_DISK_GB).max(1);
    let disk_size_gb = total_gb / disk_count;
    Some(InstanceStorageFacts {
        total_size_gb: i64::try_from(disk_size_gb * disk_count).unwrap_or(i64::MAX),
        disk_count: i32::try_from(disk_count).unwrap_or(i32::MAX),
        disk_size_gb: i64::try_from(disk_size_gb).unwrap_or(i64::MAX),
        disk_type: if HDD_STORAGE_FAMILIES.contains(&name.family) {
            "hdd"
        } else {
            "ssd"
        },
        nvme: nvme_instance_storage(name),
    })
}

/// The facts about one instance type a caller sees or is held to: what a guest sees of
/// its own CPU and memory, and what the service checks a request against.
///
/// Every field is derived from the type's name by [`instance_type_record`], so an
/// instance type is described the same way wherever it is reached. Today the one reader
/// is [`instance_type_info`], which projects it into the modelled `InstanceTypeInfo`;
/// the split is what keeps the derived FACTS usable by an operation that has to validate
/// a request against a type (CPU options, hibernation support, how many private
/// addresses an interface may take) rather than report it, without that operation
/// building a whole response shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceTypeRecord {
    /// `m5.xlarge` — a value of the modelled `InstanceType` enum.
    pub instance_type: String,
    /// The vCPUs the instance type runs with when the request asks for no CPU options.
    pub default_vcpus: i32,
    /// Those vCPUs' cores: `default_vcpus / default_threads_per_core`.
    pub default_cores: i32,
    /// The threads each core runs.
    pub default_threads_per_core: i32,
    /// The instance type's memory, in MiB.
    pub memory_mib: i64,
    /// Is this a bare metal instance type?
    pub bare_metal: bool,
    /// Is this a burstable performance T instance type?
    pub burstable: bool,
    /// Is this the latest generation of its family?
    pub current_generation: bool,
    /// Does it run on the AWS Nitro System?
    pub nitro: bool,
    /// The processor architecture, one value of the modelled `ArchitectureValues`.
    pub architecture: String,
    /// Its local instance storage, if it has any.
    pub instance_storage: Option<InstanceStorageFacts>,
    /// Is On-Demand hibernation supported?
    pub hibernation_supported: bool,
    /// The most network interfaces it can have attached.
    pub maximum_network_interfaces: i32,
    /// The most private IPv4 addresses each of those interfaces can have.
    pub ipv4_addresses_per_interface: i32,
}

impl InstanceTypeRecord {
    /// The core counts a caller may ask this instance type for: "the number of cores
    /// that can be configured for the instance type"
    /// (`VCpuInfo$ValidCores`) — one core up to the type's own default.
    pub fn valid_cores(&self) -> Vec<i32> {
        (1..=self.default_cores).collect()
    }

    /// The threads-per-core counts a caller may ask for: one thread per core disables
    /// simultaneous multithreading, which is possible exactly where the type runs more
    /// than one thread per core to begin with.
    pub fn valid_threads_per_core(&self) -> Vec<i32> {
        (1..=self.default_threads_per_core).collect()
    }
}

/// The micro-dollars one vCPU of an instance costs for one hour at the On-Demand rate.
///
/// CHOSEN, with [`MICROS_PER_GIB_HOUR`] and [`WINDOWS_LICENCE_MICROS_PER_VCPU_HOUR`]: AWS's
/// price list is published outside the model, and neither the model nor a request carries
/// it. What a caller can rely on is the RULE — an hour is priced on the instance type's own
/// published vCPUs and memory and on the platform's licence premium, so a larger size of one
/// family costs more than a smaller one and a Windows price is above the Linux price of the
/// same type — not these rates.
pub const MICROS_PER_VCPU_HOUR: u64 = 21_000;

/// The micro-dollars one GiB of an instance's memory costs for one hour at the On-Demand
/// rate. CHOSEN, see [`MICROS_PER_VCPU_HOUR`].
pub const MICROS_PER_GIB_HOUR: u64 = 5_000;

/// The micro-dollars per vCPU-hour a Windows platform adds to the On-Demand rate: the licence
/// premium AWS charges on top of the compute. CHOSEN, see [`MICROS_PER_VCPU_HOUR`].
pub const WINDOWS_LICENCE_MICROS_PER_VCPU_HOUR: u64 = 46_000;

/// The micro-dollars in one dollar, for reading a priced hour as the currency amount a
/// response carries.
pub const MICROS_PER_DOLLAR: u64 = 1_000_000;

/// The MiB in one GiB, for reading an instance type's memory (which the catalog publishes in
/// MiB) at the per-GiB rate.
const MIB_PER_GIB: u64 = 1_024;

/// What one hour of `record`'s instance type costs at the On-Demand rate, in micro-dollars:
/// its vCPUs and its memory at the rates above, plus the licence premium per vCPU when
/// `windows_licence` says the platform priced carries one.
///
/// The ONE On-Demand hour of this service, beside the instance-type facts it is derived from,
/// so every operation that prices an instance hour prices it from the same basis: a Spot price
/// is a share of this rate (`DescribeSpotPriceHistory`), and a Reserved Instance offering's
/// purchase and usage prices are this rate discounted for the term and split by the payment
/// option (`DescribeReservedInstancesOfferings`). Which platform strings carry a licence is
/// the operation's own reading of its own member, so it is passed in rather than parsed here.
pub fn on_demand_hour_micros(record: &InstanceTypeRecord, windows_licence: bool) -> u64 {
    let vcpus = u64::from(record.default_vcpus.unsigned_abs());
    let memory_mib = record.memory_mib.unsigned_abs();
    let compute = vcpus.saturating_mul(MICROS_PER_VCPU_HOUR);
    let memory = memory_mib.saturating_mul(MICROS_PER_GIB_HOUR) / MIB_PER_GIB;
    let licence = if windows_licence {
        vcpus.saturating_mul(WINDOWS_LICENCE_MICROS_PER_VCPU_HOUR)
    } else {
        0
    };
    compute.saturating_add(memory).saturating_add(licence)
}

/// Everything this emulator knows about the instance type `instance_type`, or `None`
/// when it is not one of the offered types ([`offered_instance_types`]).
pub fn instance_type_record(instance_type: &str) -> Option<InstanceTypeRecord> {
    if !instance_type_is_modelled(instance_type) {
        return None;
    }
    let name = InstanceTypeName::parse(instance_type)?;
    let sixteenths = instance_size_sixteenths_of(&name);
    let architecture = architecture_for(instance_type);
    let (default_vcpus, memory_mib) = match mac_host(name.family) {
        Some((vcpus, memory_gib)) => (vcpus, memory_gib * 1024),
        None => (
            default_vcpus(&name, sixteenths),
            memory_mib_of(&name, sixteenths),
        ),
    };
    let default_threads_per_core = default_threads_per_core(&name, &architecture, default_vcpus);
    let instance_storage = instance_storage_facts(&name, sixteenths);
    let (maximum_network_interfaces, ipv4_addresses_per_interface) = network_limits(sixteenths);
    Some(InstanceTypeRecord {
        instance_type: instance_type.to_string(),
        default_vcpus,
        default_cores: default_vcpus / default_threads_per_core,
        default_threads_per_core,
        memory_mib,
        bare_metal: name.bare_metal(),
        burstable: name.burstable(),
        current_generation: name.current_generation(),
        nitro: name.nitro(),
        architecture,
        instance_storage,
        hibernation_supported: hibernation_supported(&name, memory_mib),
        maximum_network_interfaces,
        ipv4_addresses_per_interface,
    })
}

/// The architectures the instance type's AMIs may be built for: its own, plus `i386`
/// for the four previous generation sizes that run 32-bit AMIs.
pub(super) fn supported_architectures(instance_type: &str, architecture: &str) -> Vec<String> {
    let mut architectures = Vec::new();
    if I386_INSTANCE_TYPES.contains(&instance_type) {
        architectures.push("i386".to_string());
    }
    architectures.push(architecture.to_string());
    architectures
}

/// The manufacturer of the processor: AWS designs Graviton, Apple the silicon in every
/// Mac but the Intel `mac1`, and the `a` capability letter means AMD — the rest are
/// Intel.
pub(super) fn processor_manufacturer(name: &InstanceTypeName<'_>, architecture: &str) -> &'static str {
    match architecture {
        "arm64" => "AWS",
        "arm64_mac" => "Apple",
        "x86_64_mac" => "Intel",
        _ if name.has_attribute('a') => "AMD",
        _ => "Intel",
    }
}

/// The additional processor features: "if the request returns `amd-sev-snp`, AMD
/// SEV-SNP is supported" (`ProcessorInfo$SupportedFeatures`), which the AMD families
/// offer from [`FIRST_SEV_SNP_GENERATION`] on.
pub(super) fn processor_features(name: &InstanceTypeName<'_>) -> Vec<String> {
    let sev_snp = name.has_attribute('a')
        && name
            .generation
            .is_some_and(|generation| generation >= FIRST_SEV_SNP_GENERATION);
    if sev_snp {
        vec!["amd-sev-snp".to_string()]
    } else {
        Vec::new()
    }
}

/// The usage classes the instance type is offered in: "whether the instance type is
/// offered for spot, On-Demand, or Capacity Blocks"
/// (`InstanceTypeInfo$SupportedUsageClasses`).
///
/// An EC2 Mac runs only on a Dedicated Host, which is never a Spot allocation, so
/// On-Demand is the only class it is offered in; Capacity Blocks reserve the
/// accelerated P and Trn families.
pub(super) fn supported_usage_classes(name: &InstanceTypeName<'_>) -> Vec<String> {
    if name.root == MAC_INSTANCE_FAMILY_PREFIX {
        return vec!["on-demand".to_string()];
    }
    let mut classes = vec!["on-demand".to_string(), "spot".to_string()];
    if matches!(name.root, "p" | "trn") {
        classes.push("capacity-block".to_string());
    }
    classes
}

/// The root device types the instance type supports: every type boots from EBS, and the
/// previous generation families that came with instance store volumes can also boot
/// from one.
pub(super) fn supported_root_device_types(name: &InstanceTypeName<'_>) -> Vec<String> {
    let mut types = vec!["ebs".to_string()];
    if PARAVIRTUAL_ONLY_FAMILIES.contains(&name.family)
        || PARAVIRTUAL_AND_HVM_FAMILIES.contains(&name.family)
    {
        types.push("instance-store".to_string());
    }
    types
}

/// The virtualization types the instance type supports: HVM everywhere, paravirtual on
/// the previous generation families that predate it — four of which run paravirtual
/// AMIs only.
pub(super) fn supported_virtualization_types(name: &InstanceTypeName<'_>) -> Vec<String> {
    if PARAVIRTUAL_ONLY_FAMILIES.contains(&name.family) {
        return vec!["paravirtual".to_string()];
    }
    let mut types = vec!["hvm".to_string()];
    if PARAVIRTUAL_AND_HVM_FAMILIES.contains(&name.family) {
        types.push("paravirtual".to_string());
    }
    types
}

/// Whether the instance type is EBS-optimized: `default` where EBS optimization is
/// always on (every Nitro type, and the fourth generation families that shipped it
/// enabled), `supported` where it is an option of the launch, and `unsupported` on the
/// pre-Nitro burstable and oldest families, which have no EBS-optimized mode at all.
pub(super) fn ebs_optimized_support(name: &InstanceTypeName<'_>) -> &'static str {
    if name.nitro() {
        return "default";
    }
    if name.burstable() {
        return EBS_OPTIMIZED_UNSUPPORTED;
    }
    match name.generation {
        None => "default",
        Some(generation) if generation >= 4 => "default",
        Some(generation) if generation >= FIRST_EBS_ENCRYPTION_GENERATION => "supported",
        Some(_) => EBS_OPTIMIZED_UNSUPPORTED,
    }
}

/// The `EbsOptimizedSupport` of a type with no EBS-optimized mode at all — one value of
/// that enum, named here because it is also what says the type has no
/// `EbsInfo$EbsOptimizedInfo` to report.
pub(super) const EBS_OPTIMIZED_UNSUPPORTED: &str = "unsupported";

/// Whether Elastic Network Adapter is supported: `required` on the Nitro types, which
/// have no other network device, `supported` on the current generation types that
/// offered it beside their original one, and `unsupported` on the previous generation
/// families that predate it.
pub(super) fn ena_support(name: &InstanceTypeName<'_>) -> &'static str {
    if name.nitro() {
        return "required";
    }
    if name.current_generation() {
        return "supported";
    }
    "unsupported"
}

/// Whether an EBS volume attaches to this instance type as an NVMe device
/// (`EbsInfo$NvmeSupport`, one value of `EbsNvmeSupport`:
/// `smithy_query(query="shape",shape="EbsNvmeSupport")` gives `unsupported | supported |
/// required`).
///
/// The member reports what the type's DEVICE MODEL can do, which follows from the NVMe
/// devices it has:
///
/// * `required` on a Nitro type, whose only block device model is NVMe, so every volume
///   attaches as one and nothing can ask for anything else;
/// * `supported` on a type that is not Nitro but whose local instance store is already
///   presented as NVMe devices ([`InstanceStorageFacts::nvme`]): the host has the NVMe
///   model, so a volume MAY attach as an NVMe device beside the Xen block devices — which
///   is what a client choosing `nvme*` over `xvd*` guest device names reads;
/// * `unsupported` where the type has no NVMe device at all.
///
/// Derived from the same two facts the rest of this module derives — Nitro, and whether the
/// instance store is NVMe — rather than from a per-type list, so one rule answers every
/// type of the catalog.
pub(super) fn ebs_nvme_support(nitro: bool, nvme_instance_store: bool) -> &'static str {
    if nitro {
        return "required";
    }
    if nvme_instance_store {
        return "supported";
    }
    "unsupported"
}

/// The EBS-optimized performance of one size — "the baseline and maximum bandwidth
/// performance in Mbps, the throughput in MB/s and the input/output operations per second"
/// (`EbsOptimizedInfo`) — or `None` for a type with no EBS-optimized mode at all.
///
/// AWS publishes those six figures per instance type ("Amazon EBS-optimized instance
/// types"), and the type's NAME does not carry them, so they are derived from its SIZE the
/// way that table is shaped:
///
/// * a figure grows with the size of the instance, which is the instance's share of its
///   host, counted here per `xlarge` ([`EBS_BASELINE_MBPS_PER_XLARGE`] /
///   [`EBS_BASELINE_IOPS_PER_XLARGE`]);
/// * every size can reach at least the full-size row's figure
///   ([`EBS_BURST_FLOOR_MBPS`] / [`EBS_BURST_FLOOR_IOPS`]), and above that size the
///   ceiling grows at its own, shallower rate ([`EBS_BURST_MBPS_PER_XLARGE`] /
///   [`EBS_BURST_IOPS_PER_XLARGE`]);
/// * the sustained figure never exceeds that ceiling;
/// * throughput is the same quantity as bandwidth in the other unit — a megabyte is
///   [`EBS_MEGABITS_PER_MEGABYTE`] megabits — which is exactly how the published table's
///   Mbps and MB/s columns relate.
///
/// `bursts` is what separates the two kinds of type the table holds: a Nitro instance's
/// dedicated bandwidth is a baseline it bursts above, while a pre-Nitro EBS-optimized
/// instance has one fixed figure, so for it the maximum IS the baseline.
pub(super) fn ebs_optimized_info(sixteenths: u32, bursts: bool) -> EbsOptimizedInfo {
    let scaled = |per_xlarge: i64| {
        per_xlarge.saturating_mul(i64::from(sixteenths)) / i64::from(XLARGE_SIXTEENTHS)
    };
    let narrow = |value: i64| i32::try_from(value).unwrap_or(i32::MAX);
    let bandwidth_ceiling = scaled(EBS_BURST_MBPS_PER_XLARGE).max(EBS_BURST_FLOOR_MBPS);
    let iops_ceiling = scaled(EBS_BURST_IOPS_PER_XLARGE).max(EBS_BURST_FLOOR_IOPS);
    let bandwidth = scaled(EBS_BASELINE_MBPS_PER_XLARGE).min(bandwidth_ceiling);
    let iops = scaled(EBS_BASELINE_IOPS_PER_XLARGE).min(iops_ceiling);
    let (maximum_bandwidth, maximum_iops) = if bursts {
        (bandwidth_ceiling, iops_ceiling)
    } else {
        (bandwidth, iops)
    };
    let megabytes = |mbps: i64| mbps as f64 / EBS_MEGABITS_PER_MEGABYTE;
    EbsOptimizedInfo {
        baseline_bandwidth_in_mbps: Some(narrow(bandwidth)),
        baseline_throughput_in_m_bps: Some(megabytes(bandwidth)),
        baseline_iops: Some(narrow(iops)),
        maximum_bandwidth_in_mbps: Some(narrow(maximum_bandwidth)),
        maximum_throughput_in_m_bps: Some(megabytes(maximum_bandwidth)),
        maximum_iops: Some(narrow(maximum_iops)),
    }
}

/// The placement group strategies the instance type supports.
///
/// "Cluster placement groups ... supported instance types: current generation instance
/// types" (EC2 User Guide, "Placement groups"), which the burstable families are not
/// among; partition and spread groups take any instance type. An EC2 Mac runs only on a
/// Dedicated Host, which cannot be in a placement group, so it supports none.
pub(super) fn placement_group_strategies(name: &InstanceTypeName<'_>) -> Vec<String> {
    if name.root == MAC_INSTANCE_FAMILY_PREFIX {
        return Vec::new();
    }
    let mut strategies = Vec::new();
    if name.current_generation() && !name.burstable() {
        strategies.push("cluster".to_string());
    }
    strategies.push("partition".to_string());
    strategies.push("spread".to_string());
    strategies
}

/// The boot modes the instance type supports: "Graviton instance types support UEFI
/// only", the Intel and AMD Nitro types support both, and the pre-Nitro types only the
/// legacy BIOS (EC2 User Guide, "Boot modes").
pub(super) fn supported_boot_modes(architecture: &str, nitro: bool) -> Vec<String> {
    if architecture.starts_with("arm64") {
        return vec!["uefi".to_string()];
    }
    if nitro {
        return vec!["legacy-bios".to_string(), "uefi".to_string()];
    }
    vec!["legacy-bios".to_string()]
}

/// The instance types AWS publishes MORE than one network card for, each with the number of
/// cards it carries: the EC2 User Guide's "Instance types with multiple network cards"
/// table. Every other instance type carries ONE card, which is what
/// [`network_card_count`] answers.
///
/// The count is a property of the whole instance rather than of its family's ladder — only
/// the size that has the whole host's cards carries more than one — so the entries name full
/// instance types, not families.
pub(super) const MULTI_NETWORK_CARD_TYPES: [(&str, i32); 14] = [
    ("c6in.32xlarge", 2),
    ("c6in.metal", 2),
    ("dl1.24xlarge", 4),
    ("m6idn.32xlarge", 2),
    ("m6in.32xlarge", 2),
    ("p4d.24xlarge", 4),
    ("p4de.24xlarge", 4),
    ("p5.48xlarge", 32),
    ("p5e.48xlarge", 32),
    ("p5en.48xlarge", 16),
    ("r6idn.32xlarge", 2),
    ("r6in.32xlarge", 2),
    ("trn1.32xlarge", 8),
    ("trn1n.32xlarge", 16),
];

/// How many physical network cards `instance_type` has — "the maximum number of physical
/// network cards that can be allocated to the instance"
/// (`NetworkInfo$MaximumNetworkCards`).
///
/// Every instance has at least one network card, its interfaces being attached to one; the
/// types AWS publishes several for are [`MULTI_NETWORK_CARD_TYPES`].
pub(super) fn network_card_count(instance_type: &str) -> i32 {
    MULTI_NETWORK_CARD_TYPES
        .iter()
        .find(|(named, _)| *named == instance_type)
        .map_or(1, |(_, cards)| *cards)
}

/// The index of the card an instance's interfaces are attached to unless the request names
/// another: "the index of the default network card, starting at 0"
/// (`NetworkInfo$DefaultNetworkCardIndex`). The first card is the default on every type.
pub(super) const DEFAULT_NETWORK_CARD_INDEX: i32 = 0;

/// The network bandwidth, in Gbps, of the whole host a general purpose, compute optimized or
/// memory optimized family's largest virtualized size has — the figure the "Network
/// performance" column of that size's row publishes in the EC2 User Guide's "Instance types"
/// chapter.
pub(super) const HOST_NETWORK_GBPS: i64 = 25;

/// The host bandwidth of a family built for the network: the `n` capability letter is
/// "network and EBS optimized" (the naming conventions), and the accelerated families carry
/// the same class of adapter for their collective traffic.
pub(super) const NETWORK_OPTIMIZED_HOST_GBPS: i64 = 100;

/// The bandwidth, in Gbps, a size below its host's full share can BURST to: the ceiling the
/// published table reports those sizes as "Up to" — never above the host's own figure.
pub(super) const BURST_NETWORK_GBPS: i64 = 10;

/// The hundredths in one Gbps, the unit the bandwidth derivation counts in so that a share
/// like 12.5 Gbps is exact without floating point.
const CENTI_GBPS: i64 = 100;

/// The host network bandwidth, in Gbps, of the family `name` belongs to.
pub(super) fn host_network_gbps(name: &InstanceTypeName<'_>) -> i64 {
    let accelerated = matches!(name.root, "p" | "trn" | "dl" | "inf") || name.root == HPC_ROOT;
    if name.has_attribute('n') || accelerated {
        return NETWORK_OPTIMIZED_HOST_GBPS;
    }
    HOST_NETWORK_GBPS
}

/// The baseline and peak network bandwidth of one size, in hundredths of a Gbps.
///
/// A size's baseline is its SHARE of its host's bandwidth — the instance's share of the host
/// is what every other per-size figure of this module is derived from — and a size whose
/// share is below the burst ceiling ([`BURST_NETWORK_GBPS`]) can reach that ceiling instead,
/// which is the "Up to" the published table reports those rows as. The largest virtualized
/// size has the whole host, so its baseline IS its peak.
pub(super) fn network_bandwidth_centi_gbps(
    name: &InstanceTypeName<'_>,
    sixteenths: u32,
) -> (i64, i64) {
    let host = host_network_gbps(name).saturating_mul(CENTI_GBPS);
    let largest = largest_virtualized_sixteenths(name.family)
        .unwrap_or(sixteenths)
        .max(1);
    let baseline = (host.saturating_mul(i64::from(sixteenths)) / i64::from(largest))
        .clamp(1, host);
    let burst = BURST_NETWORK_GBPS.saturating_mul(CENTI_GBPS).min(host);
    (baseline, baseline.max(burst))
}

/// `centi` hundredths of a Gbps as the published tables write the figure: a whole number of
/// Gigabit without a fraction, and a fraction to the digits it needs (`12.5`).
pub(super) fn gigabit_figure(centi: i64) -> String {
    let whole = centi / CENTI_GBPS;
    match centi % CENTI_GBPS {
        0 => whole.to_string(),
        tenths if tenths % 10 == 0 => format!("{whole}.{}", tenths / 10),
        hundredths => format!("{whole}.{hundredths:02}"),
    }
}

/// "The network performance" (`NetworkInfo$NetworkPerformance`) of one size, in the form the
/// published table writes it: the size's own figure in Gigabit, or `Up to` its burst ceiling
/// where the size bursts above its baseline share.
pub(super) fn network_performance(baseline_centi: i64, peak_centi: i64) -> String {
    if peak_centi > baseline_centi {
        return format!("Up to {} Gigabit", gigabit_figure(peak_centi));
    }
    format!("{} Gigabit", gigabit_figure(baseline_centi))
}

/// The network cards of one instance type, as `NetworkInfo$NetworkCards` reports them.
///
/// The cards of one instance are identical, so each gets an equal share of the host's
/// bandwidth and of the interfaces the type can attach, and the figures a card reports are
/// the ones the type itself reports divided by the number of cards. `interface_types` names
/// what may be attached to a card: an ordinary network interface, plus the Elastic Fabric
/// Adapter on a type that is offered one.
pub(super) fn network_cards(
    name: &InstanceTypeName<'_>,
    sixteenths: u32,
    cards: i32,
    maximum_network_interfaces: i32,
    efa_interfaces: i32,
) -> Vec<NetworkCardInfo> {
    let (baseline, peak) = network_bandwidth_centi_gbps(name, sixteenths);
    let count = i64::from(cards.max(1));
    let per_card_baseline = (baseline / count).max(1);
    let per_card_peak = (peak / count).max(per_card_baseline);
    let interfaces_per_card = (maximum_network_interfaces / cards.max(1)).max(1);
    let mut interface_types = vec!["interface".to_string()];
    if efa_interfaces > 0 {
        interface_types.push("efa".to_string());
    }
    (0..cards.max(1))
        .map(|index| NetworkCardInfo {
            network_card_index: Some(index),
            network_performance: Some(network_performance(per_card_baseline, per_card_peak)),
            maximum_network_interfaces: Some(interfaces_per_card),
            additional_flexible_network_interfaces: None,
            baseline_bandwidth_in_gbps: Some(per_card_baseline as f64 / CENTI_GBPS as f64),
            peak_bandwidth_in_gbps: Some(per_card_peak as f64 / CENTI_GBPS as f64),
            default_ena_queue_count_per_interface: None,
            maximum_ena_queue_count: None,
            maximum_ena_queue_count_per_interface: None,
            interface_types: Some(interface_types.clone()),
        })
        .collect()
}

/// The generation of the Nitro System's own features that arrives with the seventh
/// generation of a family: the local Precision Time Protocol hardware clock
/// (`InstanceTypeInfo$PhcSupport`), a configurable number of ENA queues
/// (`NetworkInfo$FlexibleEnaQueuesSupport`) and interface attachments from a secondary
/// network (`NetworkInfo$SecondaryNetworkSupported`) are features of that hardware
/// generation, so the families whose ladder has not reached it do not have them.
pub(super) const FIRST_NITRO_CLOCK_GENERATION: u32 = 7;

/// The generation from which ENA Express — "Amazon Web Services Scalable Reliable Datagram
/// (SRD) technology" (`NetworkInfo$EnaSrdSupported`) — is offered: the sixth generation,
/// the one whose adapter carries it.
pub(super) const FIRST_ENA_SRD_GENERATION: u32 = 6;

/// Whether a Nitro feature that arrives with generation `first` reaches `name`.
///
/// A bare metal size has no Nitro hypervisor between the caller and the hardware, so the
/// features the hypervisor provides are not offered on it; a family carrying no generation
/// at all is answered `false`, the way every other generation-gated fact of this module
/// answers it.
pub(super) fn has_nitro_feature(name: &InstanceTypeName<'_>, first: u32) -> bool {
    name.nitro()
        && !name.bare_metal()
        && name
            .generation
            .is_some_and(|generation| generation >= first)
}

/// The sustained clock speed of the processor, in GHz — "the speed of the processor, in GHz"
/// (`ProcessorInfo$SustainedClockSpeedInGhz`).
///
/// The processor follows from the family's manufacturer and generation
/// ([`processor_manufacturer`]), and each processor's sustained (all-core turbo) frequency is
/// the one the EC2 User Guide's "Instance types" chapter publishes for the families built on
/// it: AWS Graviton at 2.5, 2.6 and 2.8 GHz for its second, third and fourth designs, the
/// Intel Xeon generations at 2.4, 3.1, 3.5 and 3.2 GHz, and the AMD EPYC ones at 2.5, 3.6
/// and 3.7 GHz. An Apple silicon Mac publishes no such figure, so none is reported for it.
pub(super) fn sustained_clock_speed_ghz(
    manufacturer: &str,
    name: &InstanceTypeName<'_>,
) -> Option<f64> {
    let generation = name.generation.unwrap_or_default();
    let ghz = match manufacturer {
        "Apple" => return None,
        "AWS" => match generation {
            ..=5 => 2.3,
            6 => 2.5,
            7 => 2.6,
            _ => 2.8,
        },
        "AMD" => match generation {
            ..=5 => 2.5,
            6 => 3.6,
            _ => 3.7,
        },
        // Intel, including the Intel Mac host.
        _ => match generation {
            ..=4 => 2.4,
            5 => 3.1,
            6 => 3.5,
            _ => 3.2,
        },
    };
    Some(ghz)
}

/// The attachments a Nitro instance holds that are not EBS volumes and that it always has:
/// its primary network interface, which every instance is launched with.
///
/// "Instance store volumes and attached network interfaces count toward this limit" (EC2
/// User Guide, "Instance volume limits"), so the EBS volumes a Nitro type can hold are its
/// shared total ([`NITRO_ATTACHMENT_LIMIT`]) less the attachments it already has: that
/// interface, and the devices of its instance store.
pub(super) const NITRO_RESERVED_ATTACHMENTS: i32 = 1;

/// How many EBS volumes one instance type can hold attached —
/// `EbsInfo$MaximumEbsAttachments`.
///
/// A Nitro type shares ONE pool of attachments between its EBS volumes, its network
/// interfaces and its instance store devices, so the volumes it can take are that pool less
/// the attachments the instance already has ([`NITRO_RESERVED_ATTACHMENTS`] and its instance
/// store); a pre-Nitro type has a limit of its own for EBS volumes alone.
pub(super) fn maximum_ebs_attachments(nitro: bool, instance_store_disks: i32) -> i32 {
    if !nitro {
        return XEN_EBS_VOLUME_LIMIT;
    }
    (NITRO_ATTACHMENT_LIMIT - NITRO_RESERVED_ATTACHMENTS - instance_store_disks).max(1)
}

/// Everything `DescribeInstanceTypes` reports about `instance_type`, or `None` when it
/// is not one of the offered types ([`offered_instance_types`]).
///
/// An instance type is a FACT of the catalog, not a resource a caller creates: no EC2
/// operation adds a type or changes one, so this is derived from the type's name and the
/// published per-family ratios rather than stored, exactly the way
/// [`instance_type_offerings`] derives which location offers which type. Two calls
/// therefore report one instance type identically.
///
/// The members this leaves absent are the per-type figures AWS publishes as HARDWARE
/// data that neither the model nor the name yields — the GPU, FPGA, inference, media and
/// Neuron device inventories, and the configurable bandwidth weightings. An absent member
/// is reported absent rather than invented, and a filter naming one therefore selects
/// nothing.
pub fn instance_type_info(instance_type: &str) -> Option<InstanceTypeInfo> {
    let name = InstanceTypeName::parse(instance_type)?;
    let record = instance_type_record(instance_type)?;
    let sixteenths = instance_size_sixteenths_of(&name);
    let nitro = record.nitro;

    // Amazon EBS encryption, and IPv6, reach every current generation instance type and
    // the previous generation ones from the generation that introduced them on; the
    // oldest families predate both.
    let modern = record.current_generation
        || name
            .generation
            .is_some_and(|generation| generation >= FIRST_EBS_ENCRYPTION_GENERATION);
    let ipv6_supported = modern;
    let efa_interfaces = efa_interfaces(&name, sixteenths);
    let (tcp_established, udp, udp_stream) = CONNECTION_TRACKING_TIMEOUTS;
    // The network cards the instance has, and the bandwidth its size's share of the host
    // carries: every member the model publishes about the instance's network is derived from
    // those two facts, so the type's own figures and its per-card ones cannot disagree.
    let cards = network_card_count(instance_type);
    let (baseline_centi, peak_centi) = network_bandwidth_centi_gbps(&name, sixteenths);
    let instance_store_disks = record
        .instance_storage
        .map_or(0, |storage| storage.disk_count);
    // The features the Nitro hypervisor provides, each from the generation that introduced
    // it, reported as the enum member or flag its own member takes.
    let nitro_clock = has_nitro_feature(&name, FIRST_NITRO_CLOCK_GENERATION);
    let supported_or_not = |supported: bool| {
        if supported { "supported" } else { "unsupported" }.to_string()
    };

    Some(InstanceTypeInfo {
        instance_type: Some(record.instance_type.clone()),
        current_generation: Some(record.current_generation),
        free_tier_eligible: Some(FREE_TIER_INSTANCE_TYPES.contains(&instance_type)),
        supported_usage_classes: Some(supported_usage_classes(&name)),
        supported_root_device_types: Some(supported_root_device_types(&name)),
        supported_virtualization_types: Some(supported_virtualization_types(&name)),
        bare_metal: Some(record.bare_metal),
        // A bare metal instance runs the caller's own software on the host with no
        // hypervisor under it, so it reports none at all.
        hypervisor: (!record.bare_metal)
            .then(|| if nitro { "nitro" } else { "xen" }.to_string()),
        processor_info: Some(ProcessorInfo {
            supported_architectures: Some(supported_architectures(
                instance_type,
                &record.architecture,
            )),
            sustained_clock_speed_in_ghz: sustained_clock_speed_ghz(
                processor_manufacturer(&name, &record.architecture),
                &name,
            ),
            supported_features: Some(processor_features(&name)),
            manufacturer: Some(processor_manufacturer(&name, &record.architecture).to_string()),
        }),
        v_cpu_info: Some(VCpuInfo {
            default_v_cpus: Some(record.default_vcpus),
            default_cores: Some(record.default_cores),
            default_threads_per_core: Some(record.default_threads_per_core),
            valid_cores: Some(record.valid_cores()),
            valid_threads_per_core: Some(record.valid_threads_per_core()),
        }),
        memory_info: Some(MemoryInfo {
            size_in_mi_b: Some(record.memory_mib),
        }),
        instance_storage_supported: Some(record.instance_storage.is_some()),
        instance_storage_info: record
            .instance_storage
            .as_ref()
            .map(InstanceStorageFacts::to_instance_storage_info),
        ebs_info: Some(EbsInfo {
            ebs_optimized_support: Some(ebs_optimized_support(&name).to_string()),
            encryption_support: Some(
                if modern { "supported" } else { "unsupported" }.to_string(),
            ),
            // "Describes the optimized EBS performance for the instance type"
            // (`EbsInfo$EbsOptimizedInfo`): reported for every type that HAS an
            // EBS-optimized mode, and absent for one whose `EbsOptimizedSupport` is
            // `unsupported`, which has no such performance to describe.
            ebs_optimized_info: (ebs_optimized_support(&name) != EBS_OPTIMIZED_UNSUPPORTED)
                .then(|| ebs_optimized_info(sixteenths, nitro)),
            nvme_support: Some(
                ebs_nvme_support(
                    nitro,
                    record
                        .instance_storage
                        .is_some_and(|storage| storage.nvme),
                )
                .to_string(),
            ),
            maximum_ebs_attachments: Some(maximum_ebs_attachments(nitro, instance_store_disks)),
            // A Nitro instance's attachments are shared between its EBS volumes, its
            // network interfaces and its instance store devices; a Xen instance's EBS
            // volumes have a limit of their own.
            attachment_limit_type: Some(if nitro { "shared" } else { "dedicated" }.to_string()),
            maximum_ebs_cards: None,
            ebs_cards: None,
        }),
        network_info: Some(NetworkInfo {
            // "The network performance": the instance's share of its host's bandwidth, or
            // the ceiling a size below that share bursts to.
            network_performance: Some(network_performance(baseline_centi, peak_centi)),
            maximum_network_interfaces: Some(record.maximum_network_interfaces),
            // Every instance has at least one physical network card, its interfaces being
            // attached to one, and the first card is the default; the types AWS publishes
            // several for are named in [`MULTI_NETWORK_CARD_TYPES`].
            maximum_network_cards: Some(cards),
            default_network_card_index: Some(DEFAULT_NETWORK_CARD_INDEX),
            network_cards: Some(network_cards(
                &name,
                sixteenths,
                cards,
                record.maximum_network_interfaces,
                efa_interfaces,
            )),
            ipv4_addresses_per_interface: Some(record.ipv4_addresses_per_interface),
            ipv6_addresses_per_interface: ipv6_supported
                .then_some(record.ipv4_addresses_per_interface),
            ipv6_supported: Some(ipv6_supported),
            ena_support: Some(ena_support(&name).to_string()),
            efa_supported: Some(efa_interfaces > 0),
            efa_info: (efa_interfaces > 0).then_some(EfaInfo {
                maximum_efa_interfaces: Some(efa_interfaces),
            }),
            // "Indicates whether the instance type automatically encrypts in-transit
            // traffic between instances" (`NetworkInfo$EncryptionInTransitSupported`):
            // the one site of that fact is `InstanceTypeName::encrypts_in_transit`, so
            // this report and `GetVpcResourcesBlockingEncryptionEnforcement` — which asks
            // which instances of a VPC cannot encrypt — cannot answer differently for one
            // instance type.
            encryption_in_transit_supported: Some(name.encrypts_in_transit()),
            // "Indicates whether the instance type supports ENA Express"
            // (`$EnaSrdSupported`), the adapter feature the sixth generation introduced.
            ena_srd_supported: Some(has_nitro_feature(&name, FIRST_ENA_SRD_GENERATION)),
            bandwidth_weightings: None,
            // "Indicates whether changing the number of ENA queues is supported"
            // (`$FlexibleEnaQueuesSupport`), reported as the enum member it is for every
            // type rather than only for the types that have it.
            flexible_ena_queues_support: Some(supported_or_not(nitro_clock)),
            connection_tracking_configuration: nitro.then_some(
                DefaultConnectionTrackingConfiguration {
                    default_tcp_established_timeout: Some(tcp_established),
                    default_udp_timeout: Some(udp),
                    default_udp_stream_timeout: Some(udp_stream),
                },
            ),
            // "Indicates whether secondary interface attachments from secondary network
            // are supported" (`$SecondaryNetworkSupported`). A type that supports them
            // takes them on the same adapter as its primary interfaces, so the secondary
            // limits are the primary ones; a type that does not reports neither.
            secondary_network_supported: Some(nitro_clock),
            maximum_secondary_network_interfaces: nitro_clock
                .then_some(record.maximum_network_interfaces),
            ipv4_addresses_per_secondary_interface: nitro_clock
                .then_some(record.ipv4_addresses_per_interface),
        }),
        gpu_info: None,
        fpga_info: None,
        placement_group_info: Some(PlacementGroupInfo {
            supported_strategies: Some(placement_group_strategies(&name)),
        }),
        inference_accelerator_info: None,
        hibernation_supported: Some(record.hibernation_supported),
        burstable_performance_supported: Some(record.burstable),
        // "Dedicated Hosts are supported for ... current generation instance types",
        // and an EC2 Mac runs on nothing else; the burstable families are not offered
        // on a host.
        dedicated_hosts_supported: Some(record.current_generation && !record.burstable),
        // "Simplified automatic recovery" covers neither a bare metal instance nor one
        // with an instance store, whose local data a recovery cannot carry over.
        auto_recovery_supported: Some(
            !record.bare_metal && record.instance_storage.is_none(),
        ),
        supported_boot_modes: Some(supported_boot_modes(&record.architecture, nitro)),
        nitro_enclaves_support: Some(
            if nitro
                && !record.bare_metal
                && !record.burstable
                && record.default_vcpus >= MIN_ENCLAVE_VCPUS
            {
                "supported"
            } else {
                "unsupported"
            }
            .to_string(),
        ),
        // NitroTPM is a virtual device the Nitro hypervisor presents to the guest, so a
        // bare metal instance — which has no hypervisor under it, and reports none
        // ([`InstanceTypeInfo$Hypervisor`] above) — does not have one.
        nitro_tpm_support: Some(supported_or_not(nitro && !record.bare_metal)),
        nitro_tpm_info: (nitro && !record.bare_metal).then(|| NitroTpmInfo {
            supported_versions: Some(vec![NITRO_TPM_VERSION.to_string()]),
        }),
        media_accelerator_info: None,
        neuron_info: None,
        // "Indicates whether a local Precision Time Protocol (PTP) hardware clock (PHC) is
        // supported" (`$PhcSupport`): a clock of the Nitro hardware generation named by
        // [`FIRST_NITRO_CLOCK_GENERATION`].
        phc_support: Some(supported_or_not(nitro_clock)),
        // "Indicates whether reboot migration during a user-initiated reboot is supported"
        // (`$RebootMigrationSupport`): the migration moves a running instance to another
        // host, which is the hypervisor's to do, so every Nitro type but a bare metal one
        // supports it.
        reboot_migration_support: Some(supported_or_not(nitro && !record.bare_metal)),
        // Every type of the catalog is offered in every Region this emulator serves,
        // which is what [`instance_type_offerings`] reports too.
        supported_in_region: Some(true),
    })
}
