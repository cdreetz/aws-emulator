// SPDX-License-Identifier: CC0-1.0

//! The VPC, subnet and security-group stores: the resource-id mint, the writers every VPC,
//! subnet and group goes through, the ambient default network an account holds in a Region,
//! and the CIDR and security-group-rule helpers those writers share.
//!
//! Split out of the [`crate::state`] module root so each file holds one concern, and
//! re-exported from it, so a handler reaches these as `crate::state::<item>` like every
//! other primitive there.

use super::*;

impl ComAmazonawsEc2Amazonec2State {
    /// Mint the next id for `prefix`, e.g. `vpc-00000000000000001`.
    ///
    /// EC2 resource ids are `<prefix>-<hex>`, with 8 or 17 lowercase hex digits (the
    /// model's own id patterns read like `^vpc-([0-9a-f]{8}|[0-9a-f]{17})$`), so the
    /// suffix is 17 lowercase hex digits of the monotonic counter.
    pub fn next_id(&mut self, prefix: &str) -> String {
        // OnCallWorlds patch: an id the seed pinned for this setup call.
        if let Some(id) = ocw_clock::take_pinned(prefix.trim_end_matches('-')) {
            return id;
        }
        self.id_counter = self.id_counter.saturating_add(1);
        format!("{prefix}-{:017x}", self.id_counter)
    }

    /// Mint the next hosted zone id a DNS entry names, e.g. `Z0000000000001`.
    ///
    /// A hosted zone id is an opaque identifier beginning with `Z` (`DnsEntry$HostedZoneId`
    /// — "The ID of the private hosted zone"), so it takes that form over the store's own
    /// monotonic counter, the source [`Self::next_id`] draws on: unique within a run, the
    /// same across runs, and never read off a clock or a random source.
    pub fn mint_hosted_zone_id(&mut self) -> String {
        self.id_counter = self.id_counter.saturating_add(1);
        format!("Z{:013X}", self.id_counter)
    }

    /// Mint an Amazon-provided IPv6 CIDR block with the `/56` prefix length
    /// `CreateVpcRequest$AmazonProvidedIpv6CidrBlock` documents ("an Amazon-provided IPv6
    /// CIDR block with a /56 prefix length for the VPC"), out of the `2600:1f00::/24`
    /// space Amazon advertises them from.
    ///
    /// The address comes from the store's own id counter, never from the request — the
    /// caller "cannot specify the range of IP addresses, or the size of the CIDR block".
    pub fn mint_amazon_ipv6_cidr(&mut self) -> String {
        self.id_counter = self.id_counter.saturating_add(1);
        let counter = self.id_counter;
        let second = u16::try_from((counter >> 24) & 0xff).unwrap_or_default();
        let third = u16::try_from((counter >> 8) & 0xffff).unwrap_or_default();
        let fourth = u16::try_from((counter & 0xff) << 8).unwrap_or_default();
        let address = Ipv6Addr::new(0x2600, 0x1f00 | second, third, fourth, 0, 0, 0, 0);
        format!("{address}/56")
    }

    /// Whether another VPC fits inside the store's ceiling ([`MAX_VPCS`]).
    ///
    /// A create must ask this BEFORE inserting and refuse with [`vpc_limit_exceeded`]
    /// when it answers `false`, the way [`Self::would_exceed_stored_bytes`] gates the
    /// caller-chosen bytes: without a count ceiling repeated creates would grow memory
    /// without bound.
    pub fn has_vpc_capacity(&self) -> bool {
        self.vpcs.len() < MAX_VPCS
    }

    /// The Region the VPC `vpc_id` names was created in, or `None` when this store holds no
    /// such VPC.
    ///
    /// The ONE reading of "which Region is this VPC in" ([`Self::vpc_regions`]), so every
    /// operation that reports a VPC-shaped resource scopes it the same way.
    pub fn vpc_region(&self, vpc_id: &str) -> Option<&str> {
        self.vpc_regions.get(vpc_id).map(String::as_str)
    }

    /// Whether the resource that belongs to the VPC `vpc_id` names is in `region`.
    ///
    /// EC2 is a regional service reached through a regional endpoint, so a resource created
    /// in one Region is invisible to a request signed for another. A subnet, a security
    /// group, a network ACL and a route table each belong to ONE VPC, so this answers for
    /// all of them off the VPC's own Region — the resource and its VPC can never be
    /// reported in two Regions.
    ///
    /// `false` for a resource that names no VPC, or names one this store does not hold:
    /// there is no Region to place it in, so no Region's caller may see it.
    pub fn vpc_is_in_region(&self, vpc_id: Option<&str>, region: &str) -> bool {
        vpc_id.and_then(|vpc_id| self.vpc_region(vpc_id)) == Some(region)
    }

    /// Whether another subnet fits inside the store's ceiling ([`MAX_SUBNETS`]).
    ///
    /// The same contract as [`Self::has_vpc_capacity`]: a create asks first and refuses
    /// with EC2's `SubnetLimitExceeded` when it answers `false`.
    pub fn has_subnet_capacity(&self) -> bool {
        self.has_subnet_capacity_for(1)
    }

    /// Whether `additional` more subnets fit inside the store's ceiling ([`MAX_SUBNETS`]).
    ///
    /// What a writer of SEVERAL subnets at once asks, so it can refuse the whole request
    /// instead of storing some of them: a default network needs one subnet in every
    /// Availability Zone of its Region ([`Self::insert_default_subnets`]).
    pub fn has_subnet_capacity_for(&self, additional: usize) -> bool {
        self.subnets.len().saturating_add(additional) <= MAX_SUBNETS
    }

    /// Whether this account holds the DHCP option set `dhcp_options_id` names.
    ///
    /// A set exists while [`Self::dhcp_options`] holds a record for it, which is the ONE
    /// store of option sets this service has: a Region's default set is minted into it by
    /// [`Self::default_dhcp_options_id`], and a caller-created one joins it when
    /// `CreateDhcpOptions` lands, so every operation that has to resolve an id — an
    /// association, a describe, a delete — asks the same question in the same place.
    /// Whether a VPC happens to be associated with the set is beside the point: an
    /// association moves without the set ceasing to exist.
    ///
    /// A READ: an id this store does not hold is not given a set here.
    pub fn holds_dhcp_options(&self, dhcp_options_id: &str) -> bool {
        self.dhcp_options.contains_key(dhcp_options_id)
    }

    /// Whether `region`'s default DHCP option set can be answered: either the store already
    /// holds it, or another set fits inside the store's ceiling
    /// ([`MAX_DHCP_OPTION_SETS`]).
    ///
    /// A create of a VPC must ask this BEFORE inserting and refuse with
    /// [`dhcp_options_limit_exceeded`] when it answers `false`, exactly as it asks
    /// [`Self::has_vpc_capacity`]: the Region is caller-supplied text, so without this the
    /// store would mint a record per Region string a caller invents, and a VPC that is
    /// later deleted does not give its Region's set back (the Region's default set outlives
    /// every VPC of it, as it does on AWS).
    pub fn has_dhcp_option_set_capacity(&self, region: &str) -> bool {
        self.default_dhcp_options_ids.contains_key(region) || self.has_dhcp_option_set_room()
    }

    /// Whether another DHCP option set fits inside the store's ceiling
    /// ([`MAX_DHCP_OPTION_SETS`]).
    ///
    /// The ONE question a path that is about to store a set asks: `CreateDhcpOptions` asks it
    /// for the set a caller named, and [`Self::has_dhcp_option_set_capacity`] asks it for the
    /// Region's default set, so the two cannot drift apart on how many sets an account holds.
    /// A path that answers `false` refuses with [`dhcp_options_limit_exceeded`] rather than
    /// overshooting the ceiling.
    pub fn has_dhcp_option_set_room(&self) -> bool {
        self.dhcp_options.len() < MAX_DHCP_OPTION_SETS
    }

    /// Store a DHCP option set a caller created, as the modelled [`DhcpOptions`] shape, and
    /// answer the `DhcpOptionsId` it was minted with.
    ///
    /// Every member the SERVICE owns is derived here rather than taken from a caller — the
    /// id ([`DHCP_OPTIONS_ID_PREFIX`], from the one id mint) and the owning account — so a
    /// caller-created set is reported by `DescribeDhcpOptions` exactly as the Region's
    /// default set is ([`Self::default_dhcp_options_id`]), and the two cannot drift. The
    /// record's caller-chosen bytes are charged against the store's byte budget here, so no
    /// writer can store them uncharged.
    ///
    /// A WRITER: the caller must have asked [`Self::has_dhcp_option_set_room`] and
    /// [`Self::would_exceed_stored_bytes`] first, so a request past either bound is refused
    /// instead of overshooting it.
    pub fn insert_dhcp_options(
        &mut self,
        dhcp_configurations: Vec<DhcpConfiguration>,
        tags: Vec<Tag>,
    ) -> String {
        let dhcp_options_id = self.next_id(DHCP_OPTIONS_ID_PREFIX);
        self.add_stored_bytes(
            dhcp_configuration_list_bytes(&dhcp_configurations)
                .saturating_add(tag_list_bytes(&tags)),
        );
        self.dhcp_options.insert(
            dhcp_options_id.clone(),
            DhcpOptions {
                owner_id: Some(::engine::emulator_account_id().to_string()),
                tags: Some(tags),
                dhcp_options_id: Some(dhcp_options_id.clone()),
                dhcp_configurations: Some(dhcp_configurations),
            },
        );
        dhcp_options_id
    }

    /// The bytes `region`'s default DHCP option set would ADD to the store: none when the
    /// store already holds that Region's set, the record's own bytes
    /// ([`default_dhcp_options_payload_bytes`]) when the next VPC of the Region would mint
    /// it.
    ///
    /// A create asks this so the bytes it is about to store are part of what it checks
    /// against [`Self::would_exceed_stored_bytes`], rather than being added behind the
    /// budget's back.
    pub fn unheld_default_dhcp_options_bytes(&self, region: &str) -> usize {
        if self.default_dhcp_options_ids.contains_key(region) {
            0
        } else {
            default_dhcp_options_payload_bytes(region)
        }
    }

    /// The `DhcpOptionsId` of `region`'s DEFAULT DHCP option set, creating that set the
    /// first time a VPC of the Region needs it.
    ///
    /// An account has ONE default DHCP option set per Region, and every VPC created there
    /// without an explicit association inherits that same set (Amazon VPC User Guide, "DHCP
    /// option sets"), so this answers the id already recorded for the Region and mints a
    /// set only when the Region has none. The set it mints carries the two options AWS puts
    /// in a default set — [`DHCP_OPTION_DOMAIN_NAME`] at the Region's private DNS domain
    /// ([`private_dns_domain`]) and [`DHCP_OPTION_DOMAIN_NAME_SERVERS`] at
    /// [`AMAZON_PROVIDED_DNS`] — and is stored in [`Self::dhcp_options`], so the id a VPC
    /// reports names a set `DescribeDhcpOptions` can read back rather than nothing at all.
    /// The record's bytes are charged against the store's byte budget here, so no writer
    /// can store them uncharged.
    ///
    /// A WRITER: only a path that creates a VPC may call it, never a reporting operation,
    /// and that path must have asked [`Self::has_dhcp_option_set_capacity`] and
    /// [`Self::would_exceed_stored_bytes`] (with
    /// [`Self::unheld_default_dhcp_options_bytes`]) first, so a request past either bound is
    /// refused instead of overshooting it.
    pub fn default_dhcp_options_id(&mut self, region: &str) -> String {
        if let Some(dhcp_options_id) = self.default_dhcp_options_ids.get(region) {
            return dhcp_options_id.clone();
        }
        let dhcp_options_id = self.next_id(DHCP_OPTIONS_ID_PREFIX);
        let configuration = |key: &str, value: String| DhcpConfiguration {
            key: Some(key.to_string()),
            values: Some(vec![AttributeValue { value: Some(value) }]),
        };
        self.dhcp_options.insert(
            dhcp_options_id.clone(),
            DhcpOptions {
                owner_id: Some(::engine::emulator_account_id().to_string()),
                // Nothing has tagged the set the service created for the account.
                tags: Some(Vec::new()),
                dhcp_options_id: Some(dhcp_options_id.clone()),
                dhcp_configurations: Some(vec![
                    configuration(DHCP_OPTION_DOMAIN_NAME, private_dns_domain(region)),
                    configuration(
                        DHCP_OPTION_DOMAIN_NAME_SERVERS,
                        AMAZON_PROVIDED_DNS.to_string(),
                    ),
                ]),
            },
        );
        self.add_stored_bytes(default_dhcp_options_payload_bytes(region));
        self.default_dhcp_options_ids
            .insert(region.to_string(), dhcp_options_id.clone());
        dhcp_options_id
    }

    /// Insert a VPC with `cidr_block` as its primary IPv4 CIDR block, in `vpc_state`, and
    /// answer the `VpcId` it was given.
    ///
    /// The VPC's own id and its primary CIDR association's are minted here, so a VPC never
    /// shares an id with another resource of this store. Its `DhcpOptionsId` is NOT minted
    /// per VPC: it is `region`'s default DHCP option set
    /// ([`Self::default_dhcp_options_id`]), which every VPC of the Region inherits.
    ///
    /// The caller-chosen bytes of `tags` are charged against the store's byte budget HERE
    /// rather than by each writer, so no writer can store them uncharged; a create still
    /// asks [`Self::has_vpc_capacity`] and [`Self::would_exceed_stored_bytes`] first so it
    /// can refuse instead of overshooting.
    ///
    /// The default security group a VPC comes with is NOT written here: it is
    /// [`Self::insert_default_security_group`], which every writer of a VPC calls, because
    /// that group's ARN names a Region and a VPC record carries none. The default NETWORK
    /// ACL a VPC comes with IS written here ([`Self::insert_default_network_acl`]), because
    /// an ACL carries no ARN and so needs nothing of the Region — which is what keeps every
    /// VPC of this store holding the one AWS gives it.
    pub fn insert_vpc(
        &mut self,
        cidr_block: &str,
        is_default: bool,
        instance_tenancy: &str,
        vpc_state: &str,
        region: &str,
        tags: Vec<Tag>,
    ) -> String {
        let vpc_id = self.next_id("vpc");
        let association_id = self.next_id("vpc-cidr-assoc");
        let dhcp_options_id = self.default_dhcp_options_id(region);
        let vpc = Vpc {
            owner_id: Some(::engine::emulator_account_id().to_string()),
            instance_tenancy: Some(instance_tenancy.to_string()),
            // No IPv6 CIDR block is associated until something associates one.
            ipv6_cidr_block_association_set: Some(Vec::new()),
            // "Information about the IPv4 CIDR blocks associated with the VPC" (`Vpc`):
            // the primary block is one of them, so it appears in both members.
            cidr_block_association_set: Some(vec![VpcCidrBlockAssociation {
                association_id: Some(association_id),
                cidr_block: Some(cidr_block.to_string()),
                cidr_block_state: Some(VpcCidrBlockState {
                    state: Some(CIDR_BLOCK_STATE_ASSOCIATED.to_string()),
                    status_message: None,
                }),
            }]),
            is_default: Some(is_default),
            // No VPC encryption control exists until one is created for the VPC.
            encryption_control: None,
            tags: Some(tags),
            block_public_access_states: Some(BlockPublicAccessStates {
                internet_gateway_block_mode: Some(BLOCK_PUBLIC_ACCESS_OFF.to_string()),
            }),
            vpc_id: Some(vpc_id.clone()),
            state: Some(vpc_state.to_string()),
            cidr_block: Some(cidr_block.to_string()),
            dhcp_options_id: Some(dhcp_options_id),
        };
        self.add_stored_bytes(tag_list_bytes(vpc.tags.as_deref().unwrap_or_default()));
        self.vpcs.insert(vpc_id.clone(), vpc);
        // The Region this VPC belongs to, recorded HERE because this is the one writer of a
        // VPC: EC2 is a regional service, so a request signed for another Region must not
        // see this VPC or anything that belongs to it (see [`Self::vpc_regions`]).
        self.vpc_regions
            .insert(vpc_id.clone(), region.to_string());
        // The attributes the VPC starts life with, written here rather than by each
        // writer so `DescribeVpcAttribute` reads the same defaults whichever operation
        // created the VPC.
        self.vpc_attributes
            .insert(vpc_id.clone(), VpcAttributes::for_vpc(is_default));
        // The default network ACL the VPC comes with, written HERE rather than by each
        // writer of a VPC — unlike the default security group above, a network ACL carries
        // no ARN, so nothing about it needs the Region. A store already at the network-ACL
        // ceiling gets a VPC without one rather than growing past that ceiling, the way
        // [`Self::insert_default_subnets`] stops at the subnet ceiling.
        self.insert_default_network_acl(&vpc_id);
        // And the main route table it comes with, on exactly the same terms: "your VPC
        // automatically comes with a main route table that you can modify" (Amazon VPC User
        // Guide, "Route tables"), whose only route is the local one for the VPC's own CIDR
        // block. A store already at the route-table ceiling gets a VPC without one rather
        // than growing past that ceiling.
        self.insert_main_route_table(&vpc_id, cidr_block);
        vpc_id
    }

    /// The attributes of one VPC, read the way `DescribeVpcAttribute` reads them: the
    /// stored entry, or the creation defaults for a VPC whose entry predates this field.
    ///
    /// A READ ONLY — a VPC missing an entry is not given one here, so describing a VPC's
    /// attributes cannot change what a later caller sees.
    pub fn vpc_attributes_of(&self, vpc_id: &str) -> Option<VpcAttributes> {
        let vpc = self.vpcs.get(vpc_id)?;
        Some(self.vpc_attributes.get(vpc_id).copied().unwrap_or_else(|| {
            // Unreachable while every writer goes through `insert_vpc`, which stores an
            // entry. The fallback reads the VPC's OWN `IsDefault` rather than assuming a
            // non-default VPC, so a VPC without an entry is still reported with the
            // defaults AWS gives a VPC of that kind.
            VpcAttributes::for_vpc(vpc.is_default.unwrap_or(false))
        }))
    }

    /// Insert a subnet, and answer the `SubnetId` it was given.
    ///
    /// Everything the service itself owns is derived here rather than taken from the
    /// caller: the id, the ARN built from it, the owning account, and
    /// `AvailableIpAddressCount` computed from the CIDR block — so two writers cannot
    /// report the same subnet differently.
    ///
    /// Like [`Self::insert_vpc`], the caller-chosen bytes of `spec.tags` are charged
    /// against the store's byte budget here, so a writer cannot store them uncharged.
    pub fn insert_subnet(&mut self, spec: SubnetSpec) -> String {
        let subnet_id = self.next_id("subnet");
        // The VPC the subnet is in, kept before the record takes ownership of it: the
        // association below is made against that VPC's default network ACL.
        let spec_vpc_id = spec.vpc_id.clone();
        let subnet = Subnet {
            availability_zone_id: Some(spec.availability_zone_id),
            // Local network interfaces are an Outpost feature nothing here enables, so no
            // device index is reported rather than a made-up one.
            enable_lni_at_device_index: None,
            map_customer_owned_ip_on_launch: Some(false),
            // A customer-owned IPv4 pool exists only on an Outpost subnet.
            customer_owned_ipv4_pool: None,
            owner_id: Some(::engine::emulator_account_id().to_string()),
            assign_ipv6_address_on_creation: Some(false),
            // No IPv6 CIDR block is associated until something associates one.
            ipv6_cidr_block_association_set: Some(Vec::new()),
            tags: Some(spec.tags),
            subnet_arn: Some(::engine::emulator_arn(
                "ec2",
                &spec.region,
                &format!("subnet/{subnet_id}"),
            )),
            // A subnet is on an Outpost only when one was asked for.
            outpost_arn: None,
            enable_dns64: Some(false),
            ipv6_native: Some(false),
            private_dns_name_options_on_launch: Some(PrivateDnsNameOptionsOnLaunch {
                hostname_type: Some(HOSTNAME_TYPE_IP_NAME.to_string()),
                enable_resource_name_dns_a_record: Some(false),
                enable_resource_name_dns_aaaa_record: Some(false),
            }),
            block_public_access_states: Some(BlockPublicAccessStates {
                internet_gateway_block_mode: Some(BLOCK_PUBLIC_ACCESS_OFF.to_string()),
            }),
            // "Indicates if this is a subnet used with Amazon Elastic VMware Service
            // (EVS). Possible values are `Elastic VMware Service` or no value"
            // (`Subnet$Type`): no value, this being an ordinary subnet.
            r#type: None,
            subnet_id: Some(subnet_id.clone()),
            state: Some(spec.state),
            vpc_id: Some(spec.vpc_id),
            available_ip_address_count: Some(available_ipv4_addresses(&spec.cidr_block)),
            cidr_block: Some(spec.cidr_block),
            availability_zone: Some(spec.availability_zone),
            default_for_az: Some(spec.default_for_az),
            map_public_ip_on_launch: Some(spec.map_public_ip_on_launch),
        };
        self.add_stored_bytes(tag_list_bytes(subnet.tags.as_deref().unwrap_or_default()));
        self.subnets.insert(subnet_id.clone(), subnet);
        // "If you don't explicitly associate a subnet with a network ACL, the subnet is
        // automatically associated with the default network ACL" (Amazon VPC User Guide,
        // "Control subnet traffic with network access control lists") — recorded HERE, the
        // one place a subnet is stored, so no writer of a subnet can leave it associated
        // with no ACL at all. A subnet of a VPC whose default ACL the store does not hold
        // gets no association rather than one naming an ACL nothing would report.
        self.associate_subnet_with_default_network_acl(&subnet_id, &spec_vpc_id);
        subnet_id
    }

    /// Associate `ipv6_cidr_block` with the subnet `subnet_id` and answer the association
    /// as it was stored, or `None` when the store holds no such subnet.
    ///
    /// The one writer of a subnet's `Ipv6CidrBlockAssociationSet`, so
    /// `AssociateSubnetCidrBlock` and `DescribeSubnets` cannot report one association
    /// differently. The association id is minted here out of the store's own counter, and
    /// the state starts at [`CIDR_BLOCK_STATE_ASSOCIATING`] with the move to
    /// [`CIDR_BLOCK_STATE_ASSOCIATED`] recorded in [`Self::subnet_ipv6_associated_at`] one
    /// [`TRANSITION_DELAY`] out — the same arrangement a VPC's own IPv6 association has.
    ///
    /// `ipv6_address_attribute` and `ip_source` are facts of the VPC block this one is cut
    /// out of, so the caller reads them off that association rather than this writer
    /// guessing them.
    ///
    /// The bytes the association retains are charged against the store's byte budget HERE,
    /// by the one definition of that charge ([`subnet_ipv6_association_payload_bytes`]),
    /// which is what [`subnet_payload_bytes`] gives back on delete.
    ///
    /// `None`, with NOTHING written, for a subnet the store does not hold, for a subnet
    /// already at [`MAX_IPV6_ASSOCIATIONS_PER_SUBNET`] association records, and when the
    /// bytes the association would hold would cross [`MAX_STORED_BYTES`]. All three are
    /// asked HERE, before the first write, the way [`Self::insert_coip_pool`] enforces its
    /// own ceiling — so a caller that forgets to ask cannot grow the store without bound.
    pub fn associate_subnet_ipv6_cidr_block(
        &mut self,
        subnet_id: &str,
        ipv6_cidr_block: String,
        ipv6_address_attribute: Option<String>,
        ip_source: Option<String>,
    ) -> Option<SubnetIpv6CidrBlockAssociation> {
        if !self.subnets.contains_key(subnet_id) {
            return None;
        }
        let charged_bytes = subnet_ipv6_association_payload_bytes(&ipv6_cidr_block);
        if !self.has_subnet_ipv6_association_capacity(subnet_id)
            || self.would_exceed_stored_bytes(charged_bytes)
        {
            return None;
        }
        let association_id = self.next_id("subnet-cidr-assoc");
        let association = SubnetIpv6CidrBlockAssociation {
            association_id: Some(association_id),
            ipv6_cidr_block: Some(ipv6_cidr_block),
            ipv6_cidr_block_state: Some(SubnetCidrBlockState {
                state: Some(CIDR_BLOCK_STATE_ASSOCIATING.to_string()),
                status_message: None,
            }),
            ipv6_address_attribute,
            ip_source,
        };
        let subnet = self.subnets.get_mut(subnet_id)?;
        subnet
            .ipv6_cidr_block_association_set
            .get_or_insert_with(Vec::new)
            .push(association.clone());
        self.add_stored_bytes(charged_bytes);
        self.subnet_ipv6_associated_at
            .insert(subnet_id.to_string(), Instant::now() + TRANSITION_DELAY);
        Some(association)
    }

    /// Whether another IPv6 CIDR block association fits inside the ceiling this store keeps
    /// for ONE subnet ([`MAX_IPV6_ASSOCIATIONS_PER_SUBNET`]).
    ///
    /// The same contract as [`Self::has_subnet_capacity`]: a writer asks first so it can
    /// refuse instead of overshooting. A subnet the store does not hold has no room for an
    /// association either.
    pub fn has_subnet_ipv6_association_capacity(&self, subnet_id: &str) -> bool {
        self.subnets.get(subnet_id).is_some_and(|subnet| {
            subnet
                .ipv6_cidr_block_association_set
                .as_deref()
                .map_or(0, <[SubnetIpv6CidrBlockAssociation]>::len)
                < MAX_IPV6_ASSOCIATIONS_PER_SUBNET
        })
    }

    /// The subnet IPv6 CIDR block association `association_id` names, as the id of the
    /// subnet that holds it and the association itself — or `None` when no subnet of the
    /// account holds one with that id.
    ///
    /// An association of this kind is named by its own id and nothing else
    /// (`DisassociateSubnetCidrBlockRequest$AssociationId`), so the lookup walks the
    /// subnets' association sets rather than asking for a subnet first. The id is minted
    /// from the store's own counter ([`Self::associate_subnet_ipv6_cidr_block`]), so at most
    /// one association of one subnet carries it.
    pub fn subnet_ipv6_association(
        &self,
        association_id: &str,
    ) -> Option<(String, SubnetIpv6CidrBlockAssociation)> {
        self.subnets.iter().find_map(|(subnet_id, subnet)| {
            subnet
                .ipv6_cidr_block_association_set
                .iter()
                .flatten()
                .find(|association| association.association_id.as_deref() == Some(association_id))
                .map(|association| (subnet_id.clone(), association.clone()))
        })
    }

    /// Start the disassociation of the subnet IPv6 CIDR block association `association_id`,
    /// and answer the subnet that holds it with the association as it now stands — or `None`
    /// when no subnet of the account holds one with that id.
    ///
    /// The one writer of a disassociation, so `DisassociateSubnetCidrBlock` and
    /// `DescribeSubnets` cannot report one differently. The association is recorded
    /// [`CIDR_BLOCK_STATE_DISASSOCIATING`], which is what the caller is answered: the block
    /// is on its way out, so it is no longer HELD ([`cidr_association_holds_its_block`]) and
    /// the subnet may be given another one straight away. The terminal
    /// [`CIDR_BLOCK_STATE_DISASSOCIATED`] is owed to the clock one [`TRANSITION_DELAY`] out
    /// ([`Self::subnet_ipv6_disassociated_at`]) — the arrangement the `associating` ->
    /// `associated` move has, in the other direction. The record itself STAYS in the
    /// subnet's association set, reporting the block the subnet let go of and the state it
    /// ended in, so the bytes it was charged stay charged too.
    ///
    /// Idempotent: an association already on its way out keeps the instant already recorded
    /// for it, so repeating the call cannot hold the move open indefinitely.
    pub fn begin_subnet_ipv6_disassociation(
        &mut self,
        association_id: &str,
    ) -> Option<(String, SubnetIpv6CidrBlockAssociation)> {
        let (subnet_id, _) = self.subnet_ipv6_association(association_id)?;
        let association = self
            .subnets
            .get_mut(&subnet_id)?
            .ipv6_cidr_block_association_set
            .iter_mut()
            .flatten()
            .find(|association| association.association_id.as_deref() == Some(association_id))?;
        let was_held = cidr_association_holds_its_block(
            association
                .ipv6_cidr_block_state
                .as_ref()
                .and_then(|state| state.state.as_deref()),
        );
        // An association that is already on its way out, or already out, is answered exactly
        // as it stands: its state is not walked backwards and the instant recorded for its
        // move is not pushed out, so repeating the call cannot hold one open indefinitely or
        // revive one the clock has already finished with.
        if was_held {
            association.ipv6_cidr_block_state = Some(SubnetCidrBlockState {
                state: Some(CIDR_BLOCK_STATE_DISASSOCIATING.to_string()),
                status_message: None,
            });
        }
        let association = association.clone();
        if was_held {
            self.subnet_ipv6_disassociated_at
                .insert(association_id.to_string(), Instant::now() + TRANSITION_DELAY);
        }
        Some((subnet_id, association))
    }

    /// What still depends on the IPv6 CIDR block `ipv6_cidr_block` OF THE SUBNET `subnet_id`,
    /// as the ids of the depending resources.
    ///
    /// "You must detach or delete all gateways and resources that are associated with the
    /// CIDR block before you can disassociate it" (`DisassociateSubnetCidrBlock`) — and what
    /// is associated with a subnet's IPv6 block is every network interface OF THAT SUBNET
    /// holding an address or a delegated prefix out of it (`NetworkInterface$Ipv6Addresses`,
    /// `NetworkInterface$Ipv6Prefixes`). Those records ARE the in-use pool
    /// ([`Self::assigned_ipv6_addresses`]), so there is no second copy of them to drift from,
    /// and an instance holds its addresses THROUGH an interface — the same reading
    /// [`Self::subnet_dependencies`] has of what occupies a subnet.
    ///
    /// Scoped to the subnet because an address is an address OF A SUBNET: two subnets of two
    /// VPCs may hold the same block, and an interface in one of them holds nothing of the
    /// other's — the same reason the overlap `AssociateSubnetCidrBlock` refuses is asked per
    /// VPC.
    pub fn subnet_ipv6_cidr_block_dependencies(
        &self,
        subnet_id: &str,
        ipv6_cidr_block: &str,
    ) -> Vec<String> {
        let mut found: Vec<String> = self
            .network_interfaces
            .iter()
            .filter(|(_, interface)| interface.subnet_id.as_deref() == Some(subnet_id))
            .filter(|(_, interface)| {
                interface
                    .ipv6_addresses
                    .iter()
                    .flatten()
                    .filter_map(|address| address.ipv6_address.as_deref())
                    .any(|address| cidr_block_contains_address(ipv6_cidr_block, address))
                    || interface
                        .ipv6_prefixes
                        .iter()
                        .flatten()
                        .filter_map(|prefix| prefix.ipv6_prefix.as_deref())
                        .any(|prefix| cidr_block_contains_block(ipv6_cidr_block, prefix))
            })
            .map(|(network_interface_id, _)| network_interface_id.clone())
            .collect();
        found.sort();
        found
    }

    /// Whether another subnet CIDR reservation fits inside the store's ceiling
    /// ([`MAX_STORED_RECORDS_PER_STORE`]), on the contract of [`Self::has_subnet_capacity`]:
    /// a create asks first so it can refuse instead of overshooting.
    pub fn has_subnet_cidr_reservation_capacity(&self) -> bool {
        self.subnet_cidr_reservations.len() < MAX_STORED_RECORDS_PER_STORE
    }

    /// Insert a subnet CIDR reservation, and answer the `SubnetCidrReservationId` it was
    /// given.
    ///
    /// Everything the service itself owns is derived here rather than taken from the
    /// caller — the reservation id and the owning account — so two writers cannot report
    /// the same reservation differently, exactly as [`Self::insert_subnet`] does for a
    /// subnet. The caller-chosen bytes of the reservation are charged against the store's
    /// byte budget here, so a writer cannot store them uncharged.
    ///
    /// `None` means the store is at [`MAX_STORED_RECORDS_PER_STORE`] and NOTHING was
    /// stored: the ceiling is enforced here, the way [`Self::insert_coip_pool`] enforces
    /// its own, so a writer that forgets to ask cannot grow the store without bound.
    pub fn insert_subnet_cidr_reservation(
        &mut self,
        spec: SubnetCidrReservationSpec,
    ) -> Option<String> {
        if !self.has_subnet_cidr_reservation_capacity() {
            return None;
        }
        let reservation_id = self.next_id(SUBNET_CIDR_RESERVATION_ID_PREFIX);
        self.add_stored_bytes(subnet_cidr_reservation_payload_bytes(
            &spec.cidr,
            spec.description.as_deref(),
            &spec.tags,
        ));
        let reservation = SubnetCidrReservation {
            subnet_cidr_reservation_id: Some(reservation_id.clone()),
            subnet_id: Some(spec.subnet_id),
            cidr: Some(spec.cidr),
            reservation_type: Some(spec.reservation_type),
            // "The ID of the account that owns the subnet CIDR reservation"
            // (`SubnetCidrReservation$OwnerId`): this emulator serves one account.
            owner_id: Some(::engine::emulator_account_id().to_string()),
            description: spec.description,
            tags: Some(spec.tags),
        };
        self.subnet_cidr_reservations
            .insert(reservation_id.clone(), reservation);
        Some(reservation_id)
    }

    /// Remove the subnet CIDR reservation `reservation_id` names and answer it as it was
    /// last reported, or `None` when the store holds no such reservation.
    ///
    /// The answer is the record the removal took OUT of the store, so what a delete reports
    /// is what the readers reported — never a second copy built beside it. The bytes the
    /// record held go back to the store's budget on exactly the terms
    /// [`Self::insert_subnet_cidr_reservation`] took them on
    /// ([`subnet_cidr_reservation_payload_bytes`]), so a reservation that is created and
    /// deleted leaves the budget where it started.
    pub fn remove_subnet_cidr_reservation(
        &mut self,
        reservation_id: &str,
    ) -> Option<SubnetCidrReservation> {
        let reservation = self.subnet_cidr_reservations.remove(reservation_id)?;
        self.release_stored_bytes(subnet_cidr_reservation_payload_bytes(
            reservation.cidr.as_deref().unwrap_or_default(),
            reservation.description.as_deref(),
            reservation.tags.as_deref().unwrap_or_default(),
        ));
        Some(reservation)
    }

    /// Insert a customer-owned IP (CoIP) address pool, and answer the `PoolId` it was
    /// given.
    ///
    /// The writer seam for the CoIP store: `CreateCoipPool` mints a pool through it, and
    /// this crate's tests seed pools the same way, so the create and a fixture land on this
    /// one record instead of a second copy of a pool beside it.
    ///
    /// Everything the service itself owns is derived here rather than taken from the
    /// caller — the id and the `PoolArn` built from it — so two writers cannot report the
    /// same pool differently, exactly as [`Self::insert_subnet`] does for a subnet. The
    /// caller-chosen bytes of the pool's CIDRs and tags are charged against the store's
    /// byte budget here, so a writer cannot store them uncharged.
    /// `None` means the store is at [`MAX_STORED_RECORDS_PER_STORE`] and NOTHING was stored: the
    /// ceiling is enforced here, the way [`Self::insert_vpc_endpoint_connection`] enforces
    /// its own, so a writer that forgets to ask cannot grow the store without bound.
    pub fn insert_coip_pool(&mut self, spec: CoipPoolSpec) -> Option<String> {
        if self.coip_pools.len() >= MAX_STORED_RECORDS_PER_STORE {
            return None;
        }
        // [`COIP_POOL_ID_PREFIX`] carries its own separator, the way
        // [`coip_pool_id_is_well_formed`] reads one, while [`Self::next_id`] adds one.
        let pool_id = self.next_id(COIP_POOL_ID_PREFIX.trim_end_matches('-'));
        let pool = crate::ops::types::CoipPool {
            pool_id: Some(pool_id.clone()),
            pool_cidrs: Some(spec.pool_cidrs),
            local_gateway_route_table_id: Some(spec.local_gateway_route_table_id),
            tags: Some(spec.tags),
            pool_arn: Some(::engine::emulator_arn(
                "ec2",
                &spec.region,
                &format!("coip-pool/{pool_id}"),
            )),
        };
        // [`STORED_RECORD_OVERHEAD_BYTES`] beside the caller-chosen bytes, so a pool with no CIDRs
        // and no tags is not free against the byte budget either. The ONE definition of that
        // charge is [`coip_pool_payload_bytes`], which [`Self::remove_coip_pool`] gives back,
        // so what a delete releases cannot drift from what this insert took.
        self.add_stored_bytes(coip_pool_payload_bytes(&pool));
        self.coip_pools.insert(pool_id.clone(), pool);
        Some(pool_id)
    }

    /// Remove the customer-owned IP address pool `pool_id` names and answer it as it was
    /// last reported, or `None` when the store holds no such pool.
    ///
    /// The answer is the record the removal took OUT of the store, so what a delete reports
    /// is what the readers reported — never a second copy built beside it. The bytes the
    /// record held go back to the store's budget on exactly the terms
    /// [`Self::insert_coip_pool`] took them on ([`coip_pool_payload_bytes`]).
    pub fn remove_coip_pool(&mut self, pool_id: &str) -> Option<crate::ops::types::CoipPool> {
        let pool = self.coip_pools.remove(pool_id)?;
        self.release_stored_bytes(coip_pool_payload_bytes(&pool));
        Some(pool)
    }

    /// Give `vpc_id` the default subnet AWS creates in each Availability Zone of
    /// `region`, and answer their ids in zone order.
    ///
    /// "When we create a default VPC, we create a default subnet in each Availability
    /// Zone in the Region … we add a size /20 IPv4 CIDR block" with "the auto-assign
    /// public IPv4 address attribute set to `true`" (Amazon VPC User Guide, "Default
    /// VPCs"), so each zone's subnet is the n-th [`DEFAULT_SUBNET_PREFIX_LENGTH`] block of
    /// the VPC's own CIDR block, `DefaultForAz`, and public-IP-on-launch. A zone whose
    /// block does not fit inside `vpc_cidr_block` gets no subnet, rather than one with a
    /// block outside its VPC, and a store already at [`MAX_SUBNETS`] gets none at all
    /// rather than growing past its ceiling.
    pub fn insert_default_subnets(
        &mut self,
        vpc_id: &str,
        vpc_cidr_block: &str,
        region: &str,
    ) -> Vec<String> {
        let mut inserted = Vec::new();
        for (index, zone) in availability_zones_in_region(region).into_iter().enumerate() {
            if !self.has_subnet_capacity() {
                break;
            }
            let Ok(offset) = u32::try_from(index) else {
                break;
            };
            let Some(cidr_block) =
                nth_subnet_cidr_block(vpc_cidr_block, DEFAULT_SUBNET_PREFIX_LENGTH, offset)
            else {
                continue;
            };
            inserted.push(self.insert_subnet(SubnetSpec {
                vpc_id: vpc_id.to_string(),
                cidr_block,
                availability_zone: zone.zone_name,
                availability_zone_id: zone.zone_id,
                region: region.to_string(),
                state: SUBNET_STATE_AVAILABLE.to_string(),
                default_for_az: true,
                map_public_ip_on_launch: true,
                tags: Vec::new(),
            }));
        }
        inserted
    }

    /// Store a security group, and answer the `GroupId` it was given.
    ///
    /// Everything the service itself owns is derived here rather than taken from the
    /// caller: the id, the ARN built from it, and the owning account — so two writers
    /// cannot report the same group differently.
    ///
    /// The record's caller-chosen bytes are NOT charged here, because not every writer has
    /// any: `CreateSecurityGroup` charges [`security_group_payload_bytes`] of the group it
    /// stores, while [`Self::insert_default_security_group`] writes a name and description
    /// the SERVICE chose, which the budget ([`MAX_STORED_BYTES`], a bound on caller-supplied
    /// data) does not count. [`Self::remove_security_group`] gives back on exactly the same
    /// terms.
    ///
    /// The rules of `spec`'s permissions are stored through
    /// [`Self::insert_security_group_rules`], which holds the group to the published
    /// per-direction rule quota; a writer whose request may exceed it asks
    /// [`Self::has_security_group_rule_capacity`] first and refuses the whole request
    /// rather than storing a group with fewer rules than it asked for.
    ///
    /// A permission of `spec` that the store has no room for is a VALUE here, never an
    /// assertion: the store's own ceiling ([`MAX_SECURITY_GROUP_RULES`]) is reachable from
    /// request traffic, and an assertion on a path a request reaches is a panic rather than
    /// an invariant. What keeps a shortfall from reading as success is that the group's
    /// aggregate `IpPermissions` members are recomputed from the rules the store HOLDS
    /// ([`Self::resync_security_group_permissions`]), so the group can never report a rule
    /// that was not stored, and `DescribeSecurityGroupRules` and `DescribeSecurityGroups`
    /// still answer the same set.
    pub fn insert_security_group(&mut self, spec: SecurityGroupSpec) -> String {
        let group_id = self.next_id("sg");
        let region = spec.region.clone();
        let group = SecurityGroup {
            group_id: Some(group_id.clone()),
            group_name: Some(spec.group_name),
            description: Some(spec.description),
            vpc_id: Some(spec.vpc_id),
            owner_id: Some(::engine::emulator_account_id().to_string()),
            security_group_arn: Some(::engine::emulator_arn(
                "ec2",
                &region,
                &format!("security-group/{group_id}"),
            )),
            tags: Some(spec.tags),
            // The group's rules live in `Self::security_group_rules`, where each one has
            // the id `DescribeSecurityGroupRules` reports it under; these two members are
            // the AGGREGATE of those rules and are written only by
            // `Self::resync_security_group_permissions`, which the inserts below call.
            ip_permissions: Some(Vec::new()),
            ip_permissions_egress: Some(Vec::new()),
        };
        self.security_groups.insert(group_id.clone(), group);
        for permission in &spec.ip_permissions {
            // The permissions a creator stores are the service's own documented defaults —
            // `CreateSecurityGroup` takes no rules from the request — so their bytes are not
            // charged to the caller-chosen budget, the same terms the group's own name and
            // description are stored on.
            self.insert_security_group_rules(
                &group_id,
                false,
                permission,
                // `CreateSecurityGroup` takes no tags for a rule: a tag specification on it
                // applies to the GROUP.
                &[],
                false,
                &region,
            );
        }
        for permission in &spec.ip_permissions_egress {
            self.insert_security_group_rules(&group_id, true, permission, &[], false, &region);
        }
        group_id
    }

    /// Store the rules one [`IpPermission`] grants on `group_id`, and answer their
    /// `SecurityGroupRuleId`s.
    ///
    /// "If you specify multiple values for a parameter … a separate rule is created for
    /// each value" (Amazon VPC User Guide, "Security group rules"): a permission naming
    /// three CIDR blocks is THREE rules, each with its own id and its own description, so
    /// this expands every grant of the permission — its IPv4 ranges, its IPv6 ranges, its
    /// prefix lists and the groups it references — into one rule apiece. The protocol and
    /// the port range are facts of the permission, so every rule it mints carries them.
    ///
    /// The group's aggregate `IpPermissions` members are recomputed once at the end, so no
    /// writer has to remember to keep the two views in step.
    ///
    /// ALL OR NOTHING, and BOUNDED: the whole permission is weighed against the published
    /// quota ([`MAX_SECURITY_GROUP_RULES_PER_DIRECTION`], in each bucket of the direction
    /// the quota is counted in) and this store's
    /// ceiling ([`MAX_SECURITY_GROUP_RULES`]) ONCE, before anything is stored, so a
    /// permission that does not fit stores NOTHING and answers with no ids rather than
    /// leaving a group half of what the request asked for — and however many grants a
    /// request names, the store grows by at most a fixed number of records per group. A
    /// writer asks [`Self::has_security_group_rule_capacity`] itself so it can answer
    /// [`rules_per_security_group_limit_exceeded`]; the refusal here is what keeps the
    /// store finite for a writer that forgets. That bound is also what bounds the recompute
    /// below, whose cost is the group's rule count times its distinct protocol/port
    /// combinations.
    pub fn insert_security_group_rules(
        &mut self,
        group_id: &str,
        is_egress: bool,
        permission: &IpPermission,
        tags: &[Tag],
        caller_supplied: bool,
        region: &str,
    ) -> Vec<String> {
        // One rule per grant the permission names, so the whole batch is what the quota is
        // weighed against — counted once here rather than per grant, which also keeps the
        // count off the per-rule path, and in the BUCKETS the quota is counted in, so a
        // grant of one address family is not weighed against another family's rules.
        let demand = self.security_group_rule_demand(::std::slice::from_ref(permission));
        if !self.has_security_group_rule_capacity(group_id, is_egress, demand) {
            return Vec::new();
        }
        let mut minted: Vec<String> = Vec::new();
        for (rule, referenced_group_name) in
            security_group_rule_grants(group_id, is_egress, permission, tags)
        {
            minted.extend(self.insert_security_group_rule(
                rule,
                referenced_group_name,
                caller_supplied,
                region,
            ));
        }
        self.resync_security_group_permissions(group_id);
        minted
    }

    /// Store one security group rule, and answer the `SecurityGroupRuleId` it was given —
    /// or `None` when it was not stored.
    ///
    /// Everything the service itself owns is derived here rather than taken from the
    /// caller: the id and the ARN built from it — so two writers cannot report the same
    /// rule differently.
    ///
    /// Nothing is stored unless the store can hold it, so neither the record count nor the
    /// bytes this store holds can grow without bound from request input:
    ///
    /// * the rule must belong to a group this store HOLDS — a rule for an unknown group
    ///   would be reported by `DescribeSecurityGroupRules` with no `SecurityGroup`
    ///   aggregating it, the one disagreement this design exists to prevent;
    /// * the store must be under [`MAX_SECURITY_GROUP_RULES`] — an O(1) backstop, the
    ///   per-direction quota having been weighed for the whole permission by
    ///   [`Self::insert_security_group_rules`], which is the only caller; and
    /// * the bytes the record retains are charged against the store's budget
    ///   ([`MAX_STORED_BYTES`]) here when `caller_supplied` says the permission came from a
    ///   request, which [`Self::remove_security_group`] gives back. That budget bounds
    ///   CALLER-supplied data, so the service's own documented default rules are not
    ///   charged for — the same terms a group's name and description are charged on.
    pub(super) fn insert_security_group_rule(
        &mut self,
        rule: SecurityGroupRule,
        referenced_group_name: Option<String>,
        caller_supplied: bool,
        region: &str,
    ) -> Option<String> {
        let group_id = rule.group_id.clone().unwrap_or_default();
        if !self.security_groups.contains_key(&group_id) {
            return None;
        }
        if self.security_group_rules.len() >= MAX_SECURITY_GROUP_RULES {
            return None;
        }
        let rule_id = self.next_id(SECURITY_GROUP_RULE_ID_PREFIX);
        let stored = SecurityGroupRule {
            security_group_rule_id: Some(rule_id.clone()),
            security_group_rule_arn: Some(::engine::emulator_arn(
                "ec2",
                region,
                &format!("security-group-rule/{rule_id}"),
            )),
            // "The tags applied to the security group rule" (`SecurityGroupRule$Tags`): a
            // rule nothing has tagged carries an empty set, the way a stored group does.
            tags: Some(rule.tags.unwrap_or_default()),
            ..rule
        };
        let mut record = SecurityGroupRuleRecord {
            rule: stored,
            referenced_group_name,
            payload_bytes: 0,
        };
        if caller_supplied {
            record.payload_bytes = security_group_rule_payload_bytes(&record);
        }
        self.add_stored_bytes(record.payload_bytes);
        self.security_group_rules.insert(rule_id.clone(), record);
        Some(rule_id)
    }

    /// How many rules `group_id` holds in one direction — inbound when `is_egress` is
    /// false, outbound when it is true. The two directions are counted apart because the
    /// quota is published per direction.
    ///
    /// The whole side, whatever address family each of its rules grants; what the QUOTA is
    /// weighed against is one family's bucket of that side
    /// ([`Self::security_group_rule_family_count`]).
    pub fn security_group_rule_count(&self, group_id: &str, is_egress: bool) -> usize {
        self.security_group_rules
            .values()
            .filter(|record| {
                record.rule.group_id.as_deref() == Some(group_id)
                    && record.rule.is_egress.unwrap_or(false) == is_egress
            })
            .count()
    }

    /// Which of a side's quota buckets one stored rule is counted in: the bucket of the
    /// address family it grants, and EVERY bucket where its grant names no address family.
    ///
    /// A rule grants one source, "a CIDR range, security group, or prefix list"
    /// (`RevokeSecurityGroupIngress`). A CIDR grant is of one family, so it is counted in
    /// that family's bucket alone; a prefix list grants the family the list was created for
    /// (`ManagedPrefixList$AddressFamily`); and a grant naming a security group carries no
    /// family at all — it admits that group's traffic of either family — so it is counted in
    /// each. A prefix list this store holds no record of is read the same way as that last
    /// case, because which family it grants is not knowable here.
    pub fn security_group_rule_charges_family(
        &self,
        rule: &SecurityGroupRule,
        family: AddressFamily,
    ) -> bool {
        if rule.cidr_ipv4.is_some() {
            return family == AddressFamily::Ipv4;
        }
        if rule.cidr_ipv6.is_some() {
            return family == AddressFamily::Ipv6;
        }
        if let Some(prefix_list_id) = rule.prefix_list_id.as_deref() {
            return self
                .prefix_list_address_family(prefix_list_id)
                .is_none_or(|list_family| list_family == family);
        }
        true
    }

    /// The address family the managed prefix list `prefix_list_id` names grants, or `None`
    /// when this store holds no such list — an AWS-managed list of a Region, or one of
    /// another account, is not a record here.
    pub(super) fn prefix_list_address_family(&self, prefix_list_id: &str) -> Option<AddressFamily> {
        let record = self.managed_prefix_lists.get(prefix_list_id)?;
        match record.view.address_family.as_deref()? {
            PREFIX_LIST_ADDRESS_FAMILY_IPV4 => Some(AddressFamily::Ipv4),
            PREFIX_LIST_ADDRESS_FAMILY_IPV6 => Some(AddressFamily::Ipv6),
            _ => None,
        }
    }

    /// How many rules `group_id` holds in one direction that are counted in `family`'s
    /// bucket of it — the count the published quota is weighed against.
    pub fn security_group_rule_family_count(
        &self,
        group_id: &str,
        is_egress: bool,
        family: AddressFamily,
    ) -> usize {
        self.security_group_rules
            .values()
            .filter(|record| {
                record.rule.group_id.as_deref() == Some(group_id)
                    && record.rule.is_egress.unwrap_or(false) == is_egress
                    && self.security_group_rule_charges_family(&record.rule, family)
            })
            .count()
    }

    /// What the rules `permissions` grant would ask of a group's quota buckets, counted the
    /// way a stored rule is counted ([`Self::security_group_rule_charges_family`]).
    ///
    /// The ONE reading of a request's demand, so the question a writer asks
    /// ([`Self::has_security_group_rule_capacity`]) cannot weigh a permission differently
    /// from the rules [`Self::insert_security_group_rules`] then stores for it.
    pub fn security_group_rule_demand(
        &self,
        permissions: &[IpPermission],
    ) -> SecurityGroupRuleDemand {
        let mut demand = SecurityGroupRuleDemand::default();
        for permission in permissions {
            demand.charge(
                Some(AddressFamily::Ipv4),
                permission.ip_ranges.iter().flatten().count(),
            );
            demand.charge(
                Some(AddressFamily::Ipv6),
                permission.ipv6_ranges.iter().flatten().count(),
            );
            for entry in permission.prefix_list_ids.iter().flatten() {
                let family = entry
                    .prefix_list_id
                    .as_deref()
                    .and_then(|prefix_list_id| self.prefix_list_address_family(prefix_list_id));
                demand.charge(family, 1);
            }
            demand.charge(None, permission.user_id_group_pairs.iter().flatten().count());
        }
        demand
    }

    /// Whether the rules `demand` describes fit on `group_id` in one direction: every
    /// address family's bucket of that direction inside the published quota
    /// ([`MAX_SECURITY_GROUP_RULES_PER_DIRECTION`]), and the store inside its own ceiling
    /// ([`MAX_SECURITY_GROUP_RULES`]).
    ///
    /// The quota is counted PER BUCKET — one per group, direction and address family — so a
    /// side whose IPv4 rules have reached it still takes a rule of the other family, and
    /// neither side's rules are weighed against the other's.
    ///
    /// The same contract as [`Self::has_security_group_capacity`]: a writer asks this
    /// BEFORE storing anything and refuses the whole request with
    /// [`rules_per_security_group_limit_exceeded`] when it answers `false`, so a partially
    /// applied authorize is never stored.
    pub fn has_security_group_rule_capacity(
        &self,
        group_id: &str,
        is_egress: bool,
        demand: SecurityGroupRuleDemand,
    ) -> bool {
        for family in SECURITY_GROUP_RULE_FAMILIES {
            let held = self.security_group_rule_family_count(group_id, is_egress, family);
            if held.saturating_add(demand.in_bucket(family)) > MAX_SECURITY_GROUP_RULES_PER_DIRECTION
            {
                return false;
            }
        }
        self.security_group_rules
            .len()
            .saturating_add(demand.records())
            <= MAX_SECURITY_GROUP_RULES
    }

    /// Recompute the aggregate `IpPermissions` and `IpPermissionsEgress` of `group_id` from
    /// the rules the store holds for it.
    ///
    /// The rules are the resources; the two members of the group record are a VIEW of them,
    /// in which "rules that have the same protocol and port range are grouped together"
    /// (`SecurityGroup$IpPermissions` reports one `IpPermission` per protocol and port
    /// range, with every grant of that combination inside it). Every writer of a rule ends
    /// by calling this, so `DescribeSecurityGroups` can never disagree with
    /// `DescribeSecurityGroupRules` about one group.
    pub fn resync_security_group_permissions(&mut self, group_id: &str) {
        let mut inbound: Vec<IpPermission> = Vec::new();
        let mut outbound: Vec<IpPermission> = Vec::new();
        for record in self
            .security_group_rules
            .values()
            .filter(|record| record.rule.group_id.as_deref() == Some(group_id))
        {
            let rule = &record.rule;
            let permissions = if rule.is_egress.unwrap_or(false) {
                &mut outbound
            } else {
                &mut inbound
            };
            // One `IpPermission` per (protocol, from port, to port), in the order the rules
            // are held in — which is id order, so the view is stable across reads.
            let position = permissions.iter().position(|permission| {
                permission.ip_protocol == rule.ip_protocol
                    && permission.from_port == rule.from_port
                    && permission.to_port == rule.to_port
            });
            let index = match position {
                Some(index) => index,
                None => {
                    permissions.push(IpPermission {
                        ip_protocol: rule.ip_protocol.clone(),
                        from_port: rule.from_port,
                        to_port: rule.to_port,
                        user_id_group_pairs: Some(Vec::new()),
                        ip_ranges: Some(Vec::new()),
                        ipv6_ranges: Some(Vec::new()),
                        prefix_list_ids: Some(Vec::new()),
                    });
                    permissions.len() - 1
                }
            };
            let permission = &mut permissions[index];
            if let (Some(cidr), Some(ranges)) = (&rule.cidr_ipv4, permission.ip_ranges.as_mut()) {
                ranges.push(IpRange {
                    description: rule.description.clone(),
                    cidr_ip: Some(cidr.clone()),
                });
            }
            if let (Some(cidr), Some(ranges)) = (&rule.cidr_ipv6, permission.ipv6_ranges.as_mut()) {
                ranges.push(Ipv6Range {
                    description: rule.description.clone(),
                    cidr_ipv6: Some(cidr.clone()),
                });
            }
            if let (Some(prefix_list_id), Some(entries)) =
                (&rule.prefix_list_id, permission.prefix_list_ids.as_mut())
            {
                entries.push(PrefixListId {
                    description: rule.description.clone(),
                    prefix_list_id: Some(prefix_list_id.clone()),
                });
            }
            if let (Some(referenced), Some(pairs)) = (
                &rule.referenced_group_info,
                permission.user_id_group_pairs.as_mut(),
            ) {
                pairs.push(UserIdGroupPair {
                    description: rule.description.clone(),
                    user_id: referenced.user_id.clone(),
                    // The name the grant named the referenced group by, which the rule
                    // itself carries no member for — see [`SecurityGroupRuleRecord`].
                    group_name: record.referenced_group_name.clone(),
                    group_id: referenced.group_id.clone(),
                    vpc_id: referenced.vpc_id.clone(),
                    vpc_peering_connection_id: referenced.vpc_peering_connection_id.clone(),
                    peering_status: referenced.peering_status.clone(),
                });
            }
        }
        if let Some(group) = self.security_groups.get_mut(group_id) {
            group.ip_permissions = Some(inbound);
            group.ip_permissions_egress = Some(outbound);
        }
    }

    /// Give `vpc_id` the default security group AWS creates with it, and answer its
    /// `GroupId`.
    ///
    /// "Your VPC automatically comes with a default security group" whose rules "allow all
    /// inbound traffic from network interfaces … that are assigned to the same security
    /// group" and "allow all outbound … traffic from the instance" (Amazon VPC User Guide,
    /// "Default security groups for your VPCs"), so the inbound rule names this group
    /// itself and the outbound one names [`ALL_IPV4_ADDRESSES`], both for every protocol.
    /// The inbound rule can only be written once the id is minted, which is why it is set
    /// after the insert rather than passed to it.
    pub fn insert_default_security_group(&mut self, vpc_id: &str, region: &str) -> String {
        let owner_id = ::engine::emulator_account_id().to_string();
        let group_id = self.insert_security_group(SecurityGroupSpec {
            vpc_id: vpc_id.to_string(),
            group_name: DEFAULT_SECURITY_GROUP_NAME.to_string(),
            description: DEFAULT_SECURITY_GROUP_DESCRIPTION.to_string(),
            region: region.to_string(),
            tags: Vec::new(),
            ip_permissions: Vec::new(),
            ip_permissions_egress: vec![allow_all_egress()],
        });
        self.insert_security_group_rules(
            &group_id,
            false,
            &IpPermission {
                ip_protocol: Some(ALL_IP_PROTOCOLS.to_string()),
                from_port: None,
                to_port: None,
                user_id_group_pairs: Some(vec![UserIdGroupPair {
                    group_id: Some(group_id.clone()),
                    user_id: Some(owner_id),
                    // "For a security group in a nondefault VPC, use the security group
                    // ID" (`UserIdGroupPair$GroupName`): the referenced group is named by
                    // id, so no group name is reported for the pair.
                    group_name: None,
                    description: None,
                    vpc_id: None,
                    vpc_peering_connection_id: None,
                    peering_status: None,
                }]),
                ip_ranges: Some(Vec::new()),
                ipv6_ranges: Some(Vec::new()),
                prefix_list_ids: Some(Vec::new()),
            },
            &[],
            // The rule AWS gives a default group, not one a request named.
            false,
            region,
        );
        group_id
    }

    /// Make sure `region` holds the ambient default network an account already has there,
    /// and answer that network's `VpcId`.
    ///
    /// "When you create an AWS account, we create a default VPC for you in each AWS
    /// Region", and "when we create a default VPC, we create a default subnet in each
    /// Availability Zone in the Region" together with the VPC's default security group
    /// (Amazon VPC User Guide, "Default VPCs"). So the network exists in whichever Region
    /// the account is calling in, and this is the one place it is materialised: a default
    /// VPC at [`DEFAULT_VPC_CIDR_BLOCK`], one default subnet per zone of THAT Region
    /// ([`Self::insert_default_subnets`], over [`availability_zones_in_region`]) and
    /// [`Self::insert_default_security_group`].
    ///
    /// IDEMPOTENT per Region: the Region's entry is recorded, so a second call answers the
    /// ids already there rather than seeding a second copy — which is what lets a reporting
    /// operation call it. The network it materialises has been owed since the account
    /// existed, not since the call, and the entry is never removed, so a default VPC the
    /// caller DELETED is not seeded again (AWS does not recreate one either; that is
    /// `CreateDefaultVpc`). A Region that has lost its default VPC that way therefore
    /// answers `None`.
    ///
    /// `None` also when nothing was seeded: `region` is not a Region of the catalog
    /// ([`is_catalog_region`] — the Region of a credential scope is caller-controlled text,
    /// and an account has a default VPC in the Regions that exist rather than in every
    /// string shaped like a Region code), or the store has no room for the WHOLE network
    /// (one subnet per zone of the Region included), in which case nothing at all is
    /// written and nothing recorded, so the Region is not left holding a VPC without its
    /// subnets.
    pub fn ensure_default_network(&mut self, region: &str) -> Option<String> {
        if self.default_vpc_ids.contains_key(region) {
            return self.default_vpc_id(region);
        }
        // The network a fresh account has held since it existed is one AWS reports READY,
        // so it has no clock-owed move: "a default VPC is ready for you to use" (Amazon VPC
        // User Guide, "Default VPCs").
        self.insert_default_network(region, VPC_STATE_AVAILABLE)
    }

    /// Whether `region` already has the account's default VPC — materialised, or still owed.
    ///
    /// A READ: what [`Self::ensure_default_network`] would answer about, without writing
    /// anything, which is what lets `CreateDefaultVpc` refuse "you already have one" without
    /// materialising a network for the Region of a request it refuses. The account has held a
    /// default VPC in every Region since it existed ("when you create an AWS account, we
    /// create a default VPC for you in each AWS Region" — Amazon VPC User Guide, "Default
    /// VPCs"), so:
    ///
    /// * a Region with a recorded `VpcId` has one while the store still holds that VPC;
    /// * a Region with NO record has one too — the network is owed and nothing has deleted
    ///   it, and the first read of that Region materialises exactly it;
    /// * only a Region whose recorded VPC was DELETED has none, which is the one case
    ///   [`Self::create_default_network`] is for;
    /// * a Region outside the catalog never has one, the Region of a credential scope being
    ///   caller-controlled text.
    pub fn holds_or_owes_default_vpc(&self, region: &str) -> bool {
        if !is_catalog_region(region) {
            return false;
        }
        match self.default_vpc_ids.get(region) {
            Some(vpc_id) => self.vpcs.contains_key(vpc_id.as_str()),
            None => true,
        }
    }

    /// Give `region` a NEW default VPC, in `pending` with the instant the clock owes it
    /// `available` recorded beside it, and answer its `VpcId`.
    ///
    /// What `CreateDefaultVpc` does, against the same Region index
    /// [`Self::ensure_default_network`] seeds the ambient network into: "if you deleted your
    /// previous default VPC, you can create a default VPC" (`CreateDefaultVpc`), so the
    /// Region's recorded entry is OVERWRITTEN with the new network's id rather than
    /// consulted — a caller that has none is exactly the caller this is for, and
    /// [`Self::default_vpc_id`] must answer the one just created from here on.
    ///
    /// The network is the same one a default VPC has wherever it comes from — the whole of
    /// [`Self::insert_default_network`]: a `/16` at [`DEFAULT_VPC_CIDR_BLOCK`], a default
    /// subnet in every Availability Zone of THAT Region, and the VPC's default security
    /// group — so a created default VPC cannot differ from a seeded one in anything but the
    /// state the clock owes it. Unlike the seeded one this VPC is answered in the
    /// non-terminal `pending` state, because the caller just asked for it: that is the state
    /// this call ANSWERS, and the move to `available` is owed from the instant it returns
    /// ([`VPC_PROVISIONING_DELAY`]).
    ///
    /// `None` on exactly the terms [`Self::insert_default_network`] gives: `region` is not a
    /// Region of the catalog, or the store has no room for the WHOLE network, in which case
    /// nothing at all is written.
    pub fn create_default_network(&mut self, region: &str) -> Option<String> {
        let vpc_id = self.insert_default_network(region, VPC_STATE_PENDING)?;
        // What the clock now owes this VPC: `available`, one VPC_PROVISIONING_DELAY from
        // now — the same span, off the same monotonic clock, as a `CreateVpc` pending move.
        self.vpc_available_at
            .insert(vpc_id.clone(), Instant::now() + VPC_PROVISIONING_DELAY);
        Some(vpc_id)
    }

    /// Materialise `region`'s default network in `vpc_state`, record it as that Region's
    /// default VPC, and answer its `VpcId`.
    ///
    /// The ONE place a default VPC is written, whether it is the ambient one an account has
    /// held since it existed ([`Self::ensure_default_network`]) or one a caller asked for
    /// ([`Self::create_default_network`]), so the two cannot disagree about what a default
    /// VPC is: "when we create a default VPC, we create a default subnet in each
    /// Availability Zone in the Region" together with the VPC's default security group
    /// (Amazon VPC User Guide, "Default VPCs") — a VPC at [`DEFAULT_VPC_CIDR_BLOCK`] with
    /// `IsDefault` set, one default subnet per zone of THAT Region
    /// ([`Self::insert_default_subnets`], over [`availability_zones_in_region`]) and
    /// [`Self::insert_default_security_group`]. Only the state the VPC is answered in
    /// differs between the two callers, which is why it is a parameter.
    ///
    /// `None` when nothing was written: `region` is not a Region of the catalog
    /// ([`is_catalog_region`] — the Region of a credential scope is caller-controlled text,
    /// and an account has a default VPC in the Regions that EXIST rather than in every
    /// string shaped like a Region code), or the store has no room for the WHOLE network
    /// (one subnet per zone of the Region included), in which case nothing at all is
    /// written and nothing recorded, so the Region is not left holding a VPC without its
    /// subnets.
    fn insert_default_network(&mut self, region: &str, vpc_state: &str) -> Option<String> {
        if !is_catalog_region(region) {
            return None;
        }
        if !self.has_default_network_room(region) {
            return None;
        }
        let vpc_id = self.insert_vpc(
            DEFAULT_VPC_CIDR_BLOCK,
            true,
            DEFAULT_INSTANCE_TENANCY,
            vpc_state,
            region,
            Vec::new(),
        );
        self.insert_default_subnets(&vpc_id, DEFAULT_VPC_CIDR_BLOCK, region);
        self.insert_default_security_group(&vpc_id, region);
        self.default_vpc_ids
            .insert(region.to_string(), vpc_id.clone());
        Some(vpc_id)
    }

    /// Whether the store has room for the WHOLE default network of `region`.
    ///
    /// The same bounds a `CreateVpc` and the subnets of this Region would have to clear,
    /// asked before anything is written so a store at a ceiling writes nothing rather than a
    /// partial network a recorded index would then make permanent: the VPC count, room for a
    /// subnet in EVERY zone of the Region, the Region's default DHCP option set (which
    /// [`Self::insert_vpc`] mints) and its bytes, and the group the VPC comes with.
    pub fn has_default_network_room(&self, region: &str) -> bool {
        self.has_vpc_capacity()
            && self.has_subnet_capacity_for(availability_zones_in_region(region).len())
            && self.has_dhcp_option_set_capacity(region)
            && self.has_security_group_capacity()
            && !self.would_exceed_stored_bytes(self.unheld_default_dhcp_options_bytes(region))
    }

    /// Store a launch template with its first version, and answer the `LaunchTemplateId` it
    /// was given.
    ///
    /// Everything the service itself owns is derived here rather than taken from the
    /// caller: the id, and the default and latest version numbers — the first version is
    /// the only version, so it is both — so two writers cannot report the same template
    /// differently. The bytes the record retains are counted into the store's budget here
    /// as well, and [`Self::remove_launch_template`] is what gives them back.
    ///
    /// `None` means NOTHING was written and the caller must refuse the request rather than
    /// report a template that does not exist: the account already holds
    /// [`MAX_LAUNCH_TEMPLATES`] of them, or the record's caller-chosen bytes do not fit the
    /// store's byte budget ([`Self::would_exceed_stored_bytes`]). Both ceilings are enforced
    /// HERE as well as in the handler, so a writer that forgets to ask cannot grow the store
    /// without bound — and neither an id nor a byte is spent on a refusal.
    pub fn insert_launch_template(&mut self, spec: LaunchTemplateSpec) -> Option<String> {
        let payload_bytes = launch_template_payload_bytes(&spec);
        if self.launch_templates.len() >= MAX_LAUNCH_TEMPLATES
            || self.would_exceed_stored_bytes(payload_bytes)
        {
            return None;
        }
        let launch_template_id = self.next_id(LAUNCH_TEMPLATE_ID_PREFIX);
        let template = LaunchTemplate {
            launch_template_id: Some(launch_template_id.clone()),
            launch_template_name: Some(spec.name),
            create_time: Some(system_time_to_date_time(spec.create_time)),
            created_by: Some(spec.created_by.clone()),
            default_version_number: Some(FIRST_LAUNCH_TEMPLATE_VERSION),
            latest_version_number: Some(FIRST_LAUNCH_TEMPLATE_VERSION),
            tags: Some(spec.tags),
            // The operator is reported for EVERY template, whether a provider manages it or
            // not ([`unmanaged_launch_template_operator`]), so the member is derived here
            // rather than only where a request named a principal.
            operator: Some(
                spec.operator
                    .unwrap_or_else(unmanaged_launch_template_operator),
            ),
        };
        let mut versions = BTreeMap::new();
        versions.insert(
            FIRST_LAUNCH_TEMPLATE_VERSION,
            LaunchTemplateVersionRecord {
                version_number: FIRST_LAUNCH_TEMPLATE_VERSION,
                version_description: spec.version_description,
                create_time: spec.create_time,
                created_by: spec.created_by,
                default_version: true,
                data: spec.data,
            },
        );
        self.launch_templates.insert(
            launch_template_id.clone(),
            LaunchTemplateRecord {
                template,
                versions,
                highest_version_minted: FIRST_LAUNCH_TEMPLATE_VERSION,
                payload_bytes,
            },
        );
        self.add_stored_bytes(payload_bytes);
        Some(launch_template_id)
    }

    /// Store a new version of the launch template `launch_template_id` names, and answer the
    /// version number it was given.
    ///
    /// Everything the service itself owns is derived here rather than taken from the caller:
    /// "launch template versions are numbered in the order in which they are created"
    /// (`CreateLaunchTemplateVersion`), so the number is one past the highest the template
    /// has ever minted ([`LaunchTemplateRecord::highest_version_minted`]), and storing it is
    /// what moves `LaunchTemplate$LatestVersionNumber`. The template's DEFAULT
    /// version is left where it is: a new version is not the default one until something
    /// makes it so. The bytes the version retains are counted into the store's budget here as
    /// well, on the record a delete of the template gives back in one piece.
    ///
    /// `None` means NOTHING was written and the caller must refuse the request rather than
    /// report a version that does not exist: the account holds no such template, that template
    /// already holds [`MAX_LAUNCH_TEMPLATE_VERSIONS`] versions, or the version's
    /// caller-chosen bytes do not fit the store's byte budget
    /// ([`Self::would_exceed_stored_bytes`]). Both ceilings are enforced HERE as well as in
    /// the handler, for the reason [`Self::insert_launch_template`] gives.
    pub fn insert_launch_template_version(
        &mut self,
        launch_template_id: &str,
        spec: LaunchTemplateVersionSpec,
    ) -> Option<i64> {
        let payload_bytes = launch_template_version_payload_bytes(&spec);
        // Asked before the record is borrowed mutably, so the budget is read off the whole
        // store rather than through the record this call is about to grow.
        if self.would_exceed_stored_bytes(payload_bytes)
            || self.launch_templates.get(launch_template_id)?.versions.len()
                >= MAX_LAUNCH_TEMPLATE_VERSIONS
        {
            return None;
        }
        let record = self.launch_templates.get_mut(launch_template_id)?;
        // The version AFTER every version this template has ever minted
        // ([`LaunchTemplateRecord::highest_version_minted`]), so a number is never reused
        // even if the version that carried it has since been deleted — and a record that has
        // minted nothing is numbered from [`FIRST_LAUNCH_TEMPLATE_VERSION`], the number the
        // first version of a template carries.
        let version_number = record.highest_version_minted.saturating_add(1);
        record.versions.insert(
            version_number,
            LaunchTemplateVersionRecord {
                version_number,
                version_description: spec.version_description,
                create_time: spec.create_time,
                created_by: spec.created_by,
                default_version: record.template.default_version_number == Some(version_number),
                data: spec.data,
            },
        );
        record.template.latest_version_number = Some(version_number);
        record.highest_version_minted = version_number;
        record.payload_bytes = record.payload_bytes.saturating_add(payload_bytes);
        self.add_stored_bytes(payload_bytes);
        Some(version_number)
    }

    /// Remove ONE version of the launch template `launch_template_id` names, and answer the
    /// version as it was last reported — `None` when the account holds no such template or
    /// that template holds no such version, in which case NOTHING was written.
    ///
    /// The template itself stays, with every other version it holds, so this is the one way
    /// a single version leaves the store ([`Self::remove_launch_template`] being the way all
    /// of them do). `LaunchTemplate$LatestVersionNumber` is "the version number of the latest
    /// version of the launch template", so it is re-read off the versions that REMAIN here,
    /// in one place: a delete of the latest version moves it down to the highest version the
    /// template still holds, which is also the version `$Latest` then resolves to, and a
    /// delete of any other version leaves it where it was. The number itself is not given
    /// back — [`LaunchTemplateRecord::highest_version_minted`] keeps counting, because "you
    /// can't specify, change, or replace the numbering of launch template versions".
    ///
    /// The bytes the version retained go back to the store's budget, and the
    /// `CreateLaunchTemplateVersion` client token that minted it goes too: a token must never
    /// answer with a version that is no longer stored.
    pub fn remove_launch_template_version(
        &mut self,
        launch_template_id: &str,
        version_number: i64,
    ) -> Option<LaunchTemplateVersionRecord> {
        let record = self.launch_templates.get_mut(launch_template_id)?;
        let removed = record.versions.remove(&version_number)?;
        // Never more than the record was charged, so the store's budget cannot wrap below
        // what the template's remaining versions hold.
        let released = launch_template_version_record_bytes(&removed).min(record.payload_bytes);
        record.payload_bytes -= released;
        // The latest version is the latest version the template STILL holds, and a template
        // that holds none has no latest version to report: the member follows the versions
        // that remain whichever of them this call took, so no reader can report a version
        // number that is no longer stored.
        record.template.latest_version_number = record.versions.keys().next_back().copied();
        self.launch_template_version_client_tokens
            .retain(|(minted, _), number| {
                minted != launch_template_id || *number != version_number
            });
        self.release_stored_bytes(released);
        Some(removed)
    }

    /// Make the version `version_number` names the DEFAULT version of the launch template
    /// `launch_template_id` names, and answer the template as every reader then reports it —
    /// `None` when the account holds no such template.
    ///
    /// "You can specify which version of the launch template to set as the default version.
    /// When launching an instance, the default version applies when a launch template version
    /// is not specified" (`ModifyLaunchTemplate`). `LaunchTemplate$DefaultVersionNumber` and
    /// the `DefaultVersion` flag [`LaunchTemplateVersionRecord`] keeps for each version are
    /// the SAME fact seen from the template and from the version, so both move here, in one
    /// place: exactly the version named reports the flag, and every other version the
    /// template holds reports it false. Nothing else about the template or its versions
    /// changes, so the bytes the record retains stay as they were counted.
    pub fn set_default_launch_template_version(
        &mut self,
        launch_template_id: &str,
        version_number: i64,
    ) -> Option<LaunchTemplate> {
        let record = self.launch_templates.get_mut(launch_template_id)?;
        record.template.default_version_number = Some(version_number);
        for version in record.versions.values_mut() {
            version.default_version = version.version_number == version_number;
        }
        Some(record.template.clone())
    }

    /// The id of the launch template this account holds under `name`, if it holds one.
    ///
    /// A scan of the store, which [`MAX_LAUNCH_TEMPLATES`] bounds; a name names at most one
    /// template, because a create that reuses one is refused.
    pub fn launch_template_id_for_name(&self, name: &str) -> Option<String> {
        self.launch_templates
            .values()
            .find(|record| record.launch_template_name() == name)
            .map(|record| record.launch_template_id().to_string())
    }

    /// Remove the launch template `launch_template_id` names — with every version it holds,
    /// since "deleting a launch template deletes all of its versions"
    /// (`DeleteLaunchTemplate`) and they live on the one record this removes — and answer
    /// it as it was last reported.
    ///
    /// Every `CreateLaunchTemplate` client token that named it goes too: a token must never
    /// answer with a template that is no longer stored. The bytes the record held go back
    /// to the store's budget.
    pub fn remove_launch_template(
        &mut self,
        launch_template_id: &str,
    ) -> Option<LaunchTemplateRecord> {
        let record = self.launch_templates.remove(launch_template_id)?;
        self.launch_template_client_tokens
            .retain(|_, minted| minted != launch_template_id);
        self.launch_template_version_client_tokens
            .retain(|(minted, _), _| minted != launch_template_id);
        self.release_stored_bytes(record.payload_bytes);
        Some(record)
    }

    /// Give `bytes` of the caller-chosen byte budget back, for a record that is no longer
    /// stored. Saturating, so the budget can never wrap below zero.
    pub fn release_stored_bytes(&mut self, bytes: usize) {
        self.stored_bytes = self.stored_bytes.saturating_sub(bytes);
    }

    // -----------------------------------------------------------------------
    // Security groups
    // -----------------------------------------------------------------------

    /// Whether another security group fits inside the store's ceiling
    /// ([`MAX_SECURITY_GROUPS`]).
    ///
    /// The same contract as [`Self::has_vpc_capacity`]: a create asks first and refuses
    /// with EC2's `SecurityGroupLimitExceeded` when it answers `false`.
    pub fn has_security_group_capacity(&self) -> bool {
        self.security_groups.len() < MAX_SECURITY_GROUPS
    }

    /// The id of the security group this account holds in `vpc_id` under `group_name`, if
    /// it holds one.
    ///
    /// "Names are case-insensitive and must be unique within the VPC"
    /// (`CreateSecurityGroupRequest$GroupName`), so the comparison folds ASCII case and a
    /// name names at most one group per VPC. A scan of the store, which
    /// [`MAX_SECURITY_GROUPS`] bounds.
    pub fn security_group_id_for_name(&self, vpc_id: &str, group_name: &str) -> Option<String> {
        self.security_groups
            .values()
            .find(|group| {
                group.vpc_id.as_deref() == Some(vpc_id)
                    && group
                        .group_name
                        .as_deref()
                        .is_some_and(|held| held.eq_ignore_ascii_case(group_name))
            })
            .and_then(|group| group.group_id.clone())
    }

    /// The security group this account holds in `vpc_id` under `group_name`, as the
    /// `GroupIdentifier` a report carries — the id AND the name, however the caller named
    /// it.
    ///
    /// The ONE completion of a half-named group, so every resource that reports the groups
    /// a request named reports BOTH members of each one, the way AWS does: a launch that
    /// named `sg-…` reports that group's name beside it, and one that named a name reports
    /// its id. A group this account does not hold is reported exactly as the request named
    /// it, there being nothing to read the other member off.
    pub fn group_identifier_of(
        &self,
        vpc_id: Option<&str>,
        group_id: Option<&str>,
        group_name: Option<&str>,
    ) -> GroupIdentifier {
        if let Some(group_id) = group_id {
            return GroupIdentifier {
                group_id: Some(group_id.to_string()),
                group_name: self
                    .security_groups
                    .get(group_id)
                    .and_then(|group| group.group_name.clone())
                    .or_else(|| group_name.map(str::to_string)),
            };
        }
        GroupIdentifier {
            group_id: group_name
                .zip(vpc_id)
                .and_then(|(group_name, vpc_id)| {
                    self.security_group_id_for_name(vpc_id, group_name)
                }),
            group_name: group_name.map(str::to_string),
        }
    }

    /// The rules the group `group_id` holds in one direction, each beside the
    /// `SecurityGroupRuleId` the store minted for it — the inbound rules when `is_egress` is
    /// `false` and the outbound ones when it is `true`.
    ///
    /// The stored records read as the identities they stand for (see
    /// [`SecurityGroupRuleAtom::of_stored_rule`]); the store itself is not touched, so two
    /// reads of one group answer the same rules in the same order — id order, which is the
    /// order [`Self::resync_security_group_permissions`] reports them in.
    pub fn held_security_group_rules(
        &self,
        group_id: &str,
        is_egress: bool,
    ) -> Vec<(String, SecurityGroupRuleAtom)> {
        self.security_group_rules
            .iter()
            .filter(|(_, record)| {
                record.rule.group_id.as_deref() == Some(group_id)
                    && record.rule.is_egress.unwrap_or(false) == is_egress
            })
            .filter_map(|(rule_id, record)| {
                SecurityGroupRuleAtom::of_stored_rule(record).map(|atom| (rule_id.clone(), atom))
            })
            .collect()
    }

    /// What revoking `requested` from `group_id` would do, WITHOUT writing anything: see
    /// [`SecurityGroupRevoke`] for why the decision has to come before the write.
    ///
    /// A rule the request names twice is revoked once, and reported as unknown once: a
    /// request cannot remove one rule two times, and a repeat is not a second rule the
    /// group fails to hold either.
    ///
    /// One hash lookup per requested rule, against the group's rules and against the rules
    /// the request has already named, so a caller-sized batch costs time proportional to
    /// the batch (see [`SecurityGroupRuleKey`]).
    pub fn plan_security_group_revoke(
        &self,
        group_id: &str,
        is_egress: bool,
        requested: &[SecurityGroupRuleAtom],
    ) -> SecurityGroupRevoke {
        let held = self.held_security_group_rules(group_id, is_egress);
        // The group's own rules by identity, each remembered by the id it is stored under.
        // First one wins: a store that somehow held one rule twice still has one rule to
        // revoke.
        let mut by_identity: HashMap<SecurityGroupRuleKey, &str> =
            HashMap::with_capacity(held.len());
        for (rule_id, atom) in &held {
            by_identity.entry(atom.identity()).or_insert(rule_id);
        }
        let mut named: HashSet<SecurityGroupRuleKey> = HashSet::with_capacity(requested.len());
        let mut plan = SecurityGroupRevoke::default();
        for want in requested {
            let identity = want.identity();
            if !named.insert(identity.clone()) {
                continue;
            }
            match by_identity.get(&identity) {
                Some(rule_id) => plan.revoked.push((*rule_id).to_string()),
                None => plan.unknown.push(want.clone()),
            }
        }
        plan
    }

    /// Remove the stored rules `rule_ids` names, and answer them as they were last reported.
    ///
    /// The rules are the resources, so a revoke removes the RECORDS, and the bytes each one
    /// was charged go back to the store's budget on the terms they were taken on — the same
    /// terms [`Self::remove_security_group`] releases a group's rules on. Every group a rule
    /// was removed from is then resynced, so the aggregate `IpPermissions`
    /// `DescribeSecurityGroups` reports cannot disagree with the rules that are left.
    pub fn remove_security_group_rules(&mut self, rule_ids: &[String]) -> Vec<SecurityGroupRule> {
        let mut removed: Vec<SecurityGroupRule> = Vec::with_capacity(rule_ids.len());
        let mut groups: Vec<String> = Vec::new();
        for rule_id in rule_ids {
            let Some(record) = self.security_group_rules.remove(rule_id) else {
                continue;
            };
            self.release_stored_bytes(record.payload_bytes);
            if let Some(group_id) = record.rule.group_id.clone() {
                if !groups.contains(&group_id) {
                    groups.push(group_id);
                }
            }
            removed.push(record.rule);
        }
        for group_id in &groups {
            self.resync_security_group_permissions(group_id);
        }
        removed
    }

    /// Replace the rule stored under `rule_id` with the ONE rule `permission` describes, and
    /// answer the rule as it now stands — or `None` when the store holds no such rule.
    ///
    /// A security group rule is a RESOURCE, so a modification keeps the resource and replaces
    /// what it says: the id, the ARN, the group, its owner, the direction and the rule's tags
    /// are facts of the stored rule and survive, while the protocol, the port range, the one
    /// source or destination it names and its description are taken from `permission`. The
    /// replacement is built by [`security_group_rule_grants`] — the SAME reading
    /// [`Self::insert_security_group_rules`] stores a new rule through — so a modified rule and
    /// a freshly authorized one with the same members are stored identically, and
    /// `DescribeSecurityGroupRules` cannot tell which call wrote it.
    ///
    /// `permission` must describe exactly one grant: a modification acts on one rule, and a
    /// permission naming several would describe several. One naming none replaces nothing and
    /// answers `None`, so the stored rule is left as it was rather than emptied.
    ///
    /// BOUNDED: the record's caller-chosen bytes are recharged here — what the old record held
    /// is given back and the new one is charged ([`security_group_rule_payload_bytes`]), so a
    /// modification cannot grow the store's budget-counted bytes without the budget seeing it.
    /// A caller whose replacement may be larger than the rule it replaces asks
    /// [`Self::would_exceed_stored_bytes_after_refund`] first and refuses the whole request.
    /// The group's aggregate `IpPermissions` are recomputed, so `DescribeSecurityGroups` can
    /// never disagree with the rules that are stored.
    pub fn replace_security_group_rule(
        &mut self,
        rule_id: &str,
        permission: &IpPermission,
    ) -> Option<SecurityGroupRule> {
        let record = self.security_group_rules.get(rule_id)?;
        let group_id = record.rule.group_id.clone().unwrap_or_default();
        let is_egress = record.rule.is_egress.unwrap_or(false);
        let tags = record.rule.tags.clone().unwrap_or_default();
        let refund = record.payload_bytes;
        let security_group_rule_id = record.rule.security_group_rule_id.clone();
        let security_group_rule_arn = record.rule.security_group_rule_arn.clone();
        let (grant, referenced_group_name) =
            security_group_rule_grants(&group_id, is_egress, permission, &tags)
                .into_iter()
                .next()?;
        let mut replaced = SecurityGroupRuleRecord {
            rule: SecurityGroupRule {
                security_group_rule_id,
                security_group_rule_arn,
                ..grant
            },
            referenced_group_name,
            payload_bytes: 0,
        };
        // A modification is a REQUEST writing the rule, so what it leaves behind is
        // caller-supplied data whatever the old record was charged — which is why the refund
        // and the charge are separate: a service-written default rule a caller modifies was
        // charged nothing and starts being charged here.
        replaced.payload_bytes = security_group_rule_payload_bytes(&replaced);
        self.release_stored_bytes(refund);
        self.add_stored_bytes(replaced.payload_bytes);
        let answer = replaced.rule.clone();
        self.security_group_rules.insert(rule_id.to_string(), replaced);
        self.resync_security_group_permissions(&group_id);
        Some(answer)
    }
}

/// EC2's error code for a `CreateDefaultVpc` in a Region whose account already holds a
/// default VPC, named the way every other code of this crate is so one code is worded one
/// way across every operation.
pub const DEFAULT_VPC_ALREADY_EXISTS: &str = "DefaultVpcAlreadyExists";

/// Refuse a `CreateDefaultVpc` whose Region already has a default VPC: HTTP 400
/// [`DEFAULT_VPC_ALREADY_EXISTS`].
///
/// "You cannot have more than one default VPC per Region" (`CreateDefaultVpc`), so the
/// second request for one is refused rather than served with a second network. The sentence
/// names neither the Region nor the VPC already there: this error class has no variable part
/// — it says only that the account already has one where it asked.
pub fn default_vpc_already_exists<E>() -> Scaffolded<E> {
    Scaffolded::service_error(
        DEFAULT_VPC_ALREADY_EXISTS,
        400,
        "A Default VPC already exists for this account in this region.",
    )
}

/// The caller-chosen bytes one stored security group holds: its name, description and
/// tags. Charged against [`MAX_STORED_BYTES`] so the store is bounded in bytes and not
/// only in records.
pub fn security_group_payload_bytes(group: &SecurityGroup) -> usize {
    group.group_name.as_deref().map_or(0, str::len)
        + group.description.as_deref().map_or(0, str::len)
        + tag_list_bytes(group.tags.as_deref().unwrap_or_default())
}

/// The outbound rule every new security group carries: "a security group has an outbound
/// rule that allows all outbound traffic" (Amazon VPC User Guide, "Security group rules"),
/// which on the wire is the `-1` protocol over `0.0.0.0/0` — the same rule
/// [`ComAmazonawsEc2Amazonec2State::insert_default_security_group`] gives the default
/// group, so one definition serves both writers.
pub fn allow_all_egress() -> IpPermission {
    IpPermission {
        ip_protocol: Some(ALL_IP_PROTOCOLS.to_string()),
        // "For `tcp`, `udp`, and `icmp`, you must specify a port range"
        // (`IpPermission$IpProtocol`) — an all-protocols rule carries none.
        from_port: None,
        to_port: None,
        user_id_group_pairs: Some(Vec::new()),
        ip_ranges: Some(vec![IpRange {
            description: None,
            cidr_ip: Some(ALL_IPV4_ADDRESSES.to_string()),
        }]),
        ipv6_ranges: Some(Vec::new()),
        prefix_list_ids: Some(Vec::new()),
    }
}

// ---------------------------------------------------------------------------
// Security group RULE IDENTITY
// ---------------------------------------------------------------------------
//
// A group's rules are stored as RECORDS of their own ([`SecurityGroupRuleRecord`], keyed by
// the `SecurityGroupRuleId` the store mints), while a group's `IpPermissions` lists are the
// AGGREGATE view [`ComAmazonawsEc2Amazonec2State::resync_security_group_permissions`]
// recomputes from them. One `IpPermission` therefore stands for SEVERAL rules: its
// `IpRanges`, `Ipv6Ranges`, `PrefixListIds` and `UserIdGroupPairs` each name one SOURCE, and
// AWS counts ONE RULE PER SOURCE — "each rule has a protocol, from and to ports, and source
// (CIDR range, security group, or prefix list)" (`RevokeSecurityGroupIngress`).
//
// So a request that names rules by their PROPERTIES names them in the unit a stored record
// holds: one rule, a [`SecurityGroupRuleAtom`]. The record is the stored form, the permission
// is the reporting form, and the atom is the IDENTITY form — the one in which "the values
// that you specify … must match the existing rule's values exactly" is a single comparison.
// Keeping that translation here, once, is what stops the ingress and the egress path from
// reading one stored rule two different ways.

/// Where a security group rule's traffic comes from (an inbound rule) or goes to (an
/// outbound rule): exactly ONE of the four sources an [`IpPermission`] can name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecurityGroupRuleSource {
    /// An IPv4 CIDR block (`IpRange$CidrIp`).
    Ipv4(String),
    /// An IPv6 CIDR block (`Ipv6Range$CidrIpv6`).
    Ipv6(String),
    /// A prefix list (`PrefixListId$PrefixListId`).
    PrefixList(String),
    /// Another security group: its id where one is known, and otherwise the name the
    /// request or the stored pair carries — "for a security group in a nondefault VPC, use
    /// the security group ID" (`UserIdGroupPair$GroupName`), so a name is the default-VPC
    /// form of the same source and is resolved to an id before it is matched.
    ReferencedGroup(String),
}

/// ONE security group rule: a protocol, a port range and exactly one source.
///
/// The form a request NAMES a rule in and the form a stored rule is matched in, so "the
/// values that you specify … must match the existing rule's values exactly"
/// (`RevokeSecurityGroupIngress`) is one comparison — of [`Self::identity`] — rather than a
/// member-by-member walk at every call site. Deliberately NOT `PartialEq`: a rule's
/// IDENTITY leaves the description out, so an `==` that compared it would be a second,
/// quieter answer to the one question this type exists to answer.
#[derive(Debug, Clone)]
pub struct SecurityGroupRuleAtom {
    /// The protocol, canonical: see [`canonical_ip_protocol`].
    pub ip_protocol: String,
    /// The start of the port range, for the protocols that carry one.
    pub from_port: Option<i32>,
    /// The end of the port range, for the protocols that carry one.
    pub to_port: Option<i32>,
    /// What the rule allows traffic from (inbound) or to (outbound).
    pub source: SecurityGroupRuleSource,
    /// The rule's description, which is NOT part of its identity (see
    /// [`SecurityGroupRuleKey`]).
    pub description: Option<String>,
}

impl SecurityGroupRuleAtom {
    /// One rule, with its protocol and its source read into the canonical form a stored rule
    /// carries them in ([`canonical_ip_protocol`], [`canonical_rule_source`]), so a request
    /// that spells either differently still names the same rule.
    ///
    /// The port range is kept exactly as given — a rule's ports are values a request "must
    /// match … exactly" (`RevokeSecurityGroupIngress`), so neither end is dropped or
    /// defaulted for any protocol.
    pub fn new(
        ip_protocol: Option<&str>,
        from_port: Option<i32>,
        to_port: Option<i32>,
        source: SecurityGroupRuleSource,
        description: Option<String>,
    ) -> Self {
        let ip_protocol = canonical_ip_protocol(ip_protocol.unwrap_or(ALL_IP_PROTOCOLS).trim());
        Self {
            ip_protocol,
            from_port,
            to_port,
            source: canonical_rule_source(source),
            description,
        }
    }

    /// The rule a stored record holds, as the atom its identity is read in.
    ///
    /// The one translation from the STORED form to the identity form: a stored rule names
    /// exactly one source, and a referenced group is named by the id the rule carries where
    /// there is one and otherwise by the name its grant used
    /// (`SecurityGroupRuleRecord::referenced_group_name`), the two spellings of one source.
    pub fn of_stored_rule(record: &SecurityGroupRuleRecord) -> Option<Self> {
        let rule = &record.rule;
        let source = if let Some(cidr) = rule.cidr_ipv4.as_deref().filter(|it| !it.is_empty()) {
            SecurityGroupRuleSource::Ipv4(cidr.to_string())
        } else if let Some(cidr) = rule.cidr_ipv6.as_deref().filter(|it| !it.is_empty()) {
            SecurityGroupRuleSource::Ipv6(cidr.to_string())
        } else if let Some(prefix_list_id) = rule
            .prefix_list_id
            .as_deref()
            .filter(|it| !it.is_empty())
        {
            SecurityGroupRuleSource::PrefixList(prefix_list_id.to_string())
        } else {
            let named = rule
                .referenced_group_info
                .as_ref()
                .and_then(|referenced| referenced.group_id.as_deref())
                .or(record.referenced_group_name.as_deref())
                .filter(|named| !named.is_empty())?;
            SecurityGroupRuleSource::ReferencedGroup(named.to_string())
        };
        Some(Self::new(
            rule.ip_protocol.as_deref(),
            rule.from_port,
            rule.to_port,
            source,
            rule.description.clone(),
        ))
    }

    /// This rule as the SENTENCE a refusal names it by: its peer, its protocol, its port
    /// range and the action every security group rule carries.
    ///
    /// A security group rule is "a protocol, from and to ports, and source (CIDR range,
    /// security group, or prefix list)" (`RevokeSecurityGroupIngress`) and it only ever
    /// allows traffic — unlike a network ACL entry, which also denies
    /// (`NetworkAclEntry$RuleAction`) — so those are the members a rule is described by, in
    /// that order, whether or not it has been stored. No rule id: a request the service is
    /// refusing named its rule by these members rather than by an id, and a rule that was
    /// never stored has no id to name at all.
    ///
    /// For ICMP the port range is a type and a code rather than ports — "this is the ICMP
    /// type" (`IpPermission$FromPort`) and "this is the ICMP code" (`$ToPort`) — and a rule
    /// on a protocol that carries no port range is described without one.
    pub fn descriptor(&self) -> String {
        let peer = match &self.source {
            SecurityGroupRuleSource::Ipv4(cidr) | SecurityGroupRuleSource::Ipv6(cidr) => cidr,
            SecurityGroupRuleSource::PrefixList(prefix_list_id) => prefix_list_id,
            SecurityGroupRuleSource::ReferencedGroup(named) => named,
        };
        // "To specify all protocols, use -1" (`$IpProtocol`): the rule is on every protocol,
        // which is what it is described as. A protocol NAME is the word for the protocol and
        // a protocol NUMBER is the number itself.
        let protocol = if self.ip_protocol == ALL_IP_PROTOCOLS {
            "ALL".to_string()
        } else {
            self.ip_protocol.to_ascii_uppercase()
        };
        let range = match (self.from_port, self.to_port) {
            // BOTH ends, which is the only shape a rule's range has: "fromPort and toPort are
            // given together or not at all" is what
            // [`validate_ip_permission_port_range`] holds an authorized permission to, and a
            // protocol that carries no range has neither end.
            (Some(from_port), Some(to_port)) => {
                let (first, second) = if protocol_is_icmp(&self.ip_protocol) {
                    ("type", "code")
                } else {
                    ("from port", "to port")
                };
                format!(", {first}: {from_port}, {second}: {to_port}")
            }
            _ => String::new(),
        };
        format!("peer: {peer}, {protocol}{range}, ALLOW")
    }

    /// This rule's IDENTITY as a hashable key: see [`SecurityGroupRuleKey`]. The ONE way
    /// to ask whether two rules are the same rule — `left.identity() == right.identity()`
    /// — so there is no second, quieter comparison beside it.
    ///
    /// The description is deliberately left out — "if the security group rule has a
    /// description, you do not need to specify the description to revoke the rule"
    /// (`RevokeSecurityGroupIngress`).
    pub fn identity(&self) -> SecurityGroupRuleKey {
        SecurityGroupRuleKey {
            ip_protocol: self.ip_protocol.clone(),
            from_port: self.from_port,
            to_port: self.to_port,
            source: self.source.clone(),
        }
    }
}

/// What makes one security group rule the rule it is: its protocol, its port range and its
/// source — and NOT its description, which "you do not need to specify … to revoke the
/// rule" (`RevokeSecurityGroupIngress`).
///
/// A KEY rather than a predicate so a request's rules can be matched against a group's by
/// hash lookup: the work a request of N rules costs then grows with N rather than with
/// N times the rules the group holds, which is what keeps a caller-sized batch from costing
/// quadratic time (the batch itself is capped by the handler, at
/// [`MAX_RESOURCE_IDS`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecurityGroupRuleKey {
    pub(super) ip_protocol: String,
    pub(super) from_port: Option<i32>,
    pub(super) to_port: Option<i32>,
    pub(super) source: SecurityGroupRuleSource,
}

/// `source` in the form a stored rule carries it: a CIDR block with its host bits cleared
/// and rendered the one way the standard library renders an address — the form
/// [`canonical_security_group_cidr`] stores a grant's range in — so two spellings of one
/// block are one source. A value that is not a CIDR block at all is kept as given: it
/// matches no stored rule, which is the answer a request naming it has earned.
pub(super) fn canonical_rule_source(source: SecurityGroupRuleSource) -> SecurityGroupRuleSource {
    match source {
        SecurityGroupRuleSource::Ipv4(cidr) => SecurityGroupRuleSource::Ipv4(
            canonical_security_group_cidr(&cidr).unwrap_or_else(|_| cidr.trim().to_string()),
        ),
        SecurityGroupRuleSource::Ipv6(cidr) => SecurityGroupRuleSource::Ipv6(
            canonical_ipv6_cidr(&cidr)
                .unwrap_or_else(|_| cidr.trim().to_string())
                .to_ascii_lowercase(),
        ),
        other => other,
    }
}

/// The rules one [`IpPermission`] names — one per source — whether it came off a stored
/// group or out of a request.
///
/// A permission that names no source at all names no rule, so it yields nothing: every
/// security group rule has a source.
pub fn security_group_rule_atoms(permission: &IpPermission) -> Vec<SecurityGroupRuleAtom> {
    let protocol = permission.ip_protocol.as_deref();
    let from_port = permission.from_port;
    let to_port = permission.to_port;
    let mut atoms = Vec::new();
    let mut push = |source: SecurityGroupRuleSource, description: Option<String>| {
        atoms.push(SecurityGroupRuleAtom::new(
            protocol,
            from_port,
            to_port,
            source,
            description,
        ));
    };
    for range in permission.ip_ranges.iter().flatten() {
        if let Some(cidr) = range.cidr_ip.as_deref() {
            push(
                SecurityGroupRuleSource::Ipv4(cidr.to_string()),
                range.description.clone(),
            );
        }
    }
    for range in permission.ipv6_ranges.iter().flatten() {
        if let Some(cidr) = range.cidr_ipv6.as_deref() {
            push(
                SecurityGroupRuleSource::Ipv6(cidr.to_string()),
                range.description.clone(),
            );
        }
    }
    for entry in permission.prefix_list_ids.iter().flatten() {
        if let Some(prefix_list_id) = entry.prefix_list_id.as_deref() {
            push(
                SecurityGroupRuleSource::PrefixList(prefix_list_id.to_string()),
                entry.description.clone(),
            );
        }
    }
    for pair in permission.user_id_group_pairs.iter().flatten() {
        // The id where the pair carries one, the name otherwise: the two are the
        // nondefault-VPC and the default-VPC way of naming one group
        // (`UserIdGroupPair$GroupName`).
        let named = pair
            .group_id
            .as_deref()
            .or(pair.group_name.as_deref())
            .filter(|named| !named.is_empty());
        if let Some(named) = named {
            push(
                SecurityGroupRuleSource::ReferencedGroup(named.to_string()),
                pair.description.clone(),
            );
        }
    }
    atoms
}

/// The resource-id prefix a security group rule id carries, as the API Reference's own
/// rule ids read (`sgr-0123456789abcdef0`): the prefix alone, without the separator, which
/// is what [`prefixed_id_is_well_formed`] and [`require_well_formed_id`] read an id against
/// ([`ROUTE_SERVER_ID_PREFIX`] is spelled the same way). The same prefix
/// [`ComAmazonawsEc2Amazonec2State::insert_security_group_rule`] mints a stored rule's id
/// under, so an id a request names is read against the form the store issues.
pub const SECURITY_GROUP_RULE_ID_PREFIX: &str = "sgr";

/// A stored rule as the [`RevokedSecurityGroupRule`] a revoke reports it with: "details
/// about the revoked security group rules" (`RevokeSecurityGroupIngressResult`).
///
/// Every member is the STORED rule's own — including the id the store minted for it — so a
/// revoke reports the rule it removed rather than a reading of the request that named it.
pub fn revoked_security_group_rule(rule: &SecurityGroupRule) -> RevokedSecurityGroupRule {
    RevokedSecurityGroupRule {
        security_group_rule_id: rule.security_group_rule_id.clone(),
        group_id: rule.group_id.clone(),
        is_egress: rule.is_egress,
        ip_protocol: rule.ip_protocol.clone(),
        from_port: rule.from_port,
        to_port: rule.to_port,
        description: rule.description.clone(),
        cidr_ipv4: rule.cidr_ipv4.clone(),
        cidr_ipv6: rule.cidr_ipv6.clone(),
        prefix_list_id: rule.prefix_list_id.clone(),
        referenced_group_id: rule
            .referenced_group_info
            .as_ref()
            .and_then(|referenced| referenced.group_id.clone()),
    }
}

/// The rule `atom` as an [`IpPermission`] of its own — one rule, one source — which is how
/// a revoke reports the rules it did not find: "in some cases, `unknownIpPermissionSet`
/// might be in a different format from the request parameter"
/// (`RevokeSecurityGroupIngressResult$UnknownIpPermissions`).
pub fn ip_permission_for_rule(atom: &SecurityGroupRuleAtom) -> IpPermission {
    let mut permission = IpPermission {
        ip_protocol: Some(atom.ip_protocol.clone()),
        from_port: atom.from_port,
        to_port: atom.to_port,
        user_id_group_pairs: Some(Vec::new()),
        ip_ranges: Some(Vec::new()),
        ipv6_ranges: Some(Vec::new()),
        prefix_list_ids: Some(Vec::new()),
    };
    match &atom.source {
        SecurityGroupRuleSource::Ipv4(cidr) => {
            permission.ip_ranges = Some(vec![IpRange {
                description: atom.description.clone(),
                cidr_ip: Some(cidr.clone()),
            }]);
        }
        SecurityGroupRuleSource::Ipv6(cidr) => {
            permission.ipv6_ranges = Some(vec![Ipv6Range {
                description: atom.description.clone(),
                cidr_ipv6: Some(cidr.clone()),
            }]);
        }
        SecurityGroupRuleSource::PrefixList(prefix_list_id) => {
            permission.prefix_list_ids = Some(vec![PrefixListId {
                description: atom.description.clone(),
                prefix_list_id: Some(prefix_list_id.clone()),
            }]);
        }
        SecurityGroupRuleSource::ReferencedGroup(named) => {
            // A source group is named by id where the request named one or the name
            // resolved to one, and by NAME where it did not — "[Default VPC] The name of
            // the source security group" (`UserIdGroupPair$GroupName`) is the member for
            // that, so an unresolved name is reported there rather than as an id no group
            // of the account answers to.
            let by_id = security_group_id_is_well_formed(named);
            permission.user_id_group_pairs = Some(vec![UserIdGroupPair {
                description: atom.description.clone(),
                user_id: Some(::engine::emulator_account_id().to_string()),
                group_name: (!by_id).then(|| named.clone()),
                group_id: by_id.then(|| named.clone()),
                vpc_id: None,
                vpc_peering_connection_id: None,
                peering_status: None,
            }]);
        }
    }
    permission
}

/// What revoking a set of rules from one security group would do: the stored rules the
/// request named, and the rules the group does not hold.
///
/// Answered BEFORE anything is written, because the two kinds of VPC part company on the
/// second list: "for a default VPC, if the values you specify do not match the existing
/// rule's values, no error is returned, and the output describes the security group rules
/// that were not revoked. For a non-default VPC … an `InvalidPermission.NotFound` client
/// error is returned, and no rules are revoked" (`RevokeSecurityGroupIngress`).
#[derive(Debug, Clone, Default)]
pub struct SecurityGroupRevoke {
    /// The `SecurityGroupRuleId` of each rule the group holds and the request named, in the
    /// order the request named them — the ids
    /// [`ComAmazonawsEc2Amazonec2State::remove_security_group_rules`] takes, so what gets
    /// reported is the STORED rule rather than a reading of the request.
    pub revoked: Vec<String>,
    /// The rules the request named that the group does not hold.
    pub unknown: Vec<SecurityGroupRuleAtom>,
}

/// One stored security group rule: the modelled [`SecurityGroupRule`] every operation that
/// reports one answers with, beside the one fact that shape carries no member for.
///
/// The rule is kept as the modelled shape itself — the way the VPC, subnet and security
/// group stores keep theirs — so every member a writer sets round-trips through
/// `DescribeSecurityGroupRules` without a field-by-field copy that can silently drop one.
#[derive(Debug, Clone)]
pub struct SecurityGroupRuleRecord {
    /// The rule as `DescribeSecurityGroupRules` reports it.
    pub rule: SecurityGroupRule,
    /// The NAME the grant named the referenced group by, for a rule that references one:
    /// "[Default VPC] The name of the source security group"
    /// (`AuthorizeSecurityGroupIngressRequest$SourceSecurityGroupName`). The rule shape has
    /// no member for it — `SecurityGroupRule$ReferencedGroupInfo` is a
    /// [`ReferencedSecurityGroup`], which carries only the id — while the aggregate
    /// `SecurityGroup$IpPermissions` view does (`UserIdGroupPair$GroupName`), so it is held
    /// beside the rule rather than lost.
    pub referenced_group_name: Option<String>,
    /// The bytes this record is charged for — the fixed per-record overhead plus the
    /// caller-chosen bytes it retains — counted into the store's budget while it is stored,
    /// and zero for a rule the SERVICE wrote, which the budget
    /// ([`MAX_STORED_BYTES`], a bound on caller-supplied data) does not count. Held on the
    /// record so [`ComAmazonawsEc2Amazonec2State::remove_security_group`] gives back exactly
    /// what the insert took, the way [`LaunchTemplateRecord::payload_bytes`] does.
    pub payload_bytes: usize,
}

/// What the rules of a request would ask of a group's quota buckets in ONE direction.
///
/// The rules-per-security-group quota is counted per bucket — one per group, direction and
/// address family — so a demand is not a single number: a request naming IPv4 and IPv6
/// grants asks of two buckets at once, and a grant that names no address family asks of
/// every bucket. The record count is held beside them because a rule counted in two buckets
/// is still ONE stored record, which is what the store's own ceiling
/// ([`MAX_SECURITY_GROUP_RULES`]) is weighed in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SecurityGroupRuleDemand {
    /// How many rules would be stored, each counted once however many buckets it falls in.
    pub(super) records: usize,
    /// How many of them fall in the IPv4 bucket of the direction.
    pub(super) ipv4: usize,
    /// How many of them fall in the IPv6 bucket of the direction.
    pub(super) ipv6: usize,
}

impl SecurityGroupRuleDemand {
    /// Count `rules` more rules whose grant is of `family` — or of no address family, when
    /// it is `None`, which is a rule counted in EVERY bucket.
    pub fn charge(&mut self, family: Option<AddressFamily>, rules: usize) {
        self.records = self.records.saturating_add(rules);
        if family.is_none_or(|family| family == AddressFamily::Ipv4) {
            self.ipv4 = self.ipv4.saturating_add(rules);
        }
        if family.is_none_or(|family| family == AddressFamily::Ipv6) {
            self.ipv6 = self.ipv6.saturating_add(rules);
        }
    }

    /// The demand of `rules` rules that each grant one range of `family` — what a caller
    /// that counts in one family alone asks with.
    pub fn in_family(family: AddressFamily, rules: usize) -> Self {
        let mut demand = Self::default();
        demand.charge(Some(family), rules);
        demand
    }

    /// How many of these rules fall in `family`'s bucket of the direction.
    pub fn in_bucket(self, family: AddressFamily) -> usize {
        match family {
            AddressFamily::Ipv4 => self.ipv4,
            AddressFamily::Ipv6 => self.ipv6,
        }
    }

    /// How many records the store would hold for these rules.
    pub fn records(self) -> usize {
        self.records
    }
}

/// How many rules one [`IpPermission`] grants: one per value it names, since "If you
/// specify multiple values for a parameter … a separate rule is created for each value"
/// (Amazon VPC User Guide, "Security group rules").
///
/// The ONE definition of that count, shared by
/// [`ComAmazonawsEc2Amazonec2State::insert_security_group_rules`], which weighs it against
/// the per-direction quota, and by the writers that assert every grant was stored, so the
/// quota and the check cannot count a permission differently.
pub fn ip_permission_grant_count(permission: &IpPermission) -> usize {
    permission.ip_ranges.iter().flatten().count()
        + permission.ipv6_ranges.iter().flatten().count()
        + permission.prefix_list_ids.iter().flatten().count()
        + permission.user_id_group_pairs.iter().flatten().count()
}

/// The rules one [`IpPermission`] grants on `group_id`, each beside the NAME its grant named
/// a referenced group by — the rules as they will be stored, minus what the service itself
/// mints for them (the rule id and its ARN).
///
/// The ONE definition of WHICH rules a permission describes: the protocol, the port range
/// and the tags are facts of the permission, so every rule it grants carries them, while the
/// one destination and the description belong to the grant.
///
/// Reached only from [`ComAmazonawsEc2Amazonec2State::insert_security_group_rules`], and only
/// AFTER it has weighed the whole permission against the per-direction quota, so the rules
/// built here are at most that quota's worth — the same records the store is about to hold.
/// A writer that wants the SIZE of those rules before any of them exists asks
/// [`security_group_rules_charge`], which counts lengths instead of building anything.
pub(super) fn security_group_rule_grants(
    group_id: &str,
    is_egress: bool,
    permission: &IpPermission,
    tags: &[Tag],
) -> Vec<(SecurityGroupRule, Option<String>)> {
    // What every rule of this permission shares; the grant each one names is set on the
    // clones below.
    let template = SecurityGroupRule {
        group_id: Some(group_id.to_string()),
        group_owner_id: Some(::engine::emulator_account_id().to_string()),
        is_egress: Some(is_egress),
        ip_protocol: permission.ip_protocol.clone(),
        from_port: permission.from_port,
        to_port: permission.to_port,
        // "The tags applied to the security group rule"
        // (`AuthorizeSecurityGroupEgressRequest$TagSpecifications`): a tag specification
        // applies to the resources the call creates, which is every rule of the permission.
        tags: Some(tags.to_vec()),
        ..SecurityGroupRule::default()
    };
    let mut grants: Vec<(SecurityGroupRule, Option<String>)> = Vec::new();
    for range in permission.ip_ranges.iter().flatten() {
        grants.push((
            SecurityGroupRule {
                cidr_ipv4: range.cidr_ip.clone(),
                description: range.description.clone(),
                ..template.clone()
            },
            None,
        ));
    }
    for range in permission.ipv6_ranges.iter().flatten() {
        grants.push((
            SecurityGroupRule {
                cidr_ipv6: range.cidr_ipv6.clone(),
                description: range.description.clone(),
                ..template.clone()
            },
            None,
        ));
    }
    for entry in permission.prefix_list_ids.iter().flatten() {
        grants.push((
            SecurityGroupRule {
                prefix_list_id: entry.prefix_list_id.clone(),
                description: entry.description.clone(),
                ..template.clone()
            },
            None,
        ));
    }
    for pair in permission.user_id_group_pairs.iter().flatten() {
        grants.push((
            SecurityGroupRule {
                // "Describes the security group that is referenced in the rule"
                // (`SecurityGroupRule$ReferencedGroupInfo`): the same facts the permission's
                // `UserIdGroupPair` carries, minus the ones that belong to the grant rather
                // than to the referenced group (its name, which is not a member of
                // `ReferencedSecurityGroup`, and the description, which is the rule's own).
                referenced_group_info: Some(ReferencedSecurityGroup {
                    group_id: pair.group_id.clone(),
                    user_id: pair.user_id.clone(),
                    vpc_id: pair.vpc_id.clone(),
                    vpc_peering_connection_id: pair.vpc_peering_connection_id.clone(),
                    peering_status: pair.peering_status.clone(),
                }),
                description: pair.description.clone(),
                ..template.clone()
            },
            pair.group_name.clone(),
        ));
    }
    grants
}

/// The bytes the rules `permissions` describe will be charged against [`MAX_STORED_BYTES`]
/// once stored, with `tags` on every one of them.
///
/// What a writer of SEVERAL permissions asks BEFORE it stores any of them, so a request that
/// would pass the store's byte budget is refused with nothing stored rather than part-way
/// through. Counted over the rules [`security_group_rule_grants`] says the permissions
/// describe, with the same [`security_group_rule_payload_bytes`] the stored record is charged
/// with, so the question asked here and the charge made later cannot come to differ. The
/// group and the direction the rules will belong to are not charged for, which is why this
/// needs neither.
pub fn security_group_rules_charge(permissions: &[IpPermission], tags: &[Tag]) -> usize {
    let text = |value: &Option<String>| value.as_deref().map_or(0, str::len);
    // The tags one specification applies to every rule are weighed ONCE and counted per
    // rule, never cloned onto each of them, and no rule is built to weigh it: answering this
    // allocates nothing and is linear in the request, where building the rules would be the
    // product of its grant count and its tag count — and this is the guard that runs BEFORE
    // the store's budget has admitted anything.
    let tag_bytes = tag_list_bytes(tags);
    let mut charge = 0usize;
    for permission in permissions {
        // The protocol is a fact of the PERMISSION that every rule it describes keeps a copy
        // of ([`security_group_rule_grants`] clones it onto each), so it is weighed once here
        // and counted per rule, the way the tags above are.
        let protocol_bytes = text(&permission.ip_protocol);
        for range in permission.ip_ranges.iter().flatten() {
            charge = charge.saturating_add(security_group_rule_charge(
                protocol_bytes,
                text(&range.cidr_ip),
                text(&range.description),
                0,
                tag_bytes,
            ));
        }
        for range in permission.ipv6_ranges.iter().flatten() {
            charge = charge.saturating_add(security_group_rule_charge(
                protocol_bytes,
                text(&range.cidr_ipv6),
                text(&range.description),
                0,
                tag_bytes,
            ));
        }
        for entry in permission.prefix_list_ids.iter().flatten() {
            charge = charge.saturating_add(security_group_rule_charge(
                protocol_bytes,
                text(&entry.prefix_list_id),
                text(&entry.description),
                0,
                tag_bytes,
            ));
        }
        for pair in permission.user_id_group_pairs.iter().flatten() {
            charge = charge.saturating_add(security_group_rule_charge(
                protocol_bytes,
                0,
                text(&pair.description),
                // The name the grant referenced its group by, plus every member of the
                // reference itself through the one definition of that term, so a member
                // added to the shape is added to this charge and to the stored one at once.
                text(&pair.group_name).saturating_add(referenced_group_bytes(
                    &pair.group_id,
                    &pair.user_id,
                    &pair.vpc_id,
                    &pair.vpc_peering_connection_id,
                    &pair.peering_status,
                )),
                tag_bytes,
            ));
        }
    }
    charge
}

/// The caller-chosen bytes a rule's REFERENCED GROUP retains, as every member of
/// [`ReferencedSecurityGroup`] the store keeps.
///
/// The ONE definition of that term, taken by the members rather than by either shape, because
/// the two sites that need it hold the same facts in different shapes: a request's
/// `UserIdGroupPair` before any rule exists ([`security_group_rules_charge`]) and the stored
/// `ReferencedSecurityGroup` afterwards ([`security_group_rule_payload_bytes`]). Counting
/// them here is what keeps the charge a request is admitted under equal to the charge its
/// record is given and the delete gives back — every member the record retains, so a member
/// added to the shape is added to both charges at once. The name a grant referenced its group
/// by is not one of them: it is not a member of that shape, and each caller adds it from where
/// it keeps it.
pub(super) fn referenced_group_bytes(
    group_id: &Option<String>,
    user_id: &Option<String>,
    vpc_id: &Option<String>,
    vpc_peering_connection_id: &Option<String>,
    peering_status: &Option<String>,
) -> usize {
    let text = |value: &Option<String>| value.as_deref().map_or(0, str::len);
    text(group_id)
        .saturating_add(text(user_id))
        .saturating_add(text(vpc_id))
        .saturating_add(text(vpc_peering_connection_id))
        .saturating_add(text(peering_status))
}

/// What ONE stored security group rule costs the store: the fixed per-record overhead plus
/// the caller-chosen bytes it retains, grouped as the protocol it carries, the destination it
/// names, its description, the group it references (every member of that reference, counted by
/// [`referenced_group_bytes`], plus the name the grant named it by) and its tags.
///
/// Every term is a string the REQUEST chooses the length of and the RECORD retains: one left
/// out is bytes the store holds against no budget, so a member added to the stored rule
/// belongs in a term here. Taking them as separate parameters is what makes that addition a
/// compile error at both call sites rather than a silent undercount at one.
///
/// The ONE definition of a rule's charge, shared by [`security_group_rule_payload_bytes`],
/// which weighs a record that exists, and by [`security_group_rules_charge`], which weighs
/// the rules a request describes before any of them is built — so a request cannot be
/// admitted under one arithmetic and charged under another.
pub(super) fn security_group_rule_charge(
    protocol: usize,
    destination: usize,
    description: usize,
    referenced_group: usize,
    tags: usize,
) -> usize {
    STORED_RECORD_OVERHEAD_BYTES
        .saturating_add(protocol)
        .saturating_add(destination)
        .saturating_add(description)
        .saturating_add(referenced_group)
        .saturating_add(tags)
}

/// The bytes one stored security group rule holds: the fixed
/// [`STORED_RECORD_OVERHEAD_BYTES`] every stored record costs, plus every string the record
/// retains — the protocol it carries, the grant it names, its description, every member of
/// the group it references ([`referenced_group_bytes`]) and its tags.
///
/// The fixed overhead is charged here for the same reason every other store of this module
/// charges it ([`host_payload_bytes`]'s caller, the launch-template and IPAM-pool inserts):
/// a rule naming a tiny grant with no description still costs the store a record, so a loop
/// of authorize calls minting such rules cannot be nearly free against
/// [`MAX_STORED_BYTES`].
///
/// Charged against [`MAX_STORED_BYTES`] by
/// [`ComAmazonawsEc2Amazonec2State::insert_security_group_rules`] for a rule a REQUEST
/// named, recorded on [`SecurityGroupRuleRecord::payload_bytes`] and given back by
/// [`ComAmazonawsEc2Amazonec2State::remove_security_group`], so a group's rules are as
/// bounded in bytes as the group itself.
/// Counted as [`security_group_rule_charge`]'s terms, the same arithmetic
/// [`security_group_rules_charge`] admits a request under.
pub fn security_group_rule_payload_bytes(record: &SecurityGroupRuleRecord) -> usize {
    let rule = &record.rule;
    let text = |value: &Option<String>| value.as_deref().map_or(0, str::len);
    let referenced = rule.referenced_group_info.as_ref();
    security_group_rule_charge(
        text(&rule.ip_protocol),
        text(&rule.cidr_ipv4)
            .saturating_add(text(&rule.cidr_ipv6))
            .saturating_add(text(&rule.prefix_list_id)),
        text(&rule.description),
        text(&record.referenced_group_name).saturating_add(referenced.map_or(0, |group| {
            referenced_group_bytes(
                &group.group_id,
                &group.user_id,
                &group.vpc_id,
                &group.vpc_peering_connection_id,
                &group.peering_status,
            )
        })),
        tag_list_bytes(rule.tags.as_deref().unwrap_or_default()),
    )
}

/// One stored launch template: the modelled [`LaunchTemplate`] every operation that reports
/// one answers with, plus the versions the template holds.
///
/// The template is kept as the modelled shape itself — the way the VPC and subnet stores
/// keep theirs — so every member a writer sets round-trips through every reader without a
/// field-by-field copy that can silently drop one.
#[derive(Debug, Clone)]
pub struct LaunchTemplateRecord {
    /// The template as `CreateLaunchTemplate` and `DeleteLaunchTemplate` report it.
    pub template: LaunchTemplate,
    /// The template's versions, by `VersionNumber`. `CreateLaunchTemplate` stores the
    /// first one; a delete of the template takes all of them with it.
    pub versions: BTreeMap<i64, LaunchTemplateVersionRecord>,
    /// The highest version number this template has ever minted, which is the number the
    /// NEXT version is counted from.
    ///
    /// Kept beside the versions because the two facts come apart as soon as a version is
    /// deleted: `LaunchTemplate$LatestVersionNumber` is "the version number of the latest
    /// version of the launch template", so deleting the latest version moves it down to the
    /// highest version the template still holds, while "you can't specify, change, or
    /// replace the numbering of launch template versions"
    /// (`CreateLaunchTemplateVersion`) means the number that version carried is never
    /// minted a second time.
    pub highest_version_minted: i64,
    /// The caller-chosen bytes this record retains, counted into the store's budget while
    /// it is stored.
    pub payload_bytes: usize,
}

impl LaunchTemplateRecord {
    /// The template's own id, which is also the key the store holds it under.
    pub fn launch_template_id(&self) -> &str {
        self.template
            .launch_template_id
            .as_deref()
            .unwrap_or_default()
    }

    /// The template's name, the second key a caller may name it by.
    pub fn launch_template_name(&self) -> &str {
        self.template
            .launch_template_name
            .as_deref()
            .unwrap_or_default()
    }
}

/// One version of a stored launch template: the launch parameters the caller gave for it,
/// kept verbatim, beside what the service recorded about the version itself.
#[derive(Debug, Clone)]
pub struct LaunchTemplateVersionRecord {
    /// This version's number; the first version is [`FIRST_LAUNCH_TEMPLATE_VERSION`].
    pub version_number: i64,
    /// The description the caller gave the version, if it gave one.
    pub version_description: Option<String>,
    /// When the version was created.
    pub create_time: SystemTime,
    /// The principal that created it.
    pub created_by: String,
    /// Whether this is the template's default version.
    pub default_version: bool,
    /// The launch parameters, exactly as the request carried them, so nothing a caller set
    /// is dropped by the store.
    pub data: RequestLaunchTemplateData,
}

/// One launch template as a writer asks for it: the members a creator chooses. Everything
/// the service derives — the launch template id, and the default and latest version
/// numbers — is minted by [`ComAmazonawsEc2Amazonec2State::insert_launch_template`].
#[derive(Debug, Clone)]
pub struct LaunchTemplateSpec {
    /// The template's name, already checked against the modelled `LaunchTemplateName`
    /// constraints by [`launch_template_name_is_well_formed`].
    pub name: String,
    /// The principal that created it, as `LaunchTemplate$CreatedBy` reports it.
    pub created_by: String,
    /// When it was created.
    pub create_time: SystemTime,
    /// The tags the create asked for.
    pub tags: Vec<Tag>,
    /// The service provider that manages the template, when the request named one; a
    /// template no provider manages is stored with the answer
    /// [`unmanaged_launch_template_operator`] gives instead.
    pub operator: Option<OperatorResponse>,
    /// The description of the first version.
    pub version_description: Option<String>,
    /// The first version's launch parameters.
    pub data: RequestLaunchTemplateData,
}

/// The `Operator` a launch template of THIS account reports when no service provider
/// manages it.
///
/// "Describes whether the resource is managed by a service provider and, if so, describes the
/// service provider that manages it" (`OperatorResponse`), where "if `true`, the resource is
/// managed by a service provider" (`$Managed`) and "if `managed` is `true`, then the
/// principal is returned" (`$Principal`) — so a template the caller created for itself
/// answers the question with `false` and names no principal: the member reports the ANSWER,
/// and a template nobody manages still has one.
///
/// `HiddenByDefault` is "if `true`, the resource is hidden by default based on the managed
/// resource visibility settings for the account", which nothing in this emulator sets, so it
/// is reported absent rather than guessed — the one difference from [`unmanaged_operator`],
/// which the volume and network-interface stores use for the resources THEY keep.
///
/// The ONE reading of that answer for a launch template, so the template's own reports and
/// the versions' cannot differ about it.
pub fn unmanaged_launch_template_operator() -> OperatorResponse {
    OperatorResponse {
        managed: Some(false),
        principal: None,
        hidden_by_default: None,
    }
}

/// The caller-chosen bytes one stored launch template retains.
///
/// A version keeps the WHOLE `RequestLaunchTemplateData` — dozens of members, most of them
/// caller-chosen strings and lists — so counting a handful of members by hand would leave
/// most of what the store holds unaccounted for. The `Debug` rendering visits every member
/// and its length grows with all of them, which is the measure the store's byte ceiling
/// needs: it is used to decide whether the record fits, never reported to anyone.
pub fn launch_template_payload_bytes(spec: &LaunchTemplateSpec) -> usize {
    spec.name.len()
        + spec.version_description.as_ref().map_or(0, String::len)
        + tag_list_bytes(&spec.tags)
        + format!("{:?}", spec.data).len()
}

/// One new version of a stored launch template as a writer asks for it: the members a
/// creator chooses. The version NUMBER is not among them — it is minted by
/// [`ComAmazonawsEc2Amazonec2State::insert_launch_template_version`], because "you can't
/// specify, change, or replace the numbering of launch template versions"
/// (`CreateLaunchTemplateVersion`).
#[derive(Debug, Clone)]
pub struct LaunchTemplateVersionSpec {
    /// The principal that created the version, as `LaunchTemplateVersion$CreatedBy` reports
    /// it.
    pub created_by: String,
    /// When it was created.
    pub create_time: SystemTime,
    /// The description the caller gave the version, if it gave one.
    pub version_description: Option<String>,
    /// The version's launch parameters, exactly as the request carried them.
    pub data: RequestLaunchTemplateData,
}

/// The caller-chosen bytes one stored launch template VERSION retains.
///
/// The same measure [`launch_template_payload_bytes`] takes of a template's first version,
/// for the versions created after it: the `Debug` rendering visits every member of the whole
/// `RequestLaunchTemplateData` and its length grows with all of them, which is the measure
/// the store's byte ceiling needs. It is used to decide whether the version fits, never
/// reported to anyone.
pub fn launch_template_version_payload_bytes(spec: &LaunchTemplateVersionSpec) -> usize {
    version_payload_bytes(spec.version_description.as_deref(), &spec.data)
}

/// The caller-chosen bytes one STORED launch template version retains, for the delete that
/// gives them back ([`ComAmazonawsEc2Amazonec2State::remove_launch_template_version`]).
///
/// The same measure [`launch_template_version_payload_bytes`] charged when the version was
/// stored — both read it off [`version_payload_bytes`] — so a version can never release a
/// different number of bytes from the one it was charged.
pub fn launch_template_version_record_bytes(version: &LaunchTemplateVersionRecord) -> usize {
    version_payload_bytes(version.version_description.as_deref(), &version.data)
}

/// The ONE measure of a launch template version's caller-chosen bytes, taken off the two
/// members that carry them, so the writer that charges a version and the delete that gives
/// its bytes back cannot measure it differently — and neither has to copy the version to ask.
fn version_payload_bytes(
    version_description: Option<&str>,
    data: &RequestLaunchTemplateData,
) -> usize {
    version_description.map_or(0, str::len) + format!("{data:?}").len()
}

/// The id prefix every launch template id carries, which is also what
/// [`ComAmazonawsEc2Amazonec2State::insert_launch_template`] mints one under.
pub const LAUNCH_TEMPLATE_ID_PREFIX: &str = "lt";

/// Whether `id` is a well-formed launch template id.
///
/// A launch template id is `lt-` followed by 8 or 17 lowercase hexadecimal digits — the
/// short and the long id form, the same two every EC2 resource id has. EC2 answers
/// `InvalidLaunchTemplateId.Malformed` for anything else, BEFORE it looks the id up, which
/// is a different answer from `InvalidLaunchTemplateId.NotFound` for a well-formed id no
/// template was created for.
pub fn launch_template_id_is_well_formed(id: &str) -> bool {
    let Some(suffix) = id.strip_prefix("lt-") else {
        return false;
    };
    matches!(suffix.len(), 8 | 17)
        && suffix
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `name` is a name a launch template can carry: [`MIN_LAUNCH_TEMPLATE_NAME_CHARS`]
/// to [`MAX_LAUNCH_TEMPLATE_NAME_CHARS`] characters, each of them an ASCII letter, an ASCII
/// digit or one of [`LAUNCH_TEMPLATE_NAME_PUNCTUATION`].
///
/// `CreateLaunchTemplate$LaunchTemplateName` targets a plain `String` with no constraints
/// of its own, while `LaunchTemplate$LaunchTemplateName` — the member every reader reports
/// the name through — and `DeleteLaunchTemplate$LaunchTemplateName` target the modelled
/// `LaunchTemplateName`, whose `@length` is 3..128 and whose `@pattern` is
/// `^[a-zA-Z0-9\(\)\.\-/_]+$`
/// (`smithy_query(query="shape",shape="LaunchTemplateName")`). A create the boundary
/// validator lets through with a name outside that would store a template no reader could
/// report and no caller could name, so the handler refuses it here.
pub fn launch_template_name_is_well_formed(name: &str) -> bool {
    let characters = name.chars().count();
    (MIN_LAUNCH_TEMPLATE_NAME_CHARS..=MAX_LAUNCH_TEMPLATE_NAME_CHARS).contains(&characters)
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || LAUNCH_TEMPLATE_NAME_PUNCTUATION.contains(c))
}

/// Which KEY a request names a launch template by.
///
/// The REQUEST-ONLY half of [`resolve_launch_template_id`]: reading it asks nothing of the
/// store, so an operation that has to refuse a bad key combination before it answers a
/// `DryRun` — the permission question being about the caller rather than about what the
/// account holds — can read the key here and resolve it later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchTemplateKey<'request> {
    /// The template was named by its id.
    Id(&'request str),
    /// The template was named by its name.
    Name(&'request str),
}

/// The key a request names a launch template by, or the refusal for naming both or neither.
///
/// "You must specify either the launch template ID or the launch template name, but not
/// both" (`DeleteLaunchTemplate$LaunchTemplateId`), so naming both is refused as a parameter
/// combination and naming neither as a missing parameter. The ONE place that rule lives, so
/// every operation that takes a launch template reference refuses the same two mistakes the
/// same way.
pub fn launch_template_key<'request, E>(
    launch_template_id: Option<&'request str>,
    launch_template_name: Option<&'request str>,
) -> Result<LaunchTemplateKey<'request>, crate::scaffolded::Scaffolded<E>> {
    match (launch_template_id, launch_template_name) {
        (Some(_), Some(_)) => Err(crate::scaffolded::Scaffolded::invalid_parameter_combination(
            "Either the launch template ID or the launch template name may be specified, \
             but not both",
        )),
        (Some(id), None) => Ok(LaunchTemplateKey::Id(id)),
        (None, Some(name)) => Ok(LaunchTemplateKey::Name(name)),
        (None, None) => Err(crate::scaffolded::Scaffolded::missing_parameter(
            "The request must contain either the parameter LaunchTemplateId or the \
             parameter LaunchTemplateName",
        )),
    }
}

/// Resolve the one launch template a request names, by id or by name.
///
/// The key is read first ([`launch_template_key`]), before either half is looked up. An id is
/// checked for shape next, the way EC2 orders a malformed id ahead of an unknown one; a name
/// has no shape to be wrong, so an unknown name is simply not found.
pub fn resolve_launch_template_id<E>(
    store: &ComAmazonawsEc2Amazonec2State,
    launch_template_id: Option<&str>,
    launch_template_name: Option<&str>,
) -> Result<String, crate::scaffolded::Scaffolded<E>> {
    match launch_template_key(launch_template_id, launch_template_name)? {
        LaunchTemplateKey::Id(id) => {
            if !launch_template_id_is_well_formed(id) {
                return Err(invalid_launch_template_id_malformed(id));
            }
            if !store.launch_templates.contains_key(id) {
                return Err(invalid_launch_template_id_not_found());
            }
            Ok(id.to_string())
        }
        LaunchTemplateKey::Name(name) => store
            .launch_template_id_for_name(name)
            .ok_or_else(invalid_launch_template_name_not_found),
    }
}

/// Refuse a create that would take the account past the number of launch templates it may
/// hold: HTTP 400 `LaunchTemplateLimitExceeded`.
pub fn launch_template_limit_exceeded<E>(
    message: impl Into<String>,
) -> crate::scaffolded::Scaffolded<E> {
    crate::scaffolded::Scaffolded::service_error(LAUNCH_TEMPLATE_LIMIT_EXCEEDED, 400, message)
}

/// Refuse a request that named a launch template id no launch template of the account has:
/// HTTP 400 `InvalidLaunchTemplateId.NotFound`.
///
/// The sentence is EC2's, and it is FIXED: `At least one of the launch templates specified in
/// the request does not exist.` names neither the request's values nor how many of them could
/// not be resolved — a request may name several, and the service reports that at least one of
/// them is absent rather than which. It is the SAME sentence
/// [`invalid_launch_template_name_not_found`] carries under the name code, a template a caller
/// named by either key being absent in exactly one way. Recorded by the corpus unit
/// `ec2.ec2-run-from-launch-template`, which deletes a launch template and then reads and
/// launches from it.
pub fn invalid_launch_template_id_not_found<E>() -> crate::scaffolded::Scaffolded<E> {
    crate::scaffolded::Scaffolded::service_error(
        INVALID_LAUNCH_TEMPLATE_ID_NOT_FOUND,
        400,
        "At least one of the launch templates specified in the request does not exist.",
    )
}

/// Refuse a request that named something that is not a launch template id at all: HTTP 400
/// `InvalidLaunchTemplateId.Malformed`.
pub fn invalid_launch_template_id_malformed<E>(
    launch_template_id: &str,
) -> crate::scaffolded::Scaffolded<E> {
    crate::scaffolded::Scaffolded::service_error(
        INVALID_LAUNCH_TEMPLATE_ID_MALFORMED,
        400,
        format!("Invalid launch template ID: '{launch_template_id}'"),
    )
}

/// Refuse a launch template id an operation with EC2's STRICT launch-template validator
/// could not resolve, in the wording that names the id as "specified": HTTP 400
/// [`INVALID_LAUNCH_TEMPLATE_ID_MALFORMED`], `The specified launch template ID '<id>' is
/// malformed.`
///
/// A SECOND wording of that code beside [`invalid_launch_template_id_malformed`] (which says
/// `Invalid launch template ID: '<id>'`) and [`launch_template_ids_malformed`] (which names a
/// LIST of them), and a named constructor rather than a literal at a call site for the reason
/// [`crate::scaffolded::Scaffolded::instance_id_is_malformed`] is one: EC2's per-operation
/// validators do not agree about an id they cannot resolve, and WHICH wording an operation
/// answers is a fact of that operation, recorded by its caller — `ec2.create-fleet-contract`
/// pins this sentence for `CreateFleet`. The one variable part is the id the request sent,
/// cut to length by [`echoed_resource_id`] the way every refusal of this crate bounds a value
/// it repeats back.
pub fn specified_launch_template_id_is_malformed<E>(
    launch_template_id: &str,
) -> crate::scaffolded::Scaffolded<E> {
    crate::scaffolded::Scaffolded::service_error(
        INVALID_LAUNCH_TEMPLATE_ID_MALFORMED,
        400,
        format!(
            "The specified launch template ID '{}' is malformed.",
            echoed_resource_id(launch_template_id)
        ),
    )
}

/// Refuse a launch template id an operation that LAUNCHES from the template could not
/// resolve, in the wording that names the template as "specified": HTTP 400
/// [`INVALID_LAUNCH_TEMPLATE_ID_NOT_FOUND`], `The specified launch template, with template ID
/// <id>, does not exist.`
///
/// A SECOND wording of that code beside [`invalid_launch_template_id_not_found`] (which states
/// that at least one of the templates a request named is absent, naming none of them), and a
/// named constructor rather than a literal at a call site for the reason
/// [`specified_launch_template_id_is_malformed`] is one: EC2's per-operation validators do not
/// agree about an id they cannot resolve, and WHICH wording an operation answers is a fact of
/// that operation, recorded by its caller — `ec2.ec2-run-from-launch-template` pins this
/// sentence for a `RunInstances` naming a launch template the account no longer holds. The one
/// variable part is the id the request sent, cut to length by [`echoed_resource_id`] the way
/// every refusal of this crate bounds a value it repeats back.
pub fn specified_launch_template_id_not_found<E>(
    launch_template_id: &str,
) -> crate::scaffolded::Scaffolded<E> {
    crate::scaffolded::Scaffolded::service_error(
        INVALID_LAUNCH_TEMPLATE_ID_NOT_FOUND,
        400,
        format!(
            "The specified launch template, with template ID {}, does not exist.",
            echoed_resource_id(launch_template_id)
        ),
    )
}

/// Refuse the launch template ids of a request that name no launch template of the account:
/// HTTP 400 [`INVALID_LAUNCH_TEMPLATE_ID_MALFORMED`], naming every one of them in the one
/// message.
///
/// A launch template id is one the service itself minted, so an id it did not mint is not an
/// id of a launch template at all — which is the verdict the recorded units behind
/// `issues/.../20261022T235108Z-ec2-describelaunchtemplates-stub.md` show AWS answering for
/// an id in the long id form that no launch template of the account carries, with the fixed
/// text below. Beside [`invalid_launch_template_id_malformed`], which is the same refusal for
/// an operation whose member names ONE id, so an operation taking a LIST of them does not
/// word it a second way; each id is cut to length by [`echoed_resource_id`], the way every
/// refusal of this crate bounds a value it repeats back.
pub fn launch_template_ids_malformed<E>(ids: &[&str]) -> crate::scaffolded::Scaffolded<E> {
    let named: Vec<String> = ids.iter().map(|id| echoed_resource_id(id)).collect();
    crate::scaffolded::Scaffolded::service_error(
        INVALID_LAUNCH_TEMPLATE_ID_MALFORMED,
        400,
        format!(
            "The following launch template ids are malformed: {}",
            named.join(", ")
        ),
    )
}

/// Refuse a request that named a launch template name no launch template of the account
/// carries: HTTP 400 `InvalidLaunchTemplateName.NotFoundException`.
///
/// The sentence is EC2's, and it is FIXED: `At least one of the launch templates specified
/// in the request does not exist.` names neither the request's values nor how many of them
/// could not be resolved — a request may name several, and the service reports that at least
/// one of them is absent rather than which. Recorded by the corpus unit
/// `ec2.asgeni-launch-template-with-unknown-ssm-alias-rejected`, which describes the name a
/// refused create did not store and reads this answer back.
pub fn invalid_launch_template_name_not_found<E>() -> crate::scaffolded::Scaffolded<E> {
    crate::scaffolded::Scaffolded::service_error(
        INVALID_LAUNCH_TEMPLATE_NAME_NOT_FOUND,
        400,
        "At least one of the launch templates specified in the request does not exist.",
    )
}

/// Refuse a create that named a launch template name this account already holds a template
/// under: HTTP 400 `InvalidLaunchTemplateName.AlreadyExistsException`.
pub fn launch_template_name_already_exists<E>(name: &str) -> crate::scaffolded::Scaffolded<E> {
    crate::scaffolded::Scaffolded::service_error(
        INVALID_LAUNCH_TEMPLATE_NAME_ALREADY_EXISTS,
        400,
        format!("The launch template name '{name}' is already in use"),
    )
}

/// One security group as a writer asks for it: the members a creator chooses. Everything
/// the service derives — the group id, its ARN and the owning account — is minted by
/// [`ComAmazonawsEc2Amazonec2State::insert_security_group`].
#[derive(Debug, Clone)]
pub struct SecurityGroupSpec {
    /// The VPC the group is in.
    pub vpc_id: String,
    /// The group's name, unique within its VPC.
    pub group_name: String,
    /// The group's description.
    pub description: String,
    /// The Region the group's ARN names.
    pub region: String,
    /// The tags the group carries.
    pub tags: Vec<Tag>,
    /// The group's inbound rules.
    pub ip_permissions: Vec<IpPermission>,
    /// The group's outbound rules.
    pub ip_permissions_egress: Vec<IpPermission>,
}

/// One subnet as a writer asks for it: the members a creator chooses. Everything the
/// service derives — the subnet id, its ARN, the owning account and the available-address
/// count — is minted by [`ComAmazonawsEc2Amazonec2State::insert_subnet`].
#[derive(Debug, Clone)]
pub struct SubnetSpec {
    /// The VPC the subnet is in.
    pub vpc_id: String,
    /// The subnet's IPv4 CIDR block.
    pub cidr_block: String,
    /// The zone name (`us-east-1a`) the subnet is in.
    pub availability_zone: String,
    /// That zone's id (`use1-az1`).
    pub availability_zone_id: String,
    /// The Region the subnet's ARN names.
    pub region: String,
    /// One value of the `SubnetState` enum.
    pub state: String,
    /// Whether this is the default subnet for its Availability Zone.
    pub default_for_az: bool,
    /// Whether instances launched here receive a public IPv4 address.
    pub map_public_ip_on_launch: bool,
    /// The tags the subnet carries.
    pub tags: Vec<Tag>,
}

/// The prefix of a `SubnetCidrReservationId`, as EC2 spells one (`scr-…`), and the segment
/// [`ComAmazonawsEc2Amazonec2State::insert_subnet_cidr_reservation`] mints the id from.
pub const SUBNET_CIDR_RESERVATION_ID_PREFIX: &str = "scr";

/// The `ResourceType` a `CreateSubnetCidrReservation` tag specification may name: the
/// reservation it creates (`ResourceType` enum member `subnet-cidr-reservation`, in
/// [`crate::ops::types::RESOURCE_TYPE_VALUES`]).
pub const RESOURCE_TYPE_SUBNET_CIDR_RESERVATION: &str = "subnet-cidr-reservation";

/// One subnet CIDR reservation as a writer asks for it: the members a creator chooses.
/// Everything the service derives — the reservation id and the owning account — is minted
/// by [`ComAmazonawsEc2Amazonec2State::insert_subnet_cidr_reservation`].
#[derive(Debug, Clone)]
pub struct SubnetCidrReservationSpec {
    /// The subnet whose CIDR range this reservation is part of.
    pub subnet_id: String,
    /// The reserved range, in the canonical form the create read it in.
    pub cidr: String,
    /// One value of the `SubnetCidrReservationType` enum
    /// ([`crate::ops::types::SUBNET_CIDR_RESERVATION_TYPE_VALUES`]).
    pub reservation_type: String,
    /// The description the request assigned, for a reservation that carries one.
    pub description: Option<String>,
    /// The tags the reservation carries.
    pub tags: Vec<Tag>,
}

/// The caller-chosen bytes one stored subnet CIDR reservation holds, plus the fixed
/// overhead the record itself costs.
///
/// Only the members whose length the REQUEST chose are counted on top of
/// [`STORED_RECORD_OVERHEAD_BYTES`]: the reservation id and the owner are minted by
/// [`ComAmazonawsEc2Amazonec2State::insert_subnet_cidr_reservation`]. The ONE definition of
/// that charge, the way [`coip_pool_payload_bytes`] is for a CoIP pool, so a create charges
/// exactly what a delete would give back.
///
/// It takes the caller-chosen members themselves rather than a stored record, so the create
/// can ask about a reservation it has not stored yet — the budget has to be asked BEFORE the
/// write — and a later delete can ask about the record it is removing.
pub fn subnet_cidr_reservation_payload_bytes(
    cidr: &str,
    description: Option<&str>,
    tags: &[Tag],
) -> usize {
    STORED_RECORD_OVERHEAD_BYTES
        .saturating_add(cidr.len())
        .saturating_add(description.map_or(0, str::len))
        .saturating_add(tag_list_bytes(tags))
}

/// The caller-chosen bytes one stored customer-owned IP address pool holds, plus the fixed
/// overhead the record itself costs.
///
/// Only the members whose length the REQUEST chose are counted on top of
/// [`STORED_RECORD_OVERHEAD_BYTES`]: the pool id and the `PoolArn` are minted by
/// [`ComAmazonawsEc2Amazonec2State::insert_coip_pool`]. The ONE definition of that charge,
/// the way [`placement_group_spec_bytes`] is for a placement group: the insert charges
/// exactly it and [`ComAmazonawsEc2Amazonec2State::remove_coip_pool`] gives back exactly
/// it, so a pool that is created and deleted leaves the byte budget where it started, and a
/// pool with no CIDRs and no tags is not free against [`MAX_STORED_BYTES`].
pub fn coip_pool_payload_bytes(pool: &crate::ops::types::CoipPool) -> usize {
    let cidr_bytes: usize = pool.pool_cidrs.iter().flatten().map(String::len).sum();
    STORED_RECORD_OVERHEAD_BYTES
        .saturating_add(cidr_bytes)
        .saturating_add(tag_list_bytes(pool.tags.as_deref().unwrap_or_default()))
}

/// One customer-owned IP address pool as a writer asks for it: the members a creator
/// chooses. Everything the service derives — the pool id and the `PoolArn` built from it —
/// is minted by [`ComAmazonawsEc2Amazonec2State::insert_coip_pool`].
#[derive(Debug, Clone)]
pub struct CoipPoolSpec {
    /// "The ID of the local gateway route table" (`CoipPool$LocalGatewayRouteTableId`) the
    /// pool belongs to.
    pub local_gateway_route_table_id: String,
    /// The Region the pool's ARN names.
    pub region: String,
    /// "The address ranges of the address pool" (`CoipPool$PoolCidrs`).
    pub pool_cidrs: Vec<String>,
    /// The tags the pool carries (`CoipPool$Tags`).
    pub tags: Vec<Tag>,
}

/// The number of IPv4 addresses of `cidr_block` a network interface may take: the block's
/// own size less the [`SUBNET_RESERVED_ADDRESSES`] AWS reserves in it.
///
/// A block this emulator cannot read counts no available addresses, rather than a guess.
pub fn available_ipv4_addresses(cidr_block: &str) -> i32 {
    let Some((_, prefix_length)) = parse_ipv4_cidr_block(cidr_block) else {
        return 0;
    };
    let addresses = 1u64 << (32 - u64::from(prefix_length));
    let available = addresses.saturating_sub(u64::from(SUBNET_RESERVED_ADDRESSES));
    i32::try_from(available).unwrap_or(i32::MAX)
}

/// The `index`-th block of `prefix_length` bits inside `cidr_block`, or `None` when
/// `cidr_block` is unreadable, `prefix_length` is not a longer prefix than its own, or the
/// block at `index` runs past its end.
///
/// Subnetting is this arithmetic: the parent block's base address plus `index` whole
/// child blocks, as long as that stays inside the parent.
pub fn nth_subnet_cidr_block(
    cidr_block: &str,
    prefix_length: u32,
    index: u32,
) -> Option<String> {
    let (base, parent_prefix_length) = parse_ipv4_cidr_block(cidr_block)?;
    if prefix_length < parent_prefix_length || prefix_length > 32 {
        return None;
    }
    let child_size = 1u64 << (32 - u64::from(prefix_length));
    let parent_size = 1u64 << (32 - u64::from(parent_prefix_length));
    let offset = child_size.checked_mul(u64::from(index))?;
    if offset.checked_add(child_size)? > parent_size {
        return None;
    }
    let address = u32::try_from(u64::from(base).checked_add(offset)?).ok()?;
    Some(format!(
        "{}/{prefix_length}",
        ::std::net::Ipv4Addr::from(address)
    ))
}

/// `cidr_block` as its base address and prefix length, or `None` when it is not an IPv4
/// CIDR block: the address is parsed by the standard library's own `Ipv4Addr` parser, and
/// the prefix must be a decimal 0..=32 whose host bits are clear.
pub(super) fn parse_ipv4_cidr_block(cidr_block: &str) -> Option<(u32, u32)> {
    let (address, prefix_length) = cidr_block.split_once('/')?;
    let base = u32::from(address.parse::<::std::net::Ipv4Addr>().ok()?);
    let prefix_length: u32 = prefix_length.parse().ok()?;
    if prefix_length > 32 {
        return None;
    }
    // A block whose host bits are set (`172.31.0.1/16`) names no block; refusing it here
    // keeps the arithmetic above exact.
    let host_bits = 32 - prefix_length;
    if host_bits < 32 && base & ((1u32 << host_bits) - 1) != 0 {
        return None;
    }
    if host_bits == 32 && base != 0 {
        return None;
    }
    Some((base, prefix_length))
}
