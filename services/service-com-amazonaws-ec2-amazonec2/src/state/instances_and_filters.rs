// SPDX-License-Identifier: CC0-1.0

//! The instance and reservation stores, and the compiled-filter and tag primitives the
//! describe operations read every resource through.
//!
//! Split out of the [`crate::state`] module root so each file holds one concern, and
//! re-exported from it, so a handler reaches these as `crate::state::<item>` like every
//! other primitive there.

use super::*;

impl ComAmazonawsEc2Amazonec2State {
    /// A fresh, unused `r-` reservation id.
    pub fn mint_reservation_id(&mut self) -> String {
        // OnCallWorlds patch: an id the seed pinned for this setup call.
        if let Some(id) = ocw_clock::take_pinned("r") {
            return id;
        }
        self.next_reservation += 1;
        format!("r-{:017x}", self.next_reservation)
    }

    /// A fresh, unused `i-` instance id.
    ///
    /// The long form every instance id EC2 issues takes: `i-` and 17 lowercase
    /// hexadecimal digits of a counter that starts at one, so the id is never the null
    /// id and its leading digit is `0` — one of the two forms
    /// [`instance_id_is_well_formed`] reads, which is what lets an id outside them be
    /// answered as malformed rather than looked up.
    pub fn mint_instance_id(&mut self) -> String {
        // OnCallWorlds patch: an id the seed pinned for this setup call.
        if let Some(id) = ocw_clock::take_pinned("i") {
            // Instance ids are read back against this counter (an id above it was never
            // issued), so a pinned id moves it.
            if let Some(n) = long_form_identifier(&id).and_then(|n| u64::try_from(n).ok()) {
                self.next_instance = self.next_instance.max(n);
            }
            return id;
        }
        self.next_instance += 1;
        format!("i-{:017x}", self.next_instance)
    }

    /// The next unused primary private IPv4 address, or `None` when the search is
    /// exhausted.
    ///
    /// Drawn from `172.31.0.0/16`, the CIDR AWS gives a default VPC, skipping the
    /// first four addresses of each `/24` (AWS reserves them) and the broadcast
    /// address. An address already in use is skipped in constant time, and the
    /// search probes at most [`MAX_PRIVATE_IP_PROBES`] candidates so it cannot spin.
    pub fn allocate_private_ip(&mut self) -> Option<String> {
        for _ in 0..MAX_PRIVATE_IP_PROBES {
            let host = self.next_private_ip;
            self.next_private_ip = self.next_private_ip.wrapping_add(1);
            let candidate = format!("172.31.{}.{}", (host / 251) % 256, 4 + host % 251);
            if !self.assigned_private_ips.contains(&candidate) {
                // Recorded here, not only in `insert_instance`, so a caller that
                // allocates several addresses before storing any instance cannot be
                // handed the same one twice.
                self.assigned_private_ips.insert(candidate.clone());
                return Some(candidate);
            }
        }
        None
    }

    /// Whether a stored instance already holds `address` as its primary private
    /// IPv4 address.
    pub fn private_ip_in_use(&self, address: &str) -> bool {
        self.assigned_private_ips.contains(address)
    }

    /// Give an address allocated by [`Self::allocate_private_ip`] back to the pool.
    ///
    /// A launch takes one address per instance before storing any of them, so a
    /// launch that fails part way must hand back what it took or the pool shrinks
    /// for addresses no instance ever held.
    pub fn release_private_ip(&mut self, address: &str) {
        self.assigned_private_ips.remove(address);
    }

    /// Take `address` for the caller that asked for it by name, answering `false` when
    /// anything in the account already holds it.
    ///
    /// The counterpart of [`Self::allocate_private_ip`] for a request that names the
    /// private address it wants instead of letting the service choose. "Already held" is
    /// the one question [`Self::subnet_address_in_use`] answers, so a named address cannot
    /// collide with a minted one NOR with an address recorded somewhere else than in the
    /// set this insert writes — a route server endpoint's network interface, say.
    pub fn reserve_private_ip(&mut self, address: &str) -> bool {
        if self.subnet_address_in_use(address) {
            return false;
        }
        self.assigned_private_ips.insert(address.to_string())
    }

    /// Every subnet address the account's interfaces hold, from the TWO places one is
    /// recorded: the private addresses this emulator has handed out
    /// ([`Self::private_ip_in_use`] reads the same set) and the elastic network interface
    /// addresses kept on the route server endpoint records themselves.
    ///
    /// The ONE definition of "held", so the point question
    /// ([`Self::subnet_address_in_use`]) and the search ([`Self::free_subnet_address`])
    /// cannot disagree about who holds what.
    pub(super) fn held_subnet_addresses(&self) -> impl Iterator<Item = &str> {
        self.assigned_private_ips.iter().map(String::as_str).chain(
            self.route_server_endpoints
                .values()
                .filter_map(|endpoint| endpoint.eni_address.as_deref()),
        )
    }

    /// Whether anything in the account already holds the subnet address `candidate`.
    ///
    /// Asking about both records ([`Self::held_subnet_addresses`]) is what stops one subnet
    /// giving the same address to a NAT gateway address and to a route server interface.
    pub fn subnet_address_in_use(&self, candidate: &str) -> bool {
        self.held_subnet_addresses()
            .any(|address| address == candidate)
    }

    /// The lowest address of `cidr_block` a network interface may be given that nothing in
    /// the account holds, WITHOUT taking it — or `None` when the block has none (or is not
    /// a readable IPv4 block).
    ///
    /// The candidates are the window [`assignable_subnet_window`] admits — every address
    /// of the block but the four at its bottom and its last, the
    /// [`SUBNET_RESERVED_ADDRESSES`] AWS reserves — the SAME computation
    /// [`is_assignable_subnet_address`] judges a caller-named address by, so a
    /// service-chosen address is one a caller could have named. They are judged against
    /// [`Self::held_subnet_addresses`], so free means free for every resource of the
    /// subnet.
    ///
    /// The addresses already held are read ONCE into a set of numbers and the probe itself
    /// is a lookup in it, so neither the account's records nor the width of the block turns
    /// one call into unbounded work: the search probes at most
    /// [`MAX_PRIVATE_IP_PROBES`] candidates, which is every assignable address of a
    /// subnet-sized block.
    pub fn free_subnet_address(&self, cidr_block: &str) -> Option<String> {
        let window = assignable_subnet_window(cidr_block)?;
        let held: BTreeSet<u32> = self
            .held_subnet_addresses()
            .filter_map(|address| address.parse::<::std::net::Ipv4Addr>().ok())
            .map(u32::from)
            .filter(|address| window.contains(address))
            .collect();
        window
            .take(MAX_PRIVATE_IP_PROBES as usize)
            .find(|candidate| !held.contains(candidate))
            .map(|address| ::std::net::Ipv4Addr::from(address).to_string())
    }

    /// The next free private IPv4 address inside `cidr_block`, TAKEN for the caller, or
    /// `None` when the block holds none (or is not a readable IPv4 block).
    ///
    /// For a resource whose address comes out of ITS OWN subnet rather than out of the
    /// default VPC's block, which is what [`Self::allocate_private_ip`] draws from. The
    /// choice is [`Self::free_subnet_address`]'s — the one scan every subnet address comes
    /// out of — and the address is recorded in the set [`Self::private_ip_in_use`] reads,
    /// so a service-chosen address and a caller-named one can never collide.
    pub fn mint_private_ip_in_cidr(&mut self, cidr_block: &str) -> Option<String> {
        let address = self.free_subnet_address(cidr_block)?;
        self.assigned_private_ips.insert(address.clone());
        Some(address)
    }

    /// Store a launched instance, appending it to its reservation — and create the two
    /// resources the launch gives it: the EBS root volume
    /// ([`Self::mint_launched_root_volume`]) and the primary network interface
    /// ([`Self::mint_launched_primary_interface`]).
    ///
    /// For a launch that NAMED the interfaces of its instance, [`Self::insert_launched_instance`]
    /// is the same write with those interfaces instead of the single default one; this is that
    /// call with none, so every launch path stores its instance through one body.
    pub fn insert_instance(&mut self, record: InstanceRecord) {
        self.insert_launched_instance(record, &[]);
    }

    /// Store a launched instance together with the interfaces its launch named
    /// ([`LaunchedInterface`]), and answer whether every one of them was stored.
    ///
    /// `interfaces` empty is a launch that named none, which gets the single primary
    /// interface [`Self::mint_launched_primary_interface`] creates for it; a launch that
    /// named them gets exactly those, each created or attached at its own device index
    /// ([`Self::mint_launched_interfaces`]). Either way the instance, its root volume and its
    /// interfaces are stored by this one body, so no launch path can store an instance
    /// without the resources that come with it.
    pub fn insert_launched_instance(
        &mut self,
        record: InstanceRecord,
        interfaces: &[LaunchedInterface],
    ) -> bool {
        if let Some(reservation) = self.reservations.get_mut(&record.reservation_id) {
            reservation.instance_ids.push(record.instance_id.clone());
        }
        self.assigned_private_ips.insert(record.private_ip.clone());
        self.stored_bytes = self
            .stored_bytes
            .saturating_add(instance_payload_bytes(&record));
        let instance_id = record.instance_id.clone();
        self.instances.insert(record.instance_id.clone(), record);
        self.mint_launched_root_volume(&instance_id);
        if interfaces.is_empty() {
            self.mint_launched_primary_interface(&instance_id);
            return true;
        }
        self.mint_launched_interfaces(&instance_id, interfaces)
    }

    /// Start the termination of the instance `instance_id` names, as of `at`, and answer the
    /// state it was in — `None` when this store holds no such instance.
    ///
    /// The ONE writer of a termination, so every path that terminates an instance (a caller
    /// naming it, or a Spot Fleet cancellation terminating what the fleet launched) leaves
    /// the same record behind: `shutting-down` with the clock owing `terminated`, and the
    /// reason EC2 records for a shutdown somebody asked for. A termination is IDEMPOTENT — an
    /// instance already on its way to, or at, `terminated` keeps the transition it has — so
    /// the state answered here is the one a caller is told it was in.
    pub fn begin_instance_termination(
        &mut self,
        instance_id: &str,
        at: SystemTime,
    ) -> Option<InstanceStateName> {
        let instance = self.instances.get_mut(instance_id)?;
        let previous = instance.state;
        if !previous.is_terminating() {
            instance.state = InstanceStateName::ShuttingDown;
            instance.pending_transition =
                Some(PendingTransition::starting_now(InstanceStateName::Terminated));
            instance.state_transition_reason = Some(user_initiated_reason(at));
            instance.state_reason = Some((
                INSTANCE_STATE_REASON_USER_INITIATED_SHUTDOWN.to_string(),
                INSTANCE_STATE_REASON_MESSAGE_USER_INITIATED_SHUTDOWN.to_string(),
            ));
        }
        Some(previous)
    }

    /// Set the detailed monitoring of the instance `instance_id` names on its way to
    /// `settled`, through the transient state `transient`.
    ///
    /// The ONE writer of a monitoring change, so `MonitorInstances` and
    /// `UnmonitorInstances` leave the same shape of record behind: the instance reports
    /// `transient` at once ("pending" on the way up, "disabling" on the way down) and the
    /// clock owes it `settled` [`TRANSITION_DELAY`] later, whether or not anybody calls
    /// again ([`Self::materialize_due_transitions`]). Nothing else about the instance
    /// moves — turning monitoring on or off leaves the instance in the state it was in —
    /// and an instance already at `settled` with nothing owed is left exactly as it is, so
    /// a repeat of the same call reports the settled state rather than re-entering the
    /// transient one. The words are `&'static str` members of the modelled
    /// `MonitoringState` catalog, so no request text can reach the record.
    pub fn set_instance_monitoring(
        &mut self,
        instance_id: &str,
        transient: &'static str,
        settled: &'static str,
    ) {
        debug_assert!(
            self.instances.contains_key(instance_id),
            "monitoring is set only for an instance the caller's id resolved to"
        );
        let Some(instance) = self.instances.get_mut(instance_id) else {
            return;
        };
        if instance.monitoring_state == settled && instance.monitoring_transition.is_none() {
            return;
        }
        instance.monitoring_state = transient.to_string();
        instance.monitoring_transition = Some(ClockTransition::starting_now(settled));
    }

    /// Queue one reboot for the instance `instance_id` names, as of `at`.
    ///
    /// The ONE writer of a queued reboot, so one `RebootInstances` call records one reboot
    /// per instance it names however many times it names it. Nothing else about the
    /// instance moves: a reboot leaves it in the state it was in, which is why this
    /// touches neither [`InstanceRecord::state`] nor its
    /// [`InstanceRecord::pending_transition`]. An id this store holds no instance for
    /// records nothing — the handler refuses such an id before it gets here, and a
    /// terminated instance is skipped by the handler, "requests to reboot terminated
    /// instances are ignored".
    ///
    /// What the queued reboot then DOES is owed to the clock: `RebootInstances` "only queues
    /// a request to reboot the specified instances", so the guest comes up again
    /// [`TRANSITION_DELAY`] later whether or not anybody calls again — a boot of its own,
    /// with its own identity, appended to what the earlier boots wrote to the console (see
    /// [`crate::state::instance_boots`]).
    pub fn queue_instance_reboot(&mut self, instance_id: &str, at: SystemTime) {
        debug_assert!(
            self.instances.contains_key(instance_id),
            "a reboot is queued only for an instance the caller's id resolved to"
        );
        if let Some(instance) = self.instances.get_mut(instance_id) {
            instance.queued_reboots = instance.queued_reboots.saturating_add(1);
            instance.last_reboot_queued_at = Some(at);
            instance.boot_due = Some(at + TRANSITION_DELAY);
        }
    }

    /// Record one diagnostic interrupt sent to the instance `instance_id` names, as of
    /// `at`.
    ///
    /// The ONE writer of a sent interrupt, so one `SendDiagnosticInterrupt` call records
    /// one. Nothing else about the instance moves: the interrupt crashes and reboots the
    /// instance's OPERATING SYSTEM, which leaves the instance in the state it was in, so
    /// this touches neither [`InstanceRecord::state`] nor its
    /// [`InstanceRecord::pending_transition`]. An id this store holds no instance for
    /// records nothing — the handler refuses such an id before it gets here.
    pub fn record_diagnostic_interrupt(&mut self, instance_id: &str, at: SystemTime) {
        debug_assert!(
            self.instances.contains_key(instance_id),
            "an interrupt is recorded only for an instance the caller's id resolved to"
        );
        if let Some(instance) = self.instances.get_mut(instance_id) {
            instance.diagnostic_interrupts = instance.diagnostic_interrupts.saturating_add(1);
            instance.last_diagnostic_interrupt_at = Some(at);
        }
    }

    /// The caller-chosen bytes stored right now.
    pub fn stored_bytes(&self) -> usize {
        self.stored_bytes
    }

    /// Would storing `bytes` more caller-chosen bytes cross [`MAX_STORED_BYTES`]?
    pub fn would_exceed_stored_bytes(&self, bytes: usize) -> bool {
        self.stored_bytes.saturating_add(bytes) > MAX_STORED_BYTES
    }

    /// Would REPLACING a stored record — charging `charge` for the new one and giving back
    /// the `refund` the old one was charged — cross [`MAX_STORED_BYTES`]?
    ///
    /// The NET change is what the budget has to be asked about on a replacement path: a
    /// replacement stores no further record, so a record-count ceiling cannot bound it, and
    /// `charge` is caller-chosen text, so replacing a small record with a large one grows
    /// the store by the difference. Asking [`Self::would_exceed_stored_bytes`] about
    /// `charge` alone would refuse replacements the budget has room for, and skipping the
    /// question entirely would let repeated replacements grow this process's memory past
    /// the only bound it has.
    pub fn would_exceed_stored_bytes_after_refund(&self, charge: usize, refund: usize) -> bool {
        self.stored_bytes.saturating_sub(refund).saturating_add(charge) > MAX_STORED_BYTES
    }

    /// Account for `bytes` more caller-chosen bytes, written onto records that are
    /// already stored (a tag write).
    pub fn add_stored_bytes(&mut self, bytes: usize) {
        self.stored_bytes = self.stored_bytes.saturating_add(bytes);
    }

    /// Store a new reservation, keeping the launch order it reports in.
    pub fn insert_reservation(&mut self, record: ReservationRecord) {
        self.reservation_order.push(record.reservation_id.clone());
        self.reservations
            .insert(record.reservation_id.clone(), record);
    }

    /// Apply every clock-owed transition that has come due.
    ///
    /// A reporting operation may call this: each move was already owed at this
    /// instant whether or not anybody asked, so materialising it changes nothing
    /// a later caller would otherwise have seen. It covers every resource kind that
    /// has one — an instance's next state, a `pending` VPC becoming `available` with
    /// its IPv6 association moving `associating` -> `associated`, a `pending` carrier
    /// gateway becoming `available`, a subnet another service
    /// handed over `pending` becoming `available` and a subnet's own IPv6 association
    /// making that same `associating` -> `associated` move (and the `disassociating` ->
    /// `disassociated` one, in the other direction, for a block
    /// `DisassociateSubnetCidrBlock` started letting go of), a `pending` transit
    /// gateway with the route tables that come up
    /// with it (a route table a create ADDED to a gateway comes up on its own due instant),
    /// a `pending` route server endpoint or route server peer becoming
    /// `available` (a route server's own two states are derived on read by
    /// [`RouteServerRecord::view_at`] instead), a VPC BPA exclusion reaching
    /// `create-complete`, a Windows fast
    /// launch configuration reaching `enabled` or finishing the cleanup a disable started, a
    /// `pending-withdrawal` BYOIP range reaching the end of its withdrawal, and a
    /// `pending-deprovision` BYOIP range reaching the end of its release — leaving the
    /// account, or landing in `failed-deprovision` when addresses are still allocated from
    /// it — and an IPAM (with its default scopes, resource discovery and that discovery's
    /// association) reaching `create-complete`.
    ///
    /// So is the end of a secondary subnet's deletion — a `delete-in-progress` secondary
    /// subnet reaching `delete-complete` with its IPv4 CIDR block associations
    /// `disassociated` ([`Self::materialize_due_secondary_subnet_deletions`]).
    ///
    /// An `active` import image task becoming `completed` with the AMI it created is one of
    /// them too; it is documented on [`Self::complete_due_import_image_tasks`], which this
    /// calls. So is an `active` import SNAPSHOT task reaching `completed` with the EBS
    /// snapshot its disk became ([`Self::complete_due_import_snapshot_conversions`]). So is
    /// the end of an import task cancellation — a `deleting` task of either
    /// import kind reaching `deleted`
    /// ([`Self::delete_due_cancelled_import_tasks`]). So is a NAT gateway address an
    /// association left `associating` reaching
    /// `succeeded` ([`NatGatewayAddressTransition`]), and a `running` Network Access Scope
    /// analysis reaching its terminal `AnalysisStatus`. So is an `associating` local gateway
    /// route table / VPC association reaching `associated`, an `associating` local gateway
    /// route table / virtual interface group association reaching it too, a `pending` local
    /// gateway route reaching `active`, and a Client VPN
    /// target network association moving `associating` -> `associated`. So is a `pending`
    /// permission over a network interface reaching `granted`, a PTR record update owed
    /// on an Elastic IP address's `domain-name` attribute reaching that record
    /// ([`Self::apply_due_ptr_record_updates`]), and a `processing` Reserved Instances
    /// modification reaching `fulfilled` with the purchases it mints
    /// ([`Self::fulfill_due_reserved_instances_modifications`]).
    pub fn materialize_due_transitions(&mut self) {
        let now = Instant::now();
        // The one clock-owed REMOVAL: a recycled AMI whose retention period has run out was
        // permanently deleted when that instant passed, whether or not anybody called.
        self.purge_expired_recycled_images(SystemTime::now());
        // A volume whose Recycle Bin retention period has run out was permanently deleted
        // at its exit instant whether or not anybody called, so that deletion is applied
        // before anything reads the bin.
        self.delete_due_recycled_volumes(now);
        // An AMI usage report past its `ExpirationTime` was deleted by EC2 at that instant —
        // "30 days after the report was created" — and a `pending` report reaches `available`
        // once its own due instant has passed; both were owed whether or not anybody called.
        self.expire_due_image_usage_reports(SystemTime::now());
        self.materialize_due_image_usage_reports(now);
        // The primary private addresses the terminations that just COMPLETED release, taken
        // while the moves are applied so each is released exactly ONCE: an instance already
        // at `terminated` has no transition left to apply, so a later sweep collects nothing
        // for it and cannot free an address a new holder has since been given.
        let mut released: Vec<String> = Vec::new();
        for instance in self.instances.values_mut() {
            let due = instance
                .pending_transition
                .as_ref()
                .filter(|pending| now >= pending.due_at)
                .map(|pending| pending.to);
            if let Some(state) = due {
                instance.state = state;
                instance.pending_transition = None;
                // A completed termination releases the instance's primary private address:
                // the interface that held it goes at this same instant (below), so EC2 has
                // freed the address for reuse and a later launch may be given it.
                if state == InstanceStateName::Terminated {
                    released.push(instance.private_ip.clone());
                }
            }
            // The monitoring move the clock owes the same instance: `pending` -> `enabled`
            // for a `MonitorInstances`, `disabling` -> `disabled` for an
            // `UnmonitorInstances`. Owed at the same instant whether or not anybody called,
            // exactly like the state move above.
            let monitoring_due = instance
                .monitoring_transition
                .as_ref()
                .filter(|pending| now >= pending.due_at)
                .map(|pending| pending.to);
            if let Some(monitoring_state) = monitoring_due {
                instance.monitoring_state = monitoring_state.to_string();
                instance.monitoring_transition = None;
            }
        }
        for address in released {
            self.release_private_ip(&address);
        }
        // The guest boots the clock already owes: an instance that has just finished starting
        // has brought its operating system up, and one whose queued reboot fell due has
        // brought it up again. Applied after the state moves above, so an instance that
        // reached `running` in this same sweep boots in it rather than one call later.
        self.boot_due_instance_guests(SystemTime::now());
        // An instance that has reached `terminated` no longer holds the network interfaces
        // its attachments are marked to delete with it — "indicates whether the network
        // interface is deleted when the instance is terminated"
        // (`InstanceNetworkInterfaceAttachment$DeleteOnTermination`) — so those interfaces
        // were deleted at the instant the termination completed, whether or not anybody
        // called again, and with them the subnet addresses and security group references
        // they held.
        self.delete_interfaces_of_terminated_instances();
        let vpcs = &mut self.vpcs;
        self.vpc_available_at.retain(|vpc_id, due_at| {
            if now < *due_at {
                return true;
            }
            if let Some(vpc) = vpcs.get_mut(vpc_id) {
                if vpc.state.as_deref() == Some(VPC_STATE_PENDING) {
                    vpc.state = Some(VPC_STATE_AVAILABLE.to_string());
                }
                for association in vpc.ipv6_cidr_block_association_set.iter_mut().flatten() {
                    if let Some(state) = association.ipv6_cidr_block_state.as_mut() {
                        if state.state.as_deref() == Some(CIDR_BLOCK_STATE_ASSOCIATING) {
                            state.state = Some(CIDR_BLOCK_STATE_ASSOCIATED.to_string());
                        }
                    }
                }
            }
            // The transition is applied once; nothing is owed on this VPC any more.
            false
        });
        // A VPC peering request `CreateVpcPeeringConnection` answered as
        // `initiating-request` is `pending-acceptance` once its due instant has passed, and
        // one nobody answered by its own `ExpirationTime` expired at that instant — both owed
        // whether or not anybody called, the same contract as the `pending` VPC above.
        self.materialize_due_vpc_peering_connections(now, SystemTime::now());
        // An EC2 Fleet `CreateFleet` accepted as `submitted` is `active` once its due
        // instant has passed: "the EC2 Fleet places an asynchronous request for your desired
        // capacity" (`FleetData$Type`), and that request was taken on at the same instant
        // whether or not anybody called.
        self.materialize_due_fleets(now);
        let carrier_gateways = &mut self.carrier_gateways;
        self.carrier_gateway_available_at
            .retain(|carrier_gateway_id, due_at| {
                if now < *due_at {
                    return true;
                }
                if let Some(carrier_gateway) = carrier_gateways.get_mut(carrier_gateway_id) {
                    if carrier_gateway.state.as_deref() == Some(CARRIER_GATEWAY_STATE_PENDING) {
                        carrier_gateway.state = Some(CARRIER_GATEWAY_STATE_AVAILABLE.to_string());
                    }
                }
                // The transition is applied once; nothing is owed on this gateway any more.
                false
            });
        // A managed prefix list `CreateManagedPrefixList` answered as `create-in-progress`
        // reaches `create-complete` once its due instant has passed, whether or not anybody
        // called — the same contract as a `create-in-progress` IPAM scope's move below, and
        // the reason the list's due instant is kept beside the modelled shape rather than on
        // it. A list `DeleteManagedPrefixList` answered as `delete-in-progress` is REMOVED at
        // its own due instant: the deletion was carried out at that instant whether or not
        // anybody called, and a list whose deletion has been carried out is not reported at
        // all.
        let mut deleted: Vec<String> = Vec::new();
        for (prefix_list_id, record) in &mut self.managed_prefix_lists {
            let due = record
                .pending
                .as_ref()
                .filter(|pending| now >= pending.due_at)
                .map(|pending| pending.to);
            match due {
                Some(ManagedPrefixListMove::Settled(state)) => {
                    record.view.state = Some(state.to_string());
                    record.pending = None;
                }
                Some(ManagedPrefixListMove::Removed) => deleted.push(prefix_list_id.clone()),
                None => {}
            }
        }
        // Taken out after the walk rather than inside it, so the removal goes through the one
        // place a prefix list stops being stored — which is also what gives its bytes back to
        // the budget and forgets the client token that named it.
        for prefix_list_id in deleted {
            self.remove_managed_prefix_list(&prefix_list_id);
        }
        // A permission granted over a network interface is recorded `pending` and reaches
        // `granted` at its due instant, whether or not anybody called — the permission
        // counterpart of the moves above.
        let network_interface_permissions = &mut self.network_interface_permissions;
        self.network_interface_permission_granted_at
            .retain(|network_interface_permission_id, due_at| {
                if now < *due_at {
                    return true;
                }
                if let Some(permission) =
                    network_interface_permissions.get_mut(network_interface_permission_id)
                {
                    if let Some(state) = permission.permission_state.as_mut() {
                        if state.state.as_deref()
                            == Some(NETWORK_INTERFACE_PERMISSION_STATE_PENDING)
                        {
                            state.state =
                                Some(NETWORK_INTERFACE_PERMISSION_STATE_GRANTED.to_string());
                        }
                    }
                }
                // The move is applied once; nothing is owed on this permission any more.
                false
            });
        // The two moves an IAM instance profile association owes the clock: `associating` ->
        // `associated`, and the REMOVAL of one whose disassociation has been started.
        self.settle_due_iam_instance_profile_associations(now);
        // The move the clock owes a network interface's attachment: `attaching` ->
        // `attached` for an attach, and the attachment being GONE for a detach. Owed at its
        // own instant whether or not anybody called again.
        self.settle_due_network_interface_attachment_moves(now);
        let subnets = &mut self.subnets;
        self.subnet_available_at.retain(|subnet_id, due_at| {
            if now < *due_at {
                return true;
            }
            if let Some(subnet) = subnets.get_mut(subnet_id) {
                if subnet.state.as_deref() == Some(SUBNET_STATE_PENDING) {
                    subnet.state = Some(SUBNET_STATE_AVAILABLE.to_string());
                }
            }
            // The transition is applied once; nothing is owed on this subnet any more.
            false
        });
        // The IPv6 CIDR block association a subnet is given reaches `associated` on the
        // same terms its VPC's own does above: owed at its due instant whether or not
        // anybody called.
        let subnets = &mut self.subnets;
        self.subnet_ipv6_associated_at.retain(|subnet_id, due_at| {
            if now < *due_at {
                return true;
            }
            if let Some(subnet) = subnets.get_mut(subnet_id) {
                for association in subnet.ipv6_cidr_block_association_set.iter_mut().flatten() {
                    if let Some(state) = association.ipv6_cidr_block_state.as_mut() {
                        if state.state.as_deref() == Some(CIDR_BLOCK_STATE_ASSOCIATING) {
                            state.state = Some(CIDR_BLOCK_STATE_ASSOCIATED.to_string());
                        }
                    }
                }
            }
            // The transition is applied once; nothing is owed on this association any more.
            false
        });
        // And the move the other way: an association `DisassociateSubnetCidrBlock` left
        // `disassociating` has reached the terminal `disassociated` at the instant that
        // write recorded for it, whether or not anybody called again — the same contract as
        // the `associating` -> `associated` move above, in the other direction.
        let subnets = &mut self.subnets;
        self.subnet_ipv6_disassociated_at
            .retain(|association_id, due_at| {
                if now < *due_at {
                    return true;
                }
                for subnet in subnets.values_mut() {
                    let Some(association) = subnet
                        .ipv6_cidr_block_association_set
                        .iter_mut()
                        .flatten()
                        .find(|association| {
                            association.association_id.as_deref() == Some(association_id.as_str())
                        })
                    else {
                        continue;
                    };
                    if let Some(state) = association.ipv6_cidr_block_state.as_mut() {
                        if state.state.as_deref() == Some(CIDR_BLOCK_STATE_DISASSOCIATING) {
                            state.state = Some(CIDR_BLOCK_STATE_DISASSOCIATED.to_string());
                        }
                    }
                    // An association id names ONE association of ONE subnet (it is minted
                    // from the store's own counter), so the walk stops at the one it found.
                    break;
                }
                // The transition is applied once; nothing is owed on this association any
                // more.
                false
            });
        // A VPN static route `CreateVpnConnectionRoute` answered as `pending` is
        // `available` once its due instant has passed, whether or not anybody called — the
        // same contract as a `pending` VPC's move above.
        //
        // The bytes the routes that reached `deleted` below held, released once the walk is
        // over: a deleted route has LEFT its connection, so what it charged the store's
        // caller-chosen byte budget is given back, exactly as a deprovisioned IPAM pool CIDR
        // gives its own back.
        let mut released_route_bytes = 0usize;
        for record in self.vpn_connections.values_mut() {
            let VpnConnectionRecord {
                view,
                route_moves,
                pending: connection_move,
            } = record;
            // A connection `DeleteVpnConnection` left `deleting` reaches the terminal
            // `deleted` at the instant that write recorded for it, whether or not anybody
            // called again — the same contract as the virtual private gateway's own move
            // below.
            if let Some(state) = connection_move
                .as_ref()
                .and_then(|owed| owed.due_by(now))
                .map(str::to_string)
            {
                view.state = Some(state);
                *connection_move = None;
            }
            route_moves.retain(|destination_cidr_block, pending| {
                let Some(state) = pending.due_by(now).map(str::to_string) else {
                    return true;
                };
                // A route `DeleteVpnConnectionRoute` left `deleting` has reached the terminal
                // `deleted` at the instant that write recorded for it, and a deleted route is
                // one the connection no longer carries: it LEAVES the route set at that
                // instant, whether or not anybody called again.
                if state == VPN_STATE_DELETED {
                    if let Some(routes) = view.routes.as_mut() {
                        routes.retain(|route| {
                            let doomed = route.destination_cidr_block.as_deref()
                                == Some(destination_cidr_block.as_str());
                            if doomed {
                                released_route_bytes += destination_cidr_block.len();
                            }
                            !doomed
                        });
                    }
                    // The removal is applied once; nothing is owed on this route any more.
                    return false;
                }
                if let Some(route) = view.routes.iter_mut().flatten().find(|route| {
                    route.destination_cidr_block.as_deref()
                        == Some(destination_cidr_block.as_str())
                }) {
                    route.state = Some(state);
                }
                // The move is applied once; nothing is owed on this route any more.
                false
            });
        }
        self.release_stored_bytes(released_route_bytes);
        // A customer gateway written in a non-terminal `CustomerGateway$State` reaches the
        // state recorded for it once its due instant has passed, whether or not anybody
        // called — the same contract as the VPN connection's own move above.
        for record in self.customer_gateways.values_mut() {
            if let Some(state) = record
                .pending
                .as_ref()
                .and_then(|owed| owed.due_by(now))
                .map(str::to_string)
            {
                record.view.state = Some(state);
                record.pending = None;
            }
        }
        // A target network association `AssociateClientVpnTargetNetwork` answered as
        // `associating` is `associated` once its due instant has passed, whether or not
        // anybody called again — the same contract as a `pending` VPC's move above.
        self.materialize_due_client_vpn_target_networks(now);
        // A route `CreateClientVpnRoute` answered as `creating` is `active` once its due
        // instant has passed, whether or not anybody called again — the same contract as the
        // target network association above.
        self.materialize_due_client_vpn_routes(now);
        // An IPAM pool `CreateIpamPool` answered as `create-in-progress` reaches
        // `create-complete` once its due instant has passed, whether or not anybody called —
        // the same contract as the `pending` VPC above, and the reason the pool's due
        // instant is kept beside the pool rather than on the modelled shape.
        let ipam_pools = &mut self.ipam_pools;
        self.ipam_pool_create_complete_at.retain(|pool_id, due_at| {
            if now < *due_at {
                return true;
            }
            if let Some(pool) = ipam_pools.get_mut(pool_id) {
                if pool.state.as_deref() == Some(IPAM_POOL_STATE_CREATE_IN_PROGRESS) {
                    pool.state = Some(IPAM_POOL_STATE_CREATE_COMPLETE.to_string());
                }
            }
            // The transition is applied once; nothing is owed on this pool any more.
            false
        });
        // A pool `DeleteIpamPool` answered as `delete-in-progress` reaches `delete-complete`
        // once its due instant has passed, whether or not anybody called — the other end of
        // the same pool's life, owed and applied exactly as its creation was above.
        let ipam_pools = &mut self.ipam_pools;
        self.ipam_pool_delete_complete_at.retain(|pool_id, due_at| {
            if now < *due_at {
                return true;
            }
            if let Some(pool) = ipam_pools.get_mut(pool_id) {
                if pool.state.as_deref() == Some(IPAM_POOL_STATE_DELETE_IN_PROGRESS) {
                    pool.state = Some(IPAM_POOL_STATE_DELETE_COMPLETE.to_string());
                }
            }
            false
        });
        // A CIDR `ProvisionIpamPoolCidr` answered as `pending-provision` is `provisioned`
        // once its due instant has passed, and one `DeprovisionIpamPoolCidr` answered as
        // `pending-deprovision` has left its pool at its own instant — both owed whether or
        // not anybody called, the same contract as the pool's moves above.
        self.materialize_due_ipam_pool_cidr_moves(now);
        // An IPAM scope `CreateIpamScope` answered as `create-in-progress` reaches
        // `create-complete` once its due instant has passed, whether or not anybody called —
        // the same contract as the pool above. The two default scopes of an IPAM are not
        // listed here: `complete_ipam_creation` moves them with the IPAM they came up with.
        let ipam_scopes = &mut self.ipam_scopes;
        self.ipam_scope_create_complete_at.retain(|scope_id, due_at| {
            if now < *due_at {
                return true;
            }
            if let Some(scope) = ipam_scopes.get_mut(scope_id) {
                if scope.state.as_deref() == Some(IPAM_STATE_CREATE_IN_PROGRESS) {
                    scope.state = Some(IPAM_STATE_CREATE_COMPLETE.to_string());
                }
            }
            // The transition is applied once; nothing is owed on this scope any more.
            false
        });
        // An IPAM prefix list resolver `CreateIpamPrefixListResolver` answered as
        // `create-in-progress` reaches `create-complete` once its due instant has passed,
        // whether or not anybody called — the same contract as the IPAM scope above; the
        // `IpamPrefixListResolverState` enum carries those two members under the same spellings.
        let resolvers = &mut self.ipam_prefix_list_resolvers;
        self.ipam_prefix_list_resolver_create_complete_at
            .retain(|resolver_id, due_at| {
                if now < *due_at {
                    return true;
                }
                if let Some(resolver) = resolvers.get_mut(resolver_id) {
                    if resolver.state.as_deref() == Some(IPAM_STATE_CREATE_IN_PROGRESS) {
                        resolver.state = Some(IPAM_STATE_CREATE_COMPLETE.to_string());
                    }
                }
                // The transition is applied once; nothing is owed on this resolver any more.
                false
            });
        // An IPAM prefix list resolver target `CreateIpamPrefixListResolverTarget` answered as
        // `create-in-progress` reaches `create-complete` once its due instant has passed,
        // whether or not anybody called — the same contract as the scope above, and the reason
        // the target's due instant is kept beside the target rather than on the modelled shape.
        let resolver_targets = &mut self.ipam_prefix_list_resolver_targets;
        self.ipam_prefix_list_resolver_target_create_complete_at
            .retain(|target_id, due_at| {
                if now < *due_at {
                    return true;
                }
                if let Some(target) = resolver_targets.get_mut(target_id) {
                    if target.state.as_deref()
                        == Some(IPAM_PREFIX_LIST_RESOLVER_TARGET_STATE_CREATE_IN_PROGRESS)
                    {
                        target.state = Some(
                            IPAM_PREFIX_LIST_RESOLVER_TARGET_STATE_CREATE_COMPLETE.to_string(),
                        );
                    }
                }
                // The transition is applied once; nothing is owed on this target any more.
                false
            });
        // A resource discovery association `AssociateIpamResourceDiscovery` answered as
        // `associate-in-progress` reaches `associate-complete` once its due instant has
        // passed, whether or not anybody called — the same contract as the scope above. The
        // DEFAULT association of an IPAM is not listed here: `complete_ipam_creation` moves
        // it with the IPAM it came up with.
        let ipam_associations = &mut self.ipam_resource_discovery_associations;
        self.ipam_resource_discovery_association_complete_at
            .retain(|association_id, due_at| {
                if now < *due_at {
                    return true;
                }
                if let Some(association) = ipam_associations.get_mut(association_id) {
                    if association.state.as_deref()
                        == Some(IPAM_ASSOCIATION_STATE_ASSOCIATE_IN_PROGRESS)
                    {
                        association.state =
                            Some(IPAM_ASSOCIATION_STATE_ASSOCIATE_COMPLETE.to_string());
                    }
                }
                // The transition is applied once; nothing is owed on this association any
                // more.
                false
            });
        // A Verified Access endpoint `CreateVerifiedAccessEndpoint` answered as `pending`
        // reaches `active` once its due instant has passed, whether or not anybody called —
        // the same contract as a `pending` VPC's move above, and the reason the endpoint's
        // due instant is kept beside the modelled shape rather than on it.
        for record in self.verified_access_endpoints.values_mut() {
            let due = record
                .pending
                .as_ref()
                .filter(|pending| now >= pending.due_at)
                .cloned();
            if let Some(pending) = due {
                record.view.status = Some(crate::ops::types::VerifiedAccessEndpointStatus {
                    code: Some(pending.to.to_string()),
                    message: None,
                });
                // The endpoint changed when the move fell due, not when somebody next asked
                // about it, so "The last updated time" (`VerifiedAccessEndpoint$
                // LastUpdatedTime`) is the due instant.
                record.view.last_updated_time = Some(iso8601_utc(pending.at));
                record.pending = None;
            }
        }
        // A VPC BPA exclusion `CreateVpcBlockPublicAccessExclusion` answered as
        // `create-in-progress` reaches `create-complete` once its due instant has passed,
        // whether or not anybody called — the same contract as a `pending` VPC's move
        // above.
        for record in self.vpc_block_public_access_exclusions.values_mut() {
            let due = record
                .pending
                .as_ref()
                .filter(|pending| now >= pending.due_at)
                .cloned();
            if let Some(pending) = due {
                record.view.state = Some(pending.to.to_string());
                // The exclusion changed when the move fell due, not when somebody next
                // asked about it, so "when the exclusion was last updated"
                // (`VpcBlockPublicAccessExclusion$LastUpdateTimestamp`) is the due instant.
                record.view.last_update_timestamp = Some(system_time_to_date_time(pending.at));
                record.pending = None;
            }
        }
        // A Region's VPC BPA options a `ModifyVpcBlockPublicAccessOptions` answered as
        // `update-in-progress` reach `update-complete` once that update's due instant has
        // passed, whether or not anybody called — the same contract as the exclusion move
        // above.
        self.complete_due_vpc_block_public_access_option_updates(now);
        // An association `CreateLocalGatewayRouteTableVpcAssociation` answered as
        // `associating` reaches `associated` once its due instant has passed, whether or not
        // anybody called — the same contract as the `pending` VPC above.
        for record in self.local_gateway_route_table_vpc_associations.values_mut() {
            let due = record
                .pending
                .as_ref()
                .and_then(|pending| pending.due_by(now))
                .map(str::to_string);
            if let Some(state) = due {
                record.view.state = Some(state);
                record.pending = None;
            }
        }
        // An association `CreateLocalGatewayRouteTableVirtualInterfaceGroupAssociation`
        // answered as `associating` reaches `associated` the same way, on the same clock.
        for record in self
            .local_gateway_route_table_virtual_interface_group_associations
            .values_mut()
        {
            let due = record
                .pending
                .as_ref()
                .and_then(|pending| pending.due_by(now))
                .map(str::to_string);
            if let Some(state) = due {
                record.view.state = Some(state);
                record.pending = None;
            }
        }
        // A virtual interface GROUP `CreateLocalGatewayVirtualInterfaceGroup` answered as
        // `pending` is up once its due instant has passed, whether or not anybody called —
        // the same contract as the association above, on the same clock. The due instant is
        // dropped with the move, so a group reaches `available` once.
        let due: Vec<String> = self
            .local_gateway_virtual_interface_group_available_at
            .iter()
            .filter(|(_, available_at)| now >= **available_at)
            .map(|(group_id, _)| group_id.clone())
            .collect();
        for group_id in due {
            self.local_gateway_virtual_interface_group_available_at
                .remove(&group_id);
            if let Some(group) = self.local_gateway_virtual_interface_groups.get_mut(&group_id) {
                group.configuration_state =
                    Some(LOCAL_GATEWAY_VIF_GROUP_STATE_AVAILABLE.to_string());
            }
        }
        // A virtual interface `CreateLocalGatewayVirtualInterface` answered as `pending` is
        // carrying traffic once its due instant has passed, whether or not anybody called —
        // the same contract as the association above, on the same clock. The due instant is
        // dropped with the move, so an interface reaches `available` once.
        let due: Vec<String> = self
            .local_gateway_virtual_interface_available_at
            .iter()
            .filter(|(_, available_at)| now >= **available_at)
            .map(|(virtual_interface_id, _)| virtual_interface_id.clone())
            .collect();
        for virtual_interface_id in due {
            self.local_gateway_virtual_interface_available_at
                .remove(&virtual_interface_id);
            if let Some(virtual_interface) = self
                .local_gateway_virtual_interfaces
                .get_mut(&virtual_interface_id)
            {
                virtual_interface.configuration_state =
                    Some(LOCAL_GATEWAY_VIF_STATE_AVAILABLE.to_string());
            }
        }
        // A route `CreateLocalGatewayRoute` answered as `pending` is carrying traffic once
        // its due instant has passed, whether or not anybody called — the same contract as
        // the `pending` VPC above. A route is reached only through the table it is in, so
        // the moves are applied table by table, and the TABLE's own move —
        // `CreateLocalGatewayRouteTable` answers a new table `pending`, which the clock owes
        // `available` — falls due on the same clock.
        for table in self.local_gateway_route_tables.values_mut() {
            let due = table
                .pending
                .as_ref()
                .and_then(|pending| pending.due_by(now))
                .map(str::to_string);
            if let Some(state) = due {
                table.view.state = Some(state);
                table.pending = None;
            }
            for record in table.routes.values_mut() {
                let due = record
                    .pending
                    .as_ref()
                    .and_then(|pending| pending.due_by(now))
                    .map(str::to_string);
                if let Some(state) = due {
                    record.view.state = Some(state);
                    record.pending = None;
                }
            }
        }
        // The end of a release `DeprovisionByoipCidr` started: at its due instant the
        // range either stops being one of the account's ranges or lands in
        // `failed-deprovision`, whether or not anybody called again.
        //
        // Which of the two is decided HERE, at the due instant, from the addresses the
        // account holds out of the range THEN: "Ensure that all EIPs from the range have
        // been deallocated and try again" (`ByoipCidrState`'s `failed-deprovision`) is a
        // question about the end of the release, so a caller that gives an address back
        // while the range is `pending-deprovision` still gets its release.
        let due: Vec<String> = self
            .byoip_cidrs
            .iter()
            .filter(|(_, record)| {
                record
                    .released_at
                    .is_some_and(|released_at| now >= released_at)
            })
            .map(|(cidr, _)| cidr.clone())
            .collect();
        for cidr in due {
            let held = self.addresses_in_byoip_cidr(&cidr);
            if held.is_empty() {
                // The release succeeded: the range is not one of the account's any more, so
                // the bytes its record held go back to the budget — exactly what
                // [`Self::insert_byoip_cidr`] charged for it. The move the clock may still
                // have owed the range goes with the record that carried it
                // ([`ByoipCidrRecord::pending`]), so nothing can resurrect a released range.
                if let Some(record) = self.byoip_cidrs.remove(&cidr) {
                    self.release_stored_bytes(byoip_cidr_payload_bytes(&record));
                    // The address pool the provision created for the range goes with it: a
                    // pool holds the addresses OF a range, so once the account does not hold
                    // the range there is no pool of those addresses either, and its bytes
                    // return to the budget as well. The id names a pool of ONE of the two
                    // families, so at most one of these removals finds anything.
                    if let Some(pool_id) = record.byoip_cidr.pool_id.as_deref() {
                        self.remove_public_ipv4_pool(pool_id);
                        self.remove_ipv6_pool(pool_id);
                    }
                }
                continue;
            }
            // "failed-deprovision: The request to deprovision the address range was
            // unsuccessful" (`ByoipCidrState`) — the range stays the account's, carrying
            // why in its `StatusMessage` ("Otherwise, contains an error message",
            // `ByoipCidr$StatusMessage`), and can be released again once the caller has
            // cleared what held it.
            let reason = byoip_cidr_release_failure(&held);
            if let Some(record) = self.byoip_cidrs.get_mut(&cidr) {
                record.released_at = None;
                record.byoip_cidr.state = Some(BYOIP_CIDR_STATE_FAILED_DEPROVISION.to_string());
                record.byoip_cidr.status_message = Some(reason);
            }
        }
        let transit_gateways = &mut self.transit_gateways;
        let route_tables = &mut self.transit_gateway_route_tables;
        self.transit_gateway_available_at
            .retain(|transit_gateway_id, due_at| {
                if now < *due_at {
                    return true;
                }
                // The gateway's own route tables come up with it: a route table AWS
                // reports as `pending` is `available` once the gateway is. They are
                // reached through the ids the gateway's options name, so this costs a
                // lookup per role rather than a scan of every route table the store holds.
                let mut owed: Vec<String> = Vec::new();
                if let Some(transit_gateway) = transit_gateways.get_mut(transit_gateway_id) {
                    // `pending` is the state a create answers with and `modifying` the one a
                    // modification answers with: both end with the gateway usable again, so
                    // both are owed `available` on this instant.
                    if matches!(
                        transit_gateway.state.as_deref(),
                        Some(TRANSIT_GATEWAY_STATE_PENDING | TRANSIT_GATEWAY_STATE_MODIFYING)
                    ) {
                        transit_gateway.state = Some(TRANSIT_GATEWAY_STATE_AVAILABLE.to_string());
                    }
                    if let Some(options) = transit_gateway.options.as_mut() {
                        // VPC Encryption Control is turned on or off over the span of the
                        // modification that asked for it, so the transient state that
                        // modification answered with reaches its terminal one here
                        // (`EncryptionStateValue`).
                        if let Some(encryption) = options.encryption_support.as_mut() {
                            match encryption.encryption_state.as_deref() {
                                Some(ENCRYPTION_STATE_ENABLING) => {
                                    encryption.encryption_state =
                                        Some(ENCRYPTION_STATE_ENABLED.to_string());
                                }
                                Some(ENCRYPTION_STATE_DISABLING) => {
                                    encryption.encryption_state =
                                        Some(ENCRYPTION_STATE_DISABLED.to_string());
                                }
                                _ => {}
                            }
                        }
                        owed.extend(options.association_default_route_table_id.clone());
                        owed.extend(options.propagation_default_route_table_id.clone());
                    }
                }
                for route_table_id in owed {
                    if let Some(route_table) = route_tables.get_mut(&route_table_id) {
                        if route_table.state.as_deref()
                            == Some(TRANSIT_GATEWAY_ROUTE_TABLE_STATE_PENDING)
                        {
                            route_table.state =
                                Some(TRANSIT_GATEWAY_ROUTE_TABLE_STATE_AVAILABLE.to_string());
                        }
                    }
                }
                // The transition is applied once; nothing is owed on this gateway any more.
                false
            });
        // A route table `CreateTransitGatewayRouteTable` added to a gateway comes up on its
        // own due instant rather than with the gateway, which may have been `available`
        // long before the table was asked for.
        let route_tables = &mut self.transit_gateway_route_tables;
        self.transit_gateway_route_table_available_at
            .retain(|route_table_id, due_at| {
                if now < *due_at {
                    return true;
                }
                if let Some(route_table) = route_tables.get_mut(route_table_id) {
                    if route_table.state.as_deref()
                        == Some(TRANSIT_GATEWAY_ROUTE_TABLE_STATE_PENDING)
                    {
                        route_table.state =
                            Some(TRANSIT_GATEWAY_ROUTE_TABLE_STATE_AVAILABLE.to_string());
                    }
                }
                // The transition is applied once; nothing is owed on this table any more.
                false
            });
        // A transit gateway a `DeleteTransitGateway` left `deleting` was GONE at the instant
        // that call recorded for it, with the route tables that came up with it — whether or
        // not anybody called again. The gateway family's one clock-owed REMOVAL, for the reason
        // [`Self::begin_transit_gateway_deletion`] gives: a deleted gateway is one
        // `DescribeTransitGateways` stops carrying.
        self.materialize_due_transit_gateway_deletions(now);
        // A route server, its endpoints and its peers come up the same way: each is
        // answered in the non-terminal `pending` state its create hands back, so the clock
        // owes it `available` one TRANSITION_DELAY later whether or not anybody calls
        // again. A route server whose create asked for route persistence is `enabling` it
        // over exactly that span, so it reaches `enabled` on the same instant.
        let route_server_endpoints = &mut self.route_server_endpoints;
        self.route_server_endpoint_available_at
            .retain(|route_server_endpoint_id, due_at| {
                if now < *due_at {
                    return true;
                }
                if let Some(endpoint) = route_server_endpoints.get_mut(route_server_endpoint_id) {
                    if endpoint.state.as_deref() == Some(ROUTE_SERVER_ENDPOINT_STATE_PENDING) {
                        endpoint.state = Some(ROUTE_SERVER_ENDPOINT_STATE_AVAILABLE.to_string());
                    }
                }
                false
            });
        // An endpoint goes down the same way it came up: `DeleteRouteServerEndpoint` answers
        // it in the non-terminal `deleting` state, so the clock owes it the terminal
        // `deleted` one TRANSITION_DELAY later whether or not anybody calls again.
        self.route_server_endpoint_deleted_at
            .retain(|route_server_endpoint_id, due_at| {
                if now < *due_at {
                    return true;
                }
                if let Some(endpoint) = route_server_endpoints.get_mut(route_server_endpoint_id) {
                    if endpoint.state.as_deref() == Some(ROUTE_SERVER_ENDPOINT_STATE_DELETING) {
                        endpoint.state = Some(ROUTE_SERVER_ENDPOINT_STATE_DELETED.to_string());
                    }
                }
                false
            });
        let route_server_peers = &mut self.route_server_peers;
        self.route_server_peer_available_at
            .retain(|route_server_peer_id, due_at| {
                if now < *due_at {
                    return true;
                }
                if let Some(peer) = route_server_peers.get_mut(route_server_peer_id) {
                    if peer.state.as_deref() == Some(ROUTE_SERVER_PEER_STATE_PENDING) {
                        peer.state = Some(ROUTE_SERVER_PEER_STATE_AVAILABLE.to_string());
                    }
                }
                false
            });
        // A peer goes down the same way it came up: `DeleteRouteServerPeer` answers it in
        // the non-terminal `deleting` state, so the clock owes it the terminal `deleted`
        // one TRANSITION_DELAY later whether or not anybody calls again.
        self.route_server_peer_deleted_at
            .retain(|route_server_peer_id, due_at| {
                if now < *due_at {
                    return true;
                }
                if let Some(peer) = route_server_peers.get_mut(route_server_peer_id) {
                    if peer.state.as_deref() == Some(ROUTE_SERVER_PEER_STATE_DELETING) {
                        peer.state = Some(ROUTE_SERVER_PEER_STATE_DELETED.to_string());
                    }
                }
                false
            });
        // A secondary subnet goes down the same way: `DeleteSecondarySubnet` answers it in
        // the non-terminal `delete-in-progress` state with its IPv4 CIDR blocks
        // `disassociating`, so the clock owes it `delete-complete` with those blocks
        // `disassociated` one TRANSITION_DELAY later whether or not anybody calls again.
        self.materialize_due_secondary_subnet_deletions(now);
        self.fast_launch_images.retain(|_image_id, record| {
            let Some(pending) = record
                .pending
                .as_ref()
                .filter(|pending| now >= pending.due_at)
                .cloned()
            else {
                return true;
            };
            match pending.to {
                // "Discontinue Windows fast launch for a Windows AMI, and clean up existing
                // pre-provisioned snapshots" (`DisableFastLaunch`): once the cleanup the
                // disable started is done there is nothing left to report — the image is no
                // longer a Windows fast launch enabled image, and `FastLaunchStateCode` has
                // no member for one that is not.
                FastLaunchMove::Discontinued => false,
                FastLaunchMove::Enabled => {
                    record.view.state = Some(FAST_LAUNCH_STATE_ENABLED.to_string());
                    // The state changed when the move fell due, not when somebody asked
                    // about it, so the time reported is the due instant.
                    record.view.state_transition_time =
                        Some(system_time_to_date_time(pending.at));
                    record.pending = None;
                    true
                }
            }
        });
        // The end of a Network Access Scope analysis `StartNetworkInsightsAccessScopeAnalysis`
        // answered as `running`: at its due instant the analysis reaches the terminal
        // `AnalysisStatus` the start recorded for it, whether or not anybody called again —
        // the same contract as a `pending` VPC's move above.
        for record in self.network_insights_access_scope_analyses.values_mut() {
            let Some(pending) = record
                .pending
                .as_ref()
                .filter(|pending| now >= pending.due_at)
                .cloned()
            else {
                continue;
            };
            record.view.status = Some(pending.to.to_string());
            // "The analysis end date" (`NetworkInsightsAccessScopeAnalysis$EndDate`): the
            // analysis ended when the move fell due, not when somebody next asked about it.
            record.view.end_date = Some(system_time_to_date_time(pending.at));
            record.view.status_message = Some(ANALYSIS_UNSUPPORTED_STATUS_MESSAGE.to_string());
            // "Indicates whether there are findings"
            // (`NetworkInsightsAccessScopeAnalysis$FindingsFound`): nothing analyzed this
            // scope, so whether it has findings was never determined — which is exactly
            // what the `FindingsFound` catalog's `unknown` member says. `AnalyzedEniCount`
            // stays absent for the same reason: no network interface was analyzed.
            record.view.findings_found = Some(FINDINGS_FOUND_UNKNOWN.to_string());
            record.pending = None;
        }
        // The end of a path analysis `StartNetworkInsightsAnalysis` answered as `running`,
        // on the same contract as the access scope analysis above: at its due instant the
        // analysis reaches the terminal `AnalysisStatus` the start recorded for it, whether
        // or not anybody called again.
        for record in self.network_insights_analyses.values_mut() {
            let Some(pending) = record
                .pending
                .as_ref()
                .filter(|pending| now >= pending.due_at)
                .cloned()
            else {
                continue;
            };
            record.view.status = Some(pending.to.to_string());
            record.view.status_message =
                Some(PATH_ANALYSIS_UNSUPPORTED_STATUS_MESSAGE.to_string());
            // "Indicates whether the destination is reachable from the source"
            // (`NetworkInsightsAnalysis$NetworkPathFound`): nothing traced this path, so
            // whether it is reachable was never determined, and a boolean either way would
            // be a result no engine produced. It stays absent, as do the path components,
            // the explanations and the hints that only a trace could fill in.
            record.pending = None;
        }
        // Each IPAM whose `create-complete` has fallen due, with the scopes, resource
        // discovery and association the same `CreateIpam` call created. The due ids are
        // collected first because completing one borrows the other IPAM stores.
        let due_ipams: Vec<String> = self
            .ipam_create_complete_at
            .iter()
            .filter(|(_, due_at)| now >= **due_at)
            .map(|(ipam_id, _)| ipam_id.clone())
            .collect();
        for ipam_id in due_ipams {
            // The transition is applied once; nothing is owed on this IPAM any more.
            self.ipam_create_complete_at.remove(&ipam_id);
            self.complete_ipam_creation(&ipam_id);
        }
        // An IPAM `ModifyIpam` answered as `modify-in-progress` reaches `modify-complete`
        // once its due instant has passed, whether or not anybody called — the same contract
        // as the IPAM scope above. Only an IPAM still in the state the modification left it
        // in is moved, so one something else has since moved on is left alone.
        let ipams = &mut self.ipams;
        self.ipam_modify_complete_at.retain(|ipam_id, due_at| {
            if now < *due_at {
                return true;
            }
            if let Some(ipam) = ipams.get_mut(ipam_id) {
                if ipam.state.as_deref() == Some(IPAM_STATE_MODIFY_IN_PROGRESS) {
                    ipam.state = Some(IPAM_STATE_MODIFY_COMPLETE.to_string());
                }
            }
            // The transition is applied once; nothing is owed on this IPAM any more.
            false
        });
        // An IPAM `DeleteIpam` answered as `delete-in-progress` was GONE at the instant that
        // call recorded for it, with everything it contained — whether or not anybody called
        // again. The one clock-owed REMOVAL of the IPAM family, for the reason
        // [`Self::begin_ipam_deletion`] gives: a deleted IPAM is one `DescribeIpams` reports
        // as not existing.
        self.materialize_due_ipam_deletions(now);
        // The resources whose own record carries the move the clock owes it
        // ([`PendingStateMove`]): a transit gateway attachment an acceptance or a rejection
        // left transient, one subnet association of a multicast domain, a route table
        // announcement a delete started on, and a BYOIP range whose advertisement was asked
        // for. Each move was due at its instant whether or not anybody called, so applying
        // it here changes nothing a later caller would not have seen anyway.
        for record in self.transit_gateway_attachments.values_mut() {
            if let Some(state) = record
                .pending
                .as_ref()
                .and_then(|pending| pending.due_by(now))
                .map(str::to_string)
            {
                record.view.set_state(&state);
                record.pending = None;
            }
        }
        for domain in self.transit_gateway_multicast_domains.values_mut() {
            for association in &mut domain.associations {
                if let Some(state) = association
                    .pending
                    .as_ref()
                    .and_then(|pending| pending.due_by(now))
                    .map(str::to_string)
                {
                    association.state = state;
                    association.pending = None;
                }
            }
        }
        for record in self.transit_gateway_route_table_announcements.values_mut() {
            if let Some(state) = record
                .pending
                .as_ref()
                .and_then(|pending| pending.due_by(now))
                .map(str::to_string)
            {
                record.view.state = Some(state);
                record.pending = None;
            }
        }
        for record in self.transit_gateway_connect_peers.values_mut() {
            if let Some(state) = record
                .pending
                .as_ref()
                .and_then(|pending| pending.due_by(now))
                .map(str::to_string)
            {
                record.view.state = Some(state);
                record.pending = None;
            }
        }
        // A virtual private gateway `CreateVpnGateway` left `pending` or `DeleteVpnGateway`
        // left `deleting`: each reaches the terminal `VpnState` the write recorded for it at
        // the instant it was owed, whether or not anybody called again — the same contract
        // as the records above.
        for record in self.vpn_gateways.values_mut() {
            if let Some(state) = record
                .pending
                .as_ref()
                .and_then(|pending| pending.due_by(now))
                .map(str::to_string)
            {
                record.view.state = Some(state);
                record.pending = None;
            }
        }
        // One attachment's association with a policy table, which
        // `AssociateTransitGatewayPolicyTable` leaves in the transient `associating` state
        // with `associated` owed: the same contract as the multicast domain associations
        // above.
        for table in self.transit_gateway_policy_tables.values_mut() {
            for association in table.associations.values_mut() {
                if let Some(state) = association
                    .pending
                    .as_ref()
                    .and_then(|pending| pending.due_by(now))
                    .map(str::to_string)
                {
                    association.view.state = Some(state);
                    association.pending = None;
                }
            }
        }
        // One attachment's association with a ROUTE table, which
        // `AssociateTransitGatewayRouteTable` leaves in the transient `associating` state
        // with `associated` owed: the same contract as the policy table associations above.
        for association in self.transit_gateway_associations.values_mut() {
            if let Some(state) = association
                .pending
                .as_ref()
                .and_then(|pending| pending.due_by(now))
                .map(str::to_string)
            {
                association.state = state;
                association.pending = None;
            }
        }
        // A metering policy `CreateTransitGatewayMeteringPolicy` left `pending`: it reaches
        // the state that write recorded for it at the instant it was owed, whether or not
        // anybody called again — the same contract as the records above. The move is held
        // beside the store because the modelled shape carries no member for it, so the
        // policy itself is reached through the id the move is keyed by.
        let metering_policies = &mut self.transit_gateway_metering_policies;
        self.transit_gateway_metering_policy_moves
            .retain(|metering_policy_id, owed| {
                let Some(state) = owed.due_by(now).map(str::to_string) else {
                    return true;
                };
                if let Some(policy) = metering_policies.get_mut(metering_policy_id) {
                    policy.state = Some(state);
                }
                // The transition is applied once; nothing is owed on this policy any more.
                false
            });
        // One routing policy registration a delete (or another write) left transient, and
        // the delta that write minted: the registration reaches the terminal state the
        // write recorded for it and the delta reaches `published`, both at the instant they
        // were owed whether or not anybody called — the same contract as the policy table
        // associations above.
        for association in self.ipam_internet_registry_associations.values_mut() {
            for registration in association.registrations.values_mut() {
                if let Some(state) = registration
                    .pending
                    .as_ref()
                    .and_then(|pending| pending.due_by(now))
                    .map(str::to_string)
                {
                    registration.view.state = Some(state);
                    registration.pending = None;
                }
            }
        }
        // One internet registry association a create or a delete left transient: it reaches
        // the terminal state that write recorded for it at the instant it was owed, whether
        // or not anybody called, and "a message describing the current state of the internet
        // registry association" (`IpamInternetRegistryAssociation$StateMessage`) moves with
        // the state rather than keeping the in-progress wording.
        //
        // The due associations are collected first, the way the policy block below collects
        // its due policies, so each swap of the stored message is charged against the store's
        // byte budget exactly as the write that started the deletion charged it
        // ([`Self::begin_ipam_internet_registry_association_deletion`]) — the budget cannot
        // drift by the length difference between the two messages.
        let due_associations: Vec<String> = self
            .ipam_internet_registry_associations
            .iter()
            .filter(|(_, record)| {
                record
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.due_by(now).is_some())
            })
            .map(|(association_id, _)| association_id.clone())
            .collect();
        for association_id in due_associations {
            let Some(record) = self
                .ipam_internet_registry_associations
                .get_mut(&association_id)
            else {
                continue;
            };
            let Some(state) = record
                .pending
                .as_ref()
                .and_then(|pending| pending.due_by(now))
                .map(str::to_string)
            else {
                continue;
            };
            let mut released = 0usize;
            let mut charged = 0usize;
            if let Some(message) = ipam_internet_registry_association_state_message(&state) {
                released = record.view.state_message.as_deref().map_or(0, str::len);
                charged = message.len();
                record.view.state_message = Some(message.to_string());
            }
            record.view.state = Some(state);
            record.pending = None;
            self.release_stored_bytes(released);
            self.add_stored_bytes(charged);
        }
        // One IPAM policy a delete left transient: it reaches the terminal state that
        // delete recorded for it at the instant it was owed, whether or not anybody called,
        // and "a message about the state of the IPAM policy" (`IpamPolicy$StateMessage`)
        // moves with the state rather than keeping the in-progress wording.
        //
        // The due policies are collected first, the way the BYOIP block above collects its
        // due ranges, so each swap of the stored message can be charged against the store's
        // byte budget exactly as the write that started the deletion charged it
        // ([`Self::begin_ipam_policy_deletion`]) — the budget cannot drift by the length
        // difference between the two messages.
        let due_policies: Vec<String> = self
            .ipam_policies
            .iter()
            .filter(|(_, record)| {
                record
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.due_by(now).is_some())
            })
            .map(|(policy_id, _)| policy_id.clone())
            .collect();
        for policy_id in due_policies {
            let Some(record) = self.ipam_policies.get_mut(&policy_id) else {
                continue;
            };
            let Some(state) = record
                .pending
                .as_ref()
                .and_then(|pending| pending.due_by(now))
                .map(str::to_string)
            else {
                continue;
            };
            let mut released = 0usize;
            let mut charged = 0usize;
            if state == IPAM_POLICY_STATE_DELETE_COMPLETE {
                released = record.view.state_message.as_deref().map_or(0, str::len);
                charged = IPAM_POLICY_DELETE_COMPLETE_MESSAGE.len();
                record.view.state_message = Some(IPAM_POLICY_DELETE_COMPLETE_MESSAGE.to_string());
            }
            record.view.state = Some(state);
            record.pending = None;
            self.release_stored_bytes(released);
            self.add_stored_bytes(charged);
        }
        for record in self.ipam_routing_policy_registration_deltas.values_mut() {
            if let Some(state) = record
                .pending
                .as_ref()
                .and_then(|pending| pending.due_by(now))
                .map(str::to_string)
            {
                // "A message describing the current state"
                // (`IpamRoutingPolicyRegistrationDelta$StateMessage`) is about the state the
                // delta is in, so it moves with it rather than keeping the pending wording.
                record.view.state_message =
                    Some(IPAM_ROUTING_POLICY_REGISTRATION_DELTA_PUBLISHED_MESSAGE.to_string());
                record.view.state = Some(state);
                record.pending = None;
            }
        }
        for record in self.byoip_cidrs.values_mut() {
            if let Some(state) = record
                .pending
                .as_ref()
                .and_then(|pending| pending.due_by(now))
                .map(str::to_string)
            {
                // A range leaving `pending-provision` is one whose provision has just
                // completed — "the address range is not ready to use until its status
                // changes from pending-provision to provisioned" (`ProvisionByoipCidr`) —
                // and "Upon success, contains the ID of the address pool"
                // (`ByoipCidr$StatusMessage`) is what there is to report from that instant
                // on, where until it there was no success to report.
                if record.byoip_cidr.state.as_deref() == Some(BYOIP_CIDR_STATE_PENDING_PROVISION) {
                    record.byoip_cidr.status_message = record.byoip_cidr.pool_id.clone();
                }
                record.byoip_cidr.state = Some(state);
                record.pending = None;
            }
        }
        // The end of bringing one ASN to IPAM, and the end of giving one back: an ASN
        // `ProvisionIpamByoasn` left in `pending-provision`, or one `DeprovisionIpamByoasn`
        // left in `pending-deprovision`, reaches the state that call was headed for, at the
        // instant it was owed whether or not anybody called — the same contract as the
        // address ranges above.
        //
        // WHAT a release ends as is decided HERE, at the due instant, from the associations
        // the ASN still holds THEN: "This action can only be called after any BYOIP CIDR
        // associations are removed from your Amazon Web Services account with
        // DisassociateIpamByoasn" (`DeprovisionIpamByoasn`), so a caller that clears the last
        // association while the ASN is `pending-deprovision` still gets its release, and one
        // that leaves an association in place gets `failed-deprovision` carrying why — the
        // same way a range's release is decided from the addresses allocated out of it.
        let due_byoasns: Vec<String> = self
            .byoasns
            .iter()
            .filter(|(_, record)| {
                record
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.due_by(now).is_some())
            })
            .map(|(asn, _)| asn.clone())
            .collect();
        for asn in due_byoasns {
            let Some(headed_for) = self
                .byoasns
                .get(&asn)
                .and_then(|record| record.pending.as_ref())
                .map(|pending| pending.to.clone())
            else {
                continue;
            };
            // Only a RELEASE has an outcome to decide; every other move the clock owes an
            // ASN lands where it was headed.
            let held = if headed_for == ASN_STATE_DEPROVISIONED {
                self.byoip_cidrs_associated_with_asn(&asn)
            } else {
                Vec::new()
            };
            let Some(record) = self.byoasns.get_mut(&asn) else {
                continue;
            };
            if held.is_empty() {
                record.byoasn.state = Some(headed_for);
            } else {
                // The ASN stays the account's, carrying why in its `StatusMessage` ("The
                // status message", `Byoasn$StatusMessage`), and can be given back again once
                // the caller has cleared what held it. The message is bounded by what the
                // store holds, so it is rewritten in place rather than re-charged against
                // the byte budget, exactly as a range's failed release is.
                record.byoasn.state = Some(ASN_STATE_FAILED_DEPROVISION.to_string());
                record.byoasn.status_message = Some(byoasn_release_failure(&held));
            }
            record.pending = None;
        }
        // The end of one ASN-and-range association: "After the association succeeds, the
        // ASN is eligible for advertisement" (`AssociateIpamByoasn`), so an association
        // answered as `pending-association` reaches its terminal state here. The move lives
        // beside the ranges because `AsnAssociation` has no member for it, and it is applied
        // ONCE — the entry is dropped whether or not the association it names is still
        // there, so a range that was released meanwhile leaves nothing owed behind. The one
        // state word is rewritten in place and deliberately NOT re-charged against the byte
        // budget: the terminal word is no longer than the pending one, so the charge
        // `insert_byoip_cidr` took stays an upper bound on what the record holds.
        let byoip_cidrs = &mut self.byoip_cidrs;
        self.asn_association_moves.retain(|(cidr, asn), pending| {
            // Through the one definition of "has this move come due", the same
            // [`PendingStateMove::due_by`] every block above asks.
            let Some(state) = pending.due_by(now).map(str::to_string) else {
                return true;
            };
            if let Some(association) = byoip_cidrs
                .get_mut(cidr)
                .and_then(|record| record.byoip_cidr.asn_associations.as_mut())
                .and_then(|associations| {
                    associations
                        .iter_mut()
                        .find(|association| association.asn.as_deref() == Some(asn.as_str()))
                })
            {
                association.state = Some(state);
            }
            false
        });
        // The move a Capacity Reservation is owed: the interruptible allocation a
        // `CreateInterruptibleCapacityReservationAllocation` started completes, and the
        // interruptible Capacity Reservation it minted becomes usable. Each was due at its
        // instant whether or not anybody called again, so applying it here changes nothing
        // a later caller would not have seen anyway.
        for record in self.capacity_reservations.values_mut() {
            let Some(pending) = record
                .pending
                .as_ref()
                .filter(|pending| now >= pending.due_at)
                .cloned()
            else {
                continue;
            };
            match pending.to {
                CapacityReservationMove::Active => {
                    record.view.state = Some(CAPACITY_RESERVATION_STATE_ACTIVE.to_string());
                }
                CapacityReservationMove::Scheduled => {
                    record.view.state = Some(CAPACITY_RESERVATION_STATE_SCHEDULED.to_string());
                }
                CapacityReservationMove::AllocationActive => {
                    if let Some(allocation) = record.view.interruptible_capacity_allocation.as_mut()
                    {
                        // "The current status of the allocation (updating during
                        // reclamation, active when complete)"
                        // (`InterruptibleCapacityAllocation$Status`): complete, so the
                        // instances the request asked for are the instances allocated.
                        allocation.status =
                            Some(INTERRUPTIBLE_ALLOCATION_STATUS_ACTIVE.to_string());
                        allocation.instance_count = allocation.target_instance_count;
                    }
                }
                CapacityReservationMove::AllocationCanceled => {
                    if let Some(allocation) = record.view.interruptible_capacity_allocation.as_mut()
                    {
                        // The end of a cancellation: the capacity has gone back to the
                        // source reservation (the counts went with the call that cancelled
                        // it), so nothing is allocated to the interruptible reservation any
                        // more and the allocation is in its terminal status.
                        allocation.status =
                            Some(INTERRUPTIBLE_ALLOCATION_STATUS_CANCELED.to_string());
                        allocation.instance_count = Some(0);
                    }
                }
            }
            record.pending = None;
        }
        // The end of an enable or a disable of one route propagation: the pair either
        // reaches `enabled`, or stops being a propagation of that route table at all —
        // `TransitGatewayPropagationState` has no word for a pair that does not propagate,
        // and a route table whose propagation was disabled simply does not have one any
        // more. Due at its instant whether or not anybody called, like every other move
        // above. The removals are collected first, the way the BYOIP block above collects
        // its due ranges, so each one can give its bytes back to the store's budget.
        let mut removed: Vec<(String, String)> = Vec::new();
        for (key, record) in &mut self.transit_gateway_propagations {
            let Some(due) = record
                .pending
                .as_ref()
                .filter(|pending| now >= pending.due_at)
                .map(|pending| pending.to)
            else {
                continue;
            };
            match due {
                PropagationMove::Removed => removed.push(key.clone()),
                PropagationMove::Enabled => {
                    record.state = PROPAGATION_STATE_ENABLED.to_string();
                    record.pending = None;
                }
            }
        }
        for key in removed {
            if self.transit_gateway_propagations.remove(&key).is_some() {
                // Exactly what the enable charged for the record.
                self.release_stored_bytes(STORED_RECORD_OVERHEAD_BYTES);
            }
        }
        // The end of the `pending` a `CreateTransitGatewayPrefixListReference` answers with:
        // the route is in the table once the move falls due, whether or not anybody called
        // again, exactly like every other move above. The end of the `deleting` a
        // `DeleteTransitGatewayPrefixListReference` answers with is the other way round — the
        // pair is not a route of that table any more, so the record goes, and its bytes go
        // back to the store's budget. The removals are collected first, the way the
        // propagations above collect theirs, because the map cannot be written while it is
        // borrowed for the walk.
        let mut removed_references: Vec<(String, String)> = Vec::new();
        for (key, record) in &mut self.transit_gateway_prefix_list_references {
            let Some(due) = record
                .pending
                .as_ref()
                .filter(|pending| now >= pending.due_at)
                .map(|pending| pending.to)
            else {
                continue;
            };
            match due {
                PrefixListReferenceMove::Removed => removed_references.push(key.clone()),
                PrefixListReferenceMove::Available => {
                    record.view.state = Some(PREFIX_LIST_REFERENCE_STATE_AVAILABLE.to_string());
                    record.pending = None;
                }
            }
        }
        for (route_table_id, prefix_list_id) in removed_references {
            if self
                .transit_gateway_prefix_list_references
                .remove(&(route_table_id.clone(), prefix_list_id.clone()))
                .is_some()
            {
                // Exactly what the create charged for the record.
                self.release_stored_bytes(transit_gateway_prefix_list_reference_payload_bytes(
                    &route_table_id,
                    &prefix_list_id,
                ));
            }
        }
        let connections = &mut self.vpc_endpoint_connections;
        self.vpc_endpoint_connection_moves.retain(|endpoint_id, pending| {
            if now < pending.due_at {
                return true;
            }
            if let Some(connection) = connections.get_mut(endpoint_id) {
                connection.vpc_endpoint_state = Some(pending.to.clone());
            }
            // The move is applied once; nothing is owed on this connection any more.
            false
        });
        // The end of the `pending` a `CreateVpcEndpoint` answers with: the endpoint is in
        // service once its instant has passed, whether or not anybody called again — the
        // same contract, on the same clock, as the connection move above.
        let endpoints = &mut self.vpc_endpoints;
        self.vpc_endpoint_moves.retain(|endpoint_id, pending| {
            if now < pending.due_at {
                return true;
            }
            if let Some(endpoint) = endpoints.get_mut(endpoint_id) {
                endpoint.state = Some(pending.to.clone());
            }
            // The move is applied once; nothing is owed on this endpoint any more.
            false
        });
        // A NAT gateway address an association or an assignment left in a transient
        // `NatGatewayAddressStatus` reaches its terminal status once its instant has
        // passed, whether or not anybody called again — the same contract as the moves
        // above. The address is reached through the gateway its `AssociationId` names, so
        // this costs one lookup per owed move rather than a scan of every gateway.
        let nat_gateways = &mut self.nat_gateways;
        self.nat_gateway_address_transitions
            .retain(|association_id, transition| {
                if now < transition.due_at {
                    return true;
                }
                if let Some(gateway) = nat_gateways.get_mut(&transition.nat_gateway_id) {
                    for address in gateway.nat_gateway_addresses.iter_mut().flatten() {
                        if address.association_id.as_deref() == Some(association_id.as_str()) {
                            address.status = Some(transition.to.to_string());
                        }
                    }
                }
                // The move is applied once; nothing is owed on this address any more.
                false
            });
        // The end of the `pending` a `CreateNatGateway` answers with, and of the `deleting` a
        // `DeleteNatGateway` leaves: the gateway reaches its terminal `NatGatewayState` once
        // its instant has passed, whether or not anybody called again — the same contract, on
        // the same clock, as the address moves above.
        let nat_gateways = &mut self.nat_gateways;
        self.nat_gateway_moves.retain(|nat_gateway_id, pending| {
            if now < pending.due_at {
                return true;
            }
            if let Some(gateway) = nat_gateways.get_mut(nat_gateway_id) {
                gateway.state = Some(pending.to.clone());
            }
            // The move is applied once; nothing is owed on this gateway any more.
            false
        });
        // An Elastic IP address transfer the clock has taken past the end of what the
        // source account is shown: the offer expired and ownership returned to that
        // account, or an accepted transfer's 14 days of visibility ran out. Both were due
        // at their instant whether or not anybody called, and both are spans AWS
        // documents, so they are read off the wall clock rather than `now`.
        self.expire_due_address_transfers(SystemTime::now());
        // A PTR record update an address carries reaches the record once its instant has
        // passed, whether or not anybody called again — the reverse DNS counterpart of the
        // moves above.
        self.apply_due_ptr_record_updates(now);
        self.complete_due_import_image_tasks(now);
        // The same two moves for an import SNAPSHOT task: the snapshot its disk becomes
        // once the conversion window has passed, and the `active` -> `completed` move once
        // that snapshot is itself `completed`.
        self.complete_due_import_snapshot_conversions(now);
        // AFTER the completions: a cancel takes a task out of `active`, so the two can
        // never be owed on one task at once, and applying the completions first means a
        // cancelled task's `deleted` is written over nothing.
        self.delete_due_cancelled_import_tasks(now);
        // The same move for a VM import CONVERSION task: a cancel left it `cancelling` and
        // the clock owes it `cancelled`, which was owed at that instant whether or not
        // anybody called again.
        self.cancel_due_conversion_tasks(now);
        self.materialize_due_capacity_reservation_fleet_moves(now);
        self.materialize_due_spot_instance_requests(now);
        // AFTER the Spot Instance requests a Spot Fleet placed: the capacity a fleet reports
        // fulfilled is derived from the state of those requests, so they are moved first and
        // the fleet then reads the states a caller is about to be shown.
        self.materialize_due_spot_fleet_requests(now);
        self.expire_due_store_image_tasks(now);
        self.fulfill_due_reserved_instances_modifications(now);
    }

    /// The kernel and RAM disk an instance launched from `image_id` runs when its launch
    /// named neither: `Image$KernelId` and `Image$RamdiskId` of the AMI itself.
    ///
    /// That pair is also the DEFAULT `ResetInstanceAttribute` restores — "Resets an
    /// attribute of an instance to its default value" — so the launch path and the reset
    /// path read one definition of it. An image this store does not hold contributes
    /// neither, the way an HVM image carries neither.
    pub fn image_kernel_and_ramdisk(
        &self,
        image_id: Option<&str>,
    ) -> (Option<String>, Option<String>) {
        let image = image_id.and_then(|id| self.images.get(id));
        (
            image.and_then(|image| image.kernel_id.clone()),
            image.and_then(|image| image.ramdisk_id.clone()),
        )
    }

    /// The product codes one instance carries: "the product codes attached to this
    /// instance, if applicable" (`Instance$ProductCodes`).
    ///
    /// A product code reaches an instance through the AMI it was launched from — "the
    /// product code associated with the AMI used to launch the instance" is what the
    /// `product-code` filter selects on (`DescribeInstancesRequest$Filters`) — so they
    /// are read off that image's "any product codes associated with the AMI"
    /// (`Image$ProductCodes`) rather than copied onto the instance record, where the two
    /// could disagree. An instance whose image this store no longer holds carries none.
    pub fn instance_product_codes(&self, instance: &InstanceRecord) -> Vec<ProductCode> {
        instance
            .image_id
            .as_ref()
            .and_then(|image_id| self.images.get(image_id))
            .and_then(|image| image.product_codes.clone())
            .unwrap_or_default()
    }

    /// Whether enhanced networking with the Intel 82599 Virtual Function interface is
    /// enabled for one instance, as the word AWS reports it by: "a value of `simple`
    /// indicates that enhanced networking with the Intel 82599 VF interface is enabled"
    /// (`Instance$SriovNetSupport`).
    ///
    /// Enhanced networking reaches an instance through the AMI it was launched from —
    /// "enable `SriovNetSupport` on an instance and create an AMI from the instance"
    /// (`ModifyImageAttribute`) is how an image comes to carry it — so the value is read
    /// off that image's own `Image$SriovNetSupport` rather than copied onto the instance
    /// record, where the two could disagree. An instance launched from an image this store
    /// no longer holds reports the value every image this crate publishes carries
    /// ([`IMAGE_SRIOV_NET_SUPPORT_SIMPLE`]), the same fallback the instance's other
    /// AMI-derived facts take (`super::instance_detail`).
    pub fn instance_sriov_net_support(&self, instance: &InstanceRecord) -> Option<String> {
        let image = instance
            .image_id
            .as_deref()
            .and_then(|image_id| self.images.get(image_id));
        match image {
            Some(image) => image.sriov_net_support.clone(),
            None => Some(IMAGE_SRIOV_NET_SUPPORT_SIMPLE.to_string()),
        }
    }

    /// Whether the account `account_id` OWNS the product code `product_code`.
    ///
    /// No EC2 operation mints a product code: a code belongs to the seller whose PAID
    /// resource carries it, so the codes this service knows are exactly those on the
    /// images and Amazon FPGA Images it stores (`Image$ProductCodes`,
    /// `FpgaImage$ProductCodes`), each owned by that resource's own owner
    /// (`Image$OwnerId`, `FpgaImage$OwnerId`). An account owns a code when any resource
    /// OF ITS OWN carries it, and owns none of the codes that reach it only through
    /// another account's resources.
    pub fn account_owns_product_code(&self, product_code: &str, account_id: &str) -> bool {
        let carries = |codes: Option<&Vec<ProductCode>>| {
            codes.is_some_and(|codes| {
                codes
                    .iter()
                    .any(|code| code.product_code_id.as_deref() == Some(product_code))
            })
        };
        self.images.values().any(|image| {
            image.owner_id.as_deref() == Some(account_id) && carries(image.product_codes.as_ref())
        }) || self.fpga_images.values().any(|record| {
            record.view.owner_id.as_deref() == Some(account_id)
                && carries(record.view.product_codes.as_ref())
        })
    }

    /// The subnet the instance `instance` runs in: the one its launch named, or — for a
    /// launch that named none, which AWS places "in a default subnet from your default VPC"
    /// (`RunInstances`) — the subnet of its own primary network interface.
    ///
    /// Read off that interface rather than re-derived, because the interface is where the
    /// placement was RECORDED: "the ID of the subnet" an instance reports
    /// (`Instance$SubnetId`) is the subnet of the interface at device index 0, so the
    /// instance report, the interface report and the `subnet-id` filter all answer from one
    /// record.
    ///
    /// `None` for a TERMINATED instance: its network interfaces were deleted when the
    /// termination completed ([`Self::delete_interfaces_of_terminated_instances`]), so it is
    /// attached to no subnet at all and reports none — which is also what keeps it out of a
    /// `subnet-id` or `vpc-id` filtered enumeration of a network it no longer occupies.
    pub fn instance_subnet_id(&self, instance: &InstanceRecord) -> Option<String> {
        if instance.state == InstanceStateName::Terminated {
            return None;
        }
        if let Some(subnet_id) = instance.subnet_id.clone() {
            return Some(subnet_id);
        }
        self.instance_network_interfaces(&instance.instance_id)
            .into_iter()
            .find(|interface| {
                interface
                    .attachment
                    .as_ref()
                    .and_then(|attachment| attachment.device_index)
                    == Some(PRIMARY_NETWORK_INTERFACE_DEVICE_INDEX)
            })
            .and_then(|interface| interface.subnet_id)
    }

    /// The VPC the instance `instance` runs in: the VPC of its own subnet.
    ///
    /// The ONE reading of an instance's VPC, so the instance report
    /// ([`Self::instance_view`]), the `vpc-id` filter ([`Self::filter_values`]) and
    /// [`Self::instance_is_in_vpc`] cannot disagree about which VPC holds an instance. An
    /// instance whose subnet this store does not hold is in no VPC this store knows, and
    /// reports none rather than an invented id.
    pub fn instance_vpc_id(&self, instance: &InstanceRecord) -> Option<String> {
        self.subnets
            .get(&self.instance_subnet_id(instance)?)?
            .vpc_id
            .clone()
    }

    /// The network interfaces attached to the instance `instance_id`, in device-index order
    /// (so the primary interface, at index 0, comes first).
    ///
    /// Projected from the ONE interface store, so what an instance reports and what
    /// `DescribeNetworkInterfaces` reports about one interface is the same record, and
    /// narrowed to this instance's own interfaces through
    /// [`Self::network_interfaces_by_instance`] rather than by scanning that store, so the
    /// cost is the interfaces this instance holds rather than every interface the account
    /// has. An attachment that has reached `detached` holds nothing, so the interface it
    /// belongs to is no longer one of the instance's — the same reading
    /// [`Self::network_interface_attachment`] takes.
    pub fn instance_network_interfaces(&self, instance_id: &str) -> Vec<InstanceNetworkInterface> {
        let Some(held) = self.network_interfaces_by_instance.get(instance_id) else {
            return Vec::new();
        };
        let mut attached: Vec<(i32, InstanceNetworkInterface)> = held
            .iter()
            .filter_map(|network_interface_id| {
                let interface = self.network_interfaces.get(network_interface_id)?;
                let attachment = interface
                    .attachment
                    .as_ref()
                    .filter(|attachment| !attachment_is_detached(attachment))
                    .filter(|attachment| attachment.instance_id.as_deref() == Some(instance_id))?;
                Some((
                    attachment.device_index.unwrap_or_default(),
                    instance_network_interface_view(interface, attachment),
                ))
            })
            .collect();
        attached.sort_by_key(|(device_index, _)| *device_index);
        attached
            .into_iter()
            .map(|(_, interface)| interface)
            .collect()
    }

    /// The security groups the instance `instance` reports
    /// (`Instance$SecurityGroups`): the groups of its PRIMARY network interface, or — for
    /// an instance this store holds no interface for — the groups its launch named.
    ///
    /// The ONE reading of an instance's groups, so the instance report, the
    /// `instance.group-id` / `instance.group-name` filters and
    /// `DescribeNetworkInterfaces` all answer from the interface that actually carries
    /// them. A launch that named no group is given its VPC's default group on that
    /// interface ([`Self::mint_launched_primary_interface`]), which is what AWS reports for
    /// such an instance.
    ///
    /// EMPTY for a TERMINATED instance, on the same terms as [`Self::instance_subnet_id`]:
    /// the interface that carried its groups was deleted when the termination completed, so
    /// the instance is in no security group any more and the launch's own list is not a
    /// fallback for one.
    pub fn instance_security_groups(&self, instance: &InstanceRecord) -> Vec<GroupIdentifier> {
        if instance.state == InstanceStateName::Terminated {
            return Vec::new();
        }
        let primary = self
            .instance_network_interfaces(&instance.instance_id)
            .into_iter()
            .find(|interface| {
                interface
                    .attachment
                    .as_ref()
                    .and_then(|attachment| attachment.device_index)
                    == Some(PRIMARY_NETWORK_INTERFACE_DEVICE_INDEX)
            })
            .and_then(|interface| interface.groups)
            .filter(|groups| !groups.is_empty());
        primary.unwrap_or_else(|| {
            instance
                .security_groups
                .iter()
                .map(|(group_id, group_name)| GroupIdentifier {
                    group_id: group_id.clone(),
                    group_name: group_name.clone(),
                })
                .collect()
        })
    }

    /// The modelled `Instance` for one stored instance.
    ///
    /// The ONE projection of a stored instance, so `RunInstances`, `DescribeInstances` and
    /// every other operation that answers with an `Instance` answers with the same members.
    /// The FIXED detail every instance reports — the machine facts of its AMI, the CPU
    /// layout of its instance type, the volumes it holds, where it runs and the option sets
    /// its launch chose — is filled in by
    /// [`Self::report_instance_detail`](crate::state::ComAmazonawsEc2Amazonec2State::report_instance_detail)
    /// below, out of the one module that derives it (`super::instance_detail`).
    pub fn instance_view(&self, instance: &InstanceRecord) -> Instance {
        let mut view = Instance {
            instance_id: Some(instance.instance_id.clone()),
            image_id: instance.image_id.clone(),
            instance_type: Some(instance.instance_type.clone()),
            key_name: instance.key_name.clone(),
            subnet_id: self.instance_subnet_id(instance),
            // "The ID of the VPC in which the instance is running" (`Instance$VpcId`): the
            // VPC of the instance's own subnet, read off that subnet rather than copied
            // onto the instance record, so the instance report and the subnet report cannot
            // disagree about which VPC the instance is in.
            vpc_id: self.instance_vpc_id(instance),
            // "The network interfaces for the instance" (`Instance$NetworkInterfaces`):
            // every interface the account holds that is attached to THIS instance, primary
            // first — the launch's own interface at device index 0 and any further one
            // something attached — projected from the interface store, so an instance
            // report and `DescribeNetworkInterfaces` cannot disagree about one interface.
            network_interfaces: Some(self.instance_network_interfaces(&instance.instance_id)),
            state: Some(instance.state.view()),
            // EC2 reports an empty reason while the instance has not been moved
            // by a caller, so the member is always present.
            state_transition_reason: Some(
                instance.state_transition_reason.clone().unwrap_or_default(),
            ),
            // "The reason for the most recent state transition" (`Instance$StateReason`):
            // the reason a writer recorded for the transition it started, and — for an
            // instance nobody has moved, whose latest transition is the launch still
            // running — the `pending` reason that launch's own answer carries
            // ([`INSTANCE_STATE_REASON_PENDING`]). An instance the clock has since taken to
            // `running` has no reason to report at all.
            state_reason: instance
                .state_reason
                .as_ref()
                .map(|(code, message)| StateReason {
                    code: Some(code.clone()),
                    message: Some(message.clone()),
                })
                .or_else(|| {
                    (instance.state == InstanceStateName::Pending).then(|| StateReason {
                        code: Some(INSTANCE_STATE_REASON_PENDING.to_string()),
                        message: Some(INSTANCE_STATE_REASON_PENDING.to_string()),
                    })
                }),
            // "The private IPv4 address assigned to the instance"
            // (`Instance$PrivateIpAddress`): an address an instance HOLDS, which a
            // terminated instance holds none of — its network interfaces are deleted when
            // the termination completes
            // ([`Self::delete_interfaces_of_terminated_instances`]) and the addresses they
            // carried go back to the subnet — so the member is left out for a terminated
            // instance rather than reporting an address EC2 has already freed for reuse.
            private_ip_address: (instance.state != InstanceStateName::Terminated)
                .then(|| instance.private_ip.clone()),
            // Documented on `Instance$privateDnsName`: "This name is not available
            // until the instance enters the running state." It names the private address
            // above, so an instance that no longer reports one reports no name for it
            // either.
            private_dns_name: (instance.state != InstanceStateName::Pending
                && instance.state != InstanceStateName::Terminated)
                .then(|| instance.private_dns_name.clone()),
            public_ip_address: instance.public_ip.clone(),
            launch_time: Some(system_time_to_date_time(instance.launch_time)),
            ami_launch_index: Some(instance.ami_launch_index),
            architecture: Some(instance.architecture.clone()),
            // The three instance attributes stored on the record, reported off it so a
            // caller that modifies or resets one reads the same value back here as
            // `DescribeInstanceAttribute` reports for it.
            kernel_id: instance.kernel_id.clone(),
            ramdisk_id: instance.ramdisk_id.clone(),
            source_dest_check: Some(instance.source_dest_check),
            ebs_optimized: Some(instance.ebs_optimized),
            monitoring: Some(Monitoring {
                state: Some(instance.monitoring_state.clone()),
            }),
            // `placement` is filled by `report_instance_detail` below, which reads the
            // zone, its id and the tenancy off one record.
            //
            // "The security groups for the instance" (`Instance$SecurityGroups`): the
            // groups of its PRIMARY network interface, which is where a VPC instance's
            // groups live — "when you launch an instance … the security groups are
            // associated with its primary network interface" — so a launch that named none
            // reports the default group that interface was given rather than nothing at
            // all, and the instance report and `DescribeNetworkInterfaces` cannot disagree.
            // The launch's own list stands in for an instance this store holds no interface
            // for.
            security_groups: Some(self.instance_security_groups(instance)),
            client_token: instance.client_token.clone(),
            // "The product codes attached to this instance, if applicable"
            // (`Instance$ProductCodes`): the codes of the AMI it was launched from, so an
            // instance report and `ConfirmProductInstance` cannot disagree about one
            // instance — reported as the EMPTY set for an instance launched from an AMI
            // nobody sells, which is the member AWS carries for such an instance rather
            // than no member at all.
            product_codes: Some(self.instance_product_codes(instance)),
            tags: Some(tag_list(&instance.tags)),
            // "spot - the instance is a Spot Instance" (`Instance$InstanceLifecycle`) is
            // reported only for an instance a Spot Instance request launched; an
            // on-demand instance has no lifecycle word and no request id.
            instance_lifecycle: instance
                .spot_instance_request_id
                .as_ref()
                .map(|_| INSTANCE_LIFECYCLE_SPOT.to_string()),
            spot_instance_request_id: instance.spot_instance_request_id.clone(),
            // The IAM instance profile the instance runs as, "if applicable"
            // (`Instance$IamInstanceProfile`): read off the association store rather than
            // copied onto the instance record, so an instance report and an association
            // report cannot disagree about one instance's profile.
            iam_instance_profile: self.iam_instance_profile_of_instance(&instance.instance_id),
            ..Default::default()
        };
        self.report_instance_detail(instance, &mut view);
        view
    }

    /// The modelled `Reservation` for `reservation_id`, carrying exactly
    /// `instance_ids` (which the caller has already filtered and ordered).
    pub fn reservation_view(
        &self,
        reservation_id: &str,
        instance_ids: &[String],
    ) -> Option<ReservationView> {
        let reservation = self.reservations.get(reservation_id)?;
        let instances: Vec<&InstanceRecord> = instance_ids
            .iter()
            .filter_map(|id| self.instances.get(id))
            .collect();
        Some(ReservationView {
            reservation_id: Some(reservation.reservation_id.clone()),
            owner_id: Some(reservation.owner_id.clone()),
            requester_id: reservation.requester_id.clone(),
            // "Describes a launch request for one or more instances, and includes owner,
            // requester, and SECURITY GROUP INFORMATION THAT APPLIES TO ALL INSTANCES IN
            // THE LAUNCH REQUEST" (`Reservation`): the groups every instance this
            // reservation reports holds, read off the one projection of an instance's
            // groups ([`Self::instance_security_groups`]) rather than a second copy on the
            // reservation — so the launch's own groups are reported here and a group only
            // some of the instances hold is not. Each instance's groups are read ONCE, and
            // a reservation reporting none (every instance of it terminated, its interfaces
            // gone with them) reports the empty set rather than leaving the member out.
            groups: Some(Self::groups_common_to(
                instances
                    .iter()
                    .map(|instance| self.instance_security_groups(instance)),
            )),
            instances: Some(
                instances
                    .iter()
                    .map(|instance| self.instance_view(instance))
                    .collect(),
            ),
        })
    }

    /// The groups every one of `held` carries, in the order the first of them carries
    /// them — the groups one launch gave all of its instances.
    ///
    /// Each entry of `held` is one instance's groups as
    /// [`Self::instance_security_groups`] reads them, consumed once, so a reservation pays
    /// one projection per instance. An EMPTY sequence (a reservation reporting no
    /// instances) has no common group.
    fn groups_common_to(
        held: impl Iterator<Item = Vec<GroupIdentifier>>,
    ) -> Vec<GroupIdentifier> {
        let mut common: Option<Vec<GroupIdentifier>> = None;
        for groups in held {
            common = Some(match common {
                None => groups,
                Some(current) => current
                    .into_iter()
                    .filter(|group| {
                        groups
                            .iter()
                            .any(|also_held| also_held.group_id == group.group_id)
                    })
                    .collect(),
            });
        }
        common.unwrap_or_default()
    }

    /// The modelled `Reservation` for `reservation_id` with every instance it holds.
    pub fn whole_reservation_view(&self, reservation_id: &str) -> Option<ReservationView> {
        let instance_ids = self.reservations.get(reservation_id)?.instance_ids.clone();
        self.reservation_view(reservation_id, &instance_ids)
    }

    /// The values a filter NAME reads off one instance, or `None` when this slice
    /// does not resolve that name.
    ///
    /// A name that resolves to an empty list simply matches nothing — which is
    /// different from a name the service does not know, and which the caller
    /// refuses with `InvalidParameterValue`.
    ///
    /// `attached` is the instance's own network interfaces, which the caller projects once
    /// per instance ([`Self::instance_matches`]) because finding them is a scan of the
    /// interface store; a caller whose filters name none of the
    /// [`NETWORK_INTERFACE_FILTER_PREFIX`] family passes an empty slice.
    pub fn filter_values(
        &self,
        reservation: &ReservationRecord,
        instance: &InstanceRecord,
        name: &str,
        attached: &[InstanceNetworkInterface],
    ) -> Option<Vec<String>> {
        if let Some(key) = name.strip_prefix(TAG_FILTER_PREFIX) {
            return Some(instance.tags.get(key).cloned().into_iter().collect());
        }
        let single = |value: Option<String>| Some(value.into_iter().collect::<Vec<_>>());
        match name {
            "architecture" => single(Some(instance.architecture.clone())),
            "availability-zone" => single(Some(instance.placement_az.clone())),
            // "availability-zone-id - The ID of the Availability Zone of the instance"
            // (`DescribeInstancesRequest$Filters`): the id of the zone the instance's own
            // placement names, through this crate's ONE name -> id lookup, so a filter and
            // `DescribeAvailabilityZones` cannot disagree about one zone.
            "availability-zone-id" => single(zone_id_for_zone_name(&instance.placement_az)),
            "client-token" => single(instance.client_token.clone()),
            "ebs-optimized" => single(Some(instance.ebs_optimized.to_string())),
            "image-id" => single(instance.image_id.clone()),
            "instance-id" => single(Some(instance.instance_id.clone())),
            "instance-state-code" => single(Some(instance.state.code().to_string())),
            "instance-state-name" => single(Some(instance.state.as_str().to_string())),
            "instance-type" => single(Some(instance.instance_type.clone())),
            // "instance.group-id - The ID of the security group for the instance" and
            // "instance.group-name - The name of the security group for the instance"
            // (`DescribeInstancesRequest$Filters`): read off the SAME projection the
            // instance report carries ([`Self::instance_security_groups`]), so a filter and
            // a report cannot disagree about which groups an instance is in.
            "instance.group-id" => Some(
                self.instance_security_groups(instance)
                    .into_iter()
                    .filter_map(|group| group.group_id)
                    .collect(),
            ),
            "instance.group-name" => Some(
                self.instance_security_groups(instance)
                    .into_iter()
                    .filter_map(|group| group.group_name)
                    .collect(),
            ),
            // "instance-lifecycle - Indicates whether this is a Spot Instance" and
            // "spot-instance-request-id - The ID of the Spot Instance request"
            // (`DescribeInstancesRequest$Filters`): an on-demand instance holds no value
            // for either, so a filter naming one selects only Spot Instances.
            "instance-lifecycle" => single(
                instance
                    .spot_instance_request_id
                    .as_ref()
                    .map(|_| INSTANCE_LIFECYCLE_SPOT.to_string()),
            ),
            "spot-instance-request-id" => single(instance.spot_instance_request_id.clone()),
            // "iam-instance-profile.arn - The instance profile associated with the
            // instance. Specified as an ARN" (`DescribeInstancesRequest$Filters`): read off
            // the same projection the instance report carries, so a filter and a report
            // cannot disagree about one instance's profile. An instance running as none
            // holds no value for it, so a filter naming one selects only instances that do.
            "iam-instance-profile.arn" => single(
                self.iam_instance_profile_of_instance(&instance.instance_id)
                    .and_then(|profile| profile.arn),
            ),
            "key-name" => single(instance.key_name.clone()),
            // "kernel-id - The kernel ID" and "ramdisk-id - The RAM disk ID"
            // (`DescribeInstancesRequest$Filters`): the EFFECTIVE values the instance
            // reports, so a filter and the instance report cannot disagree.
            "kernel-id" => single(instance.kernel_id.clone()),
            "ramdisk-id" => single(instance.ramdisk_id.clone()),
            // "ip-address - The public IPv4 address of the instance"
            // (`DescribeInstancesRequest$Filters`): an instance with no public address holds
            // no value for it, so a filter naming one selects only instances that have one.
            "ip-address" => single(instance.public_ip.clone()),
            // "reason - The reason for the current state of the instance", and the
            // `state-reason-code` / `state-reason-message` pair beside it
            // (`DescribeInstancesRequest$Filters`) — each read off the same members the
            // instance report carries.
            "reason" => single(instance.state_transition_reason.clone()),
            "state-reason-code" => single(
                instance
                    .state_reason
                    .as_ref()
                    .map(|(code, _)| code.clone()),
            ),
            "state-reason-message" => single(
                instance
                    .state_reason
                    .as_ref()
                    .map(|(_, message)| message.clone()),
            ),
            // "source-dest-check - Indicates whether the instance performs
            // source/destination checking" (`DescribeInstancesRequest$Filters`): a boolean
            // attribute is filtered on the value a client sends for it, which is how the
            // wire renders it.
            "source-dest-check" => single(Some(instance.source_dest_check.to_string())),
            "launch-index" => single(Some(instance.ami_launch_index.to_string())),
            "monitoring-state" => single(Some(instance.monitoring_state.clone())),
            "owner-id" => single(Some(reservation.owner_id.clone())),
            // Matches what the instance REPORTS as its private DNS name, which is
            // nothing until it runs and nothing again once it is terminated.
            "private-dns-name" => single(
                (instance.state != InstanceStateName::Pending
                    && instance.state != InstanceStateName::Terminated)
                    .then(|| instance.private_dns_name.clone()),
            ),
            // Matches what the instance REPORTS as its private address, which a terminated
            // instance no longer has ([`Self::instance_view`]), so a filter on an address
            // EC2 has freed selects nothing rather than the instance that used to hold it.
            "private-ip-address" => single(
                (instance.state != InstanceStateName::Terminated)
                    .then(|| instance.private_ip.clone()),
            ),
            // "The product code associated with the AMI used to launch the instance",
            // and "the type of product code (devpay | marketplace)" — both read off the
            // same projection the instance report carries.
            "product-code" => Some(
                self.instance_product_codes(instance)
                    .into_iter()
                    .filter_map(|code| code.product_code_id)
                    .collect(),
            ),
            "product-code.type" => Some(
                self.instance_product_codes(instance)
                    .into_iter()
                    .filter_map(|code| code.product_code_type)
                    .collect(),
            ),
            "reservation-id" => single(Some(instance.reservation_id.clone())),
            "subnet-id" => single(self.instance_subnet_id(instance)),
            // "vpc-id - The ID of the VPC that the instance is running in"
            // (`DescribeInstancesRequest$Filters`), read off the same projection the
            // instance report carries ([`Self::instance_vpc_id`]), so a filter and a report
            // cannot disagree about one instance's VPC. An instance in no VPC this store
            // knows holds no value for it, so a filter naming one selects only instances
            // that are in one.
            "vpc-id" => single(self.instance_vpc_id(instance)),
            "tag-key" => Some(instance.tags.keys().cloned().collect()),
            // The `network-interface.*` family: the members of the interfaces attached to
            // this instance, each read off the SAME projection the instance report carries
            // ([`Self::instance_network_interfaces`]), so a filter cannot select on
            // something the report does not show. An instance with no interface holds no
            // value for any of them.
            //
            // `attached` is the projection made ONCE for this instance by the caller
            // ([`Self::instance_matches`]), not once per filter: finding an instance's
            // interfaces is a scan of the interface store, so doing it per filter would
            // multiply two of the store's ceilings by the filter count. The caller charges
            // that scan to the match budget.
            _ => {
                let attachments = || {
                    attached
                        .iter()
                        .filter_map(|interface| interface.attachment.as_ref())
                };
                // The private addresses of those interfaces, the subject of the
                // `network-interface.addresses.*` family.
                let addresses = || {
                    attached
                        .iter()
                        .flat_map(|interface| interface.private_ip_addresses.iter().flatten())
                };
                match name {
                    "network-interface.network-interface-id" => Some(
                        attached
                            .iter()
                            .filter_map(|interface| interface.network_interface_id.clone())
                            .collect(),
                    ),
                    "network-interface.subnet-id" => Some(
                        attached
                            .iter()
                            .filter_map(|interface| interface.subnet_id.clone())
                            .collect(),
                    ),
                    "network-interface.vpc-id" => Some(
                        attached
                            .iter()
                            .filter_map(|interface| interface.vpc_id.clone())
                            .collect(),
                    ),
                    "network-interface.mac-address" => Some(
                        attached
                            .iter()
                            .filter_map(|interface| interface.mac_address.clone())
                            .collect(),
                    ),
                    "network-interface.description" => Some(
                        attached
                            .iter()
                            .filter_map(|interface| interface.description.clone())
                            .collect(),
                    ),
                    "network-interface.owner-id" => Some(
                        attached
                            .iter()
                            .filter_map(|interface| interface.owner_id.clone())
                            .collect(),
                    ),
                    "network-interface.private-dns-name" => Some(
                        attached
                            .iter()
                            .filter_map(|interface| interface.private_dns_name.clone())
                            .collect(),
                    ),
                    "network-interface.private-ip-address" => Some(
                        attached
                            .iter()
                            .filter_map(|interface| interface.private_ip_address.clone())
                            .collect(),
                    ),
                    "network-interface.source-dest-check" => Some(
                        attached
                            .iter()
                            .filter_map(|interface| {
                                interface.source_dest_check.map(|set| set.to_string())
                            })
                            .collect(),
                    ),
                    "network-interface.status" => Some(
                        attached
                            .iter()
                            .filter_map(|interface| interface.status.clone())
                            .collect(),
                    ),
                    "network-interface.group-id" => Some(
                        attached
                            .iter()
                            .flat_map(|interface| interface.groups.iter().flatten())
                            .filter_map(|group| group.group_id.clone())
                            .collect(),
                    ),
                    "network-interface.group-name" => Some(
                        attached
                            .iter()
                            .flat_map(|interface| interface.groups.iter().flatten())
                            .filter_map(|group| group.group_name.clone())
                            .collect(),
                    ),
                    // The ADDRESSES of the attached interfaces: every private IPv4 address
                    // each one carries, not only the interface's primary — which is what
                    // `network-interface.addresses.private-ip-address` is for, where the
                    // instance's own `private-ip-address` filter "can only be used to filter
                    // by the primary IP address" (`DescribeInstancesRequest$Filters`).
                    "network-interface.addresses.private-ip-address" => Some(
                        addresses()
                            .filter_map(|address| address.private_ip_address.clone())
                            .collect(),
                    ),
                    "network-interface.addresses.private-dns-name" => Some(
                        addresses()
                            .filter_map(|address| address.private_dns_name.clone())
                            .collect(),
                    ),
                    "network-interface.addresses.primary" => Some(
                        addresses()
                            .filter_map(|address| address.primary.map(|set| set.to_string()))
                            .collect(),
                    ),
                    "network-interface.attachment.attachment-id" => Some(
                        attachments()
                            .filter_map(|attachment| attachment.attachment_id.clone())
                            .collect(),
                    ),
                    "network-interface.attachment.device-index" => Some(
                        attachments()
                            .filter_map(|attachment| {
                                attachment.device_index.map(|index| index.to_string())
                            })
                            .collect(),
                    ),
                    "network-interface.attachment.status" => Some(
                        attachments()
                            .filter_map(|attachment| attachment.status.clone())
                            .collect(),
                    ),
                    "network-interface.attachment.network-card-index" => Some(
                        attachments()
                            .filter_map(|attachment| {
                                attachment.network_card_index.map(|index| index.to_string())
                            })
                            .collect(),
                    ),
                    "network-interface.attachment.delete-on-termination" => Some(
                        attachments()
                            .filter_map(|attachment| {
                                attachment.delete_on_termination.map(|set| set.to_string())
                            })
                            .collect(),
                    ),
                    _ => None,
                }
            }
        }
    }

    /// Whether one instance satisfies EVERY filter, charging the comparisons it makes
    /// to `budget`.
    ///
    /// EC2 combines filters with AND and a single filter's values with OR, and a
    /// value may carry EC2's wildcards (see [`filter_value_matches`]). The budget is
    /// what bounds the PRODUCT of instances, filters, values and value length, none
    /// of which a per-factor cap can do on its own.
    pub fn instance_matches(
        &self,
        reservation: &ReservationRecord,
        instance: &InstanceRecord,
        filters: &[CompiledFilter],
        budget: &mut MatchBudget,
    ) -> bool {
        // One step per candidate, so even an unfiltered scan is charged and cannot
        // walk the whole store for free.
        if !budget.spend() {
            return false;
        }
        // The interfaces this instance holds, read ONCE for every filter that needs them
        // and not at all for a request whose filters do not. The read is the interfaces
        // THIS instance holds (an index lookup, [`Self::instance_network_interfaces`]),
        // and each one is charged to the same budget, so the product of stored instances,
        // stored interfaces and filters stays bounded.
        let needs_interfaces = filters
            .iter()
            .any(|filter| filter.name.starts_with(NETWORK_INTERFACE_FILTER_PREFIX));
        let attached = if needs_interfaces {
            let held = self.instance_network_interfaces(&instance.instance_id);
            if !budget.spend_steps(u64::try_from(held.len()).unwrap_or(u64::MAX)) {
                return false;
            }
            held
        } else {
            Vec::new()
        };
        filters.iter().all(|filter| {
            let Some(held) = self.filter_values(reservation, instance, &filter.name, &attached)
            else {
                return false;
            };
            filter.patterns.iter().any(|pattern| {
                held.iter()
                    .any(|value| pattern.matches_within(value, budget))
            })
        })
    }
}

/// One `DescribeInstances` filter: its name and its values parsed ONCE into
/// [`FilterPattern`]s.
#[derive(Debug, Clone)]
pub struct CompiledFilter {
    pub name: String,
    pub patterns: Vec<FilterPattern>,
}

impl CompiledFilter {
    /// Parse a filter name and its values.
    pub fn new(name: String, values: Vec<String>) -> Self {
        let patterns = values
            .iter()
            .map(|value| FilterPattern::compile(value))
            .collect();
        Self { name, patterns }
    }
}

/// Whether this slice resolves `name` as a `DescribeInstances` filter.
///
/// A `tag:` prefix with no key names no tag, so it is as undocumented as any other
/// misspelling — the same reading every other describe of this service takes.
pub fn filter_name_supported(name: &str) -> bool {
    name.strip_prefix(TAG_FILTER_PREFIX)
        .is_some_and(|key| !key.is_empty())
        || SUPPORTED_INSTANCE_FILTERS.contains(&name)
}

/// The Region an instance runs in: the Region of its own Availability Zone.
///
/// EC2 is a regional service, so a request signed for another Region must not see this
/// instance. The zone is the fact the record already carries, and `region_of_zone_name` is
/// this crate's ONE reading of which Region a zone belongs to, so an instance and the
/// resources its zone places (its root volume, its primary interface) can never be reported
/// in two Regions.
pub fn instance_region(instance: &InstanceRecord) -> &str {
    region_of_zone_name(&instance.placement_az)
}

/// The caller-chosen bytes one stored instance holds.
///
/// Only the members whose length the REQUEST chose count: an id, a state or a
/// timestamp this emulator mints is a fixed size. EVERY such member counts, though —
/// the image id, the instance type, the subnet, the key pair name, the zone and the
/// kernel and RAM disk ids are
/// cloned onto every instance a launch mints just as its user data is, so leaving them
/// out would let one request retain bytes the store's ceiling never saw.
pub fn instance_payload_bytes(record: &InstanceRecord) -> usize {
    record.user_data.as_ref().map_or(0, String::len)
        + record.client_token.as_ref().map_or(0, String::len)
        + record.image_id.as_ref().map_or(0, String::len)
        + record.instance_type.len()
        + record.subnet_id.as_ref().map_or(0, String::len)
        + record.key_name.as_ref().map_or(0, String::len)
        + record.kernel_id.as_ref().map_or(0, String::len)
        + record.ramdisk_id.as_ref().map_or(0, String::len)
        + record.placement_az.len()
        // The one caller-chosen string of the instance's own detail: every other member of
        // it is a `&'static str` out of a modelled catalog or a number.
        + record
            .detail
            .placement_group_name
            .as_ref()
            .map_or(0, String::len)
        + tag_bytes(&record.tags)
        + record
            .security_groups
            .iter()
            .map(|(group_id, group_name)| {
                group_id.as_ref().map_or(0, String::len)
                    + group_name.as_ref().map_or(0, String::len)
            })
            .sum::<usize>()
}

/// Refuse a kernel or RAM disk image id that is longer than an EC2 image id can be.
///
/// `member` names the request member in the refusal, so the caller can fix the request
/// from the message alone. The one definition both launch paths call, so a launch and a
/// Spot Instance request bound the same member the same way; the bound itself is
/// [`MAX_KERNEL_OR_RAMDISK_ID_CHARS`].
///
/// The code is `InvalidParameterValue`: this is the emulator's RETENTION bound on a member
/// AWS models no length for, not a claim about the shape of an image id (a value that is
/// not an id at all is the business of whatever resolves kernel images, which this slice
/// does not model), so it is answered as a value the service will not accept rather than as
/// one of the `InvalidAMIID.*` codes a recorded response has not shown here.
pub fn validate_kernel_or_ramdisk_id<E>(
    member: &str,
    value: Option<&str>,
) -> Result<(), crate::scaffolded::Scaffolded<E>> {
    if value.is_some_and(|id| id.chars().count() > MAX_KERNEL_OR_RAMDISK_ID_CHARS) {
        return Err(invalid_parameter_value(format!(
            "{member} accepts at most {MAX_KERNEL_OR_RAMDISK_ID_CHARS} characters, \
             the length of an EC2 image id"
        )));
    }
    Ok(())
}

/// Refuse a maximum hourly price that is not one.
///
/// "The maximum price per unit hour that you are willing to pay for a Spot Instance"
/// (`RequestSpotInstancesRequest$SpotPrice`, `SpotFleetRequestConfigData$SpotPrice` and the
/// per-pool and per-fleet totals beside it) is a non-negative number. Every one of those
/// members is a plain `String` in the model, so this is the ONE place all of them are held to
/// that, and `member` names the one that was wrong so a caller can fix the request from the
/// message alone.
pub fn validate_hourly_price<E>(
    member: &str,
    price: Option<&str>,
) -> Result<(), crate::scaffolded::Scaffolded<E>> {
    let Some(price) = price else {
        return Ok(());
    };
    let valid = price
        .parse::<f64>()
        .is_ok_and(|parsed| parsed.is_finite() && parsed >= 0.0);
    if !valid {
        return Err(invalid_parameter_value(format!(
            "Invalid value '{price}' for {member}. It must be a non-negative hourly price"
        )));
    }
    Ok(())
}

/// The modelled word `requested` names out of `catalog`, `default` when it names none, or a
/// refusal naming `member`.
///
/// `catalog` is a GENERATED `*_VALUES` constant, so an enum's members live in exactly one
/// place; answering a `&'static str` out of it is what keeps a request's own text out of the
/// store. A `None` default is for the members AWS documents no default for: those report
/// nothing at all rather than a guess. The ONE lookup of this kind in the crate, so two
/// operations cannot refuse one enum two ways.
pub fn modelled_catalog_word<E>(
    requested: Option<&str>,
    catalog: &'static [&'static str],
    member: &str,
    default: Option<&'static str>,
) -> Result<Option<&'static str>, crate::scaffolded::Scaffolded<E>> {
    match requested {
        None => Ok(default),
        Some(requested) => catalog
            .iter()
            .copied()
            .find(|modelled| *modelled == requested)
            .map(Some)
            .ok_or_else(|| {
                invalid_parameter_value(format!(
                    "Invalid value '{requested}' for {member}. Valid values: {}",
                    catalog.join(" | ")
                ))
            }),
    }
}

/// The bytes a tag map holds.
pub fn tag_bytes(tags: &BTreeMap<String, String>) -> usize {
    tags.iter().map(|(key, value)| key.len() + value.len()).sum()
}

/// The bytes a modelled `Tag` list holds.
pub fn tag_list_bytes(tags: &[Tag]) -> usize {
    tags.iter()
        .map(|tag| {
            tag.key.as_ref().map_or(0, String::len) + tag.value.as_ref().map_or(0, String::len)
        })
        .sum()
}

/// A modelled `Tag` list as comparable pairs, in a canonical order.
///
/// The modelled [`Tag`] carries no `PartialEq`, so this is how two tag lists are compared —
/// which an idempotency check has to do, to tell a replay of one request from a second,
/// non-identical request carrying the same `ClientToken`. The pairs are SORTED because
/// "tag keys must be unique per resource" makes a tag list a set: a replay that sends the
/// same tags in another order is the same request, which is also how
/// `ops/create_route_server.rs`'s own comparison reads one.
pub fn tag_pairs(tags: &[Tag]) -> Vec<(Option<&str>, Option<&str>)> {
    let mut pairs: Vec<(Option<&str>, Option<&str>)> = tags
        .iter()
        .map(|tag| (tag.key.as_deref(), tag.value.as_deref()))
        .collect();
    pairs.sort_unstable();
    pairs
}

/// The bytes a modelled `IpamResourceTag` list holds — the [`tag_list_bytes`] of the
/// separate tag shape IPAM's allocation rules carry ("tags that are required for resources
/// that use CIDRs from this IPAM pool", `IpamPool$AllocationResourceTags`), which a pool
/// retains for the process's lifetime just as it retains its own tags.
pub fn ipam_resource_tag_list_bytes(tags: &[IpamResourceTag]) -> usize {
    tags.iter()
        .map(|tag| {
            tag.key.as_ref().map_or(0, String::len) + tag.value.as_ref().map_or(0, String::len)
        })
        .sum()
}

/// Merge `updates` into a modelled `Tag` list, overwriting a key already present.
///
/// The same rule `CreateTags` documents: "When you specify an existing tag key, the
/// value is overwritten with the new value."
pub fn merge_tag_list(existing: &mut Vec<Tag>, updates: &[(String, String)]) {
    for (key, value) in updates {
        match existing
            .iter_mut()
            .find(|tag| tag.key.as_deref() == Some(key.as_str()))
        {
            Some(tag) => tag.value = Some(value.clone()),
            None => existing.push(Tag {
                key: Some(key.clone()),
                value: Some(value.clone()),
            }),
        }
    }
}

/// One stored resource's tags, in whichever form the record holding that resource keeps
/// them.
///
/// The tag operations take "the IDs of the resources" (`CreateTagsRequest$Resources`,
/// `DeleteTagsRequest$Resources`) of ANY kind, so they cannot know each store's record
/// shape: they resolve an id to one of these handles through
/// [`ComAmazonawsEc2Amazonec2State::resource_tags_mut`] and read and write the resource's
/// tags through it. That is also what keeps `CreateTags` and `DeleteTags` agreeing about
/// which ids are taggable, instead of one accepting an id the other refuses.
#[derive(Debug)]
pub enum ResourceTagsMut<'store> {
    /// Tags kept as a key -> value map, the form [`InstanceRecord`] uses.
    Map(&'store mut BTreeMap<String, String>),
    /// Tags kept as the modelled optional `Tag` list, the form every modelled EC2 shape
    /// that carries tags uses.
    List(&'store mut Option<Vec<Tag>>),
}

impl ResourceTagsMut<'_> {
    /// The resource's tags as key -> value pairs, ordered by key.
    ///
    /// A list entry carrying no key names no tag at all, so it is not reported; an entry
    /// with no value reads as the empty value, which is the value `CreateTags` stores for
    /// a tag given without one ("if you don't want the tag to have a value, specify the
    /// parameter with no value, and we set the value to an empty string").
    pub fn pairs(&self) -> BTreeMap<String, String> {
        match self {
            Self::Map(tags) => (**tags).clone(),
            Self::List(tags) => tags
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter_map(|tag| Some((tag.key.clone()?, tag.value.clone().unwrap_or_default())))
                .collect(),
        }
    }

    /// The bytes the stored tags hold, counted as the stores charge them against
    /// [`MAX_STORED_BYTES`].
    pub fn bytes(&self) -> usize {
        match self {
            Self::Map(tags) => tag_bytes(tags),
            Self::List(tags) => tag_list_bytes(tags.as_deref().unwrap_or_default()),
        }
    }

    /// Write `updates` onto the resource, overwriting a key it already carries — the rule
    /// `CreateTags` documents ("When you specify an existing tag key, the value is
    /// overwritten with the new value").
    pub fn set(&mut self, updates: &[(String, String)]) {
        match self {
            Self::Map(tags) => {
                for (key, value) in updates {
                    tags.insert(key.clone(), value.clone());
                }
            }
            Self::List(tags) => {
                let mut list = tags.take().unwrap_or_default();
                merge_tag_list(&mut list, updates);
                **tags = Some(list);
            }
        }
    }

    /// Remove every tag `selected` answers `true` for, given its key and its value, and
    /// answer the bytes that freed.
    ///
    /// Removing a tag the resource does not carry removes nothing and frees nothing: which
    /// tags a request names is the caller's business, and the resource ends up without
    /// them either way.
    pub fn remove(&mut self, selected: impl Fn(&str, &str) -> bool) -> usize {
        let before = self.bytes();
        match self {
            Self::Map(tags) => tags.retain(|key, value| !selected(key, value)),
            Self::List(tags) => {
                if let Some(list) = tags.as_mut() {
                    list.retain(|tag| {
                        !selected(
                            tag.key.as_deref().unwrap_or_default(),
                            tag.value.as_deref().unwrap_or_default(),
                        )
                    });
                }
            }
        }
        before.saturating_sub(self.bytes())
    }
}
