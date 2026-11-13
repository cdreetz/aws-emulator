// SPDX-License-Identifier: CC0-1.0

use super::*;

/// What a master user password is reported AS wherever Amazon RDS reports that one is
/// pending: the member is `@sensitive` (`PendingModifiedValues$MasterUserPassword`), so
/// the credential itself is never published and the value stands in for it.
pub const MASKED_PENDING_MASTER_USER_PASSWORD: &str = "****";

/// A stored DB instance: everything the service persists about it.
///
/// The ARN, the endpoint DNS name and the hosted zone id are NOT stored as text:
/// they are functions of the stored region, identifier and minted endpoint host, and
/// [`DbInstanceRecord::to_wire`] computes them. That is what keeps them consistent
/// after `ModifyDBInstance` renames an instance — a stored ARN would still name the
/// old identifier.
#[derive(Debug, Clone)]
pub struct DbInstanceRecord {
    pub identifier: String,
    /// The region the instance was created in; the scope of its ARN and endpoint.
    pub region: String,
    pub dbi_resource_id: String,
    /// The server-assigned middle label of the endpoint DNS name, minted once.
    pub endpoint_host: String,
    pub db_instance_class: String,
    pub engine: String,
    pub engine_version: Option<String>,
    pub status: String,
    pub pending_status: Option<PendingStatus>,
    pub db_name: Option<String>,
    pub allocated_storage: Option<i32>,
    pub max_allocated_storage: Option<i32>,
    pub master_username: Option<String>,
    /// The master user's password, as the DIGESTS a login on the instance's engine
    /// endpoint is verified against — never the password itself, which is `@sensitive`,
    /// is reported by no operation and is not stored (see
    /// [`data_plane::wire_session::MasterPasswordHash`]). `None` for an instance created
    /// without one, which no engine session can then authenticate against.
    pub master_user_password: Option<data_plane::wire_session::MasterPasswordHash>,
    /// `MasterUserSecret`: the secret RDS manages for this instance's master user
    /// password, for an instance created or modified with `ManageMasterUserPassword`
    /// turned on; `None` for one whose password the caller supplied, which has no managed
    /// secret to report.
    ///
    /// Only an operation that CREATES the secret for this instance sets it, so what is
    /// named here is the instance's OWN secret: an instance that inherits another's master
    /// credential — a read replica, an instance restored from a snapshot — manages none
    /// and reports none.
    pub master_user_secret: Option<ManagedMasterSecret>,
    /// The port the instance's engine accepts connections on as the request configured it:
    /// what `Port` (and `DBPortNumber`) set, else the documented default of its engine
    /// family. Reported by `DbInstancePort` for a cluster member
    /// ([`DbInstanceRecord::db_instance_port`]).
    pub endpoint_port: i32,
    /// Where the instance's own engine listener accepts connections IN THIS PROCESS, for
    /// the engines whose wire this emulator speaks: the address the modelled `Endpoint`
    /// publishes, because that is the address and port a client can actually reach the
    /// engine on. `None` for an engine this emulator serves no data plane for, which keeps
    /// the DNS-form endpoint and the configured port.
    pub served_endpoint: Option<ServedEndpoint>,
    pub multi_az: bool,
    pub storage_type: String,
    pub storage_encrypted: bool,
    pub kms_key_id: Option<String>,
    pub iops: Option<i32>,
    pub license_model: Option<String>,
    pub availability_zone: String,
    pub backup_retention_period: i32,
    pub preferred_backup_window: Option<String>,
    pub preferred_maintenance_window: Option<String>,
    pub publicly_accessible: bool,
    pub auto_minor_version_upgrade: bool,
    pub copy_tags_to_snapshot: bool,
    pub deletion_protection: bool,
    pub db_subnet_group_name: Option<String>,
    /// The DB parameter group applied to the instance: the one the request named, or
    /// the default group of the engine version it was created with.
    pub db_parameter_group_name: Option<String>,
    /// The option group applied to the instance: the one the request named, or the
    /// default group of its engine and major engine version. It is a REFERENCE, which
    /// is what keeps a group an instance uses from being deleted under it
    /// (`DeleteOptionGroup`).
    pub option_group_name: Option<String>,
    pub vpc_security_group_ids: Vec<String>,
    /// The legacy EC2-Classic DB security groups the request named, which is normally
    /// none: "This setting applies to the legacy EC2-Classic platform, which is no
    /// longer used to create new DB instances."
    pub db_security_group_names: Vec<String>,
    pub db_cluster_identifier: Option<String>,
    /// `ReadReplicaSourceDBInstanceIdentifier` — "the identifier of the source DB instance
    /// if this DB instance is a read replica", as `CreateDBInstanceReadReplica` resolved it,
    /// and `None` for an instance that replicates nothing.
    pub read_replica_source_db_instance_identifier: Option<String>,
    /// `ReadReplicaDBInstanceIdentifiers` — "the identifiers of the read replicas associated
    /// with this DB instance", in the order the replicas were created.
    ///
    /// The SOURCE's side of the same relationship, recorded on the source when a replica is
    /// created and dropped from it when that replica is deleted
    /// ([`Self::detach_read_replica`]), so the list never names an instance this store no
    /// longer holds.
    pub read_replica_db_instance_identifiers: Vec<String>,
    pub domain: Option<String>,
    /// The CA the instance's server certificate is issued under.
    pub ca_certificate_identifier: String,
    pub monitoring_interval: i32,
    pub performance_insights_enabled: bool,
    pub iam_database_authentication_enabled: bool,
    pub database_insights_mode: String,
    pub dedicated_log_volume: bool,
    pub customer_owned_ip_enabled: bool,
    pub network_type: String,
    pub backup_target: String,
    pub engine_lifecycle_support: String,
    /// The storage throughput provisioned for the instance, in MiBps.
    pub storage_throughput: i32,
    pub instance_create_time: ::aws_smithy_types::DateTime,
    /// When this instance's database engine last came UP: the create that provisioned it,
    /// or the most recent restart of the engine (`RebootDBInstance`, `StartDBInstance`).
    ///
    /// Separate from [`Self::instance_create_time`], which is when the INSTANCE was
    /// created and never moves. This is the engine's run, which is what the data plane's
    /// `pg_postmaster_start_time()` reports and what decides whether a parameter change
    /// that waits for a reboot is in force yet
    /// ([`data_plane::pg_server::running_parameters`]).
    pub engine_started_at: ::aws_smithy_types::DateTime,
    pub tags: Vec<Tag>,
    /// `AssociatedRoles`: the IAM roles associated with this instance, in the order they
    /// were associated — what `AddRoleToDBInstance` adds to and
    /// `RemoveRoleFromDBInstance` removes from, bounded by
    /// [`associated_roles::MAX_ASSOCIATED_ROLES`] entries.
    pub associated_roles: Vec<DBInstanceRole>,
    /// The instance's log: the lifecycle lines THIS SERVICE has recorded for it, which is
    /// what `DescribeDBLogFiles` lists and `DownloadDBLogFilePortion` serves. See
    /// [`engine_log`] for why those lines are the only honest content for it, and for the
    /// bounds on the log.
    pub engine_log: InstanceLog,
}

impl DbInstanceRecord {
    /// Apply a change whose due instant has passed. Returns whether the record is now
    /// gone — an accepted delete that has run its course — so the caller drops it from
    /// the store.
    pub(super) fn settle(&mut self, now: Instant) -> bool {
        let due = self
            .pending_status
            .as_ref()
            .is_some_and(|pending| now >= pending.due_at);
        if !due {
            return false;
        }
        match self.pending_status.take().map(|pending| pending.change) {
            Some(PendingChange::Status(status)) => {
                // The instance's own log records the lifecycle events this service
                // performs on it, and a status the clock just made due is one of them.
                self.engine_log
                    .record(format!("DB instance status is now {status}"));
                self.status = status;
            }
            Some(PendingChange::Removal) => return true,
            // Unreachable: the change was there a line ago, under this one `&mut self`.
            // Answered as "nothing was due" rather than with a panic in a request path.
            None => {}
        }
        false
    }

    /// Whether a delete has already been accepted for this instance, so it is on its
    /// way out and nothing further can be done to it.
    pub fn is_deleting(&self) -> bool {
        self.status == DB_INSTANCE_STATUS_DELETING
    }

    /// Accept a delete: the instance reports `deleting` from now on, and the clock
    /// owes its removal from the store [`STATUS_TRANSITION_DELAY`] from now, after
    /// which every read of the identifier is a `DBInstanceNotFoundFault`. Nothing
    /// sleeps: the due instant is stored and materialised by
    /// [`ComAmazonawsRdsAmazonrdsv19State::settle_due_transitions`].
    pub fn begin_deletion(&mut self) {
        self.status = DB_INSTANCE_STATUS_DELETING.to_string();
        self.pending_status = Some(PendingStatus::removal_in_a_moment());
    }

    /// Record that `identifier` replicates this instance: the source's half of the
    /// relationship `CreateDBInstanceReadReplica` creates.
    ///
    /// A replica is recorded once, so a create that is refused after this point cannot leave
    /// the identifier named twice.
    pub fn attach_read_replica(&mut self, identifier: &str) {
        if !self
            .read_replica_db_instance_identifiers
            .iter()
            .any(|held| held == identifier)
        {
            self.read_replica_db_instance_identifiers
                .push(identifier.to_string());
        }
    }

    /// Drop `identifier` from the replicas of this instance, for a replica that is being
    /// deleted: the source reports the replicas it HAS, so a deleted one is not one of them.
    pub fn detach_read_replica(&mut self, identifier: &str) {
        self.read_replica_db_instance_identifiers
            .retain(|held| held != identifier);
    }

    /// Stop replicating: an instance whose source DB instance is being deleted is promoted
    /// to a standalone DB instance, so it reports no source from then on.
    pub fn promote_from_read_replica(&mut self) {
        self.read_replica_source_db_instance_identifier = None;
    }

    /// The name of the log file this instance writes, which follows from its engine; see
    /// [`engine_log::log_file_name`].
    pub fn log_file_name(&self) -> &'static str {
        engine_log::log_file_name(&self.engine)
    }

    /// `arn:aws:rds:<region>:<account>:db:<identifier>`, from the stored region and
    /// the instance's current identifier.
    pub fn arn(&self) -> String {
        db_instance_arn(&self.region, &self.identifier)
    }

    /// The DNS name this instance's endpoint resolves to:
    /// `<identifier>.<minted host>.<region>.<domain>`, with the domain of the control plane
    /// that owns the instance's engine — see [`endpoint_domain`].
    ///
    /// An instance whose engine this emulator SERVES publishes the host its own listener
    /// is bound to instead: that is the address a client connects to, and a name this
    /// machine does not resolve would be no endpoint at all.
    pub fn endpoint_address(&self) -> String {
        // OnCallWorlds patch: a seeded account reports the endpoint AWS would, not the
        // local listener this emulator opened for the engine.
        if let Some(served) = self.served_endpoint.as_ref().filter(|_| !ocw_clock::seeded()) {
            return served.host.clone();
        }
        format!(
            "{}.{}.{}.{}",
            self.identifier,
            self.endpoint_host,
            self.region,
            endpoint_domain(&self.engine)
        )
    }

    /// The port a client connects to: the port the instance's engine listener was
    /// assigned where it has one, else the configured port.
    ///
    /// The core owns the port range the listener is bound in and takes no port from this
    /// service (`vendor/server/src/listeners.rs`), so the configured port
    /// ([`Self::endpoint_port`], which `Port` and `DBPortNumber` set) is what the instance
    /// records and the port the listener landed on is what it publishes — an endpoint whose
    /// port nothing answers on would be no endpoint at all. For an instance with no
    /// listener the two are the same value.
    pub fn published_port(&self) -> i32 {
        self.served_endpoint
            .as_ref()
            .filter(|_| !ocw_clock::seeded()) // OnCallWorlds patch: report the AWS endpoint, not the local listener
            .map_or(self.endpoint_port, |served| served.port)
    }

    /// When the server certificate issued at creation expires:
    /// [`SERVER_CERTIFICATE_VALIDITY`] after the instance was created. A function of
    /// the stored creation time rather than a stored instant, so it cannot drift from
    /// it.
    pub fn certificate_valid_till(&self) -> ::aws_smithy_types::DateTime {
        ::aws_smithy_types::DateTime::from_secs_f64(
            self.instance_create_time.as_secs_f64() + SERVER_CERTIFICATE_VALIDITY.as_secs_f64(),
        )
    }

    /// `PendingModifiedValues`: what this service has accepted for the instance and not
    /// finished applying.
    ///
    /// Every change `ModifyDBInstance` accepts is written to the stored record at once, so
    /// the only change still in flight is the one the CREATE is still applying: an
    /// instance being provisioned with a master credential has that credential pending
    /// until it is up, which is what `PendingModifiedValues$MasterUserPassword` ("the
    /// master credentials for the DB instance") reports, masked because the member is
    /// `@sensitive` ([`MASKED_PENDING_MASTER_USER_PASSWORD`]).
    ///
    /// `None` once nothing is pending — the structure "is returned only when there are
    /// pending changes" — so an EMPTY element never claims there are changes whose
    /// subelements this answer does not identify.
    pub fn pending_modified_values(&self) -> Option<PendingModifiedValues> {
        let password_pending =
            self.status == DB_INSTANCE_STATUS_CREATING && self.master_user_password.is_some();
        password_pending.then(|| PendingModifiedValues {
            master_user_password: Some(MASKED_PENDING_MASTER_USER_PASSWORD.to_string()),
            ..PendingModifiedValues::default()
        })
    }

    /// `DbInstancePort`: "The port that the DB instance listens on. If the DB instance
    /// is part of a DB cluster, this can be a different port than the DB cluster port."
    ///
    /// The member reports the port of a CLUSTER MEMBER, which is why it is separate from
    /// `Endpoint.Port`: an instance that belongs to no DB cluster has no such port, and
    /// RDS reports zero for it. It reports the CONFIGURED port — the one `Port` and
    /// `DBPortNumber` set, which the record keeps — where `Endpoint.Port` reports the
    /// port the instance's engine listener was assigned ([`Self::published_port`]): the
    /// endpoint has to be the one a client can reach, and this member is what still says
    /// which port the request asked the instance to listen on.
    pub fn db_instance_port(&self) -> i32 {
        match self.db_cluster_identifier {
            Some(_) => self.endpoint_port,
            None => 0,
        }
    }

    /// `LatestRestorableTime`: "the latest time to which a database in this DB instance
    /// can be restored with point-in-time restore."
    ///
    /// An instance has one exactly while it keeps continuous backups, which is what
    /// `BackupRetentionPeriod` decides: "To disable automated backups, set this value to
    /// 0", and a non-zero period is what makes point-in-time restore available at all. So
    /// `None` for an instance with automated backups off, and `None` while the instance is
    /// still being created, which has taken no backup yet — in both cases there is no
    /// instant the instance can be restored to, which is what reporting no member says.
    ///
    /// The value ADVANCES with the clock, trailing it by [`LATEST_RESTORABLE_LAG`], and
    /// never predates the instance: a point before it existed is not a point it can be
    /// restored to. Computed from the clock and the stored retention period rather than
    /// stored, so it cannot go stale between two describes.
    pub fn latest_restorable_time(&self) -> Option<::aws_smithy_types::DateTime> {
        if self.backup_retention_period < 1 || self.status == DB_INSTANCE_STATUS_CREATING {
            return None;
        }
        let trailing = now_as_wire_timestamp().as_secs_f64() - LATEST_RESTORABLE_LAG.as_secs_f64();
        Some(::aws_smithy_types::DateTime::from_secs_f64(
            trailing.max(self.instance_create_time.as_secs_f64()),
        ))
    }

    /// The window a point-in-time restore of this instance may target: "any point in time
    /// during your backup retention period", up to [`Self::latest_restorable_time`].
    ///
    /// `None` for an instance that keeps no continuous backup, which is the case
    /// `RestoreDBInstanceToPointInTime` answers `PointInTimeRestoreNotEnabled` for.
    pub fn restorable_window(
        &self,
    ) -> Option<(::aws_smithy_types::DateTime, ::aws_smithy_types::DateTime)> {
        let latest = self.latest_restorable_time()?;
        let retention = f64::from(self.backup_retention_period) * 24.0 * 60.0 * 60.0;
        let earliest =
            (latest.as_secs_f64() - retention).max(self.instance_create_time.as_secs_f64());
        Some((
            ::aws_smithy_types::DateTime::from_secs_f64(earliest),
            latest,
        ))
    }

    /// Project the stored record onto the modelled `DBInstance` output shape.
    ///
    /// Every member RDS reports for a DB instance it holds is projected here, from the
    /// stored record or from the documented default the record was created with; the
    /// nested `Endpoint`, `CertificateDetails`, `PendingModifiedValues` and membership
    /// lists are projected from the same record, so no two of them can disagree. A member
    /// whose value this service has no state for at all is left out rather than invented —
    /// a list it does have state for is reported EMPTY, which is what RDS reports for an
    /// instance that has none of those associations.
    ///
    /// `db_subnet_group` is the DB SUBNET GROUP record the instance's own
    /// `DBSubnetGroupName` resolves to, which the store looks up for this projection
    /// ([`ComAmazonawsRdsAmazonrdsv19State::instance_to_wire`], the one way a handler
    /// reaches it): a nested resource of another record is reported FROM that record, so
    /// the group an instance reports and the one `DescribeDBSubnetGroups` reports are one
    /// answer. `None` where the instance names a group this store no longer resolves, which
    /// reports no group at all rather than a name with nothing behind it.
    pub fn to_wire(&self, db_subnet_group: Option<&DbSubnetGroupRecord>) -> DBInstance {
        DBInstance {
            db_instance_identifier: Some(self.identifier.clone()),
            db_instance_class: Some(self.db_instance_class.clone()),
            engine: Some(self.engine.clone()),
            db_instance_status: Some(self.status.clone()),
            master_username: self.master_username.clone(),
            // `MasterUserSecret`: reported for an instance whose master user password RDS
            // manages, and only for one — an instance whose password the caller supplied
            // has no secret of RDS's own, which is what reporting nothing says.
            master_user_secret: self
                .master_user_secret
                .as_ref()
                .map(ManagedMasterSecret::to_wire),
            db_name: self.db_name.clone(),
            endpoint: Some(Endpoint {
                address: Some(self.endpoint_address()),
                port: Some(self.published_port()),
                hosted_zone_id: Some(hosted_zone_id(
                    &self.region,
                    endpoint_domain(&self.engine),
                )),
            }),
            allocated_storage: self.allocated_storage,
            instance_create_time: Some(self.instance_create_time),
            preferred_backup_window: self.preferred_backup_window.clone(),
            backup_retention_period: Some(self.backup_retention_period),
            latest_restorable_time: self.latest_restorable_time(),
            // The legacy EC2-Classic memberships: empty for every instance created
            // through the VPC platform, which is every instance this service holds
            // unless a request named one.
            db_security_groups: Some(
                self.db_security_group_names
                    .iter()
                    .map(|name| DBSecurityGroupMembership {
                        db_security_group_name: Some(name.clone()),
                        status: Some(MEMBERSHIP_ACTIVE.to_string()),
                    })
                    .collect(),
            ),
            vpc_security_groups: Some(vpc_security_group_memberships(
                &self.region,
                &self.vpc_security_group_ids,
            )),
            db_parameter_groups: Some(
                self.db_parameter_group_name
                    .iter()
                    .map(|name| DBParameterGroupStatus {
                        db_parameter_group_name: Some(name.clone()),
                        parameter_apply_status: Some(MEMBERSHIP_IN_SYNC.to_string()),
                    })
                    .collect(),
            ),
            option_group_memberships: Some(
                self.option_group_name
                    .iter()
                    .map(|name| OptionGroupMembership {
                        option_group_name: Some(name.clone()),
                        status: Some(MEMBERSHIP_IN_SYNC.to_string()),
                    })
                    .collect(),
            ),
            availability_zone: Some(self.availability_zone.clone()),
            // The DB subnet group the instance was created in, as the GROUP's own record
            // reports it: its description, its VPC, its status and its `Subnets` — each
            // subnet with the Availability Zone the service that owns subnets answered
            // with — are properties of that record, and a client reads them here to tell
            // which subnets and zones the instance can be placed in. Projected through
            // the group's one projection, so this copy cannot drift from what
            // `DescribeDBSubnetGroups` reports for the same group.
            db_subnet_group: db_subnet_group.map(DbSubnetGroupRecord::to_wire),
            preferred_maintenance_window: self.preferred_maintenance_window.clone(),
            // `PendingModifiedValues` is "returned only when there are pending changes":
            // what this instance still has pending, and nothing at all once it has none
            // ([`Self::pending_modified_values`]).
            pending_modified_values: self.pending_modified_values(),
            upgrade_rollout_order: Some(DEFAULT_UPGRADE_ROLLOUT_ORDER.to_string()),
            multi_az: Some(self.multi_az),
            engine_version: self.engine_version.clone(),
            auto_minor_version_upgrade: Some(self.auto_minor_version_upgrade),
            // The replicas of this instance, in the order they were created, and the source
            // it replicates itself. Both are stored halves of one relationship
            // `CreateDBInstanceReadReplica` creates, so an instance with no replica reports
            // an EMPTY list rather than none, and one that replicates nothing reports no
            // source at all.
            read_replica_db_instance_identifiers: Some(
                self.read_replica_db_instance_identifiers.clone(),
            ),
            read_replica_source_db_instance_identifier: self
                .read_replica_source_db_instance_identifier
                .clone(),
            license_model: self.license_model.clone(),
            iops: self.iops,
            storage_throughput: Some(self.storage_throughput),
            publicly_accessible: Some(self.publicly_accessible),
            storage_type: Some(self.storage_type.clone()),
            db_instance_port: Some(self.db_instance_port()),
            db_cluster_identifier: self.db_cluster_identifier.clone(),
            storage_encrypted: Some(self.storage_encrypted),
            kms_key_id: self.kms_key_id.clone(),
            dbi_resource_id: Some(self.dbi_resource_id.clone()),
            ca_certificate_identifier: Some(self.ca_certificate_identifier.clone()),
            certificate_details: Some(CertificateDetails {
                ca_identifier: Some(self.ca_certificate_identifier.clone()),
                valid_till: Some(self.certificate_valid_till()),
            }),
            domain_memberships: Some(
                self.domain
                    .iter()
                    .map(|domain| DomainMembership {
                        domain: Some(domain.clone()),
                        status: Some("joined".to_string()),
                        ..DomainMembership::default()
                    })
                    .collect(),
            ),
            copy_tags_to_snapshot: Some(self.copy_tags_to_snapshot),
            monitoring_interval: Some(self.monitoring_interval),
            db_instance_arn: Some(self.arn()),
            iam_database_authentication_enabled: Some(self.iam_database_authentication_enabled),
            database_insights_mode: Some(self.database_insights_mode.clone()),
            performance_insights_enabled: Some(self.performance_insights_enabled),
            deletion_protection: Some(self.deletion_protection),
            // "A list of Amazon Web Services Identity and Access Management (IAM) roles
            // associated with the DB instance": the associations this instance carries, in
            // the order they were made, and EMPTY for an instance that carries none.
            associated_roles: Some(self.associated_roles.clone()),
            max_allocated_storage: self.max_allocated_storage,
            tag_list: Some(self.tags.clone()),
            customer_owned_ip_enabled: Some(self.customer_owned_ip_enabled),
            network_type: Some(self.network_type.clone()),
            activity_stream_status: Some(ACTIVITY_STREAM_STOPPED.to_string()),
            backup_target: Some(self.backup_target.clone()),
            dedicated_log_volume: Some(self.dedicated_log_volume),
            // Nothing this service does changes an instance's storage file system
            // configuration, so no upgrade of it is ever recommended.
            is_storage_config_upgrade_available: Some(false),
            engine_lifecycle_support: Some(self.engine_lifecycle_support.clone()),
            ..DBInstance::default()
        }
    }
}
