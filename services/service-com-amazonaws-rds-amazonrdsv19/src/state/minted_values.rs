// SPDX-License-Identifier: CC0-1.0

//! The server-MINTED values this service assigns to the resources it creates: the
//! identifier prefixes, the one monotone counter they are drawn from, and the minting
//! function of each resource kind.
//!
//! Split out of [`super`] so that module keeps the store, the records and their
//! projections; every name here is re-exported from it, so a handler still reads them as
//! `crate::state::<name>`.

use super::*;

/// The immutable resource id RDS reports as `DbiResourceId`: `db-` plus 26
/// uppercase characters, minted once per instance and never reused.
pub fn mint_dbi_resource_id(mint: u64) -> String {
    // OnCallWorlds patch: an id the seed pinned for this setup call.
    if let Some(id) = ocw_clock::take_pinned("dbi") {
        return id;
    }
    format!("db-{}", base36(mint, 26))
}

/// The DNS label RDS assigns an instance's endpoint between the identifier and the
/// region: a server-minted, 12-character token, unique per instance.
pub fn mint_endpoint_host(mint: u64) -> String {
    // OnCallWorlds patch: the endpoint token the seed pinned for this setup call.
    if let Some(id) = ocw_clock::take_pinned("rdshost") {
        return id;
    }
    base36(mint, 12).to_ascii_lowercase()
}

/// The immutable resource id RDS reports as `GlobalClusterResourceId`: the
/// "partition-unique, immutable identifier for the global database cluster", written
/// `cluster-` plus 26 characters of the same server-minted alphabet
/// [`mint_dbi_resource_id`] draws on, and never reused.
pub fn mint_global_cluster_resource_id(mint: u64) -> String {
    format!("cluster-{}", base36(mint, 26))
}

/// The immutable resource id RDS reports as `DbClusterResourceId`: "the Amazon Web
/// Services Region-unique, immutable identifier for the DB cluster", of the same
/// `cluster-` plus 26 server-minted characters form as
/// [`mint_global_cluster_resource_id`]. Both draw on the one store-wide counter, so no two
/// resources of this service can be minted the same id.
pub fn mint_db_cluster_resource_id(mint: u64) -> String {
    format!("cluster-{}", base36(mint, 26))
}
