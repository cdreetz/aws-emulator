// SPDX-License-Identifier: CC0-1.0

//! Engine state for the com-amazonaws-iam-awsidentitymanagementv20100508 service.
//!
//! This module owns the persisted IAM entities plus the small helpers every
//! handler needs (name keying, ARN building, id minting, policy-document checks,
//! opaque pagination markers). Handlers reach it through [`service_state`]; they
//! never keep a second copy of a resource.
//!
//! [`authorization`] is the sub-module that answers who a signed request speaks for
//! and whether that principal's identity-based policies let it do what it asks.

use std::collections::{BTreeMap, BTreeSet};

use crate::ops::types::{
    AttachedPermissionsBoundary, DelegationRequest, Group, InstanceProfile, LoginProfile,
    ParameterDefinition, Policy, PolicyVersion, Role, RoleTemplateVersion, SAMLPrivateKey,
    ServerCertificateMetadata, ServiceSpecificCredentialMetadata, SigningCertificate, Tag,
    UpdateAccountPasswordPolicyInput, User,
};

pub mod account;
pub mod authorization;
pub mod credential_report;
pub mod entity_path;
pub mod entity_references;
pub mod input_formats;
pub mod member_forms;
pub mod reported_services;
pub mod role_templates;
pub mod simulated_decisions;
pub mod ssh_public_keys;
pub mod virtual_mfa_devices;
mod managed_policy_catalog;
pub use managed_policy_catalog::*;

pub use account::*;
pub use credential_report::*;
pub use entity_path::*;
pub use entity_references::*;
pub use input_formats::*;
pub use member_forms::*;
pub use reported_services::*;
pub use role_templates::*;
pub use ssh_public_keys::*;
pub use virtual_mfa_devices::*;

/// IAM's default entity path: every entity whose request omits `Path` is created
/// directly under the account root. The model's `pathType` documentation states
/// the parameter "defaults to a slash (/)".
pub const DEFAULT_PATH: &str = "/";

/// The number of entities `ListUsers` (and IAM's other list operations) returns
/// when the request supplies no `MaxItems`. IAM's `MaxItems` documentation states
/// that "if you do not include this parameter, the number of items defaults to
/// 100".
pub const DEFAULT_MAX_ITEMS: i32 = 100;

/// The `PermissionsBoundaryType` IAM reports on every entity that carries a permissions
/// boundary.
///
/// The member targets `PermissionsBoundaryAttachmentType`, whose single entry the model
/// NAMES `PermissionsBoundaryPolicy`
/// (`smithy_query(query="shape", shape="PermissionsBoundaryAttachmentType")`); what IAM
/// puts on the wire for it is `Policy`, which is what a client comparing the reported type
/// matches against, so the wire value is carried here rather than the enum entry's name.
pub const PERMISSIONS_BOUNDARY_TYPE: &str = "Policy";

/// The `EntityType` value that names an IAM role — the value `ListEntitiesForPolicy`'s
/// `EntityFilter` documentation itself uses ("when EntityFilter is Role, only the
/// roles that are attached to the specified policy are returned"). One of the five
/// values the enum declares, which `ops::types::ENTITY_TYPE_VALUES` records.
pub const ENTITY_FILTER_ROLE: &str = "Role";

/// The `EntityType` value that names an IAM user. See [`ENTITY_FILTER_ROLE`].
pub const ENTITY_FILTER_USER: &str = "User";

/// The `EntityType` value that names an IAM group. See [`ENTITY_FILTER_ROLE`].
pub const ENTITY_FILTER_GROUP: &str = "Group";

/// The `EntityType` value that names a managed policy the ACCOUNT owns — "use the
/// value LocalManagedPolicy to include customer managed policies"
/// (`GetAccountAuthorizationDetails$Filter`). See [`ENTITY_FILTER_ROLE`].
pub const ENTITY_FILTER_LOCAL_MANAGED_POLICY: &str = "LocalManagedPolicy";

/// The `EntityType` value that names a managed policy AWS owns, the counterpart of
/// [`ENTITY_FILTER_LOCAL_MANAGED_POLICY`]. See [`ENTITY_FILTER_ROLE`].
pub const ENTITY_FILTER_AWS_MANAGED_POLICY: &str = "AWSManagedPolicy";

/// The `PolicyUsageType` value that names a policy used as a permissions POLICY:
/// "to list only permissions policies, set PolicyUsageFilter to PermissionsPolicy"
/// (`ListEntitiesForPolicy$PolicyUsageFilter`). One of the two values the enum
/// declares, which `ops::types::POLICY_USAGE_TYPE_VALUES` records.
pub const POLICY_USAGE_PERMISSIONS_POLICY: &str = "PermissionsPolicy";

/// The `PolicyUsageType` value that names a policy used to set a permissions
/// BOUNDARY: "to list only the policies used to set permissions boundaries, set the
/// value to PermissionsBoundary". See [`POLICY_USAGE_PERMISSIONS_POLICY`].
pub const POLICY_USAGE_PERMISSIONS_BOUNDARY: &str = "PermissionsBoundary";

/// The ARN resource type of a delegation request: the entity type
/// `GetHumanReadableSummaryRequest$EntityArn` documents a summary is served for
/// ("at this time, the only supported entity type is delegation-request"), and the
/// resource type an ARN naming such a request therefore carries.
pub const DELEGATION_REQUEST_RESOURCE_TYPE: &str = "delegation-request";

/// The `policyScopeType` value that selects only the managed policies AWS owns: "to
/// list only Amazon Web Services managed policies, set Scope to AWS"
/// (`ListPolicies$Scope`). One of the three values the enum declares, which
/// `ops::types::POLICY_SCOPE_TYPE_VALUES` records.
pub const POLICY_SCOPE_AWS: &str = "AWS";

/// The `policyScopeType` value that selects only the managed policies the ACCOUNT
/// owns: "to list only the customer managed policies in your Amazon Web Services
/// account, set Scope to Local". See [`POLICY_SCOPE_AWS`]; the third value (`All`)
/// selects both, which is also what an absent `Scope` means.
pub const POLICY_SCOPE_LOCAL: &str = "Local";

/// The prefix AWS gives an IAM user's unique id. `User$UserId` is modelled as
/// `idType` (len 16..128, pattern `^[\w]+$`), which this prefix plus
/// [`UNIQUE_ID_SUFFIX_LEN`] base32 characters satisfies.
const USER_ID_PREFIX: &str = "AIDA";

/// The prefix AWS gives an IAM role's unique id. `Role$RoleId` is modelled as
/// `idType` (len 16..128, pattern `^[\w]+$`), which this prefix plus
/// [`UNIQUE_ID_SUFFIX_LEN`] base32 characters satisfies.
const ROLE_ID_PREFIX: &str = "AROA";

/// The prefix AWS gives an IAM group's unique id. `Group$GroupId` is modelled as
/// `idType` (len 16..128, pattern `^[\w]+$`), which this prefix plus
/// [`UNIQUE_ID_SUFFIX_LEN`] base32 characters satisfies.
const GROUP_ID_PREFIX: &str = "AGPA";

/// The prefix AWS gives an instance profile's unique id.
/// `InstanceProfile$InstanceProfileId` is modelled as `idType` (len 16..128, pattern
/// `^[\w]+$`), which this prefix plus [`UNIQUE_ID_SUFFIX_LEN`] base32 characters
/// satisfies.
const INSTANCE_PROFILE_ID_PREFIX: &str = "AIPA";

/// The prefix AWS gives a managed policy's unique id. `Policy$PolicyId` is
/// modelled as `idType` (len 16..128, pattern `^[\w]+$`), which this prefix plus
/// [`UNIQUE_ID_SUFFIX_LEN`] base32 characters satisfies.
const POLICY_ID_PREFIX: &str = "ANPA";

/// The version identifier the first version of a managed policy carries.
/// `CreatePolicy`'s documentation: "This operation creates a policy version with a
/// version identifier of v1 and sets v1 as the policy's default version."
pub const FIRST_POLICY_VERSION_ID: &str = "v1";

/// How many characters an IAM role name may carry: `Role$RoleName` is modelled as
/// `roleNameType` with length 1..64
/// (`smithy_query(query="shape", shape="Role")`), so a name a service-linked role
/// create would derive past that bound cannot name a role at all.
pub const MAX_ROLE_NAME_CHARACTERS: usize = 64;

/// How many IAM roles one account may hold. AWS's "IAM and STS quotas" page gives
/// the quota "Roles in an account: 1,000", and a create past it is refused with
/// `LimitExceededException`, whose documentation says "the error message describes
/// the limit exceeded". It is also what stops the role map growing without end.
pub const MAX_ROLES_PER_ACCOUNT: usize = 1_000;

/// How many roles one instance profile may hold. `AddRoleToInstanceProfile`'s
/// documentation: "An instance profile can contain only one role, and this quota
/// cannot be increased."
pub const MAX_ROLES_PER_INSTANCE_PROFILE: usize = 1;

/// How many temporary role-session credentials this account keeps a record of at once
/// ([`ComAmazonawsIamAwsidentitymanagementv20100508State::role_sessions`]).
///
/// A record is a request-driven insert, so the map needs a declared ceiling; the write
/// first gives up every record the clock has already expired, which is what normally
/// keeps it far below this. The value is a chosen emulator ceiling — AWS publishes no
/// quota on how many sessions of a role may be live — far above any test or demo
/// workload.
pub const MAX_ROLE_SESSIONS: usize = 4_096;

/// How many delegation requests one account may hold. AWS's "IAM and STS quotas"
/// page publishes no figure for a delegation request, so this bound is the
/// emulator's own: it is what stops the delegation-request map — and the workflow-id
/// index beside it — growing without end on repeated filings, and it sits far above
/// any partner engagement a caller files by hand. A filing past it is refused with
/// the modelled `LimitExceededException`, whose documentation says "the error message
/// describes the limit exceeded", exactly as a create past any other of these bounds
/// is.
pub const MAX_DELEGATION_REQUESTS_PER_ACCOUNT: usize = 1_000;

/// The maximum session duration, in seconds, a role created without one carries.
/// `CreateRole$MaxSessionDuration`'s documentation states "if you do not specify a
/// value for this setting, the default value of one hour is applied", and
/// `roleMaxSessionDurationType`'s range (3600..43200) puts one hour at its floor.
pub const DEFAULT_MAX_SESSION_DURATION_SECONDS: i32 = 3_600;

/// How many IAM instance profiles one account may hold. AWS's "IAM and STS quotas"
/// page gives the quota "Instance profiles in an account: 1,000", and a create past
/// it is refused with `LimitExceededException`, whose documentation says "the error
/// message describes the limit exceeded". It is also what stops the instance profile
/// map growing without end.
pub const MAX_INSTANCE_PROFILES_PER_ACCOUNT: usize = 1_000;

/// How many customer managed policies one account may hold. AWS's "IAM and STS
/// quotas" page gives the quota "Customer managed policies in an account: 1,500",
/// and a create past it is refused with `LimitExceededException`, whose
/// documentation says "the error message describes the limit exceeded". It is also
/// what stops the policy map growing without end.
pub const MAX_POLICIES_PER_ACCOUNT: usize = 1_500;

/// The size, in non-whitespace characters, of one managed policy document. AWS's
/// "IAM and STS character quotas" page gives "Managed policy size: 6,144
/// characters" and states that IAM "doesn't count whitespace when calculating the
/// size of a policy against this limitation", so the measure
/// ([`policy_document_characters`]) skips whitespace too.
pub const MAX_MANAGED_POLICY_CHARACTERS: usize = 6_144;

/// How many versions one managed policy may carry. `CreatePolicyVersion`'s
/// documentation: "A managed policy can have up to five versions. If the policy has
/// five versions, you must delete an existing version using DeletePolicyVersion
/// before you create a new version." A create past it is refused with
/// `LimitExceededException`, whose documentation says "the error message describes
/// the limit exceeded", and it is what stops one policy's version map growing
/// without end.
pub const MAX_POLICY_VERSIONS: usize = 5;

/// How many IAM users one account may hold. AWS's "IAM and STS quotas" page gives
/// the quota "Users in an account: 5,000", and a create past it is refused with
/// `LimitExceededException`, whose documentation says "the error message describes
/// the limit exceeded".
pub const MAX_USERS_PER_ACCOUNT: usize = 5_000;

/// How many IAM groups one account may hold. AWS's "IAM and STS quotas" page gives
/// the quota "IAM groups in an account: 300", and a create past it is refused with
/// `LimitExceededException`, whose documentation says "the error message describes
/// the limit exceeded". It is also what stops the group map growing without end.
pub const MAX_GROUPS_PER_ACCOUNT: usize = 300;

/// How many IAM groups one IAM user may belong to. AWS's "IAM and STS quotas" page
/// gives the quota "IAM groups that an IAM user can be a member of: 10", and an add
/// past it is refused with `LimitExceededException`, whose documentation says "the
/// error message describes the limit exceeded" — here, the maximum number of groups
/// per user, for the user the add names. It is also what bounds the memberships one
/// user can accumulate in [`group_members`].
///
/// [`group_members`]: ComAmazonawsIamAwsidentitymanagementv20100508State::group_members
pub const MAX_GROUPS_PER_USER: usize = 10;

/// The status a key IAM has just minted carries. `CreateAccessKey`'s
/// documentation states "the default status for new keys is Active", and `Active`
/// is one of the three values `statusType` declares
/// (`smithy_query(query="shape", shape="statusType")`: Active, Inactive, Expired).
pub const ACCESS_KEY_ACTIVE_STATUS: &str = "Active";

/// How many access keys one IAM user may hold. AWS's "IAM and STS quotas" page
/// gives the quota "Access keys per IAM user: 2", and a create past it is refused
/// with `LimitExceededException`, whose documentation says "the error message
/// describes the limit exceeded".
pub const MAX_ACCESS_KEYS_PER_USER: usize = 2;

/// How many X.509 signing certificates one IAM user may hold. AWS's "IAM and STS
/// quotas" page gives the quota "Signing certificates per IAM user: 2", and an
/// upload past it is refused with `LimitExceededException`, whose documentation says
/// "the error message describes the limit exceeded".
pub const MAX_SIGNING_CERTIFICATES_PER_USER: usize = 2;

/// The aggregate size, in non-whitespace characters, of all inline policies
/// embedded in one IAM user. AWS's "IAM and STS quotas" page gives the quota "User
/// policy size cannot exceed 2,048 characters" and states that IAM "doesn't count
/// whitespace when calculating the size of a policy against this limitation", so
/// the measure ([`policy_document_characters`]) skips whitespace; a put that would
/// carry the user past the quota is refused with `LimitExceededException`.
pub const MAX_USER_INLINE_POLICY_CHARACTERS: usize = 2_048;

/// The aggregate size, in non-whitespace characters, of all inline policies
/// embedded in one IAM role. AWS's "IAM and STS quotas" page gives the quota "Role
/// policy size cannot exceed 10,240 characters", measured the same way the other
/// policy-size quotas are ([`policy_document_characters`]); a put that would carry
/// the role past it is refused with `LimitExceededException`.
pub const MAX_ROLE_INLINE_POLICY_CHARACTERS: usize = 10_240;

/// The aggregate size, in non-whitespace characters, of all inline policies
/// embedded in one IAM group. AWS's "IAM and STS quotas" page gives the quota
/// "Group policy size cannot exceed 5,120 characters", measured the same way the
/// other policy-size quotas are ([`policy_document_characters`]); a put that would
/// carry the group past it is refused with `LimitExceededException`.
pub const MAX_GROUP_INLINE_POLICY_CHARACTERS: usize = 5_120;

/// The aggregate RAW size, in characters, of the inline-policy documents this
/// emulator retains for one entity.
///
/// The quotas above are measured with whitespace left out, so they do not bound the
/// TEXT an entity's inline policies carry: a document that fits its quota may be
/// formatted with any amount of whitespace, and every document is held verbatim so
/// a read reports it exactly as it was embedded. This is the ceiling on that text,
/// set to `policyDocumentType`'s own published maximum (`@length 1..131072`,
/// `smithy_query(query="shape", shape="policyDocumentType")`) — the longest single
/// document the service accepts at all — so one entity never retains more policy
/// text than one document may carry, and a put that would carry it past this
/// ceiling is refused with `LimitExceededException` instead of stored.
pub const MAX_INLINE_POLICY_TEXT_CHARACTERS: usize = 131_072;

/// How many sets of service-specific credentials one IAM user may hold for one
/// supported service. `CreateServiceSpecificCredential`'s documentation: "You can
/// have a maximum of two sets of service-specific credentials for each supported
/// service per user", so a create past it is refused with `LimitExceededException`,
/// whose documentation says "the error message describes the limit exceeded".
pub const MAX_SERVICE_SPECIFIC_CREDENTIALS_PER_SERVICE: usize = 2;

/// What joins the IAM user name to the account id in a generated `ServiceUserName`.
/// `ServiceSpecificCredential$ServiceUserName`: the value "is generated by combining
/// the IAM user's name combined with the ID number of the Amazon Web Services
/// account, as in `jane-at-123456789012`".
const SERVICE_USER_NAME_INFIX: &str = "-at-";

/// The version tag a long-term API key's `ServiceCredentialAlias` carries.
/// `ServiceSpecificCredential$ServiceCredentialAlias` says the alias "includes the
/// IAM user name and a suffix containing version and creation information"; this is
/// the version part of that suffix, and the creation instant is the rest.
const API_KEY_ALIAS_VERSION: &str = "v1";

/// Seconds in a day: the unit `CreateServiceSpecificCredential$CredentialAgeDays`
/// counts ("the number of days until the service specific credential expires").
const SECONDS_PER_DAY: i64 = 86_400;

/// The status a freshly created credential carries — `statusType`'s `Active`, which
/// `ServiceSpecificCredential$Status` documents as "the key is valid for API calls".
pub const CREDENTIAL_STATUS_ACTIVE: &str = "Active";

/// The status a credential whose expiration date has passed carries: `statusType`'s
/// third value (`smithy_query(query="shape", shape="statusType")` gives `Active`,
/// `Inactive`, `Expired`).
pub const CREDENTIAL_STATUS_EXPIRED: &str = "Expired";

/// The path AWS reserves for service-linked roles: every service-linked role is
/// filed under this prefix followed by the service principal it is linked to
/// (`CreateServiceLinkedRole`'s handler builds the path, and
/// [`is_service_linked_role_path`] recognises one). It is shared because a role's
/// path is what tells an operation the role is service-linked, and
/// `UnmodifiableEntityException`'s documentation says "only the service that
/// depends on the service-linked role can modify or delete the role on your
/// behalf".
pub const SERVICE_LINKED_ROLE_PATH_PREFIX: &str = "/aws-service-role/";

/// The account segment an AWS-managed policy's ARN carries
/// (`arn:aws:iam::aws:policy/...`): AWS-managed policies are owned by AWS rather
/// than by an account, which is what distinguishes them from the
/// customer-managed policies an account creates.
pub const AWS_MANAGED_POLICY_ACCOUNT: &str = "aws";

/// How many managed policies one IAM role may carry. AWS's "IAM and STS quotas"
/// page gives the quota "Managed policies attached to an IAM role: 10", and an
/// attach past it is refused with `LimitExceededException`, whose documentation
/// says "the error message describes the limit exceeded". It is also what stops a
/// role's attachment set growing without end.
pub const MAX_MANAGED_POLICIES_PER_ROLE: usize = 10;

/// How many managed policies one IAM user may carry. AWS's "IAM and STS quotas"
/// page gives the quota "Managed policies attached to an IAM user: 10", and an
/// attach past it is refused with `LimitExceededException`, exactly as a role's
/// quota ([`MAX_MANAGED_POLICIES_PER_ROLE`]) is. It is also what stops a user's
/// attachment set growing without end.
pub const MAX_MANAGED_POLICIES_PER_USER: usize = 10;

/// How many managed policies one IAM group may carry. AWS's "IAM and STS quotas"
/// page gives the quota "Managed policies attached to an IAM group: 10", and an
/// attach past it is refused with `LimitExceededException`, exactly as a role's
/// quota ([`MAX_MANAGED_POLICIES_PER_ROLE`]) is. It is also what stops a group's
/// attachment set growing without end.
pub const MAX_MANAGED_POLICIES_PER_GROUP: usize = 10;

/// The scheme an OIDC provider's URL must carry.
/// `CreateOpenIDConnectProvider$Url`'s documentation: "The URL must begin with
/// https://".
pub const OPEN_ID_CONNECT_URL_SCHEME: &str = "https://";

/// How many client IDs one IAM OIDC provider may carry.
/// `CreateOpenIDConnectProvider$ClientIDList`'s documentation: "You cannot register
/// more than 100 client IDs with a single IAM OIDC provider."
pub const MAX_CLIENT_IDS_PER_OPEN_ID_CONNECT_PROVIDER: usize = 100;

/// How many certificate thumbprints one IAM OIDC provider may carry.
/// `CreateOpenIDConnectProvider$ThumbprintList`'s documentation: "IAM lets you have
/// up to five thumbprints for an OIDC provider."
pub const MAX_THUMBPRINTS_PER_OPEN_ID_CONNECT_PROVIDER: usize = 5;

/// How many OIDC providers one account may hold. AWS's "IAM and STS quotas" page
/// gives the quota "OIDC identity providers in an account: 100", and a create past
/// it is refused with `LimitExceededException`, whose documentation says "the error
/// message describes the limit exceeded". It is also what stops the provider map
/// growing without end.
pub const MAX_OPEN_ID_CONNECT_PROVIDERS_PER_ACCOUNT: usize = 100;

/// The name that stands for EVERY OIDC provider in the account, so
/// [`open_id_connect_provider_arn`] builds the ARN of the provider collection rather than
/// of one provider. An operation that names no provider is authorized on that collection,
/// and a refusal names it, because the request is about all of them.
pub const ANY_OPEN_ID_CONNECT_PROVIDER: &str = "*";

/// How many SAML 2.0 identity providers one account may hold. AWS's "IAM and STS
/// quotas" page gives the quota "SAML providers in an account: 100", and a create past
/// it is refused with `LimitExceededException`, whose documentation says "the error
/// message describes the limit exceeded". It is also what stops the provider map
/// growing without end.
pub const MAX_SAML_PROVIDERS_PER_ACCOUNT: usize = 100;

/// How many private keys ONE SAML provider may hold: `privateKeyList` — the shape
/// `GetSAMLProvider$PrivateKeyList` reports the keys through — is modelled len 0..2
/// (`smithy_query(query="shape", shape="privateKeyList")`), so a provider holding more
/// could never be reported. It is also why "to rotate private keys, add your new private
/// key and then remove the old key in a separate request" (`UpdateSAMLProvider`): with
/// the second slot taken, the next upload is refused with `LimitExceededException`,
/// whose documentation says "the error message describes the limit exceeded".
pub const MAX_PRIVATE_KEYS_PER_SAML_PROVIDER: usize = 2;

/// How many server certificates one account may hold. AWS's "IAM and STS quotas" page
/// gives the quota "Server certificates stored in IAM per account: 20", and an upload
/// past it is refused with `LimitExceededException`, whose documentation says "the error
/// message describes the limit exceeded". It is also what stops the server-certificate
/// map growing without end.
pub const MAX_SERVER_CERTIFICATES_PER_ACCOUNT: usize = 20;

/// The XML namespace a SAML 2.0 metadata document's descriptors are declared in
/// (`urn:oasis:names:tc:SAML:2.0:metadata`, OASIS "Metadata for the OASIS Security
/// Assertion Markup Language (SAML) V2.0"). A document whose root descriptor is not in
/// it is not "an XML document generated by an identity provider (IdP) that supports
/// SAML 2.0" (`CreateSAMLProvider$SAMLMetadataDocument`).
pub const SAML_METADATA_NAMESPACE: &str = "urn:oasis:names:tc:SAML:2.0:metadata";

/// The root element of a SAML 2.0 metadata document describing ONE entity, which
/// carries that entity's `entityID` — "the issuer's name"
/// (`CreateSAMLProvider$SAMLMetadataDocument`).
const SAML_ENTITY_DESCRIPTOR: &str = "EntityDescriptor";

/// The root element of a SAML 2.0 metadata document describing a GROUP of entities;
/// the entity descriptors are nested inside it.
const SAML_ENTITIES_DESCRIPTOR: &str = "EntitiesDescriptor";

/// The metadata attribute carrying "expiration information"
/// (`CreateSAMLProvider$SAMLMetadataDocument`) — an `xs:dateTime`, which is the
/// instant `GetSAMLProvider$ValidUntil` reports for the provider.
const SAML_VALID_UNTIL_ATTRIBUTE: &str = "validUntil";

/// The metadata attribute carrying a SAML entity's issuer name.
const SAML_ENTITY_ID_ATTRIBUTE: &str = "entityID";

/// The prefix of a minted `SAMLProviderUUID`. `privateKeyIdType` (which
/// `GetSAMLProvider$SAMLProviderUUID` targets) is len 22..64 with pattern
/// `^[A-Z0-9]+$`; this prefix plus [`UNIQUE_ID_SUFFIX_LEN`] base32 characters is 22
/// characters of uppercase alphanumerics, so it satisfies both. AWS publishes no
/// prefix for this identifier, so one is chosen here that cannot collide with the
/// entity-id prefixes above.
const SAML_PROVIDER_UUID_PREFIX: &str = "SAMLP";

/// The prefix of a minted `SAMLPrivateKey$KeyId`, which targets the same
/// `privateKeyIdType` as [`SAML_PROVIDER_UUID_PREFIX`] and is built the same way, from
/// its own prefix so a key id is never a provider uuid.
const SAML_PRIVATE_KEY_ID_PREFIX: &str = "SAMLK";

/// The prefix AWS gives a server certificate's unique id — the `ASCA` prefix the "IAM
/// identifiers" page of the IAM User Guide lists for a certificate under "unique ID
/// prefixes". `ServerCertificateMetadata$ServerCertificateId` is modelled as `idType`
/// (len 16..128, pattern `^[\w]+$`), which this prefix plus [`UNIQUE_ID_SUFFIX_LEN`]
/// base32 characters satisfies.
const SERVER_CERTIFICATE_ID_PREFIX: &str = "ASCA";

/// The tag-key prefix AWS reserves. "Tagging IAM resources" (IAM User Guide):
/// "You cannot create tag keys that begin with `aws:` because this prefix is
/// reserved for Amazon Web Services use."
pub const RESERVED_TAG_KEY_PREFIX: &str = "aws:";

/// What IAM answers a request naming a reserved tag key with: one fixed sentence for the
/// whole refusal class, naming the prefix the rule is about and nothing of the request.
///
/// Every operation that writes tags refuses the same way, so the sentence is held here
/// rather than built at each call site: a reader matching AWS's reserved-prefix wording
/// sees the same text whichever `Tag*` or `Create*` call it came from, and the offending
/// key is not echoed back.
pub const RESERVED_TAG_KEY_MESSAGE: &str =
    "Tag keys beginning with aws: are reserved for system use.";

/// How many tags ONE IAM resource may carry. AWS's "IAM and STS quotas" page gives
/// the quota "Number of tags per IAM resource: 50" — the same bound `tagListType`
/// puts on a single request's list (len 0..50,
/// `smithy_query(query="shape", shape="tagListType")`), which is why the bound has
/// to be taken against the resource's tag set AFTER the merge and not just against
/// the request. A tag call that would carry a resource past it is refused with
/// `LimitExceededException`, whose documentation says "the error message describes
/// the limit exceeded", and nothing is stored: `TagRole`'s documentation states
/// "if you exceed the allowed maximum number of tags, then the entire request
/// fails".
pub const MAX_TAGS_PER_ENTITY: usize = 50;

/// How many base32 characters follow the prefix in a minted unique id.
const UNIQUE_ID_SUFFIX_LEN: usize = 17;

/// How many base32 characters one mixed 64-bit word of a minted unique id spells
/// out: five bits per character, so thirteen characters carry all 64 bits.
const BASE32_CHARACTERS_PER_WORD: usize = 13;

/// How many characters a minted `CertificateId` carries. A signing certificate's id
/// has no entity-type prefix, so the whole value is base32 characters, and 32 of them
/// sit inside `certificateIdType`'s length 24..128
/// (`smithy_query(query="shape", shape="certificateIdType")`).
const SIGNING_CERTIFICATE_ID_CHARACTERS: usize = 32;

/// How many characters a minted `DelegationRequestId` carries. AWS publishes no
/// entity-type prefix for a delegation request, so the whole value is base32
/// characters, and 32 of them sit inside `delegationRequestIdType`'s length 16..128
/// and its pattern `^[\w-]+$`
/// (`smithy_query(query="shape", shape="delegationRequestIdType")`).
const DELEGATION_REQUEST_ID_CHARACTERS: usize = 32;

/// How long after it was filed a delegation request expires, which is what
/// `DelegationRequest$ExpirationTime` ("the expiry time of this delegation request")
/// reports.
///
/// The member's documentation points at the request-lifecycle page for "details on the
/// life time of a delegation request at each state" and states no figure, so the span is
/// the emulator's own: long enough for the approval workflow the operation describes — a
/// customer reaching the console through `ConsoleDeepLink` and acting on the request — to
/// run, and bounded so a filed request does not stand for ever.
pub const DELEGATION_REQUEST_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;

/// What every pagination `Marker` this service issues carries, inside the encoded
/// payload, so a token it did not issue is recognised as foreign rather than read
/// as a position in the store. The SCOPE each marker is minted with follows it
/// (see [`encode_marker`]), so a token issued for one collection is not read as a
/// position in another.
const MARKER_PREFIX: &str = "iam:";

/// The marker scope of the account's user collection, which `ListUsers` pages
/// over.
pub const MARKER_SCOPE_USERS: &str = "users";

/// The marker scope of the account's role collection, which `ListRoles` pages
/// over. It is its OWN scope, so a marker issued while paging roles is not read
/// as a position in the user collection and vice versa.
pub const MARKER_SCOPE_ROLES: &str = "roles";

/// The marker scope of the account's group collection, which `ListGroups` pages
/// over. It is its OWN scope, for the same reason the role collection is: a marker
/// issued while paging groups is not read as a position among the users or roles.
pub const MARKER_SCOPE_GROUPS: &str = "groups";

/// The marker scope of the MEMBERSHIP of ONE group — the users that group holds —
/// which `GetGroup` pages over. The group's key follows it, so a marker issued
/// while paging one group's members does not name a position in another's, nor in
/// the account's group collection: see [`group_members_marker_scope`].
pub const MARKER_SCOPE_GROUP_MEMBERS: &str = "group-members";

/// The marker scope of the groups ONE user belongs to, which `ListGroupsForUser`
/// pages over. The user's key follows it, so a marker issued while paging one
/// user's memberships names no position in another user's — and it is its OWN
/// scope, the other way round from [`MARKER_SCOPE_GROUP_MEMBERS`], so a token
/// issued while paging a group's members is not read as a position among a user's
/// groups: see [`user_groups_marker_scope`].
pub const MARKER_SCOPE_USER_GROUPS: &str = "user-groups";

/// The marker scope of the account's instance profile collection, which
/// `ListInstanceProfiles` pages over. It is its OWN scope, exactly as the user and
/// role collections are, so a marker issued while paging another collection is not
/// read as a position among the instance profiles.
pub const MARKER_SCOPE_INSTANCE_PROFILES: &str = "instance-profiles";

/// The marker scope of the instance profiles ONE role is bound to, which
/// `ListInstanceProfilesForRole` pages over. The role's key follows it, so a marker
/// issued while paging one role's profiles names no position in another role's — and
/// it is its OWN scope, so a token issued while paging the account's whole instance
/// profile collection is not read as a position among one role's:
/// see [`role_instance_profiles_marker_scope`].
pub const MARKER_SCOPE_ROLE_INSTANCE_PROFILES: &str = "role-instance-profiles";

/// The marker scope of the managed policies an account can read — the ones it holds
/// itself and the ones AWS owns ([`AWS_MANAGED_POLICIES`]) — which `ListPolicies`
/// pages over. It is its OWN scope, like the user and role collections, and ONE
/// scope covers the whole collection because that operation pages over the same key
/// order (the policy's ARN) whichever scope, path prefix, attachment state or usage
/// it filters by: the filters select within the order rather than changing it.
pub const MARKER_SCOPE_POLICIES: &str = "policies";

/// The marker scope of ONE role's attached managed policies, which
/// `ListAttachedRolePolicies` pages over. The role's key follows it, so a marker
/// issued while paging one role's attachments does not name a position in
/// another's: see [`role_attached_policies_marker_scope`].
pub const MARKER_SCOPE_ROLE_ATTACHED_POLICIES: &str = "role-attached-policies";

/// The marker scope of ONE user's attached managed policies, which
/// `ListAttachedUserPolicies` pages over. It is its OWN scope, with the user's key
/// following it, so a marker issued while paging one user's attachments names no
/// position in another user's — nor in any role's attachment order:
/// see [`user_attached_policies_marker_scope`].
pub const MARKER_SCOPE_USER_ATTACHED_POLICIES: &str = "user-attached-policies";

/// The marker scope of ONE group's attached managed policies, which
/// `ListAttachedGroupPolicies` pages over. It is its OWN scope, with the group's
/// key following it, exactly as the user's and role's attachment scopes carry
/// theirs, so a marker issued while paging one group's attachments names no
/// position in another group's — nor in any user's or role's attachment order, nor
/// among that group's EMBEDDED inline policies:
/// see [`group_attached_policies_marker_scope`].
pub const MARKER_SCOPE_GROUP_ATTACHED_POLICIES: &str = "group-attached-policies";

/// The marker scope of ONE role's EMBEDDED inline policies, which
/// `ListRolePolicies` pages over. The role's key follows it, exactly as it does
/// for the attachment set, so a marker issued while paging one role's inline
/// policies names no position in another role's — and a marker issued for a
/// role's attachments is not read as a position among its inline policies:
/// see [`role_policies_marker_scope`].
pub const MARKER_SCOPE_ROLE_POLICIES: &str = "role-policies";

/// The marker scope of ONE user's EMBEDDED inline policies, which
/// `ListUserPolicies` pages over. It is its OWN scope, with the user's key
/// following it, exactly as the role's inline-policy scope carries the role's, so a
/// marker issued while paging one user's inline policies names no position in
/// another user's — nor among that user's ATTACHED managed policies, nor among any
/// role's inline policies: see [`user_policies_marker_scope`].
pub const MARKER_SCOPE_USER_POLICIES: &str = "user-policies";

/// The marker scope of ONE group's EMBEDDED inline policies, which
/// `ListGroupPolicies` pages over. It is its OWN scope, with the group's key
/// following it, exactly as the user's and role's inline-policy scopes carry
/// theirs, so a marker issued while paging one group's inline policies names no
/// position in another group's — nor among that group's ATTACHED managed
/// policies, nor among the account's group collection:
/// see [`group_policies_marker_scope`].
pub const MARKER_SCOPE_GROUP_POLICIES: &str = "group-policies";

/// The marker scope of the entities ONE managed policy relates to, which
/// `ListEntitiesForPolicy` pages over. The policy's ARN follows it, so a marker
/// issued while paging the entities of one policy does not name a position in
/// another's: see [`entities_for_policy_marker_scope`]. One scope covers that
/// policy's whole entity collection because the operation pages over the same key
/// order whichever entity type, usage or path prefix it filters by — the filters
/// select within the order rather than changing it.
pub const MARKER_SCOPE_ENTITIES_FOR_POLICY: &str = "entities-for-policy";

/// The marker scope of the versions of ONE managed policy, which
/// `ListPolicyVersions` pages over. The policy's ARN follows it, so a marker
/// issued while paging one policy's versions does not name a position among
/// another's: see [`policy_versions_marker_scope`].
pub const MARKER_SCOPE_POLICY_VERSIONS: &str = "policy-versions";

/// The marker scope of the account's alias collection, which
/// `ListAccountAliases` pages over. It is its OWN scope, exactly as the user and
/// role collections are, so a marker issued while paging another collection is
/// not read as a position among the aliases.
pub const MARKER_SCOPE_ACCOUNT_ALIASES: &str = "account-aliases";

/// The marker scope of the account's service-specific credentials, which
/// `ListServiceSpecificCredentials` pages over. One scope covers the whole
/// collection because that operation pages over the same key order whichever user
/// or service it filters by — the filters select within the order rather than
/// changing it.
pub const MARKER_SCOPE_SERVICE_SPECIFIC_CREDENTIALS: &str = "service-specific-credentials";

/// The marker scope of the account's access keys, which `ListAccessKeys` pages
/// over. One scope covers the whole collection because that operation pages over
/// the same key order (the access key id) whichever user it reports on — the
/// user selects within the order rather than changing it.
pub const MARKER_SCOPE_ACCESS_KEYS: &str = "access-keys";

/// The marker scope of the account's signing certificates, which
/// `ListSigningCertificates` pages over. One scope covers the whole collection for
/// the same reason [`MARKER_SCOPE_ACCESS_KEYS`] does: that operation pages over the
/// same key order (the certificate id) whichever user it reports on.
pub const MARKER_SCOPE_SIGNING_CERTIFICATES: &str = "signing-certificates";

/// The marker scope of the account's SSH public keys, which `ListSSHPublicKeys` pages
/// over. One scope covers the whole collection for the same reason
/// [`MARKER_SCOPE_ACCESS_KEYS`] does: that operation pages over the same key order (the
/// SSH public key id) whichever user it reports on.
pub const MARKER_SCOPE_SSH_PUBLIC_KEYS: &str = "ssh-public-keys";

/// The marker scope of the account's server certificate collection, which
/// `ListServerCertificates` pages over. It is its OWN scope, exactly as the user and
/// role collections are, so a marker issued while paging another collection is not
/// read as a position among the server certificates. The key it carries is the
/// [`name_key`] of a certificate name, the key
/// [`ComAmazonawsIamAwsidentitymanagementv20100508State::server_certificates`] holds a
/// certificate under, and one scope covers the whole collection because the operation
/// pages over that same key order whichever path prefix it filters by — the filter
/// selects within the order rather than changing it.
pub const MARKER_SCOPE_SERVER_CERTIFICATES: &str = "server-certificates";

/// The marker scope of a policy simulation's evaluation results, which
/// `SimulatePrincipalPolicy` pages over. Unlike the other scopes this one names a
/// position in a list the request itself determines (its actions and resources), so
/// the key the marker carries is the INDEX of the next result rather than a store key.
pub const MARKER_SCOPE_SIMULATION_RESULTS: &str = "simulation-results";

/// The marker scope of the service namespaces ONE
/// `ListPoliciesGrantingServiceAccess` request asks about. Like
/// [`MARKER_SCOPE_SIMULATION_RESULTS`] this one names a position in a list the
/// REQUEST determines (its `ServiceNamespaces`) rather than in a store, so the key
/// the marker carries is the index of the next namespace to report on.
pub const MARKER_SCOPE_POLICIES_GRANTING_SERVICE_ACCESS: &str =
    "policies-granting-service-access";

/// The marker scope of the tag set of ONE tagged entity, which IAM's tag-listing
/// operations page over. The entity's handle follows it, so a marker issued while
/// paging one entity's tags names no position in another entity's tag set — and no
/// position in any other collection: see [`entity_tags_marker_scope`].
pub const MARKER_SCOPE_ENTITY_TAGS: &str = "entity-tags";

/// The marker scope of the account's whole authorization configuration — its users,
/// groups, roles and managed policies — which `GetAccountAuthorizationDetails` pages
/// over. One scope covers all four collections because that operation reports them
/// in a SINGLE enumeration order ([`entity_page_key`]) under one `Marker`, and the
/// entity types it is filtered by select within that order rather than changing it.
pub const MARKER_SCOPE_ACCOUNT_AUTHORIZATION_DETAILS: &str = "account-authorization-details";

/// The marker scope of the account's delegation request collection, which
/// `ListDelegationRequests` pages over. It is its OWN scope, for the same reason the
/// user and role collections are: a marker issued while paging another collection
/// names no position in this one. The key it carries is a `DelegationRequestId`, the
/// key [`ComAmazonawsIamAwsidentitymanagementv20100508State::delegation_requests`]
/// holds a request under.
pub const MARKER_SCOPE_DELEGATION_REQUESTS: &str = "delegation-requests";

/// The marker scope of the services ONE service-last-accessed report reports on, which
/// `GetServiceLastAccessedDetails` pages over. The report's own `JobId` follows it, so a
/// marker issued while paging one report's services names no position in another's: see
/// [`service_last_accessed_marker_scope`]. The key it carries is a service namespace, the
/// value that report's entries are ordered by.
pub const MARKER_SCOPE_SERVICE_LAST_ACCESSED: &str = "service-last-accessed";

/// The marker scope of the entities ONE service-last-accessed report reports for ONE
/// service, which `GetServiceLastAccessedDetailsWithEntities` pages over. Both the report's
/// `JobId` and that service's namespace follow it, so a marker issued while paging one
/// service's entities names no position in another service's: see
/// [`service_last_accessed_entities_marker_scope`]. The key it carries is an
/// [`entity_page_key`].
pub const MARKER_SCOPE_SERVICE_LAST_ACCESSED_ENTITIES: &str = "service-last-accessed-entities";

/// The alphabet the suffix is drawn from: RFC 4648 base32, every character of
/// which is an uppercase alphanumeric and so inside `idType`'s `^[\w]+$`.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The FORM of credential a service issues to an IAM user: the two shapes the
/// `ServiceSpecificCredential` structure describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceCredentialForm {
    /// A generated user name and password — `ServiceUserName` plus `ServicePassword`
    /// — which is what `CreateServiceSpecificCredential` documents it generates:
    /// "a set of credentials consisting of a user name and password".
    UserNameAndPassword,
    /// A long-term API key: the public `ServiceCredentialAlias` plus the secret
    /// `ServiceCredentialSecret`, which both members document as being "For Bedrock
    /// API keys and CloudWatch Logs API keys". These are the services
    /// `CredentialAgeDays` and `ExpirationDate` apply to.
    LongTermApiKey,
}

/// One service that supports service-specific credentials.
#[derive(Debug)]
pub struct ServiceWithCredentials {
    /// The service principal the request names in `ServiceName`.
    pub service_name: &'static str,
    /// The form of credential this service issues.
    pub form: ServiceCredentialForm,
}

/// Every service that supports service-specific credentials, with the form each
/// issues — the catalog `ServiceNotSupportedException` ("the specified service does
/// not support service-specific credentials") is taken against.
///
/// Source: `CreateServiceSpecificCredential`'s own documentation, which names
/// CodeCommit ("IAM credentials for CodeCommit: Git credentials, SSH keys") and
/// Amazon Keyspaces ("Use IAM with Amazon Keyspaces (for Apache Cassandra)") for
/// the user-name-and-password form and then "services that support long-term API
/// keys", which `ServiceSpecificCredential$ExpirationDate` and
/// `$ServiceCredentialAlias` name as "Bedrock API keys and CloudWatch Logs API
/// keys". Each entry is that service's service principal.
pub const SERVICES_WITH_SPECIFIC_CREDENTIALS: &[ServiceWithCredentials] = &[
    ServiceWithCredentials {
        service_name: "bedrock.amazonaws.com",
        form: ServiceCredentialForm::LongTermApiKey,
    },
    ServiceWithCredentials {
        service_name: "cassandra.amazonaws.com",
        form: ServiceCredentialForm::UserNameAndPassword,
    },
    ServiceWithCredentials {
        service_name: "codecommit.amazonaws.com",
        form: ServiceCredentialForm::UserNameAndPassword,
    },
    ServiceWithCredentials {
        service_name: "logs.amazonaws.com",
        form: ServiceCredentialForm::LongTermApiKey,
    },
];

/// The catalog entry for `service_name`, or `None` when no service by that name
/// supports service-specific credentials.
///
/// A service principal is a DNS name, and DNS names are case-insensitive, so the
/// lookup folds ASCII case and the caller reports the catalog's own spelling.
pub fn service_with_credentials(service_name: &str) -> Option<&'static ServiceWithCredentials> {
    SERVICES_WITH_SPECIFIC_CREDENTIALS
        .iter()
        .find(|service| service.service_name.eq_ignore_ascii_case(service_name))
}

/// The `ServiceUserName` IAM generates for a service-specific credential of the
/// user-name-and-password form: the IAM user's name joined to the account id (see
/// [`SERVICE_USER_NAME_INFIX`]).
///
/// Inside `serviceUserName`'s constraints (len 0..200, pattern `^[\w+=,.@-]*$`) for
/// every name `userNameType` admits: that pattern is a subset of this one, the
/// infix and the account id add 16 characters, and a user name is at most 64.
pub fn service_user_name(user_name: &str) -> String {
    format!(
        "{user_name}{SERVICE_USER_NAME_INFIX}{}",
        ::engine::emulator_account_id()
    )
}

/// The `ServiceCredentialAlias` IAM generates for a long-term API key: the IAM
/// user's name followed by the suffix `ServiceCredentialAlias` documents, "version
/// and creation information" — the alias format's version and the second the key was
/// created.
///
/// The exact suffix AWS assembles is not documented, so this is a server-generated
/// value of the modelled type (`serviceCredentialAlias`, len 0..200, pattern
/// `^[\w+=,.@-]+$`): it is built once at creation, stored with the credential, and
/// every later read reports the stored value.
pub fn api_key_alias(user_name: &str, created: ::aws_smithy_types::DateTime) -> String {
    format!("{user_name}-{API_KEY_ALIAS_VERSION}-{}", created.secs())
}

/// When a credential created at `created` with `credential_age_days` expires:
/// `CredentialAgeDays` is "the number of days until the service specific credential
/// expires", counted from its creation.
pub fn credential_expiration(
    created: ::aws_smithy_types::DateTime,
    credential_age_days: i32,
) -> ::aws_smithy_types::DateTime {
    let age = i64::from(credential_age_days).saturating_mul(SECONDS_PER_DAY);
    ::aws_smithy_types::DateTime::from_secs(created.secs().saturating_add(age))
}

/// A fresh service-specific credential: the id to report it under, and its secret.
///
/// A service-specific credential authenticates its IAM user to ONE other Amazon Web
/// Services service — CodeCommit over HTTPS Git, Amazon Keyspaces over CQL — and
/// never to this emulator over SigV4, so the pair must not stay in the emulator's
/// credential store. Nothing in a service may construct an id or a secret itself,
/// though, so both are minted by the one component that generates them, the
/// credential store, and the record is then removed from it again — the shape
/// `service-com-amazonaws-mwaa-amazonmwaa`'s `mint_airflow_token` uses for the same
/// reason. The id that comes back is 20 characters from the base32 alphabet, inside
/// `serviceSpecificCredentialId`'s len 20..128 and `^[\w]+$`.
///
/// `None` when the store minted no secret, which leaves the caller to refuse rather
/// than report a credential it made up.
pub fn mint_service_specific_credential(
    store: &::emulator_server::CredentialStore,
) -> Option<(String, String)> {
    let minted = store.create(&::emulator_server::aws_credentials::AWS_ACCESS_KEY);
    let secret = minted
        .secret(::emulator_server::aws_credentials::SECRET_ACCESS_KEY)
        .map(str::to_string);
    // The pair is not a credential of this emulator; see above.
    let _ = store.delete(&minted.id);
    secret.map(|secret| (minted.id, secret))
}

/// One inline policy embedded in an IAM entity.
///
/// The name is kept beside the document because the map is keyed by the
/// case-folded name ([`name_key`]) while a read must report the policy as the
/// account holds it.
#[derive(Debug, Clone)]
pub struct InlinePolicy {
    /// The policy name in the case the last put chose.
    pub policy_name: String,
    /// The policy document exactly as it was stored.
    pub policy_document: String,
}

/// One managed policy the account holds.
///
/// The modelled [`Policy`] is kept exactly as every reader reports it, beside the
/// policy's versions — the `Policy` shape carries no document, so the document a
/// create or an update supplied lives in the version it created.
#[derive(Debug, Clone)]
pub struct ManagedPolicy {
    /// The policy as `CreatePolicy` returned it and `GetPolicy` reports it.
    pub policy: Policy,
    /// The policy's versions, keyed by `PolicyVersion$VersionId` (`v1`, `v2`, …).
    pub versions: BTreeMap<String, PolicyVersion>,
}

impl ManagedPolicy {
    /// The identifier the NEXT version of this policy carries: `v` followed by one
    /// past the greatest version number the policy holds
    /// ([`policy_version_number`]).
    ///
    /// Version identifiers are assigned in sequence — the first one a policy carries
    /// is [`FIRST_POLICY_VERSION_ID`], which is what this answers for a policy
    /// holding no version — so the number is also the creation order every reader of
    /// a policy's versions enumerates them in reverse of
    /// ([`policy_version_page_key`]). Taking it one past the GREATEST held number,
    /// rather than from the count, is what keeps a new version from reusing the
    /// identifier of one the policy still carries after an earlier version was
    /// deleted.
    pub fn next_version_id(&self) -> String {
        let highest = self
            .versions
            .keys()
            .map(|version_id| policy_version_number(version_id))
            .max()
            .unwrap_or(0);
        format!("v{}", highest + 1)
    }

    /// The identifier of the version in force on this policy: "the default version
    /// is the operative version … the version that is used for all principals"
    /// (`SetDefaultPolicyVersion`).
    ///
    /// ONE reading of which version is the default, consulted by every reader that
    /// reports or applies it, so a flag a listing reports and the document an
    /// attachment grants cannot name different versions. A record whose default is
    /// not recorded is read at the version every policy is created with
    /// ([`FIRST_POLICY_VERSION_ID`]), the one it would be in force at.
    pub fn default_version_id(&self) -> &str {
        self.policy
            .default_version_id
            .as_deref()
            .unwrap_or(FIRST_POLICY_VERSION_ID)
    }

    /// This policy's versions in the ONE order every reader of them enumerates them
    /// in — newest created first ([`policy_version_page_key`]) — each paired with
    /// the page key that names its POSITION in that order, and each carrying the
    /// default flag ([`Self::default_version_id`]) decides.
    ///
    /// `PolicyVersion$IsDefaultVersion` "specifies whether the policy version is set
    /// as the policy's default version", so the flag is derived here from the
    /// policy's stored default-version id rather than from a version's position in
    /// the list or from a copy of the flag held beside it: exactly one version of a
    /// policy carries it, whichever one the last `SetDefaultPolicyVersion` (or a
    /// `CreatePolicyVersion` asked to set it) selected. The page keys are what lets a
    /// single `Marker` page over this order.
    pub fn versions_newest_first(&self) -> Vec<(String, PolicyVersion)> {
        let default_version_id = self.default_version_id();
        let mut ordered: Vec<(String, PolicyVersion)> = self
            .versions
            .values()
            .map(|version| {
                let version_id = version.version_id.as_deref().unwrap_or_default();
                (
                    policy_version_page_key(version_id),
                    PolicyVersion {
                        is_default_version: version_id == default_version_id,
                        ..version.clone()
                    },
                )
            })
            .collect();
        ordered.sort_by(|(left, _), (right, _)| left.cmp(right));
        ordered
    }
}

/// One instance profile the account holds.
///
/// The modelled [`InstanceProfile`] is kept exactly as every reader reports it, beside
/// the BINDING `AddRoleToInstanceProfile` writes: the [`name_key`]s of the roles the
/// profile holds. A bound role is NOT copied in here — it stays in
/// [`ComAmazonawsIamAwsidentitymanagementv20100508State::roles`], the one record of what
/// a role is, so a read of the profile reports that role as it stands now rather than a
/// snapshot taken when it was bound (see
/// [`instance_profile_report`](ComAmazonawsIamAwsidentitymanagementv20100508State::instance_profile_report)).
#[derive(Debug, Clone)]
pub struct InstanceProfileRecord {
    /// The profile as `CreateInstanceProfile` returned it and `GetInstanceProfile`
    /// reports it. Its `roles` member is not the binding and is never read: the report
    /// builder fills it from [`role_keys`](Self::role_keys).
    pub profile: InstanceProfile,
    /// The [`name_key`]s of the roles bound to this profile, in the order they were
    /// bound. At most [`MAX_ROLES_PER_INSTANCE_PROFILE`] of them, because "an instance
    /// profile can contain only one role, and this quota cannot be increased"
    /// (`AddRoleToInstanceProfile`).
    pub role_keys: Vec<String>,
}

/// One access key an IAM user holds, keyed in [`ComAmazonawsIamAwsidentitymanagementv20100508State::access_keys`]
/// by the access key id.
///
/// The id and its secret are minted by the emulator's credential store, which is
/// the only thing that creates credential material; the secret is never stored
/// here, because `AccessKey$SecretAccessKey` "is returned only in response to
/// CreateAccessKey" (the `AccessKey` shape's documentation) and nothing may hand
/// it out again. The owning user's name is not copied in either: it is read from
/// the user the record's [`user_key`](AccessKeyRecord::user_key) names, so the
/// name lives in exactly one place.
#[derive(Debug, Clone)]
pub struct AccessKeyRecord {
    /// [`name_key`] of the IAM user that owns the key.
    pub user_key: String,
    /// The key's `statusType` value: [`ACCESS_KEY_ACTIVE_STATUS`] when it was
    /// minted, until an update moves it.
    pub status: String,
    /// The instant the key was minted, reported unchanged by every later read.
    pub create_date: ::aws_smithy_types::DateTime,
}

/// One TEMPORARY credential a role of this account is being used under, keyed in
/// [`ComAmazonawsIamAwsidentitymanagementv20100508State::role_sessions`] by the access
/// key id the session presents.
///
/// Which principal an access key id speaks for is a question about the account's
/// identities, and this store already answers it for a LONG-TERM key through
/// [`ComAmazonawsIamAwsidentitymanagementv20100508State::access_keys`]. A credential STS
/// vends for an assumed role is the other half of that same question: the permissions in
/// force on such a session are the ROLE's ("the temporary security credentials … have the
/// permissions of the role", `AssumeRole`), capped by whatever the mint scoped the
/// credential down to, so an authorization decision taken on a request signed with it has
/// to reach the role the session is of and the scope it was minted with. The session itself
/// belongs to STS, which is why only the three facts an IAM decision needs are recorded
/// here — the principal the refusal names, the role whose policies it is judged on, and the
/// session policies that cap them — written by the operation that mints the session.
#[derive(Debug, Clone)]
pub struct RoleSessionRecord {
    /// The session's own principal, as `sts:AssumeRole` reports it:
    /// `arn:<partition>:sts::<account>:assumed-role/<role name>/<session name>`. What a
    /// refusal names as the caller, and what a policy variable over the caller reads.
    pub session_arn: String,
    /// The ARN of the IAM role the session is of — the identity whose policies the call
    /// is judged on, addressed by the ARN the account holds the role under.
    pub role_arn: String,
    /// The instant the credential stops being usable, as the minting operation promised
    /// it. A record past it speaks for nobody: the credential is withdrawn at that
    /// instant, and the record is kept only until this store next prunes it.
    pub expires: ::aws_smithy_types::DateTime,
    /// The session policies the mint passed, which SCOPE what a request signed with this
    /// credential may do; see [`SessionPolicies`]. Empty for a mint that passed none,
    /// which is a session no document scopes.
    pub scope: SessionPolicies,
}

/// The session policies ONE mint of a temporary credential passed, which scope the
/// session's permissions down.
///
/// "The resulting session's permissions are the intersection of the role's identity-based
/// policy and the session policies… You cannot use session policies to grant more
/// permissions than those allowed by the identity-based policy of the role that is being
/// assumed" (`AssumeRoleRequest$PolicyArns`, the STS model): what a request signed with the
/// credential may do is what the identity's own policies allow AND what these documents
/// allow, and an explicit `Deny` in any of them refuses whatever a grant says. A managed
/// session policy named by ARN narrows exactly as an inline document does.
///
/// They live beside the role-session record ([`RoleSessionRecord::scope`]) because the
/// credential is the only thing a later request carries, and this store is what the service
/// deciding that request reads the principal out of. The inline document is held exactly as
/// the mint passed it; a managed session policy is held by ARN instead, because what it says
/// is what its DEFAULT version says at the instant of the request, which is read then
/// ([`session_scoping_documents`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionPolicies {
    /// The inline session policy document the mint passed, if any.
    pub inline: Option<String>,
    /// The managed session policies the mint named, by ARN, in the order it named them.
    pub managed_arns: Vec<String>,
}

/// The session policy DOCUMENTS in force on a credential, read for one request.
#[derive(Debug, Clone, Default)]
pub struct ScopingPolicies {
    /// Every scoping document that could be read, in the order the mint named them.
    pub documents: Vec<String>,
    /// Set when the mint named a managed session policy whose document this emulator does
    /// not hold — an entry of AWS's catalog it does not carry — so the scope may allow
    /// more than [`Self::documents`] shows.
    pub unreadable: bool,
}

impl ScopingPolicies {
    /// What this scope says about one request.
    ///
    /// A session policy CAPS what the identity's own documents grant and grants nothing of
    /// its own: "the resulting session's permissions are the intersection of the role's
    /// identity-based policy and the session policies" (`AssumeRoleRequest$PolicyArns`, the
    /// STS model), and "you cannot use session policies to grant more permissions than
    /// those allowed by the identity-based policy of the role that is being assumed". So
    /// the answer is read exactly as a permissions boundary's is by the gate that asks:
    /// an explicit `Deny` refuses whatever any grant says, a call this does not allow is
    /// refused even where the identity's documents allow it, and a call only this allows is
    /// refused as if it had allowed nothing.
    ///
    /// A credential NO mint scoped — every long-term access key, and every session minted
    /// without session policies — is capped by nothing, which is the position of a scope
    /// that allows the call. A credential scoped by a managed session policy whose document
    /// this emulator does not hold ([`Self::unreadable`]) is in that same position:
    /// refusing on evidence it does not have would deny access AWS permits, while a `Deny`
    /// in a document it CAN read still refuses.
    ///
    /// The ONE reading of a resolved scope, so this service's gate and every other service
    /// that decides a request signed with such a credential cannot cap one differently.
    #[must_use]
    pub fn decision(
        &self,
        request: &::service_common::iam_authorization::Request<'_>,
    ) -> ::service_common::iam_authorization::Decision {
        use ::service_common::iam_authorization::{identity_decision, Decision};

        let stated = identity_decision(&self.documents, request);
        if stated != Decision::Denied && (self.documents.is_empty() || self.unreadable) {
            return Decision::Allowed;
        }
        stated
    }
}

/// The documents the session policies `policies` stand for, as they read at the instant of
/// the request: the inline document the mint passed, and the version of each managed
/// session policy that is in force now ([`ComAmazonawsIamAwsidentitymanagementv20100508State::default_version_document`]).
///
/// The ONE resolution of "what scopes this session down", so this service's own gate and
/// every other service that decides a request signed with such a credential read the same
/// documents. `store` is the account's IAM records, or `None` where there are none to read —
/// in which case every managed session policy is unreadable, while the inline document the
/// mint passed scopes the session whether or not a store is there.
#[must_use]
pub fn session_scoping_documents(
    store: Option<&ComAmazonawsIamAwsidentitymanagementv20100508State>,
    policies: &SessionPolicies,
) -> ScopingPolicies {
    let mut documents: Vec<String> = policies.inline.iter().cloned().collect();
    let mut unreadable = false;
    for policy_arn in &policies.managed_arns {
        match store.and_then(|store| store.default_version_document(policy_arn)) {
            Some(document) => documents.push(document),
            None => unreadable = true,
        }
    }
    ScopingPolicies {
        documents,
        unreadable,
    }
}

/// One X.509 signing certificate an IAM user holds, keyed in
/// [`ComAmazonawsIamAwsidentitymanagementv20100508State::signing_certificates`] by its
/// `CertificateId` — the handle every other operation on one takes
/// (`UpdateSigningCertificate` and `DeleteSigningCertificate` name the certificate by
/// id, and `ListSigningCertificates` reports it).
///
/// The owning user's NAME is not copied in: it is read from the user the record's
/// [`user_key`](SigningCertificateRecord::user_key) names, so the name lives in
/// exactly one place and a user renamed by an update does not leave a stale copy here.
#[derive(Debug, Clone)]
pub struct SigningCertificateRecord {
    /// [`name_key`] of the IAM user that holds the certificate.
    pub user_key: String,
    /// "The contents of the signing certificate"
    /// (`SigningCertificate$CertificateBody`), verbatim as the upload carried it.
    pub certificate_body: String,
    /// The DER encoding the body decodes to: what tells one certificate from another,
    /// independently of the whitespace that framed it.
    ///
    /// Kept beside the body so recognising a repeat upload costs one comparison per held
    /// certificate instead of re-reading every held body. It is DERIVED from
    /// [`certificate_body`](Self::certificate_body) and reported by nothing: no modelled
    /// member carries it.
    pub certificate_der: Vec<u8>,
    /// The certificate's `statusType` value: [`CREDENTIAL_STATUS_ACTIVE`] when it was
    /// uploaded ("when you upload the certificate, its default status is Active",
    /// `UploadSigningCertificate`), until an update moves it.
    pub status: String,
    /// "The date when the signing certificate was uploaded"
    /// (`SigningCertificate$UploadDate`), reported unchanged by every later read.
    pub upload_date: ::aws_smithy_types::DateTime,
}

impl SigningCertificateRecord {
    /// This record as the one modelled shape every operation reports a signing
    /// certificate through, under the id it is keyed by and the user name as the
    /// account holds it.
    ///
    /// ONE place builds the shape, so the upload response and every later list report
    /// the same certificate identically.
    pub fn report(&self, certificate_id: &str, user_name: &str) -> SigningCertificate {
        SigningCertificate {
            user_name: user_name.to_string(),
            certificate_id: certificate_id.to_string(),
            certificate_body: self.certificate_body.clone(),
            status: self.status.clone(),
            upload_date: Some(self.upload_date),
        }
    }
}

/// One IAM OpenID Connect (OIDC) identity provider the account holds, keyed in
/// [`ComAmazonawsIamAwsidentitymanagementv20100508State::open_id_connect_providers`]
/// by its ARN — the handle every other operation on one takes
/// (`GetOpenIDConnectProvider`, `DeleteOpenIDConnectProvider` and
/// `AddClientIDToOpenIDConnectProvider` all name the provider by ARN, and
/// `ListOpenIDConnectProviders` reports nothing else about it).
///
/// The ARN is DERIVED from the URL ([`open_id_connect_provider_arn`]), so keying by
/// it is also what makes a provider's URL its identity: "you cannot register the same
/// provider multiple times in a single Amazon Web Services account"
/// (`CreateOpenIDConnectProvider$Url`).
///
/// No modelled shape carries a whole provider — `OpenIDConnectProviderListEntry`
/// holds only the ARN (`smithy_query(query="shape",
/// shape="OpenIDConnectProviderListEntry")`) — so the record holds the members
/// `GetOpenIDConnectProvider` reports, and that read is what defines them.
#[derive(Debug, Clone)]
pub struct OpenIdConnectProviderRecord {
    /// "The URL that the IAM OIDC provider resource object is associated with"
    /// (`GetOpenIDConnectProvider$Url`), WITHOUT its scheme: the host-and-path form
    /// the provider's ARN is built from, which is also the issuer form a client
    /// compares an OIDC token's `iss` claim against.
    pub url: String,
    /// "A list of client IDs (also known as audiences) that are associated with the
    /// specified IAM OIDC provider resource object"
    /// (`GetOpenIDConnectProvider$ClientIDList`), in the order they were registered.
    /// At most [`MAX_CLIENT_IDS_PER_OPEN_ID_CONNECT_PROVIDER`] of them.
    pub client_id_list: Vec<String>,
    /// "A list of certificate thumbprints that are associated with the specified IAM
    /// OIDC provider resource object" (`GetOpenIDConnectProvider$ThumbprintList`), in
    /// the order they were supplied. At most
    /// [`MAX_THUMBPRINTS_PER_OPEN_ID_CONNECT_PROVIDER`] of them, and empty when the
    /// create named none.
    pub thumbprint_list: Vec<String>,
    /// "The date and time when the IAM OIDC provider resource object was created in
    /// the Amazon Web Services account" (`GetOpenIDConnectProvider$CreateDate`):
    /// minted once and reported unchanged by every later read.
    pub create_date: ::aws_smithy_types::DateTime,
    /// The provider's tags, sorted by tag key, because "the returned list of tags is
    /// sorted by tag key" (`GetOpenIDConnectProvider$Tags`). `None` when the provider
    /// carries none, so the member is reported only when there is a tag to report.
    pub tags: Option<Vec<Tag>>,
}

/// One IAM SAML 2.0 identity provider the account holds, keyed in
/// [`ComAmazonawsIamAwsidentitymanagementv20100508State::saml_providers`] by its ARN —
/// the handle every other operation on one takes (`GetSAMLProvider`,
/// `UpdateSAMLProvider`, `DeleteSAMLProvider` and the tag calls all name the provider
/// by ARN).
///
/// The ARN is DERIVED from the provider's name ([`saml_provider_arn`]), so keying by it
/// is also what makes the name the provider's identity and refuses a second create for
/// a name the account already holds.
///
/// No modelled shape carries a whole provider — `SAMLProviderListEntry` holds the ARN
/// and its two instants (`smithy_query(query="shape",
/// shape="SAMLProviderListEntry")`) — so the record holds the members
/// `GetSAMLProvider` reports, and that read is what defines them.
///
/// The uploaded PRIVATE KEY MATERIAL is deliberately not among them: `SAMLPrivateKey`
/// reports only a key id and the instant the key was uploaded
/// (`smithy_query(query="shape", shape="SAMLPrivateKey")`), the model marks
/// `CreateSAMLProvider$AddPrivateKey` sensitive, and no operation here decrypts an
/// assertion or checks a key against one presented later, so nothing reads the key
/// material at all.
#[derive(Debug, Clone)]
pub struct SamlProviderRecord {
    /// "The unique identifier assigned to the SAML provider"
    /// (`GetSAMLProvider$SAMLProviderUUID`): minted once by
    /// [`next_saml_provider_uuid`](ComAmazonawsIamAwsidentitymanagementv20100508State::next_saml_provider_uuid)
    /// and reported unchanged by every later read.
    pub provider_uuid: String,
    /// "The XML metadata document that includes information about an identity
    /// provider" (`GetSAMLProvider$SAMLMetadataDocument`), held exactly as the request
    /// supplied it so the read hands back the same bytes.
    pub metadata_document: String,
    /// "The date and time when the SAML provider was created"
    /// (`GetSAMLProvider$CreateDate`): minted once and reported unchanged by every
    /// later read.
    pub create_date: ::aws_smithy_types::DateTime,
    /// "The expiration date and time for the SAML provider"
    /// (`GetSAMLProvider$ValidUntil`) — the `validUntil` of the metadata document
    /// ([`parse_saml_metadata`]), so it is a property of the document the request
    /// carried. `None` when the document states no expiration.
    pub valid_until: Option<::aws_smithy_types::DateTime>,
    /// "The encryption setting for the SAML provider"
    /// (`GetSAMLProvider$AssertionEncryptionMode`), one value of
    /// `assertionEncryptionModeType`. `None` when no call has set one: the model
    /// declares no default for the member, so nothing is reported until a request
    /// chooses a value.
    pub assertion_encryption_mode: Option<String>,
    /// "The private key metadata for the SAML provider"
    /// (`GetSAMLProvider$PrivateKeyList`), in the order the keys were uploaded. At most
    /// [`MAX_PRIVATE_KEYS_PER_SAML_PROVIDER`] of them, the maximum `privateKeyList`
    /// declares (len 0..2, `smithy_query(query="shape", shape="privateKeyList")`), and
    /// empty when no call uploaded one.
    pub private_keys: Vec<SAMLPrivateKey>,
    /// The provider's tags, sorted by tag key, because "the returned list of tags is
    /// sorted by tag key" (`GetSAMLProvider$Tags`). `None` when the provider carries
    /// none, so the member is reported only when there is a tag to report.
    pub tags: Option<Vec<Tag>>,
}

/// How many bytes of salt a held password verifier carries, so two users that chose
/// the same password are not held under the same digest. Sixteen bytes is the width
/// of the two mixed counter words [`PasswordVerifier::new`] draws it from.
const PASSWORD_SALT_BYTES: usize = 16;

/// How many bytes a verifier's digest is: the output width of the SHA-256 the salt
/// and the password are hashed with.
const PASSWORD_DIGEST_BYTES: usize = 32;

/// A console password as the account HOLDS it: a salt and the digest of that salt and
/// the password, never the password.
///
/// A verifier exists because one operation has to ASK about a password the account
/// accepted earlier — `ChangePassword` "changes the password of the IAM user who is
/// calling this operation" and takes that user's "current password"
/// (`ChangePassword$OldPassword`), so the account must be able to answer whether a
/// password a later request presents is the one it already accepted. This answers
/// exactly that question ([`Self::verifies`]) and no other: the password cannot be
/// read back out of a digest, no modelled shape carries one (`LoginProfile` reports
/// only `UserName`, `CreateDate` and `PasswordResetRequired`), and the model marks
/// every password member sensitive, so nothing may ever hand one out.
///
/// It is an equality oracle for one in-memory account and nothing more: the salt is
/// drawn from a counter rather than from entropy, and the digest is a single hash pass
/// rather than a password-stretching function, because no store here outlives the
/// process and no caller can read either value. Nobody should read it as a scheme for
/// storing credentials.
#[derive(Clone)]
pub struct PasswordVerifier {
    /// The salt this password was hashed with, minted once with the verifier.
    salt: [u8; PASSWORD_SALT_BYTES],
    /// SHA-256 of the salt followed by the password's bytes.
    digest: [u8; PASSWORD_DIGEST_BYTES],
}

/// What a verifier shows when the account's state is formatted: that a password is
/// held, and nothing of the material it was derived from. Written out rather than
/// derived, so no formatter of the state a verifier lives in can print the salt or the
/// digest.
impl ::std::fmt::Debug for PasswordVerifier {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        f.write_str("PasswordVerifier")
    }
}

impl PasswordVerifier {
    /// The verifier for `password`, salted from `salt_seq` — a value a caller draws
    /// from [`ComAmazonawsIamAwsidentitymanagementv20100508State::hold_password`], so
    /// each held password gets its own salt.
    pub fn new(salt_seq: u64, password: &str) -> Self {
        let mut salt = [0u8; PASSWORD_SALT_BYTES];
        for (word, bytes) in salt.chunks_mut(::std::mem::size_of::<u64>()).enumerate() {
            let mixed = splitmix64(salt_seq ^ (word as u64).rotate_left(32)).to_be_bytes();
            // Byte by byte, so the chunk and the word agreeing in length is a property
            // of the loop rather than a condition that could fault.
            for (byte, mixed) in bytes.iter_mut().zip(mixed) {
                *byte = mixed;
            }
        }
        let digest = Self::digest(&salt, password);
        Self { salt, digest }
    }

    /// Whether `password` is the password this verifier was built from.
    ///
    /// The comparison folds every byte before answering, so it takes the same work
    /// however many leading bytes happen to agree.
    pub fn verifies(&self, password: &str) -> bool {
        let candidate = Self::digest(&self.salt, password);
        candidate
            .iter()
            .zip(self.digest.iter())
            .fold(0u8, |differing, (left, right)| differing | (left ^ right))
            == 0
    }

    /// SHA-256 of `salt` followed by `password`.
    fn digest(salt: &[u8; PASSWORD_SALT_BYTES], password: &str) -> [u8; PASSWORD_DIGEST_BYTES] {
        let mut hasher = <::sha2::Sha256 as ::sha2::Digest>::new();
        ::sha2::Digest::update(&mut hasher, salt);
        ::sha2::Digest::update(&mut hasher, password.as_bytes());
        let hashed = ::sha2::Digest::finalize(hasher);
        let mut digest = [0u8; PASSWORD_DIGEST_BYTES];
        // Byte by byte rather than a slice copy, so the lengths agreeing is a property
        // of the loop and not a condition that could fault.
        for (byte, hashed) in digest.iter_mut().zip(hashed) {
            *byte = hashed;
        }
        digest
    }
}

/// One IAM user's login profile: the console password `CreateLoginProfile`
/// created, as the account holds it.
///
/// The password is held as a [`PasswordVerifier`] and never as itself: the only
/// thing any operation asks of it is whether a password presented later is the one
/// the account accepted, which a verifier answers without keeping the secret. No
/// shape reports it — `LoginProfile` (the only shape any operation reports a login
/// profile through) carries just `UserName`, `CreateDate` and
/// `PasswordResetRequired` (`smithy_query(query="shape", shape="LoginProfile")`) —
/// and the model marks `CreateLoginProfile$Password` sensitive. The owning user's
/// NAME is not copied in either, for the same reason [`AccessKeyRecord`] does not
/// copy it — it is read from the user the record's key names, so the name lives in
/// one place.
#[derive(Debug, Clone)]
pub struct LoginProfileRecord {
    /// The instant the password was created, reported unchanged by every later
    /// read: "the CreateDate reflects the initial password creation date"
    /// (`GetLoginProfile`).
    pub create_date: ::aws_smithy_types::DateTime,
    /// Whether "the user is required to set a new password on next sign-in"
    /// (`CreateLoginProfile$PasswordResetRequired`), as the last write left it.
    pub password_reset_required: bool,
    /// The verifier of the password in force: the one the create set, or the one a
    /// later `UpdateLoginProfile` or `ChangePassword` replaced it with.
    pub password: PasswordVerifier,
}

/// The account's password policy, as `UpdateAccountPasswordPolicy` wrote it.
///
/// One record per account, because the policy IS the account's own configuration:
/// "updates the password policy settings for the Amazon Web Services account", and the
/// operation "does not support partial updates … if you do not specify a parameter, that
/// parameter's value reverts to its default value", so a write REPLACES the whole record
/// rather than merging into it.
///
/// Every member is held as the account holds it, not as the request spelled it: the
/// request's optional integers already carry the defaults the operation documents
/// ([`Self::from_request`]), so the stored record answers every rule directly and nothing
/// reading it has to re-apply a default.
///
/// Every member the write carries is held, not only the ones a password check reads: the
/// policy is what the account CONFIGURED, and the operation that reports it back —
/// `GetAccountPasswordPolicy` (`crate::ops::get_account_password_policy`) — reports all of
/// them, so the members about expiry, reuse and self-service are stored for that reader
/// rather than dropped on the floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPasswordPolicy {
    /// "The minimum number of characters allowed in an IAM user password"; the default
    /// `6` when the write named none.
    pub minimum_password_length: i32,
    /// Whether a password "must contain at least one of the following symbols: ! @ # $ %
    /// ^ & * ( ) _ + - = [ ] { } | '" (`PasswordPolicy$RequireSymbols`).
    pub require_symbols: bool,
    /// Whether a password "must contain at least one numeric character (0 to 9)"
    /// (`PasswordPolicy$RequireNumbers`).
    pub require_numbers: bool,
    /// Whether a password "must contain at least one uppercase character (A to Z)"
    /// (`PasswordPolicy$RequireUppercaseCharacters`).
    pub require_uppercase_characters: bool,
    /// Whether a password "must contain at least one lowercase character (a to z)"
    /// (`PasswordPolicy$RequireLowercaseCharacters`).
    pub require_lowercase_characters: bool,
    /// Whether IAM users "are allowed to change their own password"
    /// (`PasswordPolicy$AllowUsersToChangePassword`).
    pub allow_users_to_change_password: bool,
    /// "The number of days that an IAM user password is valid", or `None` for the
    /// documented default under which "IAM user passwords never expire".
    pub max_password_age: Option<i32>,
    /// "The number of previous passwords that IAM users are prevented from reusing", or
    /// `None` for the documented default under which users "are not prevented from
    /// reusing previous passwords".
    pub password_reuse_prevention: Option<i32>,
    /// Whether IAM users are "prevented from setting a new password via the
    /// Amazon Web Services Management Console after their password has expired"
    /// (`PasswordPolicy$HardExpiry`), or `None` when the write named no value, which the
    /// operation documents as `false`.
    pub hard_expiry: Option<bool>,
}

/// The `MinimumPasswordLength` an account's policy holds when a write named none: "if you
/// do not specify a value for this parameter, then the operation uses the default value of
/// `6`" (`UpdateAccountPasswordPolicy$MinimumPasswordLength`), which is also
/// `minimumPasswordLengthType`'s own published minimum.
pub const DEFAULT_MINIMUM_PASSWORD_LENGTH: i32 = 6;

/// The symbols a password satisfies `RequireSymbols` by carrying one of, as a set to test
/// a character against: the characters `PasswordPolicy$RequireSymbols` itself lists.
const PASSWORD_POLICY_SYMBOLS: &str = "!@#$%^&*()_+-=[]{}|'";

/// The same set as the refusal SPELLS it — "! @ # $ % ^ & * ( ) _ + - = [ ] { } | '",
/// space-separated, exactly as `PasswordPolicy$RequireSymbols` writes it out. Held beside
/// [`PASSWORD_POLICY_SYMBOLS`] rather than rendered from it so the sentence is the
/// documented one character for character; `tests/all/account_password_policy.rs` drives a
/// password carrying each of these symbols and one carrying none, so the two cannot drift
/// apart unnoticed.
const PASSWORD_POLICY_SYMBOL_LIST: &str = "! @ # $ % ^ & * ( ) _ + - = [ ] { } | '";

impl AccountPasswordPolicy {
    /// The policy an `UpdateAccountPasswordPolicy` request sets, with every member the
    /// request omitted at the default that operation documents for it — the write "does
    /// not support partial updates", so what is not named is not kept but reset.
    pub fn from_request(request: &UpdateAccountPasswordPolicyInput) -> Self {
        Self {
            minimum_password_length: request
                .minimum_password_length
                .unwrap_or(DEFAULT_MINIMUM_PASSWORD_LENGTH),
            require_symbols: request.require_symbols,
            require_numbers: request.require_numbers,
            require_uppercase_characters: request.require_uppercase_characters,
            require_lowercase_characters: request.require_lowercase_characters,
            allow_users_to_change_password: request.allow_users_to_change_password,
            max_password_age: request.max_password_age,
            password_reuse_prevention: request.password_reuse_prevention,
            hard_expiry: request.hard_expiry,
        }
    }

    /// Which rule of this policy `password` breaks, worded as AWS words that refusal, or
    /// `None` when the policy admits it.
    ///
    /// Only the rules about the SUPPLIED PASSWORD's content are decided here, because they
    /// are the only ones a password-setting call can break: the length and the four
    /// character classes. `MaxPasswordAge` and `HardExpiry` govern a password already in
    /// force rather than one being set, `AllowUsersToChangePassword` grants a permission,
    /// and `PasswordReusePrevention` is a rule about passwords the account no longer holds
    /// — this store keeps the verifier of the password IN FORCE and of no superseded one
    /// ([`LoginProfileRecord::password`]), so there is nothing to compare a new password
    /// against.
    ///
    /// The rules are taken in the order `PasswordPolicy` declares them, so a password
    /// breaking several is refused by the first of them and one call cannot answer two
    /// sentences for one password.
    pub fn violation(&self, password: &str) -> Option<String> {
        // "Minimum length to require for IAM user passwords"
        // (`PasswordPolicy$MinimumPasswordLength`), counted in characters, the unit
        // `passwordType`'s own length bound is taken in. The minimum is a
        // `minimumPasswordLengthType` (range 6..128), so it is never below the documented
        // default; the floor is taken ONCE and both the check and the sentence read that
        // same value, so the rule enforced and the rule reported cannot differ.
        let minimum = self
            .minimum_password_length
            .max(DEFAULT_MINIMUM_PASSWORD_LENGTH);
        if password.chars().count() < usize::try_from(minimum).unwrap_or(0) {
            return Some(format!("Password should have a minimum length of {minimum}"));
        }
        if self.require_symbols
            && !password
                .chars()
                .any(|character| PASSWORD_POLICY_SYMBOLS.contains(character))
        {
            return Some(format!(
                "Password should have at least one of the following symbols: \
                 {PASSWORD_POLICY_SYMBOL_LIST}"
            ));
        }
        if self.require_numbers && !password.chars().any(|character| character.is_ascii_digit()) {
            return Some("Password should have at least one numeric character (0 to 9)".to_string());
        }
        if self.require_uppercase_characters
            && !password
                .chars()
                .any(|character| character.is_ascii_uppercase())
        {
            return Some(
                "Password should have at least one uppercase character (A to Z)".to_string(),
            );
        }
        if self.require_lowercase_characters
            && !password
                .chars()
                .any(|character| character.is_ascii_lowercase())
        {
            return Some(
                "Password should have at least one lowercase character (a to z)".to_string(),
            );
        }
        None
    }
}

// The account's own state struct, the records it holds and the reads and writes over them
// live in `state/account.rs`.

// The reads and writes the account makes over its own holdings live in
// `state/account.rs`.

/// What a set of inline policies takes up: the size the policy-size quota is
/// measured against, and the raw text the store retains for it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InlinePolicySize {
    /// Non-whitespace characters, the measure IAM's policy-size quotas are taken
    /// against ([`policy_document_characters`]).
    pub measured: usize,
    /// Raw characters, whitespace included: what the store holds, bounded by
    /// [`MAX_INLINE_POLICY_TEXT_CHARACTERS`].
    pub retained: usize,
}

/// What the inline policies `policies` holds for the entity keyed by `entity_key`
/// take up, counting every policy except the one keyed by `replacing`.
///
/// A put of an existing policy name REPLACES that document rather than adding to
/// it, so the document being replaced counts toward neither sum the new one has to
/// fit inside. One definition, shared by every entity kind that embeds inline
/// policies.
fn inline_policy_size(
    policies: &BTreeMap<String, BTreeMap<String, InlinePolicy>>,
    entity_key: &str,
    replacing: &str,
) -> InlinePolicySize {
    let mut size = InlinePolicySize::default();
    let Some(policies) = policies.get(entity_key) else {
        return size;
    };
    for (_, policy) in policies.iter().filter(|(key, _)| key.as_str() != replacing) {
        size.measured += policy_document_characters(&policy.policy_document);
        size.retained += policy.policy_document.chars().count();
    }
    size
}

/// The case-folded form of an IAM entity name, used as its key.
///
/// IAM entity names "are not distinguished by case", so `MyUser` and `myuser`
/// name one entity. Entity names are constrained to `^[\w+=,.@-]+$`, so ASCII
/// folding is total over the accepted alphabet.
pub fn name_key(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// The ARN of an IAM user: `arn:aws:iam::<account>:user<path><name>`.
///
/// `path` already begins and ends with `/` (the model's `pathType` pattern), so
/// it joins the `user` resource type to the name without extra separators. IAM is
/// a global service, so the region segment is empty.
pub fn user_arn(path: &str, user_name: &str) -> String {
    ::engine::emulator_arn("iam", "", &format!("user{path}{user_name}"))
}

/// The ARN of an IAM managed policy: `arn:aws:iam::<account>:policy<path><name>`.
///
/// Built the same way [`user_arn`] is, from the `policy` resource type.
pub fn policy_arn(path: &str, policy_name: &str) -> String {
    ::engine::emulator_arn("iam", "", &format!("policy{path}{policy_name}"))
}

/// The ARN of an IAM group: `arn:aws:iam::<account>:group<path><name>`.
///
/// Built the same way [`user_arn`] is, from the `group` resource type: `path`
/// already begins and ends with `/`, and IAM is a global service, so the region
/// segment is empty.
pub fn group_arn(path: &str, group_name: &str) -> String {
    ::engine::emulator_arn("iam", "", &format!("group{path}{group_name}"))
}

/// The ARN of an IAM role: `arn:aws:iam::<account>:role<path><name>`.
///
/// Built the same way [`user_arn`] is, from the `role` resource type: `path`
/// already begins and ends with `/`, and IAM is a global service, so the region
/// segment is empty.
pub fn role_arn(path: &str, role_name: &str) -> String {
    ::engine::emulator_arn("iam", "", &format!("role{path}{role_name}"))
}

/// The ARN of an IAM OIDC identity provider:
/// `arn:aws:iam::<account>:oidc-provider/<url without its scheme>`.
///
/// The provider is named by its URL, so its ARN is derived from that URL with the
/// `https://` scheme ([`OPEN_ID_CONNECT_URL_SCHEME`]) removed — which is what makes
/// two creates for one URL two creates for one provider. IAM is a global service, so
/// the region segment is empty, exactly as it is for [`user_arn`].
pub fn open_id_connect_provider_arn(url: &str) -> String {
    let host_and_path = url.strip_prefix(OPEN_ID_CONNECT_URL_SCHEME).unwrap_or(url);
    ::engine::emulator_arn("iam", "", &format!("oidc-provider/{host_and_path}"))
}

/// The ARN of an IAM SAML 2.0 identity provider:
/// `arn:aws:iam::<account>:saml-provider/<name>`.
///
/// The provider is named by its `Name`, so its ARN is derived from that name — which is
/// what makes two creates for one name two creates for one provider, and what lets
/// `AssumeRoleWithSAML`'s `PrincipalArn` ("the ARN of the SAML provider in IAM") name
/// the provider a role's trust policy trusts. IAM is a global service, so the region
/// segment is empty, exactly as it is for [`user_arn`].
pub fn saml_provider_arn(name: &str) -> String {
    ::engine::emulator_arn("iam", "", &format!("saml-provider/{name}"))
}

/// The ARN of an IAM instance profile:
/// `arn:aws:iam::<account>:instance-profile<path><name>`.
///
/// Built the same way [`user_arn`] is, from the `instance-profile` resource type.
pub fn instance_profile_arn(path: &str, instance_profile_name: &str) -> String {
    ::engine::emulator_arn(
        "iam",
        "",
        &format!("instance-profile{path}{instance_profile_name}"),
    )
}

/// The ARN of an IAM server certificate:
/// `arn:aws:iam::<account>:server-certificate<path><name>`.
///
/// Built the same way [`user_arn`] is, from the `server-certificate` resource type:
/// `path` already begins and ends with `/` (the model's `pathType` pattern), and IAM is a
/// global service, so the region segment is empty.
pub fn server_certificate_arn(path: &str, server_certificate_name: &str) -> String {
    ::engine::emulator_arn(
        "iam",
        "",
        &format!("server-certificate{path}{server_certificate_name}"),
    )
}

/// The wall-clock instant a resource was created or last changed, in the
/// modelled timestamp type.
pub fn now() -> ::aws_smithy_types::DateTime {
    let since_epoch = ::std::time::SystemTime::now()
        .duration_since(::std::time::UNIX_EPOCH)
        .unwrap_or_default();
    ::aws_smithy_types::DateTime::from_millis(since_epoch.as_millis() as i64)
}

/// Whether `path` is the path of a service-linked role — see
/// [`SERVICE_LINKED_ROLE_PATH_PREFIX`].
pub fn is_service_linked_role_path(path: &str) -> bool {
    path.starts_with(SERVICE_LINKED_ROLE_PATH_PREFIX)
}

/// The service principal a role at `path` is linked to, or `None` when `path` is not a
/// service-linked role's path at all.
///
/// The inverse of [`service_linked_role_path`]: that function files the role under
/// [`SERVICE_LINKED_ROLE_PATH_PREFIX`] followed by the principal, so the principal is
/// what sits between the prefix and the trailing separator. A path that carries no
/// principal there is linked to no service, which is why this answers an `Option`:
/// [`is_service_linked_role_path`] alone says only that the path starts in the reserved
/// prefix.
pub fn service_linked_role_principal(path: &str) -> Option<&str> {
    let service_principal = path
        .strip_prefix(SERVICE_LINKED_ROLE_PATH_PREFIX)?
        .trim_end_matches('/');
    (!service_principal.is_empty()).then_some(service_principal)
}

/// The one sentence this service states a refused change to a PROTECTED role with — a
/// role a service links itself to, which "only the service that depends on the
/// service-linked role can modify or delete … on your behalf"
/// (`UnmodifiableEntityException`).
///
/// Every word of it is fixed but the role the request named, which is quoted exactly as
/// the request spelled it. The protection is one rule about one kind of role, so every
/// operation that refuses such a change states it through here rather than wording its
/// own sentence: the sentence does not name which operation was refused, nor the service
/// the role is linked to, so there is nothing per-operation to word. It is read back by
/// `tests/all/protected_role_refusals.rs` across the operations the protection covers.
pub fn protected_role_message(role_name: &str) -> String {
    format!(
        "Cannot perform the operation on the protected role '{role_name}' - this role is \
         only modifiable by AWS"
    )
}

/// What every service-linked role name starts with. AWS's "Using service-linked
/// roles" guidance, echoed by `CreateServiceLinkedRole$CustomSuffix`'s
/// documentation ("a string that you provide, which is combined with the
/// service-provided prefix to form the complete role name"), is that the role a
/// service links to itself is named for the service behind this prefix.
pub const SERVICE_LINKED_ROLE_NAME_PREFIX: &str = "AWSServiceRoleFor";

/// The IAM policy language version a generated trust policy declares. It is the
/// current version of the policy grammar IAM documents, and the one AWS emits in
/// the trust policy of a role it creates.
pub const POLICY_LANGUAGE_VERSION: &str = "2012-10-17";

/// The role name AWS PUBLISHES for a service principal's service-linked role.
///
/// The service-provided prefix is [`SERVICE_LINKED_ROLE_NAME_PREFIX`] followed by
/// the service's own AWS-assigned label, and that label is NOT the first label of
/// the principal and is not derivable from it: `ssm-sap.amazonaws.com` links
/// `AWSServiceRoleForAWSSSMForSAP`, `migrationhub-strategy.amazonaws.com` links
/// `AWSServiceRoleForMigrationHubStrategy`, `ops.apigateway.amazonaws.com` links
/// `AWSServiceRoleForAPIGateway`, `replication.cassandra.amazonaws.com` links
/// `AWSServiceRoleForKeyspacesReplication`, and each Application Auto Scaling
/// principal links a name suffixed with the resource type it scales. No part of the
/// IAM model carries that label — `CreateServiceLinkedRole$CustomSuffix`'s
/// documentation only says a suffix "is combined with the service-provided prefix to
/// form the complete role name" — so the published names are listed here, and a
/// principal this list does not name falls back to the name
/// `CreateServiceLinkedRole` derives.
///
/// This is also the catalog of the roles the OWNING SERVICE keeps provisioned in
/// the account ([`service_provisioned_role`]), which is why it lives beside the
/// state rather than in one handler: the create and the read resolve one table.
///
/// Source: the "Using service-linked roles for <service>" page of each service's own
/// user guide, which names the role that service creates; AWS's "Amazon Web Services
/// services that work with IAM" table links them all. Rows marked `[model]` are
/// additionally corroborated by the documentation a Smithy model in THIS repository
/// carries, quoted in the named handler.
///
/// Sorted by principal, which is also the lookup key
/// ([`published_service_linked_role_name`]).
pub const PUBLISHED_SERVICE_LINKED_ROLE_NAMES: &[(&str, &str)] = &[
    ("access-analyzer.amazonaws.com", "AWSServiceRoleForAccessAnalyzer"),
    // [model] service-com-amazonaws-applicationsignals-applicationsignals
    // `src/ops/start_discovery.rs`: "creating the
    // AWSServiceRoleForCloudWatchApplicationSignals service-linked role".
    (
        "application-signals.amazonaws.com",
        "AWSServiceRoleForCloudWatchApplicationSignals",
    ),
    // [model] service-com-amazonaws-autoscaling-autoscaling-2011-01-01
    // `src/ops/create_auto_scaling_group.rs`: "service-linked role named
    // AWSServiceRoleForAutoScaling".
    ("autoscaling.amazonaws.com", "AWSServiceRoleForAutoScaling"),
    ("backup.amazonaws.com", "AWSServiceRoleForBackup"),
    // [model] service-com-amazonaws-batch-awsbatchv20160810
    // `src/ops/update_compute_environment.rs`: "the AWSServiceRoleForBatch
    // service-linked role".
    ("batch.amazonaws.com", "AWSServiceRoleForBatch"),
    ("cloudtrail.amazonaws.com", "AWSServiceRoleForCloudTrail"),
    // AWS CodeStar Notifications' own "Using service-linked roles for AWS CodeStar
    // Notifications" page names the role it creates to publish notifications to a
    // rule's targets: AWSServiceRoleForCodeStarNotifications, for the principal
    // codestar-notifications.amazonaws.com. Without the row the derived fallback name
    // is not the one AWS publishes, so a client that creates the role and then reads
    // it back under the published name never converges.
    (
        "codestar-notifications.amazonaws.com",
        "AWSServiceRoleForCodeStarNotifications",
    ),
    // AWS Compute Optimizer: the hyphen of the principal's label is not in the role
    // AWS names in "Using service-linked roles for AWS Compute Optimizer",
    // AWSServiceRoleForComputeOptimizer.
    ("compute-optimizer.amazonaws.com", "AWSServiceRoleForComputeOptimizer"),
    // [model] service-com-amazonaws-configservice-starlingdoveservice
    // `src/ops/put_service_linked_configuration_recorder.rs`: "creates a
    // service-linked role AWSServiceRoleForConfig in your account".
    ("config.amazonaws.com", "AWSServiceRoleForConfig"),
    // Application Auto Scaling publishes one role per scaled service, named
    // `AWSServiceRoleForApplicationAutoScaling_<resource type>` — the suffixes this
    // repository already lists in
    // service-com-amazonaws-applicationautoscaling-anyscalefrontendservice
    // `src/state.rs` (`SERVICE_LINKED_ROLE_SUFFIXES`).
    (
        "dynamodb.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_DynamoDBTable",
    ),
    ("ec2fleet.amazonaws.com", "AWSServiceRoleForEC2Fleet"),
    // [model] service-com-amazonaws-ecs-amazonec2containerservicev20141113
    // `src/state.rs`: `role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS`.
    ("ecs.amazonaws.com", "AWSServiceRoleForECS"),
    (
        "ecs.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_ECSService",
    ),
    ("eks-fargate.amazonaws.com", "AWSServiceRoleForAmazonEKSForFargate"),
    ("eks-nodegroup.amazonaws.com", "AWSServiceRoleForAmazonEKSNodegroup"),
    ("eks.amazonaws.com", "AWSServiceRoleForAmazonEKS"),
    ("elasticache.amazonaws.com", "AWSServiceRoleForElastiCache"),
    ("elasticbeanstalk.amazonaws.com", "AWSServiceRoleForElasticBeanstalk"),
    (
        "elasticloadbalancing.amazonaws.com",
        "AWSServiceRoleForElasticLoadBalancing",
    ),
    // [model] service-com-amazonaws-fms-awsfms-20180101
    // `src/ops/put_notification_channel.rs`: "a role other than the
    // AWSServiceRoleForFMS".
    ("fms.amazonaws.com", "AWSServiceRoleForFMS"),
    ("globalaccelerator.amazonaws.com", "AWSServiceRoleForGlobalAccelerator"),
    ("guardduty.amazonaws.com", "AWSServiceRoleForAmazonGuardDuty"),
    // [model] service-com-amazonaws-lakeformation-awslakeformation
    // `src/ops/register_resource.rs`: "choose the
    // AWSServiceRoleForLakeFormationDataAccess".
    (
        "lakeformation.amazonaws.com",
        "AWSServiceRoleForLakeFormationDataAccess",
    ),
    ("lex.amazonaws.com", "AWSServiceRoleForLexBots"),
    ("macie.amazonaws.com", "AWSServiceRoleForAmazonMacie"),
    // The AWS Migration Hub family. Each of these services is reached through a
    // HYPHENATED endpoint label (`migrationhub-orchestrator`,
    // `migrationhub-strategy` — the `cloudTrailEventSource` their own Smithy models
    // in this repository carry), while the label AWS assigns the role is the
    // service's NAME in mixed case with the hyphen gone, which no transformation of
    // the principal produces: "Using service-linked roles for AWS Migration Hub
    // Orchestrator" names AWSServiceRoleForMigrationHubOrchestrator and "Using
    // service-linked roles for Strategy Recommendations" names
    // AWSServiceRoleForMigrationHubStrategy — the role Strategy Recommendations
    // requires in the account before it will run an import or an assessment, and so
    // the name a client reads back as that prerequisite.
    (
        "migrationhub-orchestrator.amazonaws.com",
        "AWSServiceRoleForMigrationHubOrchestrator",
    ),
    (
        "migrationhub-strategy.amazonaws.com",
        "AWSServiceRoleForMigrationHubStrategy",
    ),
    (
        "opensearchservice.amazonaws.com",
        "AWSServiceRoleForAmazonOpenSearchService",
    ),
    ("ops.apigateway.amazonaws.com", "AWSServiceRoleForAPIGateway"),
    ("organizations.amazonaws.com", "AWSServiceRoleForOrganizations"),
    ("rds.amazonaws.com", "AWSServiceRoleForRDS"),
    (
        "rds.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_RDSCluster",
    ),
    // [model] service-com-amazonaws-keyspaces-keyspacesservice
    // `src/ops/update_keyspace.rs`:
    // `role/aws-service-role/replication.cassandra.amazonaws.com/AWSServiceRoleForKeyspacesReplication`.
    (
        "replication.cassandra.amazonaws.com",
        "AWSServiceRoleForKeyspacesReplication",
    ),
    // AWS Backup Audit Manager: reporting is a FEATURE of AWS Backup with its own
    // principal, and the role it links is named for the feature
    // (`...ForBackupReports`), not for the principal's first label (`reports`) —
    // "Using service-linked roles for AWS Backup" names
    // `AWSServiceRoleForBackupReports` as the role AWS Backup creates to run report
    // jobs, which is the name a client that provisions Backup reporting reads back.
    ("reports.backup.amazonaws.com", "AWSServiceRoleForBackupReports"),
    // AWS Resource Explorer: the principal carries the service's API VERSION
    // (`resource-explorer-2`), which the role AWS names in "Using service-linked
    // roles for Resource Explorer" does not — AWSServiceRoleForResourceExplorer.
    ("resource-explorer-2.amazonaws.com", "AWSServiceRoleForResourceExplorer"),
    ("securityhub.amazonaws.com", "AWSServiceRoleForSecurityHub"),
    // Amazon EC2 Spot and Spot Fleet: each role is assumed through the FEATURE's own
    // principal (`spot.amazonaws.com`, `spotfleet.amazonaws.com`), which is neither
    // the role's name nor the `ec2` endpoint prefix.
    ("spot.amazonaws.com", "AWSServiceRoleForEC2Spot"),
    ("spotfleet.amazonaws.com", "AWSServiceRoleForEC2SpotFleet"),
    // AWS Systems Manager for SAP: the role AWS SSM for SAP requires in the account
    // before it will register an application.
    ("ssm-sap.amazonaws.com", "AWSServiceRoleForAWSSSMForSAP"),
    ("ssm.amazonaws.com", "AWSServiceRoleForAmazonSSM"),
    ("sso.amazonaws.com", "AWSServiceRoleForSSO"),
    ("support.amazonaws.com", "AWSServiceRoleForSupport"),
    ("trustedadvisor.amazonaws.com", "AWSServiceRoleForTrustedAdvisor"),
];

/// AWS's own role name for `service_principal`, when it publishes one.
///
/// Matched without regard to ASCII case: a service principal is a DNS-style name
/// (`CreateServiceLinkedRole$AWSServiceName` — "a string similar to a URL but
/// without the http:// in front"), so a differently-cased spelling addresses the
/// same service, and IAM holds the resulting role name case-folded anyway
/// ([`name_key`]).
pub fn published_service_linked_role_name(service_principal: &str) -> Option<&'static str> {
    PUBLISHED_SERVICE_LINKED_ROLE_NAMES
        .iter()
        .find(|(principal, _)| principal.eq_ignore_ascii_case(service_principal))
        .map(|(_, role_name)| *role_name)
}

/// The catalog row whose PUBLISHED role name is `role_name` — its POSITION in
/// [`PUBLISHED_SERVICE_LINKED_ROLE_NAMES`], the service principal the role is linked
/// to, and the name AWS publishes for it — or `None` when no service publishes that
/// name.
///
/// The inverse of [`published_service_linked_role_name`], matched the same way IAM
/// resolves any entity name: "names are not distinguished by case"
/// (`CreateRole$RoleName`), so a request spelling the name in any case addresses the
/// same role, and the row carries the canonical spelling a read reports. The position
/// comes back with it because it is what identifies the row to
/// [`service_provisioned_role_id`].
pub fn published_service_linked_role(
    role_name: &str,
) -> Option<(usize, &'static str, &'static str)> {
    PUBLISHED_SERVICE_LINKED_ROLE_NAMES
        .iter()
        .enumerate()
        .find(|(_, (_, published))| published.eq_ignore_ascii_case(role_name))
        .map(|(row, (principal, published))| (row, *principal, *published))
}

/// The AWS-managed policy AWS attaches to the service-linked role of each service
/// principal: the policy the SERVICE controls the role's permissions through.
///
/// "The service controls the attached policies and when the role can be deleted"
/// (`CreateServiceLinkedRole`), and the policy it attaches is the one it owns under the
/// path AWS reserves for service-linked roles ([`SERVICE_LINKED_ROLE_PATH_PREFIX`]) —
/// "Amazon Web Services service role policies can only be attached to the
/// service-linked role for that service" (`PolicyNotAttachableException`). No part of
/// the IAM model names which policy belongs to which service, so the pairing is listed
/// here, keyed by principal exactly as [`PUBLISHED_SERVICE_LINKED_ROLE_NAMES`] is.
///
/// Source: the "Using service-linked roles for <service>" page of each service's own
/// user guide, which names the role AND the policy that role carries; every policy
/// named here is one [`AWS_MANAGED_POLICIES`] already carries under that path, so the
/// attachment this table makes resolves to a policy a reader of it can report. A
/// principal this table does not name attaches nothing: AWS's policy name for it is not
/// knowable here, and an invented one would name no policy.
///
/// Sorted by principal, which is also the lookup key ([`service_linked_role_policy`]).
pub const SERVICE_LINKED_ROLE_POLICIES: &[(&str, &str)] = &[
    ("autoscaling.amazonaws.com", "AutoScalingServiceRolePolicy"),
    ("backup.amazonaws.com", "AWSBackupServiceLinkedRolePolicyForBackup"),
    ("config.amazonaws.com", "AWSConfigServiceRolePolicy"),
    ("ecs.amazonaws.com", "AmazonECSServiceRolePolicy"),
    ("eks.amazonaws.com", "AmazonEKSServiceRolePolicy"),
    (
        "elasticbeanstalk.amazonaws.com",
        "AWSElasticBeanstalkServiceRolePolicy",
    ),
    (
        "elasticloadbalancing.amazonaws.com",
        "ElasticLoadBalancingServiceRolePolicy",
    ),
    ("guardduty.amazonaws.com", "AmazonGuardDutyServiceRolePolicy"),
    (
        "lakeformation.amazonaws.com",
        "LakeFormationDataAccessServiceRolePolicy",
    ),
    ("macie.amazonaws.com", "AmazonMacieServiceRolePolicy"),
    ("organizations.amazonaws.com", "AWSOrganizationsServiceTrustPolicy"),
    ("rds.amazonaws.com", "AmazonRDSServiceRolePolicy"),
    ("spot.amazonaws.com", "AWSEC2SpotServiceRolePolicy"),
    ("ssm.amazonaws.com", "AmazonSSMServiceRolePolicy"),
    ("sso.amazonaws.com", "AWSSSOServiceRolePolicy"),
    ("support.amazonaws.com", "AWSSupportServiceRolePolicy"),
    ("trustedadvisor.amazonaws.com", "AWSTrustedAdvisorServiceRolePolicy"),
];

/// The policy the service `service_principal` attaches to its service-linked role, as
/// [`AWS_MANAGED_POLICIES`] carries it, or `None` when no policy is paired with that
/// principal ([`SERVICE_LINKED_ROLE_POLICIES`]).
///
/// Matched without regard to ASCII case, for the same reason
/// [`published_service_linked_role_name`] is: a service principal is a DNS-style name,
/// so a differently-cased spelling addresses the same service. The pairing is resolved
/// against the catalog rather than trusted, so a row whose policy the catalog does not
/// carry attaches nothing instead of an ARN nothing resolves.
pub fn service_linked_role_policy(service_principal: &str) -> Option<&'static AwsManagedPolicy> {
    let policy_name = SERVICE_LINKED_ROLE_POLICIES
        .iter()
        .find(|(principal, _)| principal.eq_ignore_ascii_case(service_principal))
        .map(|(_, policy_name)| *policy_name)?;
    AWS_MANAGED_POLICIES
        .iter()
        .find(|entry| entry.policy_name == policy_name && is_service_linked_role_path(entry.path))
}

/// The path a service-linked role for `service_principal` is filed under:
/// [`SERVICE_LINKED_ROLE_PATH_PREFIX`] — the path AWS reserves for service-linked
/// roles, since a role's path is what tells every operation the role is
/// service-linked — followed by the principal and a closing `/`, which is
/// `pathType`'s required form (`^(\u002F)|(\u002F[\u0021-\u007E]+\u002F)$`).
pub fn service_linked_role_path(service_principal: &str) -> String {
    format!("{SERVICE_LINKED_ROLE_PATH_PREFIX}{service_principal}/")
}

/// The trust policy of a service-linked role: the one statement that lets the
/// service principal the role is linked to assume it.
///
/// Computed from the principal, so the document a read returns says which service
/// controls the role rather than being a fixed blob.
pub fn service_linked_role_trust_policy(service_principal: &str) -> String {
    ::serde_json::json!({
        "Version": POLICY_LANGUAGE_VERSION,
        "Statement": [{
            "Effect": "Allow",
            "Principal": { "Service": service_principal },
            "Action": ["sts:AssumeRole"],
        }],
    })
    .to_string()
}

/// Write the service-linked role `role_name`, linked to `service_principal`, into this
/// account's roles, and answer the record written.
///
/// The ONE place a service-linked role's record is built: the path IAM reserves for such a
/// role, the trust policy that lets the linked service assume it, the policy the service
/// controls its permissions through ([`service_linked_role_policy`]), this store's own id
/// minter and the default session duration. `CreateServiceLinkedRole` calls it for the
/// account's own create, and a SERVICE that links a role to itself on first use calls it
/// from its own crate, so what such a role carries cannot differ between the two.
///
/// What this does NOT decide stays with the caller, because the two paths answer them
/// differently: the role quota, a name the account already holds, and authorization. It
/// REPLACES a record held under the same name key.
pub fn insert_service_linked_role(
    store: &mut ComAmazonawsIamAwsidentitymanagementv20100508State,
    service_principal: &str,
    role_name: &str,
    description: Option<String>,
) -> Role {
    let path = service_linked_role_path(service_principal);
    let role = Role {
        arn: role_arn(&path, role_name),
        path,
        role_id: store.next_role_id(),
        create_date: now(),
        // The service that the role is linked to is the one that can assume it.
        assume_role_policy_document: Some(service_linked_role_trust_policy(service_principal)),
        description,
        max_session_duration: Some(DEFAULT_MAX_SESSION_DURATION_SECONDS),
        // A brand-new role carries neither a boundary nor tags, and has never been assumed,
        // so there is no last-used activity to report; only a role created from a role
        // template carries a `SourceRoleTemplate`, which this is not.
        permissions_boundary: None,
        tags: None,
        role_last_used: None,
        source_role_template: None,
        role_name: role_name.to_string(),
    };
    store.roles.insert(name_key(role_name), role.clone());
    // "The service controls the attached policies" (`CreateServiceLinkedRole`): the role
    // comes into existence carrying the policy its service owns
    // ([`service_linked_role_policy`]), which is why an account auditing such a role sees
    // a permissioned one. The attachment is made HERE rather than through the caller's
    // `AttachRolePolicy`, which refuses one of those policies to any identity, because it
    // is the SERVICE's attachment — "to attach a policy to this service-linked role, you
    // must make the request using the Amazon Web Services service that depends on this
    // role".
    if let Some(policy) = service_linked_role_policy(service_principal) {
        store
            .role_attached_policies
            .entry(name_key(role_name))
            .or_default()
            .insert(policy.arn());
    }
    // A role exists under this name again, so a deletion the account submitted earlier no
    // longer withholds the record the owning service keeps provisioned under it
    // ([`ComAmazonawsIamAwsidentitymanagementv20100508State::provisioned_role`]).
    store
        .withdrawn_service_provisioned_roles
        .remove(&name_key(role_name));
    role
}

/// What every `DeletionTaskId` starts with: the fixed head of the format
/// `DeleteServiceLinkedRole$DeletionTaskId` documents the identifier is returned in,
/// `task/aws-service-role/<service-principal-name>/<role-name>/<task-uuid>`. Its second
/// segment is the one [`SERVICE_LINKED_ROLE_PATH_PREFIX`] reserves for the roles those
/// tasks delete.
pub const DELETION_TASK_ID_PREFIX: &str = "task/aws-service-role/";

/// How many `/`-separated segments follow [`DELETION_TASK_ID_PREFIX`] in a
/// `DeletionTaskId`: the service principal, the role name and the task uuid. None of the
/// three can carry a separator of its own — a service principal and a `roleNameType` name
/// are both spelled without `/`, and the uuid is hex digits and dashes — so a well-formed
/// id carries exactly this many.
const DELETION_TASK_ID_SEGMENTS: usize = 3;

/// The lengths of the five hex groups a uuid is spelled in, in order: the 8-4-4-4-12
/// grouping [`uuid_from_counter`] mints and the `<task-uuid>` tail of a `DeletionTaskId`
/// therefore carries.
const UUID_GROUP_LENGTHS: [usize; 5] = [8, 4, 4, 4, 12];

/// Whether `value` is spelled as a uuid: [`UUID_GROUP_LENGTHS`] groups of hex digits
/// joined by `-`.
///
/// The ONE spelling check, read back by `tests/all/service_linked_role_deletion.rs`
/// against the ids the mint answers with, so the test and the refusal cannot disagree
/// about what a uuid is.
pub fn is_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == UUID_GROUP_LENGTHS.len()
        && groups
            .iter()
            .zip(UUID_GROUP_LENGTHS)
            .all(|(group, length)| {
                group.len() == length && group.chars().all(|digit| digit.is_ascii_hexdigit())
            })
}

/// Whether `deletion_task_id` is spelled like an identifier this service mints for a
/// service-linked role deletion ([`DELETION_TASK_ID_PREFIX`]).
///
/// A value outside that format names no task the account could ever hold, which is an
/// invalid input rather than a missing entity — the separation
/// `GetServiceLinkedRoleDeletionStatus` makes by modelling both errors.
pub fn is_service_linked_role_deletion_task_id(deletion_task_id: &str) -> bool {
    let Some(rest) = deletion_task_id.strip_prefix(DELETION_TASK_ID_PREFIX) else {
        return false;
    };
    let segments: Vec<&str> = rest.split('/').collect();
    segments.len() == DELETION_TASK_ID_SEGMENTS
        && segments.iter().all(|segment| !segment.is_empty())
        && segments.last().is_some_and(|uuid| is_uuid(uuid))
}

/// The `DeletionTaskStatusType` value of a deletion that is submitted but not finished
/// yet — one of the four values the enum declares
/// (`smithy_query(query="shape", shape="DeletionTaskStatusType")`).
pub const DELETION_TASK_STATUS_IN_PROGRESS: &str = "IN_PROGRESS";

/// The `DeletionTaskStatusType` value of a deletion that is done. See
/// [`DELETION_TASK_STATUS_IN_PROGRESS`].
pub const DELETION_TASK_STATUS_SUCCEEDED: &str = "SUCCEEDED";

/// How long after the submit a service-linked role deletion is due.
///
/// AWS publishes no duration for it — `DeleteServiceLinkedRole` says only that the submit
/// "returns a DeletionTaskId, which you can use to check the status of the deletion" — so
/// the span is the emulator's own, the same one this service gives a report job's
/// generation ([`ACCESS_REPORT_GENERATION_SECONDS`]): short enough for a caller to poll
/// through, and long enough that a caller reading straight after the submit still sees
/// the deletion `IN_PROGRESS`, which is the state AWS answers there.
pub const SERVICE_LINKED_ROLE_DELETION_SECONDS: i64 = 3;

/// How many submitted deletions the account keeps.
///
/// A finished task is a record a caller can read again, so it is kept — but not forever:
/// past this many the oldest are dropped, so repeated submits cannot grow the store
/// without end. The emulator's own bound, as [`MAX_RETAINED_ACCESS_REPORT_JOBS`] is for a
/// report job; AWS publishes no retention for a deletion task.
pub const MAX_RETAINED_SERVICE_LINKED_ROLE_DELETION_TASKS: usize = 100;

/// The `Status` the deletion due at `task.completes` is in at `now`: `IN_PROGRESS` until
/// that instant, `SUCCEEDED` from it on.
///
/// The ONE reading of that clock, shared by the submit (which asks whether an earlier
/// task for the same role is still in flight) and the read that reports the status, so
/// the two cannot disagree about one task.
pub fn service_linked_role_deletion_status(
    task: &ServiceLinkedRoleDeletionTask,
    now: ::aws_smithy_types::DateTime,
) -> &'static str {
    if now.as_secs_f64() < task.completes.as_secs_f64() {
        DELETION_TASK_STATUS_IN_PROGRESS
    } else {
        DELETION_TASK_STATUS_SUCCEEDED
    }
}

/// The message a read of a deletion task the account holds nothing under is refused
/// with — the `NoSuchEntityException` message, whose text is wholly FIXED: `Cannot find
/// deletion status for given id.`
///
/// The sentence interpolates NOTHING, which is why this helper takes no argument: the
/// deletion-status surface reports the absence of a task without naming the id it was
/// asked about, and the text a client matches is the same for every id. ONE wording, so
/// two reads cannot describe the same missing task differently.
pub fn deletion_task_not_found() -> String {
    "Cannot find deletion status for given id.".to_string()
}

/// The `CreateDate` a service-provisioned role reports: the epoch.
///
/// Nothing in this account created the role — the service that owns it did, before
/// any request this emulator served — so there is no creation instant to report, and
/// a derived record that read the clock would answer a different `CreateDate` to
/// every read. A FIXED instant keeps the record stable across reads, which is what a
/// client polling for the role depends on, and the epoch is the value this
/// repository already gives a derived record's timestamps: the xray crate's
/// `default_sampling_rule` reports `CreatedAt`/`ModifiedAt` as the epoch "because
/// nothing created it and nothing has modified it".
const SERVICE_PROVISIONED_ROLE_CREATE_MILLIS: i64 = 0;

/// The service-linked role the OWNING SERVICE keeps provisioned in the account under
/// the name AWS publishes for it, or `None` when `role_name` is not one of those
/// names.
///
/// A service-linked role "is a unique type of IAM role that is linked directly to an
/// Amazon Web Services service … predefined by the service and includes all the
/// permissions that the service requires"; the service, not the account, controls it
/// ("to attach a policy to this service-linked role, you must make the request using
/// the Amazon Web Services service that depends on this role",
/// `CreateServiceLinkedRole`), and "only the service that depends on the
/// service-linked role can modify or delete the role on your behalf"
/// (`UnmodifiableEntityException`). For every service this emulator serves, that role
/// is therefore already provisioned: the service provisions it on the account's
/// behalf when the account uses the service, and no caller has to ask for it — which
/// is why a client that waits for IAM to report one (the documented pattern before
/// using a dependent resource) converges instead of spinning on `NoSuchEntity`.
///
/// DERIVED, never inserted into the store, exactly as this crate keeps AWS-managed
/// policies out of [`ComAmazonawsIamAwsidentitymanagementv20100508State::policies`]:
/// the record belongs to AWS rather than to the account, so the account's own
/// collections stay the record of what the ACCOUNT holds, and no read writes
/// anything. Every member is a pure function of the catalog row — the path and trust
/// policy of the principal, the ARN of that path and name, an id keyed to the name
/// ([`service_provisioned_role_id`]) and a fixed `CreateDate`
/// ([`SERVICE_PROVISIONED_ROLE_CREATE_MILLIS`]) — so two reads answer the same
/// record. A record the account creates for that name (`CreateServiceLinkedRole`)
/// takes precedence: a reader looks in the store first.
///
/// NOT called directly by an operation: every resolution goes through
/// [`ComAmazonawsIamAwsidentitymanagementv20100508State::provisioned_role`], which
/// withholds the record once the ACCOUNT has asked for that service-linked role to be
/// deleted — a role the account gave up is gone, and a client waiting for it to
/// disappear before recreating it depends on that.
///
/// WHAT RESOLVES THROUGH THIS, and what deliberately does not:
///
/// * `GetRole` — the role REPORT — answers the account's own record where there is
///   one and this derived record otherwise.
/// * `UpdateRoleDescription` resolves it and MATERIALISES it as the account's own
///   record, because a description is the one mutation of a service-linked role its
///   account may make ("you can edit the description of a service-linked role" while
///   "you cannot delete or edit the permissions for this role", "Using service-linked
///   roles", IAM User Guide): the write that operation's contract mandates is what
///   creates the record, every other member of which is the service's own, carried over
///   from here.
/// * The operations that PROTECT a service-linked role resolve it here for that
///   protection: the role a service keeps provisioned is service-linked by
///   construction, so a caller's attempt to change it is refused
///   `UnmodifiableEntityException` ([`protected_role_message`]) rather than reported
///   absent — the protection is about the ROLE, not about which record resolved it.
///   `DeleteRole`, `UpdateAssumeRolePolicy`, `Put`/`DeleteRolePolicy`,
///   `Attach`/`DetachRolePolicy`, `Add`/`RemoveRoleFromInstanceProfile` and the two
///   boundary writes (`Put`/`DeleteRolePermissionsBoundary`) all read the addressed
///   role's path through it.
/// * `CreateServiceLinkedRole` still MINTS the account's own record for such a
///   principal and answers 200 rather than refusing the name as taken. That is
///   deliberate: the role a service predefines is not a record of the account's, and
///   every client that follows a service's documented bootstrap (create the role,
///   then read it back under the published name) depends on that create succeeding.
///   The created record then supersedes this one for every later read.
/// * The operations that report the ACCOUNT's own record of a role's attachments or
///   change a member no protection covers (`UpdateRole`, `Get`/`DeleteRolePolicy`'s
///   policy lookup, `Tag`/`UntagRole`, the `ListRole*` listings and `ListRoles`) keep
///   answering from the store alone, so a name only this function resolves is still
///   `NoSuchEntity` there: reporting the policies, tags or session settings a service
///   keeps on its OWN role would mean inventing a catalog no model in this repository
///   carries.
pub fn service_provisioned_role(role_name: &str) -> Option<Role> {
    let (row, service_principal, published_name) = published_service_linked_role(role_name)?;
    let path = service_linked_role_path(service_principal);
    Some(Role {
        arn: role_arn(&path, published_name),
        role_id: service_provisioned_role_id(row),
        create_date: ::aws_smithy_types::DateTime::from_millis(
            SERVICE_PROVISIONED_ROLE_CREATE_MILLIS,
        ),
        // The service that the role is linked to is the one that can assume it.
        assume_role_policy_document: Some(service_linked_role_trust_policy(service_principal)),
        // A role the service predefined carries no description of the account's, no
        // permissions boundary and no tags of its own, and nothing in this account
        // has assumed it, so there is no last-used activity to report.
        description: None,
        max_session_duration: Some(DEFAULT_MAX_SESSION_DURATION_SECONDS),
        permissions_boundary: None,
        tags: None,
        role_last_used: None,
        // Only a role created from a role template carries one
        // (`smithy_query(query="shape", shape="Role")`), which this is not.
        source_role_template: None,
        role_name: published_name.to_string(),
        path,
    })
}

/// The `RoleId` of the service-provisioned role at position `row` of
/// [`PUBLISHED_SERVICE_LINKED_ROLE_NAMES`]: an id minted by [`unique_id`], this
/// module's one id minter, from the ROW rather than from a counter.
///
/// Keying it to the row is what makes it stable — the same name resolves the same row
/// and so reads the same id, call after call — and distinct per role, since
/// [`unique_id`] is injective in the position it is given. The position is offset by
/// [`SERVICE_PROVISIONED_ROLE_ID_BASE`], past every value
/// [`ComAmazonawsIamAwsidentitymanagementv20100508State::role_id_seq`] can reach, so a
/// provisioned role's id can never collide with one minted for a created role.
fn service_provisioned_role_id(row: usize) -> String {
    unique_id(ROLE_ID_PREFIX, SERVICE_PROVISIONED_ROLE_ID_BASE + row as u64)
}

/// Where the id positions of the service-provisioned roles start: the top half of the
/// `u64` range.
///
/// [`ComAmazonawsIamAwsidentitymanagementv20100508State::role_id_seq`] starts at zero
/// and is bumped once per created role, so it cannot reach this base, and the
/// catalog's length cannot carry a row past the range — which is what makes the two
/// id spaces disjoint by construction.
const SERVICE_PROVISIONED_ROLE_ID_BASE: u64 = 1 << 63;

/// The marker scope of the attachment set of the role keyed by `role_key`.
pub fn role_attached_policies_marker_scope(role_key: &str) -> String {
    format!("{MARKER_SCOPE_ROLE_ATTACHED_POLICIES}:{role_key}")
}

/// The marker scope of the instance profiles the role keyed by `role_key` is bound to.
/// See [`MARKER_SCOPE_ROLE_INSTANCE_PROFILES`].
pub fn role_instance_profiles_marker_scope(role_key: &str) -> String {
    format!("{MARKER_SCOPE_ROLE_INSTANCE_PROFILES}:{role_key}")
}

/// The marker scope of the membership of the group keyed by `group_key`.
/// See [`MARKER_SCOPE_GROUP_MEMBERS`].
pub fn group_members_marker_scope(group_key: &str) -> String {
    format!("{MARKER_SCOPE_GROUP_MEMBERS}:{group_key}")
}

/// The marker scope of the groups the user keyed by `user_key` belongs to.
/// See [`MARKER_SCOPE_USER_GROUPS`].
pub fn user_groups_marker_scope(user_key: &str) -> String {
    format!("{MARKER_SCOPE_USER_GROUPS}:{user_key}")
}

/// The marker scope of the attachment set of the user keyed by `user_key`.
pub fn user_attached_policies_marker_scope(user_key: &str) -> String {
    format!("{MARKER_SCOPE_USER_ATTACHED_POLICIES}:{user_key}")
}

/// The marker scope of the attachment set of the group keyed by `group_key`.
/// See [`MARKER_SCOPE_GROUP_ATTACHED_POLICIES`].
pub fn group_attached_policies_marker_scope(group_key: &str) -> String {
    format!("{MARKER_SCOPE_GROUP_ATTACHED_POLICIES}:{group_key}")
}

/// The marker scope of the inline-policy set of the role keyed by `role_key`.
pub fn role_policies_marker_scope(role_key: &str) -> String {
    format!("{MARKER_SCOPE_ROLE_POLICIES}:{role_key}")
}

/// The marker scope of the inline-policy set of the user keyed by `user_key`.
pub fn user_policies_marker_scope(user_key: &str) -> String {
    format!("{MARKER_SCOPE_USER_POLICIES}:{user_key}")
}

/// The marker scope of the inline-policy set of the group keyed by `group_key`.
pub fn group_policies_marker_scope(group_key: &str) -> String {
    format!("{MARKER_SCOPE_GROUP_POLICIES}:{group_key}")
}

/// The marker scope of the entity collection of the managed policy `policy_arn`
/// names. See [`MARKER_SCOPE_ENTITIES_FOR_POLICY`].
pub fn entities_for_policy_marker_scope(policy_arn: &str) -> String {
    format!("{MARKER_SCOPE_ENTITIES_FOR_POLICY}:{policy_arn}")
}

/// The marker scope of the version collection of the managed policy `policy_arn`
/// names. See [`MARKER_SCOPE_POLICY_VERSIONS`].
pub fn policy_versions_marker_scope(policy_arn: &str) -> String {
    format!("{MARKER_SCOPE_POLICY_VERSIONS}:{policy_arn}")
}

/// The marker scope of the services the report job `job_id` names reports on. See
/// [`MARKER_SCOPE_SERVICE_LAST_ACCESSED`].
pub fn service_last_accessed_marker_scope(job_id: &str) -> String {
    format!("{MARKER_SCOPE_SERVICE_LAST_ACCESSED}:{job_id}")
}

/// The marker scope of the entities the report job `job_id` names reports for the service
/// whose namespace is `service_namespace`. See
/// [`MARKER_SCOPE_SERVICE_LAST_ACCESSED_ENTITIES`].
pub fn service_last_accessed_entities_marker_scope(
    job_id: &str,
    service_namespace: &str,
) -> String {
    format!("{MARKER_SCOPE_SERVICE_LAST_ACCESSED_ENTITIES}:{job_id}:{service_namespace}")
}

/// The page key of ONE policy version in the order a reader of a managed policy's
/// versions enumerates them — NEWEST FIRST: the COMPLEMENT of the version NUMBER,
/// zero padded, followed by the version identifier itself.
///
/// A policy's versions are reported most recently created first, so the greatest
/// version number is the first member of the list and [`FIRST_POLICY_VERSION_ID`]
/// the last. A version identifier is `v` then a number then an optional dotted
/// suffix (`policyVersionIdType`'s pattern `^v[1-9][0-9]*(\.[A-Za-z0-9-]*)?$`), so
/// the identifiers alone do not sort in version order — `v10` precedes `v2` byte by
/// byte. Taking the number's complement within `u64` and padding it to
/// [`POLICY_VERSION_KEY_DIGITS`] digits makes the byte order of these keys the
/// DESCENDING numeric order, the reverse of the order the versions were created in,
/// and appending the identifier keeps the key unique when two identifiers carry the
/// same number with different suffixes. The byte order IS the enumeration order,
/// which is what lets a reader resume strictly after the key a `Marker` names even
/// when the version it named has since been deleted.
pub fn policy_version_page_key(version_id: &str) -> String {
    let descending = u64::MAX - policy_version_number(version_id);
    format!(
        "{descending:0width$}:{version_id}",
        width = POLICY_VERSION_KEY_DIGITS
    )
}

/// The NUMBER a policy version identifier carries: the digit run after the leading
/// `v` of `policyVersionIdType`'s pattern `^v[1-9][0-9]*(\.[A-Za-z0-9-]*)?$`.
///
/// ONE reading of an identifier's number, shared by the enumeration order
/// ([`policy_version_page_key`]) and by the minting of the next identifier
/// ([`ManagedPolicy::next_version_id`]), so a version created is numbered in the
/// space the readers order by. An identifier the pattern admits always carries a
/// number; one that somehow does not counts as 0, so it sorts first rather than
/// being dropped from the order.
pub fn policy_version_number(version_id: &str) -> u64 {
    version_id
        .trim_start_matches('v')
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

/// How many digits [`policy_version_page_key`] pads a version number to: enough
/// for every `u64`, so no number can overflow the padding and sort out of order.
const POLICY_VERSION_KEY_DIGITS: usize = 20;

/// The marker scope of the tag set of the entity `entity_handle` names — an ARN or
/// an entity key, whichever handle the tag-listing operation takes. See
/// [`MARKER_SCOPE_ENTITY_TAGS`].
pub fn entity_tags_marker_scope(entity_handle: &str) -> String {
    format!("{MARKER_SCOPE_ENTITY_TAGS}:{entity_handle}")
}

/// The page key of ONE entity in the order an operation that enumerates entities of
/// SEVERAL types under one `Marker` walks them: the entity's TYPE tag followed by the
/// key its own store holds it under ([`name_key`] of its name, or an ARN for a
/// managed policy).
///
/// The byte order of these keys IS the enumeration order, which is what lets such an
/// operation resume strictly after the key a `Marker` names even when the entity it
/// named has since been deleted. Each tag is followed by the same separator, so the
/// keys group by entity type, in the tags' own order, and then run ascending within a
/// type — the order each store is already keyed in. `ListEntitiesForPolicy` tags the
/// three entity kinds a policy relates to ([`ENTITY_KEY_TAG_GROUP`],
/// [`ENTITY_KEY_TAG_ROLE`], [`ENTITY_KEY_TAG_USER`]);
/// `GetAccountAuthorizationDetails` tags the five the `EntityType` enum names, which
/// is also what its `Filter` selects by.
pub fn entity_page_key(type_tag: &str, name_key: &str) -> String {
    format!("{type_tag}:{name_key}")
}

/// The [`entity_page_key`] type tag of an IAM group.
pub const ENTITY_KEY_TAG_GROUP: &str = "group";

/// The [`entity_page_key`] type tag of an IAM role.
pub const ENTITY_KEY_TAG_ROLE: &str = "role";

/// The [`entity_page_key`] type tag of an IAM user.
pub const ENTITY_KEY_TAG_USER: &str = "user";

/// The managed-policy ARN the entity's permissions boundary names, if it carries
/// one.
///
/// A permissions boundary is "the ARN of the managed policy that is used to set the
/// permissions boundary" (`AttachedPermissionsBoundary$PermissionsBoundaryArn`),
/// which is what makes the entity one the boundary policy relates to.
pub fn permissions_boundary_arn(
    boundary: Option<&AttachedPermissionsBoundary>,
) -> Option<&str> {
    boundary?.permissions_boundary_arn.as_deref()
}

/// The parts of an IAM managed-policy ARN that an operation taking one reads.
#[derive(Debug, Clone)]
pub struct PolicyArn {
    /// The ARN's account segment: an account id, or
    /// [`AWS_MANAGED_POLICY_ACCOUNT`] for an AWS-managed policy.
    pub account: String,
    /// The policy's path, beginning and ending with `/` — `/` for a policy at the
    /// root, `/service-role/` for one AWS files under that path.
    pub path: String,
    /// The policy's friendly name: the last segment of the ARN's resource.
    pub policy_name: String,
}

/// The parts of `arn` when it is an IAM managed-policy ARN, or `None` when it is
/// not one — which is what makes an operation taking a `PolicyArn` refuse it as an
/// "invalid … value … supplied for an input parameter".
///
/// A managed policy's ARN is `arn:<partition>:iam::<account>:policy/<path><name>`:
/// IAM is a global service, so the region segment is EMPTY, and the resource is
/// the `policy` type followed by the policy's path and friendly name (the form
/// `arnType`'s documentation points at Amazon Resource Names in the AWS General
/// Reference for). Path segments are non-empty, since `policyPathType`'s pattern
/// (`^((/[A-Za-z0-9\.,\+@=_-]+)*)/$`) admits no empty one.
pub fn parse_policy_arn(arn: &str) -> Option<PolicyArn> {
    let (account, resource) = iam_arn_parts(arn)?;
    let (path, policy_name) = split_path_and_name(resource.strip_prefix("policy/")?)?;
    Some(PolicyArn {
        account: account.to_string(),
        path,
        policy_name: policy_name.to_string(),
    })
}

/// The parts of a delegation request's ARN that an operation taking one reads.
#[derive(Debug, Clone)]
pub struct DelegationRequestArn {
    /// The ARN's account segment: the account that holds the request.
    pub account: String,
    /// The request's `DelegationRequestId`: the whole resource body.
    pub delegation_request_id: String,
}

/// The parts of `arn` when it is a delegation request's ARN, or `None` when it is
/// not one — which is what lets an operation taking an ARN of any entity kind tell
/// the one kind it acts on from every other.
///
/// Such an ARN is `arn:<partition>:iam::<account>:delegation-request/<id>`, read
/// through the same [`iam_arn_parts`] envelope as every other IAM ARN this crate
/// parses; the identifier is the whole resource body, since
/// `delegationRequestIdType`'s pattern (`^[\w-]+$`) admits no `/` and so no path.
/// The account segment comes back with it for the same reason it does for a managed
/// policy ([`parse_policy_arn`]): it is part of WHICH request the ARN names.
pub fn parse_delegation_request_arn(arn: &str) -> Option<DelegationRequestArn> {
    let (account, resource) = iam_arn_parts(arn)?;
    let delegation_request_id = resource
        .strip_prefix(DELEGATION_REQUEST_RESOURCE_TYPE)?
        .strip_prefix('/')?;
    if delegation_request_id.is_empty() || delegation_request_id.contains('/') {
        return None;
    }
    Some(DelegationRequestArn {
        account: account.to_string(),
        delegation_request_id: delegation_request_id.to_string(),
    })
}

/// The ARN of a delegation request:
/// `arn:aws:iam::<account>:delegation-request/<id>`.
///
/// Built the same way [`user_arn`] is, from the
/// [`DELEGATION_REQUEST_RESOURCE_TYPE`] resource type: IAM is a global service, so
/// the region segment is empty, and a delegation request carries no path — its
/// identifier is the whole resource body ([`parse_delegation_request_arn`] reads it
/// back).
pub fn delegation_request_arn(delegation_request_id: &str) -> String {
    ::engine::emulator_arn(
        "iam",
        "",
        &format!("{DELEGATION_REQUEST_RESOURCE_TYPE}/{delegation_request_id}"),
    )
}

/// The Region the IAM console lives in, which every console page this crate names is
/// served from.
///
/// IAM is a GLOBAL service: its endpoint `iam.amazonaws.com` is in `us-east-1` ("AWS
/// Identity and Access Management endpoints and quotas", AWS General Reference), and so
/// is the console that manages what it holds. A request signed for another Region is
/// still a request to that one global service, so the page it is pointed at is the same
/// one — the Region a request named in its SigV4 credential scope is not where the
/// console view of the resource lives.
const IAM_CONSOLE_REGION: &str = "us-east-1";

/// The console deep link of a delegation request: the page a partner redirects a
/// customer to in order to act on the request this emulator holds under
/// `delegation_request_id`.
///
/// "A deep link URL to the Amazon Web Services Management Console for managing the
/// delegation request" (`CreateDelegationRequestResponse$ConsoleDeepLink`), so it is the
/// IAM console's own address — its `/iam/home` page in the Region that console is served
/// from ([`IAM_CONSOLE_REGION`]) — with the request named by the resource type IAM gives
/// it ([`DELEGATION_REQUEST_RESOURCE_TYPE`]) and the identifier that was minted for it.
/// Fixed text around those two values, so the link carries nothing of any other request,
/// and well inside `consoleDeepLinkType`'s length 1..255.
pub fn delegation_request_console_link(delegation_request_id: &str) -> String {
    let region = IAM_CONSOLE_REGION;
    format!(
        "https://{region}.console.aws.amazon.com/iam/home?region={region}\
         #/{DELEGATION_REQUEST_RESOURCE_TYPE}/{delegation_request_id}"
    )
}

/// How IAM refuses a value supplied for a member its documentation says is an ARN when
/// that value cannot be read as an ARN at all.
///
/// Measured wording, and it quotes NOTHING of the value or the member: the refusal states
/// only that what arrived is not an ARN.
///
/// The sentence states the ARN IAM managed to read BETWEEN two fixed halves — `Invalid
/// ARN:`, one space, that reading, one space, `Could not be parsed!` — and a value nothing
/// can be read as an ARN from fills that slot with nothing, so the rendered sentence
/// carries the template's two spaces, one on each side of an empty slot, after the colon.
/// The spaces belong to the template rather than to the value, so the slot is RENDERED
/// empty rather than dropped: a sentence with the whitespace around it collapsed is not
/// the one AWS answers. Stated ONCE here so the operations reading a caller-supplied ARN
/// cannot word that refusal two ways.
pub const ARN_UNPARSEABLE: &str = "Invalid ARN:  Could not be parsed!";

/// How IAM refuses a value that IS a well-formed ARN but names a resource the member
/// cannot address — a resource of another service, or of another type in the same service
/// than the one the member's documentation names.
///
/// The wording `crate::ops::get_human_readable_summary` was measured answering an
/// `EntityArn` of the wrong resource type with, shared from here for the same reason
/// [`ARN_UNPARSEABLE`] is.
pub const ARN_WRONG_RESOURCE_TYPE: &str = "Invalid resource type in ARN";

/// How IAM refuses an ARN supplied for a member that names a TEMPLATE when that ARN
/// carries an account number.
///
/// A template is pre-registered content published by a service rather than a resource an
/// account owns — `DelegationPermission$PolicyTemplateArn` "maps to a pre-registered policy
/// content for this partner" and `managedByTypeType` declares the single value `Service` —
/// so its ARN is written with the publisher in the account field (the `aws` spelling an
/// AWS-published policy ARN uses, [`AWS_MANAGED_POLICY_ACCOUNT`]) and never with an
/// account's own number. Measured wording, entirely fixed: it quotes neither the member nor
/// the value.
pub const TEMPLATE_ARN_WITH_ACCOUNT_NUMBER: &str =
    "Invalid ARN: account numbers are not acceptable for template ARNs!";

/// Whether `arn` — a value already read as a well-formed ARN — names a template by an
/// account NUMBER, which is the one thing a template ARN may not carry
/// ([`TEMPLATE_ARN_WITH_ACCOUNT_NUMBER`]).
///
/// The account field of an ARN is "empty for an account-less resource" and carries the
/// publisher for a published one, so what is refused here is specifically a field that
/// spells a number: `accountIdType`'s pattern is `^\d{12}$`, and a field of digits is that
/// number however many of them a caller sent. A field naming a publisher (`aws`) or no
/// account at all is not one.
pub fn template_arn_carries_account_number(arn: &str) -> bool {
    ::service_common::arn::parse(arn).is_some_and(|parsed| {
        !parsed.account.is_empty()
            && parsed
                .account
                .chars()
                .all(|character| character.is_ascii_digit())
    })
}

/// The one sentence IAM refuses a change to a SERVICE-LINKED role's maximum session
/// duration with — the duration belongs to the service the role is linked to, which is the
/// only party that may change the role ("only the service that depends on the
/// service-linked role can modify or delete the role on your behalf",
/// `UnmodifiableEntityException`).
///
/// A different sentence from [`protected_role_message`], and deliberately so: that one
/// states the protection of the role as a whole, while this one is the wording measured for
/// a request that asked to move `MaxSessionDuration`, and names both the role and the
/// setting. Its only variable part is the role as the request spelled it.
pub fn service_linked_role_session_duration_message(role_name: &str) -> String {
    format!(
        "{role_name} is an AWS service linked role, max session duration cannot be changed."
    )
}

/// The message a call that cannot resolve a delegation request the account does not hold
/// is refused with: the entity type that was looked for, then the identifier the request
/// named — "the error message describes the resource" (`NoSuchEntityException`).
///
/// The delegation-request API family's own wording, which is not the "The &lt;entity&gt;
/// with name &lt;name&gt; cannot be found." form IAM words its user, role and group
/// reads with (see `crate::ops::get_human_readable_summary`). Stated ONCE here so the
/// operations spelling the entity this way cannot word their refusal two ways; the
/// identifier is taken from the request. The family words that entity TWO ways and which
/// one a refusal carries goes by the operation: the reads and the acceptance name it by
/// the shape, while the update, the rejection, the association and the token send spell it
/// the other way ([`delegation_request_write_not_found_message`]).
pub fn delegation_request_not_found_message(delegation_request_id: &str) -> String {
    format!("DelegationRequest not found: {delegation_request_id}")
}

/// The message a CHANGE to a delegation request the account does not hold is refused
/// with: the entity that was looked for, then the identifier the request named — "the
/// error message describes the resource" (`NoSuchEntityException`).
///
/// The delegation-request family words that entity two ways, and which one a refusal
/// carries goes by the operation: the reads and the acceptance name it by the shape
/// ([`delegation_request_not_found_message`]), while the update, the rejection, the
/// association and the token send spell it as the two words recorded for them. Stated ONCE
/// here for the same reason the other wording is: those operations cannot word their
/// refusal two ways. The identifier is whatever the caller sent, and nothing of it is part
/// of the text.
pub fn delegation_request_write_not_found_message(delegation_request_id: &str) -> String {
    format!("Delegation request not found: {delegation_request_id}")
}

/// The number of colon-separated fields every ARN carries: `arn`, the partition, the
/// service, the region, the account and the resource
/// (`arn:<partition>:<service>:<region>:<account>:<resource>`).
const ARN_FIELDS: usize = 6;

/// Whether `value` is an ARN AT ALL — the `arn:` frame and its [`ARN_FIELDS`] fields —
/// whatever service, account or resource it goes on to name.
///
/// A member that must BE an ARN is taken in TWO layers, and this is the first of them.
/// A value that is not an ARN never gets as far as naming a resource: it is refused as a
/// value whose FORM is wrong for the member it was supplied for, with the error code IAM
/// answers such a refusal with (`ValidationError`,
/// [`crate::scaffolded::Scaffolded::validation_error`]). An ARN that IS one, but names another
/// service, another resource type or a resource body IAM's own grammar does not admit,
/// is read by the parser the member's operation uses ([`parse_policy_arn`],
/// [`parse_entity_arn`]) and refused as the "invalid … value … supplied for an input
/// parameter" that operation MODELS — the same sentence under the operation's own code.
///
/// ONE reading of the frame, so no two members of this service disagree about what is an
/// ARN.
pub fn is_arn(value: &str) -> bool {
    let fields: Vec<&str> = value.splitn(ARN_FIELDS, ':').collect();
    fields.len() == ARN_FIELDS && fields[0] == "arn"
}

/// The message IAM refuses a member that must BE an ARN, and was given a value it cannot
/// use as one, with: the fixed text `ARN ` and ` is not valid.` around the value the
/// request supplied.
///
/// The sentence of the operations that must decide whether the ARN they are handed names
/// an ATTACHABLE managed policy — the ones modelling `PolicyNotAttachableException`, which
/// read the value themselves before anything else can be said about it — in BOTH layers of
/// that reading ([`is_arn`]), so a caller matching IAM's text sees one sentence from them
/// whichever layer refused the value; the layers differ in the error CODE, which is what a
/// client branches on, not in the sentence. Every OTHER member taking an ARN hands a value
/// it cannot read to IAM's generic ARN parser, whose refusal quotes nothing of it
/// ([`ARN_UNPARSEABLE`]).
pub fn arn_not_valid(value: &str) -> String {
    format!("ARN {value} is not valid.")
}

/// The account and resource segments of `arn` when it is an IAM resource's ARN, or
/// `None` when it is not one.
///
/// Every IAM ARN is `arn:<partition>:iam::<account>:<resource>`: IAM is a global
/// service, so the region segment is EMPTY, and the account segment names the
/// account that holds the resource (or [`AWS_MANAGED_POLICY_ACCOUNT`] for a policy
/// AWS itself owns). ONE reading of that envelope, shared by every parser of an IAM
/// ARN in this crate, so no two of them can disagree about what an IAM ARN is.
fn iam_arn_parts(arn: &str) -> Option<(&str, &str)> {
    let mut fields = arn.splitn(6, ':');
    if fields.next()? != "arn" {
        return None;
    }
    if fields.next()?.is_empty() {
        return None;
    }
    if fields.next()? != "iam" {
        return None;
    }
    if !fields.next()?.is_empty() {
        return None;
    }
    let account = fields.next()?;
    if account.is_empty() {
        return None;
    }
    Some((account, fields.next()?))
}

/// Split the body of an IAM resource's ARN — its path followed by its friendly name
/// — into that path (beginning and ending with `/`) and that name, or `None` when
/// `resource` is not such a body.
///
/// Everything before the LAST `/` is the path, which is absent for a resource at the
/// account root ([`DEFAULT_PATH`]). An empty path segment (`//Name`) is not a path
/// IAM's path patterns admit — `policyPathType`'s is
/// `^((/[A-Za-z0-9\.,\+@=_-]+)*)/$` — and an empty name names nothing, so neither is
/// a resource body.
fn split_path_and_name(resource: &str) -> Option<(String, &str)> {
    let (path, name) = match resource.rfind('/') {
        Some(last) => {
            let path_body = &resource[..last];
            if path_body.split('/').any(str::is_empty) {
                return None;
            }
            (format!("/{path_body}/"), &resource[last + 1..])
        }
        None => (DEFAULT_PATH.to_string(), resource),
    };
    (!name.is_empty()).then_some((path, name))
}

/// The kind of IAM identity an ARN names: one of the three a policy can be attached
/// to — "an IAM user, group, or role"
/// (`GetContextKeysForPrincipalPolicy$PolicySourceArn`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityKind {
    /// An IAM user, whose ARN carries the `user` resource type.
    User,
    /// An IAM group, whose ARN carries the `group` resource type.
    Group,
    /// An IAM role, whose ARN carries the `role` resource type.
    Role,
}

impl EntityKind {
    /// Every kind, in the order the documentation lists them.
    pub const ALL: &'static [Self] = &[Self::User, Self::Group, Self::Role];

    /// The ARN resource type that names this kind of identity, which is also the
    /// word a refusal naming such an identity uses.
    pub fn resource_type(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
            Self::Role => "role",
        }
    }
}

/// The parts of an IAM identity's ARN that an operation taking one reads.
#[derive(Debug, Clone)]
pub struct EntityArn {
    /// Which of the three identities the ARN names.
    pub kind: EntityKind,
    /// The ARN's account segment: the account that holds the identity.
    pub account: String,
    /// The identity's path, beginning and ending with `/`.
    pub path: String,
    /// The identity's friendly name: the last segment of the ARN's resource.
    pub name: String,
}

/// The parts of `arn` when it is the ARN of an IAM user, group or role, or `None`
/// when it is not one — which is what makes an operation taking a principal's ARN
/// refuse it as an "invalid … value … supplied for an input parameter" rather than
/// report a missing entity.
///
/// Such an ARN is `arn:<partition>:iam::<account>:<type><path><name>`, read through
/// the same [`iam_arn_parts`] envelope and [`split_path_and_name`] body as a managed
/// policy's ([`parse_policy_arn`]); only the resource type differs.
pub fn parse_entity_arn(arn: &str) -> Option<EntityArn> {
    let (account, resource) = iam_arn_parts(arn)?;
    let (kind, body) = EntityKind::ALL.iter().find_map(|kind| {
        let body = resource.strip_prefix(kind.resource_type())?.strip_prefix('/')?;
        Some((*kind, body))
    })?;
    let (path, name) = split_path_and_name(body)?;
    Some(EntityArn {
        kind,
        account: account.to_string(),
        path,
        name: name.to_string(),
    })
}

/// The identity-based policies an IAM identity carries, as
/// [`principal_policies`](ComAmazonawsIamAwsidentitymanagementv20100508State::principal_policies)
/// collects them.
#[derive(Debug, Clone, Default)]
pub struct PrincipalPolicies {
    /// The policy documents themselves: the identity's inline policies, then the
    /// default version of each managed policy attached to it.
    pub documents: Vec<String>,
    /// The ARNs of the attached managed policies whose document this emulator does
    /// not hold — an ARN in AWS's own namespace that [`AWS_MANAGED_POLICIES`] does
    /// not carry, the only attachment that can resolve to no document, so nothing
    /// can be reported about its content ([`uncarried_aws_managed_policy`]).
    pub uncarried: Vec<String>,
}

/// WHERE one identity-based policy in force on a principal comes from, as
/// [`principal_sourced_policies`](ComAmazonawsIamAwsidentitymanagementv20100508State::principal_sourced_policies)
/// reports it.
///
/// The two forms an identity-based policy takes are the two the IAM grammar names: a
/// policy EMBEDDED in the identity (an inline policy, identified by its own name and
/// the entity it is embedded in) and a managed policy ATTACHED to it (identified by
/// its ARN, which also says whether AWS or the account owns it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySource {
    /// An inline policy embedded in the identity.
    Inline {
        /// The policy's own name, as the put that embedded it spelled it.
        policy_name: String,
        /// Which kind of identity embeds it: one of [`EntityKind::resource_type`]'s
        /// words, the same three values the model's `AttachmentType` enum declares.
        attachment_type: &'static str,
        /// The friendly name of the identity that embeds it.
        attachment_name: String,
    },
    /// A managed policy attached to the identity.
    Managed {
        /// The attached policy's ARN.
        policy_arn: String,
        /// Whether that ARN is in AWS's own managed-policy namespace rather than the
        /// account's ([`is_aws_managed_policy_arn`]).
        aws_owned: bool,
    },
}

/// One identity-based policy in force on a principal: where it comes from, and its
/// document when this emulator holds one for it (see
/// [`PrincipalPolicies::uncarried`] for the one case it does not).
#[derive(Debug, Clone)]
pub struct SourcedPolicy {
    /// Where the policy comes from.
    pub source: PolicySource,
    /// The document in force: an inline policy's own text, or the default version of
    /// an attached managed policy.
    pub document: Option<String>,
}

/// Every condition context key the IAM policy documents in `documents` reference,
/// folded to one entry per key and ordered.
///
/// A policy references a context key by TESTING it: "context keys can be evaluated
/// by testing against a value in an IAM policy"
/// (`GetContextKeysForPrincipalPolicy`), and the place a statement tests one is its
/// `Condition` element, whose every condition-operator block is a map from context
/// key to the values that key is tested against — so the keys of those blocks are
/// the keys the document references. A statement with no `Condition` tests none, and
/// `Statement` is read both as the list and as the single statement the IAM policy
/// grammar admits.
///
/// Context key names are not distinguished by case, so two spellings of one key are
/// one key: the folded name is the identity and the first spelling seen is the one
/// reported. A document that is not JSON contributes nothing — the operations taking
/// a policy document refuse one ([`is_policy_document`]) before reaching here.
pub fn context_keys_in_policies<'a, I: IntoIterator<Item = &'a str>>(documents: I) -> Vec<String> {
    let mut keys: BTreeMap<String, String> = BTreeMap::new();
    for document in documents {
        let Ok(parsed) = ::serde_json::from_str::<::serde_json::Value>(document) else {
            continue;
        };
        let Some(statement) = parsed.get("Statement") else {
            continue;
        };
        let statements = match statement.as_array() {
            Some(statements) => statements.as_slice(),
            None => ::std::slice::from_ref(statement),
        };
        for statement in statements {
            let Some(condition) = statement.get("Condition").and_then(|c| c.as_object()) else {
                continue;
            };
            for tested in condition.values().filter_map(|block| block.as_object()) {
                for key in tested.keys() {
                    keys.entry(key.to_ascii_lowercase())
                        .or_insert_with(|| key.clone());
                }
            }
        }
    }
    keys.into_values().collect()
}

/// The `Effect` value that makes a statement a GRANT rather than a refusal, as the
/// IAM policy grammar spells it.
const EFFECT_ALLOW: &str = "Allow";

/// The character separating a service namespace from an action name in an action
/// element's value (`iam:CreateUser`).
const ACTION_SEPARATOR: char = ':';

/// The whole-element wildcard: the value that stands for every action, and the one
/// action element the grammar admits with no service namespace in front of it.
const ANY_ACTION: &str = "*";

/// Whether the IAM policy document `document` grants access to the service whose
/// namespace is `service_namespace` — that is, whether one of its statements ALLOWS
/// at least one action belonging to that service.
///
/// A policy grants access to a service when it permits an action of that service:
/// an action element's value is `<namespace>:<action>` (or the whole-element `*`),
/// so the namespace a value reaches is the part before the separator, matched with
/// IAM's `*` and `?` wildcards and without regard to case — the comparison
/// [`::service_common::iam_authorization::wildcard_match`] makes for every action
/// name in the tree. A `NotAction` element permits everything its values do NOT, so
/// it reaches the namespace unless one of its values covers EVERY action of it.
///
/// Only a statement's EFFECT and its action element decide this: what the policy
/// grants access to is a property of the policy, so a statement's resource scope
/// narrows which resources of the service it reaches rather than whether it reaches
/// the service, and a `Deny` — in this document or another — refuses access rather
/// than granting it. A document that is not JSON grants nothing, the reading
/// [`context_keys_in_policies`] gives such a document, and `Statement` is read both
/// as the list and as the single statement the grammar admits.
pub fn grants_service_access(document: &str, service_namespace: &str) -> bool {
    let Ok(parsed) = ::serde_json::from_str::<::serde_json::Value>(document) else {
        return false;
    };
    let Some(statement) = parsed.get("Statement") else {
        return false;
    };
    let statements = match statement.as_array() {
        Some(statements) => statements.as_slice(),
        None => ::std::slice::from_ref(statement),
    };
    statements.iter().any(|statement| {
        let allows = statement
            .get("Effect")
            .and_then(::serde_json::Value::as_str)
            .is_some_and(|effect| effect == EFFECT_ALLOW);
        if !allows {
            return false;
        }
        if let Some(permitted) = statement.get("Action") {
            return element_values(permitted)
                .into_iter()
                .any(|value| reaches_namespace(value, service_namespace));
        }
        if let Some(excluded) = statement.get("NotAction") {
            return !element_values(excluded)
                .into_iter()
                .any(|value| covers_namespace(value, service_namespace));
        }
        // A statement with neither element is about no action at all.
        false
    })
}

/// The string values one policy element carries: the IAM grammar writes
/// `Action`/`NotAction` either as one string or as a list of them.
fn element_values(element: &::serde_json::Value) -> Vec<&str> {
    match element.as_array() {
        Some(values) => values.as_slice(),
        None => ::std::slice::from_ref(element),
    }
    .iter()
    .filter_map(::serde_json::Value::as_str)
    .collect()
}

/// Whether the action-element value `value` names at least ONE action of the service
/// whose namespace is `service_namespace`.
fn reaches_namespace(value: &str, service_namespace: &str) -> bool {
    match value.split_once(ACTION_SEPARATOR) {
        Some((namespace, _action)) => ::service_common::iam_authorization::wildcard_match(
            namespace,
            service_namespace,
            false,
        ),
        // Without a separator the only value that names an action is the
        // whole-element wildcard, which names every action of every service.
        None => value == ANY_ACTION,
    }
}

/// Whether the action-element value `value` names EVERY action of the service whose
/// namespace is `service_namespace` — what a `NotAction` value has to do to put the
/// whole service outside the statement's grant.
fn covers_namespace(value: &str, service_namespace: &str) -> bool {
    match value.split_once(ACTION_SEPARATOR) {
        Some((namespace, action)) => {
            action == ANY_ACTION
                && ::service_common::iam_authorization::wildcard_match(
                    namespace,
                    service_namespace,
                    false,
                )
        }
        None => value == ANY_ACTION,
    }
}

/// The most `(action, resource)` asks one delegation request's permission policy is
/// read as ([`delegated_asks`]).
///
/// Every document that reaches that reading came through an operation that bounds the
/// policy it carries, so this is a backstop such a document never meets: it keeps one
/// that somehow got past those from making a decision walk do work proportional to the
/// PRODUCT of a statement's two element lists. A document naming more asks than this is
/// read as one whose asks cannot be enumerated, which is what the reading answers for
/// every other document it cannot reduce to concrete asks.
const MAX_DELEGATED_ASKS: usize = 1_024;

/// Every `(action, resource)` pair the permission policy `document` of a delegation
/// request ASKS to have delegated, or `None` when the asks cannot be read out of it in
/// full.
///
/// A delegation request carries the permissions it asks for as an IAM policy document
/// (`DelegationRequest$PermissionPolicy`, "JSON content of the associated permission
/// policy of this delegation request"), so what it asks for is the set of
/// `(action, resource)` pairs its GRANTING statements name — the cartesian product of a
/// statement's action and resource elements, each written either as one string or as a
/// list of them ([`element_values`]). A `Deny` statement asks for nothing: it narrows
/// what the delegated session may do rather than naming a permission anybody must hold.
///
/// `None` is the answer for every document whose asks are not that set: one that is not
/// an IAM policy document at all, one that states no granting statement, one whose
/// statement is missing an element this needs, and one written with `NotAction`,
/// `NotResource` or a `Condition` — a complement names the permissions the statement
/// does NOT ask for and a condition narrows an ask to request states that are not
/// modelled here, so neither reduces to the concrete pairs a decision is made against.
/// `Statement` is read both as the list and as the single statement the IAM policy
/// grammar admits, as [`grants_service_access`] and [`context_keys_in_policies`] read
/// it.
pub fn delegated_asks(document: &str) -> Option<Vec<(String, String)>> {
    let parsed = ::serde_json::from_str::<::serde_json::Value>(document).ok()?;
    let statement = parsed.get("Statement")?;
    let statements = match statement.as_array() {
        Some(statements) => statements.as_slice(),
        None => ::std::slice::from_ref(statement),
    };

    let mut asks: Vec<(String, String)> = Vec::new();
    for statement in statements {
        let effect = statement.get("Effect").and_then(::serde_json::Value::as_str)?;
        if effect != EFFECT_ALLOW {
            continue;
        }
        if statement.get("NotAction").is_some()
            || statement.get("NotResource").is_some()
            || statement.get("Condition").is_some()
        {
            return None;
        }
        let actions = element_values(statement.get("Action")?);
        let resources = element_values(statement.get("Resource")?);
        if actions.is_empty() || resources.is_empty() {
            return None;
        }
        if asks.len() + actions.len() * resources.len() > MAX_DELEGATED_ASKS {
            return None;
        }
        for action in &actions {
            for resource in &resources {
                asks.push(((*action).to_string(), (*resource).to_string()));
            }
        }
    }
    (!asks.is_empty()).then_some(asks)
}

/// The scaffold's 501 payload for a policy ATTACHED to an identity whose ARN is in
/// AWS's own managed-policy namespace and which [`AWS_MANAGED_POLICIES`] does not
/// carry — `what` naming the part of the policy the caller needed ("document").
///
/// NOT for an operation addressed by a `PolicyArn`: a read of the policy resource
/// itself resolves the ARN and refuses a miss with the `NoSuchEntityException` its
/// model declares ([`policy_not_found`]), because an operation may answer only the
/// errors it models. This payload is for the operations whose subject is an IDENTITY
/// that exists and whose attached grant the emulator holds no document for: nothing
/// they model says "a document this request needed is not available", so the honest
/// answer is that nobody has written that catalog entry down yet.
///
/// ONE wording, shared by those operations, so they cannot describe the same
/// unreadable grant three different ways.
pub fn uncarried_aws_managed_policy(arn: &str, what: &str) -> crate::scaffolded::NotImplemented {
    crate::scaffolded::NotImplemented {
        message: format!(
            "AWS-managed policy {arn} is not in this emulator's catalog of AWS-managed \
             policies, so its {what} cannot be reported; the policy is not claimed to \
             be absent"
        ),
    }
}

/// The message IAM refuses an operation addressed by `PolicyArn` with when the
/// account holds no managed policy under that ARN — the `NoSuchEntityException`
/// message, whose fixed text is `Policy ` and ` was not found.` around the ARN the
/// request supplied.
///
/// ONE wording, shared by every operation whose subject is the policy RESOURCE itself, so a
/// read, a tag call and a delete cannot describe the same missing policy three different
/// ways. It is also what the DETACH family answers for a policy the named entity does not
/// carry: what such a request addresses is the policy, so the sentence carries the ARN and
/// nothing of the entity, which is why `Detach`/`User`/`Role`/`GroupPolicy` all word that
/// absence here rather than each composing a clause naming its own entity.
///
/// NOT for an operation of the policy-ATTACHMENT family, which words the same absence as
/// [`policy_not_attachable`]: the two sentences are separate templates, and which of them an
/// operation emits is part of the wire contract a client matching the message sees.
pub fn policy_not_found(arn: &str) -> String {
    format!("Policy {arn} was not found.")
}

/// The message IAM refuses an operation that LOOKS a provider up by
/// `OpenIDConnectProviderArn` with when the account holds no OIDC identity provider under
/// that ARN — the `NoSuchEntityException` message, whose fixed text is `OpenIDConnect
/// Provider not found for arn ` followed by the ARN the request supplied, with no trailing
/// period.
///
/// ONE wording, shared by the operations whose subject is the provider RECORD — reporting
/// it, registering or removing a client ID on it, replacing its thumbprint list — so a read
/// and a client-ID change cannot describe the same missing provider two different ways.
///
/// IAM does NOT word every absence of a provider this way: the calls that change the
/// provider's TAGS answer the sentence [`open_id_connect_provider_cannot_be_found`] builds
/// instead, so the two families stay separate templates rather than one helper bent to
/// cover both.
pub fn open_id_connect_provider_not_found(arn: &str) -> String {
    format!("OpenIDConnect Provider not found for arn {arn}")
}

/// The message IAM refuses an operation that CHANGES an OIDC identity provider's tags with
/// when the account holds no provider under the `OpenIDConnectProviderArn` it was addressed
/// by — the `NoSuchEntityException` message, whose fixed text is `OpenId connect Provider `
/// and ` cannot be found.` around the ARN the request supplied.
///
/// A different sentence from [`open_id_connect_provider_not_found`], deliberately: IAM's
/// tag-mutation surface for this resource words the same absence its own way (that spelling
/// of the resource, the ARN in the middle, a trailing period), and both wordings are part of
/// the wire contract a client matching the message sees. ONE wording, shared by the
/// tag-mutation calls, so adding a tag and removing one cannot describe the same missing
/// provider two different ways.
pub fn open_id_connect_provider_cannot_be_found(arn: &str) -> String {
    format!("OpenId connect Provider {arn} cannot be found.")
}

/// The message IAM refuses an operation of the policy-ATTACHMENT family with when the
/// account holds no managed policy under the `PolicyArn` it was addressed by — the
/// `NoSuchEntityException` message, whose fixed text is `Policy ` and ` does not exist or
/// is not attachable.` around the ARN the request supplied.
///
/// The trailing clause is what separates that family — the operations whose subject is
/// whether a managed policy can be, or already is, attached to an entity (`AttachRolePolicy`,
/// `AttachUserPolicy`, `AttachGroupPolicy`, `ListEntitiesForPolicy`), together with
/// `CreatePolicyVersion`, which writes the version that takes effect for the identities the
/// policy is attached to, and `ListPolicyVersions`, which reports those versions and which
/// of them is in force for them — both resolve their `PolicyArn` through the same
/// attachability check — from a plain read, tag or delete of the policy resource itself,
/// which reports the same absence as [`policy_not_found`]. Such a call cannot tell "this ARN
/// names nothing" from "it names something that cannot take part in an attachment", and its
/// wording says so.
pub fn policy_not_attachable(arn: &str) -> String {
    format!("Policy {arn} does not exist or is not attachable.")
}

/// The message IAM refuses an attach or a permissions-boundary put with when the policy
/// the `PolicyArn` resolves to EXISTS but AWS reserves it — the
/// `PolicyNotAttachableException` message, whose fixed text is `Cannot attach AWS reserved
/// policy to an IAM ` and `.` around the KIND of identity the policy would have been
/// attached to (`role`, `user`, `group`).
///
/// A reserved policy is one published in AWS's own namespace under the path reserved for
/// service-linked roles, so it belongs to that role alone
/// ([`AwsManagedPolicy::is_reserved_for_service_linked_role`]) and no identity of this
/// account may take it, as a permissions policy or as a permissions boundary — whatever
/// `Policy$IsAttachable` reports for it, which is the flag AWS publishes for the policy.
/// What the refusal states is that reservation — not a property of the ARN the request
/// supplied — so the sentence carries nothing of the policy, and the only value in it is
/// the kind of identity the call addressed.
///
/// Distinct from [`policy_not_attachable`], which is the `NoSuchEntityException` text for
/// an ARN that resolves to NOTHING: here the policy is one the account can read, and what
/// the refusal says is why it may not take part in an attachment. The two names are
/// deliberately unalike, because the error classes are: picking one at a call site picks
/// the error code a client branches on. ONE wording, shared by the three attach calls and
/// the two boundary puts
/// ([`ComAmazonawsIamAwsidentitymanagementv20100508State::policy_is_attachable`] is the
/// one decision behind them), so a caller matching IAM's text sees one sentence whichever
/// operation it reached the policy through.
pub fn aws_reserved_policy_refusal(entity_kind: &str) -> String {
    format!("Cannot attach AWS reserved policy to an IAM {entity_kind}.")
}

/// The kind of IAM identity [`aws_reserved_policy_refusal`] names for an operation acting
/// on a role, a user and a group — IAM's own words for the entity types a managed policy
/// can be attached to or bound on (`Policy$IsAttachable`: "the policy can be attached to
/// an IAM user, group, or role").
pub const IDENTITY_KIND_ROLE: &str = "role";
/// The identity kind [`aws_reserved_policy_refusal`] names for a user.
pub const IDENTITY_KIND_USER: &str = "user";
/// The identity kind [`aws_reserved_policy_refusal`] names for a group.
pub const IDENTITY_KIND_GROUP: &str = "group";

/// The message IAM refuses an operation addressed by a `PolicyArn` and a `VersionId`
/// with when the policy that ARN resolves to carries no such version — the
/// `NoSuchEntityException` message, whose fixed text is `Policy `, ` version ` and
/// ` does not exist or is not attachable.` around the two values the request supplied.
///
/// The closing clause is part of IAM's fixed text for a policy the request cannot be
/// served from, not a statement about this particular version: the same clause closes
/// the refusal of an attach or a permissions-boundary put naming a policy that cannot
/// be attached (`AttachUserPolicy`, `AttachRolePolicy`, `PutUserPermissionsBoundary`,
/// `PutRolePermissionsBoundary` in this crate all word it that way), so a caller
/// matching IAM's text sees one wording however it addressed the policy.
///
/// ONE wording, shared by every operation taking a policy version, so a read and a
/// delete cannot describe the same missing version two different ways.
pub fn policy_version_not_found(arn: &str, version_id: &str) -> String {
    format!("Policy {arn} version {version_id} does not exist or is not attachable.")
}

/// The message IAM refuses a permissions-boundary put with when the `PermissionsBoundary`
/// ARN names no policy the boundary could be set from — the fixed text `Scope ARN: ` and
/// ` does not exist or is not attachable.` around the ARN the request supplied.
///
/// What a boundary call names is a SCOPE on an entity's permissions rather than an
/// attachment of a policy to it, and IAM words the two differently: the attachment family
/// opens its sentence with `Policy ` ([`policy_not_attachable`]) and a boundary put with
/// `Scope ARN: `. ONE wording, shared by both boundary puts, so a caller matching IAM's
/// text sees one sentence whether it set the boundary of a role or of a user.
pub fn boundary_scope_not_attachable(arn: &str) -> String {
    format!("Scope ARN: {arn} does not exist or is not attachable.")
}

/// The message IAM refuses an operation addressed by a `RoleName` the account holds no role
/// under with — the `NoSuchEntityException` message, whose fixed text is `The role with name `
/// and ` cannot be found.` around the name the request supplied.
///
/// ONE wording for the role-absence this surface answers, so a reader and a write cannot
/// describe the same missing role two different ways. It is NOT every sentence IAM has for a
/// missing role: the permissions-boundary surface words the absence of a USER its own way
/// (`User <name> was not found.`), and both sentences are part of the wire contract a client
/// matching the message sees.
pub fn role_cannot_be_found(role_name: &str) -> String {
    format!("The role with name {role_name} cannot be found.")
}

/// The message IAM refuses a USER permissions-boundary call addressed by a `UserName` the
/// account holds no user under with — the `NoSuchEntityException` message, whose fixed text
/// is `User ` and ` was not found.` around the name the request supplied.
///
/// A different sentence from the `The user with name … cannot be found.` IAM's classic user
/// surface answers (the readers, the tag calls, the inline-policy calls): the
/// permissions-boundary surface words a missing user its own way, and both sentences are
/// part of the wire contract a client matching the message sees. ONE wording, shared by the
/// put and the delete of a user's boundary, so the two cannot describe the same missing
/// user differently.
pub fn user_was_not_found(user_name: &str) -> String {
    format!("User {user_name} was not found.")
}

/// The message IAM refuses a permissions-boundary DELETE with when the entity it names
/// carries no boundary — the `NoSuchEntityException` message, whose fixed text is
/// `Principal ` and ` does not have scope` around the entity's own unique id
/// (`User$UserId`, `Role$RoleId`), with no trailing period.
///
/// What a boundary call addresses is a SCOPE on a principal's permissions, and the refusal
/// states it that way: the principal is named by the id that identifies it for the life of
/// the account rather than by the name the request spelled, and the sentence carries nothing
/// of the boundary. ONE wording, shared by both boundary deletes, so a caller matching IAM's
/// text — or reading the principal id out of it — sees one sentence whether it cleared the
/// boundary of a role or of a user.
pub fn principal_has_no_scope(principal_id: &str) -> String {
    format!("Principal {principal_id} does not have scope")
}

/// How IAM refuses a delete whose entity still holds an ATTACHED MANAGED policy: one
/// fixed sentence naming the class of subordinate entity to remove, and nothing of the
/// entity, the policy or how many there are.
///
/// Every delete-conflict refusal in this crate is one of the constants here, for the same
/// reason: IAM's `DeleteConflictException` text is fixed per class of blocking dependent
/// ("The error message describes these entities" — the CLASS, not their names), so a
/// client branching on the sentence to decide whether to detach, to delete or to remove a
/// membership and retry sees the same text whichever entity kind it addressed.
///
/// Where SEVERAL classes block one delete, IAM names exactly one of them, and which one
/// follows a fixed precedence: a binding held by a SEPARATE resource (the instance
/// profile that holds a role) comes first, then a managed policy ATTACHED to the entity,
/// then a policy EMBEDDED in it — the dependents furthest from the entity before the ones
/// inside it. Each delete handler checks in that order, so the caller is told to remove
/// the same dependent IAM would name.
pub const DELETE_CONFLICT_DETACH_POLICIES: &str =
    "Cannot delete entity, must detach all policies first.";

/// How IAM refuses a delete whose entity still EMBEDS an inline policy.
pub const DELETE_CONFLICT_DELETE_POLICIES: &str =
    "Cannot delete entity, must delete policies first.";

/// How IAM refuses a delete blocked by an instance profile: the role is still in one, or
/// the instance profile still holds a role. One sentence for both, because what has to
/// change is the same binding.
pub const DELETE_CONFLICT_REMOVE_ROLES_FROM_INSTANCE_PROFILE: &str =
    "Cannot delete entity, must remove roles from instance profile first.";

/// How IAM refuses a delete blocked by a group membership.
pub const DELETE_CONFLICT_REMOVE_USERS_FROM_GROUP: &str =
    "Cannot delete entity, must remove users from group first.";

/// How IAM refuses a delete whose user still holds an access key.
pub const DELETE_CONFLICT_DELETE_ACCESS_KEYS: &str =
    "Cannot delete entity, must delete access keys first.";

/// How IAM refuses a delete whose user still holds a signing certificate.
pub const DELETE_CONFLICT_DELETE_SIGNING_CERTIFICATES: &str =
    "Cannot delete entity, must delete signing certificates first.";

/// How IAM refuses a delete whose user still has a console password.
pub const DELETE_CONFLICT_DELETE_LOGIN_PROFILE: &str =
    "Cannot delete entity, must delete login profile first.";

/// How IAM refuses a `DeletePolicy` whose managed policy still carries a version other
/// than its default: three sentences of entirely fixed text, which state the condition,
/// what the caller has to do about it and what this call does with the default version.
///
/// A managed policy's versions are the subordinate entities of the policy itself, so the
/// refusal is worded about the VERSIONS rather than with the
/// `Cannot delete entity, must … first.` sentence the entity deletes answer — IAM words
/// each class of blocking dependent its own way, and this class is the policy's own
/// version history.
pub const DELETE_CONFLICT_DELETE_POLICY_VERSIONS: &str =
    "This policy has more than one version. Before you delete a policy, you must delete \
     the policy's versions. The default version is deleted with the policy.";

/// The message IAM refuses an add of a role to an instance profile that already holds one
/// with — the fixed text `Cannot exceed quota for InstanceSessionsPerInstanceProfile: `
/// and the quota itself.
///
/// The quota NAME is what identifies which of the operation's several `LimitExceeded`
/// causes fired, and the one IAM names for an instance profile that already holds a role
/// is `InstanceSessionsPerInstanceProfile` — recorded behaviour for a second
/// `AddRoleToInstanceProfile`. The sentence is shaped like every other
/// `Cannot exceed quota for <quota>: <limit>` refusal in this crate
/// ([`policy_size_quota_exceeded`]) and carries nothing of the role or the profile.
pub fn instance_profile_role_quota_exceeded(quota: usize) -> String {
    format!("Cannot exceed quota for InstanceSessionsPerInstanceProfile: {quota}")
}

/// The message IAM refuses a MANAGED policy document past its size quota with — the fixed
/// text `Cannot exceed quota for PolicySize: ` and the quota itself.
///
/// A managed policy's document is measured against an ACCOUNT quota (`PolicySize`), so the
/// refusal names that quota and nothing of the policy, exactly as every other
/// `Cannot exceed quota for <quota>: <limit>` refusal in this crate does. An INLINE
/// policy's document is measured against the embedding entity instead, and is worded with
/// that entity ([`inline_policy_size_exceeded`]).
pub fn policy_size_quota_exceeded(quota: usize) -> String {
    format!("Cannot exceed quota for PolicySize: {quota}")
}

/// The message IAM refuses an INLINE policy document past the embedding entity's
/// policy-size quota with — the fixed text `Maximum policy size of `, ` bytes exceeded for
/// ` and the entity kind and name the request named.
///
/// The unit is `bytes`, which is IAM's own word in this refusal, and the entity is named
/// because the quota is the ENTITY's (a user's 2048, a role's 10240, a group's 5120)
/// rather than the account's.
pub fn inline_policy_size_exceeded(quota: usize, entity_kind: &str, entity_name: &str) -> String {
    format!("Maximum policy size of {quota} bytes exceeded for {entity_kind} {entity_name}")
}

/// What the (user, credential id) pair an operation naming a service-specific credential
/// resolves to, as
/// [`service_specific_credential_lookup`](ComAmazonawsIamAwsidentitymanagementv20100508State::service_specific_credential_lookup)
/// decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceSpecificCredentialLookup {
    /// The user the request names holds the credential the id names, so the operation
    /// acts on it.
    Held,
    /// The account holds a credential under that id, but ANOTHER user holds it: the pair
    /// the request named is not one the account holds, while the credential itself exists.
    HeldByAnotherUser,
    /// The account holds no credential under that id at all.
    Absent,
}

/// The message IAM refuses a service-specific credential lookup that found NOTHING with —
/// the `NoSuchEntityException` text, whose fixed parts are `No such credential ` and
/// ` exists` around the id the request asked for.
///
/// ONE wording, shared by every operation that reaches a credential by id, so a delete, a
/// status update and a reset cannot describe the same missing credential three ways.
pub fn service_specific_credential_not_found(credential_id: &str) -> String {
    format!("No such credential {credential_id} exists")
}

/// The message IAM refuses a request pairing a user with a service-specific credential id
/// that user does not hold with — the fixed parts `User ` and ` does not have a service
/// specific credential with id ` around the user name and the id the request paired.
///
/// Distinct from [`service_specific_credential_not_found`], which is the missing-entity
/// text for an id the account holds no credential under at all: here the credential
/// EXISTS, and what fails is the pair the request named, so the refusal names both halves
/// of it and is the unmodelled validation one
/// ([`crate::scaffolded::Scaffolded::validation_error`]) rather than a claim that the
/// credential is absent. The two names are deliberately unalike, because picking one at a
/// call site picks the error code a client branches on.
pub fn service_specific_credential_not_owned(user_name: &str, credential_id: &str) -> String {
    format!("User {user_name} does not have a service specific credential with id {credential_id}")
}

/// The fixed sentence IAM refuses a call whose implicit `UserName` resolved to no IAM user
/// with: the whole message is fixed text, naming neither the caller nor the operation.
pub const MUST_SPECIFY_USER_NAME: &str =
    "Must specify userName when calling with non-User credentials";

/// How this service refuses an operation whose optional `UserName` was omitted by a caller
/// whose credentials belong to no IAM user.
///
/// ONE definition for the whole family — every operation that resolves an absent
/// `UserName` "based on the Amazon Web Services access key ID used to sign the request" —
/// so the status, the wire code and the sentence cannot drift between them. None of those
/// operations models an error for a request that named no entity (the request named no
/// entity to be missing, and the service did not fail), so the refusal goes through the
/// crate's unmodelled client-input channel, under the code IAM itself answers a request it
/// cannot accept with and the one its clients branch on — the same code the boundary
/// validator already answers a value outside a modelled bound with.
pub fn must_specify_user_name<E>() -> crate::scaffolded::Scaffolded<E> {
    crate::scaffolded::Scaffolded::validation_error(MUST_SPECIFY_USER_NAME)
}

/// AWS's sentence for a `pathPrefix` whose form is wrong — the one message it answers for
/// the whole published form of that member, naming no submitted value.
pub const INVALID_PATH_PREFIX: &str = "The specified value for pathPrefix is invalid. It must \
                                       begin with the / character and contain only \
                                       alphanumeric characters and/or / characters.";

/// AWS's sentence for an `accountAlias` whose form is wrong, which states that member's
/// whole published form — its length AND its alphabet — in one message, again naming no
/// submitted value.
pub const INVALID_ACCOUNT_ALIAS: &str =
    "The specified value for accountAlias is invalid. It must be a minimum length of 3 \
     characters and maximum length of 63 characters, contain only digits, lowercase letters, \
     and hyphens (-), but cannot begin or end with a hyphen.";

/// The input members whose WHOLE format rule IAM states as ONE fixed sentence, each with
/// that sentence: `(the member path a refusal names, AWS's sentence for it)`.
///
/// IAM takes these members itself rather than through the model-level constraint walk, and
/// the recorded refusals are what show it: a `pathPrefix` outside its declared pattern and
/// an `accountAlias` under its declared minimum length are both answered with a single
/// sentence stating the member's whole form, where the model-level walk states one clause
/// per broken constraint inside `N validation error(s) detected: …` and echoes the
/// submitted value. Both of those constraints belong to the member's own shape, so what
/// the two recordings show is one validator for the member rather than one per constraint:
/// a value refused for a member named here is refused with that sentence whichever of the
/// member's declared constraints it broke, and the member's constraints are never stated as
/// a clause.
///
/// SOURCE, for adding a member: AWS's own sentence for that member — the recorded refusal,
/// or the format statement for it in the IAM API Reference — which reads `The specified
/// value for <member> is invalid. It must <the published form>`. An entry is added only
/// when such a statement is in hand; a member nobody has one for keeps the model-level
/// clause, which is what the framework already states.
///
/// The member is named by the path a refusal names it by (lowerCamel, as
/// `aws_smithy_schema_server::constraints::path::member` builds it), so ONE entry answers
/// for every operation that carries that member — `pathPrefix` on each of this service's
/// listings, `accountAlias` on the create and the delete alike — whatever shape the member
/// targets there, because AWS's sentence names the member and not the shape. The recordings
/// in hand are of `pathPrefix` on the listings targeting `pathPrefixType`, so its sentence
/// is carried to the listings whose `pathPrefix` targets `policyPathType` and `pathType` on
/// that reading alone: if a recording of one of those ever shows AWS wording it by the
/// SHAPE's own form rather than by the member, this entry is what splits.
pub const MEMBER_FORMAT_REFUSALS: &[(&str, &str)] = &[
    ("pathPrefix", INVALID_PATH_PREFIX),
    ("accountAlias", INVALID_ACCOUNT_ALIAS),
];

/// AWS's sentence for the member `path` names, or `None` for a member whose form IAM states
/// no sentence of its own for (see [`MEMBER_FORMAT_REFUSALS`]).
///
/// The LAST path segment decides, so a member reached inside a nested structure is the same
/// member as one reached at the top of an operation's input.
pub fn member_format_refusal(path: &str) -> Option<&'static str> {
    let member = path.split('.').next_back()?;
    MEMBER_FORMAT_REFUSALS
        .iter()
        .find_map(|(named, sentence)| (*named == member).then_some(*sentence))
}

/// The shortest account alias, from `accountAliasType`'s published length
/// (`smithy_query(query="shape", shape="accountAliasType")`: length 3..63) — the first of
/// the two numbers [`INVALID_ACCOUNT_ALIAS`] states.
pub const MIN_ACCOUNT_ALIAS_CHARACTERS: usize = 3;

/// The longest account alias, from that same published length — the second of them.
pub const MAX_ACCOUNT_ALIAS_CHARACTERS: usize = 63;

/// Whether `alias` is in the published form of `accountAliasType`: 3..63 characters of
/// "lowercase letters, digits, and dashes", where "you cannot start or finish with a dash,
/// nor can you have two dashes in a row" (`CreateAccountAlias$AccountAlias`, which is the
/// prose of that shape's pattern `^[a-z0-9]([a-z0-9]|-(?!-)){1,61}[a-z0-9]$`).
///
/// Read HERE rather than by the constraint walk because that pattern's "not followed by a
/// dash" is a lookahead, which the walk's regex engine does not compile — and a pattern it
/// cannot compile is treated as satisfied (`vendor/smithy-schema-server/src/constraints.rs`
/// says so in as many words), so the alphabet half of this rule reaches no model-level
/// check at all and an alias outside it would otherwise be stored.
pub fn is_account_alias_shape(alias: &str) -> bool {
    let letter_or_digit =
        |character: char| character.is_ascii_lowercase() || character.is_ascii_digit();
    // The length is restated so this predicate reads the WHOLE published form in one
    // place; the model-level walk already refuses a value outside it (and renders the same
    // sentence for it), so that branch is not what enforces the bound.
    (MIN_ACCOUNT_ALIAS_CHARACTERS..=MAX_ACCOUNT_ALIAS_CHARACTERS).contains(&alias.chars().count())
        && alias.starts_with(letter_or_digit)
        && alias.ends_with(letter_or_digit)
        && alias
            .chars()
            .all(|character| letter_or_digit(character) || character == '-')
        && !alias.contains("--")
}

/// How this service refuses an `accountAlias` whose form is wrong: AWS's one sentence for
/// that member ([`INVALID_ACCOUNT_ALIAS`]), under the code IAM answers a value it cannot
/// accept with — the same code and sentence the refusal seam answers when the same member
/// breaks a constraint the model-level walk DOES take, so one logical failure has one
/// answer however it was reached.
pub fn invalid_account_alias<E>() -> crate::scaffolded::Scaffolded<E> {
    crate::scaffolded::Scaffolded::validation_error(INVALID_ACCOUNT_ALIAS)
}

/// Encode a state map key as the opaque pagination `Marker` a client echoes back.
///
/// The codec is `aws_smithy_types::base64` — already in this crate's dependency
/// tree, since it is what the wire protocols use for blob members — so the token
/// needs no dependency of its own. Base64's alphabet is inside `markerType`'s
/// `^[\u0020-\u00FF]+$` pattern and its 1..320 length for any key the entity-name
/// constraints admit, and the token carries no structure a client could depend on
/// beyond being echo-able.
pub fn encode_marker(scope: &str, key: &str) -> String {
    ::aws_smithy_types::base64::encode(format!("{MARKER_PREFIX}{scope}:{key}"))
}

/// The state map key an opaque `Marker` names within `scope`, or `None` when the
/// token was not produced by [`encode_marker`] for that scope — which the prefix
/// and the scope are what establish, since a foreign token that happens to be
/// valid base64, or one this service issued while paging another collection, does
/// not carry them.
pub fn decode_marker(scope: &str, marker: &str) -> Option<String> {
    let decoded = String::from_utf8(::aws_smithy_types::base64::decode(marker).ok()?).ok()?;
    decoded
        .strip_prefix(&format!("{MARKER_PREFIX}{scope}:"))
        .map(str::to_string)
}

/// The message IAM refuses a paginated call whose `Marker` it did not issue with: one fixed
/// sentence, carrying nothing of the token the request supplied and nothing of the
/// collection being paged.
///
/// ONE wording, shared by every operation that takes a `Marker`, so a caller matching IAM's
/// text sees the same sentence whichever listing it was paging and whether that operation's
/// model gives it a client-input error of its own to answer under: what the refusal states
/// is that the token names no page of this service, which is the same fact in every one of
/// them.
pub const INVALID_MARKER: &str = "Invalid Marker.";

/// One stored role as a resource-LISTING operation reports it: the attributes
/// `ListRoles` documents it withholds are dropped, every other one is reported as
/// the account holds it.
///
/// `ListRoles`' documentation: "IAM resource-listing operations return a subset of
/// the available attributes for the resource. This operation does not return the
/// following attributes, even though they are an attribute of the returned object:
/// PermissionsBoundary RoleLastUsed Tags. To view all of the information for a
/// role, see GetRole."
pub fn listed_role(role: &Role) -> Role {
    Role {
        permissions_boundary: None,
        role_last_used: None,
        tags: None,
        ..role.clone()
    }
}

/// One stored user as a resource-LISTING operation reports it, for the same reason
/// [`listed_role`] exists.
///
/// `ListUsers`' documentation: "IAM resource-listing operations return a subset of
/// the available attributes for the resource. This operation does not return the
/// following attributes, even though they are an attribute of the returned object:
/// PermissionsBoundary Tags. To view all of the information for a user, see
/// GetUser." `PasswordLastUsed` is NOT among them, so it stays.
pub fn listed_user(user: &User) -> User {
    User {
        permissions_boundary: None,
        tags: None,
        ..user.clone()
    }
}

/// One managed policy as a resource-LISTING operation reports it, for the same
/// reason [`listed_role`] exists.
///
/// `ListPolicies`' documentation: "IAM resource-listing operations return a subset of
/// the available attributes for the resource. For example, this operation does not
/// return tags, even though they are an attribute of the returned object. To view all
/// of the information for a customer manged policy, see GetPolicy." `Description` is
/// withheld on the same ground, stated by the member itself: "this element is included
/// in the response to the GetPolicy operation. It is not included in the response to
/// the ListPolicies operation" (`Policy$Description`). Every other member of the
/// record — including the two counts the resolution derives — is reported as it stands.
pub fn listed_policy(policy: &Policy) -> Policy {
    Policy {
        description: None,
        tags: None,
        ..policy.clone()
    }
}

/// One stored instance profile as a resource-LISTING operation reports it, for the
/// same reason [`listed_role`] exists.
///
/// `ListInstanceProfiles`' documentation: "IAM resource-listing operations return a
/// subset of the available attributes for the resource. For example, this operation
/// does not return tags, even though they are an attribute of the returned object. To
/// view all of the information for an instance profile, see GetInstanceProfile." Every
/// other member — including `Roles`, which the resolution fills from the roles the
/// account holds — is reported as it stands.
pub fn listed_instance_profile(instance_profile: InstanceProfile) -> InstanceProfile {
    InstanceProfile {
        tags: None,
        ..instance_profile
    }
}

/// A unique entity id: `prefix` followed by [`UNIQUE_ID_SUFFIX_LEN`] base32
/// characters that spell out `seq` mixed through SplitMix64.
///
/// The mix is a bijection on `u64` and the first [`BASE32_CHARACTERS_PER_WORD`]
/// suffix characters carry all 64 of its bits, so distinct `seq` values always
/// yield distinct ids. The remaining characters come from a second, independently
/// mixed word purely so the id has the shape and entropy of an AWS unique id
/// rather than a visible counter.
fn unique_id(prefix: &str, seq: u64) -> String {
    unique_id_of_length(prefix, seq, UNIQUE_ID_SUFFIX_LEN)
}

/// [`unique_id`] over a suffix of `suffix_len` characters, for an id whose modelled
/// length constraint asks for more or fewer than [`UNIQUE_ID_SUFFIX_LEN`].
///
/// Unique for the same reason: the first [`BASE32_CHARACTERS_PER_WORD`] characters
/// carry all 64 bits of the bijectively mixed counter, and every further word is
/// keyed to its own position so no two positions repeat one word's characters.
fn unique_id_of_length(prefix: &str, seq: u64, suffix_len: usize) -> String {
    // OnCallWorlds patch: an id the seed pinned for this setup call.
    if let Some(id) = ocw_clock::take_pinned(prefix) {
        return id;
    }
    // The same golden-ratio odd constant SplitMix64's step adds, used here to key each
    // word to the position it fills.
    const WORD_KEY: u64 = 0x9E37_79B9_7F4A_7C15;

    let mut id = String::with_capacity(prefix.len() + suffix_len);
    id.push_str(prefix);
    let mut word = 0;
    for i in 0..suffix_len {
        if i.is_multiple_of(BASE32_CHARACTERS_PER_WORD) {
            let position = (i / BASE32_CHARACTERS_PER_WORD) as u64;
            word = splitmix64(seq ^ position.wrapping_mul(WORD_KEY));
        }
        id.push(BASE32_ALPHABET[(word & 31) as usize] as char);
        word >>= 5;
    }
    id
}

/// SplitMix64's finalizer: a bijection on `u64` that scatters consecutive inputs.
fn splitmix64(seq: u64) -> u64 {
    let mut z = seq.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// What the LOW word of a 128-bit identifier is keyed with, so the two words of one id
/// are drawn from independent mixes of the same counter rather than repeating it
/// ([`uuid_from_counter`]). The HIGH word carries all 64 bits of the counter's bijective
/// mix, which is what makes two distinct counter values yield two distinct ids.
const JOB_ID_LOW_WORD_KEY: u64 = 0xA076_1D64_78BD_642F;

/// The uuid at counter position `seq`: the 8-4-4-4-12 grouping of 128 bits AWS spells a
/// uuid-shaped identifier in — `jobIDType`'s exactly 36 characters — built over two
/// bijectively mixed words of the counter ([`splitmix64`], [`JOB_ID_LOW_WORD_KEY`]).
///
/// ONE spelling, shared by every identifier of that shape the account mints (a report
/// job's `JobId`, the task-uuid inside a service-linked role deletion's
/// `DeletionTaskId`), so a client cannot tell which call produced an id from its shape.
fn uuid_from_counter(seq: u64) -> String {
    let high = splitmix64(seq);
    let low = splitmix64(seq ^ JOB_ID_LOW_WORD_KEY);
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        high >> 32,
        (high >> 16) & 0xFFFF,
        high & 0xFFFF,
        low >> 48,
        low & 0xFFFF_FFFF_FFFF
    )
}

/// How long after the request an Organizations access report's generation is due.
///
/// AWS publishes no duration for it — "this operation … might take a few minutes" is all
/// `GenerateOrganizationsAccessReport` says — so the span is the emulator's own, chosen
/// short enough for a caller to poll through and long enough that a caller reading straight
/// after the generate still sees the job `IN_PROGRESS`, which is the state AWS answers
/// there.
pub const ACCESS_REPORT_GENERATION_SECONDS: i64 = 3;

/// How many access-report jobs may be generating AT ONCE.
///
/// `ReportGenerationLimitExceededException` is "the maximum number of concurrent requests
/// for this account are already running", which is the quota this is: a caller that asks
/// for one report after another is refused with that modelled error rather than being
/// allowed to start work without limit. AWS publishes no figure for it, so the bound is
/// the emulator's own.
pub const MAX_CONCURRENT_ACCESS_REPORT_JOBS: usize = 5;

/// How many FINISHED report jobs of ONE kind the account keeps.
///
/// A report job is a record a caller can ask for again, so a finished one is kept — but not
/// forever: past this many the oldest are dropped, so the store cannot grow without end on
/// repeated generates. The emulator's own bound; AWS publishes no retention for a report.
pub const MAX_RETAINED_ACCESS_REPORT_JOBS: usize = 100;

/// The `JobStatus` the job whose generation is due at `completes` is in at `now`:
/// `IN_PROGRESS` until that instant, `COMPLETED` from it on.
///
/// The ONE reading of that clock, shared by every report job the account records, so the
/// status a read reports and the `JobCompletionDate` beside it cannot disagree.
pub fn report_job_status(
    completes: ::aws_smithy_types::DateTime,
    now: ::aws_smithy_types::DateTime,
) -> &'static str {
    if now.as_secs_f64() < completes.as_secs_f64() {
        JOB_STATUS_IN_PROGRESS
    } else {
        JOB_STATUS_COMPLETED
    }
}

/// The `JobStatus` an Organizations access-report job is in at `now`, read through the one
/// clock rule [`report_job_status`] states.
pub fn access_report_job_status(
    job: &OrganizationsAccessReportJob,
    now: ::aws_smithy_types::DateTime,
) -> &'static str {
    report_job_status(job.completes, now)
}

/// The message a read of a report job the account holds nothing under is refused with —
/// the `NoSuchEntityException` message, whose fixed text is `Job ` and ` does not exist.`
/// around the id the request supplied.
///
/// ONE wording, shared by every reader of a report job, so two reads cannot describe the
/// same missing job differently.
pub fn report_job_not_found(job_id: &str) -> String {
    format!("Job {job_id} does not exist.")
}

/// How long after the request the account's credential report is due.
///
/// AWS publishes no duration for it — the generation is asynchronous, which is why
/// `GenerateCredentialReport` answers a `State` at all — so the span is the emulator's own,
/// read through the same clock rule every asynchronous job of this service uses
/// ([`report_job_status`]): short enough for a caller to poll through, and long enough that
/// a caller calling again straight away still sees the generation in flight.
pub const CREDENTIAL_REPORT_GENERATION_SECONDS: i64 = 3;

/// How long after a credential report was ASKED FOR the account may ask for another.
///
/// "You can generate a credential report as often as once every four hours" ("Getting
/// credential reports for your Amazon Web Services account", IAM User Guide) — a published
/// rate, so it keeps its value: a request for a new report inside the window is past "the
/// current Amazon Web Services account limits" and is refused with the modelled
/// `LimitExceededException`, and from the window's end a new generation starts.
pub const CREDENTIAL_REPORT_REGENERATION_SECONDS: i64 = 4 * 60 * 60;

/// The message a request for a credential report the published rate does not yet allow is
/// refused with — the `LimitExceededException` message, which "describes the limit
/// exceeded" the way every quota refusal of this service words one: `Cannot exceed quota
/// for `, the quota's name, and the figure it stands at.
///
/// Stated ONCE here, beside the rate it reports, so the refusal and the decision behind it
/// cannot drift apart.
pub fn credential_report_rate_exceeded() -> String {
    format!(
        "Cannot exceed quota for ReportGenerationLimit: 1 report every {} seconds",
        CREDENTIAL_REPORT_REGENERATION_SECONDS
    )
}

// The role templates AWS services publish, the `@{parameter}` substitution a role created
// from one goes through and the wording of a call addressing a template the account holds
// none of live in `state/role_templates.rs`.


// The published role-template catalog, its row types and the lookups over it live in
// `state/role_templates.rs`.

/// The `AccessAdvisorUsageGranularityType` value that asks for SERVICE data only: "if you
/// specify service-level granularity, this operation generates only service data"
/// (`GenerateServiceLastAccessedDetails$Granularity`), and the level an omitted
/// `Granularity` asks for. One of the two values the enum declares, which
/// `ops::types::ACCESS_ADVISOR_USAGE_GRANULARITY_TYPE_VALUES` records.
pub const USAGE_GRANULARITY_SERVICE_LEVEL: &str = "SERVICE_LEVEL";

/// The `AccessAdvisorUsageGranularityType` value that asks for action data beside the
/// service data: "if you specify action-level granularity, it generates service and action
/// data". See [`USAGE_GRANULARITY_SERVICE_LEVEL`].
pub const USAGE_GRANULARITY_ACTION_LEVEL: &str = "ACTION_LEVEL";

// The services a service-last-accessed report covers, the row type, the catalog of
// those services, the count of recorded access attempts and the refusal wording for an
// unknown namespace all live in `state/reported_services.rs`.

/// The `jobStatusType` value of a job whose generation is not due yet.
pub const JOB_STATUS_IN_PROGRESS: &str = "IN_PROGRESS";

/// The `jobStatusType` value of a job whose generation is done.
pub const JOB_STATUS_COMPLETED: &str = "COMPLETED";

/// This service's store in the shared engine: call it with a handler's `&*self.engine`.
///
/// Answer `None` with a modelled server error, never with a fresh engine.
pub fn service_state<Eng: Send + Sync + 'static>(
    engine: &Eng,
) -> Option<::engine::ServiceState<ComAmazonawsIamAwsidentitymanagementv20100508State>> {
    (engine as &dyn ::std::any::Any)
        .downcast_ref::<::engine::InMemoryEngine>()
        .map(::engine::InMemoryEngine::state::<ComAmazonawsIamAwsidentitymanagementv20100508State>)
}

/// How many characters an account property key may carry: `accountPropertyKeyType` is
/// length 1..50 (`smithy_query(query="shape", shape="accountPropertiesMapType")`). A map
/// KEY's own constraints are outside the framework's constraint walk, so the operation
/// taking these keys is what takes them against the published bound.
pub const MAX_ACCOUNT_PROPERTY_KEY_CHARACTERS: usize = 50;

/// The shortest key that shape admits, the other half of its published `@length`.
pub const MIN_ACCOUNT_PROPERTY_KEY_CHARACTERS: usize = 1;

/// The alphabet that shape publishes, as the model declares it — the ONE copy of this
/// pattern: [`is_account_property_key_shape`] enforces it and the refusal for a key outside
/// it states it (`input_formats::account_property_key_refusal`), so the two cannot drift.
pub const ACCOUNT_PROPERTY_KEY_PATTERN: &str = "^[A-Za-z][A-Za-z0-9/_-]*$";

/// How many account-level properties one account may hold. AWS publishes no quota
/// for these properties, so this bound is the emulator's own: it is what stops the
/// property map growing without end on repeated writes of fresh keys, and it sits
/// far above any set of namespaces and properties the service configures (each
/// entry is itself bounded, by [`MAX_ACCOUNT_PROPERTY_KEY_CHARACTERS`] and the
/// published 1024-character value length). A write that would carry the account
/// past it is refused with the modelled `InvalidInputException` — this operation
/// models no limit error — and stores nothing; re-setting a property the account
/// already holds is never refused, because the bound is taken against what the
/// account would hold AFTER the write.
pub const MAX_ACCOUNT_PROPERTIES_PER_ACCOUNT: usize = 1_000;

/// Whether `key` is within the published length and alphabet of
/// `accountPropertyKeyType` ([`MIN_ACCOUNT_PROPERTY_KEY_CHARACTERS`],
/// [`MAX_ACCOUNT_PROPERTY_KEY_CHARACTERS`] and [`ACCOUNT_PROPERTY_KEY_PATTERN`], which is
/// this predicate read as a regular expression) — see the bound for why this is checked
/// here rather than by the constraint walk.
pub fn is_account_property_key_shape(key: &str) -> bool {
    (MIN_ACCOUNT_PROPERTY_KEY_CHARACTERS..=MAX_ACCOUNT_PROPERTY_KEY_CHARACTERS)
        .contains(&key.chars().count())
        && key.starts_with(|first: char| first.is_ascii_alphabetic())
        && key
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/_-".contains(character))
}

/// The NAMESPACE an account property key names, or `None` when `key` is not in the
/// account property key format.
///
/// The one definition of that format: "each key uses the format
/// `Namespace/PropertyName`. The key must contain exactly one `/` separating the
/// namespace from the property name, and cannot start or end with `/`"
/// (`PutAccountPropertiesRequest$Properties`). So a key with no separator, with
/// more than one, or with either part empty names no property, and the namespace a
/// well-formed key names is the part before the separator — the value the
/// one-namespace-per-request rule is taken against.
pub fn account_property_namespace(key: &str) -> Option<&str> {
    let (namespace, property_name) = key.split_once('/')?;
    let names_one_property =
        !namespace.is_empty() && !property_name.is_empty() && !property_name.contains('/');
    names_one_property.then_some(namespace)
}

/// One account-property NAMESPACE this service serves, with the properties it carries and
/// the value an account holds for each before anything has been written.
///
/// Account properties "are configuration settings that control account-wide IAM features
/// such as Role Manager" and "each namespace groups related configuration settings"
/// (`PutAccountProperties`, `GetAccountProperties`), so a namespace names a FEATURE the
/// service itself offers rather than a name a caller invents: the set of namespaces is
/// published, and so is the value each of their properties has until an account sets it.
#[derive(Debug, Clone, Copy)]
pub struct ServedAccountPropertyNamespace {
    /// The namespace segment of a key, in its published spelling.
    pub namespace: &'static str,
    /// The namespace's properties, as `(the property name after the separator, the value
    /// an account holds for it before any write)`.
    pub defaults: &'static [(&'static str, &'static str)],
}

/// The account-property namespaces this service serves, each with its properties and
/// their default values.
///
/// SOURCE, for adding a namespace: the account-wide feature IAM publishes properties for,
/// with the value a fresh account reports for each of them. Role Manager is the feature
/// both of these operations name, its `Enabled` property is what gates it, and an account
/// that has never set it reports it off — a feature is not on until an account turns it
/// on. A namespace nobody has that for is NOT listed: an unlisted namespace is refused
/// ([`unsupported_account_property_namespace`]) rather than stored under a default nobody
/// can state.
pub const SERVED_ACCOUNT_PROPERTY_NAMESPACES: &[ServedAccountPropertyNamespace] =
    &[ServedAccountPropertyNamespace {
        namespace: "RoleManager",
        defaults: &[("Enabled", "false")],
    }];

/// Whether `namespace` is one this service serves — see
/// [`SERVED_ACCOUNT_PROPERTY_NAMESPACES`].
///
/// The comparison is EXACT. A namespace is published in one spelling, and
/// `accountPropertyKeyType`'s alphabet admits both cases while keys are stored verbatim,
/// so another spelling of a served name is a different namespace and not one this service
/// serves.
pub fn is_served_account_property_namespace(namespace: &str) -> bool {
    SERVED_ACCOUNT_PROPERTY_NAMESPACES
        .iter()
        .any(|served| served.namespace == namespace)
}

/// How a write under a namespace this service does not serve is refused: the
/// `InvalidInputException` message, whose fixed text is `Unsupported namespace: ` followed
/// by the namespace segment of the submitted key.
pub fn unsupported_account_property_namespace(namespace: &str) -> String {
    format!("Unsupported namespace: {namespace}")
}

/// The properties an account holds before any `PutAccountProperties`: every property of
/// every served namespace at its default, keyed as `Namespace/PropertyName` — the form
/// "keys are in the format `Namespace/PropertyName`"
/// (`GetAccountPropertiesResponse$Properties`) states.
///
/// A read of an account that has written nothing therefore reports the configuration the
/// account is actually in, which is what a caller checking a feature gate before setting
/// it reads.
pub fn default_account_properties() -> BTreeMap<String, String> {
    SERVED_ACCOUNT_PROPERTY_NAMESPACES
        .iter()
        .flat_map(|served| {
            served.defaults.iter().map(|(property, value)| {
                (
                    format!("{}/{property}", served.namespace),
                    (*value).to_string(),
                )
            })
        })
        .collect()
}

/// Whether any of `keys` is a reserved tag key — one beginning with
/// [`RESERVED_TAG_KEY_PREFIX`], however it is capitalised.
///
/// A predicate rather than a lookup, because the refusal every caller answers is the one
/// fixed sentence [`RESERVED_TAG_KEY_MESSAGE`], which carries nothing of the request: what
/// a caller asks is whether the request names such a key at all, never which one it was.
pub fn has_reserved_tag_key<'a, I: IntoIterator<Item = &'a str>>(keys: I) -> bool {
    let prefix = RESERVED_TAG_KEY_PREFIX.as_bytes();
    keys.into_iter().any(|key| {
        // The comparison is over BYTES and takes the head through `get`, so neither a
        // key shorter than the prefix nor one whose first bytes are part of a
        // multi-byte character can make it fault.
        key.as_bytes()
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    })
}

/// The tags a record holds, as a slice: the stored list, or the EMPTY set for a record
/// that holds no tags at all.
///
/// A tagged IAM record spells "no tags" as an absent list, because its modelled `Tags`
/// member is optional and a reader "does not return tags" as an empty element
/// (`User$Tags`); for a caller asking WHICH tags the record carries, both spellings are
/// the same answer.
fn held_tags(held: Option<&Vec<Tag>>) -> &[Tag] {
    held.map_or(&[], ::std::vec::Vec::as_slice)
}

/// The tag set an entity holding `held` carries after a tag call supplying
/// `incoming`, or `None` when the merged set would pass
/// [`MAX_TAGS_PER_ENTITY`].
///
/// The rule every IAM tag operation follows, in one place: "if a tag with the same
/// key name already exists, then that tag is overwritten with the new value"
/// (`TagRole`), so a supplied key REPLACES the held value in place — the held
/// order is preserved and only a key the entity does not hold yet is appended.
/// Keys compare exactly: "tag keys and values are case sensitive" ("Tagging IAM
/// resources", IAM User Guide), so two spellings of one word are two tags. A key
/// repeated inside one request settles on its LAST value, the same way a second
/// call would overwrite the first.
///
/// The merged set is what the bound is taken against, so re-tagging a held key is
/// never refused however many tags the entity already carries.
pub fn merge_tags(held: Option<&Vec<Tag>>, incoming: Vec<Tag>) -> Option<Vec<Tag>> {
    let mut merged: Vec<Tag> = held.cloned().unwrap_or_default();
    for tag in incoming {
        match merged.iter_mut().find(|existing| existing.key == tag.key) {
            Some(existing) => existing.value = tag.value,
            None => merged.push(tag),
        }
    }
    (merged.len() <= MAX_TAGS_PER_ENTITY).then_some(merged)
}

/// One PAGE of a tagged entity's tags, as an IAM tag-listing operation reports it:
/// the tags themselves, whether more remain, and the token that resumes after them.
#[derive(Debug)]
pub struct TagPage {
    /// The tags this page reports, sorted by tag key. Empty when the entity holds
    /// none, because "if no tags are attached to the specified resource, the response
    /// contains an empty list" (`ListSAMLProviderTags$Tags`).
    pub tags: Vec<Tag>,
    /// Whether "there are more items to return" (`$IsTruncated`).
    pub is_truncated: bool,
    /// The `Marker` to resume from, present only when the page is truncated: "when
    /// IsTruncated is true, this element is present" (`$Marker`).
    pub marker: Option<String>,
}

/// The page of the `held` tag set that follows `resume_after`, at most `page_size`
/// tags long, with markers minted in `scope`.
///
/// The rule every IAM tag-listing operation follows, in one place: "the returned list
/// of tags is sorted by tag key" (`ListSAMLProviderTags`), so the tag KEY is the page
/// order whatever order the entity's record holds its tags in, and a `Marker` names
/// the last key the previous page reported. The next page resumes STRICTLY after that
/// key, which stays well defined when the tag it named has been removed since: paging
/// resumes from the position, and the removed tag is simply no longer in the range.
pub fn tag_page(
    held: Option<&Vec<Tag>>,
    scope: &str,
    resume_after: Option<&str>,
    page_size: usize,
) -> TagPage {
    // A page holds at least one tag, so a truncated page always carries the key a
    // `Marker` can resume after: "when IsTruncated is true, this element is present"
    // (`$Marker`) cannot be honoured by a page of nothing. `maxItemsType`'s range floor
    // is 1, so no request reaches here asking for a smaller page.
    let page_size = page_size.max(1);
    let mut sorted: Vec<Tag> = held.cloned().unwrap_or_default();
    sorted.sort_by(|left, right| left.key.cmp(&right.key));

    let mut tags: Vec<Tag> = Vec::new();
    let mut is_truncated = false;
    for tag in sorted
        .into_iter()
        .filter(|tag| resume_after.is_none_or(|after| tag.key.as_str() > after))
    {
        if tags.len() == page_size {
            // At least one more tag follows, so the caller needs another page to see it.
            is_truncated = true;
            break;
        }
        tags.push(tag);
    }
    let marker = is_truncated
        .then(|| tags.last().map(|tag| encode_marker(scope, &tag.key)))
        .flatten();
    TagPage {
        tags,
        is_truncated,
        marker,
    }
}

/// The tag set an entity holding `held` carries after an untag call naming
/// `keys`.
///
/// The rule every IAM untag operation follows, in one place: the call "removes the
/// specified tags from the role" (`UntagRole`), so each held tag whose key is named
/// is dropped and every tag it does not name keeps its value and its position in
/// the held order. Keys compare exactly: "tag keys and values are case sensitive"
/// ("Tagging IAM resources", IAM User Guide), so a key spelled in another case
/// names a different tag. A named key the entity does not hold removes nothing —
/// these operations model no error for one — so the call is idempotent and naming
/// no keys at all leaves the held set as it was.
pub fn remove_tags<'a, I: IntoIterator<Item = &'a str>>(
    held: Option<&Vec<Tag>>,
    keys: I,
) -> Vec<Tag> {
    let removed: BTreeSet<&str> = keys.into_iter().collect();
    held.into_iter()
        .flatten()
        .filter(|tag| !removed.contains(tag.key.as_str()))
        .cloned()
        .collect()
}

/// Whether `document` is an IAM policy document.
///
/// An IAM policy document is a JSON object whose top-level elements are `Version`
/// and `Id` (both optional) and `Statement` (required) — the IAM JSON policy
/// grammar. So a document that does not parse, is not an object, or carries no
/// `Statement` is not a policy, and the operation taking it is refused with the
/// modelled `MalformedPolicyDocumentException`.
///
/// Validation deliberately stops at that top level: the grammar BELOW `Statement`
/// is not checked here, so a 200 from an operation taking a policy document is the
/// claim "stored", not "every statement is valid IAM". What a MANAGED policy's own
/// statements must carry beside it is [`managed_policy_document_defect`]. This is the
/// ONE definition of the top-level rule, shared by every operation that accepts a policy
/// document (`PutUserPolicy`'s inline policy, `CreateRole`'s trust policy).
pub fn is_policy_document(document: &str) -> bool {
    policy_document_defect(document).is_none()
}

/// WHY a value supplied where an IAM policy document is expected is not one.
///
/// The decision is one — the document is no policy — and WHICH of these a reader reports
/// is what lets each validator word it as IAM does: a text that is no JSON object at all
/// failed to PARSE, while a JSON object that carries no `Statement` parsed and described
/// no statement. A role's trust policy is read by a validator that words those two apart
/// ([`PolicyDocumentDefect::trust_policy_message`]) — the first is a serialization bug on
/// the caller's side, the second a policy that would grant nothing — where the
/// identity-policy validator answers one sentence for both
/// ([`PolicyDocumentDefect::message`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDocumentDefect {
    /// The value does not parse as a JSON object: it is not JSON, or it is JSON that is
    /// not an object (a list, a number, a string), neither of which can carry the
    /// top-level elements of the IAM JSON policy grammar.
    Syntax,
    /// The value IS a JSON object, and carries no `Statement` element — the one element
    /// that grammar requires.
    NoStatements,
    /// A statement of the document names no actions: it carries neither an `Action` nor
    /// a `NotAction` element, so it says nothing about what it applies to.
    NoActions,
    /// A statement of the document names no resources: it carries neither a `Resource`
    /// nor a `NotResource` element, which an identity-based policy's every statement
    /// must.
    NoResources,
}

/// The fixed sentence IAM refuses an identity or resource policy document it cannot read
/// as a policy with: one that does not parse as a JSON object, and one that parses and
/// carries no `Statement` element.
///
/// IAM's identity-policy validator reports both as a SYNTAX error and gives no diagnosis
/// at all — recorded behaviour for a `CreatePolicy` whose document is valid JSON carrying
/// only `Version` — so the whole message is fixed text. The TRUST-policy validator is the
/// one that tells the two apart ([`TRUST_POLICY_INVALID_JSON`],
/// [`POLICY_HAS_NO_STATEMENTS`]).
pub const SYNTAX_ERRORS_IN_POLICY: &str = "Syntax errors in policy.";

/// How IAM refuses an entry of a `PolicyInputList` it cannot read as a policy document:
/// the fixed text, carrying the POSITION of the offending entry in the list it arrived in,
/// counted from one.
///
/// The operations that take that member — the two simulations and the two context-key
/// readers — take a LIST of documents, so a caller submitting several in one call needs to
/// be told WHICH one was rejected; that is the only variable part, and it comes from the
/// request. It is why these operations do not answer the sentence an operation taking a
/// SINGLE policy document answers ([`SYNTAX_ERRORS_IN_POLICY`]), which identifies no entry.
///
/// Every defect [`policy_document_defect`] reports is worded this way here, because what the
/// refusal says is that the entry is not content these operations can read as a policy —
/// a text that is no JSON object and an object describing no statement are alike unreadable
/// as the "complete, valid JSON text of an IAM policy" the member documents.
pub fn policy_input_list_item_invalid(position: usize) -> String {
    format!("Policy input list item {position} has invalid content")
}

/// The fixed sentence IAM refuses a TRUST policy document that does not parse as a JSON
/// object with.
///
/// A role's trust policy is validated by its own validator in IAM, which words an
/// unusable document differently from the one that reads an identity or resource policy
/// ([`SYNTAX_ERRORS_IN_POLICY`]) — recorded behaviour for a trust-policy write carrying
/// text that is no JSON object. Fixed text throughout: it carries nothing of the document
/// and nothing of the member that supplied it.
pub const TRUST_POLICY_INVALID_JSON: &str = "This policy contains invalid Json";

/// The fixed sentence IAM's TRUST-policy validator refuses a JSON object carrying no
/// `Statement` element with — recorded behaviour for a `CreateRole` whose
/// `AssumeRolePolicyDocument` is an object with no `Statement`.
pub const POLICY_HAS_NO_STATEMENTS: &str = "Policy has no statements";

/// The fixed sentence IAM refuses a statement naming no actions with.
pub const STATEMENT_WITHOUT_ACTIONS: &str = "Policy statement must contain actions.";

/// The fixed sentence IAM refuses a statement of an identity-based policy naming no
/// resources with.
pub const STATEMENT_WITHOUT_RESOURCES: &str = "Policy statement must contain resources.";

impl PolicyDocumentDefect {
    /// How IAM words this defect in the modelled `MalformedPolicyDocumentException` for an
    /// IDENTITY or RESOURCE policy document: a FIXED sentence per defect, carrying nothing
    /// of the document and nothing of the member that supplied it, so every operation
    /// taking such a document refuses the same text for the same defect.
    ///
    /// A document that is no JSON object and one that carries no `Statement` are both
    /// reported as the SYNTAX defect here ([`SYNTAX_ERRORS_IN_POLICY`]): this validator
    /// gives no diagnosis of a document it cannot read as a policy at all, and only the
    /// statement-level requirements it does read are worded apart
    /// ([`STATEMENT_WITHOUT_ACTIONS`], [`STATEMENT_WITHOUT_RESOURCES`]). A role's trust
    /// policy is read by a validator of IAM's own, which words both of those two cases its
    /// way ([`Self::trust_policy_message`]).
    pub fn message(self) -> &'static str {
        match self {
            Self::Syntax | Self::NoStatements => SYNTAX_ERRORS_IN_POLICY,
            Self::NoActions => STATEMENT_WITHOUT_ACTIONS,
            Self::NoResources => STATEMENT_WITHOUT_RESOURCES,
        }
    }

    /// How IAM words this defect for a TRUST policy document — a role's
    /// `AssumeRolePolicyDocument`, which `CreateRole` and `UpdateAssumeRolePolicy` write.
    ///
    /// The DECISION is the same one [`policy_document_defect`] makes for every policy
    /// document; what differs is that IAM validates a role's trust policy with a validator
    /// of its own, which tells a document that does not parse as a JSON object
    /// ([`TRUST_POLICY_INVALID_JSON`]) from one that parses and describes no statement
    /// ([`POLICY_HAS_NO_STATEMENTS`]) — where the identity-policy validator reports one
    /// sentence for both ([`Self::message`]). The statement-level requirements are worded
    /// alike for both classes.
    pub fn trust_policy_message(self) -> &'static str {
        match self {
            Self::Syntax => TRUST_POLICY_INVALID_JSON,
            Self::NoStatements => POLICY_HAS_NO_STATEMENTS,
            other => other.message(),
        }
    }
}

/// Why `document` is not an IAM policy document, or `None` when it is one.
///
/// The ONE reader of the rule [`is_policy_document`] states, so the refusal an operation
/// answers and the decision it answers it on cannot drift apart.
pub fn policy_document_defect(document: &str) -> Option<PolicyDocumentDefect> {
    policy_statements(document).err()
}

/// The `Statement` element of `document`, or the defect that says `document` is no policy
/// document at all.
///
/// The ONE place the top-level grammar is read, so the decision
/// [`policy_document_defect`] reports and the statements
/// [`managed_policy_document_defect`] walks come from one parse of one rule.
fn policy_statements(document: &str) -> Result<::serde_json::Value, PolicyDocumentDefect> {
    match ::serde_json::from_str::<::serde_json::Value>(document) {
        Ok(::serde_json::Value::Object(mut elements)) => elements
            .remove("Statement")
            .ok_or(PolicyDocumentDefect::NoStatements),
        Ok(_) | Err(_) => Err(PolicyDocumentDefect::Syntax),
    }
}

/// The elements the IAM JSON policy grammar REQUIRES of every statement of an
/// identity-based policy, each with the defect a statement naming none of its spellings
/// is reported under.
///
/// A statement of an identity policy "must include … the Action element" and "the
/// Resource element", each of which the grammar also admits in its negated spelling
/// (`NotAction`, `NotResource`) — the element is what says WHICH operations the statement
/// is about and WHICH resources they may be performed on, and an identity policy carries
/// no `Principal` because the identity it is attached to is the principal ("Grammar of
/// the IAM JSON policy language", IAM User Guide).
const IDENTITY_STATEMENT_ELEMENTS: &[(&[&str], PolicyDocumentDefect)] = &[
    (
        &["Action", "NotAction"],
        PolicyDocumentDefect::NoActions,
    ),
    (
        &["Resource", "NotResource"],
        PolicyDocumentDefect::NoResources,
    ),
];

/// Whether `element` NAMES something: a statement element that is absent, null or an
/// empty list names nothing, and so does not satisfy a requirement of the grammar.
fn names_something(element: Option<&::serde_json::Value>) -> bool {
    match element {
        None | Some(::serde_json::Value::Null) => false,
        Some(::serde_json::Value::Array(values)) => !values.is_empty(),
        Some(_) => true,
    }
}

/// Why `document` is no document a MANAGED policy can hold, or `None` when it is one.
///
/// A managed policy's document is an IDENTITY-based policy — "a customer managed policy
/// … can be attached to a user, group or role" and grants that identity its permissions —
/// so it is the document [`policy_document_defect`] judges, held to the grammar BELOW
/// `Statement` as well: every statement of it must name the actions it is about and the
/// resources those actions apply to ([`IDENTITY_STATEMENT_ELEMENTS`]), and a statement
/// omitting one describes no permission IAM could enforce, so the operation taking the
/// document is refused with the modelled `MalformedPolicyDocumentException`. `Statement`
/// is read both as the list and as the single statement the grammar admits, and a
/// statement that is not an object at all is no statement — which is the SYNTAX defect,
/// not a missing element.
///
/// This is the ONE definition of the rule, shared by both operations that write a managed
/// policy's document: `CreatePolicy` and `CreatePolicyVersion`.
pub fn managed_policy_document_defect(document: &str) -> Option<PolicyDocumentDefect> {
    let statement = match policy_statements(document) {
        Ok(statement) => statement,
        Err(defect) => return Some(defect),
    };
    let statements = match statement.as_array() {
        Some(statements) => statements.as_slice(),
        None => ::std::slice::from_ref(&statement),
    };
    for statement in statements {
        let Some(elements) = statement.as_object() else {
            return Some(PolicyDocumentDefect::Syntax);
        };
        for (spellings, defect) in IDENTITY_STATEMENT_ELEMENTS {
            if !spellings
                .iter()
                .any(|spelling| names_something(elements.get(*spelling)))
            {
                return Some(*defect);
            }
        }
    }
    None
}

/// What IAM reads out of a SAML provider's metadata document.
///
/// `CreateSAMLProvider` has to READ the document rather than store it blindly, because
/// what a provider reports about itself comes from it: "that document includes the
/// issuer's name, expiration information, and keys" (`CreateSAMLProvider`), and the
/// expiration is what `GetSAMLProvider$ValidUntil` answers.
#[derive(Debug, Clone)]
pub struct SamlMetadata {
    /// The root descriptor's `validUntil`, when the document carries one: the instant
    /// the metadata — and so the provider — stops being valid.
    pub valid_until: Option<::aws_smithy_types::DateTime>,
}

/// Read `document` as a SAML 2.0 metadata document, or `None` when it is not one.
///
/// A metadata document is "an XML document generated by an identity provider (IdP) that
/// supports SAML 2.0" whose root is an entity (or entities) descriptor in the SAML
/// metadata namespace ([`SAML_METADATA_NAMESPACE`]) and which "includes the issuer's
/// name" — the entity descriptor's `entityID`
/// (`CreateSAMLProvider$SAMLMetadataDocument`, OASIS "Metadata for SAML V2.0" §2.3).
/// So a document that is not well-formed XML, is rooted at something else, or names no
/// issuer describes no identity provider, and the operation taking it is refused as
/// having been "supplied an invalid … value … for an input parameter"
/// (`InvalidInputException`).
///
/// Validation deliberately stops there: the keys and endpoints BELOW the descriptor are
/// not checked, so a 200 from an operation taking a metadata document is the claim
/// "this is SAML 2.0 metadata for an issuer", not "every binding in it is usable".
/// This is the ONE definition of the rule, shared by every operation that accepts a
/// metadata document.
///
/// WHICH of those it was is deliberately not reported: the refusal is
/// [`INVALID_SAML_METADATA_DOCUMENT`], one fixed sentence for every way a document can
/// fail to be SAML 2.0 metadata, so no reader of the document can put its own diagnostics
/// on the wire.
pub fn parse_saml_metadata(document: &str) -> Option<SamlMetadata> {
    let parsed = ::roxmltree::Document::parse(document).ok()?;
    let root = parsed.root_element();
    let in_metadata_namespace = |node: &::roxmltree::Node<'_, '_>, local: &str| {
        node.tag_name().namespace() == Some(SAML_METADATA_NAMESPACE)
            && node.tag_name().name() == local
    };
    // The descriptor that names the issuer: the root itself for a document describing
    // one entity, or the first entity descriptor nested in a group of them.
    let entity = if in_metadata_namespace(&root, SAML_ENTITY_DESCRIPTOR) {
        root
    } else if in_metadata_namespace(&root, SAML_ENTITIES_DESCRIPTOR) {
        root.descendants()
            .find(|node| in_metadata_namespace(node, SAML_ENTITY_DESCRIPTOR))?
    } else {
        return None;
    };
    if entity
        .attribute(SAML_ENTITY_ID_ATTRIBUTE)
        .is_none_or(str::is_empty)
    {
        return None;
    }
    // "Expiration information": `validUntil` on the root descriptor, or on the entity
    // descriptor itself when the root is a group that carries none. It is an
    // `xs:dateTime`, so it may state a UTC offset rather than `Z` (XML Schema Part 2,
    // §3.2.7) — read through the ONE reader every service with a text timestamp shares.
    let valid_until = match root
        .attribute(SAML_VALID_UNTIL_ATTRIBUTE)
        .or_else(|| entity.attribute(SAML_VALID_UNTIL_ATTRIBUTE))
    {
        None => None,
        Some(text) => Some(parse_xs_date_time(text)?),
    };
    Some(SamlMetadata { valid_until })
}

/// The message IAM refuses an operation taking a `SAMLMetadataDocument` with when the
/// value describes no SAML 2.0 identity provider ([`parse_saml_metadata`]) — the
/// `InvalidInputException` message, which is this ONE fixed sentence: it names neither the
/// input member, nor which of the document's properties was wrong, nor anything the reader
/// of the document observed about its text.
pub const INVALID_SAML_METADATA_DOCUMENT: &str = "Invalid SAML metadata document";

/// The instant an `xs:dateTime` names, or `None` when the text is not one.
///
/// The calendar conversion (month lengths, leap years, a fractional second) comes from
/// the maintained library, which reads the `Z` form; a value carrying the numeric UTC
/// offset `xs:dateTime` also admits is resolved by reading its civil part as UTC and
/// shifting by that offset, through the ONE reader of that offset every service with a
/// text timestamp shares. A value stating NO zone is local time of an undetermined zone
/// (XML Schema Part 2 §3.2.7), which is a form a well-formed document may use, so it is
/// read as UTC rather than refused.
fn parse_xs_date_time(text: &str) -> Option<::aws_smithy_types::DateTime> {
    let (civil, offset_secs) =
        ::service_common::rfc3339::split_utc_offset(text).unwrap_or((text, 0));
    let parsed = ::aws_smithy_types::DateTime::from_str(
        &format!("{civil}Z"),
        ::aws_smithy_types::date_time::Format::DateTime,
    )
    .ok()?;
    Some(::aws_smithy_types::DateTime::from_secs_and_nanos(
        parsed.secs().checked_sub(offset_secs)?,
        parsed.subsec_nanos(),
    ))
}

/// The size a policy document is measured at against the policy-size quota of
/// whatever it is embedded in or held as ([`MAX_MANAGED_POLICY_CHARACTERS`],
/// [`MAX_USER_INLINE_POLICY_CHARACTERS`], [`MAX_ROLE_INLINE_POLICY_CHARACTERS`],
/// [`MAX_GROUP_INLINE_POLICY_CHARACTERS`]): its characters except whitespace,
/// because AWS "doesn't count whitespace when calculating the size of a policy
/// against this limitation" — one measure, so a document that fits a quota fits it
/// whichever operation stores it and however it is formatted.
pub fn policy_document_characters(document: &str) -> usize {
    document.chars().filter(|c| !c.is_whitespace()).count()
}
