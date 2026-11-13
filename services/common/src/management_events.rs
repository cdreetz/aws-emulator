// SPDX-License-Identifier: CC0-1.0

//! The account's MANAGEMENT-EVENT log: the audit record of the API calls this emulator
//! served, which CloudTrail's `LookupEvents` reads.
//!
//! CloudTrail does not record its OWN calls only — it records the management (control
//! plane) API calls of every service in the account, and `LookupEvents` serves them
//! back. So the log cannot live in one service's state struct: the service that SERVES
//! a call is the one that knows the call happened, and the service that REPORTS it is
//! CloudTrail. This is that one store, held once in the shared engine, written by the
//! service that served the call ([`ManagementEventLog::record`]) and read by CloudTrail.
//!
//! Nothing here names a wire shape or a Smithy type: a reader projects a
//! [`ManagementEvent`] onto the shapes ITS model declares (CloudTrail's `Event` /
//! `Resource`). What lives here is the record, the JSON form of a CloudTrail event
//! ([`ManagementEvent::to_cloudtrail_event_json`]), the writers every recording service
//! shares ([`recorded_caller`], [`recorded_members`], [`recorded_failure`]) and the
//! bounds that keep the log from growing without end.
//!
//! The log is BOUNDED twice over, because every call may add to it:
//!
//! * by TIME — a record older than [`EVENT_RETENTION`] is dropped, which is also the
//!   window CloudTrail serves ("You can look up events that occurred in a Region within
//!   the last 90 days", `LookupEvents`); and
//! * by COUNT — [`MAX_RECORDED_EVENTS`] records at most, oldest dropped first, so the
//!   events a live workflow just made stay resolvable.
//!
//! Both are materialised on the WRITE path ([`ManagementEventLog::record`] prunes what
//! the clock has already made due), never on a read: a lookup must not change what a
//! later lookup sees.
//!
//! The log is also where the account's OTHER reader of a management event is served from.
//! While a trail of the Region is logging, CloudTrail publishes each call it logs onto the
//! account's default EventBridge bus, so the log carries the one fact that decision needs —
//! which trails are logging, projected here by CloudTrail ([`DeliveringTrail`]) — and
//! [`ManagementEventLog::record_delivered`] answers the event to publish beside the record
//! it just wrote. The channel itself is [`crate::api_call_events`].

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long a recorded event stays retrievable.
///
/// From the CloudTrail `LookupEvents` documentation: "You can look up events that
/// occurred in a Region within the last 90 days."
pub const EVENT_RETENTION: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// How many events the log holds at once.
///
/// An EMULATOR ceiling, not an AWS quota: the log lives in memory for the life of the
/// process and every served call appends to it, so without a ceiling a caller looping on
/// any write would grow it without end. The oldest record is dropped first, so the
/// events a live workflow just made are the ones that survive.
pub const MAX_RECORDED_EVENTS: usize = 20_000;

/// The `eventCategory` of a management (control-plane) event, as CloudTrail stamps it —
/// the category `LookupEvents` serves when the request names no `EventCategory`.
pub const EVENT_CATEGORY_MANAGEMENT: &str = "Management";

/// The `eventCategory` of a CloudTrail Insights event. Insights events are DERIVED by
/// CloudTrail from a trail's unusual call volume rather than recorded per call, so
/// nothing in this emulator writes one; the constant is here because a reader filtering
/// by category needs the value it is filtering for.
pub const EVENT_CATEGORY_INSIGHT: &str = "Insight";

/// The `eventType` of a record made for an AWS API call (as against a service event or
/// a console sign-in).
pub const EVENT_TYPE_AWS_API_CALL: &str = "AwsApiCall";

/// The `eventVersion` stamped on every record this emulator writes: one version for one
/// record format, so a reader parsing `CloudTrailEvent` knows which fields to expect.
pub const EVENT_VERSION: &str = "1.09";

/// `userIdentity.type` for a call signed with an IAM user's long-term access key.
pub const PRINCIPAL_TYPE_IAM_USER: &str = "IAMUser";

/// `userIdentity.type` for a call signed with the temporary credentials of an assumed
/// role.
pub const PRINCIPAL_TYPE_ASSUMED_ROLE: &str = "AssumedRole";

/// `userIdentity.type` for a call signed with the temporary credentials of a federated
/// user — the session `GetFederationToken` mints.
pub const PRINCIPAL_TYPE_FEDERATED_USER: &str = "FederatedUser";

/// `userIdentity.type` for a call that carried no credential this emulator can read an
/// identity from.
pub const PRINCIPAL_TYPE_UNKNOWN: &str = "Unknown";

/// `sessionContext.sessionIssuer.type` for a session an IAM ROLE issued, which is what an
/// assumed-role session's issuer is.
pub const SESSION_ISSUER_TYPE_ROLE: &str = "Role";

/// The IAM user name a long-term access key speaks for in this emulator.
///
/// The emulator publishes ONE long-term credential, and it belongs to the IAM user
/// `user/emulator` — the identity STS answers `GetCallerIdentity` with for a caller
/// presenting it, and the record IAM holds for it, both stated once by
/// [`crate::caller_principal`]. CloudTrail reports that name as an event's `Username`,
/// which is what a lookup by the `Username` attribute filters on. A request signed with a
/// TEMPORARY credential speaks for a session whose role name a serving service cannot
/// resolve, so it is recorded without a user name rather than with a guessed one.
pub const AMBIENT_USER_NAME: &str = crate::caller_principal::AMBIENT_USER_NAME;

/// The access-key-id prefix of a temporary (session) credential, from the IAM
/// "unique identifier prefixes" table: `ASIA` for a temporary access key, `AKIA` for an
/// IAM user's long-term one.
const TEMPORARY_ACCESS_KEY_PREFIX: &str = "ASIA";

/// What `extract_akid` answers for a request that carried no SigV4 credential.
const UNSIGNED_ACCESS_KEY_ID: &str = "default";

/// Who made the call, as a record names them: the three `userIdentity` facts a serving
/// service can read off the request itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedCaller {
    /// The access key id the request was signed with, when it carried one.
    pub access_key_id: Option<String>,
    /// `userIdentity.type` — one of the `PRINCIPAL_TYPE_*` constants.
    pub principal_type: &'static str,
    /// The user name the caller speaks for, when the emulator can resolve one.
    pub user_name: Option<String>,
}

/// Who made the request, from the credential scope it was signed with.
///
/// ONE rule for every service that records a call, so two services recording the same
/// caller report the same `userIdentity`. An unsigned request names no caller:
/// `extract_akid` answers the sentinel `"default"` for one, which is reported as an
/// ABSENT key and the unknown principal type rather than as a key with that id.
pub fn recorded_caller(parts: &http::request::Parts) -> RecordedCaller {
    let access_key_id = ::emulator_server::extract_akid(&parts.headers);
    let access_key_id = (access_key_id != UNSIGNED_ACCESS_KEY_ID).then_some(access_key_id);
    let principal_type = match access_key_id.as_deref() {
        None => PRINCIPAL_TYPE_UNKNOWN,
        Some(key) if key.starts_with(TEMPORARY_ACCESS_KEY_PREFIX) => PRINCIPAL_TYPE_ASSUMED_ROLE,
        Some(_) => PRINCIPAL_TYPE_IAM_USER,
    };
    RecordedCaller {
        access_key_id,
        principal_type,
        user_name: (principal_type == PRINCIPAL_TYPE_IAM_USER)
            .then(|| AMBIENT_USER_NAME.to_string()),
    }
}

/// The request's `User-Agent`, when it sent one — an event's `userAgent`.
pub fn recorded_user_agent(parts: &http::request::Parts) -> Option<String> {
    parts
        .headers
        .get(http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
}

/// The `requestParameters` / `responseElements` of a record, from the members a request
/// carried or a response answered with.
///
/// A member that was ABSENT is left out rather than recorded as null: CloudTrail records
/// what the call actually carried, so a lookup reading the event back cannot tell an
/// absent member from one explicitly set to null if nulls are written. Members are named
/// as the event document names them — the modelled member name with a lower-case first
/// letter.
pub fn recorded_members<const N: usize>(
    members: [(&str, serde_json::Value); N],
) -> serde_json::Value {
    members
        .into_iter()
        .filter(|(_, value)| !value.is_null())
        .map(|(name, value)| (name.to_string(), value))
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into()
}

/// What a record carries in place of a value the serving API declares SENSITIVE.
///
/// CloudTrail does not store such a value at all — it substitutes this fixed literal, so
/// a password a caller sent appears nowhere in event history while the record still shows
/// that the member was carried. The literal is CloudTrail's own, not this emulator's
/// invention, so it is stated once here and used by every recorder.
pub const HIDDEN_SENSITIVE_VALUE: &str = "HIDDEN_DUE_TO_SECURITY_REASONS";

/// The members whose values a record does NOT carry, and HOW each one is withheld.
///
/// Both sets hold MODELLED member names, so a set answers for every operation that
/// carries a member of that name. They are separate because the serving API decides which
/// of the two withholdings its records use, and the two are observably different to a
/// client reading event history back:
///
/// * a REDACTED member is present in the document with [`HIDDEN_SENSITIVE_VALUE`] as its
///   value, so the record still shows that the call carried it;
/// * an OMITTED member is absent from the document altogether — there is no key for it at
///   all, which is how a record of a call whose defining property is that the credential
///   material was never persisted can be told apart from one that stored a placeholder.
///
/// A member named in neither set is recorded as the call carried it.
#[derive(Debug, Clone, Copy, Default)]
pub struct WithheldFromRecord<'a> {
    /// Members whose value is replaced by [`HIDDEN_SENSITIVE_VALUE`].
    pub redacted: &'a [&'a str],
    /// Members the record leaves out entirely, value and key both.
    pub omitted: &'a [&'a str],
}

/// The member NAME a record spells a modelled member with: the modelled name with a
/// lower-case first letter (`DBInstanceIdentifier` -> `dBInstanceIdentifier`), which is
/// how a CloudTrail event document names the members of the call it records.
///
/// Only the first character changes: the rest of the name keeps the model's own casing,
/// so a member whose name is already lower-case first is recorded unchanged.
#[must_use]
pub fn recorded_member_name(modelled: &str) -> String {
    let mut chars = modelled.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
    }
}

/// How deep into a value a record goes. A record is a report of ONE call, so the depth is
/// bounded rather than sized by the value: a shape nested deeper than this is reported
/// only down to this level.
const MAX_RECORDED_DEPTH: usize = 16;

/// How many values one recorded document holds. The same reason as [`MAX_RECORDED_DEPTH`]:
/// every served call appends a record, so one record's size is bounded here rather than by
/// what the caller sent.
const MAX_RECORDED_VALUES: usize = 1_024;

/// One built shape — a request's input or a response's output — as the JSON document a
/// record carries it in (`requestParameters` / `responseElements`).
///
/// SCHEMA-DRIVEN, so it holds for every modelled shape rather than per operation: the walk
/// is the framework's own [`SerializableStruct`] walk, each member named as
/// [`recorded_member_name`] spells it, and a member that was ABSENT is simply never
/// written (the generated walk writes nothing for an unset optional member), which is what
/// keeps an absent member out of the record rather than in it as null.
///
/// `withheld` names the members whose values this record does not carry: a value held at a
/// REDACTED one — a leaf, or a whole subtree — is replaced by [`HIDDEN_SENSITIVE_VALUE`],
/// and one held at an OMITTED member is left out of the document entirely. Neither is
/// read, so the plaintext reaches no record either way (see [`WithheldFromRecord`]).
#[must_use]
pub fn recorded_shape(
    value: &dyn ::aws_smithy_schema::serde::SerializableStruct,
    schema: &::aws_smithy_schema::Schema,
    withheld: WithheldFromRecord<'_>,
) -> serde_json::Value {
    let mut walk = RecordedShape {
        stack: Vec::new(),
        root: serde_json::Value::Null,
        withheld,
        written: 0,
    };
    // The root of a request or a response is a structure; drive it the way a codec does.
    // A walk that cannot finish leaves the document built so far: a record reports a call
    // that was already served, so failing to render one is never a failure of the call.
    let _ = ::aws_smithy_schema::serde::ShapeSerializer::write_struct(&mut walk, schema, value);
    walk.root
}

/// An in-progress container of the document [`recorded_shape`] builds.
enum RecordedFrame {
    /// A structure, keyed by the names its members are recorded under.
    Structure(serde_json::Map<String, serde_json::Value>),
    /// A list, in the order its elements were written.
    List(Vec<serde_json::Value>),
    /// A map: its entries arrive as alternating keys and values on the same walk, so which
    /// one comes next is state.
    Map {
        entries: serde_json::Map<String, serde_json::Value>,
        pending_key: Option<String>,
        expecting_key: bool,
    },
}

/// The [`ShapeSerializer`](::aws_smithy_schema::serde::ShapeSerializer) that builds a
/// record's JSON document; see [`recorded_shape`].
struct RecordedShape<'a> {
    /// The containers currently open, outermost first.
    stack: Vec<RecordedFrame>,
    /// The finished document, once the outermost container closes.
    root: serde_json::Value,
    /// The members whose values are never stored, and how each is withheld.
    withheld: WithheldFromRecord<'a>,
    /// How many values have been written, against [`MAX_RECORDED_VALUES`].
    written: usize,
}

impl RecordedShape<'_> {
    /// Whether `schema` names a member the serving model declares sensitive.
    ///
    /// Matched on the member's own MODELLED name, which is how a service states its
    /// sensitive members — not the lower-first-letter spelling the finished record uses.
    fn is_sensitive(&self, schema: &::aws_smithy_schema::Schema) -> bool {
        schema
            .member_name()
            .is_some_and(|name| self.withheld.redacted.contains(&name))
    }

    /// Whether `schema` names a member the serving API's records leave OUT: nothing at all
    /// is written for it, so the finished document carries no key for it.
    ///
    /// Matched on the member's own MODELLED name, exactly as [`Self::is_sensitive`] is.
    fn is_omitted(&self, schema: &::aws_smithy_schema::Schema) -> bool {
        schema
            .member_name()
            .is_some_and(|name| self.withheld.omitted.contains(&name))
    }

    /// Whether this walk has already written everything one record holds.
    fn full(&self) -> bool {
        self.written >= MAX_RECORDED_VALUES || self.stack.len() > MAX_RECORDED_DEPTH
    }

    /// Account for a value this walk did NOT write.
    ///
    /// A map's entries arrive as alternating keys and values on one walk, so a write that
    /// is skipped still has to advance that alternation — otherwise the next key would be
    /// taken for a value and the recorded map would pair the wrong things. The entry whose
    /// half was skipped is dropped whole, which leaves an unwritten value out of the
    /// record rather than under a key it does not belong to.
    fn skipped(&mut self) {
        if let Some(RecordedFrame::Map {
            pending_key,
            expecting_key,
            ..
        }) = self.stack.last_mut()
        {
            *pending_key = None;
            *expecting_key = !*expecting_key;
        }
    }

    /// Put `value` where the walk currently is: under its member name inside a structure,
    /// at the end of a list, as a map's key or its value, or as the whole document when no
    /// container is open.
    fn place(&mut self, schema: &::aws_smithy_schema::Schema, value: serde_json::Value) {
        self.written += 1;
        match self.stack.last_mut() {
            None => self.root = value,
            Some(RecordedFrame::Structure(members)) => {
                let name = schema
                    .member_name()
                    .map_or_else(|| schema.shape_id().shape_name().to_string(), |name| {
                        recorded_member_name(name)
                    });
                members.insert(name, value);
            }
            Some(RecordedFrame::List(elements)) => elements.push(value),
            Some(RecordedFrame::Map {
                entries,
                pending_key,
                expecting_key,
            }) => {
                if *expecting_key {
                    // A map key is a string on the wire, and is recorded as the key it is.
                    *pending_key = Some(match value {
                        serde_json::Value::String(key) => key,
                        other => other.to_string(),
                    });
                } else {
                    let key = pending_key.take().unwrap_or_default();
                    entries.insert(key, value);
                }
                *expecting_key = !*expecting_key;
            }
        }
    }

    /// Open `frame`, write the composite's children into it, then close it and place the
    /// composite itself.
    fn composite(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        frame: RecordedFrame,
        write_children: &dyn Fn(
            &mut dyn ::aws_smithy_schema::serde::ShapeSerializer,
        ) -> Result<(), ::aws_smithy_schema::serde::SerdeError>,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        if self.is_sensitive(schema) {
            self.place(
                schema,
                serde_json::Value::String(HIDDEN_SENSITIVE_VALUE.to_string()),
            );
            return Ok(());
        }
        // An omitted member is not walked at all: its children are inside it, so leaving
        // the composite out leaves every value it held out with it.
        if self.is_omitted(schema) || self.full() {
            self.skipped();
            return Ok(());
        }
        self.stack.push(frame);
        let out = write_children(self);
        let closed = match self.stack.pop() {
            Some(RecordedFrame::Structure(members)) => serde_json::Value::Object(members),
            Some(RecordedFrame::List(elements)) => serde_json::Value::Array(elements),
            Some(RecordedFrame::Map { entries, .. }) => serde_json::Value::Object(entries),
            // Unreachable: the frame just pushed is the one popped here.
            None => serde_json::Value::Null,
        };
        self.place(schema, closed);
        out
    }

    /// Place one leaf, or the redaction literal when the member it fills is sensitive.
    fn leaf(&mut self, schema: &::aws_smithy_schema::Schema, value: serde_json::Value) {
        if self.is_sensitive(schema) {
            self.place(
                schema,
                serde_json::Value::String(HIDDEN_SENSITIVE_VALUE.to_string()),
            );
            return;
        }
        if self.is_omitted(schema) || self.full() {
            self.skipped();
            return;
        }
        self.place(schema, value);
    }

    /// A Smithy `document` as the JSON it already is, BOUNDED like the rest of the walk.
    ///
    /// A document's shape is the caller's to choose, so neither its depth nor its size is
    /// the record's to follow: `depth` stops at [`MAX_RECORDED_DEPTH`] — which is what
    /// keeps this recursion shallow whatever the request nested — and every value
    /// produced counts against [`MAX_RECORDED_VALUES`], the same budget the schema walk
    /// spends. A collection stops producing values the moment that budget is spent and
    /// carries ONE [`TRUNCATED_BY_RECORD_LIMIT`] entry saying where the walk stopped, so
    /// what the record holds is sized by the budget and not by how many elements the
    /// request nested.
    fn recorded_document(
        &mut self,
        value: &::aws_smithy_types::Document,
        depth: usize,
    ) -> serde_json::Value {
        use ::aws_smithy_types::{Document, Number};

        self.written += 1;
        if depth >= MAX_RECORDED_DEPTH || self.written >= MAX_RECORDED_VALUES {
            return serde_json::Value::String(TRUNCATED_BY_RECORD_LIMIT.to_string());
        }
        match value {
            Document::Null => serde_json::Value::Null,
            Document::Bool(flag) => serde_json::json!(flag),
            Document::String(text) => serde_json::json!(text),
            Document::Number(Number::PosInt(number)) => serde_json::json!(number),
            Document::Number(Number::NegInt(number)) => serde_json::json!(number),
            Document::Number(Number::Float(number)) => serde_json::json!(number),
            Document::Array(elements) => {
                let mut recorded = Vec::new();
                for element in elements {
                    if self.written >= MAX_RECORDED_VALUES {
                        recorded.push(serde_json::Value::String(
                            TRUNCATED_BY_RECORD_LIMIT.to_string(),
                        ));
                        break;
                    }
                    recorded.push(self.recorded_document(element, depth + 1));
                }
                serde_json::Value::Array(recorded)
            }
            Document::Object(members) => {
                let mut recorded = serde_json::Map::new();
                for (name, member) in members {
                    if self.written >= MAX_RECORDED_VALUES {
                        recorded.insert(
                            TRUNCATED_BY_RECORD_LIMIT.to_string(),
                            serde_json::Value::Null,
                        );
                        break;
                    }
                    recorded.insert(name.clone(), self.recorded_document(member, depth + 1));
                }
                serde_json::Value::Object(recorded)
            }
        }
    }
}

impl ::aws_smithy_schema::serde::ShapeSerializer for RecordedShape<'_> {
    fn write_struct(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        value: &dyn ::aws_smithy_schema::serde::SerializableStruct,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        let write_members = |s: &mut dyn ::aws_smithy_schema::serde::ShapeSerializer| {
            value.serialize_members(s)
        };
        self.composite(
            schema,
            RecordedFrame::Structure(serde_json::Map::new()),
            &write_members,
        )
    }

    fn write_list(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        write_elements: &dyn Fn(
            &mut dyn ::aws_smithy_schema::serde::ShapeSerializer,
        ) -> Result<(), ::aws_smithy_schema::serde::SerdeError>,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        self.composite(schema, RecordedFrame::List(Vec::new()), write_elements)
    }

    fn write_map(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        write_entries: &dyn Fn(
            &mut dyn ::aws_smithy_schema::serde::ShapeSerializer,
        ) -> Result<(), ::aws_smithy_schema::serde::SerdeError>,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        self.composite(
            schema,
            RecordedFrame::Map {
                entries: serde_json::Map::new(),
                pending_key: None,
                expecting_key: true,
            },
            write_entries,
        )
    }

    fn write_boolean(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        value: bool,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        self.leaf(schema, serde_json::json!(value));
        Ok(())
    }

    fn write_byte(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        value: i8,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        self.leaf(schema, serde_json::json!(value));
        Ok(())
    }

    fn write_short(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        value: i16,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        self.leaf(schema, serde_json::json!(value));
        Ok(())
    }

    fn write_integer(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        value: i32,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        self.leaf(schema, serde_json::json!(value));
        Ok(())
    }

    fn write_long(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        value: i64,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        self.leaf(schema, serde_json::json!(value));
        Ok(())
    }

    fn write_float(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        value: f32,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        self.leaf(schema, serde_json::json!(value));
        Ok(())
    }

    fn write_double(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        value: f64,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        self.leaf(schema, serde_json::json!(value));
        Ok(())
    }

    fn write_big_integer(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        value: &::aws_smithy_types::BigInteger,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        // A big integer and a big decimal travel as their digits, which is how a record
        // reports one: a JSON number cannot hold either without losing precision.
        self.leaf(schema, serde_json::json!(value.as_ref()));
        Ok(())
    }

    fn write_big_decimal(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        value: &::aws_smithy_types::BigDecimal,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        self.leaf(schema, serde_json::json!(value.as_ref()));
        Ok(())
    }

    fn write_string(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        value: &str,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        self.leaf(schema, serde_json::json!(value));
        Ok(())
    }

    fn write_blob(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        value: &[u8],
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        // A record reports a blob's SIZE, never its bytes: the bytes are the caller's
        // payload, and an event document is not where a payload is stored.
        self.leaf(schema, serde_json::json!(value.len()));
        Ok(())
    }

    fn write_timestamp(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        value: &::aws_smithy_types::DateTime,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        // The ISO 8601 `<date>T<time>Z` rendering, carrying the value's own resolution:
        // this is a member the CALL carried, so what is recorded is the instant the caller
        // sent rather than the second-resolution form an event's own `eventTime` has.
        let rendered = value
            .fmt(::aws_smithy_types::date_time::Format::DateTime)
            .unwrap_or_default();
        self.leaf(schema, serde_json::json!(rendered));
        Ok(())
    }

    fn write_document(
        &mut self,
        schema: &::aws_smithy_schema::Schema,
        value: &::aws_smithy_types::Document,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        // A position whose value is withheld, and one past what this record holds, need
        // no walk of the document at all: `leaf` writes the redaction literal for the
        // first and nothing for the second.
        if self.is_sensitive(schema) || self.is_omitted(schema) || self.full() {
            self.leaf(schema, serde_json::Value::Null);
            return Ok(());
        }
        let document = self.recorded_document(value, 0);
        self.leaf(schema, document);
        Ok(())
    }

    fn write_null(
        &mut self,
        _schema: &::aws_smithy_schema::Schema,
    ) -> Result<(), ::aws_smithy_schema::serde::SerdeError> {
        // Nothing is recorded: CloudTrail records what the call CARRIED, so a member with
        // no value is left out of the document rather than written as null. The position
        // is still accounted for, so a map's key/value alternation stays in step.
        self.skipped();
        Ok(())
    }
}

/// What a record carries in place of a part of a `document` member that lies past the
/// walk's ceilings ([`MAX_RECORDED_DEPTH`] / [`MAX_RECORDED_VALUES`]).
///
/// An EMULATOR ceiling, not anything CloudTrail does: a `document` member's shape is the
/// caller's to choose, so the walk over one is bounded like every other part of a record
/// and says where it stopped rather than reporting a value it did not read.
pub const TRUNCATED_BY_RECORD_LIMIT: &str = "(truncated: past this record's limit)";

/// How many bytes of JSON one record's `requestParameters` or `responseElements` may
/// carry.
///
/// Another EMULATOR ceiling, for the same reason as [`MAX_RECORDED_VALUES`] and
/// independent of how a walk terminated: the values a request carries are sized by the
/// caller, every served call appends a record, and the log keeps up to
/// [`MAX_RECORDED_EVENTS`] of them, so one record's footprint is capped here rather than
/// by what was sent. A document past it is replaced WHOLE by
/// [`TRUNCATED_BY_RECORD_LIMIT`]: a record that says it withheld the parameters is
/// honest, while one holding half a document would not be.
pub const MAX_RECORDED_DOCUMENT_BYTES: usize = 64 * 1024;

/// `document` as a record carries it: itself when its JSON fits in
/// [`MAX_RECORDED_DOCUMENT_BYTES`], else the truncation marker alone.
fn within_record_limit(document: serde_json::Value) -> serde_json::Value {
    // `to_string` renders exactly the bytes the record would carry, so the measurement is
    // of the document itself rather than of an estimate.
    if document.to_string().len() <= MAX_RECORDED_DOCUMENT_BYTES {
        document
    } else {
        serde_json::Value::String(TRUNCATED_BY_RECORD_LIMIT.to_string())
    }
}

/// The error code and message an outcome carries: `(None, None)` for a success.
///
/// Read off the operation's own error channel, so the code a record carries is the FAULT
/// SHAPE's own name — which is what CloudTrail records, and not always the code the
/// caller saw: a query-protocol error renders its `awsQueryError` code on the wire
/// (`DBInstanceNotFound`) while the record names the shape (`DBInstanceNotFoundFault`).
/// The modelled error's `Display` prefixes that same shape name, which the record already
/// carries as its `errorCode`, so the message is recorded alone.
pub fn recorded_failure<T, E>(outcome: &Result<T, E>) -> (Option<String>, Option<String>)
where
    E: ::smithy_server_runtime::OperationError + std::fmt::Display,
{
    match outcome {
        Ok(_) => (None, None),
        Err(error) => {
            let rendered = error.to_string();
            let message = rendered
                .strip_prefix(&format!("{}: ", error.shape_name()))
                .unwrap_or(&rendered)
                .to_string();
            (Some(error.shape_name().to_string()), Some(message))
        }
    }
}

/// The `requestParameters` a record carries for a call, given whether the serving API
/// STOPPED that call AT AUTHORIZATION — refused it for want of permission before the
/// operation acted on the request at all.
///
/// Such a call is recorded with no request parameters and no response elements, JSON `null`
/// for both: the parameters report what a call that was authorized and DISPATCHED carried,
/// so the record of a refusal says that a caller asked for an action it may not perform and
/// not what the body of the refused request held. That is the contrast a reader of event
/// history separates the two by — parameters present on a call the service acted on, absent
/// on one stopped at the permission check — and it is what keeps a denied request's own
/// input out of the audit trail.
///
/// Every other call records `parameters` as it carried them, a failure the OPERATION
/// answered included (a resource that is not there, a document that does not admit the
/// request, a quota): such a call was dispatched, and what it was dispatched with is what a
/// reader auditing it needs.
///
/// WHICH refusals are the first kind is the serving API's own fact and not this function's
/// (see [`crate::audited_operation::AuditedService::stopped_at_authorization`]): two
/// services answer the same status for refusals decided in different places, one before the
/// operation runs and one by the operation itself.
#[must_use]
pub fn recorded_request_parameters(
    parameters: serde_json::Value,
    stopped_at_authorization: bool,
) -> serde_json::Value {
    if stopped_at_authorization {
        serde_json::Value::Null
    } else {
        parameters
    }
}

/// One resource an event refers to: the pair CloudTrail reports in an event's
/// `Resources`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditedResource {
    /// E.g. `AWS::CloudTrail::Trail`.
    pub resource_type: String,
    /// The name (or ARN) of the resource the call acted on.
    pub resource_name: String,
}

impl AuditedResource {
    /// The resource of `resource_type` named `resource_name`.
    pub fn new(resource_type: impl Into<String>, resource_name: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            resource_name: resource_name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// The session a temporary credential belongs to
// ---------------------------------------------------------------------------

/// Who ISSUED the session a temporary credential belongs to, as a record names it in
/// `userIdentity.sessionContext.sessionIssuer` — "the role that was assumed", which is the
/// resource an action taken through a shared role is attributed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedSessionIssuer {
    /// `sessionIssuer.type`: [`SESSION_ISSUER_TYPE_ROLE`] for an assumed role.
    pub principal_type: String,
    /// The unique id of the issuing entity — the role id for an assumed role.
    pub principal_id: String,
    /// The ARN of the issuing entity: the ROLE's own ARN, never the session's.
    pub arn: String,
    /// The account that holds it.
    pub account_id: String,
    /// Its friendly name — the role name for an assumed role.
    pub user_name: String,
}

/// What a record names about the SESSION a call's temporary credential belongs to.
///
/// A session is minted by one service (STS, or a service that assumes a role on a
/// caller's behalf) and the calls made WITH it are served by every other, so these facts
/// live in the shared [`SessionAuditDirectory`] rather than in the minting service's own
/// state: the service that records a call is the one that needs them, and it cannot read
/// another service's store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedSession {
    /// `userIdentity.type` of a call made with the session: one of the `PRINCIPAL_TYPE_*`
    /// constants.
    pub principal_type: String,
    /// `userIdentity.principalId` — `<RoleId>:<RoleSessionName>` for an assumed role.
    pub principal_id: String,
    /// `userIdentity.arn`: the session's own ARN (`…:assumed-role/<role>/<session>`).
    pub arn: String,
    /// The account the session belongs to.
    pub account_id: String,
    /// The friendly name the session speaks under, which CloudTrail reports as an event's
    /// `Username`: the role session name for an assumed role.
    pub user_name: Option<String>,
    /// The role or user that issued the session, when the emulator holds one.
    pub issuer: Option<RecordedSessionIssuer>,
    /// The source identity the session carries, when it carries one — "the source identity
    /// value persists across chained role sessions", so a chained session carries the value
    /// its caller carried. `None` for a session assumed without one, which is what leaves
    /// `sessionContext.sourceIdentity` out of the record altogether.
    pub source_identity: Option<String>,
    /// When the session was minted, as `sessionContext.attributes.creationDate`.
    pub created_at: SystemTime,
    /// When the credential stops being valid — the instant past which no call can be made
    /// with it, which is what bounds this directory (see
    /// [`SessionAuditDirectory::remember`]).
    pub expires_at: SystemTime,
}

/// How many sessions the directory holds at once.
///
/// An EMULATOR ceiling, not an AWS quota: minting a session is a request-driven insert, so
/// the directory needs a declared cap. The session whose credential expires SOONEST gives
/// way first, so the sessions still able to make a call are the ones that survive.
pub const MAX_AUDITED_SESSIONS: usize = 8_192;

/// The account's directory of live sessions, keyed by the access key id each was minted
/// under: what a recorder needs to name the session a call was made with.
///
/// Held once in the shared engine, like the log itself — written by the service that MINTS
/// a session and read by every service that records a call — so the two cannot hold two
/// different accounts of one session.
///
/// A record keeps its OWN copy of these facts at the instant it is written, so forgetting
/// a session here never changes what an already-recorded event reports.
#[derive(Debug, Default)]
pub struct SessionAuditDirectory {
    /// Every remembered session, keyed by its access key id. At most
    /// [`MAX_AUDITED_SESSIONS`] entries.
    sessions: HashMap<String, RecordedSession>,
}

impl SessionAuditDirectory {
    /// Remember the session minted under `access_key_id`.
    ///
    /// Prunes first: a session whose credential the clock has already expired can make no
    /// further call, so its entry is dropped — owed at this instant whether or not anybody
    /// minted anything — and at [`MAX_AUDITED_SESSIONS`] the entry expiring soonest gives
    /// way, so no path can push the directory past the cap.
    pub fn remember(
        &mut self,
        access_key_id: impl Into<String>,
        session: RecordedSession,
        now: SystemTime,
    ) {
        self.prune(now);
        self.sessions.insert(access_key_id.into(), session);
    }

    /// The session an access key id names, or `None` for a credential this directory holds
    /// no session for (a long-term key, or a session minted before it was remembered).
    pub fn session(&self, access_key_id: &str) -> Option<&RecordedSession> {
        self.sessions.get(access_key_id)
    }

    /// Forget the session minted under `access_key_id` — for a mint the minting service
    /// gave up again, so the directory never names a credential that was never handed out.
    pub fn forget(&mut self, access_key_id: &str) {
        self.sessions.remove(access_key_id);
    }

    /// How many sessions the directory holds.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether the directory holds no session at all.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Drop what the clock has already made unusable, then make room under the cap.
    ///
    /// Called BEFORE an entry is added, which is why the count test is `>=`: it leaves room
    /// for the entry about to be inserted.
    fn prune(&mut self, now: SystemTime) {
        self.sessions.retain(|_, session| now < session.expires_at);
        while self.sessions.len() >= MAX_AUDITED_SESSIONS {
            let soonest = self
                .sessions
                .iter()
                .min_by(|(one_key, one), (other_key, other)| {
                    (one.expires_at, one_key.as_str()).cmp(&(other.expires_at, other_key.as_str()))
                })
                .map(|(key, _)| key.clone());
            match soonest {
                Some(key) => {
                    self.sessions.remove(&key);
                }
                None => break,
            }
        }
    }
}

/// What the service that SERVED a call knows about it — everything in a record except
/// the identifiers and the instant the log itself stamps.
#[derive(Debug, Clone)]
pub struct ServedApiCall {
    /// The API operation's name, as the model spells it (`CreateTrail`).
    pub event_name: String,
    /// The service the call was made to, in CloudTrail's `<endpoint-prefix>.amazonaws.com`
    /// form.
    pub event_source: String,
    /// The Region the call was served in.
    pub aws_region: String,
    /// Whether the call only READ state. CloudTrail records this as the event's
    /// `readOnly`, and `LookupEvents` can filter on it.
    pub read_only: bool,
    /// The access key id the request was signed with, when it carried one.
    pub access_key_id: Option<String>,
    /// The user (or role) name the caller speaks for, when the emulator can resolve one.
    pub user_name: Option<String>,
    /// `userIdentity.type` — one of the `PRINCIPAL_TYPE_*` constants.
    pub principal_type: String,
    /// The unique identifier of the entity that made the call, as CloudTrail reports it in
    /// `userIdentity.principalId`. `None` leaves the resolution to the record: the
    /// principal a long-term credential speaks for is the account's own IAM user, whose
    /// unique id is stated once by [`crate::caller_principal`], and a principal this
    /// emulator cannot identify at all is recorded without the field. A recorder that
    /// knows an id of its own — one it minted for a federated session, say — states it
    /// here.
    pub principal_id: Option<String>,
    /// The EXTERNAL identity provider that authenticated the caller, for a call made on
    /// behalf of a federated user: CloudTrail reports it as `userIdentity.identityProvider`
    /// ("the principal name of the external identity provider"). `None` for a caller this
    /// account authenticated itself, which is every call signed with an AWS credential.
    pub identity_provider: Option<String>,
    /// The SESSION the call's temporary credential belongs to, for a call made with one:
    /// what the record carries as `userIdentity.sessionContext` (and as the session's own
    /// `userIdentity.arn`). `None` for a call made with a long-term credential or with none
    /// at all, which is what leaves the whole block out of the record — the twin of a
    /// session that carries no source identity, whose record carries the block without a
    /// `sourceIdentity`.
    pub session: Option<RecordedSession>,
    /// The account the call was served for.
    pub account_id: String,
    /// The request's `User-Agent`, when it sent one.
    pub user_agent: Option<String>,
    /// The resources the call acted on.
    pub resources: Vec<AuditedResource>,
    /// The request's parameters, as the event's `requestParameters` — JSON null for a call
    /// that was not dispatched at all, which is what
    /// [`recorded_request_parameters`] answers for one stopped at authorization.
    pub request_parameters: serde_json::Value,
    /// The response's values, as the event's `responseElements`; `None` for a call that
    /// failed or that returns nothing.
    pub response_elements: Option<serde_json::Value>,
    /// The wire error code the call answered with, for a call that failed.
    pub error_code: Option<String>,
    /// The message that went with [`ServedApiCall::error_code`].
    pub error_message: Option<String>,
}

/// One recorded event: a [`ServedApiCall`] plus the identifiers and the instant the log
/// stamped it with.
#[derive(Debug, Clone)]
pub struct ManagementEvent {
    /// The log's own ordinal for this record. Strictly increasing, so two events
    /// recorded in the same millisecond still have one definite order.
    pub seq: u64,
    /// The event's `eventID` / CloudTrail `EventId`.
    pub event_id: String,
    /// The `requestID` of the call the event records.
    pub request_id: String,
    /// When the call was served.
    pub event_time: SystemTime,
    /// One of [`EVENT_CATEGORY_MANAGEMENT`] / [`EVENT_CATEGORY_INSIGHT`].
    pub event_category: String,
    /// What the serving service reported.
    pub call: ServedApiCall,
    /// OnCallWorlds patch: a record loaded from a seed, reported exactly as given.
    pub verbatim: Option<serde_json::Value>,
}

impl ManagementEvent {
    /// The record's time as whole milliseconds since the epoch — the resolution a
    /// caller-supplied lookup window is compared at.
    pub fn event_time_millis(&self) -> i64 {
        self.event_time
            .duration_since(UNIX_EPOCH)
            .map(|since| i64::try_from(since.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }

    /// The record as the JSON document CloudTrail puts in an event's `CloudTrailEvent`.
    ///
    /// Only what this emulator actually knows is written: a field it cannot determine
    /// (the caller's source IP, a principal id for an unknown credential) is left out
    /// rather than filled with a made-up value.
    pub fn to_cloudtrail_event_json(&self) -> serde_json::Value {
        if let Some(record) = &self.verbatim {
            return record.clone();
        }
        let call = &self.call;
        let mut identity = serde_json::Map::new();
        identity.insert(
            "type".to_string(),
            serde_json::Value::String(call.principal_type.clone()),
        );
        identity.insert(
            "accountId".to_string(),
            serde_json::Value::String(call.account_id.clone()),
        );
        // The IAM entity the call's principal IS, for the one principal this emulator can
        // resolve: a long-term credential speaks for the account's single IAM user, whose
        // ARN and unique id are stated once by [`crate::caller_principal`] — the same two
        // values STS answers `GetCallerIdentity` with and IAM holds for that user. So a
        // client that reads its own identity finds its calls' records naming it, rather
        // than a `userIdentity` that names a user without naming who it is. A principal
        // this emulator cannot resolve (a session, an unsigned request) is left without
        // either field rather than given a made-up one.
        let ambient_principal = call.principal_type == PRINCIPAL_TYPE_IAM_USER
            && call.user_name.as_deref() == Some(AMBIENT_USER_NAME);
        if ambient_principal {
            identity.insert(
                "arn".to_string(),
                serde_json::Value::String(crate::caller_principal::ambient_user_arn()),
            );
        }
        match (&call.principal_id, ambient_principal) {
            (Some(principal_id), _) => {
                identity.insert(
                    "principalId".to_string(),
                    serde_json::Value::String(principal_id.clone()),
                );
            }
            (None, true) => {
                identity.insert(
                    "principalId".to_string(),
                    serde_json::Value::String(crate::caller_principal::ambient_user_id()),
                );
            }
            (None, false) => {}
        }
        if let Some(access_key_id) = &call.access_key_id {
            identity.insert(
                "accessKeyId".to_string(),
                serde_json::Value::String(access_key_id.clone()),
            );
        }
        // The friendly name of the identity that made the call. CloudTrail reports
        // `userIdentity.userName` for an identity that HAS a name of its own — an IAM user,
        // including one calling with its own session-token credentials, and a user an
        // external provider authenticated — and reports none for the two principal types
        // whose name belongs to another entity: an assumed role, whose role name is in
        // `sessionContext.sessionIssuer.userName`, and a federated user, named by its own
        // ARN. The name still names the EVENT whatever the type (CloudTrail's
        // `Event$Username`, which a lookup filters on), which is what `user_name` carries.
        let named_by_another_entity = matches!(
            call.principal_type.as_str(),
            PRINCIPAL_TYPE_ASSUMED_ROLE | PRINCIPAL_TYPE_FEDERATED_USER
        );
        if let (Some(user_name), false) = (&call.user_name, named_by_another_entity) {
            identity.insert(
                "userName".to_string(),
                serde_json::Value::String(user_name.clone()),
            );
        }
        if let Some(identity_provider) = &call.identity_provider {
            identity.insert(
                "identityProvider".to_string(),
                serde_json::Value::String(identity_provider.clone()),
            );
        }
        if let Some(session) = &call.session {
            // The session's own ARN, and the block CloudTrail reports a temporary
            // credential's session in: the entity that issued it, when the emulator holds
            // one, and the source identity it carries, which is absent for a session
            // assumed without one.
            identity.insert(
                "arn".to_string(),
                serde_json::Value::String(session.arn.clone()),
            );
            let mut context = serde_json::Map::new();
            if let Some(issuer) = &session.issuer {
                context.insert(
                    "sessionIssuer".to_string(),
                    serde_json::json!({
                        "type": issuer.principal_type,
                        "principalId": issuer.principal_id,
                        "arn": issuer.arn,
                        "accountId": issuer.account_id,
                        "userName": issuer.user_name,
                    }),
                );
            }
            context.insert(
                "attributes".to_string(),
                serde_json::json!({"creationDate": iso8601(session.created_at)}),
            );
            if let Some(source_identity) = &session.source_identity {
                context.insert(
                    "sourceIdentity".to_string(),
                    serde_json::Value::String(source_identity.clone()),
                );
            }
            identity.insert("sessionContext".to_string(), context.into());
        }

        let mut event = serde_json::Map::new();
        event.insert(
            "eventVersion".to_string(),
            serde_json::Value::String(EVENT_VERSION.to_string()),
        );
        event.insert("userIdentity".to_string(), identity.into());
        event.insert(
            "eventTime".to_string(),
            serde_json::Value::String(iso8601(self.event_time)),
        );
        event.insert(
            "eventSource".to_string(),
            serde_json::Value::String(call.event_source.clone()),
        );
        event.insert(
            "eventName".to_string(),
            serde_json::Value::String(call.event_name.clone()),
        );
        event.insert(
            "awsRegion".to_string(),
            serde_json::Value::String(call.aws_region.clone()),
        );
        if let Some(user_agent) = &call.user_agent {
            event.insert(
                "userAgent".to_string(),
                serde_json::Value::String(user_agent.clone()),
            );
        }
        if let Some(error_code) = &call.error_code {
            event.insert(
                "errorCode".to_string(),
                serde_json::Value::String(error_code.clone()),
            );
        }
        if let Some(error_message) = &call.error_message {
            event.insert(
                "errorMessage".to_string(),
                serde_json::Value::String(error_message.clone()),
            );
        }
        event.insert(
            "requestParameters".to_string(),
            call.request_parameters.clone(),
        );
        event.insert(
            "responseElements".to_string(),
            call.response_elements
                .clone()
                .unwrap_or(serde_json::Value::Null),
        );
        event.insert(
            "requestID".to_string(),
            serde_json::Value::String(self.request_id.clone()),
        );
        event.insert(
            "eventID".to_string(),
            serde_json::Value::String(self.event_id.clone()),
        );
        event.insert(
            "readOnly".to_string(),
            serde_json::Value::Bool(call.read_only),
        );
        event.insert(
            "eventType".to_string(),
            serde_json::Value::String(EVENT_TYPE_AWS_API_CALL.to_string()),
        );
        event.insert(
            "managementEvent".to_string(),
            serde_json::Value::Bool(self.event_category == EVENT_CATEGORY_MANAGEMENT),
        );
        event.insert(
            "recipientAccountId".to_string(),
            serde_json::Value::String(call.account_id.clone()),
        );
        event.insert(
            "eventCategory".to_string(),
            serde_json::Value::String(self.event_category.clone()),
        );
        event.into()
    }
}

/// The log: every recorded event, oldest first.
///
/// Reached through the shared engine (`engine.state::<ManagementEventLog>()`) so the
/// service that records a call and the service that reports it hold ONE log and not two
/// copies of it.
#[derive(Debug, Default)]
pub struct ManagementEventLog {
    /// Records in the order they were made, which is the order they were served in.
    events: VecDeque<ManagementEvent>,
    /// The ordinal the next record takes.
    next_seq: u64,
    /// Which trails of the account are LOGGING, keyed by trail ARN — the one fact a
    /// recorded call needs that belongs to CloudTrail: whether the account's CloudTrail
    /// delivers this Region's management events, which is what decides the EventBridge
    /// fan-out ([`Self::record_delivered`]).
    ///
    /// Not a second copy of a trail: a trail's own record — its destination, its tags,
    /// everything `DescribeTrails` reports — stays in CloudTrail's store, which is the only
    /// writer here ([`Self::trails_delivering`]). What is projected is the DELIVERY
    /// decision, because the service that records a call cannot read CloudTrail's store and
    /// the fan-out is decided on the recording path.
    delivering_trails: Vec<DeliveringTrail>,
}

/// Which class of management events a trail logs, as `EventSelector$ReadWriteType` states
/// it: "ReadOnly", "WriteOnly" or "All".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ManagementEventClass {
    /// Read-only calls only.
    ReadOnly,
    /// Write (mutating) calls only.
    WriteOnly,
    /// Both — the class a trail logs by default ("trails created without specific event
    /// selectors will be configured to log all read and write management events").
    #[default]
    All,
}

impl ManagementEventClass {
    /// The class `read_write_type` names, or [`Self::All`] for a value outside the three
    /// the member publishes — which is also what a trail with no selector logs.
    #[must_use]
    pub fn from_read_write_type(read_write_type: Option<&str>) -> Self {
        match read_write_type {
            Some("ReadOnly") => Self::ReadOnly,
            Some("WriteOnly") => Self::WriteOnly,
            _ => Self::All,
        }
    }

    /// Whether a call of this read/write kind falls in the class.
    #[must_use]
    pub fn covers(self, read_only: bool) -> bool {
        match self {
            Self::ReadOnly => read_only,
            Self::WriteOnly => !read_only,
            Self::All => true,
        }
    }
}

/// One trail of the account that is logging, as far as the management-event fan-out is
/// concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveringTrail {
    /// The trail's ARN, which identifies it.
    pub trail_arn: String,
    /// The Region the trail is homed in — the only Region a single-Region trail logs the
    /// REGIONAL services of.
    pub home_region: String,
    /// The bucket the trail delivers its log files into (`Trail$S3BucketName`), where an
    /// audit pipeline reads them ([`crate::trail_log_files`]).
    pub s3_bucket_name: String,
    /// The key prefix the trail's log files land under in that bucket
    /// (`Trail$S3KeyPrefix`): "the Amazon S3 key prefix that comes after the name of the
    /// bucket you have designated for log file delivery". `None` for a trail that carries
    /// none, whose files land at the bucket's root.
    pub s3_key_prefix: Option<String>,
    /// Whether the trail applies to every Region of the account
    /// (`Trail$IsMultiRegionTrail`).
    pub multi_region: bool,
    /// Whether the trail logs the calls of the partition's GLOBAL services
    /// (`Trail$IncludeGlobalServiceEvents`: "whether the trail is publishing events from
    /// global services such as IAM to the log files"), wherever it is homed.
    pub global_service_events: bool,
    /// Whether the trail's selectors include management events at all
    /// (`EventSelector$IncludeManagementEvents`).
    pub management_events: bool,
    /// Which class of management events it logs.
    pub event_class: ManagementEventClass,
}

/// The Region a partition's GLOBAL services record their management events in — the
/// partition's leader Region, which is where a lookup over IAM's or CloudFront's event
/// history is made.
///
/// A trail logging global-service events logs those records wherever the trail is homed,
/// which is what the Region test below reads this constant for.
pub const PARTITION_LEADER_REGION: &str = "us-east-1";

impl DeliveringTrail {
    /// Whether this trail logs a management call served in `region` of the given
    /// read/write kind.
    ///
    /// Three ways a trail covers a Region: it applies to all of them, it is homed in this
    /// one, or it logs global-service events and this is the Region the partition's global
    /// services record in ([`PARTITION_LEADER_REGION`]). The last is read off the Region
    /// alone, which is as far as a projection of the trail can tell: a call of a REGIONAL
    /// service served in the leader Region is admitted by it too.
    #[must_use]
    pub fn logs(&self, region: &str, read_only: bool) -> bool {
        let covers_region = self.multi_region
            || self.home_region == region
            || (self.global_service_events && region == PARTITION_LEADER_REGION);
        self.management_events && self.event_class.covers(read_only) && covers_region
    }
}

impl ManagementEventLog {
    /// Record `call`, served at `at`, as a management event; answer the event's id.
    ///
    /// Prunes first: a record the retention window has run out on, and the oldest
    /// records past [`MAX_RECORDED_EVENTS`], are dropped. Both are owed at this instant
    /// whether or not anybody recorded anything, so the write path is where they are
    /// materialised.
    ///
    /// The parameters and the response a record carries are held to
    /// [`MAX_RECORDED_DOCUMENT_BYTES`] here, where every recorder passes, so one record's
    /// footprint is bounded whatever built the documents.
    pub fn record(&mut self, call: ServedApiCall, at: SystemTime) -> String {
        // No id the caller was answered under is known here, so the record is named by one
        // of its own: see [`record_answered`](Self::record_answered) for the recorder that
        // knows it.
        self.record_answered(call, at, mint_uuid())
    }

    /// Record `call`, served at `at` and answered under `request_id`, as a management
    /// event; answer the event's id.
    ///
    /// `request_id` is the id the CALLER was answered by — the one an SDK reports as the
    /// call's `ResponseMetadata.RequestId` — which is what a record's `requestID` carries:
    /// a client holding a response can then find the record of that very call in event
    /// history, and two records of two calls to one operation are told apart by the call
    /// each of them answered. A recorder that cannot resolve it uses
    /// [`record`](Self::record) instead, which names the record by an id of its own rather
    /// than by one belonging to another response.
    ///
    /// Everything else is [`record`](Self::record)'s: the retention and count bounds are
    /// pruned first, and one record's documents are held to
    /// [`MAX_RECORDED_DOCUMENT_BYTES`].
    pub fn record_answered(
        &mut self,
        mut call: ServedApiCall,
        at: SystemTime,
        request_id: String,
    ) -> String {
        // OnCallWorlds patch: a seeded account's history is the seed's; the emulator's
        // own partial records of the calls it serves would contradict it.
        if ocw_clock::seeded() {
            return mint_uuid();
        }
        self.prune(at);
        call.request_parameters = within_record_limit(call.request_parameters);
        call.response_elements = call.response_elements.map(within_record_limit);
        self.next_seq = self.next_seq.saturating_add(1);
        let event = ManagementEvent {
            seq: self.next_seq,
            event_id: mint_uuid(),
            request_id,
            event_time: at,
            event_category: EVENT_CATEGORY_MANAGEMENT.to_string(),
            call,
            verbatim: None,
        };
        let event_id = event.event_id.clone();
        self.events.push_back(event);
        event_id
    }

    /// Every record, oldest first. The iterator is double-ended, so a reader that
    /// reports the most recent event first walks it in reverse.
    /// OnCallWorlds patch: add one CloudTrail record from a seed. `call` carries what a
    /// lookup filters on; `record` is what it reports. Not pruned: retention is the
    /// lookup's own window, read against the (shifted) clock.
    pub fn insert_seeded(
        &mut self,
        record: serde_json::Value,
        call: ServedApiCall,
        at: SystemTime,
        event_id: String,
        request_id: String,
    ) {
        self.next_seq = self.next_seq.saturating_add(1);
        self.events.push_back(ManagementEvent {
            seq: self.next_seq,
            event_id,
            request_id,
            event_time: at,
            event_category: EVENT_CATEGORY_MANAGEMENT.to_string(),
            call,
            verbatim: Some(record),
        });
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &ManagementEvent> {
        self.events.iter()
    }

    /// Record `call` as [`record_answered`](Self::record_answered) does, and answer what the
    /// account's CloudTrail DELIVERS for it — or `None` when no trail of the account logs a
    /// call of this kind in this Region.
    ///
    /// Two deliveries, one decision. The event a rule on the default bus matches and the
    /// log file an audit pipeline reads are both the CloudTrail record of the call, so the
    /// document published and the documents written are the very document `LookupEvents`
    /// reports and none of them can disagree. What decides whether anything is delivered at
    /// all is the trail projection ([`trails_delivering`](Self::trails_delivering)): the
    /// delivery is CloudTrail's, so it runs while a trail of the Region is logging
    /// management events of the call's read/write class and not otherwise — one log file per
    /// such trail, into the bucket that trail was created with.
    ///
    /// Delivering is the CALLER's: a store holds no transport, and neither the publication
    /// nor the object write must happen under this lock
    /// ([`crate::api_call_events::DeliveredApiCall::deliver`]).
    pub fn record_delivered(
        &mut self,
        call: ServedApiCall,
        at: SystemTime,
        request_id: String,
    ) -> Option<crate::api_call_events::DeliveredApiCall> {
        if ocw_clock::seeded() {
            return None;
        }
        let read_only = call.read_only;
        let region = call.aws_region.clone();
        let account_id = call.account_id.clone();
        let source = crate::api_call_events::event_source_of(&call.event_source);
        self.record_answered(call, at, request_id);
        let logging: Vec<DeliveringTrail> = self
            .delivering_trails
            .iter()
            .filter(|trail| trail.logs(&region, read_only))
            .cloned()
            .collect();
        if logging.is_empty() {
            return None;
        }
        let event = self.events.back()?;
        let record = event.to_cloudtrail_event_json();
        // One file per logging trail, each named for the minute the record belongs to and
        // carrying that record — the file's own instant is the CALL's, not the instant the
        // write is made.
        let log_files = logging
            .iter()
            .filter(|trail| !trail.s3_bucket_name.is_empty())
            .map(|trail| crate::trail_log_files::DeliveredLogFile {
                bucket: trail.s3_bucket_name.clone(),
                key: crate::trail_log_files::log_file_key(
                    trail.s3_key_prefix.as_deref(),
                    &account_id,
                    &region,
                    event.event_time,
                    &crate::trail_log_files::unique_field(),
                ),
                region: region.clone(),
                records: vec![record.clone()],
            })
            .collect();
        Some(crate::api_call_events::DeliveredApiCall {
            source,
            region,
            time_millis: event.event_time_millis(),
            detail: record,
            log_files,
        })
    }

    /// Replace the account's logging trails with `trails` — CloudTrail's own write, made
    /// whenever a trail of the account is created, reconfigured, started, stopped or
    /// deleted, so the projection is never stale between two of those.
    ///
    /// The whole set is replaced rather than one entry amended: CloudTrail recomputes it
    /// from its own store, which is the only account of what is logging, so there is no
    /// state here to fall out of step with it.
    pub fn trails_delivering(&mut self, trails: Vec<DeliveringTrail>) {
        self.delivering_trails = trails;
    }

    /// The account's logging trails, as the last [`trails_delivering`](Self::trails_delivering)
    /// left them.
    #[must_use]
    pub fn delivering_trails(&self) -> &[DeliveringTrail] {
        &self.delivering_trails
    }

    /// Whether the account's CloudTrail delivers a management call served in `region`, of
    /// the given read/write kind, onto the default event bus.
    #[must_use]
    pub fn delivers(&self, region: &str, read_only: bool) -> bool {
        self.delivering_trails
            .iter()
            .any(|trail| trail.logs(region, read_only))
    }

    /// How many records the log holds.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the log holds no record at all.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Drop what the clock has already made unretrievable: records older than
    /// [`EVENT_RETENTION`], then the oldest records above [`MAX_RECORDED_EVENTS`].
    ///
    /// Called BEFORE a record is appended, which is why the count test is `>=`: it
    /// leaves room for the record about to be pushed, so the log settles at exactly
    /// [`MAX_RECORDED_EVENTS`] rather than one above it.
    fn prune(&mut self, now: SystemTime) {
        while self
            .events
            .front()
            .is_some_and(|event| event.event_time + EVENT_RETENTION <= now)
        {
            self.events.pop_front();
        }
        while self.events.len() >= MAX_RECORDED_EVENTS {
            self.events.pop_front();
        }
    }
}

/// Render `at` the way a CloudTrail event's `eventTime` carries it: ISO 8601 at
/// WHOLE-SECOND resolution, `2026-10-22T22:04:46Z`.
///
/// The resolution is part of the format, not an accident of the clock: an event document's
/// `eventTime` is the `yyyy-MM-dd'T'HH:mm:ss'Z'` form CloudTrail publishes for it (the
/// pattern the CloudTrail event schema states for the member), so a consumer parsing it
/// with that pattern reads every record this emulator writes. The instant is TRUNCATED to
/// the second rather than rounded, so a rendered time never names an instant later than
/// the call it records.
fn iso8601(at: SystemTime) -> String {
    let whole_seconds = at
        .duration_since(UNIX_EPOCH)
        .map(|since| UNIX_EPOCH + Duration::from_secs(since.as_secs()))
        .unwrap_or(at);
    ::aws_smithy_types::DateTime::from(whole_seconds)
        .fmt(::aws_smithy_types::date_time::Format::DateTime)
        .unwrap_or_default()
}

/// A fresh identifier in the canonical 8-4-4-4-12 UUID text form, the form CloudTrail's
/// `eventID` and `requestID` carry.
///
/// A version-4 UUID from the maintained `uuid` crate: an event id names one recorded
/// call and nothing else, so it is drawn fresh (never derived from the request or from
/// the log's position), which is also what makes two records' ids distinct.
fn mint_uuid() -> String {
    ::uuid::Uuid::new_v4().hyphenated().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(name: &str) -> ServedApiCall {
        ServedApiCall {
            event_name: name.to_string(),
            event_source: "cloudtrail.amazonaws.com".to_string(),
            aws_region: "us-east-1".to_string(),
            read_only: false,
            access_key_id: Some("AKIDEMULATOR".to_string()),
            user_name: Some("emulator".to_string()),
            principal_type: PRINCIPAL_TYPE_IAM_USER.to_string(),
            principal_id: None,
            identity_provider: None,
            session: None,
            account_id: "000000000000".to_string(),
            user_agent: None,
            resources: vec![AuditedResource::new("AWS::CloudTrail::Trail", "demo")],
            request_parameters: serde_json::json!({"name": "demo"}),
            response_elements: None,
            error_code: None,
            error_message: None,
        }
    }

    /// Every record gets its own ordinal and its own ids, and the log keeps them in the
    /// order they were served.
    #[test]
    fn records_are_ordered_and_uniquely_identified() {
        let mut log = ManagementEventLog::default();
        let now = SystemTime::now();
        let first = log.record(call("CreateTrail"), now);
        let second = log.record(call("DeleteTrail"), now);
        assert_ne!(
            first, second,
            "case two records: expected distinct event ids, got {first:?} twice"
        );
        let seqs: Vec<u64> = log.iter().map(|event| event.seq).collect();
        assert_eq!(
            seqs,
            vec![1, 2],
            "case two records: expected increasing ordinals, got {seqs:?}"
        );
        let names: Vec<&str> = log.iter().map(|e| e.call.event_name.as_str()).collect();
        assert_eq!(
            names,
            vec!["CreateTrail", "DeleteTrail"],
            "case two records: expected the served order, got {names:?}"
        );
    }

    /// A minted id has the canonical UUID form: 8-4-4-4-12 lowercase hex, version 4,
    /// variant 10xx.
    #[test]
    fn minted_ids_have_the_uuid_form() {
        let mut log = ManagementEventLog::default();
        let id = log.record(call("CreateTrail"), SystemTime::now());
        let groups: Vec<&str> = id.split('-').collect();
        let widths: Vec<usize> = groups.iter().map(|group| group.len()).collect();
        assert_eq!(
            widths,
            vec![8, 4, 4, 4, 12],
            "case {id:?}: expected the 8-4-4-4-12 grouping, got widths {widths:?}"
        );
        assert!(
            groups
                .iter()
                .all(|group| group.chars().all(|c| c.is_ascii_hexdigit()
                    && !c.is_ascii_uppercase())),
            "case {id:?}: expected lowercase hex digits"
        );
        assert_eq!(
            groups[2].chars().next(),
            Some('4'),
            "case {id:?}: expected the version nibble 4"
        );
        assert!(
            groups[3].starts_with(['8', '9', 'a', 'b']),
            "case {id:?}: expected the variant nibble in [89ab]"
        );
    }

    /// A record the retention window has run out on is dropped by the next write.
    #[test]
    fn retention_window_prunes_old_records() {
        let mut log = ManagementEventLog::default();
        let now = SystemTime::now();
        // Served just over the retention window ago, so `now` owes its removal.
        log.record(
            call("CreateTrail"),
            now - EVENT_RETENTION - Duration::from_secs(1),
        );
        // Served inside the window, so it stays.
        log.record(
            call("DeleteTrail"),
            now - EVENT_RETENTION + Duration::from_secs(60),
        );
        assert_eq!(
            log.len(),
            2,
            "case nothing due yet: expected both records, got {:?}",
            log.iter()
                .map(|e| e.call.event_name.clone())
                .collect::<Vec<_>>()
        );
        log.record(call("StartLogging"), now);
        let names: Vec<String> = log.iter().map(|e| e.call.event_name.clone()).collect();
        assert_eq!(
            names,
            vec!["DeleteTrail".to_string(), "StartLogging".to_string()],
            "case within retention: expected both kept, got {names:?}"
        );
    }

    /// The JSON form carries the fields a client reads an event by, and leaves out what
    /// the emulator does not know.
    #[test]
    fn cloudtrail_event_json_reports_what_is_known() {
        let mut log = ManagementEventLog::default();
        let mut failed = call("CreateTrail");
        failed.error_code = Some("TrailAlreadyExistsException".to_string());
        failed.error_message = Some("Trail demo already exists in us-east-1".to_string());
        log.record(failed, SystemTime::now());
        let event = log.iter().next().expect("the recorded event");
        let json = event.to_cloudtrail_event_json();
        for (field, expected) in [
            ("eventVersion", serde_json::json!(EVENT_VERSION)),
            ("eventName", serde_json::json!("CreateTrail")),
            ("eventSource", serde_json::json!("cloudtrail.amazonaws.com")),
            ("awsRegion", serde_json::json!("us-east-1")),
            ("readOnly", serde_json::json!(false)),
            ("eventType", serde_json::json!(EVENT_TYPE_AWS_API_CALL)),
            ("managementEvent", serde_json::json!(true)),
            ("eventCategory", serde_json::json!(EVENT_CATEGORY_MANAGEMENT)),
            (
                "errorCode",
                serde_json::json!("TrailAlreadyExistsException"),
            ),
        ] {
            assert_eq!(
                json.get(field),
                Some(&expected),
                "case {field:?}: expected {expected}, got {json}"
            );
        }
        assert_eq!(
            json.get("userAgent"),
            None,
            "case userAgent: an unknown field must be left out, got {json}"
        );
        assert_eq!(
            json.pointer("/userIdentity/userName"),
            Some(&serde_json::json!("emulator")),
            "case userIdentity: expected the caller's user name, got {json}"
        );
    }

    /// One remembered session, lasting `lasts` from `at` and carrying `source_identity`.
    fn session(source_identity: Option<&str>, at: SystemTime, lasts: Duration) -> RecordedSession {
        RecordedSession {
            principal_type: PRINCIPAL_TYPE_ASSUMED_ROLE.to_string(),
            principal_id: "AROAEXAMPLEROLEID001:analyst".to_string(),
            arn: "arn:aws:sts::000000000000:assumed-role/shared/analyst".to_string(),
            account_id: "000000000000".to_string(),
            user_name: Some("analyst".to_string()),
            issuer: Some(RecordedSessionIssuer {
                principal_type: SESSION_ISSUER_TYPE_ROLE.to_string(),
                principal_id: "AROAEXAMPLEROLEID001".to_string(),
                arn: "arn:aws:iam::000000000000:role/shared".to_string(),
                account_id: "000000000000".to_string(),
                user_name: "shared".to_string(),
            }),
            source_identity: source_identity.map(ToString::to_string),
            created_at: at,
            expires_at: at + lasts,
        }
    }

    /// A call made with a session credential is recorded with the session's own ARN and
    /// the `sessionContext` block — the issuer that minted it, and the source identity
    /// only when the session carries one.
    #[test]
    fn a_session_call_records_its_session_context() {
        let now = SystemTime::now();
        // The rows differ along the one fact the record is read for: whether the session
        // carries a source identity.
        for (case, source_identity) in [
            ("a session with a source identity", Some("alice@example.com")),
            ("a session without one", None),
        ] {
            let mut log = ManagementEventLog::default();
            let mut served = call("DescribeTrails");
            served.session = Some(session(source_identity, now, Duration::from_secs(3600)));
            // What a recorder fills for a session call: the identity is the SESSION's, so
            // the type and the name are its own.
            served.principal_type = PRINCIPAL_TYPE_ASSUMED_ROLE.to_string();
            served.user_name = Some("analyst".to_string());
            log.record(served, now);
            let json = log
                .iter()
                .next()
                .expect("the recorded event")
                .to_cloudtrail_event_json();
            assert_eq!(
                json.pointer("/userIdentity/arn"),
                Some(&serde_json::json!(
                    "arn:aws:sts::000000000000:assumed-role/shared/analyst"
                )),
                "case {case:?}: expected the session's own ARN, got {json}"
            );
            assert_eq!(
                json.pointer("/userIdentity/sessionContext/sessionIssuer/arn"),
                Some(&serde_json::json!("arn:aws:iam::000000000000:role/shared")),
                "case {case:?}: expected the issuing role's ARN, got {json}"
            );
            assert_eq!(
                json.pointer("/userIdentity/sessionContext/sourceIdentity"),
                source_identity.map(|value| serde_json::json!(value)).as_ref(),
                "case {case:?}: expected sourceIdentity {source_identity:?}, got {json}"
            );
            assert_eq!(
                json.pointer("/userIdentity/userName"),
                None,
                "case {case:?}: an assumed role's identity carries no userName — the name \
                 behind it is the issuer's, got {json}"
            );
        }
    }

    /// The directory answers the session a credential names, forgets a session whose
    /// credential the clock has expired, and holds no more than its cap.
    #[test]
    fn the_session_directory_is_bounded_by_the_clock_and_by_its_cap() {
        let now = SystemTime::now();
        let mut directory = SessionAuditDirectory::default();
        directory.remember(
            "ASIALIVE",
            session(Some("alice@example.com"), now, Duration::from_secs(3600)),
            now,
        );
        // Minted an hour ago for an hour, so `now` owes its removal.
        directory.remember(
            "ASIAEXPIRED",
            session(None, now - Duration::from_secs(3600), Duration::from_secs(1)),
            now,
        );
        assert_eq!(
            directory
                .session("ASIALIVE")
                .and_then(|held| held.source_identity.clone()),
            Some("alice@example.com".to_string()),
            "case a live session: expected its source identity, got {directory:?}"
        );
        // The next write is what materialises the expiry the clock already made due.
        directory.remember(
            "ASIAOTHER",
            session(None, now, Duration::from_secs(3600)),
            now,
        );
        assert_eq!(
            directory.session("ASIAEXPIRED"),
            None,
            "case an expired session: expected it dropped, got {directory:?}"
        );
        directory.forget("ASIAOTHER");
        assert_eq!(
            directory.session("ASIAOTHER"),
            None,
            "case a forgotten session: expected it dropped, got {directory:?}"
        );

        for index in 0..MAX_AUDITED_SESSIONS + 16 {
            directory.remember(
                format!("ASIAFILLER{index}"),
                session(None, now, Duration::from_secs(3600 + index as u64)),
                now,
            );
        }
        assert!(
            directory.len() <= MAX_AUDITED_SESSIONS,
            "case past the cap: expected at most {MAX_AUDITED_SESSIONS} sessions, got {}",
            directory.len()
        );
    }

    /// The caller a record names comes from the credential scope the request was signed
    /// with: a long-term key speaks for the emulator's IAM user, a temporary one for a
    /// session whose role name nothing here resolves, and an unsigned request for nobody.
    #[test]
    fn the_recorded_caller_follows_the_credential_the_request_carried() {
        // The rows differ along the kind of credential presented, which is what the
        // access-key-id prefix carries.
        for (case, authorization, access_key_id, principal_type, user_name) in [
            (
                "a long-term key",
                Some("AKIAEXAMPLEKEY123456"),
                Some("AKIAEXAMPLEKEY123456"),
                PRINCIPAL_TYPE_IAM_USER,
                Some(AMBIENT_USER_NAME),
            ),
            (
                "a session key",
                Some("ASIAEXAMPLEKEY123456"),
                Some("ASIAEXAMPLEKEY123456"),
                PRINCIPAL_TYPE_ASSUMED_ROLE,
                None,
            ),
            ("an unsigned request", None, None, PRINCIPAL_TYPE_UNKNOWN, None),
        ] {
            let mut request = http::Request::builder().uri("https://example.amazonaws.com/");
            if let Some(key) = authorization {
                request = request.header(
                    "authorization",
                    format!(
                        "AWS4-HMAC-SHA256 Credential={key}/20260101/us-east-1/s3/aws4_request, \
                         SignedHeaders=host, Signature=0"
                    ),
                );
            }
            let (parts, ()) = request.body(()).expect("the request builds").into_parts();
            let caller = recorded_caller(&parts);
            assert_eq!(
                caller.access_key_id.as_deref(),
                access_key_id,
                "case {case:?}: expected access key {access_key_id:?}, got {caller:?}"
            );
            assert_eq!(
                caller.principal_type, principal_type,
                "case {case:?}: expected principal type {principal_type:?}, got {caller:?}"
            );
            assert_eq!(
                caller.user_name.as_deref(),
                user_name,
                "case {case:?}: expected user name {user_name:?}, got {caller:?}"
            );
        }
    }

    /// A record spells a modelled member with a lower-case first letter and keeps the
    /// rest of the model's own casing — for every shape of name the models use.
    #[test]
    fn a_recorded_member_keeps_every_letter_but_the_first() {
        // (the modelled member name, the name a record spells it with)
        for (modelled, expected) in [
            ("DBInstanceIdentifier", "dBInstanceIdentifier"),
            ("Engine", "engine"),
            ("MasterUserPassword", "masterUserPassword"),
            ("KmsKeyId", "kmsKeyId"),
            ("PerformanceInsightsKMSKeyId", "performanceInsightsKMSKeyId"),
            // Already lower-case first: nothing changes.
            ("identityPoolId", "identityPoolId"),
            ("", ""),
        ] {
            let actual = recorded_member_name(modelled);
            assert_eq!(
                actual, expected,
                "case {modelled:?}: expected {expected:?}, got {actual:?}"
            );
        }
    }

    /// A `document` member nested past the walk's ceiling is TRUNCATED rather than
    /// followed: the walk's recursion is bounded by [`MAX_RECORDED_DEPTH`] whatever the
    /// caller nested, so a deep document cannot exhaust the stack.
    #[test]
    fn a_deeply_nested_document_is_truncated_rather_than_followed() {
        use ::aws_smithy_types::Document;

        /// Far past the ceiling, and shallow enough that building the value here is
        /// itself cheap.
        const NESTED: usize = MAX_RECORDED_DEPTH * 8;

        let mut document = Document::String("leaf".to_string());
        for _ in 0..NESTED {
            document = Document::Array(vec![document]);
        }
        let mut walk = RecordedShape {
            stack: Vec::new(),
            root: serde_json::Value::Null,
            withheld: WithheldFromRecord::default(),
            written: 0,
        };
        let recorded = walk.recorded_document(&document, 0);

        // How deep the RECORDED value goes, which is what the ceiling bounds.
        let mut reached = 0;
        let mut at = &recorded;
        while let Some(inner) = at.as_array().and_then(|elements| elements.first()) {
            reached += 1;
            at = inner;
        }
        assert!(
            reached <= MAX_RECORDED_DEPTH,
            "case {NESTED} levels: expected at most {MAX_RECORDED_DEPTH} recorded levels, \
             got {reached} in {recorded}"
        );
        assert_eq!(
            at.as_str(),
            Some(TRUNCATED_BY_RECORD_LIMIT),
            "case {NESTED} levels: expected the deepest recorded value to say it was \
             truncated, got {at}"
        );
    }

    /// A `document` member with more elements than one record holds stops being read when
    /// that budget is spent: what the record carries is sized by the budget, not by how
    /// many elements the request carried.
    #[test]
    fn a_wide_document_stops_at_the_record_budget() {
        use ::aws_smithy_types::Document;

        /// Far more elements than [`MAX_RECORDED_VALUES`].
        const ELEMENTS: usize = MAX_RECORDED_VALUES * 4;

        let wide = Document::Array(
            (0..ELEMENTS)
                .map(|at| Document::String(format!("element-{at}")))
                .collect(),
        );
        let mut walk = RecordedShape {
            stack: Vec::new(),
            root: serde_json::Value::Null,
            withheld: WithheldFromRecord::default(),
            written: 0,
        };
        let recorded = walk.recorded_document(&wide, 0);
        let elements = recorded
            .as_array()
            .unwrap_or_else(|| panic!("case {ELEMENTS} elements: expected a list, got {recorded}"));
        assert!(
            elements.len() <= MAX_RECORDED_VALUES,
            "case {ELEMENTS} elements: expected at most {MAX_RECORDED_VALUES} recorded \
             elements, got {}",
            elements.len()
        );
        assert_eq!(
            elements.last().and_then(serde_json::Value::as_str),
            Some(TRUNCATED_BY_RECORD_LIMIT),
            "case {ELEMENTS} elements: expected one entry saying where the walk stopped, \
             got {:?}",
            elements.last()
        );
    }

    /// A record's documents are held to a byte ceiling wherever they came from, so one
    /// record's footprint is bounded even when the walk that built it finished.
    #[test]
    fn a_document_past_the_byte_ceiling_is_withheld_whole() {
        let mut log = ManagementEventLog::default();
        let mut oversized = call("CreateTrail");
        oversized.request_parameters =
            serde_json::json!({"name": "x".repeat(MAX_RECORDED_DOCUMENT_BYTES + 1)});
        oversized.response_elements = Some(serde_json::json!({"name": "kept"}));
        log.record(oversized, SystemTime::now());

        let event = log.iter().next().expect("the recorded event");
        assert_eq!(
            event.call.request_parameters,
            serde_json::json!(TRUNCATED_BY_RECORD_LIMIT),
            "case past the ceiling: expected the parameters to be withheld whole, got {}",
            event.call.request_parameters
        );
        assert_eq!(
            event.call.response_elements,
            Some(serde_json::json!({"name": "kept"})),
            "case inside the ceiling: expected the response as it was, got {:?}",
            event.call.response_elements
        );
    }

    /// A member the call did not carry is left OUT of the record, so a reader cannot
    /// mistake an absent member for one that was sent as null.
    #[test]
    fn recorded_members_leave_out_what_was_absent() {
        let members = recorded_members([
            ("name", serde_json::json!("demo")),
            ("count", serde_json::json!(0)),
            ("enabled", serde_json::json!(false)),
            ("absent", serde_json::Value::Null),
            ("alsoAbsent", serde_json::json!(None::<String>)),
        ]);
        assert_eq!(
            members,
            serde_json::json!({"name": "demo", "count": 0, "enabled": false}),
            "expected only the members that were carried, got {members}"
        );
    }
}
