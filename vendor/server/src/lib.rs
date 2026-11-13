// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Shared HTTP service plumbing for AWS emulated services.
//!
//! Provides AKID extraction, error response helpers, tenant isolation,
//! and reusable HTTP infrastructure for building in-process AWS service emulators.

pub mod cli;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use aws_smithy_schema_server::xml_escape;

pub mod aws_credentials;
pub mod credential_store;
pub use credential_store::CredentialStore;
pub mod request_authentication;
pub use request_authentication::{
    Denied, RequestAuthenticator, SigV4Authenticator, VendedCredentials, authentication_enabled,
    set_authentication,
};
pub use emulator_paths::set_emulator_home_dir;

pub mod embedded;

/// The PKCS#12 trust store published next to `ca.pem` for JVM clients.
pub mod java_truststore;

mod tls_certificate_authority;
pub use tls_certificate_authority::TlsCertificateAuthority;

/// Resource-listener surfaces: the agent-facing `tcp()`/`http()` listeners a generated
/// service opens for a resource (RDS Postgres port, API Gateway invoke URL),
/// plus the pure transport-safety enforcement the core owns for them.
mod listener_guard;
mod listeners;
pub use listener_guard::{
    caps as listener_caps, classify_browser_request, is_loopback_host, is_websocket_upgrade,
    looks_like_http_preface, parse_listener_port_range, BrowserVerdict, PortRange, RemoteOrigins,
    SurfaceError, LISTENER_PORT_RANGE_ENV,
};
pub use listeners::{
    Listeners, ListenerConn, ListenerStream, HttpHandler, HttpPolicy, NativeHandler,
    ResourceListener, TlsUpgrader,
};

/// Extract AWS Access Key ID from SigV4 Authorization header.
///
/// Parses the `Credential=AKID/...` component from the standard
/// `AWS4-HMAC-SHA256 Credential=...` header format.
///
/// Returns `"default"` if the header is missing, unparseable, or empty.
pub fn extract_akid(headers: &http::HeaderMap) -> String {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| {
            auth.strip_prefix("AWS4-HMAC-SHA256 Credential=")
                .or_else(|| auth.strip_prefix("AWS4-HMAC-SHA256  Credential="))
        })
        .and_then(|cred| cred.split('/').next())
        .filter(|akid| !akid.is_empty())
        .unwrap_or("default")
        .to_string()
}

/// Protocol version for AWS JSON services.
///
/// Different AWS services use different protocol versions in their content-type header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwsJsonProtocol {
    V1_0,
    V1_1,
}

impl AwsJsonProtocol {
    pub fn content_type(&self) -> &'static str {
        match self {
            Self::V1_0 => "application/x-amz-json-1.0",
            Self::V1_1 => "application/x-amz-json-1.1",
        }
    }
}

/// Build a standard AWS JSON error response.
///
/// The caller passes the full `error_type` string. Services that need
/// a prefix (e.g. Cognito's `"com.amazonaws.cognitoidentityprovider#NotAuthorizedException"`)
/// should include it in the `error_type` argument.
pub fn aws_json_error_response(
    status: u16,
    error_type: &str,
    message: &str,
    protocol: AwsJsonProtocol,
) -> http::Response<bytes::Bytes> {
    let body = serde_json::json!({
        "__type": error_type,
        "message": message,
    });
    let body_bytes = serde_json::to_vec(&body).expect("JSON Value always serializes");
    let mut builder = http::Response::builder()
        .status(status)
        .header("content-type", protocol.content_type());
    // restJson1 resolves an error SHAPE from this header rather than from the body,
    // and it is harmless on the awsJson families, which read the body.
    // `wire_error_response` below already sets it; this builder did not, so the two
    // boundary error paths disagreed.
    //
    // Added FALLIBLY, not with `.header(...)`. `error_type` is a `&str` from a public
    // signature, and a header value rejects most control bytes while a JSON string
    // accepts them — so interpolating it unchecked would move validation to `.body()`
    // and turn the `expect` below into a panic on the ERROR path, where a panic
    // becomes a 500 that SDKs RETRY. On a rejected value the header is simply
    // omitted; the body's `__type` still carries the shape.
    if let Ok(value) = http::HeaderValue::from_str(error_type) {
        builder = builder.header("x-amzn-errortype", value);
    }
    builder
        .body(bytes::Bytes::from(body_bytes))
        .expect("valid status and headers")
}

/// Build a standard AWS JSON success response (200 OK).
pub fn aws_json_ok_response(
    body: &impl serde::Serialize,
    protocol: AwsJsonProtocol,
) -> http::Response<bytes::Bytes> {
    let body_bytes = serde_json::to_vec(body).expect("serializable body");
    http::Response::builder()
        .status(200)
        .header("content-type", protocol.content_type())
        .body(bytes::Bytes::from(body_bytes))
        .expect("valid status and headers")
}

/// The single, canonical AWS account id every generated emulator must present.
///
/// # Why this exact value
///
/// `000000000000` is a fixed, non-routable placeholder account id. Every
/// generated emulator must present THIS value — never a real literal such as
/// `123456789012`, nor a per-AKID-derived one — so every ARN and account field
/// it emits is deterministic and discloses no real account.
///
/// This constant lives in the vendored (scaffold-managed, agent-immutable)
/// runtime crate so it is the SINGLE source of truth: generated code must build
/// every account/ARN field through [`emulator_account_id`] / [`emulator_arn`] — never a
/// string literal — and a re-scaffold carries the canonical value into
/// long-lived tenant repos.
// OnCallWorlds patch: the account every ARN names. A build may name another with
// `OCW_ACCOUNT_ID=<12 digits>`; upstream's placeholder was 000000000000.
pub const EMULATOR_ACCOUNT_ID: &str = match option_env!("OCW_ACCOUNT_ID") {
    Some(account) => account,
    None => "418295736104",
};

/// The canonical AWS account id ([`EMULATOR_ACCOUNT_ID`]) every generated emulator
/// must present. Prefer this accessor over hardcoding the literal so the account
/// contract has exactly one source of truth.
pub fn emulator_account_id() -> &'static str {
    EMULATOR_ACCOUNT_ID
}

/// Build a canonical AWS ARN for an emulated resource:
/// `arn:aws:{service}:{region}:000000000000:{resource}`.
///
/// The account segment is always [`EMULATOR_ACCOUNT_ID`], so every ARN a generated
/// emulator emits carries this canonical placeholder account. `region` is
/// caller-supplied (emulators default to `us-east-1`); `resource` is the
/// already-formatted resource portion (e.g. `"role/my-role"`,
/// `"function:my-fn"`, `"table/my-table"`). Global-service ARNs (IAM, S3) simply
/// pass an empty `region`.
pub fn emulator_arn(service: &str, region: &str, resource: &str) -> String {
    format!("arn:aws:{service}:{region}:{EMULATOR_ACCOUNT_ID}:{resource}")
}

pub use aws_smithy_runtime_api;
pub use aws_smithy_types;
pub use bytes;
pub use http;
pub use http_body_util;

/// Convention trait for emulated services.
///
/// Implement this to use `impl_emulator_http_traits!` and `serve_on_ephemeral_port()`.
pub trait EmulatorService: Clone + Send + Sync + 'static {
    fn handle_request(
        &self,
        req: http::Request<bytes::Bytes>,
    ) -> impl std::future::Future<Output = http::Response<bytes::Bytes>> + Send;

    /// Called once the data port is bound and before it serves, with the URL clients reach it
    /// at (`https://host:port`, the shared config's `endpoint_url`). A service that hands out
    /// addresses of itself records it here; the default ignores it. A wrapper forwards it to
    /// the service it wraps.
    fn serving_at(&self, endpoint_url: &str) {
        let _ = endpoint_url;
    }
}

/// Shared logic for `HttpConnector::call()`. Called by macro-generated code.
///
/// Every failure path returns a [`ConnectorError`] rather than panicking: this
/// runs on the request path of a long-lived emulator process, so an unwrap here
/// would take the whole server down (and with it every other tenant and service
/// sharing the process) over one malformed request.
pub async fn http_connector_call<S: EmulatorService>(
    svc: &S,
    request: aws_smithy_runtime_api::client::orchestrator::HttpRequest,
) -> Result<
    aws_smithy_runtime_api::client::orchestrator::HttpResponse,
    aws_smithy_runtime_api::client::result::ConnectorError,
> {
    use aws_smithy_runtime_api::client::result::ConnectorError;

    let http_req = request
        .try_into_http1x()
        .map_err(|e| ConnectorError::user(Box::new(e)))?;
    let (parts, body) = http_req.into_parts();
    let body_bytes = http_body_util::BodyExt::collect(body)
        .await
        .map_err(ConnectorError::io)?
        .to_bytes();
    let req = http::Request::from_parts(parts, body_bytes);

    tokio::task::yield_now().await;
    let response = svc.handle_request(req).await;
    let (mut parts, body_bytes) = response.into_parts();
    set_framing_content_length(&mut parts, body_bytes.len());

    // The whole response goes to the SDK: status, every header, and the body. An SDK reads
    // most of what a call returns from the headers (an S3 `ETag`, `Content-Length` and
    // version id, for one), so a response rebuilt from the status and body alone reaches
    // the caller with those members absent. The conversion reports a failure as a connector
    // error rather than a panic, as the request side does for a request it cannot convert.
    let response =
        http::Response::from_parts(parts, aws_smithy_types::body::SdkBody::from(body_bytes));
    aws_smithy_runtime_api::client::orchestrator::HttpResponse::try_from(response)
        .map_err(|e| ConnectorError::other(Box::new(e), None))
}

/// Gives an in-process response the `Content-Length` the network listeners' HTTP stack
/// (hyper) writes on the wire: the body's length, unless the handler set one itself (an S3
/// `HeadObject` reports the object's size) or the status carries no content (1xx, 204, 304).
/// The SDK sees the same framing header in embedded mode as over a socket.
fn set_framing_content_length(parts: &mut http::response::Parts, body_len: usize) {
    let status = parts.status;
    if status.is_informational()
        || status == http::StatusCode::NO_CONTENT
        || status == http::StatusCode::NOT_MODIFIED
        || parts.headers.contains_key(http::header::CONTENT_LENGTH)
        || parts.headers.contains_key(http::header::TRANSFER_ENCODING)
    {
        return;
    }
    parts
        .headers
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(body_len));
}

/// Generate `HttpConnector` and `HttpClient` impls for a concrete service type.
///
/// The macro expands in the invoking crate so the concrete type is local,
/// satisfying Rust's orphan rule.
#[macro_export]
macro_rules! impl_emulator_http_traits {
    ($service_type:ty) => {
        impl $crate::aws_smithy_runtime_api::client::http::HttpConnector for $service_type {
            fn call(
                &self,
                request: $crate::aws_smithy_runtime_api::client::orchestrator::HttpRequest,
            ) -> $crate::aws_smithy_runtime_api::client::http::HttpConnectorFuture {
                let svc = self.clone();
                $crate::aws_smithy_runtime_api::client::http::HttpConnectorFuture::new(Box::pin(
                    async move { $crate::http_connector_call(&svc, request).await },
                ))
            }
        }

        impl $crate::aws_smithy_runtime_api::client::http::HttpClient for $service_type {
            fn http_connector(
                &self,
                _settings: &$crate::aws_smithy_runtime_api::client::http::HttpConnectorSettings,
                _components: &$crate::aws_smithy_runtime_api::client::runtime_components::RuntimeComponents,
            ) -> $crate::aws_smithy_runtime_api::client::http::SharedHttpConnector {
                $crate::aws_smithy_runtime_api::client::http::SharedHttpConnector::new(self.clone())
            }
        }
    };
}

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

// ---------------------------------------------------------------------------
// Panic containment at the server boundary
// ---------------------------------------------------------------------------
//
// A generated operation handler runs inside the hyper connection task that is
// serving the request. A panic there — a `todo!()`/`unimplemented!()` stub, an
// `unwrap()` on absent state, an arithmetic overflow — unwinds that task, so the
// caller receives NO HTTP RESPONSE AT ALL: its socket dies mid-request. A
// behavioral/wire check then hangs on a dead socket instead of recording a
// verdict, which silently removes whole operations from measurement.
//
// Every serve path in this crate therefore drives its response future through
// [`contain_panics`], which polls it inside `catch_unwind` and answers a caught
// panic with a protocol-shaped `500 InternalFailure`. The connection, the
// listener, and the process all survive, and the next request is served
// normally.
//
// Two failure modes are outside any containment layer's reach, both by Rust
// design: a profile built with `panic = "abort"` never unwinds (no emulator
// profile sets it), and a destructor that panics WHILE a panic is unwinding is a
// non-unwinding panic that aborts the process before the guard regains control.
//
// And one accepted limit of the guarantee itself: containment promises the
// CONNECTION, LISTENER and PROCESS survive a panic — NOT that in-memory state
// stays consistent. The shared engine guards each service's state with a
// `Mutex`, which never poisons, so a handler that panics halfway through a
// multi-step mutation releases the lock with the state partially updated, and a
// later request observes that. Previously the connection simply died, which hid
// it; the exposure is the price of answering the caller at all.

/// AWS's canonical error code for an unmodeled server-side failure. Every AWS
/// SDK maps it to a retryable service error, which is what a contained panic is:
/// the request failed inside the emulator, not in the caller.
const INTERNAL_FAILURE_CODE: &str = "InternalFailure";

/// Caller-facing message for a contained panic.
///
/// Deliberately generic: the panic's own message is logged, never returned, so a
/// request cannot read internal detail out of the emulator. Contains no XML
/// metacharacters, so it needs no escaping in the XML envelope (enforced by a
/// test).
const INTERNAL_FAILURE_MESSAGE: &str =
    "the emulator encountered an internal error while handling this request";

/// Error code for a request the emulator could not read off the wire. Matches
/// the framework's own malformed-request code, which is a Sender fault and
/// terminal (unlike `InternalFailure`, an SDK will not retry it).
const INVALID_REQUEST_CODE: &str = "InvalidRequest";

/// Caller-facing message when the request body cannot be read off the socket.
///
/// Named rather than inlined so the call site and the test that enforces the
/// no-XML-metacharacters invariant cannot drift apart.
const INVALID_REQUEST_BODY_MESSAGE: &str = "the request body could not be read";

/// Response header a `noErrorWrapping` restXml error echoes, naming the request;
/// the unwrapped body's `<RequestId>` carries the same value.
const REQUEST_ID_HEADER: &str = "x-amz-request-id";
/// Second request-correlation header on that error, mirroring the body's
/// `<HostId>`.
const EXTENDED_REQUEST_ID_HEADER: &str = "x-amz-id-2";

/// A fresh request-id for one unwrapped restXml error response, carried
/// identically in the body's `<RequestId>` element and the `x-amz-request-id`
/// header. Each response carries its own id so two responses are
/// distinguishable; the id names a request for correlation and is not a
/// security token, so a random value is correct. Generate it once per response
/// and use the one value in both places.
fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// A fresh extended request-id (`<HostId>` / `x-amz-id-2`) for one unwrapped
/// restXml error response. Unlike the request-id it is not a UUID: the S3
/// `x-amz-id-2` shape is a 64-lowercase-hex-character string, so hex-encode 32
/// random bytes (two v4 UUIDs' worth). Like the request-id, generate it once
/// per response and use the one value in both the body's `<HostId>` and the
/// header.
fn new_host_id() -> String {
    let mut hex = String::with_capacity(64);
    for byte in uuid::Uuid::new_v4()
        .as_bytes()
        .iter()
        .chain(uuid::Uuid::new_v4().as_bytes().iter())
    {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Response header stamped on every response synthesized from a CONTAINED panic.
///
/// A contained panic is an emulator DEFECT that happens to be reported as a
/// well-formed `500`. Marking it on the wire lets a caller
/// tell it apart from a legitimately modeled server-fault response instead of
/// mistaking a crash for intended behaviour.
pub const PANIC_CONTAINED_HEADER: &str = "x-emulator-panic";

/// The request facts a contained panic is reported with, captured BEFORE the
/// request is moved into the handler.
///
/// Owned rather than borrowed because the request itself is consumed by the
/// guarded future. These few short strings are what make a contained panic
/// attributable to a specific operation in the emulator log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFacts {
    /// HTTP method, e.g. `POST`.
    pub method: String,
    /// Request path, without the query string.
    pub path: String,
    /// The request's `content-type`, which selects the wire shape of the error
    /// envelope (see [`wire_error_response`]).
    pub content_type: Option<String>,
    /// `X-Amz-Target` when present — for awsJson and rpcv2Cbor services this
    /// names the operation whose handler panicked.
    pub target: Option<String>,
    /// The SigV4 credential-scope signing name (`"ec2"`, `"sqs"`, …) when the
    /// request is signed. In a multi-service emulator this names WHICH mounted
    /// service panicked — it is the same signal [`resolve_route_key`] routes
    /// on — and it is what distinguishes an ec2Query caller from an awsQuery one
    /// (see [`envelope_for`]).
    pub signing_name: Option<String>,
    /// Whether the service these facts belong to sets restXml `noErrorWrapping`.
    /// When true AND the caller's envelope resolves to [`ErrorEnvelope::Xml`],
    /// the boundary emits a bare `<Error>` root plus the `x-amz-request-id` /
    /// `x-amz-id-2` headers instead of the `<ErrorResponse>` wrapper.
    ///
    /// It cannot be read off the request — it is a model trait — so
    /// [`RequestFacts::from_request`] defaults it to `false` (wrapped), and a
    /// caller that knows the model opts in with
    /// [`RequestFacts::with_no_error_wrapping`]. A caller that does neither gets
    /// the wrapped envelope.
    pub no_error_wrapping: bool,
}

impl RequestFacts {
    /// Capture the facts from a request of any body type.
    pub fn from_request<B>(req: &http::Request<B>) -> Self {
        let header = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        Self {
            method: req.method().to_string(),
            path: req.uri().path().to_string(),
            content_type: header("content-type"),
            target: header("x-amz-target"),
            signing_name: service_from_sigv4(req.headers()),
            no_error_wrapping: false,
        }
    }

    /// Mark that the service these facts belong to sets restXml
    /// `noErrorWrapping`, so an XML error from the boundary is emitted unwrapped
    /// (see the field docs). A no-op for any other caller envelope.
    pub fn with_no_error_wrapping(mut self, no_error_wrapping: bool) -> Self {
        self.no_error_wrapping = no_error_wrapping;
        self
    }
}

/// Wire shape of an error envelope synthesized at the server boundary.
///
/// AWS protocols do not share one error encoding, so a boundary-generated error
/// must be encoded the way the CALLER's protocol expects; otherwise its SDK
/// reports a response-parse failure rather than the server fault that occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorEnvelope {
    /// `{"__type":..,"message":..}` under `content_type` — the awsJson family
    /// (which echoes its versioned media type) and restJson1.
    Json { content_type: &'static str },
    /// `<ErrorResponse><Error>..` — restXml and awsQuery.
    Xml,
    /// `<Response><Errors><Error>..` — ec2Query, which does NOT share awsQuery's
    /// wrapper even though both send form-urlencoded requests.
    Ec2Query,
    /// A CBOR map — rpcv2Cbor.
    Cbor,
}

/// Choose the error envelope from the REQUEST's content-type.
///
/// The content-type is the only protocol signal available here: the boundary is
/// generic over [`EmulatorService`] and one generic listener serves every protocol,
/// so the response encoding is inferred from what the caller sent. Each protocol
/// the emulator serves announces itself: the awsJson family sends its
/// versioned JSON media type, rpcv2Cbor `application/cbor`, awsQuery/ec2Query
/// `application/x-www-form-urlencoded`, restJson1 `application/json`, restXml
/// `application/xml`.
///
/// awsQuery and ec2Query BOTH send `application/x-www-form-urlencoded` and do
/// NOT share an error envelope, so the content-type alone cannot separate them.
/// ec2Query is selected by the SigV4 credential-scope signing name `ec2` — the
/// same signal [`resolve_route_key`] uses as its primary routing key, and in
/// AWS `ec2Query` is EC2's protocol. An UNSIGNED ec2Query request therefore
/// falls back to awsQuery's `<ErrorResponse>` wrapper: a best-effort shape whose
/// `500` status and `x-amzn-errortype` header still carry the verdict.
///
/// An absent or unrecognized content-type falls back to JSON — the encoding both
/// JSON protocol families use, and the one a bodyless restJson1 `GET` needs. A
/// bodyless restXml `GET` therefore receives a JSON envelope; the `500` status
/// and the `x-amzn-errortype` header still carry the verdict, so the caller
/// records a server fault either way rather than losing the connection.
fn envelope_for(facts: &RequestFacts) -> ErrorEnvelope {
    let media = facts
        .content_type
        .as_deref()
        .map(|ct| {
            ct.split(';')
                .next()
                .unwrap_or(ct)
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    match media.as_str() {
        "application/x-amz-json-1.0" => ErrorEnvelope::Json {
            content_type: "application/x-amz-json-1.0",
        },
        "application/x-amz-json-1.1" => ErrorEnvelope::Json {
            content_type: "application/x-amz-json-1.1",
        },
        "application/cbor" => ErrorEnvelope::Cbor,
        "application/x-www-form-urlencoded" if facts.signing_name.as_deref() == Some("ec2") => {
            ErrorEnvelope::Ec2Query
        }
        "application/xml" | "text/xml" | "application/x-www-form-urlencoded" => ErrorEnvelope::Xml,
        _ => ErrorEnvelope::Json {
            content_type: "application/json",
        },
    }
}

/// Build an error response encoded in the wire shape the caller's protocol
/// expects (see [`envelope_for`]), carrying `status`, `code` and `message`.
///
/// `B` is the body type of the transport the response is returned on
/// (`bytes::Bytes` for the buffered [`EmulatorService`] paths, `axum::body::Body` on
/// the axum router), so one builder serves every serve path.
///
/// `message` MUST NOT carry internal detail: it is returned to the sender. The
/// XML envelopes escape `code` and `message`, so any text renders as well-formed
/// XML.
pub fn wire_error_response<B: From<bytes::Bytes>>(
    status: http::StatusCode,
    code: &str,
    message: &str,
    facts: &RequestFacts,
) -> http::Response<B> {
    // A `noErrorWrapping` restXml error carries one request-id and one host-id,
    // each used in both the unwrapped body (above) and the two response headers
    // (below). Generated once here so the body and headers always agree. Empty
    // (and unused) for every other envelope, which carries no such ids.
    let (request_id, host_id) = if facts.no_error_wrapping {
        (new_request_id(), new_host_id())
    } else {
        (String::new(), String::new())
    };
    let envelope = envelope_for(facts);
    let (xml_code, xml_message) = match envelope {
        ErrorEnvelope::Xml | ErrorEnvelope::Ec2Query => (xml_escape(code), xml_escape(message)),
        ErrorEnvelope::Json { .. } | ErrorEnvelope::Cbor => (String::new(), String::new()),
    };
    let (body, response_content_type, smithy_protocol) = match envelope {
        ErrorEnvelope::Json { content_type } => (
            bytes::Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "__type": code,
                    "message": message,
                }))
                .expect("JSON Value always serializes"),
            ),
            content_type,
            None,
        ),
        ErrorEnvelope::Xml => {
            // A restXml service that sets `noErrorWrapping` reads the error
            // `<Code>` off a bare `<Error>` root, so emit that shape — with no
            // `<Type>`, trailing `<RequestId>`/`<HostId>`, and the matching
            // `x-amz-request-id` / `x-amz-id-2` headers (added after the builder
            // below). One request-id and one host-id are generated per response
            // and used in both the body and those headers. awsQuery never sets
            // the flag, so it keeps the wrapper.
            let body = if facts.no_error_wrapping {
                format!(
                    "<?xml version=\"1.0\"?><Error><Code>{xml_code}</Code>\
                     <Message>{xml_message}</Message><RequestId>{request_id}</RequestId>\
                     <HostId>{host_id}</HostId></Error>"
                )
            } else {
                // `Sender` for a client fault, `Receiver` for a server fault —
                // the fault attribution awsQuery and restXml clients read. The
                // framework hardcodes `Sender` in `query_error_body`/the macro's
                // pre-dispatch envelope because every error it renders there is a
                // 4xx; a contained panic is a 5xx, which is a Receiver fault.
                let fault = if status.is_server_error() {
                    "Receiver"
                } else {
                    "Sender"
                };
                format!(
                    "<?xml version=\"1.0\"?><ErrorResponse><Error><Type>{fault}</Type>\
                     <Code>{xml_code}</Code><Message>{xml_message}</Message></Error></ErrorResponse>"
                )
            };
            (bytes::Bytes::from(body), "application/xml", None)
        }
        // Mirrors `aws_smithy_schema_server::query::query_error_body(ec2: true)`,
        // which this crate cannot call (it does not depend on the schema-server):
        // no `<Type>` element and no `<RequestID>`, exactly as the framework and
        // real EC2 emit.
        ErrorEnvelope::Ec2Query => (
            bytes::Bytes::from(format!(
                "<?xml version=\"1.0\"?><Response><Errors><Error>\
                 <Code>{xml_code}</Code><Message>{xml_message}</Message>\
                 </Error></Errors></Response>"
            )),
            "application/xml",
            None,
        ),
        ErrorEnvelope::Cbor => (
            bytes::Bytes::from(cbor_error_map(code, message)),
            "application/cbor",
            Some("rpc-v2-cbor"),
        ),
    };

    let mut builder = http::Response::builder()
        .status(status)
        .header("content-type", response_content_type)
        // restJson1 clients read the error code from this header instead of the
        // body, and it is harmless on every other protocol.
        .header("x-amzn-errortype", code);
    if let Some(protocol) = smithy_protocol {
        builder = builder.header("smithy-protocol", protocol);
    }
    // A `noErrorWrapping` restXml error carries the two request-correlation
    // headers whose values the unwrapped body's `<RequestId>`/`<HostId>` mirror.
    // Only the XML envelope sets the flag's meaning, so this is a no-op for every
    // other protocol even if `no_error_wrapping` is somehow set.
    if facts.no_error_wrapping && envelope == ErrorEnvelope::Xml {
        builder = builder
            .header(REQUEST_ID_HEADER, &request_id)
            .header(EXTENDED_REQUEST_ID_HEADER, &host_id);
    }
    builder
        .body(B::from(body))
        .expect("a valid status with static headers always builds")
}

/// Build the `500 InternalFailure` response returned for a CONTAINED panic,
/// additionally stamped with [`PANIC_CONTAINED_HEADER`] so the panic is visible
/// on the wire and not merely in the log.
pub fn internal_failure_response<B: From<bytes::Bytes>>(facts: &RequestFacts) -> http::Response<B> {
    let mut resp = wire_error_response(
        http::StatusCode::INTERNAL_SERVER_ERROR,
        INTERNAL_FAILURE_CODE,
        INTERNAL_FAILURE_MESSAGE,
        facts,
    );
    resp.headers_mut().insert(
        PANIC_CONTAINED_HEADER,
        http::HeaderValue::from_static("contained"),
    );
    resp
}

/// CBOR major type 3 (text string), shifted into the initial byte's high bits.
const CBOR_MAJOR_TEXT: u8 = 3 << 5;
/// CBOR major type 5 (map), shifted into the initial byte's high bits.
const CBOR_MAJOR_MAP: u8 = 5 << 5;

/// Encode `{"__type": <code>, "message": <message>}` as a definite-length CBOR
/// map — the error document an rpcv2Cbor client decodes.
///
/// Hand-encoded because this crate carries no CBOR dependency: it is vendored
/// verbatim into every tenant repo, so its dependency set is kept minimal. Two
/// text-string pairs in a `map(2)` is the simplest well-formed CBOR document
/// that satisfies the shape.
fn cbor_error_map(code: &str, message: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push_cbor_head(&mut out, CBOR_MAJOR_MAP, 2);
    for (key, value) in [("__type", code), ("message", message)] {
        push_cbor_text(&mut out, key);
        push_cbor_text(&mut out, value);
    }
    out
}

/// Append a CBOR text string: the major-type-3 head carrying the byte length,
/// then the UTF-8 bytes.
fn push_cbor_text(out: &mut Vec<u8>, s: &str) {
    push_cbor_head(out, CBOR_MAJOR_TEXT, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// Append the CBOR initial byte for `major` carrying `argument`, using the
/// shortest of the five RFC 8949 argument encodings that fits.
fn push_cbor_head(out: &mut Vec<u8>, major: u8, argument: u64) {
    match argument {
        0..=23 => out.push(major | argument as u8),
        24..=0xff => out.extend_from_slice(&[major | 24, argument as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(argument as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&(argument as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&argument.to_be_bytes());
        }
    }
}

/// Render a panic payload as a log message. `panic!`, `todo!`, `unwrap` and
/// `expect` produce either a `&'static str` or a formatted `String`; a payload
/// from `panic_any` has no printable form.
fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// A future that polls `inner` inside [`std::panic::catch_unwind`], yielding the
/// panic payload instead of unwinding into the caller.
///
/// The inner future is boxed so this type is `Unpin` and needs no unsafe pin
/// projection (`unsafe` is forbidden in every generated tenant workspace). It is
/// taken out for the duration of each poll and put back only when that poll
/// returns `Pending`, so a future whose poll panicked is never polled again.
struct CatchUnwind<T> {
    inner: Option<Pin<Box<dyn Future<Output = T> + Send>>>,
}

impl<T: Send> Future for CatchUnwind<T> {
    type Output = Result<T, Box<dyn std::any::Any + Send>>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        use std::task::Poll;

        let this = self.get_mut();
        // The ONE panic in this type that the guard cannot contain: it is raised
        // outside the `catch_unwind` below and would escape. It fires only if the
        // executor re-polls a future that already returned `Ready`, which the
        // `Future` contract forbids and tokio/hyper/axum never do.
        let mut inner = this
            .inner
            .take()
            .expect("CatchUnwind must not be polled after it returned Ready");
        let polled =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.as_mut().poll(cx)));
        match polled {
            Ok(Poll::Pending) => {
                this.inner = Some(inner);
                Poll::Pending
            }
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Err(payload) => {
                // The future is left NOT put back, so it is dropped here and can
                // never be polled again: polling a future whose poll unwound is
                // undefined by the `Future` contract.
                drop(inner);
                Poll::Ready(Err(payload))
            }
        }
    }
}

/// Drive one request's whole response future with panic containment.
///
/// A panic anywhere inside `fut` — in a generated operation handler, in an extra
/// route, or in the dispatch machinery between them — is caught, LOGGED at
/// `error` with the request facts, and answered with a protocol-shaped
/// [`internal_failure_response`]. The connection and the listener survive, so the
/// caller reads a real HTTP error response and the next request is served
/// normally.
///
/// The panic is NOT swallowed. The process-wide panic hook still reports it with
/// its source location and any backtrace, and this logs a structured `error`
/// event naming the request, so a genuine emulator defect stays fully visible
/// without taking the connection with it.
pub async fn contain_panics<F, B>(facts: RequestFacts, fut: F) -> http::Response<B>
where
    F: Future<Output = http::Response<B>> + Send + 'static,
    B: From<bytes::Bytes> + Send + 'static,
{
    let guarded = CatchUnwind {
        inner: Some(Box::pin(fut)),
    };
    match guarded.await {
        Ok(resp) => resp,
        Err(payload) => {
            tracing::error!(
                method = %facts.method,
                path = %facts.path,
                target = facts.target.as_deref().unwrap_or("-"),
                service = facts.signing_name.as_deref().unwrap_or("-"),
                panic = %panic_payload_message(payload.as_ref()),
                "CONTAINED PANIC in a request handler: answering 500 InternalFailure so the \
                 connection survives. This is an emulator defect, not a client error"
            );
            internal_failure_response(&facts)
        }
    }
}

/// Axum middleware that contains a panic raised by ANY route of the router it is
/// layered onto, including the catch-all AWS-surface fallback.
async fn panic_guard(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let facts = RequestFacts::from_request(&req);
    contain_panics(facts, next.run(req)).await
}

/// Layer panic containment onto `router` so a panic in any of its routes is
/// answered with a protocol-shaped `500` instead of destroying the connection.
///
/// Applied to every router this crate serves; exported so a generated emulator
/// that builds its own axum router still gets the guarantee.
pub fn with_panic_guard(router: axum::Router) -> axum::Router {
    router.layer(axum::middleware::from_fn(panic_guard))
}

/// Bind to an ephemeral port and start serving HTTP for any `EmulatorService`.
///
/// Returns `(endpoint_url, service)` after the server is ready to accept connections.
/// The server runs in a background tokio task.
pub async fn serve_on_ephemeral_port<S: EmulatorService>(service: S) -> (String, S) {
    let std_listener = std::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("failed to bind ephemeral port");
    let port = std_listener
        .local_addr()
        .expect("failed to get local addr")
        .port();
    std_listener.set_nonblocking(true).expect("set nonblocking");

    let endpoint = format!("http://localhost:{}", port);
    let svc = service.clone();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let make_svc =
            hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let svc = svc.clone();
                async move {
                    // Panic containment: this path has no axum router to layer,
                    // so the guard wraps the whole request future directly. A
                    // panic in the handler answers 500 instead of unwinding the
                    // connection task and leaving the caller on a dead socket.
                    let facts = RequestFacts::from_request(&req);
                    let resp: http::Response<bytes::Bytes> =
                        contain_panics(facts.clone(), async move {
                            let (parts, body) = req.into_parts();
                            let body_bytes = match http_body_util::BodyExt::collect(body).await {
                                Ok(collected) => collected.to_bytes(),
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        "could not read the request body"
                                    );
                                    return wire_error_response(
                                        http::StatusCode::BAD_REQUEST,
                                        INVALID_REQUEST_CODE,
                                        INVALID_REQUEST_BODY_MESSAGE,
                                        &facts,
                                    );
                                }
                            };
                            let req = http::Request::from_parts(parts, body_bytes);
                            svc.handle_request(req).await
                        })
                        .await;
                    let (parts, body_bytes) = resp.into_parts();
                    Ok::<_, std::convert::Infallible>(http::Response::from_parts(
                        parts,
                        http_body_util::Full::new(body_bytes),
                    ))
                }
            });

        let listener = tokio::net::TcpListener::from_std(std_listener)
            .expect("failed to convert to tokio listener");
        let _ = tx.send(());

        loop {
            let (stream, _) = listener.accept().await.expect("accept failed");
            let svc = make_svc.clone();
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, svc)
                .await;
            });
        }
    });

    let _ = rx.await;
    (endpoint, service)
}

/// Upper bound on a request/response body buffered when bridging a request
/// through a [`EmulatorService`] on the production serve path. The emulator serves
/// small canned fixtures; this only guards against an accidentally unbounded
/// stream. A larger request is answered `413 Payload Too Large`.
const MAX_PRODUCTION_BODY_BYTES: usize = 16 * 1024 * 1024;

/// How long a client on the production data port may take to send a request's
/// headers before its connection is closed, so a client that opens connections
/// and trickles their headers cannot hold them open.
const HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a client on the production data port may take to send a request's
/// body before it is answered `408 Request Timeout`, for the same reason.
const BODY_READ_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(listener_caps::HTTP_REQUEST_DEADLINE_SECS);

/// Errors from the long-lived [`serve_production`] path.
#[derive(Debug)]
pub enum ServeError {
    /// Self-signed TLS certificate/config generation failed.
    Tls(String),
    /// Listener bind or serve I/O error.
    Io(std::io::Error),
    /// The requested bind address did not parse as an IP address.
    ///
    /// Refused rather than defaulted, unlike an unparseable port: a port that
    /// falls back to its documented default is still the same listener on the
    /// same interfaces, whereas a bind address that fell back would silently
    /// change *which networks can reach the emulator*. The two directions of
    /// that mistake are both unacceptable — widening exposes an unauthenticated
    /// surface the operator meant to close, narrowing makes the emulator
    /// unreachable to its health check and manifests as an unexplained
    /// deployment failure minutes later rather than as a message at boot.
    BindAddress(String),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls(msg) => write!(f, "TLS setup failed: {msg}"),
            Self::Io(e) => write!(f, "server I/O error: {e}"),
            Self::BindAddress(msg) => write!(f, "invalid bind address: {msg}"),
        }
    }
}

impl std::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Tls(_) | Self::BindAddress(_) => None,
        }
    }
}

/// Axum fallback handler: drive one buffered request through the wrapped
/// [`EmulatorService`]. Converts the inbound axum request into the
/// `http::Request<Bytes>` the emulated-service contract uses, dispatches it, and
/// converts the `http::Response<Bytes>` back into an axum response. The whole
/// AWS surface is a fallback because AWS wire protocols route by header/body,
/// not by URL path.
async fn emulator_service_fallback<S: EmulatorService>(
    axum::extract::State(service): axum::extract::State<Arc<S>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    let (parts, body) = req.into_parts();
    let body_bytes = match read_production_body(body).await {
        Ok(b) => b,
        Err(status) => {
            return axum::response::Response::builder()
                .status(status)
                .body(axum::body::Body::empty())
                .expect("a status-only response is always valid");
        }
    };
    let emulator_req = http::Request::from_parts(parts, body_bytes);
    let emulator_resp = service.handle_request(emulator_req).await;
    let (resp_parts, resp_body) = emulator_resp.into_parts();
    axum::response::Response::from_parts(resp_parts, axum::body::Body::from(resp_body))
}

/// Buffers a request body: declared past [`MAX_PRODUCTION_BODY_BYTES`] it is a `413` before any
/// of it is read, past the cap as it arrives a `413`, not finished within [`BODY_READ_TIMEOUT`] a
/// `408`, and unreadable (a reset or malformed stream) a `400`.
async fn read_production_body(body: axum::body::Body) -> Result<bytes::Bytes, http::StatusCode> {
    let declared = axum::body::HttpBody::size_hint(&body).exact();
    if declared.is_some_and(|length| length > MAX_PRODUCTION_BODY_BYTES as u64) {
        return Err(refused_unread(body));
    }
    let read = axum::body::to_bytes(body, MAX_PRODUCTION_BODY_BYTES);
    match tokio::time::timeout(BODY_READ_TIMEOUT, read).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(error)) if is_over_the_size_cap(&error) => Err(http::StatusCode::PAYLOAD_TOO_LARGE),
        Ok(Err(_)) => Err(http::StatusCode::BAD_REQUEST),
        Err(_) => Err(http::StatusCode::REQUEST_TIMEOUT),
    }
}

fn is_over_the_size_cap(error: &axum::Error) -> bool {
    let cause = std::error::Error::source(error);
    cause.is_some_and(|cause| cause.is::<http_body_util::LengthLimitError>())
}

/// A `413` before an over-cap declared body is read; the rest is dropped so its client reads it.
fn refused_unread(mut body: axum::body::Body) -> http::StatusCode {
    let discard =
        async move { while let Some(Ok(_)) = http_body_util::BodyExt::frame(&mut body).await {} };
    tokio::spawn(tokio::time::timeout(BODY_READ_TIMEOUT, discard));
    http::StatusCode::PAYLOAD_TOO_LARGE
}

/// Default data (HTTPS) listener port when [`DATA_PORT_ENV`] is unset — the
/// well-known port the emulator has always served on.
pub const DEFAULT_DATA_PORT: u16 = 9297;

/// The readiness path, served over HTTPS on the data port ahead of the service
/// surface: `GET` answers `200 ok` once the emulator accepts requests.
pub const HEALTH_PATH: &str = "/__admin/health";

/// Environment variable a caller can set to override the data (HTTPS) listener
/// port. A value of `0` requests an OS-assigned (ephemeral) port; any other
/// value pins that port.
pub const DATA_PORT_ENV: &str = "EMULATOR_DATA_PORT";

/// Interface the production listeners bind when [`BIND_ADDRESS_ENV`] is unset.
///
/// `127.0.0.1` — reachable only from the host the emulator runs on. This is the
/// safe default because the emulator verifies no request signature and shards
/// tenants on an access-key id it does not authenticate: anything that can reach
/// the port can drive every operation, read and modify any tenant's state.
/// Defaulting to the wildcard made that surface reachable by every
/// peer on a developer's network, which is not a choice a test double should make
/// on its operator's behalf.
///
/// **A container deployment must set [`BIND_ADDRESS_ENV`] to `0.0.0.0`
/// explicitly.** Under `awsvpc` a load balancer health check and a replay
/// harness arrive at the task's own ENI address, never over loopback, so a
/// loopback-only emulator is reachable by nothing there and never passes its
/// readiness gate. That requirement is now stated by the deployment rather than
/// inherited from this constant, which is the point: the wildcard is a
/// deliberate declaration, not a default nobody chose.
pub const DEFAULT_BIND_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Environment variable a caller can set to choose which interface the
/// listener binds, as an IP literal — `127.0.0.1` to confine the
/// emulator to the host it runs on, `0.0.0.0` for every IPv4 interface, `::1` or
/// `::` for their IPv6 equivalents. Unset means [`DEFAULT_BIND_ADDRESS`].
///
/// A value that is not an IP literal is REFUSED, not defaulted — see
/// [`ServeError::BindAddress`].
pub const BIND_ADDRESS_ENV: &str = "EMULATOR_BIND_ADDRESS";

/// Resolve the interface the production listeners should bind from the
/// environment: [`BIND_ADDRESS_ENV`], defaulting to [`DEFAULT_BIND_ADDRESS`]
/// when unset — so an emulator with no environment override behaves exactly as
/// before.
///
/// A value that is set but not valid UTF-8 is refused rather than read as unset,
/// for the same reason an unparseable one is: treating it as absent would take
/// the WIDENING direction, which is the one direction a mistake here must never
/// silently take.
pub fn bind_address_from_env() -> Result<IpAddr, ServeError> {
    let raw = match std::env::var(BIND_ADDRESS_ENV) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(ServeError::BindAddress(format!(
                "{BIND_ADDRESS_ENV} is set but is not valid UTF-8; \
                 use 127.0.0.1 for host-only, 0.0.0.0 for every interface, or unset it"
            )));
        }
    };
    parse_bind_address(raw.as_deref())
}

/// Pure parsing core of [`bind_address_from_env`], split out so it is
/// unit-testable without mutating (and racing on) process-global environment
/// variables.
///
/// An absent variable yields [`DEFAULT_BIND_ADDRESS`]; surrounding whitespace is
/// tolerated as it is for a port. Anything else that does not parse as an IP
/// literal is an error rather than a fallback, so the operator learns at boot
/// which value was rejected instead of inferring it from where traffic did or
/// did not arrive.
fn parse_bind_address(raw: Option<&str>) -> Result<IpAddr, ServeError> {
    match raw {
        Some(v) => v.trim().parse::<IpAddr>().map_err(|e| {
            ServeError::BindAddress(format!(
                "{BIND_ADDRESS_ENV}={v:?} is not an IP literal ({e}); \
                 use 127.0.0.1 for host-only, 0.0.0.0 for every interface, or unset it"
            ))
        }),
        None => Ok(DEFAULT_BIND_ADDRESS),
    }
}

/// Resolve the port the production emulator should bind from the environment.
///
/// Reads [`DATA_PORT_ENV`], defaulting to [`DEFAULT_DATA_PORT`] (`9297`) when
/// unset or unparseable — so an emulator with no environment override binds
/// the well-known port.
///
/// A value of `0` selects an OS-assigned ephemeral port. Because the OS hands
/// out a distinct free port to each caller, several emulators can run
/// concurrently on a single host without colliding on the fixed well-known
/// ports — this is what lets callers run concurrent emulators without the
/// `Address already in use` failures that fixed ports caused. The caller learns
/// the actual port from [`serve_production`]'s post-bind startup announcement
/// (`endpoint_url`, the URL clients dial).
pub fn data_port_from_env() -> u16 {
    parse_port(std::env::var(DATA_PORT_ENV).ok().as_deref(), DEFAULT_DATA_PORT)
}

/// Pure port-parsing core of [`data_port_from_env`], split out so it is
/// unit-testable without mutating (and racing on) process-global environment
/// variables: returns `default` for an absent or unparseable value, and
/// preserves `0`.
fn parse_port(raw: Option<&str>, default: u16) -> u16 {
    match raw {
        Some(v) => v.trim().parse::<u16>().unwrap_or(default),
        None => default,
    }
}

/// Bind the production emulator's HTTPS listener on `bind_address`, honoring `0`
/// as "OS-assigned ephemeral port".
///
/// Returns the listener paired with its **post-bind** [`SocketAddr`] — the
/// concrete port the OS actually chose. Binding the data listener up front (as
/// a `std::net::TcpListener` handed to `axum_server::from_tcp_rustls`) rather
/// than letting `axum_server` bind lazily is what makes the announced
/// `endpoint_url` carry the *real* port when `data_port == 0`; otherwise the
/// announcement would advertise the placeholder `:0` and the launcher could not
/// discover the endpoint.
fn bind_production_listener(
    bind_address: IpAddr,
    data_port: u16,
) -> Result<(std::net::TcpListener, SocketAddr), ServeError> {
    let data_listener = std::net::TcpListener::bind(SocketAddr::from((bind_address, data_port)))
        .map_err(ServeError::Io)?;
    let data_addr = data_listener.local_addr().map_err(ServeError::Io)?;
    Ok((data_listener, data_addr))
}

/// Serve a [`EmulatorService`] as a long-lived production emulator, with the
/// listener port taken from the environment.
///
/// This is the entry point the generated emulator binary uses. The HTTPS port,
/// which also answers [`HEALTH_PATH`], comes from [`data_port_from_env`] —
/// [`DATA_PORT_ENV`], defaulting to `9297` when unset, with `0` selecting an
/// OS-assigned ephemeral port. Reading the environment *here* means every
/// caller (the generated server binary and any future one) gets env-driven port
/// selection for free, with no wrapper plumbing.
///
/// Passing `0` lets several emulators run **concurrently on one host** without
/// colliding on the fixed well-known port. The startup announcement logs the
/// **post-bind actual** port in `endpoint_url` and `health_check_url`, so even with
/// `0` the caller can discover the real port.
///
/// Delegates to [`serve_production_on_address`]; callers that must pin explicit
/// ports (e.g. tests) can call [`serve_production_on`] directly.
pub async fn serve_production<S: EmulatorService>(service: S) -> Result<(), ServeError> {
    let (bind_override, port_override) = cli::listen_overrides();
    let bind_address = match bind_override {
        Some(bind_address) => bind_address,
        None => bind_address_from_env()?,
    };
    let data_port = port_override.unwrap_or_else(data_port_from_env);
    serve_production_on_address(service, bind_address, data_port).await
}

/// Serve a [`EmulatorService`] as a long-lived production emulator on an
/// explicit port, matching the contract the control plane probes and replays
/// against. One self-signed **HTTPS** listener on `{bind_address}:{data_port}`
/// (default `9297`) serves both:
///
/// * **Health** — `GET` [`HEALTH_PATH`] -> `200 ok`, the readiness gate the
///   caller polls before it starts sending requests.
/// * **Data** — every other request goes to the full AWS service surface. A
///   caller connects with `https://<ip>:{data_port}` accepting
///   the self-signed cert.
///
/// # Port selection
///
/// `data_port` is bound verbatim, except that `0` selects an **OS-assigned
/// ephemeral port**. Callers that want the well-known default pass `9297` (see
/// [`DEFAULT_DATA_PORT`]); callers that want env-driven selection use
/// [`serve_production`] (which reads [`data_port_from_env`]); see it for how
/// the caller learns the port the OS chose.
///
/// Binds [`DEFAULT_BIND_ADDRESS`] (`127.0.0.1` — host-only), and returns only on
/// a serve error or a shutdown signal (SIGTERM / Ctrl+C). **A container
/// deployment must not use this function**: under `awsvpc` the health check
/// arrives at the task's ENI address, so a loopback listener never becomes
/// healthy. Call [`serve_production_on_address`] with `0.0.0.0`, or use
/// [`serve_production`] and set [`BIND_ADDRESS_ENV`] in the task definition. This
/// is the out-of-process counterpart to [`serve_on_ephemeral_port`], which binds
/// a loopback ephemeral port for in-process tests.
pub async fn serve_production_on<S: EmulatorService>(
    service: S,
    data_port: u16,
) -> Result<(), ServeError> {
    serve_production_on_address(service, DEFAULT_BIND_ADDRESS, data_port).await
}

/// [`serve_production_on`] with the bound interface named explicitly rather than
/// inherited from [`DEFAULT_BIND_ADDRESS`].
///
/// `bind_address` decides who can reach the emulator: `0.0.0.0` for every IPv4
/// interface (what a container deployment behind a load balancer requires, since
/// the health check arrives at the task's ENI address), `127.0.0.1` to confine it
/// to the host it runs on (what a developer running it on a workstation wants,
/// because the emulator authenticates nothing and holds whatever state its
/// callers created). [`serve_production`] resolves this from
/// [`BIND_ADDRESS_ENV`].
pub async fn serve_production_on_address<S: EmulatorService>(
    service: S,
    bind_address: IpAddr,
    data_port: u16,
) -> Result<(), ServeError> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let client_host = dialable_host(bind_address);
    let ca = TlsCertificateAuthority::covering(Some(client_host))
        .map_err(|e| ServeError::Tls(e.to_string()))?;
    if !ca.covers(client_host) {
        return Err(ServeError::Tls(format!(
            "this process's TLS certificate was made before the data port and does not name \
             {client_host}; set {BIND_ADDRESS_ENV}={client_host} so every listener covers it"
        )));
    }
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(
        data_listener_tls_config(ca).map_err(|e| ServeError::Tls(e.to_string()))?,
    );

    // Bind before announcing so the logged address is the REAL post-bind port
    // — essential when the port is `0` (OS-assigned).
    let (data_listener, data_addr) = bind_production_listener(bind_address, data_port)?;
    let port = data_addr.port();

    // The one published address of the data port: the shared config's `endpoint_url` and the
    // base of every URL the service hands out are this one value, so they cannot disagree.
    let endpoint_url = listeners::url_for(SocketAddr::new(client_host, port));
    service.serving_at(&endpoint_url);

    // The router is wrapped in panic containment: a panic in ANY operation
    // handler, extra route, or health probe is answered with a protocol-shaped
    // `500 InternalFailure` and the listener keeps serving, instead of unwinding
    // the connection task and leaving the caller on a dead socket.
    let data_router = with_panic_guard(
        axum::Router::new()
            .route(HEALTH_PATH, axum::routing::get(|| async { "ok" }))
            .fallback(emulator_service_fallback::<S>)
            .with_state(Arc::new(service)),
    );

    // Listen before publishing: a client that stops the emulator once it sees the published
    // files must get a clean stop, which removes them, not the signal's default exit.
    let shutdown = shutdown_signal();
    let credentials_file = match SigV4Authenticator::minted_credentials() {
        Some(keys) => Some(
            request_authentication::write_credentials_file(keys, data_addr.port())
                .map_err(ServeError::Io)?,
        ),
        None => None,
    };
    if let Some(file) = &credentials_file {
        tracing::info!(credentials_file = %file.0.display(), "request authentication enabled");
    }
    let ca_file = request_authentication::write_emulator_file(port, "ca.pem", &ca.pem())
        .map_err(ServeError::Io)?;
    // JVMs ignore `ca.pem`; they trust the emulator through this store, named by
    // `-Djavax.net.ssl.trustStore` (see `java_truststore`).
    let java_truststore_file = request_authentication::write_emulator_bytes(
        port,
        java_truststore::FILE_NAME,
        &ca.pkcs12_trust_store(),
    )
    .map_err(ServeError::Io)?;
    let config_text = shared_config_text(&endpoint_url, &ca_file.0);
    let config_file = request_authentication::write_emulator_file(port, "config", &config_text)
        .map_err(ServeError::Io)?;

    // `endpoint_url` is what clients dial; a bind other machines can reach is named by the
    // exposure warning below.
    tracing::info!(
        %endpoint_url,
        health_check_url = %format_args!("{endpoint_url}{HEALTH_PATH}"),
        config_file = %config_file.0.display(),
        ca_file = %ca_file.0.display(),
        java_truststore_file = %java_truststore_file.0.display(),
        "emulator server information"
    );
    for warning in exposure_warnings(bind_address, port, authentication_enabled()) {
        tracing::warn!(%bind_address, "{warning}");
    }
    // Ready means the port is bound and the client files are written: an error
    // before this point is a failed startup.
    if let Some(telemetry) = emulator_telemetry::global() {
        telemetry.mark_ready();
    }

    let mut data_server = axum_server::from_tcp_rustls(data_listener, tls_config);
    data_server
        .http_builder()
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    tokio::select! {
        result = data_server.serve(data_router.into_make_service()) => {
            result.map_err(ServeError::Io)?;
        }
        _ = shutdown => {
            tracing::info!("shutdown signal received; stopping emulator server");
        }
        _ = cli::idle_timeout_reached() => {
            tracing::info!("no API call within --idle-timeout; stopping emulator server");
        }
    }

    Ok(())
}

/// What a start must warn about: a bind other machines can reach, and request authentication
/// being off. Each names who can reach the emulator and how to narrow it, so the log alone says
/// what to change.
fn exposure_warnings(bind_address: IpAddr, port: u16, authentication: bool) -> Vec<String> {
    let reachable = !bind_address.to_canonical().is_loopback();
    let reachable_bind = reachable.then(|| reachable_bind_warning(bind_address, port));
    let authentication_off = (!authentication).then(|| AUTHENTICATION_OFF_WARNING.to_string());
    reachable_bind
        .into_iter()
        .chain(authentication_off)
        .collect()
}

fn reachable_bind_warning(bind_address: IpAddr, port: u16) -> String {
    format!(
        "the emulator listens on {bind_address}, not loopback: other machines that can \
         reach port {port} can call it; bind 127.0.0.1 (-b 127.0.0.1) unless that is intended"
    )
}

const AUTHENTICATION_OFF_WARNING: &str = "request authentication is off: the emulator accepts \
     any request, signed or not; start it with -a on to require signatures";

/// The address a client dials to reach a listener bound on `bind_address`: the address itself,
/// or loopback for a wildcard bind, which has no single address to name.
pub(crate) fn dialable_host(bind_address: IpAddr) -> IpAddr {
    match bind_address {
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ip if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    }
}

/// ALPN protocols the data listener offers: HTTP/1.1 only.
///
/// The server stack answers `Expect: 100-continue` with an interim
/// `100 Continue` on HTTP/1.1, but not on HTTP/2. A client that negotiates `h2`
/// and sends `Expect: 100-continue` (the AWS SDK for Kotlin does for S3 bodies
/// of 2 MiB or more) holds the body back waiting for that interim response,
/// while the emulator waits for the body, so the request stalls until the
/// client times out. Offering only `http/1.1` keeps every client on the path
/// that answers it, which also matches the S3 endpoints these clients target.
/// Every request on this listener is fully buffered, so nothing here relies on
/// HTTP/2 streaming.
const DATA_LISTENER_ALPN: &[&[u8]] = &[b"http/1.1"];

/// The rustls server config for the data listener: the process certificate `ca`, no
/// client auth, and [`DATA_LISTENER_ALPN`].
fn data_listener_tls_config(
    ca: &TlsCertificateAuthority,
) -> Result<Arc<rustls::ServerConfig>, rustls::Error> {
    let mut config = ca.server_config()?;
    config.alpn_protocols = DATA_LISTENER_ALPN.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(config))
}

/// The AWS shared config (`AWS_CONFIG_FILE`) that points an SDK or the CLI at this emulator.
fn shared_config_text(endpoint_url: &str, ca_file: &std::path::Path) -> String {
    let ca_file = ca_file.display();
    format!(
        "[default]\nregion = us-east-1\nendpoint_url = {endpoint_url}\nca_bundle = {ca_file}\n\
         s3 =\n  signature_version = s3v4\n"
    )
}

/// Listen for a shutdown signal (SIGTERM or Ctrl+C) from now on, so a stop request ends the
/// emulator cleanly instead of by the signal's default action. Each signal is listened for on its
/// own, so one that cannot be registered does not disable the other. The returned future
/// completes once one arrives, even if it arrived before the future was polled.
#[cfg(unix)]
fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    use tokio::signal::unix::{signal, SignalKind};
    let terminate = signal(SignalKind::terminate()).ok();
    let interrupt = signal(SignalKind::interrupt()).ok();
    async move {
        tokio::select! {
            _ = signal_received(terminate) => {}
            _ = signal_received(interrupt) => {}
        }
    }
}

/// Completes when `listening` receives its signal; never, when it could not be registered.
#[cfg(unix)]
async fn signal_received(listening: Option<tokio::signal::unix::Signal>) {
    match listening {
        Some(mut listening) => drop(listening.recv().await),
        None => std::future::pending().await,
    }
}

/// [`shutdown_signal`] where only Ctrl+C exists.
#[cfg(not(unix))]
fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    async {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// A boxed async handler for an extra, non-Smithy route. Receives the buffered
/// request and returns a buffered response — the same `Request<Bytes>` ->
/// `Response<Bytes>` shape a [`EmulatorService`] uses, so extra routes serve normal
/// request/response HTTP.
pub type ExtraRouteHandler = Arc<
    dyn Fn(
            http::Request<bytes::Bytes>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = http::Response<bytes::Bytes>> + Send>,
        > + Send
        + Sync,
>;

/// A predicate over the buffered request head+body that decides whether a
/// [`RouteMatcher::Predicate`] route handles a request. It is the fully general
/// escape hatch: it can key off method, the FULL uri (path + query), any header,
/// or even the body bytes — everything a raw AWS operation needs to self-route
/// when neither an exact path nor a simple prefix is enough (e.g. S3's
/// query-subresource operations like `?uploads` / `?acl`, or host-style bucket
/// addressing). It only READS the request; it never mutates it.
pub type RoutePredicate = Arc<dyn Fn(&http::Request<bytes::Bytes>) -> bool + Send + Sync>;

/// How an [`ExtraRoute`] decides whether it handles a given request.
#[derive(Clone)]
enum RouteMatcher {
    /// Exact `method` + exact `path` (the original, most-specific match).
    Exact { method: http::Method, path: String },
    /// Exact `method` + path *prefix* (`request.path().starts_with(prefix)`).
    ///
    /// This is what makes unbounded path spaces routable — an S3 bucket serves
    /// the whole `/{bucket}/{key}` subtree (keys contain arbitrarily many `/`),
    /// which no exact-path registration can cover.
    Prefix {
        method: http::Method,
        prefix: String,
    },
    /// A caller-supplied [`RoutePredicate`] — total control over matching.
    Predicate(RoutePredicate),
}

impl RouteMatcher {
    /// Whether this matcher claims `req`. Path/prefix matches also gate on the
    /// HTTP method; the predicate variant sees the whole request and decides
    /// everything itself.
    fn matches(&self, req: &http::Request<bytes::Bytes>) -> bool {
        match self {
            RouteMatcher::Exact { method, path } => {
                req.method() == method && req.uri().path() == path
            }
            RouteMatcher::Prefix { method, prefix } => {
                req.method() == method && req.uri().path().starts_with(prefix.as_str())
            }
            RouteMatcher::Predicate(pred) => pred(req),
        }
    }
}

#[derive(Clone)]
struct ExtraRoute {
    matcher: RouteMatcher,
    handler: ExtraRouteHandler,
}

/// Wraps a buffered Smithy [`EmulatorService`] and lets agent-owned server code
/// register arbitrary **non-Smithy routes** (e.g. a health check or any custom
/// endpoint) that are matched *before* Smithy dispatch.
///
/// This is the generic raw-HTTP escape hatch: it merges extra routes into the
/// serve path while leaving the Smithy `Request<Bytes> -> Response<Bytes>`
/// dispatch fully intact. Routes are tried in REGISTRATION ORDER and the first
/// matcher that claims the request wins; any request that no route claims falls
/// through to the wrapped Smithy service unchanged. Three matcher kinds are
/// available, from most to least specific:
///
/// * [`route`](Self::route) — exact `method` + `path` (e.g. `POST /__admin/example`).
/// * [`route_prefix`](Self::route_prefix) — `method` + path *prefix*, for
///   unbounded path spaces the codec can't express as fixed operation paths
///   (e.g. S3's `/{bucket}/{key}` subtree).
/// * [`route_matching`](Self::route_matching) — an arbitrary predicate over the
///   whole request (method, full uri incl. query, headers, body), the ultimate
///   catch-all a custom handler can self-dispatch on.
///
/// Every handler receives the RAW buffered request (headers + body bytes intact)
/// and returns a RAW buffered response, so it can implement `@httpPayload`/
/// raw-body operations and emit arbitrary XML/streaming bytes that the Smithy
/// codec does not model — the exact codegen gap this seam exists to cover.
///
/// Because `WithExtraRoutes` is itself a [`EmulatorService`], serve it on the
/// existing [`serve_on_ephemeral_port`] — no separate serve path is required:
///
/// ```ignore
/// let svc = WithExtraRoutes::new(my_smithy_service)
///     .route(http::Method::GET, "/health", |_req| async {
///         http::Response::builder()
///             .status(200)
///             .body(bytes::Bytes::from_static(b"ok"))
///             .unwrap()
///     });
/// let (endpoint, _svc) = serve_on_ephemeral_port(svc).await;
/// ```
#[derive(Clone)]
pub struct WithExtraRoutes<S> {
    smithy: S,
    routes: Vec<ExtraRoute>,
}

impl<S: EmulatorService> WithExtraRoutes<S> {
    /// Wrap a Smithy service with an (initially empty) set of extra routes.
    pub fn new(smithy: S) -> Self {
        Self {
            smithy,
            routes: Vec::new(),
        }
    }

    /// Register an extra route for an exact `method` + `path`. The handler
    /// receives the buffered request and returns a buffered response.
    pub fn route<H, Fut>(self, method: http::Method, path: impl Into<String>, handler: H) -> Self
    where
        H: Fn(http::Request<bytes::Bytes>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = http::Response<bytes::Bytes>> + Send + 'static,
    {
        self.push_route(
            RouteMatcher::Exact {
                method,
                path: path.into(),
            },
            handler,
        )
    }

    /// Register an extra route that matches `method` plus any request whose path
    /// STARTS WITH `prefix`. This is the seam for unbounded path spaces the
    /// Smithy codec cannot express as fixed operation paths — e.g. an S3 bucket
    /// serving the whole `/{bucket}/{key}` subtree, where the key contains an
    /// arbitrary number of `/` segments. The handler receives the raw buffered
    /// request (headers + body bytes intact) and returns a raw buffered
    /// response, so it can implement `@httpPayload`/raw-body operations and
    /// emit arbitrary XML/streaming bytes the codec does not model.
    pub fn route_prefix<H, Fut>(
        self,
        method: http::Method,
        prefix: impl Into<String>,
        handler: H,
    ) -> Self
    where
        H: Fn(http::Request<bytes::Bytes>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = http::Response<bytes::Bytes>> + Send + 'static,
    {
        self.push_route(
            RouteMatcher::Prefix {
                method,
                prefix: prefix.into(),
            },
            handler,
        )
    }

    /// Register an extra route guarded by an arbitrary `predicate` over the
    /// buffered request. This is the most general form: the predicate can key
    /// off method, the full uri (path AND query string), any header, or the body
    /// bytes, so a single custom handler can serve a whole family of operations
    /// that self-route (e.g. S3 query-subresource ops such as `?uploads`/`?acl`,
    /// or a catch-all fallback that dispatches internally). The predicate only
    /// READS the request; the matched handler then consumes it and returns a raw
    /// buffered response.
    pub fn route_matching<P, H, Fut>(self, predicate: P, handler: H) -> Self
    where
        P: Fn(&http::Request<bytes::Bytes>) -> bool + Send + Sync + 'static,
        H: Fn(http::Request<bytes::Bytes>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = http::Response<bytes::Bytes>> + Send + 'static,
    {
        self.push_route(RouteMatcher::Predicate(Arc::new(predicate)), handler)
    }

    fn push_route<H, Fut>(mut self, matcher: RouteMatcher, handler: H) -> Self
    where
        H: Fn(http::Request<bytes::Bytes>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = http::Response<bytes::Bytes>> + Send + 'static,
    {
        let handler: ExtraRouteHandler = Arc::new(move |req| Box::pin(handler(req)));
        self.routes.push(ExtraRoute { matcher, handler });
        self
    }
}

impl<S: EmulatorService> EmulatorService for WithExtraRoutes<S> {
    async fn handle_request(
        &self,
        req: http::Request<bytes::Bytes>,
    ) -> http::Response<bytes::Bytes> {
        let matched = self
            .routes
            .iter()
            .find(|r| r.matcher.matches(&req))
            .cloned();
        if let Some(route) = matched {
            return (route.handler)(req).await;
        }
        self.smithy.handle_request(req).await
    }

    fn serving_at(&self, endpoint_url: &str) {
        self.smithy.serving_at(endpoint_url);
    }
}

// ---------------------------------------------------------------------------
// Request routing-key resolution and the framework can_handle predicates
// ---------------------------------------------------------------------------

/// Resolve the target service key for a request, applying a fixed tiered
/// precedence: a SigV4 credential scope (the `Authorization` header, then a
/// presigned-URL `X-Amz-Credential` query parameter), then `X-Amz-Target`, then
/// a host-style endpoint (the `Host` header, then the HTTP/2 `:authority`).
/// `None` when no signal identifies a service.
///
/// The whole request is read, not just its headers, because two routable
/// signals do not live in a header: a presigned S3 URL carries its SigV4 scope
/// in the query string, and an HTTP/2 request addresses its endpoint through the
/// `:authority` pseudo-header, which `http` exposes on the URI rather than as a
/// `Host` header. Reading `parts.uri` alongside `parts.headers` lets a presigned,
/// anonymous, or HTTP/2 request route by the same tiered rule a signed HTTP/1
/// request does.
///
/// This is the single source of the routing key every front door reads: the
/// router's own `can_handle` filter runs it through
/// [`can_handle_based_on_route_key`], and a `404`/`500` diagnostic reports the
/// key it returned. A SigV4 scope wins because it is present on every signed AWS
/// SDK request and names the target service unambiguously, independent of the
/// wire protocol (`awsJson`, `restXml`, `awsQuery`, `ec2Query`, `restJson1`,
/// `rpcv2Cbor`). A host-style endpoint is the last resort, so an unsigned
/// (anonymous) request still routes when it addresses a service by endpoint.
pub fn resolve_route_key(parts: &http::request::Parts) -> Option<String> {
    resolve_route_key_from(&parts.uri, &parts.headers)
}

/// The routing rule [`resolve_route_key`] applies, over a borrowed URI and
/// header map rather than a whole [`http::request::Parts`]. Separated so the
/// request-based [`can_handle_based_on_route_key`] can apply the identical rule
/// without owning a `Parts`.
fn resolve_route_key_from(uri: &http::Uri, headers: &http::HeaderMap) -> Option<String> {
    service_from_sigv4(headers)
        .or_else(|| service_from_sigv4_query(uri))
        .or_else(|| service_from_target(headers))
        .or_else(|| service_from_host(headers))
        .or_else(|| service_from_authority(uri))
}

/// The SigV4 credential-scope service name (4th field of `Credential=`) from the
/// `Authorization` header, the PRIMARY routing signal [`resolve_route_key`]
/// reads first.
pub fn service_from_sigv4(headers: &http::HeaderMap) -> Option<String> {
    let scope = sigv4_credential_scope(headers)?;
    let key = normalize_service_key(&scope.service);
    (!key.is_empty()).then_some(key)
}

/// The SigV4 credential-scope service name from a presigned-URL `X-Amz-Credential`
/// query parameter, the second signal [`resolve_route_key`] reads.
///
/// A presigned request (an S3 presigned URL is the common case) carries its SigV4
/// scope in the query string instead of an `Authorization` header, so the primary
/// [`service_from_sigv4`] reader never sees it. The query value is the same
/// `<access key id>/<date>/<region>/<service>/aws4_request` scope, percent-encoded
/// (the `/` separators arrive as `%2F`); the 4th field is the signing name.
pub fn service_from_sigv4_query(uri: &http::Uri) -> Option<String> {
    let credential = query_param_value(uri, "X-Amz-Credential")?;
    let decoded = percent_decode_slashes(&credential);
    let mut fields = decoded.split('/');
    let (Some(_access_key_id), Some(_date), Some(_region), Some(service), Some("aws4_request")) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return None;
    };
    let key = normalize_service_key(service);
    (!key.is_empty()).then_some(key)
}

/// The `X-Amz-Target` service prefix (segment before the first `.`, trailing
/// `_<version>` stripped, e.g. `DynamoDB_20120810.GetItem` -> `dynamodb`). The
/// third signal [`resolve_route_key`] reads, covering awsJson services on an
/// unsigned request.
pub fn service_from_target(headers: &http::HeaderMap) -> Option<String> {
    let target = headers.get("x-amz-target")?.to_str().ok()?;
    let prefix = target.split('.').next()?;
    let key = normalize_service_key(strip_target_version_suffix(prefix));
    (!key.is_empty()).then_some(key)
}

/// The `Host` header's first dot-separated label (`iam.amazonaws.com` -> `iam`),
/// ignoring bare loopback hosts and IP literals (which do not name a service).
/// A host-style routing signal [`resolve_route_key`] reads, covering REST
/// services addressed by endpoint host — including an anonymous (unsigned)
/// request, which reaches this reader after every credential and target signal
/// is absent.
pub fn service_from_host(headers: &http::HeaderMap) -> Option<String> {
    let host = headers.get("host")?.to_str().ok()?;
    service_from_host_authority(host)
}

/// The HTTP/2 `:authority` first dot-separated label, the host-style equivalent
/// [`resolve_route_key`] reads last.
///
/// HTTP/2 replaces the `Host` header with the `:authority` pseudo-header, which
/// `http` parses onto the URI rather than exposing as a header, so an HTTP/2
/// request has no `Host` for [`service_from_host`] to read. Reading the URI
/// authority routes such a request — signed, anonymous, or presigned — by the
/// same endpoint rule a `Host`-bearing HTTP/1 request uses.
pub fn service_from_authority(uri: &http::Uri) -> Option<String> {
    let authority = uri.authority()?;
    service_from_host_authority(authority.as_str())
}

/// The service label shared by a `Host` header and a `:authority`: the first
/// dot-separated label of the host, with any `:port` and `user@` removed,
/// rejecting bare loopback hosts and IP literals (which do not name a service).
fn service_from_host_authority(host: &str) -> Option<String> {
    let host_no_userinfo = host.rsplit('@').next().unwrap_or(host);
    let host_no_port = host_no_userinfo
        .split(':')
        .next()
        .unwrap_or(host_no_userinfo);
    let label = host_no_port.split('.').next()?;
    let key = normalize_service_key(label);
    if key.is_empty() || key == "localhost" || key.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(key)
}

/// The raw value of query parameter `name` in `uri`, or `None` when the URI has
/// no query or the parameter is absent. The value is returned still
/// percent-encoded; the caller decodes what it needs.
fn query_param_value(uri: &http::Uri, name: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.to_string())
    })
}

/// Decode the percent-encoded `/` separators (`%2F`/`%2f`) in a SigV4
/// `X-Amz-Credential` scope so its `/`-delimited fields can be split. Only the
/// slash separator is decoded, which is all the scope's four fields and
/// `aws4_request` terminator require.
fn percent_decode_slashes(value: &str) -> String {
    value.replace("%2F", "/").replace("%2f", "/")
}

/// Whether `req` targets the AWS service whose SigV4 signing name is
/// `route_key`, using the tiered header precedence [`resolve_route_key`] applies.
///
/// This is the framework-owned predicate body that every macro-generated
/// `can_handle` delegates to, so the routing rule stays in agent-immutable code
/// and cannot drift per service.
pub fn can_handle_based_on_route_key(
    request: &http::Request<bytes::Bytes>,
    route_key: &str,
) -> bool {
    match resolve_route_key_from(request.uri(), request.headers()) {
        // `resolve_route_key` already returns a normalized key, so comparing
        // case-insensitively against the trimmed argument matches
        // `normalize_service_key` without allocating. Every registered handler
        // runs this once per request, so the allocation is worth avoiding. The
        // assert pins the invariant that makes the two forms equivalent.
        Some(resolved) => {
            debug_assert_eq!(
                resolved,
                normalize_service_key(&resolved),
                "resolve_route_key must return an already-normalized key"
            );
            resolved.eq_ignore_ascii_case(route_key.trim())
        }
        None => false,
    }
}

/// The first `/`-separated segment of `path`, or `None` when the path has no
/// non-empty first segment (`"/"`, `""`).
fn first_path_segment(path: &str) -> Option<&str> {
    let segment = path.trim_start_matches('/').split('/').next()?;
    (!segment.is_empty()).then_some(segment)
}

/// Whether `request` targets the service whose SigV4 signing name is `route_key`
/// AND whose modeled URI path space claims the request path.
///
/// `path_segments` is the set of first URI path segments the service's model
/// declares, derived at generated-crate build time by `emulator-core-build-support`.
/// It disambiguates services that SHARE one signing name: `bedrock` and
/// `bedrock-runtime` both sign as `bedrock`, so the signing name alone matches
/// both handlers and the router rejects the request as `AmbiguousService`. Their
/// path spaces are disjoint, so the first path segment separates them.
///
/// An EMPTY `path_segments` means the service published no usable path
/// discriminator and this degrades to exactly [`can_handle_based_on_route_key`].
/// `emulator-core-build-support` emits empty for any service whose modeled paths
/// cannot discriminate — an `awsQuery`/`awsJson` service (no `smithy.api#http`
/// traits at all, so it serves `POST /`), or a REST service whose URIs begin
/// with a path LABEL rather than a literal (S3 operations begin `/{Bucket}`,
/// which matches any first segment). That keeps every non-colliding service on
/// its existing behavior.
///
/// Matching is EXACT segment equality, deliberately NOT a prefix test. The
/// bedrock pair is the proof: `bedrock-runtime` publishes `/guardrail/...` while
/// the control plane publishes `/guardrails/...`, and the runtime's `model`
/// segment is a prefix of SIX control-plane segments (`model-copy-jobs`,
/// `model-customization`, `model-customization-jobs`, `model-import-jobs`,
/// `model-invocation-job`, `model-invocation-jobs`). Any `starts_with` test
/// would make both handlers claim those paths and reinstate the ambiguity this
/// function exists to remove. Comparison is also case-sensitive, matching HTTP
/// path semantics — the control plane publishes camelCase segments such as
/// `listTagsForResource` and `enforcedGuardrailsConfiguration`.
pub fn can_handle_based_on_route_key_and_path(
    request: &http::Request<bytes::Bytes>,
    route_key: &str,
    path_segments: &[&str],
) -> bool {
    if !can_handle_based_on_route_key(request, route_key) {
        return false;
    }
    if path_segments.is_empty() {
        return true;
    }
    match first_path_segment(request.uri().path()) {
        Some(segment) => path_segments.contains(&segment),
        // A ROOT path (`POST /`). `first_path_segment` can never return this sentinel
        // for a real request, so it is unambiguous. It is how a service that is BOTH
        // RPC and partly http-bound claims its RPC traffic without claiming every
        // path: Glue is awsJson1_1 with a MINORITY of its operations http-bound, so it must
        // answer `POST /` while NOT swallowing a peer that shares its signing name and
        // owns a real path space.
        None => path_segments.contains(&ROOT_PATH_SEGMENT),
    }
}

/// Sentinel in `ROUTE_PATH_SEGMENTS` meaning "this service claims the ROOT path".
///
/// Emitted by `emulator-core-build-support` for a service whose protocol is RPC — every
/// operation posts to `/` — but whose model also carries `smithy.api#http` bindings on
/// some operations. Publishing an EMPTY segment list for such a service makes it claim
/// every path under its signing name, so it swallows a peer that shares that name and
/// the router answers `500 AmbiguousService` for the peer's traffic.
pub const ROOT_PATH_SEGMENT: &str = "/";

/// Generate a service crate's `can_handle` entry point, bound to consts baked in
/// at generation time.
///
/// Emitted by `emulator-core-build-support` alongside `pub const ROUTE_KEY` and
/// `pub const ROUTE_PATH_SEGMENTS`, so the generated (agent-editable) crate
/// carries only the constants while the matching rule lives in
/// [`can_handle_based_on_route_key_and_path`].
///
/// A service serves a request when the signing name matches AND the request's
/// first URI path segment is one its model declares. That path conjunct is what
/// lets two services sharing a signing name (`bedrock` and `bedrock-runtime` both
/// sign as `bedrock`) each claim only their own requests. A service whose model
/// publishes no usable path discriminator passes an EMPTY `ROUTE_PATH_SEGMENTS`,
/// which matches on the signing name alone.
///
/// ```ignore
/// pub const ROUTE_KEY: &str = "bedrock";
/// pub const ROUTE_PATH_SEGMENTS: &[&str] = &["async-invoke", "guardrail", "model"];
/// emulator_server::impl_emulator_can_handle!(ROUTE_KEY, ROUTE_PATH_SEGMENTS);
///
/// // A service with no path discriminator (every awsQuery/awsJson service):
/// pub const ROUTE_KEY: &str = "sqs";
/// pub const ROUTE_PATH_SEGMENTS: &[&str] = &[];
/// emulator_server::impl_emulator_can_handle!(ROUTE_KEY, ROUTE_PATH_SEGMENTS);
/// ```
#[macro_export]
macro_rules! impl_emulator_can_handle {
    ($route_key:expr, $path_segments:expr) => {
        /// Whether this service serves `request`, per its generated route key and
        /// the first URI path segments its model declares.
        pub fn can_handle(request: &$crate::http::Request<$crate::bytes::Bytes>) -> bool {
            $crate::can_handle_based_on_route_key_and_path(request, $route_key, $path_segments)
        }
    };
}

/// Normalize a service key to the canonical form the router indexes by:
/// trimmed and ASCII-lowercased (`"IAM"`, `" iam "`, and `"iam"` all collide).
fn normalize_service_key(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// Strip a trailing `_<digits>` API-version suffix from an `X-Amz-Target`
/// prefix, e.g. `DynamoDB_20120810` -> `DynamoDB`. Leaves any other name intact.
fn strip_target_version_suffix(prefix: &str) -> &str {
    if let Some(idx) = prefix.rfind('_') {
        let suffix = &prefix[idx + 1..];
        if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()) {
            return &prefix[..idx];
        }
    }
    prefix
}

/// The leading four fields of a SigV4 `Credential=` scope:
/// `<access key id>/<date>/<region>/<service>/aws4_request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4Scope {
    pub access_key_id: String,
    pub date: String,
    pub region: String,
    pub service: String,
}

/// Parse the SigV4 credential scope out of an `Authorization` header.
///
/// The single source of SigV4-scope parsing: service routing
/// ([`service_from_sigv4`]) and telemetry region
/// extraction both build on it instead of re-splitting the header.
pub fn sigv4_credential_scope(headers: &http::HeaderMap) -> Option<SigV4Scope> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    // Trimming after the scheme tolerates the single- and double-space
    // variants of the "AWS4-HMAC-SHA256 " prefix.
    let credential = auth
        .strip_prefix("AWS4-HMAC-SHA256 ")?
        .trim_start()
        .strip_prefix("Credential=")?
        .split(',')
        .next()?
        .trim();
    let mut fields = credential.split('/');
    let (Some(access_key_id), Some(date), Some(region), Some(service), Some("aws4_request"), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return None;
    };
    if access_key_id.is_empty() || date.is_empty() || region.is_empty() || service.is_empty() {
        return None;
    }
    Some(SigV4Scope {
        access_key_id: access_key_id.to_string(),
        date: date.to_string(),
        region: region.to_string(),
        service: service.to_string(),
    })
}

/// Run the emulator as a long-lived production server.
///
/// Calls `serve_production` (self-signed TLS on 9297 with
/// [`HEALTH_PATH`] on the same port, overridable via `EMULATOR_DATA_PORT`,
/// on the interface named by `EMULATOR_BIND_ADDRESS` — see
/// [`BIND_ADDRESS_ENV`] and [`DEFAULT_BIND_ADDRESS`]).
///
/// # Example
/// ```ignore
/// // `router` is any `EmulatorService`. In a generated emulator it is the
/// // `smithy_server_runtime::MultiServiceRouter` assembled from the mounted services.
/// serve_emulator(router).await;
/// ```
pub async fn serve_emulator<R: EmulatorService>(router: R) -> ! {
    match serve_emulator_until_shutdown(router).await {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            tracing::error!(error = %e, "emulator server failed");
            std::process::exit(1);
        }
    }
}

/// Run the emulator as a long-lived production server, RETURNING on shutdown
/// instead of exiting the process.
///
/// Same as [`serve_emulator`], but the caller
/// gets control back after a shutdown signal (Ctrl+C / SIGTERM) or a serve
/// error — the seam a generated `main.rs` needs to run bounded cleanup such
/// as a final telemetry flush before the process exits.
pub async fn serve_emulator_until_shutdown<R: EmulatorService>(
    router: R,
) -> Result<(), ServeError> {
    reporting_startup_failure(serve_production(router).await)
}

/// [`serve_emulator_until_shutdown`] with explicit bind address and port
/// (bypassing the `EMULATOR_*` environment), for tests and embedders
/// that manage their own port allocation.
pub async fn serve_emulator_on<R: EmulatorService>(
    router: R,
    bind_address: IpAddr,
    data_port: u16,
) -> Result<(), ServeError> {
    reporting_startup_failure(serve_production_on_address(router, bind_address, data_port).await)
}

/// Telemetry reports a serve that ended in an error before it was ready as a
/// failed startup; an error after ready leaves the startup outcome as it is.
fn reporting_startup_failure(result: Result<(), ServeError>) -> Result<(), ServeError> {
    if result.is_err()
        && let Some(telemetry) = emulator_telemetry::global()
    {
        telemetry.mark_startup_failed();
    }
    result
}

// Initialize the standard JSON tracing subscriber for emulator binaries.
//
// Requires `tracing-subscriber` with `json` + `env-filter` features in the
// caller's Cargo.toml (the router crate has it; the core library does not).
// This is a convenience note — callers should inline:
// ```ignore
// tracing_subscriber::fmt()
//     .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
//         .unwrap_or_else(|_| "info".into()))
//     .json()
//     .init();
// ```

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;
    use parking_lot::Mutex;
    use std::collections::HashMap;

    /// A service that answers every request with a fixed response.
    #[derive(Clone)]
    struct Fixed(http::Response<bytes::Bytes>);

    impl EmulatorService for Fixed {
        async fn handle_request(
            &self,
            _req: http::Request<bytes::Bytes>,
        ) -> http::Response<bytes::Bytes> {
            self.0.clone()
        }
    }

    fn sdk_request() -> aws_smithy_runtime_api::client::orchestrator::HttpRequest {
        aws_smithy_runtime_api::client::orchestrator::HttpRequest::get("http://localhost/")
            .expect("a valid request")
    }

    /// The SDK reads an S3 `ETag`, `Content-Length` and version id, among much else, from
    /// the response headers, so the connector must hand every header through, repeated
    /// ones included, along with the status and the body.
    #[tokio::test]
    async fn the_connector_passes_the_status_every_header_and_the_body_through() {
        let response = http::Response::builder()
            .status(206)
            .header("etag", "\"abc\"")
            .header("content-length", "5")
            .header("x-amz-version-id", "v1")
            .header("x-amz-meta-note", "first")
            .header("x-amz-meta-note", "second")
            .body(bytes::Bytes::from_static(b"hello"))
            .unwrap();

        let out = http_connector_call(&Fixed(response), sdk_request())
            .await
            .unwrap();

        check!(out.status().as_u16() == 206);
        check!(out.headers().get("etag") == Some("\"abc\""));
        check!(out.headers().get("content-length") == Some("5"));
        check!(out.headers().get("x-amz-version-id") == Some("v1"));
        check!(out.headers().get_all("x-amz-meta-note").collect::<Vec<_>>() == ["first", "second"]);
        check!(out.body().bytes() == Some(&b"hello"[..]));
    }

    /// A response with no headers still converts, and a header value that is not valid
    /// text is carried through without a panic.
    #[tokio::test]
    async fn the_connector_converts_a_headerless_response_and_a_non_text_header() {
        let plain = http::Response::new(bytes::Bytes::from_static(b"ok"));
        let out = http_connector_call(&Fixed(plain), sdk_request())
            .await
            .unwrap();
        check!(out.status().as_u16() == 200);
        check!(out.body().bytes() == Some(&b"ok"[..]));

        let mut binary = http::Response::new(bytes::Bytes::new());
        binary.headers_mut().insert(
            "x-binary",
            http::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        check!(
            http_connector_call(&Fixed(binary), sdk_request())
                .await
                .is_ok()
        );
    }

    fn with_status(status: u16, body: &'static [u8]) -> http::Response<bytes::Bytes> {
        http::Response::builder()
            .status(status)
            .body(bytes::Bytes::from_static(body))
            .unwrap()
    }

    /// Over a socket hyper frames a response with `Content-Length: <body length>`; the
    /// in-process connector writes the same header, for a success and an error alike.
    #[tokio::test]
    async fn the_connector_frames_a_response_with_its_body_length() {
        for (status, body, want) in [
            (200, &b"{\"TableNames\":[]}"[..], "17"),
            (
                400,
                &b"{\"__type\":\"ResourceNotFoundException\"}"[..],
                "38",
            ),
            (200, &b""[..], "0"),
        ] {
            let out = http_connector_call(&Fixed(with_status(status, body)), sdk_request())
                .await
                .unwrap();
            check!(out.headers().get("content-length") == Some(want));
        }
    }

    /// A length the handler set stays as it is (an S3 `HeadObject` reports the object's
    /// size over an empty body), and a status that carries no content gets none, as hyper
    /// writes it.
    #[tokio::test]
    async fn the_connector_keeps_a_handler_length_and_adds_none_to_a_status_without_content() {
        let mut head = with_status(200, b"");
        head.headers_mut()
            .insert("content-length", http::HeaderValue::from_static("5"));
        let out = http_connector_call(&Fixed(head), sdk_request())
            .await
            .unwrap();
        check!(out.headers().get("content-length") == Some("5"));

        for status in [204, 304] {
            let out = http_connector_call(&Fixed(with_status(status, b"")), sdk_request())
                .await
                .unwrap();
            check!(out.headers().get("content-length").is_none());
        }

        let mut chunked = with_status(200, b"abc");
        chunked.headers_mut().insert(
            "transfer-encoding",
            http::HeaderValue::from_static("chunked"),
        );
        let out = http_connector_call(&Fixed(chunked), sdk_request())
            .await
            .unwrap();
        check!(out.headers().get("content-length").is_none());
    }


    #[test]
    fn rustls_trusts_the_server_certificate_as_its_own_ca() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let der = CertificateDer::from(TlsCertificateAuthority::for_this_process().der().to_vec());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        for host in ["127.0.0.1", "::1"].map(|name| ServerName::try_from(name).unwrap()) {
            let verified = verifier.verify_server_cert(&der, &[], &host, &[], UnixTime::now());
            check!(verified.is_ok());
        }
    }

    #[test]
    fn a_wildcard_bind_is_dialed_on_loopback_and_an_address_as_itself() {
        let dial = |bind: &str| dialable_host(bind.parse().unwrap()).to_string();
        check!(dial("0.0.0.0") == "127.0.0.1");
        check!(dial("::") == "::1");
        check!(dial("10.0.0.5") == "10.0.0.5");
        check!(dial("::1") == "::1");
    }

    #[test]
    fn the_shared_config_names_the_region_endpoint_ca_bundle_and_s3_sigv4() {
        let endpoint = listeners::url_for(SocketAddr::from((Ipv4Addr::LOCALHOST, 9297)));
        let text = shared_config_text(&endpoint, std::path::Path::new("/h/.emulator/9297/ca.pem"));
        check!(
            text == "[default]\nregion = us-east-1\nendpoint_url = https://127.0.0.1:9297\nca_bundle = /h/.emulator/9297/ca.pem\ns3 =\n  signature_version = s3v4\n"
        );
    }

    #[test]
    fn extract_akid_standard_sigv4() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc"
                .parse()
                .unwrap(),
        );
        check!(extract_akid(&headers) == "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn extract_akid_double_space() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "authorization",
            "AWS4-HMAC-SHA256  Credential=TESTKEY/20240101/us-east-1/kms/aws4_request, SignedHeaders=host, Signature=abc"
                .parse()
                .unwrap(),
        );
        check!(extract_akid(&headers) == "TESTKEY");
    }

    #[test]
    fn extract_akid_missing_header() {
        let headers = http::HeaderMap::new();
        check!(extract_akid(&headers) == "default");
    }

    #[test]
    fn extract_akid_non_sigv4() {
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        check!(extract_akid(&headers) == "default");
    }

    #[test]
    fn extract_akid_empty_credential() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=/20240101/us-east-1/kms/aws4_request, SignedHeaders=host, Signature=abc"
                .parse()
                .unwrap(),
        );
        check!(extract_akid(&headers) == "default");
    }

    #[test]
    fn error_response_structure() {
        let resp = aws_json_error_response(
            400,
            "ValidationException",
            "bad input",
            AwsJsonProtocol::V1_1,
        );
        check!(resp.status() == 400);
        check!(resp.headers().get("content-type").unwrap() == "application/x-amz-json-1.1");
        // restJson1 reads the error SHAPE from this header, not the body, and it must
        // agree with the body or a client resolves two different shapes from one
        // response. `wire_error_response` already set it; this builder did not, so
        // the two boundary error paths disagreed.
        check!(resp.headers().get("x-amzn-errortype").unwrap() == "ValidationException");
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        check!(body["__type"] == "ValidationException");
        check!(body["message"] == "bad input");
    }

    /// The header must never turn a 4xx into a PANIC.
    ///
    /// `error_type` is a `&str` on a public signature. A header value rejects control
    /// bytes that a JSON string accepts, so setting it unchecked defers validation to
    /// `.body()` and makes the `expect` there panic — on the error path, where a panic
    /// becomes a 500 that SDKs RETRY. The header is omitted instead; the body's
    /// `__type` still carries the shape.
    #[test]
    fn an_unrepresentable_error_type_omits_the_header_instead_of_panicking() {
        for hostile in ["Bad\u{0}Type", "Bad\nType", "Bad\u{7f}Type"] {
            let resp = aws_json_error_response(400, hostile, "m", AwsJsonProtocol::V1_1);
            check!(resp.status() == 400);
            check!(resp.headers().get("x-amzn-errortype").is_none());
            // The shape is still resolvable from the body.
            let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
            check!(body["__type"] == hostile);
        }
    }

    #[test]
    fn ok_response_structure() {
        let resp = aws_json_ok_response(
            &serde_json::json!({"KeyId": "abc-123"}),
            AwsJsonProtocol::V1_1,
        );
        check!(resp.status() == 200);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        check!(body["KeyId"] == "abc-123");
    }

    #[test]
    fn error_response_with_service_prefix() {
        let resp = aws_json_error_response(
            400,
            "com.amazonaws.cognitoidentityprovider#ResourceNotFoundException",
            "User pool not found",
            AwsJsonProtocol::V1_1,
        );
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        check!(body["__type"] == "com.amazonaws.cognitoidentityprovider#ResourceNotFoundException");
    }

    #[test]
    fn ok_response_v1_0_content_type() {
        let resp = aws_json_ok_response(
            &serde_json::json!({"TableName": "t"}),
            AwsJsonProtocol::V1_0,
        );
        check!(resp.headers().get("content-type").unwrap() == "application/x-amz-json-1.0");
    }

    #[test]
    fn error_response_v1_0_content_type() {
        let resp =
            aws_json_error_response(500, "InternalServerError", "boom", AwsJsonProtocol::V1_0);
        check!(resp.headers().get("content-type").unwrap() == "application/x-amz-json-1.0");
    }

    #[derive(Clone)]
    struct EchoService;

    impl EmulatorService for EchoService {
        async fn handle_request(
            &self,
            _req: http::Request<bytes::Bytes>,
        ) -> http::Response<bytes::Bytes> {
            aws_json_ok_response(&serde_json::json!({"echo": true}), AwsJsonProtocol::V1_1)
        }
    }

    #[tokio::test]
    async fn serve_on_ephemeral_port_accepts_requests() {
        let (endpoint, _svc) = serve_on_ephemeral_port(EchoService).await;

        let resp = reqwest::Client::new()
            .post(&endpoint)
            .header("content-type", "application/x-amz-json-1.1")
            .body("{}")
            .send()
            .await
            .expect("request should succeed");
        check!(resp.status() == 200);

        let body: serde_json::Value = resp.json().await.expect("valid json");
        check!(body["echo"] == true);
    }

    // -----------------------------------------------------------------------
    // Custom raw-route escape hatch: prefix + predicate matching. These prove
    // the seam a generated emulator uses to serve codegen-unsupported ops
    // (restXml `@httpPayload` raw bodies, unbounded `/{bucket}/{key}` paths)
    // WITHOUT the Smithy codec — while normal ops still fall through to Smithy.
    // -----------------------------------------------------------------------

    /// A tiny object store shared by the mini-S3 handlers, keyed by request path.
    fn new_store() -> Arc<Mutex<HashMap<String, bytes::Bytes>>> {
        Arc::new(Mutex::new(HashMap::new()))
    }

    /// Wire a mini PUT/GET object API onto `/test-bucket/` via prefix routes,
    /// plus a predicate route that claims any request carrying `x-raw-op`.
    fn mini_s3(store: Arc<Mutex<HashMap<String, bytes::Bytes>>>) -> WithExtraRoutes<EchoService> {
        let put_store = store.clone();
        let get_store = store.clone();
        WithExtraRoutes::new(EchoService)
            .route_prefix(http::Method::PUT, "/test-bucket/", move |req| {
                let store = put_store.clone();
                async move {
                    let key = req.uri().path().to_string();
                    // Raw @httpPayload body: stored verbatim, no codec parsing.
                    store.lock().insert(key, req.into_body());
                    http::Response::builder()
                        .status(200)
                        .body(bytes::Bytes::new())
                        .unwrap()
                }
            })
            .route_prefix(http::Method::GET, "/test-bucket/", move |req| {
                let store = get_store.clone();
                async move {
                    let key = req.uri().path();
                    match store.lock().get(key) {
                        Some(bytes) => http::Response::builder()
                            .status(200)
                            .header("content-type", "application/octet-stream")
                            .body(bytes.clone())
                            .unwrap(),
                        None => http::Response::builder()
                            .status(404)
                            .body(bytes::Bytes::new())
                            .unwrap(),
                    }
                }
            })
            .route_matching(
                |req: &http::Request<bytes::Bytes>| req.headers().contains_key("x-raw-op"),
                |_req| async {
                    http::Response::builder()
                        .status(418)
                        .body(bytes::Bytes::from_static(b"raw-op"))
                        .unwrap()
                },
            )
    }

    #[tokio::test]
    async fn custom_prefix_route_serves_raw_body_round_trip_in_process() {
        let svc = mini_s3(new_store());

        // PUT a raw payload under a DEEPLY nested key (multiple `/` segments) —
        // the prefix matcher covers the whole unbounded `/{bucket}/{key}` space.
        let put = http::Request::builder()
            .method(http::Method::PUT)
            .uri("/test-bucket/nested/dir/object.bin")
            .body(bytes::Bytes::from_static(b"\x00\x01raw-payload-bytes\xff"))
            .unwrap();
        let put_resp = svc.handle_request(put).await;
        check!(put_resp.status() == 200);

        // GET it back: exact raw bytes, round-tripped without any codec.
        let get = http::Request::builder()
            .method(http::Method::GET)
            .uri("/test-bucket/nested/dir/object.bin")
            .body(bytes::Bytes::new())
            .unwrap();
        let get_resp = svc.handle_request(get).await;
        check!(get_resp.status() == 200);
        check!(get_resp.body().as_ref() == b"\x00\x01raw-payload-bytes\xff");

        // A miss under the same prefix is the handler's own 404 (not Smithy).
        let miss = http::Request::builder()
            .method(http::Method::GET)
            .uri("/test-bucket/absent")
            .body(bytes::Bytes::new())
            .unwrap();
        check!(svc.handle_request(miss).await.status() == 404);

        // Predicate route: any request with `x-raw-op` is claimed regardless of
        // method/path (here a path that matches no prefix route).
        let pred = http::Request::builder()
            .method(http::Method::POST)
            .uri("/anything")
            .header("x-raw-op", "1")
            .body(bytes::Bytes::new())
            .unwrap();
        let pred_resp = svc.handle_request(pred).await;
        check!(pred_resp.status() == 418);
        check!(pred_resp.body().as_ref() == b"raw-op");
    }

    #[tokio::test]
    async fn normal_ops_fall_through_to_smithy_when_no_custom_route_matches() {
        let svc = mini_s3(new_store());

        // A request that matches NO custom route (wrong bucket prefix, no
        // `x-raw-op`) must reach the wrapped Smithy service unchanged.
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("/other-bucket/thing")
            .body(bytes::Bytes::from_static(b"{}"))
            .unwrap();
        let resp = svc.handle_request(req).await;
        check!(resp.status() == 200);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        check!(body["echo"] == true);
    }

    #[tokio::test]
    async fn custom_prefix_route_serves_raw_body_round_trip_over_socket() {
        let (endpoint, _svc) = serve_on_ephemeral_port(mini_s3(new_store())).await;
        let client = reqwest::Client::new();

        // PutObject-style raw upload via the hatch (no SigV4, no codec).
        let put = client
            .put(format!("{endpoint}/test-bucket/photos/2026/pic.jpg"))
            .body("binary-ish object contents")
            .send()
            .await
            .expect("put should connect");
        check!(put.status() == 200);

        // GetObject-style raw download returns the exact stored bytes.
        let get = client
            .get(format!("{endpoint}/test-bucket/photos/2026/pic.jpg"))
            .send()
            .await
            .expect("get should connect");
        check!(get.status() == 200);
        let got = get.bytes().await.expect("body");
        check!(got.as_ref() == b"binary-ish object contents");

        // An AWS-shaped call that matches no custom route falls through to the
        // Smithy service (proving no regression to normal dispatch).
        let smithy = client
            .post(format!("{endpoint}/"))
            .header("content-type", "application/x-amz-json-1.1")
            .body("{}")
            .send()
            .await
            .expect("smithy call should connect");
        check!(smithy.status() == 200);
        let body: serde_json::Value = smithy.json().await.expect("valid json");
        check!(body["echo"] == true);
    }

    // -----------------------------------------------------------------------
    // Production serve path: one TLS listener (:9297-shaped) serving both the
    // health path and the AWS surface. This is the exact contract the emulator
    // launcher probes (`HEALTH_PATH`) and a client connects to
    // (`https://<ip>:<data_port>`).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn serve_production_serves_health_and_data_over_one_tls_port() {
        // Mount the AWS surface plus an admin-style extra route to prove the
        // wrapped EmulatorService (WithExtraRoutes) is what gets served.
        let svc = WithExtraRoutes::new(EchoService).route(
            http::Method::POST,
            "/__admin/extra",
            |_req| async {
                http::Response::builder()
                    .status(200)
                    .body(bytes::Bytes::from_static(b"{\"extra\":true}"))
                    .unwrap()
            },
        );

        let (data_port, server) = serve_production_on_a_free_port(svc).await;
        let client = tls_client();
        let health_url = format!("https://127.0.0.1:{data_port}{HEALTH_PATH}");

        // 1) Health on the data port answers 200 "ok" over HTTPS.
        let health = client
            .get(&health_url)
            .send()
            .await
            .expect("health request should connect");
        check!(health.status() == 200);
        check!(health.text().await.unwrap() == "ok");

        // 2) The same port (self-signed, accepted) routes an AWS-shaped request
        //    through the wrapped EmulatorService.
        let resp = client
            .post(format!("https://127.0.0.1:{data_port}/"))
            .header("content-type", "application/x-amz-json-1.1")
            .body("{}")
            .send()
            .await
            .expect("data request should connect over TLS");
        check!(resp.status() == 200);
        let body: serde_json::Value = resp.json().await.expect("valid json");
        check!(body["echo"] == true);

        // 3) The wrapped extra route is reachable over the same TLS listener.
        let admin = client
            .post(format!("https://127.0.0.1:{data_port}/__admin/extra"))
            .send()
            .await
            .expect("admin route reachable over TLS");
        check!(admin.status() == 200);
        let admin_body: serde_json::Value = admin.json().await.expect("valid json");
        check!(admin_body["extra"] == true);

        // 4) Health is not a plaintext endpoint any more.
        let plaintext = reqwest::get(format!("http://127.0.0.1:{data_port}{HEALTH_PATH}")).await;
        check!(plaintext.is_err() || plaintext.unwrap().status() != 200);

        server.abort();
    }

    fn tls_client() -> reqwest::Client {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("tls client")
    }

    /// A service that reports the URL `serve_production_on` hands its `serving_at`, so a test
    /// can serve on an OS-assigned port and still learn which one.
    #[derive(Clone)]
    struct ReportsItsUrl<S> {
        inner: S,
        url: Arc<Mutex<Option<tokio::sync::oneshot::Sender<String>>>>,
    }

    impl<S: EmulatorService> EmulatorService for ReportsItsUrl<S> {
        fn handle_request(
            &self,
            req: http::Request<bytes::Bytes>,
        ) -> impl std::future::Future<Output = http::Response<bytes::Bytes>> + Send {
            self.inner.handle_request(req)
        }

        fn serving_at(&self, endpoint_url: &str) {
            self.inner.serving_at(endpoint_url);
            if let Some(report) = self.url.lock().take() {
                let _ = report.send(endpoint_url.to_string());
            }
        }
    }

    /// Serve `svc` through `serve_production_on` on an OS-assigned port, and return that port
    /// once health answers on it. A fixed port fails whenever anything else on the host holds
    /// it, such as the same suite building for another platform on a shared build host. A
    /// serve that ends before binding fails the test with the serve's own error.
    async fn serve_production_on_a_free_port<S: EmulatorService>(
        svc: S,
    ) -> (u16, tokio::task::JoinHandle<Result<(), ServeError>>) {
        let (report, reported) = tokio::sync::oneshot::channel();
        let svc = ReportsItsUrl {
            inner: svc,
            url: Arc::new(Mutex::new(Some(report))),
        };
        let server = tokio::spawn(serve_production_on(svc, 0));
        let endpoint_url =
            match tokio::time::timeout(std::time::Duration::from_secs(10), reported).await {
                Ok(Ok(url)) => url,
                Ok(Err(_)) => panic!("the emulator ended before binding: {:?}", server.await),
                Err(_) => panic!("the emulator did not bind its data port within 10s"),
            };
        let port: u16 = endpoint_url
            .rsplit(':')
            .next()
            .and_then(|port| port.parse().ok())
            .unwrap_or_else(|| panic!("no port in {endpoint_url}"));
        let health_url = format!("https://127.0.0.1:{port}{HEALTH_PATH}");
        check!(
            wait_until_serving(&tls_client(), &health_url).await,
            "the listener must bind"
        );
        (port, server)
    }

    /// A JVM with no TLS code reaches the production listener once
    /// `JAVA_TOOL_OPTIONS` names the published `truststore.p12`, and fails the
    /// handshake without it. Skipped when no `JAVA_HOME/bin/java` is present.
    /// Multi-threaded because the JVM runs as a blocking child process while the
    /// server task must keep answering it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_jvm_trusts_the_emulator_through_the_published_truststore() {
        let Some(java) = std::env::var_os("JAVA_HOME")
            .map(|home| std::path::PathBuf::from(home).join("bin").join("java"))
            .filter(|path| path.exists())
        else {
            eprintln!("skipped: no JAVA_HOME/bin/java");
            return;
        };
        // `java Health.java` (single-file source launch) needs JDK 11 or later.
        let version = std::process::Command::new(&java)
            .arg("-version")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stderr).into_owned())
            .unwrap_or_default();
        let major = java_major_version(&version);
        if major.is_none_or(|major| major < 11) {
            eprintln!("skipped: needs JDK 11 or later, found {major:?}");
            return;
        }
        let (data_port, server) = serve_production_on_a_free_port(EchoService).await;
        let health_url = format!("https://127.0.0.1:{data_port}{HEALTH_PATH}");

        let store = emulator_paths::emulator_home()
            .unwrap()
            .join(data_port.to_string())
            .join(java_truststore::FILE_NAME);
        check!(store.exists(), "{} must be published", store.display());

        // Single-file source launch: plain HttpsURLConnection, default trust only.
        let dir = std::env::temp_dir().join(format!("jvm-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("Health.java");
        std::fs::write(
            &source,
            "public class Health { public static void main(String[] a) throws Exception {\n\
             var c = (javax.net.ssl.HttpsURLConnection) new java.net.URL(a[0]).openConnection();\n\
             System.out.print(new String(c.getInputStream().readAllBytes()));\n} }\n",
        )
        .unwrap();
        let run = |tool_options: Option<String>| {
            let mut cmd = std::process::Command::new(&java);
            cmd.arg(&source)
                .arg(&health_url)
                .env_remove("JAVA_TOOL_OPTIONS");
            if let Some(options) = tool_options {
                cmd.env("JAVA_TOOL_OPTIONS", options);
            }
            cmd.output().unwrap()
        };

        let trusted = run(Some(format!(
            "-Djavax.net.ssl.trustStore={} -Djavax.net.ssl.trustStoreType=PKCS12",
            store.display()
        )));
        let untrusted = run(None);
        let _ = std::fs::remove_dir_all(&dir);
        server.abort();

        check!(
            trusted.status.success() && trusted.stdout == b"ok",
            "trusted run: {}",
            String::from_utf8_lossy(&trusted.stderr)
        );
        check!(
            !untrusted.status.success(),
            "without the store the handshake must fail"
        );
        check!(String::from_utf8_lossy(&untrusted.stderr).contains("PKIX"));
    }

    /// The major version from `java -version` output: `"1.8.0_402"` is 8,
    /// `"11.0.33"` and `"21"` are 11 and 21.
    fn java_major_version(output: &str) -> Option<u32> {
        let quoted = output.split('"').nth(1)?;
        let mut parts = quoted.split(['.', '_', '-', '+']);
        match parts.next()?.parse().ok()? {
            1 => parts.next()?.parse().ok(),
            major => Some(major),
        }
    }

    #[test]
    fn java_major_version_reads_old_and_new_formats() {
        check!(java_major_version("java version \"1.8.0_402\"") == Some(8));
        check!(java_major_version("openjdk version \"11.0.33\" 2026-10-20 LTS") == Some(11));
        check!(java_major_version("openjdk version \"21\" 2023-09-19") == Some(21));
        check!(java_major_version("openjdk version \"17-ea\"") == Some(17));
        check!(java_major_version("no version here").is_none());
    }

    // -----------------------------------------------------------------------
    // Dynamic port allocation: env-driven port selection + OS-assigned (`0`)
    // ports so several emulators can run concurrently on one host without the
    // `Address already in use` failures fixed ports caused under concurrent
    // probes.
    // -----------------------------------------------------------------------

    #[test]
    fn parse_port_defaults_preserves_zero_and_rejects_garbage() {
        // Unset -> documented default (backward compatible).
        check!(parse_port(None, DEFAULT_DATA_PORT) == DEFAULT_DATA_PORT);
        // Explicit fixed port is honored verbatim.
        check!(parse_port(Some("8081"), DEFAULT_DATA_PORT) == 8081);
        // `0` is preserved — it requests an OS-assigned ephemeral port.
        check!(parse_port(Some("0"), DEFAULT_DATA_PORT) == 0);
        // Surrounding whitespace is tolerated.
        check!(parse_port(Some(" 9443 "), DEFAULT_DATA_PORT) == 9443);
        // Non-numeric / out-of-`u16`-range / empty all fall back to the default.
        check!(parse_port(Some("not-a-port"), DEFAULT_DATA_PORT) == DEFAULT_DATA_PORT);
        check!(parse_port(Some("70000"), DEFAULT_DATA_PORT) == DEFAULT_DATA_PORT);
        check!(parse_port(Some(""), DEFAULT_DATA_PORT) == DEFAULT_DATA_PORT);
    }

    #[test]
    fn data_port_from_env_defaults_to_the_well_known_port_when_unset() {
        // No test in this crate sets EMULATOR_DATA_PORT, so the resolver must
        // return the well-known port.
        check!(data_port_from_env() == DEFAULT_DATA_PORT);
        // Customers copy this port from the AWS Emulator user guide. Changing
        // it needs a user guide change in the same release.
        check!(DEFAULT_DATA_PORT == 9297);
    }

    #[test]
    fn a_loopback_authenticated_start_warns_about_nothing() {
        let loopback = [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "::1".parse().unwrap(),
            "::ffff:127.0.0.1".parse().unwrap(),
        ];
        for bind in loopback {
            check!(exposure_warnings(bind, 9297, true).is_empty(), "{bind}");
        }
    }

    #[test]
    fn every_non_loopback_bind_warns_who_can_reach_the_emulator() {
        for bind in ["0.0.0.0", "::", "10.0.0.5"] {
            let warnings = exposure_warnings(bind.parse().unwrap(), 9297, true);
            let expected = format!("the emulator listens on {bind}, not loopback");
            check!(
                warnings.len() == 1 && warnings[0].starts_with(&expected),
                "{bind}"
            );
            check!(warnings[0].contains("port 9297"));
        }
    }

    #[test]
    fn a_start_without_authentication_warns_that_any_request_is_accepted() {
        let warnings = exposure_warnings(IpAddr::V4(Ipv4Addr::LOCALHOST), 9297, false);
        check!(warnings == [AUTHENTICATION_OFF_WARNING]);
    }

    #[test]
    fn a_reachable_start_without_authentication_warns_about_both() {
        check!(exposure_warnings(Ipv4Addr::UNSPECIFIED.into(), 9297, false).len() == 2);
    }

    #[test]
    fn parse_bind_address_defaults_to_loopback_and_refuses_a_non_literal() {
        // Unset -> host-only. This is the property that makes an emulator started
        // with no environment safe on a workstation, and the one a container
        // deployment must override explicitly.
        check!(parse_bind_address(None).unwrap() == DEFAULT_BIND_ADDRESS);
        check!(DEFAULT_BIND_ADDRESS == IpAddr::V4(Ipv4Addr::LOCALHOST));
        check!(parse_bind_address(None).unwrap().is_loopback());
        // Both directions of the choice this knob exists to express.
        check!(parse_bind_address(Some("127.0.0.1")).unwrap() == DEFAULT_BIND_ADDRESS);
        check!(
            parse_bind_address(Some("0.0.0.0"))
                .unwrap()
                .is_unspecified()
        );
        // IPv6 forms parse too.
        check!(parse_bind_address(Some("::1")).unwrap().is_loopback());
        check!(parse_bind_address(Some("::")).unwrap().is_unspecified());
        // Surrounding whitespace is tolerated, as it is for a port.
        check!(
            parse_bind_address(Some(" 0.0.0.0 "))
                .unwrap()
                .is_unspecified()
        );

        // Anything that is not an IP literal is REFUSED rather than defaulted:
        // silently substituting a different interface would either widen the
        // reachable surface or take the listener away from its health check, and
        // both mistakes are invisible at the point they are made. A hostname is
        // included deliberately — it looks like it should work.
        for rejected in ["localhost", "loopback", "0.0.0.0:8443", "", "  "] {
            let error = parse_bind_address(Some(rejected));
            assert!(
                matches!(error, Err(ServeError::BindAddress(_))),
                "{rejected:?} must be refused, not defaulted"
            );
            // The message names the variable and the value, so the operator does
            // not have to infer which input was rejected.
            let rendered = error.unwrap_err().to_string();
            assert!(
                rendered.contains(BIND_ADDRESS_ENV),
                "the error must name {BIND_ADDRESS_ENV}, got {rendered:?}"
            );
        }
    }

    #[test]
    fn bind_production_listener_honors_the_requested_interface() {
        // Both directions. The wildcard is spelled out rather than taken from
        // DEFAULT_BIND_ADDRESS, so this test keeps testing the wildcard if the
        // default moves again.
        let (_data_listener, data_addr) =
            bind_production_listener(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).expect("loopback bind");
        check!(data_addr.ip().is_loopback());

        let (_data_listener, data_addr) =
            bind_production_listener(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).expect("wildcard bind");
        check!(data_addr.ip().is_unspecified());

        // And the default is the host-only one, which is what an emulator started
        // with no environment gets.
        let (_data_listener, data_addr) =
            bind_production_listener(DEFAULT_BIND_ADDRESS, 0).expect("default bind");
        check!(data_addr.ip().is_loopback());
    }

    #[test]
    fn bind_production_listener_assigns_distinct_real_ports_for_zero() {
        // Two concurrent OS-assigned (`0`) binds get distinct, REAL (non-zero)
        // ports — the property that lets concurrent probes coexist without
        // colliding on the fixed 9297.
        let (data1_listener, data1) =
            bind_production_listener(DEFAULT_BIND_ADDRESS, 0).expect("first bind");
        let (_data2_listener, data2) = bind_production_listener(DEFAULT_BIND_ADDRESS, 0)
            .expect("second concurrent bind must not collide");

        for (label, addr) in [("data1", data1), ("data2", data2)] {
            assert!(
                addr.port() != 0,
                "{label} must report the real OS-assigned port, not the placeholder 0"
            );
        }

        assert_ne!(
            data1.port(),
            data2.port(),
            "the two OS-assigned ports must be distinct"
        );

        // Sanity: binding a FIXED port that is already held DOES fail with the
        // `Address already in use` error that requesting `0` avoids. Reuse
        // data1's still-held port to prove that failure mode is real (guards
        // against SO_REUSEADDR masking an active-listener collision).
        let reuse = bind_production_listener(DEFAULT_BIND_ADDRESS, data1.port());
        assert!(
            matches!(reuse, Err(ServeError::Io(_))),
            "re-binding an already-held fixed port must fail (EADDRINUSE), got {reuse:?}"
        );

        drop(data1_listener);
    }

    #[tokio::test]
    async fn two_emulators_launch_concurrently_on_os_assigned_ports() {
        use std::time::Duration;

        // Launch TWO full production emulators concurrently, BOTH requesting
        // OS-assigned ports (`0`), so they coexist instead of colliding on a
        // fixed port. Exercised through the real
        // `serve_production_on` bind/serve path (`serve_production` delegates to
        // it after reading the ports from the environment).
        let first = tokio::spawn(async { serve_production_on(EchoService, 0).await });
        let second = tokio::spawn(async { serve_production_on(EchoService, 0).await });

        // serve_production only returns on a bind/serve error or shutdown; give
        // both a moment to bind, then assert neither exited early.
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(
            !first.is_finished(),
            "first emulator exited early (a bind/serve error) instead of serving"
        );
        assert!(
            !second.is_finished(),
            "second concurrent emulator exited early — port 0 must avoid EADDRINUSE"
        );

        first.abort();
        second.abort();
    }

    // -----------------------------------------------------------------------
    // Generic extra-route seam (end-to-end over a real TCP socket).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn extra_route_responds_and_smithy_still_works() {
        let svc =
            WithExtraRoutes::new(EchoService).route(http::Method::GET, "/health", |_req| async {
                http::Response::builder()
                    .status(200)
                    .body(bytes::Bytes::from_static(b"ok"))
                    .unwrap()
            });
        let (endpoint, _svc) = serve_on_ephemeral_port(svc).await;

        // 1) The agent-registered extra route answers.
        let resp = reqwest::Client::new()
            .get(format!("{endpoint}/health"))
            .send()
            .await
            .expect("GET /health");
        check!(resp.status() == 200);
        check!(resp.text().await.unwrap() == "ok");

        // 2) The Smithy dispatch is untouched: POST / still echoes.
        let resp = reqwest::Client::new()
            .post(&endpoint)
            .header("content-type", "application/x-amz-json-1.1")
            .body("{}")
            .send()
            .await
            .expect("POST /");
        check!(resp.status() == 200);
        let body: serde_json::Value = resp.json().await.expect("valid json");
        check!(body["echo"] == true);
    }

    // -----------------------------------------------------------------------
    // Routing predicates: tested directly, as pure request + key(s) -> bool
    //
    // The functions below ([`can_handle_based_on_route_key`],
    // [`can_handle_based_on_route_key_and_path`], [`resolve_route_key`] and the
    // `service_from_*` readers) are this crate's own routing RULE. The pins
    // assert them directly on a built request, with no router: a service either
    // claims a request or it does not, which is a property of the predicate
    // alone. The multi-service SELECTION contract these predicates feed — one
    // claimant serves, zero is `404 UnknownService`, two or more is
    // `500 AmbiguousService` — belongs to `smithy_server_runtime::MultiServiceRouter`
    // and is pinned against that real router in its own crate, not reimplemented
    // here.
    // -----------------------------------------------------------------------
    fn headers_with(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        for (k, v) in pairs {
            headers.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        headers
    }

    fn sigv4(service: &str) -> String {
        format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240101/us-east-1/{service}/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature=deadbeef"
        )
    }

    fn signed_request(service: &str) -> http::Request<bytes::Bytes> {
        http::Request::builder()
            .method("POST")
            .uri("/")
            .header("authorization", sigv4(service))
            .body(bytes::Bytes::from_static(b"{}"))
            .unwrap()
    }

    /// A buffered POST carrying exactly `pairs` as headers — used to drive one
    /// routing signal (or none) at a time.
    fn request_with(pairs: &[(&str, &str)]) -> http::Request<bytes::Bytes> {
        let mut request = http::Request::builder()
            .method("POST")
            .uri("/")
            .body(bytes::Bytes::from_static(b"{}"))
            .unwrap();
        *request.headers_mut() = headers_with(pairs);
        request
    }

    /// The `http::request::Parts` of a `POST uri` carrying exactly `pairs` as
    /// headers — the shape [`resolve_route_key`] reads, so a test can drive the
    /// URI (query string, `:authority`) and headers together.
    fn parts_with_uri(uri: &str, pairs: &[(&str, &str)]) -> http::request::Parts {
        let mut request = http::Request::builder()
            .method("POST")
            .uri(uri)
            .body(bytes::Bytes::from_static(b"{}"))
            .unwrap();
        *request.headers_mut() = headers_with(pairs);
        request.into_parts().0
    }

    /// The `http::request::Parts` of a `POST /` carrying exactly `pairs` as
    /// headers — the header-only equivalent of [`parts_with_uri`] for a test that
    /// drives a header signal with no query string or authority.
    fn parts_with(pairs: &[(&str, &str)]) -> http::request::Parts {
        parts_with_uri("/", pairs)
    }

    #[test]
    fn sigv4_credential_scope_extracts_all_four_fields() {
        let headers = headers_with(&[(
            "authorization",
            "AWS4-HMAC-SHA256  Credential=AKIDEXAMPLE/20240101/eu-west-1/DynamoDB/aws4_request, \
             SignedHeaders=host, Signature=abc",
        )]);
        let scope = sigv4_credential_scope(&headers).unwrap();
        check!(scope.access_key_id == "AKIDEXAMPLE");
        check!(scope.date == "20240101");
        check!(scope.region == "eu-west-1");
        check!(scope.service == "DynamoDB");
        check!(sigv4_credential_scope(&http::HeaderMap::new()).is_none());
        let basic = headers_with(&[("authorization", "Basic dXNlcjpwYXNz")]);
        check!(sigv4_credential_scope(&basic).is_none());
        let truncated = headers_with(&[("authorization", "AWS4-HMAC-SHA256 Credential=AKID/2024")]);
        check!(sigv4_credential_scope(&truncated).is_none());
        let other_scheme = headers_with(&[(
            "authorization",
            "Bearer Credential=AKID/20240101/us-west-2/sqs/aws4_request",
        )]);
        check!(sigv4_credential_scope(&other_scheme).is_none());
        let wrong_terminator = headers_with(&[(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKID/20240101/us-west-2/sqs/not_sigv4",
        )]);
        check!(sigv4_credential_scope(&wrong_terminator).is_none());
        let extra_component = headers_with(&[(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKID/20240101/us-west-2/sqs/aws4_request/x",
        )]);
        check!(sigv4_credential_scope(&extra_component).is_none());
    }

    #[test]
    fn service_from_sigv4_extracts_scope_service() {
        let headers = headers_with(&[("authorization", &sigv4("iam"))]);
        check!(service_from_sigv4(&headers) == Some("iam".to_string()));
    }

    #[test]
    fn service_from_sigv4_tolerates_double_space_and_case() {
        let headers = headers_with(&[(
            "authorization",
            "AWS4-HMAC-SHA256  Credential=AKID/20240101/eu-west-1/DynamoDB/aws4_request, \
             SignedHeaders=host, Signature=abc",
        )]);
        check!(service_from_sigv4(&headers) == Some("dynamodb".to_string()));
    }

    #[test]
    fn service_from_sigv4_none_when_absent_or_malformed() {
        check!(service_from_sigv4(&http::HeaderMap::new()).is_none());
        let basic = headers_with(&[("authorization", "Basic dXNlcjpwYXNz")]);
        check!(service_from_sigv4(&basic).is_none());
    }

    #[test]
    fn service_from_target_strips_version_suffix() {
        let headers = headers_with(&[("x-amz-target", "DynamoDB_20120810.GetItem")]);
        check!(service_from_target(&headers) == Some("dynamodb".to_string()));
    }

    #[test]
    fn service_from_target_without_version() {
        let headers = headers_with(&[("x-amz-target", "AWSKMS.Encrypt")]);
        check!(service_from_target(&headers) == Some("awskms".to_string()));
    }

    #[test]
    fn service_from_host_takes_first_label() {
        let headers = headers_with(&[("host", "dynamodb.us-east-1.amazonaws.com")]);
        check!(service_from_host(&headers) == Some("dynamodb".to_string()));
    }

    #[test]
    fn service_from_host_ignores_loopback_and_ip() {
        let local = headers_with(&[("host", "localhost:8443")]);
        check!(service_from_host(&local).is_none());
        let ip = headers_with(&[("host", "127.0.0.1:8443")]);
        check!(service_from_host(&ip).is_none());
    }

    #[test]
    fn route_key_prefers_sigv4_over_target_and_host() {
        // All three signals present but disagree: SigV4 (iam) must win.
        let parts = parts_with(&[
            ("authorization", &sigv4("iam")),
            ("x-amz-target", "DynamoDB_20120810.GetItem"),
            ("host", "s3.amazonaws.com"),
        ]);
        check!(resolve_route_key(&parts) == Some("iam".to_string()));
    }

    #[test]
    fn route_key_falls_back_to_target_then_host() {
        // No auth: X-Amz-Target wins over Host.
        let target = parts_with(&[
            ("x-amz-target", "DynamoDB_20120810.GetItem"),
            ("host", "s3.amazonaws.com"),
        ]);
        check!(resolve_route_key(&target) == Some("dynamodb".to_string()));

        // No auth, no target: Host is the last resort.
        let host = parts_with(&[("host", "s3.amazonaws.com")]);
        check!(resolve_route_key(&host) == Some("s3".to_string()));
    }

    #[test]
    fn route_key_none_when_no_signal() {
        check!(resolve_route_key(&parts_with(&[])).is_none());
    }

    #[test]
    fn route_key_from_presigned_credential_query_only() {
        // A presigned S3 URL carries the SigV4 scope in the query string, not an
        // `Authorization` header. The `/` separators arrive percent-encoded as
        // `%2F`, and other presigned query parameters surround `X-Amz-Credential`.
        let parts = parts_with_uri(
            "/my-bucket/key.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=AKIDEXAMPLE%2F20240101%2Fus-east-1%2Fs3%2Faws4_request\
             &X-Amz-Date=20240101T000000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host\
             &X-Amz-Signature=deadbeef",
            &[("host", "my-bucket.s3.amazonaws.com")],
        );
        // The presigned credential names `s3` directly; it must win over the host
        // label, exactly as an `Authorization` SigV4 scope outranks `Host`.
        check!(resolve_route_key(&parts) == Some("s3".to_string()));
    }

    #[test]
    fn route_key_authorization_header_outranks_presigned_query() {
        // Both a signed header and a presigned query are present and disagree. The
        // `Authorization` scope is the primary signal and must win.
        let parts = parts_with_uri(
            "/?X-Amz-Credential=AKIDEXAMPLE%2F20240101%2Fus-east-1%2Fs3%2Faws4_request",
            &[("authorization", &sigv4("iam"))],
        );
        check!(resolve_route_key(&parts) == Some("iam".to_string()));
    }

    #[test]
    fn route_key_from_http2_authority_when_no_host_header() {
        // An HTTP/2 request has no `Host` header; `http` parses `:authority` onto
        // the URI. A request addressed only by authority must still route by its
        // endpoint label.
        let parts = parts_with_uri("https://dynamodb.us-east-1.amazonaws.com/", &[]);
        check!(parts.headers.get("host").is_none());
        check!(parts.uri.authority().is_some());
        check!(resolve_route_key(&parts) == Some("dynamodb".to_string()));
    }

    #[test]
    fn route_key_host_header_outranks_authority() {
        // When both a `Host` header and a URI authority are present and disagree,
        // the `Host` header is read first, matching the host-style tier order.
        let parts = parts_with_uri(
            "https://s3.amazonaws.com/",
            &[("host", "iam.amazonaws.com")],
        );
        check!(resolve_route_key(&parts) == Some("iam".to_string()));
    }

    #[test]
    fn route_key_anonymous_request_routes_by_host() {
        // No credentials and no `X-Amz-Target`: an anonymous request still routes
        // when it addresses a service by endpoint host.
        let host_parts = parts_with(&[("host", "sqs.us-east-1.amazonaws.com")]);
        check!(host_parts.headers.get("authorization").is_none());
        check!(resolve_route_key(&host_parts) == Some("sqs".to_string()));

        // The same anonymous request over HTTP/2, addressed by `:authority`.
        let authority_parts = parts_with_uri("https://sqs.us-east-1.amazonaws.com/", &[]);
        check!(resolve_route_key(&authority_parts) == Some("sqs".to_string()));
    }

    #[test]
    fn route_key_ignores_loopback_authority_and_malformed_presigned_query() {
        // A loopback authority names no service, exactly as a loopback `Host` does.
        let loopback = parts_with_uri("http://localhost:8443/", &[]);
        check!(resolve_route_key(&loopback).is_none());

        // A presigned credential whose scope does not terminate in `aws4_request`
        // is not a SigV4 scope and names no service.
        let malformed = parts_with_uri(
            "/?X-Amz-Credential=AKIDEXAMPLE%2F20240101%2Fus-east-1%2Fs3%2Fnot_the_terminator",
            &[],
        );
        check!(resolve_route_key(&malformed).is_none());
    }

    // -----------------------------------------------------------------------
    // Macro-generated `can_handle` parity with the previous `route_key` lookup
    // -----------------------------------------------------------------------

    /// DynamoDB exactly as `emulator-core-build-support` generates it: `awsJson1_0`,
    /// so no operation carries `smithy.api#http` and the derived
    /// `ROUTE_PATH_SEGMENTS` is EMPTY. That empty list is the real generated shape
    /// for every awsQuery/awsJson service, and it must route on the signing name
    /// alone — which is what the parity assertion below pins.
    mod generated_service {
        pub const ROUTE_KEY: &str = "dynamodb";
        pub const ROUTE_PATH_SEGMENTS: &[&str] = &[];
        crate::impl_emulator_can_handle!(ROUTE_KEY, ROUTE_PATH_SEGMENTS);
    }

    #[test]
    fn macro_generated_can_handle_matches_the_previous_route_key_lookup() {
        // The generated predicate must select a handler on exactly the signals
        // `route_key(headers) == key` selects, agreeing on every signal tier and
        // on every no-match case, or it silently changes which emulator serves a
        // request.
        let cases: Vec<(&str, http::Request<bytes::Bytes>)> = vec![
            ("sigv4 match", signed_request("dynamodb")),
            ("sigv4 match, mixed case", signed_request("DynamoDB")),
            ("sigv4 miss", signed_request("iam")),
            (
                "target match with version suffix",
                request_with(&[("x-amz-target", "DynamoDB_20120810.GetItem")]),
            ),
            (
                "target miss",
                request_with(&[("x-amz-target", "AWSKMS.Encrypt")]),
            ),
            (
                "host match",
                request_with(&[("host", "dynamodb.us-east-1.amazonaws.com")]),
            ),
            ("host miss", request_with(&[("host", "iam.amazonaws.com")])),
            (
                "loopback host resolves nothing",
                request_with(&[("host", "localhost:8443")]),
            ),
            ("no signal at all", request_with(&[])),
            (
                "non-ascii signing name resolves but never matches",
                request_with(&[("authorization", &sigv4("dynamodb\u{00e9}"))]),
            ),
            (
                "interior whitespace in the signing name",
                request_with(&[("authorization", &sigv4("dynamo db"))]),
            ),
            (
                "sigv4 wins over a disagreeing target",
                request_with(&[
                    ("authorization", &sigv4("dynamodb")),
                    ("x-amz-target", "AWSKMS.Encrypt"),
                ]),
            ),
            (
                "sigv4 miss wins over a matching target",
                request_with(&[
                    ("authorization", &sigv4("iam")),
                    ("x-amz-target", "DynamoDB_20120810.GetItem"),
                ]),
            ),
        ];

        for (label, request) in cases {
            let legacy = resolve_route_key_from(request.uri(), request.headers()).as_deref()
                == Some(generated_service::ROUTE_KEY);
            let generated = generated_service::can_handle(&request);
            check!(generated == legacy, "{}", label);
        }
    }

    #[test]
    fn the_rds_trio_signs_identically_so_only_the_signing_name_predicate_claims() {
        // rds, docdb and neptune all sign as `rds`: a shared-config wire capture
        // showed byte-identical requests to rds.us-west-2.amazonaws.com with
        // credential scope .../us-west-2/rds/aws4_request. The signing name alone
        // therefore CANNOT separate them, so a predicate keyed on each of the
        // three claims the request only for the key that equals the wire signal.
        // The router's verdict on three siblings that each claim their own key
        // (served) versus three that collide on the shared key (refused) is the
        // SELECTION contract, pinned against the real `MultiServiceRouter`.
        let request = signed_request("rds");
        for key in ["rds", "docdb", "neptune"] {
            let claims = can_handle_based_on_route_key(&request, key);
            // Only the signing name itself matches on the wire signal; the other
            // two are separated by per-service endpoints, not by this predicate.
            check!(claims == (key == "rds"), "{key}");
        }
    }

    // -----------------------------------------------------------------------
    // Path-segment discrimination: two services sharing one signing name
    // -----------------------------------------------------------------------

    /// The two bedrock service crates as `emulator-core-build-support` generates them.
    /// Both carry `ROUTE_KEY = "bedrock"` because both models declare
    /// `aws.auth#sigv4/name = "bedrock"`; only `ROUTE_PATH_SEGMENTS` separates
    /// them. Each list is the real set derived from the published model
    /// (`bedrock-runtime-2023-09-30`, `bedrock-2023-04-20`), so these fixtures
    /// drift with the models rather than encoding a convenient subset.
    mod generated_bedrock_runtime {
        pub const ROUTE_KEY: &str = "bedrock";
        pub const ROUTE_PATH_SEGMENTS: &[&str] =
            &["async-invoke", "guardrail", "guardrail-checks", "model"];
        crate::impl_emulator_can_handle!(ROUTE_KEY, ROUTE_PATH_SEGMENTS);
    }

    mod generated_bedrock_control_plane {
        pub const ROUTE_KEY: &str = "bedrock";
        pub const ROUTE_PATH_SEGMENTS: &[&str] = &[
            "advanced-prompt-optimization-job",
            "advanced-prompt-optimization-jobs",
            "automated-reasoning-policies",
            "create-foundation-model-agreement",
            "custom-models",
            "data-retention",
            "delete-foundation-model-agreement",
            "enforcedGuardrailsConfiguration",
            "evaluation-job",
            "evaluation-jobs",
            "foundation-model-availability",
            "foundation-models",
            "guardrails",
            "imported-models",
            "inference-profiles",
            "list-foundation-model-agreement-offers",
            "listTagsForResource",
            "logging",
            "marketplace-model",
            "model-copy-jobs",
            "model-customization",
            "model-customization-jobs",
            "model-import-jobs",
            "model-invocation-job",
            "model-invocation-jobs",
            "prompt-routers",
            "provisioned-model-throughput",
            "provisioned-model-throughputs",
            "resource-policy",
            "tagResource",
            "untagResource",
            "use-case-for-model-access",
        ];
        crate::impl_emulator_can_handle!(ROUTE_KEY, ROUTE_PATH_SEGMENTS);
    }

    /// A `bedrock`-signed request to `path`, as either bedrock SDK client sends it.
    fn bedrock_request(path: &str) -> http::Request<bytes::Bytes> {
        http::Request::builder()
            .method("POST")
            .uri(path)
            .header("authorization", sigv4("bedrock"))
            .body(bytes::Bytes::from_static(b"{}"))
            .unwrap()
    }

    /// Which of the two bedrock predicates claim `path`, as `(runtime, control)`.
    fn bedrock_claimants(path: &str) -> (bool, bool) {
        let request = bedrock_request(path);
        (
            generated_bedrock_runtime::can_handle(&request),
            generated_bedrock_control_plane::can_handle(&request),
        )
    }

    #[test]
    fn a_bedrock_runtime_request_is_claimed_only_by_the_runtime() {
        // An InvokeModel round-trip. Before path discrimination BOTH
        // predicates claimed this (shared signing name) and the request was
        // ambiguous, so neither bedrock probe could pass. Only the runtime
        // predicate claims it now.
        check!(bedrock_claimants("/model/anthropic.claude-v2/invoke") == (true, false));
    }

    #[test]
    fn a_bedrock_control_plane_request_is_claimed_only_by_the_control_plane() {
        check!(bedrock_claimants("/foundation-models") == (false, true));
    }

    #[tokio::test]
    async fn every_modeled_first_segment_routes_to_exactly_one_bedrock_service() {
        // The disjointness the whole mechanism rests on, asserted over the FULL
        // derived sets rather than one sampled path from each: no modeled first
        // segment may be claimed by both services, or by neither.
        for segment in generated_bedrock_runtime::ROUTE_PATH_SEGMENTS {
            let path = format!("/{segment}/some/tail");
            check!(
                bedrock_claimants(&path) == (true, false),
                "runtime {segment}"
            );
        }
        for segment in generated_bedrock_control_plane::ROUTE_PATH_SEGMENTS {
            let path = format!("/{segment}/some/tail");
            check!(
                bedrock_claimants(&path) == (false, true),
                "control {segment}"
            );
        }
    }

    #[test]
    fn singular_guardrail_and_plural_guardrails_route_to_different_services() {
        // THE regression test for a `starts_with` rewrite. `bedrock-runtime`
        // publishes `/guardrail/...` and the control plane `/guardrails/...`: the
        // runtime's segment is a strict prefix of the control plane's, so a prefix
        // test would make the runtime claim BOTH and reinstate the ambiguity. Each
        // path must be claimed by exactly one of the two predicates.
        check!(bedrock_claimants("/guardrail/gr-123/version/1/apply") == (true, false));
        check!(bedrock_claimants("/guardrails/gr-123") == (false, true));
    }

    #[test]
    fn the_runtime_model_segment_does_not_claim_the_control_planes_model_prefixed_paths() {
        // The second half of the prefix trap, and the wider one: the runtime's
        // `model` segment is a strict prefix of SIX control-plane segments. Under a
        // prefix test the runtime would claim every one of them.
        for segment in [
            "model-copy-jobs",
            "model-customization",
            "model-customization-jobs",
            "model-import-jobs",
            "model-invocation-job",
            "model-invocation-jobs",
        ] {
            let path = format!("/{segment}/job-1");
            check!(bedrock_claimants(&path) == (false, true), "{segment}");
        }
    }

    #[test]
    fn an_unmodeled_bedrock_path_is_claimed_by_neither() {
        // Neither predicate claims a path no model declares, so the request has
        // zero claimants. The router turns zero claimants into a loud
        // `404 UnknownService` rather than falling back to either emulator; that
        // selection verdict is pinned against the real `MultiServiceRouter`.
        check!(bedrock_claimants("/not-a-modeled-segment") == (false, false));
    }

    #[test]
    fn two_distinct_services_sharing_a_key_and_first_segment_both_claim_one_request() {
        // Path discrimination narrows claimants; it does NOT, on its own, break a
        // tie. Two services modeled with the same signing name AND a first path
        // segment in common each have their predicate claim a request to that
        // segment, so the request has two claimants. The two predicates are
        // genuinely distinct here (different segment sets that merely overlap on
        // `shared`), which is the real still-colliding shape. Turning two
        // claimants into a `500 AmbiguousService` that names both is the router's
        // SELECTION contract, pinned against the real `MultiServiceRouter`.
        let request = bedrock_request("/shared/thing");
        check!(can_handle_based_on_route_key_and_path(
            &request,
            "bedrock",
            &["shared"]
        ));
        check!(can_handle_based_on_route_key_and_path(
            &request,
            "bedrock",
            &["shared", "other"]
        ));
    }

    #[test]
    fn an_empty_segment_list_is_no_constraint_and_preserves_signing_name_only_routing() {
        // The no-regression guarantee for every service that does not collide.
        // `emulator-core-build-support` emits an empty list for an awsQuery/awsJson
        // service (no `smithy.api#http` traits) and for a REST service whose URIs
        // begin with a path label (every S3 operation begins `/{Bucket}`). Empty
        // must therefore behave EXACTLY like the signing-name-only predicate on
        // every path, including paths no model declares.
        for path in ["/", "/anything", "/{Bucket}", "/model/x/invoke", "/a/b/c"] {
            let request = http::Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", sigv4("sqs"))
                .body(bytes::Bytes::from_static(b"{}"))
                .unwrap();
            let with_empty = can_handle_based_on_route_key_and_path(&request, "sqs", &[]);
            let signing_name_only = can_handle_based_on_route_key(&request, "sqs");
            check!(with_empty == signing_name_only, "{path}");
            check!(with_empty, "{path}");

            // And a non-matching signing name is still refused regardless of path.
            check!(
                !can_handle_based_on_route_key_and_path(&request, "iam", &[]),
                "{path}"
            );
        }
    }

    #[test]
    fn path_segment_matching_is_case_sensitive_like_an_http_path() {
        // The control plane publishes camelCase segments (`listTagsForResource`,
        // `tagResource`, `enforcedGuardrailsConfiguration`). Lowercasing the path
        // the way the signing name is normalized would make those miss.
        check!(bedrock_claimants("/listTagsForResource") == (false, true));
        check!(bedrock_claimants("/listtagsforresource") == (false, false));
    }

    #[test]
    fn a_bedrock_request_with_no_path_segments_is_claimed_by_neither() {
        // Root `/` yields no first segment, so a service WITH a segment list
        // cannot claim it. Both bedrock models are restJson1 and neither declares
        // a root operation.
        check!(bedrock_claimants("/") == (false, false));
    }

    #[test]
    fn path_discrimination_still_requires_the_signing_name_to_match() {
        // Path narrowing is a conjunct, not a replacement: a request signed for
        // another service must not be claimed even when its path is one this
        // service models.
        let request = http::Request::builder()
            .method("POST")
            .uri("/model/anthropic.claude-v2/invoke")
            .header("authorization", sigv4("sagemaker"))
            .body(bytes::Bytes::from_static(b"{}"))
            .unwrap();
        check!(!generated_bedrock_runtime::can_handle(&request));
        check!(!generated_bedrock_control_plane::can_handle(&request));
    }

    #[test]
    fn a_non_colliding_rest_service_with_segments_claims_only_its_modeled_paths() {
        // Lambda and the RDS Data API derive a non-empty segment list even though
        // neither collides with anything: every one of their operations begins
        // with a literal (Lambda's date prefixes `/2015-03-31/...`, the Data
        // API's `/Execute`). They therefore DO get narrowed, so the predicate
        // must claim a modeled path and decline an unmodeled one. Turning a
        // declined request into a loud `404` instead of silently absorbing it is
        // the router's SELECTION contract, pinned against the real router.
        const LAMBDA_SEGMENTS: &[&str] = &["2015-03-31", "2021-10-31"];

        let modeled = http::Request::builder()
            .method("POST")
            .uri("/2015-03-31/functions/my-function/invocations")
            .header("authorization", sigv4("lambda"))
            .body(bytes::Bytes::from_static(b"{}"))
            .unwrap();
        check!(can_handle_based_on_route_key_and_path(
            &modeled,
            "lambda",
            LAMBDA_SEGMENTS
        ));

        let unmodeled = http::Request::builder()
            .method("POST")
            .uri("/1999-01-01/functions/my-function/invocations")
            .header("authorization", sigv4("lambda"))
            .body(bytes::Bytes::from_static(b"{}"))
            .unwrap();
        check!(!can_handle_based_on_route_key_and_path(
            &unmodeled,
            "lambda",
            LAMBDA_SEGMENTS
        ));
    }

    // -----------------------------------------------------------------------
    // Canonical account/ARN contract: every generated emulator must present
    // account `000000000000` (the canonical placeholder) so its
    // ARN/account fields are deterministic.
    // -----------------------------------------------------------------------

    #[test]
    fn emulator_account_id_is_the_scoring_sentinel() {
        check!(EMULATOR_ACCOUNT_ID == "000000000000");
        check!(emulator_account_id() == "000000000000");
    }

    #[test]
    fn emulator_arn_carries_the_canonical_account() {
        // Regional resource ARN (e.g. a DynamoDB table).
        check!(
            emulator_arn("dynamodb", "us-east-1", "table/Orders")
                == "arn:aws:dynamodb:us-east-1:000000000000:table/Orders"
        );
        // Global-service ARN (empty region, e.g. an IAM role) still carries the
        // canonical account in the account segment.
        let iam = emulator_arn("iam", "", "role/App");
        check!(iam == "arn:aws:iam::000000000000:role/App");
        check!(iam.contains(":000000000000:"));
    }

    // -----------------------------------------------------------------------
    // Panic containment at the server boundary.
    //
    // A panic in a generated operation handler is caught at the server
    // boundary: it is LOGGED, answered with a protocol-shaped 500
    // InternalFailure, and the server keeps serving — it does not unwind the
    // hyper connection task and leave the caller with a dropped socket. These
    // tests pin that contract.
    // -----------------------------------------------------------------------

    fn facts(content_type: Option<&str>) -> RequestFacts {
        signed_facts(content_type, None)
    }

    /// `RequestFacts` for a request with an optional content-type and an optional
    /// SigV4 credential scope naming `signing_name`.
    fn signed_facts(content_type: Option<&str>, signing_name: Option<&str>) -> RequestFacts {
        let mut builder = http::Request::builder().method("POST").uri("/2015-03-31/x");
        if let Some(ct) = content_type {
            builder = builder.header("content-type", ct);
        }
        if let Some(service) = signing_name {
            builder = builder.header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential=TESTKEY/20240101/us-east-1/{service}/aws4_request, \
                     SignedHeaders=host, Signature=abc"
                ),
            );
        }
        let req = builder
            .header("x-amz-target", "Svc.Schedule")
            .body(bytes::Bytes::new())
            .expect("request builds");
        RequestFacts::from_request(&req)
    }

    #[test]
    fn error_envelope_is_chosen_from_the_request_content_type() {
        let json_1_0 = ErrorEnvelope::Json {
            content_type: "application/x-amz-json-1.0",
        };
        let json_1_1 = ErrorEnvelope::Json {
            content_type: "application/x-amz-json-1.1",
        };
        let plain_json = ErrorEnvelope::Json {
            content_type: "application/json",
        };

        check!(envelope_for(&facts(Some("application/x-amz-json-1.0"))) == json_1_0);
        check!(envelope_for(&facts(Some("application/x-amz-json-1.1"))) == json_1_1);
        check!(envelope_for(&facts(Some("application/cbor"))) == ErrorEnvelope::Cbor);
        check!(envelope_for(&facts(Some("application/xml"))) == ErrorEnvelope::Xml);
        check!(envelope_for(&facts(Some("text/xml"))) == ErrorEnvelope::Xml);
        check!(envelope_for(&facts(Some("application/json"))) == plain_json);

        // Parameters and casing are part of the header, not the media type.
        check!(envelope_for(&facts(Some("Application/X-Amz-Json-1.1; charset=utf-8"))) == json_1_1);

        // A bodyless request (no content-type) still gets a parseable envelope.
        check!(envelope_for(&facts(None)) == plain_json);
        check!(envelope_for(&facts(Some("application/octet-stream"))) == plain_json);
    }

    #[test]
    fn the_query_family_is_split_by_signing_name_because_the_content_type_cannot() {
        // awsQuery and ec2Query send the SAME content-type but do NOT share an
        // error envelope, so the SigV4 signing name is what separates them.
        let form = Some("application/x-www-form-urlencoded");
        check!(envelope_for(&signed_facts(form, Some("ec2"))) == ErrorEnvelope::Ec2Query);
        check!(envelope_for(&signed_facts(form, Some("sqs"))) == ErrorEnvelope::Xml);

        // Unsigned: falls back to awsQuery's wrapper (documented best effort).
        check!(envelope_for(&facts(form)) == ErrorEnvelope::Xml);

        // The signing name only decides the QUERY family; it must not divert a
        // JSON or CBOR caller onto an XML envelope.
        check!(
            envelope_for(&signed_facts(Some("application/json"), Some("ec2")))
                == ErrorEnvelope::Json {
                    content_type: "application/json"
                }
        );
        check!(
            envelope_for(&signed_facts(Some("application/cbor"), Some("ec2")))
                == ErrorEnvelope::Cbor
        );
    }

    #[test]
    fn ec2_query_gets_its_own_error_wrapper_not_the_aws_query_one() {
        // ec2Query uses <Response><Errors><Error>, with no <Type> and no
        // <RequestID> — matching `query_error_body(ec2: true)` and real EC2.
        let resp: http::Response<bytes::Bytes> = internal_failure_response(&signed_facts(
            Some("application/x-www-form-urlencoded"),
            Some("ec2"),
        ));
        check!(resp.status() == 500);
        check!(resp.headers().get("content-type").unwrap() == "application/xml");
        let xml = String::from_utf8(resp.body().to_vec()).expect("utf-8 xml");
        check!(xml.contains("<Response><Errors><Error>"));
        check!(xml.contains("<Code>InternalFailure</Code>"));
        check!(xml.contains(INTERNAL_FAILURE_MESSAGE));
        check!(
            !xml.contains("<ErrorResponse>"),
            "ec2Query must not use awsQuery's wrapper: {xml}"
        );
        check!(
            !xml.contains("<Type>"),
            "ec2Query errors carry no fault element: {xml}"
        );

        // The awsQuery caller still gets <ErrorResponse>.
        let aws_query: http::Response<bytes::Bytes> = internal_failure_response(&signed_facts(
            Some("application/x-www-form-urlencoded"),
            Some("sqs"),
        ));
        let xml = String::from_utf8(aws_query.body().to_vec()).expect("utf-8 xml");
        check!(xml.contains("<ErrorResponse><Error><Type>Receiver</Type>"));
    }

    #[test]
    fn internal_failure_response_is_a_parseable_aws_json_error() {
        let resp: http::Response<bytes::Bytes> =
            internal_failure_response(&facts(Some("application/x-amz-json-1.1")));
        check!(resp.status() == 500);
        check!(resp.headers().get("content-type").unwrap() == "application/x-amz-json-1.1");
        check!(resp.headers().get("x-amzn-errortype").unwrap() == "InternalFailure");
        // The contained panic is observable ON THE WIRE, so a caller
        // can tell an emulator defect from a modeled server-fault response.
        check!(resp.headers().get(PANIC_CONTAINED_HEADER).unwrap() == "contained");
        let body: serde_json::Value = serde_json::from_slice(resp.body()).expect("valid json");
        check!(body["__type"] == "InternalFailure");
        check!(body["message"] == INTERNAL_FAILURE_MESSAGE);
    }

    #[test]
    fn error_envelopes_carry_the_protocol_fault_attribution() {
        // 5xx is a Receiver (server) fault; 4xx is a Sender (client) fault.
        let server: http::Response<bytes::Bytes> = wire_error_response(
            http::StatusCode::INTERNAL_SERVER_ERROR,
            INTERNAL_FAILURE_CODE,
            INTERNAL_FAILURE_MESSAGE,
            &facts(Some("application/xml")),
        );
        check!(server.headers().get("content-type").unwrap() == "application/xml");
        let xml = String::from_utf8(server.body().to_vec()).expect("utf-8 xml");
        check!(xml.contains("<Type>Receiver</Type>"));
        check!(xml.contains("<Code>InternalFailure</Code>"));
        check!(xml.contains(INTERNAL_FAILURE_MESSAGE));

        let client: http::Response<bytes::Bytes> = wire_error_response(
            http::StatusCode::BAD_REQUEST,
            INVALID_REQUEST_CODE,
            INVALID_REQUEST_BODY_MESSAGE,
            &facts(Some("application/x-www-form-urlencoded")),
        );
        check!(client.status() == 400);
        let xml = String::from_utf8(client.body().to_vec()).expect("utf-8 xml");
        check!(xml.contains("<Type>Sender</Type>"));
        check!(xml.contains("<Code>InvalidRequest</Code>"));
    }

    #[test]
    fn xml_error_envelopes_escape_code_and_message() {
        // restXml, awsQuery, and the EC2 query envelope.
        let form = "application/x-www-form-urlencoded";
        for request in [
            facts(Some("application/xml")),
            facts(Some(form)),
            signed_facts(Some(form), Some("ec2")),
        ] {
            let response: http::Response<bytes::Bytes> = wire_error_response(
                http::StatusCode::BAD_REQUEST,
                "Bad<Code>",
                "a & b </Message><Injected/>",
                &request,
            );
            let xml = String::from_utf8(response.body().to_vec()).expect("utf-8 xml");
            check!(xml.contains("<Code>Bad&lt;Code&gt;</Code>"));
            check!(xml.contains("<Message>a &amp; b &lt;/Message&gt;&lt;Injected/&gt;</Message>"));
            check!(!xml.contains("<Injected/>"));
        }
    }

    #[test]
    fn cbor_error_map_is_a_well_formed_two_entry_map() {
        let encoded = cbor_error_map("InternalFailure", "boom");
        // a2                        map(2)
        // 66 5f 5f 74 79 70 65      text(6) "__type"
        // 6f "InternalFailure"      text(15)
        // 67 "message"              text(7)
        // 64 "boom"                 text(4)
        let mut expected = vec![0xa2, 0x66];
        expected.extend_from_slice(b"__type");
        expected.push(0x6f);
        expected.extend_from_slice(b"InternalFailure");
        expected.push(0x67);
        expected.extend_from_slice(b"message");
        expected.push(0x64);
        expected.extend_from_slice(b"boom");
        check!(encoded == expected);

        // The real envelope's message is longer than 23 bytes, so its head takes
        // the one-byte-argument form rather than being inlined.
        let real = cbor_error_map(INTERNAL_FAILURE_CODE, INTERNAL_FAILURE_MESSAGE);
        check!(real[0] == 0xa2);
        let message_head = 1 + 1 + "__type".len() + 1 + INTERNAL_FAILURE_CODE.len() + 1 + 7;
        check!(real[message_head] == CBOR_MAJOR_TEXT | 24);
        check!(real[message_head + 1] == INTERNAL_FAILURE_MESSAGE.len() as u8);
    }

    #[test]
    fn cbor_heads_use_the_shortest_argument_encoding() {
        let head = |argument: u64| {
            let mut out = Vec::new();
            push_cbor_head(&mut out, CBOR_MAJOR_TEXT, argument);
            out
        };
        check!(head(0) == vec![0x60]);
        check!(head(23) == vec![0x77]);
        check!(head(24) == vec![0x78, 24]);
        check!(head(0xff) == vec![0x78, 0xff]);
        check!(head(0x100) == vec![0x79, 0x01, 0x00]);
        check!(head(0xffff) == vec![0x79, 0xff, 0xff]);
        check!(head(0x1_0000) == vec![0x7a, 0x00, 0x01, 0x00, 0x00]);
        check!(head(0x1_0000_0000) == vec![0x7b, 0, 0, 0, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn panic_payloads_render_for_the_log() {
        // `panic!("literal")` carries a &'static str; a formatted panic (what
        // `todo!`, `unwrap` and `expect` produce) carries a String.
        let literal =
            std::panic::catch_unwind(|| panic!("a literal panic")).expect_err("the closure panics");
        check!(panic_payload_message(literal.as_ref()) == "a literal panic");

        let formatted = std::panic::catch_unwind(|| {
            let missing: Option<u8> = None;
            missing.expect("engine state is missing")
        })
        .expect_err("the closure panics");
        check!(panic_payload_message(formatted.as_ref()).contains("engine state is missing"));

        let opaque = std::panic::catch_unwind(|| std::panic::panic_any(7u32))
            .expect_err("the closure panics");
        check!(panic_payload_message(opaque.as_ref()) == "<non-string panic payload>");
    }

    #[test]
    fn request_facts_capture_what_attributes_a_panic() {
        let captured = signed_facts(Some("application/x-amz-json-1.0"), Some("lambda"));
        check!(captured.method == "POST");
        check!(captured.path == "/2015-03-31/x");
        check!(captured.content_type.as_deref() == Some("application/x-amz-json-1.0"));
        check!(captured.target.as_deref() == Some("Svc.Schedule"));
        // In a multi-service emulator this is WHICH mounted service panicked.
        check!(captured.signing_name.as_deref() == Some("lambda"));
        check!(facts(None).signing_name.is_none());

        // A query string is not part of the path.
        let req = http::Request::builder()
            .uri("/objects?uploads=1")
            .body(bytes::Bytes::new())
            .unwrap();
        check!(RequestFacts::from_request(&req).path == "/objects");
    }

    #[tokio::test]
    async fn contain_panics_passes_a_healthy_response_through_untouched() {
        let resp: http::Response<bytes::Bytes> = contain_panics(facts(None), async {
            aws_json_ok_response(&serde_json::json!({"ok": true}), AwsJsonProtocol::V1_1)
        })
        .await;
        check!(resp.status() == 200);
        check!(resp.headers().get(PANIC_CONTAINED_HEADER).is_none());
        let body: serde_json::Value = serde_json::from_slice(resp.body()).expect("valid json");
        check!(body["ok"] == true);
    }

    #[tokio::test]
    async fn contain_panics_turns_a_panic_into_a_protocol_shaped_500() {
        // A `todo!()` op stub is exactly this shape.
        let resp: http::Response<bytes::Bytes> =
            contain_panics(facts(Some("application/x-amz-json-1.0")), async {
                todo!("return a real ScheduleOutput")
            })
            .await;
        check!(resp.status() == 500);
        check!(resp.headers().get("content-type").unwrap() == "application/x-amz-json-1.0");
        check!(resp.headers().get(PANIC_CONTAINED_HEADER).unwrap() == "contained");
        let body: serde_json::Value = serde_json::from_slice(resp.body()).expect("valid json");
        check!(body["__type"] == "InternalFailure");
    }

    #[tokio::test]
    async fn contain_panics_catches_a_panic_raised_after_an_await() {
        // The guard has to hand the inner future BACK after a `Pending` poll and
        // still contain a panic raised on a later poll — the common case, since a
        // handler panics after awaiting engine state.
        let resp: http::Response<bytes::Bytes> = contain_panics(facts(None), async {
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
            panic!("panicked after two awaits");
        })
        .await;
        check!(resp.status() == 500);
        check!(resp.headers().get(PANIC_CONTAINED_HEADER).unwrap() == "contained");
    }

    #[tokio::test]
    async fn a_contained_panic_releases_the_state_the_handler_was_holding() {
        // The guarded future is dropped once its poll unwinds — it is never
        // polled again, and whatever it owned is released rather than leaked for
        // the lifetime of the (long-lived) emulator process.
        struct Tracked(Arc<Mutex<bool>>);
        impl Drop for Tracked {
            fn drop(&mut self) {
                *self.0.lock() = true;
            }
        }

        let dropped = Arc::new(Mutex::new(false));
        let owned = Tracked(dropped.clone());
        let resp: http::Response<bytes::Bytes> = contain_panics(facts(None), async move {
            let _owned = owned;
            panic!("handler panics while holding state");
        })
        .await;
        check!(resp.status() == 500);
        check!(
            *dropped.lock(),
            "the panicked future's state must be released"
        );
    }

    /// A minimal `tracing::Subscriber` that records the fields of every
    /// `ERROR`-level event. Hand-rolled because this crate carries no
    /// `tracing-subscriber` dependency — it is vendored into every tenant repo,
    /// so its dependency set stays minimal.
    #[derive(Clone, Default)]
    struct ErrorEventCapture {
        events: Arc<Mutex<Vec<String>>>,
    }

    struct FieldText<'a>(&'a mut String);

    impl tracing::field::Visit for FieldText<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write;
            let _ = write!(self.0, "{}={value:?} ", field.name());
        }
    }

    impl tracing::Subscriber for ErrorEventCapture {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() == tracing::Level::ERROR
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::Id {
            tracing::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::Id, _follows: &tracing::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut rendered = String::new();
            event.record(&mut FieldText(&mut rendered));
            self.events.lock().push(rendered);
        }

        fn enter(&self, _span: &tracing::Id) {}

        fn exit(&self, _span: &tracing::Id) {}
    }

    /// The ERROR-event capture, installed ONCE as the PROCESS-WIDE default
    /// subscriber.
    ///
    /// It must be global rather than thread-local (`subscriber::set_default`):
    /// `tracing` caches each callsite's interest GLOBALLY, computed from whatever
    /// subscriber the FIRST thread to reach that callsite happened to have. With
    /// the test harness running tests in parallel, another test reaching
    /// `contain_panics`'s `error!` first — with no subscriber installed — would
    /// cache that callsite as "never" and a thread-local capture would see
    /// nothing. One global capture plus an interest-cache rebuild removes that
    /// ordering dependency.
    fn error_events() -> &'static ErrorEventCapture {
        static CAPTURE: std::sync::OnceLock<ErrorEventCapture> = std::sync::OnceLock::new();
        CAPTURE.get_or_init(|| {
            let capture = ErrorEventCapture::default();
            tracing::subscriber::set_global_default(capture.clone())
                .expect("these tests install no other global tracing subscriber");
            // Recompute interest for callsites a parallel test may already have
            // reached — and cached as "never" — before this subscriber existed.
            tracing::callsite::rebuild_interest_cache();
            capture
        })
    }

    #[tokio::test]
    async fn a_contained_panic_is_logged_at_error_and_never_swallowed() {
        // Unique to this test, so the assertion is unaffected by the contained
        // panics other tests raise into the same process-wide capture.
        const MARKER: &str = "engine state is missing for tenant 7f3a91c4";
        let capture = error_events();

        let resp: http::Response<bytes::Bytes> = contain_panics(
            signed_facts(Some("application/x-amz-json-1.1"), Some("lambda")),
            async { panic!("{MARKER}") },
        )
        .await;
        check!(resp.status() == 500);

        let logged = capture
            .events
            .lock()
            .iter()
            .find(|event| event.contains(MARKER))
            .cloned();
        let logged = logged.expect("a contained panic must be logged at ERROR, not swallowed");
        // The panic message, the request that triggered it, the operation and the
        // service are all in the log, so a genuine emulator defect stays
        // diagnosable — and attributable in a multi-service emulator.
        check!(logged.contains("CONTAINED PANIC"));
        check!(logged.contains("Svc.Schedule"));
        check!(logged.contains("/2015-03-31/x"));
        check!(logged.contains("lambda"));
    }

    /// A service that panics for `/panic` — the way a generated `todo!()` stub
    /// does — and answers normally for anything else, recording every path it
    /// was asked for so a test can prove it kept being called.
    #[derive(Clone)]
    struct PanickingService {
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl PanickingService {
        fn new() -> Self {
            Self {
                seen: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl EmulatorService for PanickingService {
        async fn handle_request(
            &self,
            req: http::Request<bytes::Bytes>,
        ) -> http::Response<bytes::Bytes> {
            self.seen.lock().push(req.uri().path().to_string());
            if req.uri().path() == "/panic" {
                todo!("return a real ScheduleOutput");
            }
            aws_json_ok_response(&serde_json::json!({"echo": true}), AwsJsonProtocol::V1_1)
        }
    }

    /// Poll `url` until it answers or ~5s elapse, so a test never races the
    /// listener bind. A fixed sleep flakes on a cold, loaded build host.
    async fn wait_until_serving(client: &reqwest::Client, url: &str) -> bool {
        for _ in 0..100 {
            if client.get(url).send().await.is_ok() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        false
    }

    #[tokio::test]
    async fn a_panicking_handler_answers_500_over_a_real_socket_and_the_server_survives() {
        let svc = PanickingService::new();
        let seen = svc.seen.clone();
        let (endpoint, _svc) = serve_on_ephemeral_port(svc).await;
        let client = reqwest::Client::new();

        // 1) The panicking operation gets a REAL HTTP response, not a dropped
        //    connection.
        let panicked = client
            .post(format!("{endpoint}/panic"))
            .header("content-type", "application/x-amz-json-1.1")
            .body("{}")
            .send()
            .await
            .expect("a panicking handler must still answer, not kill the socket");
        check!(panicked.status() == 500);
        check!(panicked.headers().get(PANIC_CONTAINED_HEADER).unwrap() == "contained");
        check!(
            panicked.headers().get("content-type").unwrap() == "application/x-amz-json-1.1",
            "the 500 must be encoded in the caller's protocol"
        );
        let body: serde_json::Value = panicked.json().await.expect("a parseable error body");
        check!(body["__type"] == "InternalFailure");

        // 2) SURVIVAL: the same server serves the next request normally.
        let after = client
            .post(format!("{endpoint}/ok"))
            .header("content-type", "application/x-amz-json-1.1")
            .body("{}")
            .send()
            .await
            .expect("the server must still be serving after a contained panic");
        check!(after.status() == 200);
        let body: serde_json::Value = after.json().await.expect("valid json");
        check!(body["echo"] == true);

        // 3) Containment is not one-shot: a second panic is contained too.
        let again = client
            .post(format!("{endpoint}/panic"))
            .header("content-type", "application/x-amz-json-1.1")
            .body("{}")
            .send()
            .await
            .expect("a second panicking call must still answer");
        check!(again.status() == 500);

        check!(seen.lock().clone() == vec!["/panic", "/ok", "/panic"]);
    }

    #[tokio::test]
    async fn a_panicking_handler_answers_500_over_the_production_tls_path() {
        // The production contract end to end: one self-signed HTTPS listener
        // serving health and the AWS surface, the same shape the launcher probes
        // and callers drive. A panic in a handler must not take down
        // the listener or its health answer.
        // The AWS surface plus a panicking EXTRA route, proving containment
        // covers the raw-route seam as well as Smithy dispatch.
        let svc = WithExtraRoutes::new(PanickingService::new()).route(
            http::Method::POST,
            "/__admin/boom",
            |_req| async { panic!("an extra route panics too") },
        );

        let (data_port, server) = serve_production_on_a_free_port(svc).await;
        let client = tls_client();
        let health_url = format!("https://127.0.0.1:{data_port}{HEALTH_PATH}");

        // 1) A panicking operation answers 500 over TLS.
        let panicked = client
            .post(format!("https://127.0.0.1:{data_port}/panic"))
            .header("content-type", "application/x-amz-json-1.1")
            .body("{}")
            .send()
            .await
            .expect("a panicking handler must answer over the TLS data listener");
        check!(panicked.status() == 500);
        check!(panicked.headers().get(PANIC_CONTAINED_HEADER).unwrap() == "contained");
        let body: serde_json::Value = panicked.json().await.expect("a parseable error body");
        check!(body["__type"] == "InternalFailure");

        // 2) A panicking extra route is contained on the same listener.
        let route_panicked = client
            .post(format!("https://127.0.0.1:{data_port}/__admin/boom"))
            .send()
            .await
            .expect("a panicking extra route must answer");
        check!(route_panicked.status() == 500);

        // 3) SURVIVAL: the data listener still serves AWS traffic...
        let after = client
            .post(format!("https://127.0.0.1:{data_port}/ok"))
            .header("content-type", "application/x-amz-json-1.1")
            .body("{}")
            .send()
            .await
            .expect("the data listener must survive a contained panic");
        check!(after.status() == 200);
        let body: serde_json::Value = after.json().await.expect("valid json");
        check!(body["echo"] == true);

        // ...the health gate still answers, so the launcher keeps seeing a live
        // emulator...
        let health = client
            .get(&health_url)
            .send()
            .await
            .expect("health request");
        check!(health.status() == 200);
        check!(health.text().await.unwrap() == "ok");

        // ...and the serve task itself never exited.
        check!(
            !server.is_finished(),
            "the emulator serve task must not exit because a handler panicked"
        );

        server.abort();
    }

    // =====================================================================
    // `noErrorWrapping` boundary error envelope
    // =====================================================================

    /// Assert `s` is a canonical v4 UUID: `8-4-4-4-12` lowercase hex, version
    /// nibble `4`, variant nibble `8`/`9`/`a`/`b`.
    fn assert_is_v4_uuid(s: &str) {
        let groups: Vec<&str> = s.split('-').collect();
        check!(groups.len() == 5, "a UUID has five groups: {s}");
        check!(
            groups.iter().map(|g| g.len()).collect::<Vec<_>>() == vec![8, 4, 4, 4, 12],
            "group lengths must be 8-4-4-4-12: {s}"
        );
        check!(
            s.chars()
                .all(|c| c == '-' || c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "a UUID is lowercase hex and hyphens: {s}"
        );
        check!(&groups[2][0..1] == "4", "version nibble must be 4: {s}");
        check!(
            matches!(&groups[3][0..1], "8" | "9" | "a" | "b"),
            "variant nibble must be 8/9/a/b: {s}"
        );
    }

    /// Assert `s` is the S3 `x-amz-id-2` shape: exactly 64 lowercase hex chars.
    fn assert_is_host_id(s: &str) {
        check!(s.len() == 64, "a host-id is 64 hex characters: {s}");
        check!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "a host-id is lowercase hex: {s}"
        );
    }

    /// Pull the text of the first `<Element>text</Element>` out of `body`.
    fn element_text<'a>(body: &'a str, element: &str) -> &'a str {
        let open = format!("<{element}>");
        let close = format!("</{element}>");
        let start = body
            .find(&open)
            .unwrap_or_else(|| panic!("<{element}> in {body}"))
            + open.len();
        let end = body[start..]
            .find(&close)
            .unwrap_or_else(|| panic!("</{element}> in {body}"))
            + start;
        &body[start..end]
    }

    /// A restXml service that sets `noErrorWrapping` gets a bare `<Error>` root
    /// from the boundary — no `<ErrorResponse>` wrapper, no `<Type>`, trailing
    /// `<RequestId>`/`<HostId>` — plus the `x-amz-request-id` / `x-amz-id-2`
    /// headers. Each id is generated per response: the header carries the same
    /// value as the body element, the request-id is a v4 UUID, and the host-id
    /// is 64 lowercase hex characters.
    #[test]
    fn xml_boundary_error_is_unwrapped_when_the_service_sets_no_error_wrapping() {
        let facts = facts(Some("application/xml")).with_no_error_wrapping(true);
        let resp: http::Response<bytes::Bytes> = internal_failure_response(&facts);
        check!(resp.status() == 500);
        check!(resp.headers().get("content-type").unwrap() == "application/xml");

        let xml = String::from_utf8(resp.body().to_vec()).expect("utf-8 xml");
        check!(
            xml.starts_with(&format!(
                "<?xml version=\"1.0\"?><Error><Code>{code}</Code><Message>{msg}</Message>",
                code = INTERNAL_FAILURE_CODE,
                msg = INTERNAL_FAILURE_MESSAGE,
            )),
            "unwrapped boundary error must be a bare <Error> root with no \
             <ErrorResponse> and no <Type>: {xml}"
        );
        check!(!xml.contains("<ErrorResponse"), "{xml}");
        check!(!xml.contains("<Type>"), "{xml}");

        let body_request_id = element_text(&xml, "RequestId");
        let body_host_id = element_text(&xml, "HostId");
        assert_is_v4_uuid(body_request_id);
        assert_is_host_id(body_host_id);
        check!(
            resp.headers().get("x-amz-request-id").unwrap() == body_request_id,
            "x-amz-request-id header must equal the body's <RequestId>: {xml}"
        );
        check!(
            resp.headers().get("x-amz-id-2").unwrap() == body_host_id,
            "x-amz-id-2 header must equal the body's <HostId>: {xml}"
        );
    }

    /// The default (flag unset, as `from_request` leaves it) keeps the wrapped
    /// `<ErrorResponse>` envelope and adds no request-id headers — the
    /// no-regression pin for every current caller.
    #[test]
    fn xml_boundary_error_stays_wrapped_by_default() {
        let resp: http::Response<bytes::Bytes> =
            internal_failure_response(&facts(Some("application/xml")));
        let xml = String::from_utf8(resp.body().to_vec()).expect("utf-8 xml");
        check!(
            xml.contains("<ErrorResponse><Error><Type>Receiver</Type>"),
            "{xml}"
        );
        check!(!xml.contains("<RequestId>"), "{xml}");
        check!(resp.headers().get("x-amz-request-id").is_none());
        check!(resp.headers().get("x-amz-id-2").is_none());
    }

    /// `no_error_wrapping` only means anything on the XML envelope: a JSON caller
    /// with the flag set must still get the plain JSON error and no XML headers.
    #[test]
    fn no_error_wrapping_is_inert_for_a_non_xml_caller() {
        let facts = facts(Some("application/x-amz-json-1.0")).with_no_error_wrapping(true);
        let resp: http::Response<bytes::Bytes> = internal_failure_response(&facts);
        check!(resp.headers().get("content-type").unwrap() == "application/x-amz-json-1.0");
        check!(resp.headers().get("x-amz-request-id").is_none());
        let body = String::from_utf8(resp.body().to_vec()).expect("utf-8");
        check!(body.contains("\"__type\""), "{body}");
    }
}
