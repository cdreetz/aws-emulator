// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! The operation contract and the typed-call orchestrator step.
//!
//! An [`Operation`] is one modeled operation: it pins its input, output, and
//! error as associated types and provides the single typed [`handle`](Operation::handle)
//! body a service author writes. The service author's file contains only that
//! `handle` body — no serialization, no telemetry, no routing.
//!
//! [`run_operation_http`] is the one framework-owned per-request sequence: it
//! deserializes the body, validates constraints, calls `op.handle(input, ctx)`,
//! records the per-operation telemetry outcome, and serializes the output or
//! error — including the service's own refusal wording for a framework-level
//! failure. It is generic over any [`Operation`],
//! naming only framework types plus the two per-operation `Schema` constants the
//! trait carries, so the whole sequence lives in this vended crate. The per-service
//! generated `ErasedOperation::run` collapses to a one-line shim that calls it
//! with the concrete operation type — the shim is the monomorphization site the
//! erased router dispatch cannot provide.
//!
//! The engine is NOT reached through [`OperationContext`]: it is a constructor
//! dependency held on the operation struct, so engine access is guaranteed at
//! build time rather than being a request-time lookup that could be absent.
//! Besides the request metadata, [`OperationContext`] carries a callback into
//! the emulator the handler is running within, so a handler can call another
//! emulated service through the AWS SDK without a cross-crate dependency; see
//! [`OperationContext::callback`].

use crate::service::ServiceIdentity;
use emulator_server::embedded::{aws_credentials_provider, SharedCredentialsProvider};
use emulator_server::{CredentialStore, TlsCertificateAuthority, VendedCredentials};
use aws_smithy_runtime_api::client::http::{
    HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpClient,
    SharedHttpConnector,
};
use aws_smithy_runtime_api::client::orchestrator::HttpRequest;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_schema::serde::SerializableStruct;
use aws_smithy_schema_server::DeserializableStruct;
use std::future::Future;

/// The maximum number of in-process callback calls one external request may fan
/// out into before the router refuses the next one.
///
/// A callback re-enters the same router, so a service that calls another which
/// calls back forms a cycle with no natural end. The depth of the current chain
/// travels in a [`CallbackRecursionDepth`] request extension; the router reads
/// it on every dispatch and refuses once it exceeds this limit, which bounds the
/// recursion to a fixed depth no matter how the handlers are wired. The value is
/// a fixed constant chosen well above any legitimate call graph: a real
/// multi-service fan-out is a handful of levels deep, far short of this, so a
/// chain past this many is a cycle, not real work. It is a cycle backstop rather
/// than a resource budget. Changing it changes how deep a legitimate chain may
/// go before it is refused.
pub const CALLBACK_RECURSION_LIMIT: u8 = 100;

/// The depth of the current in-process callback chain, carried as a request
/// extension so it survives the AWS SDK transport boundary between one dispatch
/// and the next.
///
/// An external request carries none, which the router reads as depth zero. Each
/// callback through [`OperationContext::callback`] stamps the next depth onto
/// the outbound request, so the router can bound the chain at
/// [`CALLBACK_RECURSION_LIMIT`] without any handler having to cooperate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallbackRecursionDepth(pub u8);

/// A handle to an emulator running in this process, exposing exactly the
/// embedded-mode surface: an SDK HTTP client, the credentials the emulator
/// accepts, and an SDK credentials provider for them.
///
/// It wraps the router that serves the emulator's services. A host in embedded
/// mode builds one over a fresh engine; a handler reaches the one it is running
/// within through [`OperationContext::callback`]. Either way the accessors are
/// the single surface for driving an emulator through the AWS SDK.
#[derive(Clone)]
pub struct EmbeddedEmulator {
    router: crate::MultiServiceRouter,
    credentials: Vec<VendedCredentials>,
    /// Set only for the callback a handler reaches through
    /// [`OperationContext::callback`]: the depth every request it sends is
    /// stamped with, so the router can bound a re-entrant chain. `None` for a
    /// host-facing emulator, whose requests start a fresh chain.
    next_recursion_depth: Option<u8>,
}

impl EmbeddedEmulator {
    /// Build a handle over an existing router. Every accessor serves that router,
    /// so handles built over one router share its engine and state.
    pub fn from_router(router: crate::MultiServiceRouter) -> Self {
        let credentials = router.vended_credentials();
        Self {
            router,
            credentials,
            next_recursion_depth: None,
        }
    }

    /// The emulator's SDK `HttpClient`, to pass to an AWS SDK config's
    /// `.http_client(..)`. Requests sent through it route to the emulator's
    /// services in-process.
    ///
    /// Returns the SDK's public [`SharedHttpClient`] wrapper, not the concrete
    /// router — the router is an internal type with no cross-crate promise. It
    /// hands out the same connector as [`http_connector`](Self::http_connector),
    /// so the recursion-depth stamping described there applies here too.
    pub fn http_client(&self) -> SharedHttpClient {
        SharedHttpClient::new(EmulatorHttpClient {
            connector: self.http_connector(),
        })
    }

    /// The emulator's SDK `HttpConnector`, for driving the emulator in-process
    /// directly (`connector.call(request)`) without building a full SDK client.
    ///
    /// It also fetches a URL the emulator handed out while not served on a port (one under
    /// [`UNSERVED_URL_BASE`](crate::UNSERVED_URL_BASE)): send a request whose URI is the
    /// whole URL, with any headers [`SignedUrl::required_headers`](crate::SignedUrl::required_headers)
    /// lists. It is routed by the URL's `X-Amz-Credential` and, with authentication on,
    /// verified like any other request:
    ///
    /// ```ignore
    /// use aws_smithy_runtime_api::client::orchestrator::HttpRequest;
    /// use aws_smithy_types::body::SdkBody;
    ///
    /// let request = http::Request::get(url.as_str()).body(SdkBody::empty())?;
    /// let response = emulator.http_connector().call(HttpRequest::try_from(request)?).await?;
    /// ```
    ///
    /// For the callback a handler reaches through
    /// [`OperationContext::callback`], the returned connector stamps the next
    /// [`CallbackRecursionDepth`] on every request so the router bounds a
    /// re-entrant chain; the wrapping is done here, so a request that never makes
    /// a callback pays nothing for it.
    pub fn http_connector(&self) -> SharedHttpConnector {
        let inner = SharedHttpConnector::new(self.router.clone());
        match self.next_recursion_depth {
            Some(next_depth) => SharedHttpConnector::new(EmulatorCallbackTransport {
                inner,
                next_depth,
            }),
            None => inner,
        }
    }

    /// The credentials the emulator accepts; placeholder keys when authentication
    /// is off, so a call signs with something the emulator will route on.
    pub fn credentials(&self) -> Vec<VendedCredentials> {
        self.credentials.clone()
    }

    /// An AWS SDK credentials provider signing with [`credentials`](Self::credentials).
    pub fn aws_credentials_provider(&self) -> SharedCredentialsProvider {
        aws_credentials_provider(&self.credentials)
    }

    /// The TLS certificate every listener of this process presents: the data port and each
    /// resource listener a service opens. A host trusts it to reach those listeners, as a
    /// standalone client trusts the published `ca.pem`: `pem()` for `AWS_CA_BUNDLE` or
    /// `curl --cacert`, `der()` for a rustls root store, `pkcs12_trust_store()` for a JVM.
    ///
    /// # Panics
    ///
    /// When the process cannot generate a key pair, which leaves it no TLS at all.
    pub fn certificate_authority(&self) -> &TlsCertificateAuthority {
        TlsCertificateAuthority::for_this_process()
    }

    /// Mark this handle as the in-process callback a handler uses to call another
    /// service, so its [`http_client`](Self::http_client) stamps `next_depth` on
    /// every request. Setting the depth allocates nothing.
    pub(crate) fn with_recursion_depth(mut self, next_depth: u8) -> Self {
        self.next_recursion_depth = Some(next_depth);
        self
    }
}

impl std::fmt::Debug for EmbeddedEmulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The credentials this handle holds are not disclosed in its debug form.
        f.debug_struct("EmbeddedEmulator").finish_non_exhaustive()
    }
}

/// An in-process transport that stamps the next [`CallbackRecursionDepth`] onto
/// every request before handing it to the emulator's own connector.
///
/// Stamping at the transport layer, the last step before the request crosses the
/// SDK boundary into the router, keeps the depth correct no matter how the SDK
/// client built the request: the handler cannot forget to carry it and an
/// orchestrator rebuild cannot drop it. The router reads the stamped depth on
/// the next dispatch and refuses once it exceeds [`CALLBACK_RECURSION_LIMIT`].
#[derive(Debug)]
struct EmulatorCallbackTransport {
    inner: SharedHttpConnector,
    next_depth: u8,
}

impl HttpConnector for EmulatorCallbackTransport {
    fn call(&self, mut request: HttpRequest) -> HttpConnectorFuture {
        request.add_extension(CallbackRecursionDepth(self.next_depth));
        self.inner.call(request)
    }
}

/// An SDK [`HttpClient`] over the emulator, so [`EmbeddedEmulator::http_client`]
/// returns the SDK's public client type rather than the internal router. It
/// hands the SDK the one connector the emulator already built — stamp-aware for
/// a callback handle, plain for a host-facing one — for every connector setting,
/// because an in-process transport has no timeouts or pool to vary on.
#[derive(Debug)]
struct EmulatorHttpClient {
    connector: SharedHttpConnector,
}

impl HttpClient for EmulatorHttpClient {
    fn http_connector(
        &self,
        _settings: &HttpConnectorSettings,
        _components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        self.connector.clone()
    }
}

/// Request metadata handed to every operation handler.
///
/// Wraps a borrowed [`http::request::Parts`] and the service's vended
/// [`ServiceIdentity`]. Both are framework types, so the generic
/// [`run_operation_http`] can build the context without naming any service-generated
/// type. A handler reads headers, URI, method, and anything middleware placed in
/// `parts.extensions` (e.g. the authenticated caller) through
/// [`parts`](OperationContext::parts); it reaches the engine through its own
/// struct field, not through this context.
///
/// It also carries a [`callback`](OperationContext::callback) into the emulator
/// the handler is running within, for calling another emulated service in-process.
pub struct OperationContext<'a> {
    parts: &'a http::request::Parts,
    identity: &'a ServiceIdentity,
    /// See [`callback`](OperationContext::callback) for how a handler uses this.
    callback: EmbeddedEmulator,
}

impl<'a> OperationContext<'a> {
    /// Build a context from borrowed request parts, the service identity, and the
    /// callback into the emulator this handler runs within.
    ///
    /// Called by the framework dispatch; every argument is a framework type.
    pub fn new(
        parts: &'a http::request::Parts,
        identity: &'a ServiceIdentity,
        callback: EmbeddedEmulator,
    ) -> Self {
        Self {
            parts,
            identity,
            callback,
        }
    }

    /// The request's headers, URI, method, and extensions.
    pub fn parts(&self) -> &http::request::Parts {
        self.parts
    }

    /// The identity of the service handling this request.
    pub fn identity(&self) -> &ServiceIdentity {
        self.identity
    }

    /// Call back into the emulator this handler is running within: build an AWS
    /// SDK client over [`callback().http_client()`](EmbeddedEmulator::http_client)
    /// with [`callback().aws_credentials_provider()`](EmbeddedEmulator::aws_credentials_provider)
    /// to invoke another emulated service by its signing name. The call routes
    /// in-process through the same emulator; it never names the callee's crate,
    /// so no cross-crate edge forms. The emulator bounds a re-entrant callback
    /// chain at [`CALLBACK_RECURSION_LIMIT`].
    pub fn callback(&self) -> &EmbeddedEmulator {
        &self.callback
    }

    /// The credentials this emulator accepts. An operation that returns credentials creates
    /// them here, of the kind it returns (`aws_credentials::AWS_ACCESS_KEY`, `AWS_SESSION`), and
    /// returns the created secrets; one that deletes a credential deletes it here. Works the
    /// same with authentication off; the credentials are just not checked.
    pub fn credential_store(&self) -> &CredentialStore {
        &self.callback.router.credential_store
    }

    /// SigV4 query-signs URLs a caller fetches later, which lead back to this emulator: use it
    /// for any URL the modeled operation returns presigned. It signs for the region this
    /// request was signed for unless the request names one. See
    /// [`UrlSigner`](crate::UrlSigner).
    pub fn url_signer(&self) -> crate::UrlSigner {
        let region = crate::signed_url::signed_region(self.parts);
        crate::UrlSigner::new(&self.callback.router, region)
    }

    /// The base URL a later request addresses, for an output member that carries a resource's
    /// address: `scheme://host[:port]`, with no path, no signature and no expiry. Append the
    /// resource's own path. Callers send normally signed requests to it.
    ///
    /// Returns the data port's URL when the emulator is served, and
    /// [`UNSERVED_URL_BASE`](crate::endpoint::UNSERVED_URL_BASE) (`https://emulator.invalid`)
    /// when it is not.
    ///
    /// The served URL is the shared config's `endpoint_url`. An unserved one (embedded, or a
    /// test) a caller reaches in-process through [`EmbeddedEmulator::http_connector`]. It
    /// names the same base [`url_signer`](Self::url_signer) signs for. See
    /// [`crate::endpoint`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let address = format!("{}/{resource_id}", ctx.endpoint().as_str());
    /// output.resource_url = Some(address);
    /// ```
    pub fn endpoint(&self) -> crate::EndpointUrl {
        self.callback.router.url_base.get()
    }
}

/// A single modeled operation.
///
/// Implemented by the per-operation type the service author owns (one `struct`
/// per operation). The associated types pin the operation's input, output, and
/// error so the compiler enforces `handle(Input) -> Result<Output, Error>` with
/// no runtime type registry. The engine the operation needs is held on the
/// implementing struct (constructor-injected by the service), not passed here.
pub trait Operation: Send + Sync + 'static {
    /// The deserialized request input.
    ///
    /// Also `SerializableStruct` because the centralized request-handling
    /// sequence runs constraint-trait validation over the built input
    /// (`constraints::validate` drives it as a serializer); every generated
    /// input shape already implements both, so this adds no obligation.
    type Input: DeserializableStruct + SerializableStruct + Send;
    /// The operation output, serialized into the response on success.
    type Output: SerializableStruct + Send;
    /// The modeled error channel for this operation.
    type Error: crate::errors::OperationError + Send;

    /// The wire operation name, e.g. `"CreateBucket"`.
    ///
    /// A `&'static str`, because this trait is vended and cannot name a type
    /// generated into a service crate. A service's own generated name map stays
    /// internal to that crate.
    const NAME: &'static str;

    /// The input shape's `Schema`, baked at codegen.
    ///
    /// The protocol's deserialize and constraint-validation steps take an
    /// explicit `&Schema` (they are schema-driven, not type-driven), so the
    /// centralized sequence in [`run_operation_http`] needs to name it generically.
    /// The value is the service crate's generated `*_INPUT_SCHEMA` constant,
    /// which only the per-operation generated `impl Operation` can name — so the
    /// const is declared here and filled there.
    const INPUT_SCHEMA: &'static aws_smithy_schema::Schema;

    /// The output shape's `Schema`, baked at codegen. Consumed by the success
    /// serialize step of [`run_operation_http`]; see [`INPUT_SCHEMA`](Self::INPUT_SCHEMA).
    const OUTPUT_SCHEMA: &'static aws_smithy_schema::Schema;

    /// The HTTP status this operation returns on success — its modeled
    /// `@http(code:)`, or `200` when the model declares none.
    ///
    /// Status is an operation fact, not an output-shape fact: two operations may
    /// share one output shape yet return different codes (a `Get` returning
    /// `200` and an `Update` returning `201` over the same configuration shape),
    /// so it is pinned per operation here and never read off the shared
    /// [`OUTPUT_SCHEMA`](Self::OUTPUT_SCHEMA). A `@httpResponseCode` output member
    /// still overrides it at serialize time — a response that binds the status to
    /// a member value wins over this default.
    const SUCCESS_STATUS: u16;

    /// The one typed call into service-author code.
    ///
    /// `ctx` carries request metadata (headers, URI, extensions) and the service
    /// identity; it is always present by construction (the request context is
    /// never an opt-in parameter). The engine is read from `self`, set when the
    /// operation was constructed.
    fn handle(
        &self,
        input: Self::Input,
        ctx: &OperationContext<'_>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send;
}

/// The framework's entire per-request sequence for one modeled operation.
///
/// This owns every step between the wire and the handler and back:
/// deserialize the body against the input schema, run constraint-trait
/// validation, call the typed [`handle`](Operation::handle), then serialize the
/// output on success or the modeled error on failure — including the
/// `awsQueryCompatible` `x-amzn-query-error` header and, for a framework-level
/// refusal, the service's own refusal wording via
/// [`Service::override_refusal`](crate::Service::override_refusal).
///
/// It is generic over any [`Operation`], so it lives in this vended crate and
/// names only framework types plus the two per-operation `Schema` constants the
/// trait now carries ([`INPUT_SCHEMA`](Operation::INPUT_SCHEMA) /
/// [`OUTPUT_SCHEMA`](Operation::OUTPUT_SCHEMA)). The per-service generated
/// [`ErasedOperation::run`](crate::ErasedOperation::run) collapses to a one-line
/// shim that calls this with its concrete `Self` — the monomorphization site
/// that recovers a concrete `O`, because the router looks the operation up as an
/// erased `&dyn ErasedOperation` and so has no concrete type to name.
///
/// Refusal is reached as a service-level call: `svc` is the same `&dyn Service`
/// the router looked the operation up from, passed back through the object-safe
/// `run` boundary. The service answers from its own refusal renderer, so refusal
/// wording is single-homed on the service and the sequence needs no per-operation
/// refusal state.
///
/// `pre_dispatch` is the [`PreDispatchProtocol`](crate::PreDispatchProtocol)
/// envelope framework errors render in (`Copy`). The generated shim passes the
/// envelope of the protocol the request is served in,
/// [`ErasedServiceDefinition::wire_protocol`](crate::ErasedServiceDefinition::wire_protocol),
/// which is the codec this sequence picks unless the author's
/// [`override_protocol`](crate::Service::override_protocol) replaces it. An
/// override does not change this envelope; that seam's contract says how such a
/// service rewords its framework errors.
pub async fn run_operation_http<'r, O: Operation>(
    op: &'r O,
    svc: &'r dyn crate::Service,
    req: &'r aws_smithy_runtime_api::http::Request,
    ctx: &'r OperationContext<'r>,
    pre_dispatch: crate::PreDispatchProtocol<'r>,
) -> aws_smithy_runtime_api::http::Response {
    use crate::errors::OperationError;

    // OnCallWorlds patch: a sealed (seeded, read-only) account refuses every mutating
    // call in the service's own access-denied wording.
    if let Some(refused) = ocw_refusal::<O>(ctx, req, pre_dispatch) {
        return refused;
    }

    // The service's wire protocol for the modeled sequence below, selected by
    // `resolve_protocol` (the author's `override_protocol` if any, else the
    // protocol the request is served in). The deserialize and serialize steps drive it as a
    // `&dyn ServerHttpProtocol`, so the sequence takes no separate protocol argument.
    // This is a shared borrow of `*svc` alongside `op` (which the router looked
    // up from `svc`) and `svc` itself — all under `'r`, which the router holds
    // alive while it awaits.
    let protocol = resolve_protocol(svc, req);

    // Telemetry is recorded here, in the one framework sequence, so every
    // operation is instrumented once by code the service author never writes.
    //
    // Everything telemetry does is gated on `recording_active()`, read once:
    // when no client is collecting, the sequence parses no request headers, builds
    // no handle, and keeps no timer — a disabled emulator costs nothing. When
    // recording, the request metadata is the already-sanitized
    // `RequestTelemetry` (only parsed, closed dimensions ever leave
    // `from_headers`), preserving the sanitization the extractor owns.
    let recording = emulator_telemetry::recording_active();
    let telemetry = recording.then(|| {
        (
            std::time::Instant::now(),
            crate::RequestTelemetry::from_headers(&ctx.parts().headers).into_metadata(),
        )
    });
    // Counts this operation as in flight for peak concurrency until the sequence
    // returns; dropping the guard on any exit, including unwinding, ends it.
    let _in_flight = recording
        .then(emulator_telemetry::global)
        .flatten()
        .map(emulator_telemetry::TelemetryClient::begin_request);

    // The deserialize -> validate -> handle -> serialize sequence, with every
    // framework-level failure travelling as a `ProtocolError` so the single
    // error tail below can render it in the service's own envelope. On the
    // `Ok` path the sequence also carries the classified operation outcome
    // (`None` for success, `Some(OperationFailure)` for a modeled error),
    // captured from the modeled error's own HTTP status and wire shape name so
    // the telemetry classification matches the legacy per-op path exactly.
    type WalkOk = (
        aws_smithy_runtime_api::http::Response,
        Option<emulator_telemetry::OperationFailure>,
    );
    let result: Result<WalkOk, aws_smithy_schema_server::ProtocolError> = async {
        let mut deser = protocol.deserialize_input(req, O::INPUT_SCHEMA)?;
        let input = <O::Input as crate::DeserializableStruct>::deserialize(&mut *deser)
            .map_err(aws_smithy_schema_server::ProtocolError::Serde)?;
        drop(deser);

        let violations = aws_smithy_schema_server::constraints::validate(&input, O::INPUT_SCHEMA);
        if !violations.is_empty() {
            return Err(aws_smithy_schema_server::ProtocolError::Invalid(violations));
        }

        match op.handle(input, ctx).await {
            Ok(output) => {
                let resp = protocol.serialize_output(
                    &output,
                    O::OUTPUT_SCHEMA,
                    O::NAME,
                    O::SUCCESS_STATUS,
                )?;
                Ok((resp, None))
            }
            Err(e) => {
                // Classify the modeled failure for telemetry from the same two
                // facts the legacy path used — the modeled HTTP status and the
                // wire shape name — before anything about the error is dropped.
                // `OperationFailure::classify` folds the scaffold's
                // not-emulated signal into a coverage gap and every other pair
                // into its outcome plus folded error type.
                let failure =
                    emulator_telemetry::OperationFailure::classify(e.http_status(), e.shape_name());

                // Name the error on the wire exactly as the legacy path does:
                // for a query protocol the model's `awsQueryError` code (the only
                // code its clients match on), the shape name everywhere else.
                let query_code = e.query_error_code();
                let wire_error_code = match pre_dispatch {
                    crate::PreDispatchProtocol::Query { .. } => {
                        query_code.unwrap_or_else(|| e.shape_name())
                    }
                    _ => e.shape_name(),
                };
                let mut resp = protocol.serialize_error(
                    e.as_serializable(),
                    e.variant_schema(),
                    wire_error_code,
                    e.http_status(),
                )?;
                // `awsQueryCompatible`: a query-compat SDK opts in with
                // `x-amzn-query-mode: true`, and only then do we surface the
                // legacy query error code + fault in the `x-amzn-query-error`
                // response header. Native awsJson clients (no header) get the
                // unadorned awsJson error. Reads the opt-in from the request the
                // lookup already routed on.
                let query_mode = req
                    .headers()
                    .get("x-amzn-query-mode")
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if query_mode {
                    if let Some(code) = query_code {
                        let fault = if resp.status().as_u16() >= 500 {
                            "Receiver"
                        } else {
                            "Sender"
                        };
                        resp.headers_mut()
                            .insert("x-amzn-query-error", format!("{};{}", code, fault));
                    }
                }
                Ok((resp, Some(failure)))
            }
        }
    }
    .await;

    let (response, failure) = match result {
        Ok((resp, failure)) => (resp, failure),
        Err(e) => {
            // The framework-level failure tail: a refusal (an absent required
            // member, or a value outside a declared bound) is reworded by the
            // service through its own renderer, reached directly as a
            // service-level call. Anything that is not a structured refusal
            // renders from its own message. The status and the envelope stay
            // with the protocol via `pre_dispatch`.
            let chosen = crate::refusal_of(&e).and_then(|r| svc.override_refusal(&r));
            let resp = crate::protocol_error_response_with(pre_dispatch, e, chosen);
            // A framework-level failure is not a modeled error, so it has no
            // modeled shape name to fold. Classify it from the rendered
            // response status under the framework error-shape name, which the
            // closed `ErrorType` vocabulary folds to its protocol/framework
            // category just as the legacy path did for a non-modeled failure.
            let failure = emulator_telemetry::OperationFailure::classify(
                resp.status().as_u16(),
                FRAMEWORK_ERROR_SHAPE_NAME,
            );
            (resp, Some(failure))
        }
    };

    // Record once per operation, only when the gate was open at entry. The
    // namespace is the service's model-derived signing name and the operation
    // is the sequence's `O::NAME`; both fold through the closed dimension grammar,
    // so no request-time or free-form string can become a dimension.
    if let Some((started, request_metadata)) = telemetry {
        let handle = emulator_telemetry::OperationHandle::folded(
            ctx.identity().signing_name_static(),
            O::NAME,
        );
        emulator_telemetry::record_generated_operation_with_handle(
            &handle,
            started.elapsed(),
            failure,
            request_metadata,
        );
    }

    response
}

/// The wire protocol the dispatch sequence runs for `svc`: the author's
/// [`override_protocol`](crate::Service::override_protocol) when it returns
/// `Some`, else the model-derived protocol `req` is served in, from
/// [`ErasedServiceDefinition::wire_protocol`](crate::ErasedServiceDefinition::wire_protocol).
/// The one selection site the sequence and its test both call; the seam's own
/// contract lives on `override_protocol`.
fn resolve_protocol<'r>(
    svc: &'r dyn crate::Service,
    req: &aws_smithy_runtime_api::http::Request,
) -> &'r dyn crate::ServerHttpProtocol {
    svc.override_protocol()
        .unwrap_or_else(|| svc.definition().wire_protocol(req).protocol())
}

/// The wire shape name used to classify a framework-level failure for
/// telemetry. A framework failure (a refusal, a codec error) is not a modeled
/// error and carries no model shape name; the closed [`ErrorType`] vocabulary
/// folds this stand-in to its protocol/framework category.
///
/// [`ErrorType`]: emulator_telemetry::ErrorType
const FRAMEWORK_ERROR_SHAPE_NAME: &str = "FrameworkError";

/// OnCallWorlds patch (PATCHES.md): the read-only gate of a sealed account.
fn ocw_refusal<O: Operation>(
    ctx: &OperationContext<'_>,
    req: &aws_smithy_runtime_api::http::Request,
    pre_dispatch: crate::PreDispatchProtocol<'_>,
) -> Option<aws_smithy_runtime_api::http::Response> {
    ocw_clock::sealed()?;
    let framing = match pre_dispatch {
        crate::PreDispatchProtocol::Query { ec2: true } => ocw_clock::Framing::Ec2Query,
        crate::PreDispatchProtocol::Query { ec2: false } => ocw_clock::Framing::Query,
        crate::PreDispatchProtocol::RestXml { .. } => ocw_clock::Framing::RestXml,
        _ => ocw_clock::Framing::Json,
    };
    let body = req.body().bytes().unwrap_or_default();
    let refused = ocw_clock::refusal(
        ctx.identity().signing_name_static(),
        O::NAME,
        framing,
        req.uri(),
        body,
    )?;
    let error = aws_smithy_schema_server::ProtocolError::Unauthenticated {
        code: refused.code,
        message: "",
    };
    let chosen = crate::Refused {
        code: refused.code.to_string(),
        message: refused.message,
    };
    Some(crate::protocol_error_response_with(pre_dispatch, error, Some(chosen)))
}

#[cfg(test)]
mod tests {
    //! The protocol the dispatch sequence runs with is chosen once, by
    //! [`resolve_protocol`](super::resolve_protocol), which
    //! [`run_operation_http`] calls at the top of the sequence. These tests drive
    //! that same function and pin its choice: an author's `override_protocol`
    //! wins when it returns `Some`, and the model-derived protocol from
    //! `definition()` is used unchanged when it returns `None`. The whole
    //! deserialize/serialize sequence is not re-exercised here — the codecs have
    //! their own tests; what is proven is which protocol object the sequence drives.

    use crate::service::{
        ErasedServiceDefinition, OperationRoutingTable, ServerHttpProtocol, Service,
        ServiceIdentity,
    };
    use aws_smithy_runtime_api::http::{Request as RtRequest, Response as RtResponse};
    use aws_smithy_schema::serde::{SerializableStruct, ShapeDeserializer};
    use aws_smithy_schema::{Schema, ShapeId};
    use aws_smithy_schema_server::{ProtocolError, ServerProtocol};

    /// A protocol identified only by its `protocol_id`, which is all these tests
    /// read. The deserialize and serialize members are never reached — the test
    /// asserts which protocol the sequence selects, not the codec it drives — so
    /// they refuse rather than fabricate a codec that could mislead.
    #[derive(Debug)]
    struct NamedProtocol(ShapeId);

    impl aws_smithy_schema_server::ServerProtocol for NamedProtocol {
        type Request = RtRequest;
        type Response = RtResponse;

        fn protocol_id(&self) -> &ShapeId {
            &self.0
        }

        fn routing_key<'a>(&self, _request: &'a RtRequest) -> Result<&'a str, ProtocolError> {
            unreachable!("the selection test never routes")
        }

        fn deserialize_input<'a>(
            &self,
            _request: &'a RtRequest,
            _input_schema: &Schema,
        ) -> Result<Box<dyn ShapeDeserializer + 'a>, ProtocolError> {
            unreachable!("the selection test never deserializes")
        }

        fn serialize_output(
            &self,
            _output: &dyn SerializableStruct,
            _output_schema: &Schema,
            _operation_name: &str,
            _success_status: u16,
        ) -> Result<RtResponse, ProtocolError> {
            unreachable!("the selection test never serializes an output")
        }

        fn serialize_error(
            &self,
            _error: &dyn SerializableStruct,
            _error_schema: &Schema,
            _error_code: &str,
            _http_status: u16,
        ) -> Result<RtResponse, ProtocolError> {
            unreachable!("the selection test never serializes an error")
        }
    }

    fn model_protocol() -> NamedProtocol {
        NamedProtocol(ShapeId::from_static(
            "test#modelProtocol",
            "test",
            "modelProtocol",
        ))
    }

    fn custom_protocol() -> NamedProtocol {
        NamedProtocol(ShapeId::from_static(
            "test#customProtocol",
            "test",
            "customProtocol",
        ))
    }

    /// The model-derived half: only `wire_protocol()` is real, since the selection
    /// path reads nothing else. The routing table, identity, and error
    /// renderers are never reached on this path, so they are left unreachable
    /// rather than given stub behaviour that could mislead.
    struct ModelDefinition {
        protocol: NamedProtocol,
    }

    impl ErasedServiceDefinition for ModelDefinition {
        fn identity(&self) -> &ServiceIdentity {
            unreachable!("the selection test never reads the identity")
        }

        fn protocol(&self) -> &dyn ServerHttpProtocol {
            unreachable!("the framework never reads the legacy protocol accessor")
        }

        fn routing_table(&self) -> &OperationRoutingTable {
            unreachable!("the selection test never reads the routing table")
        }

        fn routing_error_response(&self, _req: &RtRequest) -> RtResponse {
            unreachable!("the selection test never renders a routing error")
        }

        fn framework_error_response(&self, _error: ProtocolError, _req: &RtRequest) -> RtResponse {
            unreachable!("the selection test never renders a framework error")
        }

        fn wire_protocol(&self, _req: &RtRequest) -> crate::WireProtocol<'_> {
            // Selection reads only the codec; the envelope is never rendered.
            crate::WireProtocol::new(&self.protocol, crate::PreDispatchProtocol::RpcV2Cbor)
        }
    }

    /// A service that carries a model-derived protocol on its definition and,
    /// optionally, an author-overridden one. `override_protocol` returns
    /// `Some(&self.overridden)` exactly when a service was built with one, and the
    /// dispatch sequence serves it in place of the definition's.
    struct ProtocolService {
        definition: ModelDefinition,
        overridden: Option<NamedProtocol>,
    }

    impl Service for ProtocolService {
        fn definition(&self) -> &dyn ErasedServiceDefinition {
            &self.definition
        }

        fn can_handle(&self, _parts: &http::request::Parts) -> bool {
            unreachable!("the selection test never routes")
        }

        fn override_protocol(&self) -> Option<&dyn ServerHttpProtocol> {
            self.overridden
                .as_ref()
                .map(|p| p as &dyn ServerHttpProtocol)
        }
    }

    /// Read the protocol the dispatch sequence would run for `svc`, through the same
    /// `resolve_protocol` the production [`run_operation_http`] calls — so a change
    /// that stops the sequence consulting `override_protocol` fails this test rather
    /// than passing against a copy of the rule.
    fn selected_protocol_id(svc: &dyn Service) -> ShapeId {
        let req = RtRequest::new(aws_smithy_types::body::SdkBody::empty());
        *super::resolve_protocol(svc, &req).protocol_id()
    }

    #[test]
    fn override_protocol_some_drives_the_walk() {
        // A service whose author returns `Some` from `override_protocol` serves
        // that codec, not the one its model declares.
        let svc = ProtocolService {
            definition: ModelDefinition {
                protocol: model_protocol(),
            },
            overridden: Some(custom_protocol()),
        };

        assert_eq!(
            selected_protocol_id(&svc),
            *custom_protocol().protocol_id(),
            "the overridden protocol must win over the model-derived one"
        );
    }

    #[test]
    fn override_protocol_none_falls_back_to_the_model_protocol() {
        // The default `override_protocol` returns `None`, so the sequence uses the
        // model-derived protocol from `definition()` unchanged.
        let svc = ProtocolService {
            definition: ModelDefinition {
                protocol: model_protocol(),
            },
            overridden: None,
        };

        assert_eq!(
            selected_protocol_id(&svc),
            *model_protocol().protocol_id(),
            "with no override the model-derived protocol must be used"
        );
    }
}
