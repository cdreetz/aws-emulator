// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! The multi-service router: the emulator core that mounts N services in one
//! process and dispatches each request to the one service that claims it.

use crate::service::{ErasedOperation, Service};
use crate::OperationContext;
use emulator_server::{aws_json_error_response, AwsJsonProtocol, EmulatorService};
use emulator_server::{
    CredentialStore, Denied, RequestAuthenticator, SigV4Authenticator, VendedCredentials,
};
use aws_smithy_runtime_api::http::{Request as RtRequest, Response as RtResponse};

/// A front-router that mounts N emulated services in one process and dispatches
/// each inbound request to the one service that claims it.
///
/// Routing is a fixed two-step sequence: find the single service whose
/// [`can_handle`](Service::can_handle) returns true, then ask that service for
/// the operation and run it. Zero claimants is a 404 `UnknownService`. Several
/// AWS services share one SigV4 signing name, so two or more services can claim
/// one request; the router then keeps only the claimants whose model names an
/// operation for it, and serves the one that remains. When none or several
/// remain it answers 500 `AmbiguousService`. Ambiguity is never resolved by
/// registration order, because serving an arbitrary service would answer the
/// wrong one.
///
/// `MultiServiceRouter` implements [`EmulatorService`], so it composes with the
/// transport layer's `serve_*` paths, and it is exposed as an SDK `HttpConnector`
/// (via `impl_emulator_http_traits!`), so the embedded front door drives it
/// in-process through exactly the same `dispatch`. The two front doors cannot
/// diverge in routing behaviour because they share this one path.
#[derive(Default, Clone)]
pub struct MultiServiceRouter {
    // `Arc` so the router is `Clone` (required by `EmulatorService`, which the
    // in-process `HttpConnector` bridge clones per call) even though a
    // `Box<dyn Service>` is not: the service set is built once, before the
    // router is ever cloned or served.
    services: std::sync::Arc<Vec<Box<dyn Service>>>,
    authenticators: Vec<&'static dyn RequestAuthenticator>,
    /// Shared by every clone, so a handler's callback sees the credentials its emulator created.
    pub(crate) credential_store: std::sync::Arc<CredentialStore>,
    /// The base URL every URL this router hands out names, shared by every clone and every
    /// `UrlSigner` it made: `UNSERVED_URL_BASE` until `serving_at` or `set_url_base`.
    pub(crate) url_base: std::sync::Arc<crate::endpoint::UrlBase>,
}

impl MultiServiceRouter {
    /// An empty router. Register services with [`register_service`](Self::register_service).
    ///
    /// Every front door builds its router here, in vendored code an author does not edit, so this
    /// is the one place request authentication is switched on: with `--auth on` (`set_authentication`)
    /// requests are verified with this process's SigV4 keys.
    pub fn new() -> Self {
        let mut router = Self::default();
        if emulator_server::authentication_enabled() {
            router.register_authenticator(SigV4Authenticator::for_this_process());
        }
        router
    }

    /// Mount a service. Each service carries its own identity, protocol,
    /// `can_handle`, and operation map, so the router needs no separate name.
    ///
    /// Called only during assembly, before the router is cloned or served, so
    /// the `Arc` is uniquely held and `get_mut` always succeeds.
    pub fn register_service(&mut self, svc: impl Service) -> &mut Self {
        std::sync::Arc::get_mut(&mut self.services)
            .expect("register_service called after the router was shared")
            .push(Box::new(svc));
        self
    }

    /// Refuse requests no registered authenticator verifies, except to operations the model serves unsigned.
    /// An operation is checked by the authenticators of the auth schemes its model lists.
    pub fn register_authenticator(
        &mut self,
        authenticator: &'static dyn RequestAuthenticator,
    ) -> &mut Self {
        self.authenticators.push(authenticator);
        self
    }

    /// Turns request authentication on or off for this router only, overriding the process-wide
    /// `set_authentication`: off removes every registered authenticator, on registers the ones
    /// this emulator supports. When on, requests must carry [`Self::vended_credentials`].
    pub fn set_request_authentication(&mut self, enabled: bool) -> &mut Self {
        self.authenticators.clear();
        if enabled {
            self.register_authenticator(SigV4Authenticator::for_this_process());
        }
        self
    }

    /// The base URL this router's signed URLs and `OperationContext::endpoint` name while it
    /// is not served on a port, in place of
    /// [`UNSERVED_URL_BASE`](crate::endpoint::UNSERVED_URL_BASE). Shared by every clone.
    /// Serving the router on its data port replaces it with the data port's URL. See
    /// [`crate::endpoint`].
    pub fn set_url_base(&mut self, base: crate::EndpointUrl) -> &mut Self {
        self.url_base.set(base);
        self
    }

    /// The credentials each registered authenticator hands out; empty when none is registered.
    pub fn vended_credentials(&self) -> Vec<VendedCredentials> {
        self.authenticators
            .iter()
            .filter_map(|authenticator| authenticator.vended_credentials())
            .collect()
    }

    /// Shape ids of all registered services (sorted). For diagnostics.
    ///
    /// Reports each service by its Smithy shape id, the precise per-service
    /// identity, rather than its signing name: signing names collide across
    /// services (rds, docdb, and neptune share one), so a signing-name list
    /// cannot distinguish them.
    pub fn service_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .services
            .iter()
            .map(|s| s.definition().identity().shape_id().to_string())
            .collect();
        names.sort();
        names
    }

    /// Dispatch a buffered request to the one service that claims it.
    ///
    /// STEP 1 — filter by `can_handle`, require exactly one claimant; refuse a
    /// request that names none of the service's protocols.
    /// STEP 2 — name the operation: the service's `override_operation` first,
    /// else the model-derived `routing_table` keyed by the protocol's routing key;
    /// then refuse it unless a registered authenticator its model lists verifies it.
    /// STEPS 3–11 — the operation's `run` drives the full deserialize → handle →
    /// telemetry → serialize sequence, converting the request to the runtime-API
    /// shape the protocol speaks and back.
    pub async fn dispatch(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> http::Response<bytes::Bytes> {
        let (parts, _body) = {
            let (parts, body) = request.into_parts();
            (parts, body)
        };

        // RE-ENTRANCY GUARD — read the chain depth from the
        // [`crate::CallbackRecursionDepth`] request extension and refuse here,
        // before any service is selected, once it passes
        // [`crate::CALLBACK_RECURSION_LIMIT`]. The refusal is a throttle-shaped
        // 5xx an SDK maps to a retryable service error, returned to whichever
        // caller made the over-limit call.
        let recursion_depth = parts
            .extensions
            .get::<crate::CallbackRecursionDepth>()
            .map_or(0, |depth| depth.0);
        if recursion_depth > crate::CALLBACK_RECURSION_LIMIT {
            return callback_recursion_limit_response(recursion_depth);
        }

        // STEP 1 — exactly one service must claim the request.
        let svc = match self.select_service(&parts, &_body) {
            Ok(svc) => svc,
            Err(refused) => return *refused,
        };

        // Build the runtime-API request (parts + body) ONCE, up front: the
        // operation lookup needs the body (a `query` service routes by the
        // `Action` form field, not the headers), and so does the matched
        // operation's `run`. Reusing one request for both guarantees routing and
        // deserialization see identical bytes.
        let mut rt_req = runtime_api_request_from_parts(&parts, _body.to_vec());

        // A virtual-hosted request names its bucket in the host, but the operations are
        // modeled path-style, so the bucket moves into the path here, before anything routes
        // on the path. Only this routing copy changes: authentication reads `parts`, which
        // still carries the host and path the client signed. The addresses come from the
        // claiming service's own model (its endpoint rules); a service that declares none
        // gets its request as it arrived.
        if path_style_for_virtual_hosted(
            &mut rt_req,
            &parts,
            svc.definition().identity().virtual_host_addressing(),
        )
        .is_err()
        {
            return invalid_virtual_hosted_address_response();
        }

        // The protocol this request is served in (see `crate::wire_protocol`):
        // every step below, from operation lookup to every error, uses it. Read
        // from the headers and path alone, so it is decided before the body is
        // touched. A request that names none of the service's protocols is
        // refused here, before anything else is done for it: by the author's
        // `override_routing_error` when it answers, otherwise by the definition's
        // routing renderer, so a definition that wraps the generated entry answers
        // it too. `override_operation` is not asked, because the request is never
        // served.
        let wire = svc.definition().wire_protocol(&rt_req);
        if wire.is_unrecognised() {
            let rt_resp = svc
                .override_routing_error(&rt_req)
                .unwrap_or_else(|| svc.definition().routing_error_response(&rt_req));
            return http_response_from_runtime_api(rt_resp);
        }

        // `aws-chunked` is a transfer encoding, not a payload, so it is stripped
        // once here — before any protocol or the operation lookup reads the body
        // — exactly as an HTTP server strips `Transfer-Encoding: chunked`, and
        // exactly where the legacy per-service `dispatch` stripped it. It is a
        // pure header-gated no-op for every request that is not `aws-chunked`
        // (the overwhelmingly common case), so a non-chunked service is
        // unaffected. Left in place, S3 object writes would store the framing
        // bytes as the object: wrong length, wrong ETag, and no error raised.
        // A body that DECLARES the framing and cannot be decoded is a client
        // error, rendered in the claiming service's OWN protocol envelope (a
        // `restXml` S3 service answers `400 InvalidRequest` as `application/xml`),
        // never a pass-through that would silently store the framing bytes.
        if let Err(e) = aws_smithy_schema_server::aws_chunked::decode_request(&mut rt_req) {
            // The author's `override_framework_error` gets first refusal; on
            // `None` the definition renders it in the request's protocol. The error is
            // borrowed by the override and, if it declines, moved into the default
            // renderer — consumed exactly once, so no `Clone` of the non-`Clone`
            // `ProtocolError` is needed.
            let err = aws_smithy_schema_server::ProtocolError::Malformed(e.to_string());
            let rt_resp = svc
                .override_framework_error(&err)
                .unwrap_or_else(|| svc.definition().framework_error_response(err, &rt_req));
            return http_response_from_runtime_api(rt_resp);
        }

        // STEP 2 — the service names the operation. The author's
        // `override_operation` gets first refusal (it serves what the model's
        // routing key cannot name); on `None` the model-derived routing table
        // resolves it from the protocol's routing key. Both read the same
        // runtime-API request, so a body-routed protocol (awsQuery / ec2Query,
        // keyed on the `Action` form field) resolves exactly as the matched
        // operation's `run` later deserializes it.
        let op = match svc.override_operation(&rt_req) {
            Some(op) => Some(op),
            None => match wire.protocol().routing_key(&rt_req) {
                Ok(key) => svc.definition().routing_table().get(key),
                Err(_) => None,
            },
        };
        let Some(op) = op else {
            // The request reached its service but named no modeled operation.
            // The service renders the refusal in ITS OWN protocol envelope
            // (query -> 400 InvalidAction text/xml, awsJson -> 404, …), rather
            // than the router stamping one awsJson shape on every protocol. The
            // author's `override_routing_error` gets first refusal; on `None` the
            // entry renders the protocol-correct default.
            let rt_resp = svc
                .override_routing_error(&rt_req)
                .unwrap_or_else(|| svc.definition().routing_error_response(&rt_req));
            return http_response_from_runtime_api(rt_resp);
        };
        let admitted = refuse_cross_site_browsers(&parts);
        let admitted =
            admitted.and_then(|()| {
                // OnCallWorlds patch: seed setup calls are the account root's, in process.
                if ocw_clock::seeding() {
                    return Ok(());
                }
                self.authenticate(svc, wire, op, &rt_req, &parts, &_body)
            });
        if let Err(denied) = admitted {
            let (code, message) = (denied.code, denied.message);
            let err = aws_smithy_schema_server::ProtocolError::Unauthenticated { code, message };
            let chosen = crate::refusal_of(&err).and_then(|r| svc.override_refusal(&r));
            return http_response_from_runtime_api(
                svc.definition().refusal_response(err, chosen, &rt_req),
            );
        }

        // STEPS 3–11 — run the op against the same request, convert the response
        // back to the buffered `http` shape. The service is passed back into
        // `run` (it was looked up FROM `svc`), so the centralized sequence can read
        // the protocol this request is served in via
        // `svc.definition().wire_protocol(req)` and reach its own refusal wording
        // via `Service::override_refusal`.
        //
        // The handler is handed a callback into this same, live emulator: an
        // `EmbeddedEmulator` over `self` (which is already an SDK transport via
        // `impl_emulator_http_traits!`, cheap to clone behind its `Arc`). A
        // callback therefore hits the same engine and state. The callback's
        // transport stamps the next recursion depth, so a re-entrant chain is
        // bounded at the limit by the guard above.
        let callback = crate::EmbeddedEmulator::from_router(self.clone())
            .with_recursion_depth(recursion_depth.saturating_add(1));
        let ctx = OperationContext::new(&parts, svc.definition().identity(), callback);
        emulator_server::cli::record_api_call();
        let rt_resp = op.run(svc, &rt_req, &ctx).await;
        http_response_from_runtime_api(rt_resp)
    }
}

impl MultiServiceRouter {
    /// The one service that serves the request, or the refusal to send instead, by
    /// the selection rule on [`MultiServiceRouter`]. A claimant "names an
    /// operation" when [`names_operation`] says so.
    fn select_service(
        &self,
        parts: &http::request::Parts,
        body: &[u8],
    ) -> Result<&dyn Service, Box<http::Response<bytes::Bytes>>> {
        let claimants: Vec<&dyn Service> = self
            .services
            .iter()
            .map(|s| s.as_ref())
            .filter(|s| s.can_handle(parts))
            .collect();

        match claimants.as_slice() {
            [one] => Ok(*one),
            [] => {
                let key = emulator_server::resolve_route_key(parts);
                Err(Box::new(unknown_service_response(key.as_deref())))
            }
            several => {
                // Only this branch pays for building the request: the operation
                // lookup needs the body (a query protocol routes by its `Action`
                // form field). It is not `aws-chunked`-decoded first; no protocol
                // reads its routing key from a chunked body.
                let probe = runtime_api_request_from_parts(parts, body.to_vec());
                let modeling: Vec<&dyn Service> = several
                    .iter()
                    .copied()
                    .filter(|s| names_operation(*s, &probe))
                    .collect();
                if let [one] = modeling.as_slice() {
                    return Ok(*one);
                }
                let names: Vec<&str> = several
                    .iter()
                    .map(|s| s.definition().identity().signing_name())
                    .collect();
                let key = emulator_server::resolve_route_key(parts);
                Err(Box::new(ambiguous_service_response(key.as_deref(), &names)))
            }
        }
    }

    /// `Ok` when no authenticator is registered or `op` is served unsigned. The modeled operation
    /// the routing key names decides, so an author-written operation cannot weaken its schemes;
    /// an operation's own schemes count only when the model names none for the request.
    fn authenticate(
        &self,
        svc: &dyn Service,
        wire: crate::WireProtocol<'_>,
        op: &dyn ErasedOperation,
        rt_req: &RtRequest,
        parts: &http::request::Parts,
        body: &[u8],
    ) -> Result<(), Denied> {
        if self.authenticators.is_empty() {
            return Ok(());
        }
        let schemes = modeled_operation(svc, wire, rt_req)
            .and_then(|modeled| modeled.auth_schemes())
            .or_else(|| op.auth_schemes());
        if schemes.is_some_and(<[_]>::is_empty) {
            return Ok(());
        }
        let authenticator = authenticator_for(&self.authenticators, schemes.unwrap_or(&[]), parts)?;
        let serving = svc.definition().identity().signing_name();
        authenticator.verify(parts, body, serving, &self.credential_store)
    }
}

/// What a browser request from another site is refused with.
const CROSS_SITE_REFUSED: emulator_server::request_authentication::Denied =
    emulator_server::request_authentication::Denied {
        code: "AccessDenied",
        message: "Requests a browser sends from another site are refused",
    };

/// Refuses a request a browser sent from another site (its `Origin` or `Sec-Fetch-Site` says so),
/// before authentication, so a web page the developer visits cannot drive the emulator, even an
/// operation served unsigned. SDKs and CLIs send neither header.
fn refuse_cross_site_browsers(
    parts: &http::request::Parts,
) -> Result<(), emulator_server::request_authentication::Denied> {
    let header = |name| parts.headers.get(name).and_then(|value| value.to_str().ok());
    let origins = emulator_server::RemoteOrigins::SameOriginOnly;
    let verdict = emulator_server::classify_browser_request(
        header("origin"),
        header("sec-fetch-site"),
        &origins,
        false,
    );
    match verdict {
        emulator_server::BrowserVerdict::Allow => Ok(()),
        emulator_server::BrowserVerdict::Forbid(_) => Err(CROSS_SITE_REFUSED),
    }
}

/// The operation the model's routing table names for the request's routing key,
/// read in the protocol the request is served in.
fn modeled_operation<'s>(
    svc: &'s dyn Service,
    wire: crate::WireProtocol<'_>,
    req: &RtRequest,
) -> Option<&'s dyn ErasedOperation> {
    let key = wire.protocol().routing_key(req).ok()?;
    svc.definition().routing_table().get(key)
}

/// Whether `svc` names an operation for `req`, the way dispatch would look it up: in
/// the protocol the request is served in, the author's
/// [`override_operation`](Service::override_operation) first, then the model's
/// routing table. A request in none of the service's protocols names nothing, since
/// dispatch would refuse it before either is asked.
fn names_operation(svc: &dyn Service, req: &RtRequest) -> bool {
    let wire = svc.definition().wire_protocol(req);
    !wire.is_unrecognised()
        && (svc.override_operation(req).is_some() || modeled_operation(svc, wire, req).is_some())
}

/// The first registered authenticator, in the operation's scheme order, that recognizes the request; with no
/// schemes known, any registered one. None means the request is refused: its scheme cannot be verified here.
fn authenticator_for(
    authenticators: &[&'static dyn RequestAuthenticator],
    schemes: &[&str],
    parts: &http::request::Parts,
) -> Result<&'static dyn RequestAuthenticator, Denied> {
    let rank = |a: &dyn RequestAuthenticator| match schemes {
        [] => Some(0),
        _ => schemes.iter().position(|s| *s == a.scheme_id()),
    };
    let recognizing = authenticators.iter().filter(|a| a.recognizes(parts));
    let ranked = recognizing.filter_map(|a| Some((rank(*a)?, *a)));
    let first = ranked.min_by_key(|(rank, _)| *rank).map(|(_, a)| a);
    first.ok_or(emulator_server::request_authentication::ACCESS_DENIED)
}

impl EmulatorService for MultiServiceRouter {
    async fn handle_request(
        &self,
        req: http::Request<bytes::Bytes>,
    ) -> http::Response<bytes::Bytes> {
        self.dispatch(req).await
    }

    /// Records the data port's URL, so every URL the router hands out from now on names it.
    fn serving_at(&self, endpoint_url: &str) {
        self.url_base.serving_at(endpoint_url);
    }
}

// Expose the router as an SDK `HttpConnector`/`HttpClient`, so a caller can drive
// it in-process (the embedded front door) through exactly the same `dispatch` as
// a socket-served request — the two modes cannot diverge in routing behaviour.
emulator_server::impl_emulator_http_traits!(MultiServiceRouter);

impl std::fmt::Debug for MultiServiceRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiServiceRouter")
            .field("services", &self.service_names())
            .finish()
    }
}

/// Build the throttle-shaped `503 CallbackRecursionLimitExceeded` envelope
/// returned when an in-process callback chain passes
/// [`crate::CALLBACK_RECURSION_LIMIT`].
///
/// A `503` is a Receiver fault an AWS SDK maps to a retryable service error,
/// which is what an over-limit callback is to its caller: the request was
/// refused by the emulator, not malformed. The message names the depth reached
/// and the limit, so a cycle is diagnosable from the response alone.
fn callback_recursion_limit_response(depth_reached: u8) -> http::Response<bytes::Bytes> {
    let message = format!(
        "in-process callback chain reached depth {} past the limit of {}; \
         the request is refused to bound re-entrant callbacks",
        depth_reached,
        crate::CALLBACK_RECURSION_LIMIT,
    );
    aws_json_error_response(
        503,
        "CallbackRecursionLimitExceeded",
        &message,
        AwsJsonProtocol::V1_1,
    )
}

/// Build the `404 UnknownService` envelope returned when no registered service
/// claims a request.
fn unknown_service_response(key: Option<&str>) -> http::Response<bytes::Bytes> {
    let message = match key {
        Some(k) => format!("no emulated service is registered for '{k}'"),
        None => "could not resolve a target service from the request \
                 (no SigV4 credential scope, X-Amz-Target, or Host header)"
            .to_string(),
    };
    aws_json_error_response(404, "UnknownService", &message, AwsJsonProtocol::V1_1)
}

/// Build the `500 AmbiguousService` envelope returned when more than one
/// registered service claims a request. The message names every claimant so the
/// collision is diagnosable from the response alone.
fn ambiguous_service_response(
    key: Option<&str>,
    claimants: &[&str],
) -> http::Response<bytes::Bytes> {
    let resolved = key.unwrap_or("<unresolved>");
    let message = format!(
        "{} emulated services all claim requests for '{}': {}; \
         the request is rejected rather than served by an arbitrary one",
        claimants.len(),
        resolved,
        claimants.join(", "),
    );
    aws_json_error_response(500, "AmbiguousService", &message, AwsJsonProtocol::V1_1)
}

/// Build a runtime-API request from buffered parts + body, preserving URI,
/// method, and headers (so URI-routed protocols and `@httpHeader` bindings see
/// what the client sent).
/// Rewrites `req` from virtual-hosted to path-style when its host is one of the service's
/// virtual-hosted addresses (see [`crate::VirtualHostAddressing`]): `PUT /dir/k1` on
/// `b.s3.us-east-1.amazonaws.com` becomes `PUT /b/dir/k1` on `s3.us-east-1.amazonaws.com`.
/// The host comes from the `Host` header, else the URI authority (HTTP/2, and the
/// absolute URI the embedded front door's SDK requests carry). Any other request is left
/// alone, and so is any request to a service that declares no virtual-hosted address.
///
/// `Err` when the rewritten URI cannot be built. The request must then be refused, not
/// served as the path-style request it is not: that would read or write the wrong bucket.
fn path_style_for_virtual_hosted(
    req: &mut RtRequest,
    parts: &http::request::Parts,
    addressing: Option<&crate::VirtualHostAddressing>,
) -> Result<(), ()> {
    let Some(addressing) = addressing else {
        return Ok(());
    };
    let host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| parts.uri.authority().map(|authority| authority.as_str()));
    let Some(virtual_host) = host.and_then(|host| addressing.split(host)) else {
        return Ok(());
    };
    let path_and_query = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
    // `/` and `/?sub` name the bucket itself, addressed path-style as `/b` and `/b?sub`.
    let rest = match path_and_query.strip_prefix('/') {
        Some(rest) if rest.is_empty() || rest.starts_with('?') => rest.to_string(),
        _ => path_and_query.to_string(),
    };
    let path = format!("/{}{rest}", virtual_host.bucket);
    let uri = match parts.uri.scheme_str() {
        Some(scheme) => format!("{scheme}://{}{path}", virtual_host.endpoint),
        None => path,
    };
    req.set_uri(uri.as_str()).map_err(|_| ())?;
    if req.headers().contains_key("host") {
        req.headers_mut()
            .insert("host", virtual_host.endpoint.to_string());
    }
    Ok(())
}

/// The refusal for a virtual-hosted address whose path-style form cannot be built. The
/// address is validated before it gets here, so this is a guard that stays closed, not a
/// path a client reaches.
fn invalid_virtual_hosted_address_response() -> http::Response<bytes::Bytes> {
    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>InvalidURI</Code>\
                <Message>Couldn't parse the specified URI.</Message></Error>";
    let mut response = http::Response::new(bytes::Bytes::from_static(body.as_bytes()));
    *response.status_mut() = http::StatusCode::BAD_REQUEST;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/xml"),
    );
    response
}

fn runtime_api_request_from_parts(parts: &http::request::Parts, body: Vec<u8>) -> RtRequest {
    let mut req = RtRequest::new(aws_smithy_types::body::SdkBody::from(body));
    let uri_str = parts.uri.to_string();
    req.set_uri(uri_str.as_str()).expect("valid URI");
    req.set_method(parts.method.as_str()).expect("valid method");
    for (name, value) in parts.headers.iter() {
        if let Ok(v) = value.to_str() {
            // `append`, not `insert`: `HeaderMap::iter` yields one entry per
            // value, so a repeated or multi-valued header must keep every value
            // (e.g. `@httpHeader` list / `@httpPrefixHeaders` bindings) rather
            // than collapsing to the last one.
            req.headers_mut()
                .append(name.as_str().to_string(), v.to_string());
        }
    }
    req
}

/// Convert a runtime-API response back to the buffered `http::Response<Bytes>`
/// the `EmulatorService` contract uses, dropping hop-by-hop and transfer-framing
/// headers that describe a transfer this buffered body no longer has.
///
/// `content-length` is a handler decision, not transfer framing: an operation
/// may set it to advertise a size that is not this message's body length (a
/// `HEAD` carries the resource's length with an empty body), so a value the
/// handler set is preserved verbatim. Only when the handler sets no
/// `content-length` is the header omitted, leaving the transport to frame it
/// from the body length. Stripping a handler-set value would report the wrong
/// size on exactly the responses that set it deliberately.
fn http_response_from_runtime_api(resp: RtResponse) -> http::Response<bytes::Bytes> {
    let status = resp.status().as_u16();
    let mut builder = http::Response::builder().status(status);
    for (name, value) in resp.headers().iter() {
        if [
            "transfer-encoding",
            "connection",
            "keep-alive",
            "proxy-connection",
            "upgrade",
            "te",
            "trailer",
        ]
        .iter()
        .any(|banned| name.eq_ignore_ascii_case(banned))
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    let body_bytes = resp
        .into_body()
        .bytes()
        .map(|b| b.to_vec())
        .unwrap_or_default();
    builder
        .body(bytes::Bytes::from(body_bytes))
        .expect("valid status and headers")
}

#[cfg(test)]
mod tests {
    //! The multi-service SELECTION verdicts, pinned against the real
    //! [`MultiServiceRouter`]: zero claimants is a `404 UnknownService` naming
    //! the resolved key, two or more is a `500 AmbiguousService` naming every
    //! claimant, that ambiguity verdict does not depend on registration order,
    //! and a request no service claims is never silently absorbed. These pins
    //! drive the router's own `dispatch` through `register_service`, so they
    //! guard the production selection path itself rather than a reimplementation
    //! of it.
    //!
    //! The single-claimant SERVE path is deliberately NOT pinned here: serving
    //! needs a real operation map and protocol, which the generated service
    //! crates supply, so it is covered end to end in the `*-service-test` crates
    //! (e.g. `aws-query-compat-service-test`) that register a real generated
    //! service and drive `dispatch`. The predicate RULE each service's
    //! `can_handle` applies is pinned separately, as a pure function, in
    //! `emulator-server`.

    use super::*;
    use crate::service::{ErasedOperation, ServiceIdentity};
    use aws_smithy_runtime_api::http::Request as RtRequest;

    /// A request to `uri` carrying `host`, as both the routing copy and the signed `parts`.
    fn request_to(uri: &str, host: &str) -> (RtRequest, http::request::Parts) {
        let (parts, ()) = http::Request::builder()
            .uri(uri)
            .header("host", host)
            .body(())
            .expect("valid request")
            .into_parts();
        (runtime_api_request_from_parts(&parts, Vec::new()), parts)
    }

    const S3_LIKE: crate::VirtualHostAddressing =
        crate::VirtualHostAddressing::new(&["s3.{region}.{dnsSuffix}", "s3.{dnsSuffix}"]);

    #[test]
    fn a_service_that_declares_virtual_hosted_addresses_has_its_request_rewritten() {
        let (mut req, parts) = request_to("/dir/k1?uploads", "bucket.s3.us-east-1.amazonaws.com");
        path_style_for_virtual_hosted(&mut req, &parts, Some(&S3_LIKE)).expect("rewritable");
        assert_eq!(req.uri(), "/bucket/dir/k1?uploads");
        assert_eq!(
            req.headers().get("host"),
            Some("s3.us-east-1.amazonaws.com")
        );
    }

    #[test]
    fn a_service_that_declares_none_has_its_request_left_as_it_arrived() {
        let host = "bucket.s3.us-east-1.amazonaws.com";
        let (mut req, parts) = request_to("/dir/k1?uploads", host);
        path_style_for_virtual_hosted(&mut req, &parts, None).expect("left alone");
        assert_eq!(req.uri(), "/dir/k1?uploads");
        assert_eq!(req.headers().get("host"), Some(host));
    }

    #[test]
    fn a_host_that_is_not_one_of_the_declared_addresses_is_left_as_it_arrived() {
        for host in [
            "s3.us-east-1.amazonaws.com",
            "127.0.0.1:4566",
            "a?x.s3.amazonaws.com",
            "bucket.sqs.us-east-1.amazonaws.com",
        ] {
            let (mut req, parts) = request_to("/b/k", host);
            path_style_for_virtual_hosted(&mut req, &parts, Some(&S3_LIKE)).expect("left alone");
            assert_eq!(req.uri(), "/b/k", "{host}");
        }
    }

    #[test]
    fn the_refusal_for_an_unbuildable_address_is_a_400_xml_error() {
        let response = invalid_virtual_hosted_address_response();
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
        assert!(String::from_utf8_lossy(response.body()).contains("<Code>InvalidURI</Code>"));
    }

    /// How a test double decides whether it claims a request.
    #[derive(Clone, Copy)]
    enum Claim {
        /// Claim only when the request resolves to this service's own signing
        /// name — the framework-default predicate a generated service seeds.
        WhenKeyMatches,
        /// Claim every request, so two such services registered together
        /// contend for one request and make it ambiguous.
        Always,
        /// Claim nothing, so a request that resolves to this service's key is
        /// still declined and must not be absorbed.
        Never,
    }

    /// The [`ErasedServiceDefinition`] a [`SelectingService`] exposes: its
    /// identity, an awsJson1_0 protocol (routing key from `x-amz-target`), and a
    /// routing table that models the operations it was built with. Selection
    /// reads the protocol and table only to narrow several claimants; the error
    /// renderers are never reached by these tests, so they stay `unreachable!()`.
    struct SelectingEntry {
        identity: ServiceIdentity,
        protocol: aws_smithy_schema_server::HttpRpcServerProtocol<
            aws_smithy_schema_server::json::JsonCodec,
        >,
        table: crate::service::OperationRoutingTable,
        /// Whether the request is in a protocol this service declares; when not,
        /// `wire_protocol` answers unrecognised, as a generated entry does.
        speaks: bool,
    }

    impl SelectingEntry {
        /// An entry for `signing_name` whose routing table models `operations`,
        /// each answering with [`Answer`].
        fn new(signing_name: &'static str, operations: &[&'static str]) -> Self {
            let mut table = crate::service::OperationRoutingTable::new();
            for op in operations {
                table.add_operation(op, Box::new(Answer));
            }
            Self {
                identity: ServiceIdentity::new(signing_name, signing_name),
                protocol: aws_smithy_schema_server::AwsJson10(),
                table,
                speaks: true,
            }
        }
    }

    /// A modeled operation that answers 200 with the serving service's signing
    /// name, so a test can tell which claimant served a request.
    struct Answer;
    impl ErasedOperation for Answer {
        fn run<'r>(
            &'r self,
            svc: &'r dyn Service,
            _req: &'r RtRequest,
            _ctx: &'r OperationContext<'r>,
        ) -> crate::BoxFuture<'r, RtResponse> {
            let name = svc.definition().identity().signing_name().to_string();
            Box::pin(async move {
                RtResponse::new(
                    aws_smithy_runtime_api::http::StatusCode::try_from(200).unwrap(),
                    aws_smithy_types::body::SdkBody::from(name),
                )
            })
        }
    }

    impl crate::service::ErasedServiceDefinition for SelectingEntry {
        fn identity(&self) -> &ServiceIdentity {
            &self.identity
        }

        fn protocol(&self) -> &dyn crate::ServerHttpProtocol {
            unreachable!("the framework never reads the legacy protocol accessor")
        }

        fn routing_table(&self) -> &crate::service::OperationRoutingTable {
            &self.table
        }

        fn routing_error_response(
            &self,
            _req: &RtRequest,
        ) -> aws_smithy_runtime_api::http::Response {
            unreachable!("selection answers before a routing error is rendered")
        }

        fn framework_error_response(
            &self,
            _error: aws_smithy_schema_server::ProtocolError,
            _req: &RtRequest,
        ) -> aws_smithy_runtime_api::http::Response {
            unreachable!("selection answers before a framework error is rendered")
        }

        fn wire_protocol(&self, _req: &RtRequest) -> crate::WireProtocol<'_> {
            if !self.speaks {
                return crate::WireProtocol::unrecognised();
            }
            let envelope = crate::PreDispatchProtocol::Json {
                content_type: "application/x-amz-json-1.0",
                errortype_header: false,
            };
            crate::WireProtocol::new(&self.protocol, envelope)
        }
    }

    /// A minimal [`Service`] that participates in routing by identity, predicate
    /// and the operations its routing table models. `override_operation` returns
    /// `None`, so the table alone names its operations. The error-rendering seams
    /// are never reached by these tests and are left unreachable rather than
    /// given stub behaviour that could mislead.
    struct SelectingService {
        entry: SelectingEntry,
        claim: Claim,
    }

    impl SelectingService {
        /// A service keyed on `signing_name`, claiming a request only when it
        /// resolves to that name.
        fn by_signing_name(signing_name: &'static str) -> Self {
            Self {
                entry: SelectingEntry::new(signing_name, &[]),
                claim: Claim::WhenKeyMatches,
            }
        }

        /// A service named `signing_name` that claims every request and models no
        /// operation, for forcing an ambiguous collision.
        fn always_claiming(signing_name: &'static str) -> Self {
            Self::always_claiming_modeling(signing_name, &[])
        }

        /// A service named `signing_name` that claims every request and models
        /// `operations`, as two services sharing one signing name do.
        fn always_claiming_modeling(
            signing_name: &'static str,
            operations: &[&'static str],
        ) -> Self {
            Self {
                entry: SelectingEntry::new(signing_name, operations),
                claim: Claim::Always,
            }
        }

        /// A service named `signing_name` that claims nothing, for proving a
        /// declined request is never absorbed.
        fn never_claiming(signing_name: &'static str) -> Self {
            Self {
                entry: SelectingEntry::new(signing_name, &[]),
                claim: Claim::Never,
            }
        }
    }

    impl Service for SelectingService {
        fn definition(&self) -> &dyn crate::service::ErasedServiceDefinition {
            &self.entry
        }

        fn can_handle(&self, parts: &http::request::Parts) -> bool {
            match self.claim {
                Claim::Always => true,
                Claim::Never => false,
                Claim::WhenKeyMatches => {
                    emulator_server::resolve_route_key(parts).as_deref()
                        == Some(self.entry.identity.signing_name())
                }
            }
        }

        fn override_operation(&self, _req: &RtRequest) -> Option<&dyn ErasedOperation> {
            // A service that does not speak the request's protocol answers every request
            // here, so a test can prove selection does not ask it: dispatch never would.
            (!self.entry.speaks).then_some(&Answer as &dyn ErasedOperation)
        }

        fn override_routing_error(&self, _req: &RtRequest) -> Option<RtResponse> {
            unreachable!("selection answers before a routing error is rendered")
        }

        fn override_framework_error(
            &self,
            _error: &aws_smithy_schema_server::ProtocolError,
        ) -> Option<RtResponse> {
            unreachable!("selection answers before a framework error is rendered")
        }

        fn override_refusal(&self, _refusal: &crate::Refusal) -> Option<crate::Refused> {
            unreachable!("selection answers before a refusal is rendered")
        }
    }

    /// A buffered POST whose SigV4 credential scope names `signing_name`, so the
    /// router resolves that routing key and a `by_signing_name` service claims
    /// it.
    fn signed_request(signing_name: &str) -> http::Request<bytes::Bytes> {
        http::Request::builder()
            .method("POST")
            .uri("/")
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 \
                     Credential=AKIDEXAMPLE/20240101/us-east-1/{signing_name}/aws4_request, \
                     SignedHeaders=host, Signature=deadbeef"
                ),
            )
            .body(bytes::Bytes::from_static(b"{}"))
            .unwrap()
    }

    fn body_json(resp: &http::Response<bytes::Bytes>) -> serde_json::Value {
        serde_json::from_slice(resp.body()).unwrap()
    }

    #[tokio::test]
    async fn zero_claimants_is_404_unknown_service_naming_the_resolved_key() {
        // A request that resolves to a service no one registered has zero
        // claimants, so the router answers 404 UnknownService rather than
        // serving an arbitrary service, and the message names the key it could
        // not place.
        let mut router = MultiServiceRouter::new();
        router.register_service(SelectingService::by_signing_name("iam"));

        let resp = router.dispatch(signed_request("ec2")).await;
        assert_eq!(resp.status(), 404);
        let body = body_json(&resp);
        assert_eq!(body["__type"], "UnknownService");
        assert!(
            body["message"].as_str().unwrap().contains("ec2"),
            "the unresolved key is named: {}",
            body["message"]
        );
    }

    #[tokio::test]
    async fn two_or_more_claimants_is_500_ambiguous_service_naming_every_claimant() {
        // rds, docdb and neptune all sign as `rds`; registering three services
        // that each claim the `rds` key makes one request ambiguous. The router
        // refuses it 500 AmbiguousService and names every claimant so the
        // collision is diagnosable from the response alone.
        let mut router = MultiServiceRouter::new();
        for name in ["rds", "docdb", "neptune"] {
            // Each claims unconditionally so all three contend for the request.
            router.register_service(SelectingService::always_claiming(name));
        }

        let resp = router.dispatch(signed_request("rds")).await;
        assert_eq!(resp.status(), 500);
        let body = body_json(&resp);
        assert_eq!(body["__type"], "AmbiguousService");
        let message = body["message"].as_str().unwrap();
        for name in ["rds", "docdb", "neptune"] {
            assert!(message.contains(name), "{name} is named: {message}");
        }
        assert!(
            message.contains('3'),
            "the claimant count is named: {message}"
        );
    }

    #[tokio::test]
    async fn ambiguity_is_refused_regardless_of_registration_order() {
        // Reversing the order two colliding services are registered in must not
        // change the verdict: an ambiguous request is refused either way, never
        // served by whichever registered first.
        let build = |order: [&'static str; 2]| {
            let mut router = MultiServiceRouter::new();
            for name in order {
                router.register_service(SelectingService::always_claiming(name));
            }
            router
        };

        let forward = build(["rds", "docdb"]);
        let reverse = build(["docdb", "rds"]);
        assert_eq!(forward.dispatch(signed_request("rds")).await.status(), 500);
        assert_eq!(reverse.dispatch(signed_request("rds")).await.status(), 500);
    }

    /// A signed awsJson call to `operation`: the `x-amz-target` header names it,
    /// the SigV4 scope names `signing_name`.
    fn signed_call(signing_name: &str, operation: &str) -> http::Request<bytes::Bytes> {
        let (mut parts, body) = signed_request(signing_name).into_parts();
        parts.headers.insert(
            "x-amz-target",
            http::HeaderValue::from_str(&format!("Service.{operation}")).unwrap(),
        );
        http::Request::from_parts(parts, body)
    }

    /// Two services that both claim a request, as services sharing one signing
    /// name do (`bedrock` and `bedrock-agent` both sign as `bedrock`), registered
    /// in `order`. Each models its own operations.
    fn colliding_router(order: [&'static str; 2]) -> MultiServiceRouter {
        let mut router = MultiServiceRouter::default();
        for name in order {
            let operations: &[&'static str] = match name {
                "bedrock" => &["ListFoundationModels", "Shared"],
                _ => &["ListAgents", "Shared"],
            };
            router.register_service(SelectingService::always_claiming_modeling(name, operations));
        }
        router
    }

    #[tokio::test]
    async fn several_claimants_are_served_by_the_one_whose_model_names_the_operation() {
        // Both services claim every request, but only one models each of these
        // operations, so that one serves it, whichever was registered first.
        for order in [["bedrock", "bedrock-agent"], ["bedrock-agent", "bedrock"]] {
            let router = colliding_router(order);
            for (operation, server) in [
                ("ListAgents", "bedrock-agent"),
                ("ListFoundationModels", "bedrock"),
            ] {
                let resp = router.dispatch(signed_call("bedrock", operation)).await;
                assert_eq!(resp.status(), 200, "{operation} with order {order:?}");
                assert_eq!(
                    resp.body().as_ref(),
                    server.as_bytes(),
                    "{operation} is served by {server} with order {order:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn several_claimants_that_all_model_the_operation_stay_ambiguous() {
        // When more than one claimant models the operation, the model does not
        // separate them either, so the router still refuses rather than serving
        // an arbitrary one, and names every claimant.
        for order in [["bedrock", "bedrock-agent"], ["bedrock-agent", "bedrock"]] {
            let resp = colliding_router(order)
                .dispatch(signed_call("bedrock", "Shared"))
                .await;
            assert_eq!(resp.status(), 500, "order {order:?}");
            let body = body_json(&resp);
            assert_eq!(body["__type"], "AmbiguousService");
            let message = body["message"].as_str().unwrap();
            assert!(message.contains("bedrock-agent"), "{message}");
            assert!(message.contains('2'), "claimant count named: {message}");
        }
    }

    #[tokio::test]
    async fn a_claimant_that_does_not_speak_the_request_protocol_does_not_name_its_operation() {
        // Both claimants name `Shared` (one through `override_operation`), but that
        // one does not declare the request's protocol, so dispatch would refuse the
        // request there before asking it: only the other names it.
        for mute_first in [true, false] {
            let mut router = MultiServiceRouter::default();
            for (i, name) in ["bedrock", "bedrock-agent"].into_iter().enumerate() {
                let mut svc = SelectingService::always_claiming_modeling(name, &["Shared"]);
                svc.entry.speaks = (i == 0) != mute_first;
                router.register_service(svc);
            }
            let resp = router.dispatch(signed_call("bedrock", "Shared")).await;
            assert_eq!(resp.status(), 200, "mute_first {mute_first}");
            let served = ["bedrock", "bedrock-agent"][usize::from(mute_first)];
            assert_eq!(resp.body().as_ref(), served.as_bytes());
        }
    }

    #[tokio::test]
    async fn several_claimants_none_modeling_the_operation_stay_ambiguous() {
        // No claimant models the operation, so the model cannot pick one: the
        // request is refused as ambiguous, not served by any of them.
        let resp = colliding_router(["bedrock", "bedrock-agent"])
            .dispatch(signed_call("bedrock", "DeleteEverything"))
            .await;
        assert_eq!(resp.status(), 500);
        assert_eq!(body_json(&resp)["__type"], "AmbiguousService");
    }

    #[tokio::test]
    async fn a_declining_service_never_absorbs_a_request_it_does_not_claim() {
        // There is no catch-all: a registered service whose predicate declines a
        // request does not make the router serve it. A request that resolves to
        // that service's key but is declined, and a request that resolves to no
        // registered key at all, both answer 404 UnknownService.
        let mut router = MultiServiceRouter::new();
        router.register_service(SelectingService::never_claiming("iam"));

        let declined = router.dispatch(signed_request("iam")).await;
        assert_eq!(declined.status(), 404);
        assert_eq!(body_json(&declined)["__type"], "UnknownService");

        let unregistered = router.dispatch(signed_request("ec2")).await;
        assert_eq!(unregistered.status(), 404);
        assert_eq!(body_json(&unregistered)["__type"], "UnknownService");
    }

    #[test]
    fn request_authentication_switches_and_vends_for_one_router() {
        let mut router = MultiServiceRouter::default();
        router.set_request_authentication(false);
        assert!(
            router.authenticators.is_empty(),
            "off on a router without one is a no-op"
        );
        router
            .set_request_authentication(true)
            .set_request_authentication(true);
        assert_eq!(
            router.authenticators.len(),
            1,
            "on twice registers one authenticator"
        );
        let keys = SigV4Authenticator::minted_credentials().expect("on mints the process keys");
        assert!(std::ptr::addr_eq(router.authenticators[0], keys));
        assert_eq!(
            router.vended_credentials(),
            vec![keys.vended_credentials().expect("SigV4 vends its key pair")],
            "an authenticating router hands out the keys it checks"
        );
        router.register_authenticator(Box::leak(Box::new(SigV4Authenticator {
            access_key_id: "OTHER".into(),
            secret_access_key: "other".into(),
        })));
        router.set_request_authentication(false);
        assert!(
            router.authenticators.is_empty(),
            "off removes every authenticator"
        );
        assert!(router.vended_credentials().is_empty(), "off vends nothing");
    }

    #[test]
    fn a_request_is_checked_only_by_an_authenticator_its_operation_lists() {
        let sigv4: &'static dyn RequestAuthenticator = Box::leak(Box::new(SigV4Authenticator {
            access_key_id: "EMULATORAAAAAAAAAAAA".into(),
            secret_access_key: "s".into(),
        }));
        let bearer = http::Request::builder()
            .header("authorization", "Bearer token")
            .body(())
            .unwrap();
        let (signed, bearer) = (signed_request("sqs").into_parts().0, bearer.into_parts().0);
        #[rustfmt::skip]
        let cases: [(&str, &[&str], &http::request::Parts, bool); 4] = [
            ("sigv4 operation, sigv4 request", &["aws.auth#sigv4"], &signed, true),
            ("no schemes modeled, sigv4 request", &[], &signed, true),
            ("bearer-only operation (CodeCatalyst), no bearer authenticator", &["smithy.api#httpBearerAuth"], &signed, false),
            ("sigv4 operation, unsupported Authorization scheme", &["aws.auth#sigv4"], &bearer, false),
        ];
        for (name, schemes, parts, checked) in cases {
            assert_eq!(
                authenticator_for(&[sigv4], schemes, parts).is_ok(),
                checked,
                "{name}"
            );
        }
    }

    use aws_smithy_runtime_api::http::StatusCode;
    use aws_smithy_types::body::SdkBody;

    /// A handler-set `content-length` survives the conversion to the buffered
    /// response unchanged. A `HEAD` reply carries the resource's size with an
    /// empty body, so the advertised length is not the message body length;
    /// recomputing it from the body would report `0` and misstate the size.
    #[test]
    fn handler_set_content_length_survives_conversion_unchanged() {
        let mut rt = RtResponse::new(StatusCode::try_from(200).unwrap(), SdkBody::from(&b""[..]));
        rt.headers_mut().insert("content-length", "4096");

        let resp = http_response_from_runtime_api(rt);

        assert_eq!(
            resp.headers()
                .get("content-length")
                .map(|v| v.to_str().unwrap()),
            Some("4096"),
            "the handler's advertised length is preserved, not recomputed from the empty body"
        );
        assert!(resp.body().is_empty(), "the empty body is left empty");
    }

    /// With no handler-set `content-length`, the converted response carries
    /// none, leaving the transport to frame it from the body length rather than
    /// inheriting a stale or forced value.
    #[test]
    fn absent_content_length_is_left_for_the_transport_to_compute() {
        let rt = RtResponse::new(
            StatusCode::try_from(200).unwrap(),
            SdkBody::from(&b"hello"[..]),
        );

        let resp = http_response_from_runtime_api(rt);

        assert!(
            resp.headers().get("content-length").is_none(),
            "no header is forced when the handler set none; the transport frames the body"
        );
        assert_eq!(
            resp.body().as_ref(),
            b"hello",
            "the body is carried through"
        );
    }

    /// Transfer-framing and hop-by-hop headers that describe a transfer the
    /// buffered body no longer has are still dropped, so preserving
    /// `content-length` does not reopen the strip for the framing headers.
    #[test]
    fn transfer_framing_headers_are_still_dropped() {
        let mut rt = RtResponse::new(
            StatusCode::try_from(200).unwrap(),
            SdkBody::from(&b"{}"[..]),
        );
        rt.headers_mut().insert("transfer-encoding", "chunked");
        rt.headers_mut().insert("connection", "keep-alive");
        rt.headers_mut().insert("content-type", "application/json");

        let resp = http_response_from_runtime_api(rt);

        assert!(resp.headers().get("transfer-encoding").is_none());
        assert!(resp.headers().get("connection").is_none());
        assert_eq!(
            resp.headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap()),
            Some("application/json"),
            "a non-framing header the handler set is carried through"
        );
    }
}
