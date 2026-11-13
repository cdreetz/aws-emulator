// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! SigV4 request authentication, switched by [`authentication_enabled`].
//! A request is verified by signing it again with `aws-sigv4`, the SDK's own signer.
//! `MultiServiceRouter::new` decides once whether to enforce it; the serve path then
//! publishes the keys of [`SigV4Authenticator::minted_credentials`].

use aws_sigv4::http_request::{PercentEncodingMode, SignableBody, SignableRequest, sign};
use aws_sigv4::http_request::{SignatureLocation, SigningSettings, UriPathNormalizationMode};
use crate::aws_credentials::{SECRET_ACCESS_KEY, SESSION_TOKEN, SIGV4_SCHEME};
use crate::credential_store::{CredentialStore, random_from, same_secret};
use std::time::{Duration, SystemTime};

type Parts = http::request::Parts;

const X_AMZ_DATE: &str = "x-amz-date";
const X_AMZ_CONTENT_SHA256: &str = "x-amz-content-sha256";
const HEX_ALPHABET: &[u8] = b"0123456789ABCDEF";
const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The query fields of a presigned URL that the signer adds back itself.
/// Seven days, the longest validity AWS accepts for a presigned URL.
const MAX_PRESIGNED_EXPIRES_SECS: u64 = 604_800;

const PRESIGNED_FIELDS: &str = "Algorithm Credential Date Expires SignedHeaders Signature";

/// Decides whether a request may reach the operation served by `serving_signing_name`, the signing
/// name as the router keys it: trimmed and lowercased, so `IoTSecuredTunneling` arrives as
/// `iotsecuredtunneling`. Any S3-family name serves any other, since S3 and S3 Control requests
/// are signed under `s3`, `s3express`, `s3-outposts` and `s3-object-lambda`.
pub trait RequestAuthenticator: Send + Sync {
    /// The Smithy auth scheme shape id this verifies, as operations list it (`aws.auth#sigv4`).
    fn scheme_id(&self) -> &'static str;
    /// Whether the request carries this scheme's credentials at all.
    fn recognizes(&self, parts: &Parts) -> bool;
    /// Whether `credentials` hold the credential the request is signed with, and the signature
    /// is right.
    fn verify(
        &self,
        parts: &Parts,
        body: &[u8],
        serving_signing_name: &str,
        credentials: &CredentialStore,
    ) -> Result<(), Denied>;
    /// What a caller must present to pass this authenticator, when it can be handed out.
    fn vended_credentials(&self) -> Option<VendedCredentials> {
        None
    }
}

/// Credentials an authenticator hands to an in-process caller, one variant per kind of secret.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub enum VendedCredentials {
    /// An AWS access key pair, for SigV4 signing.
    AwsAccessKey {
        access_key_id: String,
        secret_access_key: String,
    },
}

/// Prints the key id but never the secret, so a logged value leaks nothing.
impl std::fmt::Debug for VendedCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwsAccessKey { access_key_id, .. } => f
                .debug_struct("AwsAccessKey")
                .field("access_key_id", access_key_id)
                .field("secret_access_key", &"<redacted>")
                .finish(),
        }
    }
}

/// The AWS error code and message a refused caller sees.
#[derive(Debug, PartialEq, Eq)]
pub struct Denied {
    pub code: &'static str,
    pub message: &'static str,
}

pub const ACCESS_DENIED: Denied = Denied {
    code: "AccessDenied",
    message: "Sign the request with the emulator credentials",
};
const SIGNATURE_MISMATCH: Denied = Denied {
    code: "SignatureDoesNotMatch",
    message: "The request signature does not match",
};
const REQUEST_TIME_TOO_SKEWED: Denied = Denied {
    code: "RequestTimeTooSkewed",
    message: "The difference between the request time and the current time is too large",
};

const INVALID_SESSION_TOKEN: Denied = Denied {
    code: "InvalidClientTokenId",
    message: "The security token included in the request is invalid",
};

/// How far a header-signed request's `x-amz-date` may be from this clock, as AWS allows.
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(15 * 60);

static AUTHENTICATION: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Sets the process-wide switch (`--auth on|off`); call before any router is built.
pub fn set_authentication(enabled: bool) {
    AUTHENTICATION.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// The one switch for request authentication, off unless [`set_authentication`] turned it on.
pub fn authentication_enabled() -> bool {
    AUTHENTICATION.load(std::sync::atomic::Ordering::Relaxed)
}

/// The key pair this emulator process publishes, minted on first use. Requests signed with it
/// verify beside those signed with credentials the router's operations created.
pub struct SigV4Authenticator {
    pub access_key_id: String,
    pub secret_access_key: String,
}

static MINTED: std::sync::OnceLock<SigV4Authenticator> = std::sync::OnceLock::new();

impl SigV4Authenticator {
    pub fn for_this_process() -> &'static Self {
        MINTED.get_or_init(|| Self {
            access_key_id: format!("EMULATOR{}", random_from(HEX_ALPHABET, 12)),
            secret_access_key: random_from(HEX_ALPHABET, 40),
        })
    }

    /// The keys, once something in this process registered the authenticator.
    pub fn minted_credentials() -> Option<&'static Self> {
        MINTED.get()
    }

    /// The secret of `key_id`: this key pair's own, else a created credential's.
    fn secret_for(&self, key_id: &str, credentials: &CredentialStore) -> Result<String, Denied> {
        if key_id == self.access_key_id {
            return Ok(self.secret_access_key.clone());
        }
        credentials.secret_for(key_id, SIGV4_SCHEME, SECRET_ACCESS_KEY)
    }

    fn signature_for(
        &self,
        parts: &Parts,
        body: &[u8],
        signed: &Signature,
        secret: &str,
    ) -> Option<String> {
        let settings = signing_settings(signed.signing_name(), signed.expires_secs);
        with_signing_params(signed, secret, settings, |params| {
            let headers = signed.headers.iter().filter(|name| *name != X_AMZ_DATE);
            let headers = headers.flat_map(|name| header_values(parts, name));
            let uri = signable_uri_with_signed_host(parts, signed)?;
            let payload = payload(parts, body, signed);
            let request = SignableRequest::new(parts.method.as_str(), uri, headers, payload);
            let signing = sign(request.ok()?, &params.into()).ok()?;
            Some(signing.signature().to_string())
        })
    }
}

impl RequestAuthenticator for SigV4Authenticator {
    fn scheme_id(&self) -> &'static str {
        SIGV4_SCHEME
    }

    fn vended_credentials(&self) -> Option<VendedCredentials> {
        Some(VendedCredentials::AwsAccessKey {
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
        })
    }

    fn recognizes(&self, parts: &Parts) -> bool {
        let header = parts
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok());
        header.map_or_else(
            || presigned_field(parts, "X-Amz-Algorithm").is_some_and(|a| a == SIGV4_ALGORITHM),
            |header| header.starts_with(&format!("{SIGV4_ALGORITHM} ")),
        )
    }

    fn verify(
        &self,
        parts: &Parts,
        body: &[u8],
        serving_signing_name: &str,
        credentials: &CredentialStore,
    ) -> Result<(), Denied> {
        let signed = Signature::of(parts).ok_or(ACCESS_DENIED)?;
        let signed_for_serving = |service: &str| {
            crate::normalize_service_key(service) == serving_signing_name
                || (signs_like_s3(service) && signs_like_s3(serving_signing_name))
        };
        let scoped_key_id = match &signed.scope[..] {
            [key_id, _, _, service, terminator]
                if signed_for_serving(service) && terminator == "aws4_request" =>
            {
                Some(key_id)
            }
            _ => None,
        };
        let expired = signed.expires_secs.is_some_and(|secs| {
            if secs > MAX_PRESIGNED_EXPIRES_SECS {
                return true;
            }
            let at = parse_amz_date(&signed.amz_date);
            let valid_until = at.and_then(|at| at.checked_add(Duration::from_secs(secs)));
            valid_until.is_none_or(|valid_until| valid_until < ocw_clock::real_now())
        });
        let (Some(key_id), false) = (scoped_key_id, expired) else {
            return Err(ACCESS_DENIED);
        };
        if signed.expires_secs.is_none() && !within_clock_skew(&signed.amz_date) {
            return Err(REQUEST_TIME_TOO_SKEWED);
        }
        let secret = self.secret_for(key_id, credentials)?;
        own_session_token_presented(parts, key_id, credentials)?;
        let expected = self.signature_for(parts, body, &signed, &secret);
        let matches = expected.is_some_and(|expected| same_secret(&expected, &signed.value));
        let chunks_match =
            || !streams_signed_chunks(parts) || chunk_signatures_match(body, &signed, &secret);
        (matches && chunks_match())
            .then_some(())
            .ok_or(SIGNATURE_MISMATCH)
    }
}

/// The SigV4 fields of a request, from its `Authorization` header or else its presigned query.
struct Signature {
    scope: Vec<String>,
    headers: Vec<String>,
    value: String,
    amz_date: String,
    expires_secs: Option<u64>,
}

impl Signature {
    fn of(parts: &Parts) -> Option<Self> {
        let header = parts.headers.get(http::header::AUTHORIZATION);
        let field = |name: &str| match header {
            Some(header) => authorization_field(header.to_str().ok()?, name),
            None => presigned_field(parts, &format!("X-Amz-{name}")),
        };
        let (amz_date, expires_secs) = match header {
            Some(_) => (
                parts.headers.get(X_AMZ_DATE)?.to_str().ok()?.to_string(),
                None,
            ),
            None if field("Algorithm")? == SIGV4_ALGORITHM => {
                (field("Date")?, Some(field("Expires")?.parse().ok()?))
            }
            None => return None,
        };
        let split = |text: String, separator| text.split(separator).map(str::to_string).collect();
        let scope = split(field("Credential")?, '/');
        let headers = split(field("SignedHeaders")?, ';');
        let value = field("Signature")?;
        Some(Self {
            scope,
            headers,
            value,
            amz_date,
            expires_secs,
        })
    }

    /// The signing name the request's credential scope names (`key/date/region/name/aws4_request`).
    fn signing_name(&self) -> &str {
        self.scope.get(3).map_or("", String::as_str)
    }
}

fn authorization_field(header: &str, name: &str) -> Option<String> {
    let fields = header.strip_prefix(SIGV4_ALGORITHM)?.strip_prefix(' ')?;
    let mut fields = fields.split(',');
    let value = fields.find_map(|field| field.trim().strip_prefix(name)?.strip_prefix('='));
    value.map(str::to_string)
}

/// A field of a presigned request's query, such as the `X-Amz-Credential` that names the
/// service the URL was signed for.
fn presigned_field(parts: &Parts, name: &str) -> Option<String> {
    let decode = |text| {
        percent_encoding::percent_decode_str(text)
            .decode_utf8_lossy()
            .into()
    };
    let mut pairs = parts
        .uri
        .query()?
        .split('&')
        .filter_map(|item| item.split_once('='));
    let value = pairs.find(|(key, _)| decode(key) == *name)?.1;
    Some(decode(value))
}

/// A created session credential is served only with its own session token, from the
/// `x-amz-security-token` header or a presigned URL's `X-Amz-Security-Token`, as AWS serves
/// temporary credentials. A credential without a session token needs none.
fn own_session_token_presented(
    parts: &Parts,
    key_id: &str,
    credentials: &CredentialStore,
) -> Result<(), Denied> {
    let Ok(expected) = credentials.secret_for(key_id, SIGV4_SCHEME, SESSION_TOKEN) else {
        return Ok(());
    };
    let header = parts.headers.get("x-amz-security-token");
    let header = header.and_then(|value| value.to_str().ok()).map(str::to_string);
    let presented = header.or_else(|| presigned_field(parts, "X-Amz-Security-Token"));
    let matches = presented.is_some_and(|presented| same_secret(&expected, &presented));
    matches.then_some(()).ok_or(INVALID_SESSION_TOKEN)
}

/// Calls `with` with the SigV4 signing parameters `signed` names, for `secret`.
fn with_signing_params<S: Default, T>(
    signed: &Signature,
    secret: &str,
    settings: S,
    with: impl FnOnce(aws_sigv4::sign::v4::SigningParams<'_, S>) -> Option<T>,
) -> Option<T> {
    let [key, _, region, service, _] = &signed.scope[..] else {
        return None;
    };
    let credentials = aws_credential_types::Credentials::builder().provider_name("emulator");
    let credentials = credentials.access_key_id(key).secret_access_key(secret);
    let identity = credentials.build().into();
    let params = aws_sigv4::sign::v4::SigningParams::builder().identity(&identity);
    let params = params.region(region).name(service).settings(settings);
    let params = params
        .time(parse_amz_date(&signed.amz_date)?)
        .build()
        .ok()?;
    with(params)
}

/// Whether the body is an `aws-chunked` stream whose every chunk is signed
/// (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, with or without trailers).
fn streams_signed_chunks(parts: &Parts) -> bool {
    let declared = parts.headers.get(X_AMZ_CONTENT_SHA256);
    let declared = declared.and_then(|value| value.to_str().ok());
    declared.is_some_and(|marker| marker.starts_with("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"))
}

/// Every chunk of a signed `aws-chunked` stream carries the signature of its data chained from
/// the request's own signature, as SDKs sign a streamed payload. A chunk without one, or framing
/// that cannot be read, fails.
fn chunk_signatures_match(body: &[u8], signed: &Signature, secret: &str) -> bool {
    let chained = with_signing_params(signed, secret, (), |params| {
        let mut previous = signed.value.clone();
        for (data, signature) in signed_chunks(body)? {
            let data = bytes::Bytes::copy_from_slice(data);
            let expected = aws_sigv4::sign::v4::sign_chunk(&data, &previous, &params).ok()?;
            if !same_secret(expected.signature(), signature) {
                return Some(false);
            }
            previous = signature.to_string();
        }
        Some(true)
    });
    chained.unwrap_or(false)
}

/// The data and `chunk-signature` of each chunk of an `aws-chunked` body, through the final
/// empty chunk; `None` when the framing is malformed or a chunk is unsigned.
fn signed_chunks(mut body: &[u8]) -> Option<Vec<(&[u8], &str)>> {
    let mut chunks = Vec::new();
    loop {
        let header_end = body.windows(2).position(|pair| pair == b"\r\n")?;
        let header = std::str::from_utf8(&body[..header_end]).ok()?;
        let (size, signature) = header.split_once(";chunk-signature=")?;
        let size = usize::from_str_radix(size, 16).ok()?;
        let data = body.get(header_end + 2..)?.get(..size)?;
        chunks.push((data, signature));
        if size == 0 {
            return Some(chunks);
        }
        body = body.get(header_end + 2 + size..)?.strip_prefix(b"\r\n")?;
    }
}

fn header_values<'p>(parts: &'p Parts, name: &'p str) -> impl Iterator<Item = (&'p str, &'p str)> {
    let values = parts.headers.get_all(name).iter();
    values.filter_map(move |value| Some((name, value.to_str().ok()?)))
}

/// The signing names whose endpoint rules set `disableDoubleEncoding` (the S3 and S3 Control
/// models): their paths are encoded once, never normalized, and presigned with an unsigned payload.
fn signs_like_s3(signing_name: &str) -> bool {
    matches!(
        signing_name,
        "s3" | "s3-outposts" | "s3-object-lambda" | "s3express"
    )
}

fn signing_settings(service: &str, presigned_expires_secs: Option<u64>) -> SigningSettings {
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = aws_sigv4::http_request::PayloadChecksumKind::NoHeader;
    settings.excluded_headers = None;
    if signs_like_s3(service) {
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    }
    if let Some(secs) = presigned_expires_secs {
        settings.signature_location = SignatureLocation::QueryParams;
        settings.expires_in = Some(Duration::from_secs(secs));
    }
    settings
}

/// The URI the signer reads: a presigned query loses the fields the signer adds back, a
/// request without a `Host` header (in-process, HTTP/2) signs its URI authority as the host, and
/// an S3 path is signed decoded and then encoded once, so `/a/%2Fb` signs as `/a//b`. `None` when
/// the host is not signed or not known: the signer always signs one, and panics without one.
fn signable_uri_with_signed_host(parts: &Parts, signed: &Signature) -> Option<String> {
    let added_by_signer = |name: &str| {
        let field = name.strip_prefix("X-Amz-").unwrap_or("-");
        signed.expires_secs.is_some() && PRESIGNED_FIELDS.split(' ').any(|added| added == field)
    };
    let items = parts
        .uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|item| !item.is_empty());
    let items = items.filter(|item| !added_by_signer(item.split('=').next().unwrap_or("")));
    let (path, query) = (
        signable_path(parts, signed),
        items.collect::<Vec<_>>().join("&"),
    );
    let path_and_query = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    if !signed.headers.iter().any(|name| name == "host") {
        return None;
    }
    if parts.headers.contains_key(http::header::HOST) {
        return Some(path_and_query);
    }
    let (scheme, authority) = (parts.uri.scheme_str()?, parts.uri.authority()?);
    Some(format!("{scheme}://{authority}{path_and_query}"))
}

/// SigV4's `UriEncode` keeps only the unreserved characters, plus `/` in a path.
const S3_PATH_ENCODE_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn signable_path<'p>(parts: &'p Parts, signed: &Signature) -> std::borrow::Cow<'p, str> {
    let wire_path = parts.uri.path();
    if !signs_like_s3(signed.signing_name()) {
        return wire_path.into();
    }
    let decoded: Vec<u8> = percent_encoding::percent_decode_str(wire_path).collect();
    percent_encoding::percent_encode(&decoded, S3_PATH_ENCODE_SET)
        .to_string()
        .into()
}

/// SigV4's `UriEncode` for a query name or value: only the unreserved characters stay, so a
/// `+` is sent as `%2B` and never read back as a space.
const QUERY_ENCODE_SET: &percent_encoding::AsciiSet = &S3_PATH_ENCODE_SET.add(b'/');

/// One request a later caller sends to a URL [`presign_url`] signs.
pub struct PresignTarget<'a> {
    /// `https://host:port`, the listener the caller connects to; its host is signed.
    pub endpoint: &'a str,
    pub method: &'a str,
    /// The signing name the target service verifies, such as `s3`.
    pub signing_name: &'a str,
    pub region: &'a str,
    /// The path decoded: it is encoded here as [`SigV4Authenticator::verify`] reads it back.
    pub path: &'a str,
    /// Query fields beyond the signature's own, decoded.
    pub query: &'a [(&'a str, &'a str)],
    /// Headers the caller must send as given, such as a `content-type` on a `PUT`.
    pub headers: &'a [(&'a str, &'a str)],
}

/// The header a caller must send with a presigned request to `signing_name` by `method`, so the
/// request verifies whatever body it carries: `x-amz-content-sha256: UNSIGNED-PAYLOAD` for a
/// method that sends a body (`PUT`, `POST`, `PATCH`) to a service outside the S3 family. Those
/// services verify a body against its hash unless the request declares the payload unsigned,
/// and the URL is signed before the body exists. An S3-family request needs none: a presigned
/// S3 request is always verified with an unsigned payload. [`presign_url`] signs the header in.
pub fn presigned_payload_header(
    signing_name: &str,
    method: &str,
) -> Option<(&'static str, &'static str)> {
    let sends_body = matches!(method, "PUT" | "POST" | "PATCH");
    (sends_body && !signs_like_s3(signing_name)).then_some((X_AMZ_CONTENT_SHA256, UNSIGNED_PAYLOAD))
}

/// The marker a request declares in `x-amz-content-sha256` for a payload its signature leaves out.
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// The SigV4 query-presigned URL for `target`, signed at `signed_at` with `key_id` and `secret`
/// and valid for `expires_secs`: the form [`SigV4Authenticator::verify`] accepts, with the same
/// signing settings and path encoding. The payload is left out of the signature where the
/// verifier leaves it out: always for an S3-family target, and for any other target where
/// [`presigned_payload_header`] names a header, which is signed in and which the caller must
/// send. Any other target is signed for an empty body. `None` when the target cannot be signed
/// (an empty path, a header that is not valid HTTP) or `expires_secs` is 0 or longer than the
/// seven days the verifier accepts.
///
/// Handlers hand out URLs through the runtime's `UrlSigner`, which fills the endpoint and keys.
pub fn presign_url(
    target: &PresignTarget<'_>,
    key_id: &str,
    secret: &str,
    signed_at: SystemTime,
    expires_secs: u64,
) -> Option<String> {
    if expires_secs == 0 || expires_secs > MAX_PRESIGNED_EXPIRES_SECS {
        return None;
    }
    fn encode(text: &str) -> percent_encoding::PercentEncode<'_> {
        percent_encoding::utf8_percent_encode(text, QUERY_ENCODE_SET)
    }
    let path = percent_encoding::utf8_percent_encode(target.path, S3_PATH_ENCODE_SET).to_string();
    let path = path.starts_with('/').then_some(path)?;
    let mut query: Vec<String> = target
        .query
        .iter()
        .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
        .collect();
    let uri = match query.is_empty() {
        true => format!("{}{path}", target.endpoint),
        false => format!("{}{path}?{}", target.endpoint, query.join("&")),
    };
    let settings = signing_settings(target.signing_name, Some(expires_secs));
    let credentials = aws_credential_types::Credentials::builder().provider_name("emulator");
    let identity = credentials.access_key_id(key_id).secret_access_key(secret).build().into();
    let params = aws_sigv4::sign::v4::SigningParams::builder().identity(&identity);
    let params = params.region(target.region).name(target.signing_name);
    let params = params.time(signed_at).settings(settings).build().ok()?.into();
    let payload_header = presigned_payload_header(target.signing_name, target.method);
    let body = match signs_like_s3(target.signing_name) || payload_header.is_some() {
        true => SignableBody::UnsignedPayload,
        false => SignableBody::Bytes(&[]),
    };
    let headers = target.headers.iter().copied().chain(payload_header);
    let request = SignableRequest::new(target.method, &uri, headers, body).ok()?;
    let (instructions, _) = sign(request, &params).ok()?.into_parts();
    let (_, signature_fields) = instructions.into_parts();
    query.extend(signature_fields.iter().map(|(name, value)| format!("{name}={}", encode(value))));
    Some(format!("{}{path}?{}", target.endpoint, query.join("&")))
}

/// A declared marker (`UNSIGNED-PAYLOAD`, `STREAMING-...`) is signed as written; a declared hash
/// is not trusted, the body is hashed instead.
fn payload<'b>(parts: &Parts, body: &'b [u8], signed: &Signature) -> SignableBody<'b> {
    let declared = parts
        .headers
        .get(X_AMZ_CONTENT_SHA256)
        .map(|value| value.to_str());
    match declared {
        Some(Ok(marker)) if marker.contains('-') => SignableBody::Precomputed(marker.to_string()),
        _ if signed.expires_secs.is_some() && signs_like_s3(signed.signing_name()) => {
            SignableBody::UnsignedPayload
        }
        _ => SignableBody::Bytes(body),
    }
}

/// `YYYYMMDDTHHMMSSZ`, as SigV4 writes dates.
fn parse_amz_date(raw: &str) -> Option<SystemTime> {
    let format =
        time::format_description::parse_borrowed::<2>("[year][month][day]T[hour][minute][second]Z");
    Some(
        time::PrimitiveDateTime::parse(raw, &format.ok()?)
            .ok()?
            .assume_utc()
            .into(),
    )
}

fn within_clock_skew(amz_date: &str) -> bool {
    let Some(signed_at) = parse_amz_date(amz_date) else {
        return false;
    };
    // OnCallWorlds patch: the caller signs with the real clock, whatever ours says.
    let now = ocw_clock::real_now();
    let skew = now
        .duration_since(signed_at)
        .or_else(|_| signed_at.duration_since(now));
    skew.is_ok_and(|skew| skew <= MAX_CLOCK_SKEW)
}

/// Writes `keys` to `<emulator home>/<port>/emulator_credentials` (AWS shared credentials format,
/// owner-only); the file is removed when the returned guard drops. Refused where the file cannot be
/// made owner-only (non-Unix), rather than leaving the secret readable by other users.
pub fn write_credentials_file(
    keys: &SigV4Authenticator,
    port: u16,
) -> std::io::Result<EmulatorFile> {
    if cfg!(not(unix)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the credentials file cannot be made owner-only on this platform",
        ));
    }
    let (key, secret) = (&keys.access_key_id, &keys.secret_access_key);
    let text = format!("[default]\naws_access_key_id = {key}\naws_secret_access_key = {secret}\n");
    write_emulator_file(port, "emulator_credentials", &text)
}

/// Writes `text` to `<emulator home>/<port>/<name>`, owner-only on Unix, replacing (never
/// following) whatever is already there; the file is removed when the returned guard drops.
pub fn write_emulator_file(port: u16, name: &str, text: &str) -> std::io::Result<EmulatorFile> {
    write_emulator_bytes(port, name, text.as_bytes())
}

/// [`write_emulator_file`] for binary content, such as the Java trust store.
pub fn write_emulator_bytes(port: u16, name: &str, bytes: &[u8]) -> std::io::Result<EmulatorFile> {
    let home = emulator_paths::emulator_home().ok_or(std::io::ErrorKind::NotFound)?;
    let folder = home.join(port.to_string());
    std::fs::create_dir_all(&folder)?;
    #[cfg(unix)]
    std::fs::set_permissions(&folder, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let path = folder.join(name);
    match std::fs::remove_file(&path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(&mut options.open(&path)?, bytes)?;
    Ok(EmulatorFile(path))
}

pub struct EmulatorFile(pub std::path::PathBuf);

impl Drop for EmulatorFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(test)]
#[path = "request_authentication_tests.rs"]
mod tests;
