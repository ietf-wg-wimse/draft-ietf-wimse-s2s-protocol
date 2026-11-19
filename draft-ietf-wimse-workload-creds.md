---
title: "WIMSE Workload Credentials"
abbrev: "WIMSE Workload Credentials"
category: std

docname: draft-ietf-wimse-workload-creds-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Applications and Real-Time"
workgroup: "Workload Identity in Multi System Environments"
keyword:
 - workload
 - identity
venue:
  group: "Workload Identity in Multi System Environments"
  type: "Working Group"
  mail: "wimse@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/wimse/"
  github: "ietf-wg-wimse/draft-ietf-wimse-s2s-protocol"
  latest: "https://ietf-wg-wimse.github.io/draft-ietf-wimse-s2s-protocol/draft-ietf-wimse-workload-creds.html"

author:
 -
    fullname: "Brian Campbell"
    organization: "Ping Identity"
    email: bcampbell@pingidentity.com
 -
    fullname: "Joe Salowey"
    organization: Palo Alto Networks
    email: joe@salowey.net
 -
    fullname: "Arndt Schwenkschuster"
    organization: Defakto Security
    email: arndts.ietf@gmail.com
 -
    fullname: "Yaron Sheffer"
    organization: Independent
    email: "yaronf.ietf@gmail.com"
 -
    fullname: "Yaroslav Rosomakho"
    organization: Zscaler
    email: "yrosomakho@zscaler.com"

normative:

informative:

--- abstract

The WIMSE architecture defines authentication and authorization for software workloads
in a variety of runtime environments, from the most basic ones up to complex
multi-service, multi-cloud, multi-tenant deployments.

This document defines credentials that represent workload identity and enable workloads to authenticate to each other using different protocols. Authentication requires proof of possession of the associated private key, using mechanisms specified in separate documents.

--- middle

# Introduction

This document defines credentials to facilitate authentication and authorization in the context of interaction between two workloads.
This is the core component of the WIMSE architecture {{?WIMSE-ARCH=I-D.ietf-wimse-arch}}.

Two credential types are defined, both of which represent the identity of a workload and bind a public key to that identity:

* The Workload Identity Token (WIT) is a JWT {{!JWT=RFC7519}}.

* The Workload Identity Certificate (WIC) is an X.509 certificate {{!INET-PKI=RFC5280}}.

The Workload Identity Token is targeted for application-layer protocols. The Workload Identity Certificate is targeted for transport-layer protocols, primarily mutual TLS. Presenting a WIT over a TLS-protected channel, or binding an application-layer proof of possession to TLS session properties (see {{wit-pop}}), does not make the WIT a transport-layer credential: mutual TLS authentication uses the Workload Identity Certificate, not the WIT. This does not preclude the use of the WIC in application-layer protocols or the WIT in transport-layer protocols, but these are the primary intended uses.

The various protocol bindings that use these credentials to authenticate workloads to each other are specified in separate documents and are out of scope for this document. Each such binding defines how a workload proves possession of the key material bound to its credential in order to authenticate to another workload. At the time of writing, three such protocol bindings are defined:

* Transport-layer authentication using mutual TLS with the Workload Identity Certificate, specified in {{?WIMSE-MTLS=I-D.ietf-wimse-mutual-tls}}.

* Application-layer authentication using the Workload Identity Token in conjunction with a JWT-based proof of possession, the Workload Proof Token (WPT), specified in {{?WIMSE-WPT=I-D.ietf-wimse-wpt}}.

* Application-layer authentication using the Workload Identity Token in conjunction with HTTP Message Signatures, specified in {{?WIMSE-HTTPSIG=I-D.ietf-wimse-http-signature}}.

## Deployment Architecture and Message Flow

This architecture and message flow is part of the broader flow as described in the WIMSE architecture {{Section 3.3 of WIMSE-ARCH}}.

The following example assumes that workloads hold credentials from the same trust domain. Time progresses downward; the numbered steps are described below.

~~~ aasvg
+------------+                       +------------+
| Workload A |                       | Workload B |
+------------+                       +------------+
      |                                    |
      |        (1) TLS connection          |
      |<---------------------------------->|
      |                                    |
      |            (2) Request             |
      |----------------------------------->|
      |                                    |--+
      |                                    |  | (3) Authorize
      |                                    |<-+
      |            (4) Response            |
      |<-----------------------------------|
      |                                    |
~~~
{: #high-level-seq title="Sequence of Operations"}

The high-level message flow is as follows:

1. A transport connection is established using TLS {{?TLS=RFC9846}} server authentication for Workload B, optionally incorporating mutual TLS (mTLS) with Workload A's Workload Identity Certificate for client authentication.

2. Workload A sends a request to Workload B. If application-layer authentication is used, the request includes the Workload Identity Token and proof of possession, which Workload B validates.

3. Workload B authorizes Workload A and the call.

4. Workload B returns a response to Workload A, which may be either a success or an error response.

Workload B authenticates Workload A during step (1), step (2), or both, depending on the protocol binding, before authorizing the request in step (3).

## Workload Identifiers and Authentication Granularity {#granular-auth}

The Workload Identifier is a URI and its baseline syntax and processing requirements are defined in {{!WIMSE-ID=I-D.ietf-wimse-identifier}}.
Workload Identifiers MUST be interpreted in the context of their trust domain (the URI authority component).
While deployments define how they assign identifiers and what the path portion means, implementations are expected to conform to the URI requirements outlined in {{Section 4.1 of WIMSE-ID}}.

To enable granular authentication between workloads, i.e., authenticate a peer as a specific workload, the following must be in place:

- Each workload must know its own identifier.
- A callee must be able to verify that a request is intended for it.
- A caller that authenticates the callee must know the identifier it expects the callee to present.

Once these conditions are met, the methods described in this document can be used for the caller and callee to authenticate one another.
At the transport layer, the client validates the server certificate against that expected identifier
as described in "Verifying Service Identity" of {{!TLS-SERVIDENT=RFC9525}}.
At the application layer, the callee verifies the audience of the proof of possession ({{app-audience}}).

# Conventions and Definitions

All terminology in this document follows {{WIMSE-ARCH}}.

{::boilerplate bcp14-tagged}

# Establishing Trust Anchors {#trust-anchors}

Trust anchors used to validate Workload Identity Certificates and Workload Identity Tokens are associated with a trust domain, as discussed in {{Section 3.1.1 of WIMSE-ARCH}}. They are provisioned to consumers together with trust domain metadata for that domain. Trust anchors can be represented in different ways depending on the deployment; for example, as a set of public keys (such as a JWK Set (JWKS), {{Section 5 of !JWK=RFC7517}}), as an X.509 certification authority used to validate certificate chains ({{INET-PKI}}), or as other deployment-specific material.

Consumers MUST associate each trust domain with a known, preconfigured issuer (or set of issuers) and with the corresponding trust anchors. That mapping MUST be distributed via a secure out-of-band mechanism. A credential MUST be validated only against the anchors bound to the trust domain named in its Workload Identifier. This document does not define a mechanism for discovering trust anchor information.

To validate a WIT, the receiving workload MUST verify the JWS signature using an algorithm accepted by its policy for the trust domain in the `sub` claim and a key from that domain's configured trust anchors. Trust anchor material for WIT validation MAY include more than one public key so that operators can rotate signing keys. The optional `kid` header parameter ({{Section 4.1.4 of !JWS=RFC7515}}) can guide selection of a key from those trust anchors; it does not establish trust in a key. Recipient processing of a presented WIT is specified in {{wit-validation}}.

For Workload Identity Certificates, validators use the trust anchors for the peer's trust domain to validate the X.509 chain and the Workload Identifier in the certificate, as described in {{to-wic}}. Additional certificate validation requirements are defined by the protocol using the WIC; for example, {{Section 3.2 of WIMSE-MTLS}} defines these requirements for mutual TLS.

# One Workload Identity per Credential {#single-workload-identity}

Each WIMSE credential MUST carry exactly one Workload Identifier ({{WIMSE-ID}}) that is used for authentication and authorization. Requiring a single identifier per credential keeps authorization and auditing unambiguous and aligns with common practice for workload X.509 certificates (for example, a single URI in an X.509-SVID).

For a Workload Identity Token, that identifier is the value of the `sub` claim. For a Workload Identity Certificate, that identifier is carried in the single URI SubjectAltName described in {{to-wic}}. Multiple credentials of the same Workload Identifier may be differentiated using other fields such as the optional `jti` claim.

# Application-Layer Credentials {#app-layer}

In many deployments communication between workloads cannot use end-to-end transport security such as TLS. For these deployment styles, this document proposes a credential that can be used at the application-layer.

## The Workload Identity Token {#to-wit}

The Workload Identity Token (WIT) is a JWS {{JWS}} signed JWT {{JWT}} that represents the identity of a workload.
It is issued by the Identity Server and binds a public key to the workload identity. See {{workload-identity-key-management}} for key management requirements.

A WIT has the following header parameters and claims:

* in the JOSE header:
    * `alg`: This parameter MUST be present and identify the algorithm used to sign the WIT.
    * `typ`: This parameter MUST be present and have the value `wit+jwt`, explicitly typing the WIT as recommended in {{Section 3.11 of !JWT-BCP=I-D.ietf-oauth-rfc8725bis}}.
* in the JWT claims:
    * `iss`: This claim is RECOMMENDED and identifies the issuer of the token (the Identity Server) as a URI; see {{add-claims}} for its auditing and operational uses.
    * `sub`: This claim MUST be present and contain the Workload Identifier as defined in {{WIMSE-ID}}, constrained to exactly one per credential ({{single-workload-identity}}).
    * `exp`: This claim MUST be present and limit the token's lifetime by specifying its expiration time as defined in {{Section 4.1.4 of JWT}}.
    * `jti`: This claim is OPTIONAL and provides a unique identifier for the token as defined in {{Section 4.1.7 of JWT}}. It is useful for auditing the issuance of individual WITs. Deployments MAY operate a token status or deny-list mechanism ({{wit-lifetime}}); such deployments MUST include `jti` in every WIT so that each token can be identified individually. Some token generation environments do not support it.
    * `cnf`: This claim MUST be present and reference the public key of the workload.
        * `jwk`: This member MUST be present within `cnf` and contain the public key of the workload as defined in {{Section 3.2 of !POP-JWT=RFC7800}}.
            * `alg`: This member MUST be present within `jwk` and identify the algorithm for the proof of possession.

Both the JOSE header `alg` parameter and the `cnf.jwk.alg` member MUST identify asymmetric digital signature algorithms from the IANA JOSE Algorithms registry {{?IANA.JOSE.ALGS=IANA.jose_web-signature-encryption-algorithms}} established by {{!JWA=RFC7518}}. The presented proof MUST be produced with the algorithm specified in `cnf.jwk.alg`. To promote interoperability, the `ES256` signing algorithm SHOULD be supported by general purpose implementations of this document unless local policy prevents use of this algorithm.

WITs SHOULD be short-lived, typically on the order of hours; see {{wit-lifetime}} for lifetime considerations.

As noted in {{Section 4 of WIMSE-ID}}, a Workload Identifier is a URI that includes a trust domain in the authority component.
The runtime environment often determines which
URI scheme is used, e.g., if SPIFFE is used to authenticate workloads, it mandates `spiffe` URIs.
For deployments that do not use an environment-specific scheme, the `wimse` URI scheme can be used; it is defined in {{Section 4.4 of WIMSE-ID}}.

An example WIT might look like this:

~~~ jwt
{::include includes/wit.txt.out}
~~~
{: #example-wit title="An example Workload Identity Token (WIT)"}

The decoded JOSE header of the WIT from the example above is shown here:

~~~ json
{
  "alg": "ES256",
  "kid": "June 5",
  "typ": "wit+jwt"
}
~~~
{: title="Example WIT JOSE Header"}

The decoded JWT claims of the WIT from the example above are shown here:

~~~ json
{
  "cnf": {
    "jwk": {
      "alg": "Ed25519",
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "1CXXvflN_LVVsIsYXsUvB03JmlGWeCHqQVuouCF92bg"
    }
  },
  "exp": 1745512510,
  "iat": 1745508910,
  "jti": "x-_1CTL2cca3CSE4cwb_l",
  "sub": "wimse://example.com/specific-workload"
}
~~~
{: title="Example WIT claims, including an `iat` claim, demonstrating WIT's extensibility"}

The example omits the recommended `iss` claim; see {{to-wit}} and {{add-claims}}.

The claims indicate that the example WIT:

* is valid until Thu Apr 24 2025 16:35:10 GMT (represented as NumericDate {{Section 2 of JWT}} value `1745512510`).
* identifies the workload to which the token was issued as `wimse://example.com/specific-workload`.
* has a unique identifier of `x-_1CTL2cca3CSE4cwb_l`.
* binds the public key represented by the `jwk` confirmation method to the workload `wimse://example.com/specific-workload`.
* requires the proof to be produced with the `Ed25519` signature algorithm.

For elucidative purposes only, the workload's key, including the private part, is shown below in JWK {{JWK}} format:

~~~ jwk
{
 "kty": "OKP",
 "crv": "Ed25519",
 "x": "1CXXvflN_LVVsIsYXsUvB03JmlGWeCHqQVuouCF92bg",
 "d": "sdLX8yCYKqo_XvGBLn-ZWeKT7llYeeQpgeCaXVxb5kY"
}
~~~
{: #example-caller-jwk title="Example Workload's Key"}

The example WIT is signed with one of the Identity Server's signing keys; the JOSE header `kid` identifies which key was used.
Validators use the Identity Server's public keys from the trust anchors configured for that trust domain to verify the signature (see {{trust-anchors}}).
The Identity Server's public key from this example is shown below in JWK {{JWK}} format:

~~~ jwk
{
 "kty": "EC",
 "kid": "June 5",
 "crv": "P-256",
 "x": "kXqnA2Op7hgd4zRMbw0iFcc_hDxUxhojxOFVGjE2gks",
 "y": "n__VndPMR021-59UAs0b9qDTFT-EZtT6xSNs_xFskLo"
}
~~~
{: title="Example Identity Server Key"}

### Including Additional Claims {#add-claims}

The WIT can be extended by adding claims beyond those defined in this document. The following rules address potential interoperability issues:

* To ensure interoperability in WIMSE environments, the use of Private claim names ({{Section 4.3 of JWT}}) is NOT RECOMMENDED.
* In closed environments, deployers MAY freely add claims to the WIT. Such claims SHOULD be collision-resistant, such as `example.com/myclaim`.
* A recipient that does not understand such claims MUST ignore them, as per {{Section 4 of JWT}}.
* Outside of closed environments, new claims MUST be registered with IANA {{?IANA.JWT.CLAIMS=IANA.jwt_claims}} before they can be used.

The recommended `iss` claim identifies the issuing Identity Server, allowing operators to correlate WITs with issuance logs and distinguish issuers within a trust domain during auditing and troubleshooting. Validators are not required to use `iss` when validating the WIT or establishing the workload identity: the trust domain and workload identity are carried in the mandatory `sub` claim ({{WIMSE-ID}}).

### Validating the WIT {#wit-validation}

Verification of a WIT follows {{JWS}} and the JWT best practices in {{JWT-BCP}}, with the WIMSE-specific requirements below. To validate a WIT, the recipient MUST ensure the following:

* The token is a single well-formed JWT using JWS compact serialization ({{JWS}}, {{JWT}}).
* The `sub` claim is present and is a single Workload Identifier ({{WIMSE-ID}}, {{single-workload-identity}}). The recipient uses the trust domain of that identifier to select the configured trust anchors ({{trust-anchors}}).
* The `typ` JOSE header parameter conveys a media type of `wit+jwt`.
* The JWS signature is valid under those trust anchors, as described in {{trust-anchors}}.
* The `cnf` claim is present and contains a `jwk` object with an `alg` member as specified in {{to-wit}}.
* Additional claims that are not understood are ignored, as specified in {{add-claims}}.

See {{wit-lifetime}} for WIT lifetime considerations.

## Presenting the WIT {#wit-presentation}

The workload MUST prove possession of the private key corresponding to `cnf.jwk` when presenting the WIT to another party. The WIT MUST NOT be used as a bearer token.

The proof of possession MUST be time limited, and recipients MUST reject proofs received outside their validity time. The proof MAY be bound to a transport-layer sender, such as the client identity of a TLS session, or to TLS channel binding parameters. The protocol binding defines the proof-of-possession mechanism.

The WIT and its proof of possession MUST be sent over a secure, server-authenticated TLS connection unless a secure channel is provided by some other mechanism (see {{middleboxes}}).

## The WIT HTTP Header {#wit-http-header}

When a WIT is conveyed in an HTTP header field, it MUST use the `Workload-Identity-Token` field. Protocol bindings define whether this conveyance is used. The WIT is not intended for the `Authorization` header (see {{coexist}}).

ABNF {{!ABNF=RFC5234}} for the value of `Workload-Identity-Token` header field is provided in {{wit-header-abnf}}:

~~~ abnf
ALPHA = %x41-5A / %x61-7A ; A-Z / a-z
DIGIT = %x30-39 ; 0-9
base64url = 1*(ALPHA / DIGIT / "-" / "_")
JWT =  base64url "." base64url "." base64url
WIT =  JWT
~~~
{: #wit-header-abnf title="Workload-Identity-Token Header Field ABNF"}

The following shows the WIT from {{example-wit}} in an example of a `Workload-Identity-Token` header field:

~~~ http-message
{::include includes/wit-header.txt.out}
~~~
{: title="An example Workload Identity Token HTTP Header Field"}

Note that per {{Section 5.1 of !HTTP=RFC9110}}, header field names are case insensitive;
thus, `Workload-Identity-Token`, `workload-identity-token`, `WORKLOAD-IDENTITY-TOKEN`,
etc., are all valid and equivalent header field names. However, case is significant in the header field value.

## Audience of Application-Layer Proofs {#app-audience}

The Workload Identifier in a WIT identifies the sender.
The audience of the proof of possession that accompanies the WIT identifies the intended recipient.
A recipient MUST verify that the audience refers to it, using trusted configuration rather than request fields such as `Host`,
because intermediaries may rewrite the request URI.
Each proof-of-possession mechanism defines how the audience is set and validated;
see "Audience validation" in {{Section 3.1.7 of WIMSE-WPT}} and "The `wimse-aud` Signature Parameter" in {{Section 3.2 of WIMSE-HTTPSIG}}.

## Error Conditions

Errors may occur during the processing of the WIT. If the WIT validation fails for any reason,
such as an invalid signature, an expired validity time window, or a malformed data structure, an error is returned. Typically,
this will be in response to an API call, so an HTTP status code such as 400 (Bad Request) is appropriate. This response could
include more details as per {{?HTTPAPI-PROBLEM=RFC9457}}, such as an indicator that the wrong key material or algorithm was used.  Using the HTTP
status code 401 is only recommended for this purpose when an acceptable HTTP authentication mechanism exists that can be returned with the WWW-Authenticate HTTP header.

## Coexistence with JWT Bearer Tokens {#coexist}

The `Workload-Identity-Token` header field MAY be presented alongside an `Authorization` header carrying a bearer token {{?OAUTH-BEARER=RFC6750}}. This
property allows for transition from mechanisms using identity tokens based on bearer JWTs to proof-of-possession-based WITs.
A workload may implement a policy that accepts both bearer tokens and WITs during a transition period. This policy may be configurable
per-caller to allow the workload to reject bearer tokens from callers that support WITs. Once a deployment fully supports WITs, then the use of
bearer tokens for identity can be disabled through policy.  Implementations should be careful when implementing such a transition strategy,
since the decision which token to prefer is made when the caller's identity has still not been authenticated, and needs to be revalidated following the authentication step.

For example, during migration an API can accept a JWT bearer token from a legacy caller and a WIT with its proof of possession from an upgraded caller, requiring WIT authentication once that caller's migration is complete.

The WIT can also coexist with tokens used to establish security context, such as transaction tokens {{?TXN-TOKENS=I-D.ietf-oauth-transaction-tokens}}. In this case a workload's
authorization policy may take into account both the sending workload's identity and the information in the context token.

For example, a request to an invoice API can carry a WIT and its proof of possession to authenticate the billing workload, alongside an OAuth access token in `Authorization: Bearer ...` authorizing access to a user's invoices. The API evaluates both credentials under its policy.

# Transport-Layer Credentials {#transport-layer}

As noted in the introduction, for many deployments, transport-layer protection of application traffic is ideal.

## The Workload Identity Certificate {#to-wic}

The Workload Identity Certificate is an X.509 certificate {{INET-PKI}}. The Workload Identifier used for WIMSE authentication and authorization MUST appear in exactly one SubjectAltName extension of type URI, as required by {{single-workload-identity}}. The certificate MUST NOT contain more than one URI SAN that carries a Workload Identifier.

When the certificate is also used for TLS server authentication, it is RECOMMENDED to include SubjectAltName extensions of type DNSName with the appropriate DNS names for clients that validate the server by host name rather than by workload identity. The certificate MAY contain SubjectAltName extensions of other types for PKIX or local policy, but only the URI SAN above is the WIMSE workload identity.

A relying party MUST validate the certificate against the trust anchors configured for the peer's trust domain ({{trust-anchors}}) and MUST reject the certificate if the Workload Identifier is not within that trust domain and the trust anchor used. Protocol-specific certificate validation requirements are defined in {{Section 3.2 of WIMSE-MTLS}}.

Deployments SHOULD use certificate lifetimes appropriate to the workload environment, typically on a similar scale to WITs ({{to-wit}}). Deployments MAY use certificate revocation lists (CRLs) {{INET-PKI}} or Online Certificate Status Protocol (OCSP) {{?OCSP=RFC6960}} as a defense in depth measure; this document does not rely on either mechanism.

# Client Authorization Using the Workload Identity {#client-name}

The authenticated Workload Identifier provides a common input to authorization, accounting, and auditing regardless of the credential format. This section describes how applications obtain that identifier; authorization policy is deployment-specific.
For example, the full Workload Identifier may be matched against ACLs to authorize actions requested by the peer and the identifier may be included in log messages to associate actions to the client workload for audit purposes.
A deployment may specify other authorization policies based on the specific details of how the Workload Identifier is constructed.
See {{granular-auth}} on additional security implications of Workload Identifiers.

How the receiving application obtains the Workload Identifier depends on the credential used to authenticate the peer:

* Application-layer: After successfully validating the WIT, the receiving application retrieves the Workload Identifier from the `sub` claim.
* Transport-layer: When the client is authenticated with a Workload Identity Certificate, the receiving application retrieves the Workload Identifier from the client certificate's SubjectAltName extension of type URI.

A workload MAY use other standard and deployment specific fields in the workload credential for accounting or authorization purposes.

# Workload Identity Key Management {#workload-identity-key-management}

Both the Workload Identity Token and the Workload Identity Certificate carry a public key. The corresponding private key:

* MUST be kept private
* MUST be bound to a single Workload Identifier ({{WIMSE-ID}})
* MUST NOT be used once the credential is expired
* SHOULD be regenerated for each new Workload Identity Token or Certificate, unless the key is sufficiently protected, e.g., non-exportable and hardware-bound.

For purposes of this section, keeping the private key private means that the private key is not intentionally disclosed
outside the workload instance or an authorized signing component, is not placed in credentials, logs, images, configuration
artifacts, or bearer tokens, and is not made available to intermediaries except as part of an explicitly trusted signing
service.

# Implementation Status

<cref>Note to RFC Editor: please remove this section, as well as the reference to RFC 7942, before publication.</cref>

This section records the status of known implementations of the protocol defined by this document at the time of posting of this Internet-Draft, and is based on a proposal described in {{!RFC7942}}. The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.  Please note that the listing of any individual implementation here does not imply endorsement by the IETF.  Furthermore, no effort has been spent to verify the information presented here that was supplied by IETF contributors. This is not intended as, and must not be construed to be, a catalog of available implementations or their features.  Readers are advised to note that other implementations may exist.

According to RFC 7942, "this will allow reviewers and working groups to assign due consideration to documents that have the benefit of running code, which may serve as evidence of valuable experimentation and feedback that have made the implemented protocols more mature.  It is up to the individual working groups to use this information as they see fit".

SPIFFE (Standard)

* Organization: CNCF
* Maturity:
    * Workload Identity Certificate: fully compatible with the X509-SVID and widely used.
    * Workload Identity Token: beta
* Coverage: Workload Identity Certificate, WIT
* Contact: [SPIFFE sig-spec community](https://github.com/spiffe/spiffe/tree/main/community/sig-spec)

Defakto Security

* Organization: Defakto Security (prior SPIRL)
* Maturity:
    * Workload Identity Certificate: production
    * Workload Identity Token: alpha
* Coverage: Workload Identity Certificate, WIT
* Contact: arndt@defakto.security

Teleport - Machine & Workload Identity

* Organization: Teleport
* Maturity:
    * Workload Identity Certificate: production
    * Workload Identity Token: research
* Coverage: Workload Identity Certificate
* Contact: noah@goteleport.com

wimsey

* Organization: independent
* Implementation: <https://github.com/kanywst/wimsey>
* Maturity:
    * Workload Identity Token: alpha
    * Workload Identity Certificate: alpha
* Coverage: WIT, Workload Identity Certificate
* Contact: [kanywst on GitHub](https://github.com/kanywst)

# Security Considerations

## Workload Identity

Workload Identifiers ({{WIMSE-ID}}) are scoped to a trust domain (the URI authority component), as described in {{granular-auth}}. Using a Workload Identifier without taking into account the trust domain could allow one domain to issue tokens to spoof identities in another domain. Similarly, a validator that obtains key material from the credential itself, for example by resolving the `iss` claim of a WIT to a key set, would accept credentials from any entity able to operate an issuer. The pre-configured binding of trust domains to authorized issuers and trust anchors described in {{trust-anchors}} prevents both attacks.

## Trust Domain Membership and Peer Authentication {#trust-domain-membership}

Validating a peer's credential against the trust anchors for a trust domain establishes that the peer belongs to that trust domain, but does not by itself establish which workload the peer represents. The additional identity comparison described in {{granular-auth}} is required to make that distinction. This affects both sides of a call, workloads acting as clients and workloads acting as servers.

Proof of possession does not mitigate this vulnerability. It shows that the peer holds the private key for the credential it presented ({{wit-pop}}), but it does not prove the identity itself. The same consideration applies when a Workload Identity Certificate is used at the transport layer.

Deprovisioning a workload instance or stopping credential issuance does not invalidate its existing WITs or WICs. If the corresponding private key remains usable, these credentials can still support authentication until expiry, including any permitted clock skew, unless relying parties reject them earlier, for example through revocation. Credential lifetimes therefore affect the residual exposure after deprovisioning or detection of compromise. If multiple instances use the same Workload Identifier, the identifier alone cannot distinguish them for authorization or auditing.

## Workload Identity Token and Proof of Possession {#wit-pop}

The Workload Identity Token (WIT) is bound to a secret cryptographic key and is always presented with a proof of possession (PoP) as described in {{wit-presentation}}. The WIT is a general purpose token that can be presented in multiple contexts. The WIT and its PoP are used for application-layer authentication; they are not used as the client or server credential for mutual TLS, which uses the Workload Identity Certificate ({{to-wic}}). Requiring proof of possession reduces the sensitivity of the token, but a token and its PoP may still be captured and replayed within the PoP's lifetime. The following are some mitigations for the capture and reuse of the WIT and its PoP:

### Limiting Workload Identity Token Lifespan {#wit-lifetime}

The WIT's lifetime is limited by the `exp` claim ({{to-wit}}). If both a WIT and its corresponding private key are compromised, an attacker can impersonate the workload until the WIT expires. Because this document does not rely on revocation of WITs, a short expiration is the primary mitigation against continued use of a compromised WIT and key. The recommended short lifetime balances the operational cost of frequent refresh against the window of exposure if a credential is compromised.

This document does not define a revocation mechanism for WITs; validators are not required to consult any token status service. Deployments can nevertheless operate such a mechanism as a defense in depth measure, for example a Token Status List {{?OAUTH-STATUSLIST=I-D.ietf-oauth-status-list}} or a deny-list of `jti` values, subject to the `jti` requirement in {{to-wit}}. Such mechanisms are subject to a propagation delay during which a revoked WIT may still be accepted, and their use does not relax the recommendation for short WIT lifetimes.

### Limiting Proof of Possession Lifespan

The validity limits required by {{wit-presentation}} bound the replay window. A PoP should only be valid over the time necessary for it to be successfully used for the purpose it is needed. This will typically be on the order of minutes.

### Limiting Proof of Possession Scope

In order to reduce the risk of theft and replay the PoP should have a limited scope. For example, a PoP may be targeted for use with a specific workload and even a specific transaction to reduce the impact of a stolen PoP. In some cases a workload may wish to reuse a PoP for a period of time or have it accepted by multiple target workloads. A careful analysis is warranted to understand the impacts to the system if a PoP is disclosed allowing it to be presented by an attacker along with a captured WIT.

### Replay Protection

PoP mechanisms should include replay protection to prevent reuse of a captured PoP. Without it an attacker can replay a captured PoP within its validity period.

### Binding to TLS Endpoint

Binding the PoP to a TLS endpoint, as permitted by {{wit-presentation}}, can limit replay across connections. The mechanisms for binding are outside the scope of this document.

## Workload Identity Certificate

The Workload Identity Certificate carries the Workload Identifier in a single URI SubjectAltName ({{to-wic}}). As with the WIT, the identifier is meaningful only within its trust domain. The validation requirements in {{to-wic}} bind the identifier to that domain's trust anchors. Evaluating the path or other components of the identifier without also considering the trust domain and the trust anchor can allow one trust domain to impersonate workloads in another.

### Limiting Workload Identity Certificate Lifespan

Workload Identity Certificates are frequently issued to dynamic and/or short-lived workloads. Long-lived certificates increase the impact of private-key compromise. As with WITs, the short lifetimes recommended in {{to-wic}} are the primary mitigation against continued use of a compromised key; optional revocation mechanisms provide defense in depth.

The lifetime of Workload Identity Certificates is bounded by the lifetime and rotation cadence of the trust anchors of the trust domain ({{trust-anchors}}). Compromise of a trust anchor permits issuance of certificates for the trust domain for as long as that anchor remains trusted. Deployments should therefore consider leaf and trust-anchor lifetimes together rather than the leaf lifetime in isolation.

## Workload Identity Key Management {#key-management-security}

Compromise or disclosure of the private key invalidates the security assumptions of the associated WIT or WIC. The requirements in {{workload-identity-key-management}} address key confidentiality, identity binding, and reuse.
This document does not require a particular key-protection mechanism; deployments that require stronger properties such
as non-exportability, hardware-backed protection, or binding to a measured runtime need additional deployment-specific
evidence or profile requirements. The WIT or WIC alone does not provide evidence of such stronger properties.

## Transport Security {#middleboxes}

An attacker observing or intercepting the communication channel can view the Workload Identity Token and its PoP and attempt to replay them to gain an advantage. The secure channel required by {{wit-presentation}} protects against such capture.

In some deployments the Workload Identity Token and PoP may pass through multiple systems. Communication between systems is over TLS, but the token and PoP are available in the clear at each intermediary.  While an intermediary cannot modify the token or the information within the PoP, it can attempt to capture and replay the token or modify data not protected by the PoP. Mitigations listed in {{wit-pop}} can reduce this risk. Deployments should analyze their situation to determine whether it is appropriate to trust and allow traffic to pass through a middlebox.

# Privacy Considerations

WITs and PoPs may contain private information such as user names or other identities. Care should be taken to prevent the disclosure of this information. The use of TLS helps protect the privacy of WITs and PoPs in transit. Workload Identity Certificates likewise expose the Workload Identifier, and any attributes carried in the certificate, to the peer, to any TLS-terminating intermediary, and to logs; in particular, client-certificate authentication discloses the client's workload identity to the server during the TLS handshake.

WITs and certificates with Workload Identifiers are typically associated with a workload and not a specific user, however in some deployments the workload may be associated directly to a user. While these are exceptional cases a deployment should evaluate if the disclosure of WITs or certificates can be used to track a user.


# IANA Considerations

## Media Type Registration

IANA is requested to register the following entries to the "Media Types" registry {{?IANA.MEDIA.TYPES=IANA.media-types}}:

* `application/wit+jwt`, per {{iana-wit}}.

### application/wit+jwt {#iana-wit}

Type name: application

Subtype name: wit+jwt

Required parameters: N/A

Optional parameters: N/A

Encoding considerations: Encoding considerations are identical to those specified for the `application/jwt` media type. See {{JWT}}.

Security considerations: See the Security Considerations section of RFC XXX.

Interoperability considerations: N/A

Published specification: RFC XXX, {{to-wit}}.

Applications that use this media type: Identity Servers that issue Workload Identity Tokens, and workloads that
use these tokens to authenticate to each other.

Fragment identifier considerations: N/A

Additional information:

Deprecated alias names for this type: N/A

Magic number(s): N/A

File extension(s): None

Macintosh file type code(s): N/A

Person & email address to contact for further information:

See the Authors' Addresses section of RFC XXX.

Intended usage: COMMON

Restrictions on usage: N/A

Author: See the Authors' Addresses section of RFC XXX.

Change controller: Internet Engineering Task Force (iesg@ietf.org).

## Hypertext Transfer Protocol (HTTP) Field Name Registration

IANA is requested to register the following entries to the "Hypertext Transfer Protocol (HTTP) Field Name Registry" {{?IANA.HTTP.FIELDS=IANA.http-fields}}:

* `Workload-Identity-Token`, per {{iana-wit-field}}.

### Workload-Identity-Token {#iana-wit-field}

* Field Name: Workload-Identity-Token
* Status: permanent
* Structured Type: N/A
* Specification Document: RFC XXX, {{wit-http-header}}
* Comments: see reference above for an ABNF syntax of this field

--- back

# Document History
<cref>RFC Editor: please remove before publication.</cref>

## draft-ietf-wimse-workload-creds-04

* Simplify the abstract and introduction, and clarify authentication timing in the sequence diagram.
* Clarify trust-anchor validation and the role of `kid` in key selection.
* Make the single-identifier and individual WIT field requirements explicit, explain the `iss` recommendation, and consolidate algorithm requirements.
* Change general-purpose ES256 support from MUST to SHOULD.
* Separate WIT presentation and HTTP conveyance from the token format, and clarify when the HTTP header is used.
* Clarify authorization inputs and add examples of coexistence with bearer tokens.
* Move normative security and key-management requirements into the main body.
* Add missing references, use consistent inline reference aliases, and update the TLS reference to RFC 9846.

## draft-ietf-wimse-workload-creds-03

* Replace the access-path-to-identifier mapping API with conditions for caller and callee, and add a short subsection on the audience of application-layer proofs (#173, #175).
* Added a section to describe the security considerations of granular authentication.
* Use the fully-specified `Ed25519` algorithm identifier in the examples instead of the deprecated `EdDSA` ({{?RFC9864}}).
* Add a WIT validation procedure for recipients (#290, #294).
* Clarify that WIT/PoP are application-layer credentials and are not used for mutual TLS; TLS binding does not change that (#256).
* Simplify the one-Workload-Identifier-per-credential section (#395).
* State the WIC revocation stance: short lifetimes like WITs; no CRL reliance (#270).
* State the WIT revocation stance and resolve the conflicting `jti` description: the document does not rely on revocation, but deployments may operate a token status list or `jti` deny-list, in which case `jti` is required in every WIT (#269).
* Editorial: consistent use of "proof of possession"/"PoP", with the abbreviation expanded on first use, and consistent capitalization of the defined term "Workload Identifier".
* Remove superfluous 'Use In Other Protocols' subsection that basically just said what amounts to "other specs can reference this"
* Retitle Application-Layer and Transport-Layer Workload-to-Workload Authentication to Application-Layer and Transport-Layer Credentials to clarify that these are credentials, not authentication protocols.
* say what it means to keep the private key private and that reuse of a key is probably okay when it's non-exportable and hardware-protected
* Reduce some normative and definitional duplication
* Point to draft-ietf-wimse-arch's "Trust Domain" from "Establishing Trust Anchors"
* Define `sub` a little more cleanly
* fix various editorial nits
* Try to clarify always server and sometimes client authentication in the transport bullet of the Message Flow breakdown
* Attempt some clarification of the Authentication Granularity section and reference RFC9525 for server certificate name validation
* Allow HTTP 401 for WIT errors when a WWW-Authenticate mechanism exists (#402).
* Validate credentials only against their trust domain's anchors (#370).
* Simplify `iss` text; remove `iss`-based key distribution (#411).
* Add exposure window after deprovisioning or compromise (#393).
* Remove Identity Server, PEP and PDP from the architecture diagram (#303).


## draft-ietf-wimse-workload-creds-02

* Add a section requiring exactly one Workload Identifier per credential (the `sub` claim for a WIT, a single URI SubjectAltName for a WIC).
* Add a Trust Anchors section and clarify WIT validation, key selection, and key rotation.
* Rework the Security Considerations, including WIT lifetime, WIC validation and lifetime, and privacy of the workload identifier.
* Generalize client authorization to cover both the WIT and the WIC.
* Reference the protocol binding documents (mutual TLS, WPT, and HTTP Message Signatures).
* Rename "level" to "layer" throughout.

## draft-ietf-wimse-workload-creds-01

* Clarify that the `iss` claim is RECOMMENDED in part for auditing and operations, and that validation of workload identity uses `sub`, not `iss`.
* Remove the `wimse` URI scheme definition and IANA registration from this document; both are specified in {{WIMSE-ID}}.

## draft-ietf-wimse-workload-creds-00

* Remove WPT, HTTP-Sig and mutual TLS sections, which are going to be covered by individual documents. This includes re-phrasing of various sections to focus on the credentials only.

## draft-ietf-wimse-s2s-protocol-07

* Rework the WPT's `oth` claim.
* update the media types.
* Discuss extensibility of WIT and WPT.
* Clarify error handling, specifically why not HTTP 401.
* Correct the code examples.
* Add registration request content for a `wimse` URI scheme.
* New section on key management.
* Use of the `Accept-Signature` header.

## draft-ietf-wimse-s2s-protocol-06

* Explicit definition of the Workload Identity Certificate.
* Definition of the validation of workload identifiers as part of workload authentication. Still work in progress.

## draft-ietf-wimse-s2s-protocol-05

* Removed the entire Workload Identity section which is now covered in the Architecture document.
* Content-Digest is mandatory with HTTP-Sig.
* Some wording on extending the protocol beyond HTTP.
* IANA considerations.

## draft-ietf-wimse-s2s-protocol-04

* Require `cnf.jwk.alg` in WIT which restricts signature algorithm of WPT or HTTP-Sig.
* Replay protection as a SHOULD for both WPT and HTTP-Sig.
* Consolidate terminology with the Architecture draft.

## draft-ietf-wimse-s2s-protocol-03

* Consistently use "workload".
* Implement comments from the SPIFFE community.
* Make `iss` claim in WIT optional and add wording about its relation to key distribution.
* Remove `iss` claim from WPT.
* Make `jti` claim in WIT optional.
* Error handling for the application-level methods.

## draft-ietf-wimse-s2s-protocol-02

* Coexistence with bearer tokens.
* Improve the architecture diagram.
* Some more ABNF.
* Clarified identifiers and URIs.
* Moved an author to acknowledgments.

## draft-ietf-wimse-s2s-protocol-01

* Addressed multiple comments from Pieter.
* Clarified WIMSE identity concepts, specifically "trust domain"
and "workload identifier".
* Much more detail around mTLS, including some normative language.
* WIT (the identity token) is now included in the WPT proof of possession.
* Added a section comparing the DPoP-inspired app-level security option to
the Message Signature-based alternative.

## draft-ietf-wimse-s2s-protocol-00

* Initial WG draft, an exact copy of draft-sheffer-wimse-s2s-protocol-00
* Added this document history section

# Acknowledgments
{:numbered="false"}

The authors would like to thank Pieter Kasselman for his detailed comments.

We thank Daniel Feldman for his contributions to earlier versions of this document.

Additional thanks to the WIMSE working group for the feedback and discussions that helped shape this specification, including, but not limited to,
Andrii Deinega,
Flemming Andreasen,
Jean-François "Jeff" Lombardo,
Karthik Rampalli,
and
Songbo Bu.
