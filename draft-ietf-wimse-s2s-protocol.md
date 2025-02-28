---
title: "WIMSE Workload to Workload Authentication"
abbrev: "WIMSE W2W Auth"
category: std

docname: draft-ietf-wimse-s2s-protocol-latest
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
  latest: "https://ietf-wg-wimse.github.io/draft-ietf-wimse-s2s-protocol/draft-ietf-wimse-s2s-protocol.html"

author:
 -
    fullname: "Brian Campbell"
    organization: "Ping Identity"
    email: bcampbell@pingidentity.com
 -
    fullname: "Joe Salowey"
    organization: Venafi
    email: joe.salowey@gmail.com
 -
    fullname: "Arndt Schwenkschuster"
    organization: SPIRL
    email: arndts.ietf@gmail.com
 -
    fullname: "Yaron Sheffer"
    organization: Intuit
    email: "yaronf.ietf@gmail.com"

normative:
  RFC5234:
  RFC7515:
  RFC7517:
  RFC7519:
  RFC7800:
  RFC8725:
  RFC9110:

informative:
  IANA.JOSE.ALGS: IANA.jose_web-signature-encryption-algorithms

--- abstract

The WIMSE architecture defines authentication and authorization for software workloads
in a variety of runtime environments, from the most basic ones up to complex
multi-service, multi-cloud, multi-tenant deployments. This document defines the simplest, atomic unit of
this architecture: the protocol between two workloads that need to verify each other's identity
in order to communicate securely. The scope of this protocol is a single HTTP request-and-response
pair. To address the needs of different setups, we propose two protocols,
one at the application level and one that makes use of trusted TLS transport.
These two protocols are compatible, in the sense that a single call
chain can have some calls use one protocol and some use the other. Workload A can call
Workload B with mutual TLS authentication, while the next call from Workload B to Workload C
would be authenticated at the application level.

--- middle

# Introduction

This document defines authentication and authorization in the context of interaction between two workloads.
This is the core component of the WIMSE architecture {{?I-D.ietf-wimse-arch}}.
For simplicity, this document focuses on HTTP-based services,
and the workload-to-workload call consists of a single HTTP request and its response.
We define the credentials that both workloads should possess and how they are used to protect the HTTP exchange.

There are multiple deployment styles in use today, and they result in different security properties.
We propose to address them differently.

* Many use cases have various middleboxes inserted between pairs of workloads, resulting in a transport layer
that is not end-to-end encrypted. We propose to address these use cases by protecting the HTTP messages at the application
level ({{app-level}}).

* The other commonly deployed architecture has a mutual-TLS connection between each pair of workloads. This setup
can be addressed by a simpler solution ({{mutual-tls}}).

It is an explicit goal of this protocol that a workload deployment can include both architectures across a multi-chain call.
In other words, Workload A can call Workload B with mutual TLS protection,
while the next call to Workload C is protected at the application level.

For application-level protection we currently propose two alternative solutions, one inspired by DPoP {{?RFC9449}} in {{dpop-esque-auth}} and
one which is a profile of HTTP Message Signatures {{!RFC9421}} in {{http-sig-auth}}. The design team believes that we need to pick
one of these two alternatives for standardization, once we have understood their pros and cons.

## Deployment Architecture and Message Flow

Regardless of the transport between the workloads, we assume the following logical architecture
(numbers refer to the sequence of steps listed below):

~~~ aasvg
+------------+               +------------+
|            |      (1)      |            |
|            |<=============>|            |
|            |               |            |
| Workload A |      (3)      | Workload B |
|            |==============>|            |
|            |               |            |
|            |      (5)      |   +--------+
|            |<==============|   |  PEP   |
+------------+               +---+--------+
      ^                        ^     ^
      |            (2)         |     |
  (2) | +----------------------+     | (4)
      | |                            |
      v v                            v
+------------+               +------------+
|            |               |            |
|  Identity  |               |    PDP     |
|   Server   |               | (optional) |
|            |               |            |
+------------+               +------------+
~~~
{: #high-level-seq title="Sequence of Operations"}

The Identity Server provisions credentials to each of the workloads. At least Workload A (and possibly both) must be provisioned
with a credential before the call can proceed. Details of communication with the Identity Server are out of scope
of this document, however we do describe the credential received by the workload.

PEP is a Policy Enforcement Point, the component that allows the call to go through or blocks it. PDP is an optional
Policy Decision Point, which may be deployed in architectures where policy management is centralized. All details of
policy management and message authorization are out of scope of this document.

The high-level message flow is as follows:

1. A transport connection is set up. In the case of mutual TLS, this includes authentication of both workloads to
one another. In the case of application-level security, the TLS connection is typically one-way authenticated,
and workload-level authentication does not yet take place.
2. Workload A (and similarly, Workload B) obtains a credential from the Identity Server. This happens periodically, e.g. once every 24 hours.
3. Workload A makes an HTTP call into Workload B. This is a regular HTTP request, with the additional protection
mechanisms defined below.
4. In the case of application-level security, Workload B authenticates Workload A (when using mutual TLS, this happened in step 1).
In either case, Workload B decides whether to authorize the call.
In certain architectures, Workload B may need to consult with an external server when making this decision.
5. Workload B returns a response to Workload A, which may be an error response or a regular one.

# Conventions and Definitions

All terminology in this document follows {{?I-D.ietf-wimse-arch}}.

{::boilerplate bcp14-tagged}

# Workload Identity {#whimsical-identity}

## Trust Domain {#trust-domain}

A trust domain is a logical grouping of systems that share a common set of security controls and policies. WIMSE certificates and tokens are issued under the authority of a trust domain. Trust domains SHOULD be identified by a fully qualified domain name belonging to the organization defining the trust domain.
A trust domain maps to one or more trust anchors for validating X.509 certificates and a mechanism to securely obtain a JWK Set {{!RFC7517}} for validating WIMSE WIT tokens. This mapping MUST be obtained through a secure mechanism that ensures the authenticity and integrity of the mapping is fresh and not compromised. This secure mechanism is out of scope for this document.

A single organization may define multiple trust domains for different purposes such as different departments or environments. Each trust domain must have a unique identifier. Workload identifiers are scoped within a trust domain. If two identifiers differ only by trust domain they still refer to two different entities.

## Workload Identifier {#workload-identifier}

This document defines a workload identifier as a URI {{!RFC3986}}. This URI is used in the subject fields in the certificates and tokens defined later in this document. The URI MUST meet the criteria for the URI type of Subject Alternative Name defined in Section 4.2.1.6 of {{!RFC5280}}.

>   The name MUST NOT be a relative URI, and it MUST follow the URI syntax and
>   encoding rules specified in {{!RFC3986}}.  The name MUST include both a
>   scheme and a scheme-specific-part.

In addition the URI MUST include an authority that identifies the trust domain within which the identifier is scoped. The trust domain SHOULD be a fully qualified domain name belonging to the organization defining the trust domain to help provide uniqueness for the trust domain identifier. The scheme and scheme specific part are not defined by this specification. An example of an identifier format that conforms to this definition is [SPIFFE ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md).
While the URI encoding rules allow host names to be specified as IP addresses, IP addresses MUST NOT be used to represent trust domains except in the case where they are needed for compatibility with existing naming schemes.


# Application Level Workload To Workload Authentication {#app-level}

As noted in the Introduction, for many deployments communication between workloads cannot use
end-to-end TLS. For these deployment styles, this document proposes application-level protections.

The current version of the document includes two alternatives, both using the newly introduced
Workload Identity Token ({{to-wit}}). The first alternative ({{dpop-esque-auth}}) is inspired by the OAuth DPoP specification.
The second ({{http-sig-auth}}) is based on the HTTP Message Signatures RFC. We present both alternatives and expect
the working group to select one of them as this document progresses towards IETF consensus.
A comparison of the two alternatives is attempted in {{app-level-comparison}}.

## The Workload Identity Token {#to-wit}

The Workload Identity Token (WIT) is a JWS {{RFC7515}} signed JWT {{RFC7519}} that represents the identity of a workload.
It is issued by the Identity Server and binds a public key to the workload identity.
A WIT MUST contain the following claims, except where noted:

* in the JOSE header:
    * `alg`: An identifier for a JWS asymmetric digital signature algorithm
     (registered algorithm identifiers are listed in the IANA JOSE Algorithms registry {{IANA.JOSE.ALGS}}). The value `none` MUST NOT be used.
    * `typ`: the WIT is explicitly typed, as recommended in {{Section 3.11 of RFC8725}}, using the `wimse-id+jwt` media type.
* in the JWT claims:
    * `iss`: The issuer of the token, which is the Identity Server, represented by a URI. The `iss` claim is RECOMMENDED but optional, see {{wit-iss-note}} for more.
    * `sub`: The subject of the token, which is the identity of the workload, represented by a URI.
    * `exp`: The expiration time of the token (as defined in {{Section 4.1.4 of RFC7519}}).
      WITs should be refreshed regularly, e.g. on the order of hours.
    * `jti`: A unique identifier for the token. This claim is OPTIONAL. The `jti` claim is frequently useful for auditing issuance of individual WITs or to revoke them, but some token generation environments do not support it.
    * `cnf`: A confirmation claim containing the public key of the workload using the `jwk` member as defined in {{Section 3.2 of RFC7800}}.
     The workload MUST prove possession of the corresponding private key when presenting the WIT to another party, which can be accomplished by using it in conjunction with one of the methods in {{dpop-esque-auth}} or {{http-sig-auth}}. As such, it MUST NOT be used as a bearer token and is not intended for use in the `Authorization` header.

An example WIT might look like this (all examples, of course, are non-normative and with line breaks and extra space for readability):

~~~ jwt
eyJhbGciOiJFUzI1NiIsImtpZCI6Ikp1bmUgNSIsInR5cCI6IndpbXNlLWlkK2p3dCJ9.
eyJjbmYiOnsiandrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4Ijoiclp3V
UEwVHJIazRBWEs5MkY2Vll2bUhIWDN4VU0tSUdsck11VkNRaG04VSJ9fSwiZXhwIjoxNz
QwNzU4MzQ4LCJpYXQiOjE3NDA3NTQ3NDgsImp0aSI6IjRmYzc3ZmNlZjU3MWIzYmIzM2I
2NzJlYWYyMDRmYWY0Iiwic3ViIjoid2ltc2U6Ly9leGFtcGxlLmNvbS9zcGVjaWZpYy13
b3JrbG9hZCJ9.j-WlF3bufTwWeVZQntPhlzvSTPwf37-4wfazJZARdHYmW9S_olB5nKEq
wqTZpIX_LoVVIcyK0VBE7Fa0CMvw2g
~~~
{: #example-wit title="An example Workload Identity Token (WIT)"}

The decoded JOSE header of the WIT from the example above is shown here:

~~~ json
{
  "alg": "ES256",
  "kid": "June 5",
  "typ": "wimse-id+jwt"
}
~~~
{: title="Example WIT JOSE Header"}

The decoded JWT claims of the WIT from the example above are shown here:

~~~ json
{
  "cnf": {
    "jwk": {
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "rZwUA0TrHk4AXK92F6VYvmHHX3xUM-IGlrMuVCQhm8U"
    }
  },
  "exp": 1740758348,
  "iat": 1740754748,
  "jti": "4fc77fcef571b3bb33b672eaf204faf4",
  "sub": "wimse://example.com/specific-workload"
}
~~~
{: title="Example WIT Claims"}

The claims indicate that the example WIT:

* was issued by an Identity Server known as `wimse://example.com/trusted-central-authority`.
* is valid until May 15, 2024 3:28:45 PM GMT-06:00 (represented as NumericDate {{Section 2 of RFC7519}} value `1717612470`).
* identifies the workload to which the token was issued as `wimse://example.com/specific-workload`.
* has a unique identifier of `x-_1CTL2cca3CSE4cwb__`.
* binds the public key represented by the `jwk` confirmation method to the workload `wimse://example.com/specific-workload`.

For elucidative purposes only, the workload's key, including the private part, is shown below in JWK {{RFC7517}} format:

~~~ jwk
{
 "kty": "OKP",
 "crv": "Ed25519",
 "x": "rZwUA0TrHk4AXK92F6VYvmHHX3xUM-IGlrMuVCQhm8U",
 "d": "SFrq2PHwRyUGPbUxLVlNVq6XP4S2iklVo3GIBjlb6ZE"
}
~~~
{: #example-caller-jwk title="Example Workload's Key"}

The afore-exampled WIT is signed with the private key of the Identity Server.
The public key(s) of the Identity Server need to be known to all workloads in order to verify the signature of the WIT.
The Identity Server's public key from this example is shown below in JWK {{RFC7517}} format:

~~~ jwk
{
 "kty": "EC",
 "kid": "June 5",
 "crv": "P-256",
 "x": "aolos9KoHX-GeIO-TXhVg-D8BBzZtrHWMZt54SVwMQs",
 "y": "ouPmPL2f9U054ePXiaZ1-VxTvUhXssEbjWO8EAkM96s"
}
~~~
{: title="Example Identity Server Key"}

### The WIT HTTP Header {#wit-http-header}

A WIT is conveyed in an HTTP header field named `Workload-Identity-Token`.

For those who celebrate, ABNF {{RFC5234}} for the value of `Workload-Identity-Token` header field is provided in {{wit-header-abnf}}:

~~~ abnf
ALPHA = %x41-5A / %x61-7A ; A-Z / a-z
DIGIT = %x30-39 ; 0-9
base64url = 1*(ALPHA / DIGIT / "-" / "_")
JWT =  base64url "." base64url "." base64url
WIT =  JWT
~~~~
{: #wit-header-abnf title="Workload-Identity-Token Header Field ABNF"}

The following shows the WIT from {{example-wit}} in an example of a `Workload-Identity-Token` header field:

~~~ http-message
Workload-Identity-Token: eyJhbGciOiJFUzI1NiIsImtpZCI6Ikp1bmUgNSIsInR5
cCI6IndpbXNlLWlkK2p3dCJ9.eyJjbmYiOnsiandrIjp7ImNydiI6IkVkMjU1MTkiLCJr
dHkiOiJPS1AiLCJ4Ijoiclp3VUEwVHJIazRBWEs5MkY2Vll2bUhIWDN4VU0tSUdsck11V
kNRaG04VSJ9fSwiZXhwIjoxNzQwNzU4MzQ4LCJpYXQiOjE3NDA3NTQ3NDgsImp0aSI6Ij
RmYzc3ZmNlZjU3MWIzYmIzM2I2NzJlYWYyMDRmYWY0Iiwic3ViIjoid2ltc2U6Ly9leGF
tcGxlLmNvbS9zcGVjaWZpYy13b3JrbG9hZCJ9.j-WlF3bufTwWeVZQntPhlzvSTPwf37-
4wfazJZARdHYmW9S_olB5nKEqwqTZpIX_LoVVIcyK0VBE7Fa0CMvw2g
~~~
{: title="An example Workload Identity Token HTTP Header Field"}

Note that per {{RFC9110}}, header field names are case insensitive;
thus, `Workload-Identity-Token`, `workload-identity-token`, `WORKLOAD-IDENTITY-TOKEN`,
etc., are all valid and equivalent header field names. However, case is significant in the header field value.

### A note on `iss` claim and key distribution {#wit-iss-note}

It is RECOMMENDED that the WIT carries an `iss` claim. This specification itself does not make use of a potential `iss` claim but also carries the trust domain in the workload identifier ({{workload-identifier}}). Implementations MAY include the `iss` claim in the form of a `https` URL to facilitate key distribution via mechanisms like the `jwks_uri` from {{!RFC8414}} but alternative key distribution methods may make use of the trust domain included in the workload identifier which is carried in the mandatory `sub` claim.

## Option 1: DPoP-Inspired Authentication {#dpop-esque-auth}

This option, inspired by the OAuth DPoP specification {{?RFC9449}}, uses a DPoP-like mechanism to authenticate
the calling workload in the context of the request. The WIMSE Identity Token ({{to-wit}}) is sent in the request as
described in {{wit-http-header}}. An additional JWT, the Workload Proof Token (WPT), is signed by the private key
corresponding to the public key in the WIT. The WPT is sent in the `Workload-Proof-Token` header field of the request.
The ABNF syntax of the `Workload-Proof-Token` header field is:

~~~ abnf
WPT =  JWT
~~~~
{: #wpt-header-abnf title="Workload-Proof-Token Header Field ABNF"}

where the `JWT` projection is defined in {{wit-header-abnf}}.

A WPT contains the following:

* in the JOSE header:
    * `alg`: An identifier for an appropriate JWS asymmetric digital signature algorithm corresponding to
     the confirmation key in the associated WIT.
    * `typ`: the WPT is explicitly typed, as recommended in {{Section 3.11 of RFC8725}},
     using the `application/wimse-proof+jwt` media type.
* in the JWT claims:
    * `aud`: The audience of the token contains the HTTP target URI ({{Section 7.1 of RFC9110}}) of the request
     to which the WPT is attached, without query or fragment parts.
    * `exp`: The expiration time of the WIT (as defined in {{Section 4.1.4 of RFC7519}}). WPT lifetimes MUST be short,
     e.g., on the order of minutes or seconds.
    * `jti`: A unique identifier for the token.
    * `wth`: Hash of the Workload Identity Token, defined in {{to-wit}}. The value is the base64url encoding of the
     SHA-256 hash of the ASCII encoding of the token's value.
    * `ath`: Hash of the OAuth access token, if present in the request, which might convey end-user identity and
     authorization context of the request. The value, as per {{Section 4.1 of RFC9449}},
     is the base64url encoding of the SHA-256 hash of the ASCII encoding of the access token's value.
    * `tth`: Hash of the Txn-Token {{?I-D.ietf-oauth-transaction-tokens}}, if present in the request,
     which might convey end-user identity and authorization context of the request. The value MUST be the result of
     a base64url encoding (as defined in {{Section 2 of RFC7515}}) of the SHA-256 hash of
     the ASCII encoding of the associated token's value.
    * `oth`: Hash of any other token in the request that might convey end-user identity and authorization context of the
     request, if such a token exists.
     The value MUST be the result of a base64url encoding (as defined in {{Section 2 of RFC7515}}) of the
     SHA-256 hash of the ASCII encoding of the associated token's value.
     (Note: this is less than ideal but seems we need something like this for extensibility.)

An example WPT might look like the following:

~~~ jwt
eyJhbGciOiJFZERTQSIsInR5cCI6IndpbXNlLXByb29mK2p3dCJ9.eyJhdGgiOiJDTDR3
amZwUm1OZi1iZFlJYllMblY5ZDVyTUFSR3dLWUUxMHdVd3pDMGpJIiwiYXVkIjoiaHR0c
HM6Ly93b3JrbG9hZC5leGFtcGxlLmNvbS9wYXRoIiwiZXhwIjoxNzQwNzU1MDQ4LCJqdG
kiOiIwYzc0MDM4NmNhMWRjYWQzN2RlMWI1ZjlkZTFiMDcwNSIsInd0aCI6ImFBMFdfb0Z
KSzdxVjd6WWhjbXpSMUtPWFZDSGpkMng2YzRzT1FMdkU5MFkifQ.W9RZqieXeD-UgdtbY
f8ZNkf2_6_6b_kJSfkODQdq3_QDSSGOhVbRAR3qQoOu0SzihiG6HCsGwslfo4WdvnH5AQ
~~~
{: #example-wpt title="Example Workload Proof Token (WPT)"}

The decoded JOSE header of the WPT from the example above is shown here:

~~~ json
{
  "alg": "EdDSA",
  "typ": "wimse-proof+jwt"
}
~~~
{: title="Example WPT JOSE Header"}

The decoded JWT claims of the WPT from the example above are shown here:

~~~ json
{
  "ath": "CL4wjfpRmNf-bdYIbYLnV9d5rMARGwKYE10wUwzC0jI",
  "aud": "https://workload.example.com/path",
  "exp": 1740755048,
  "jti": "0c740386ca1dcad37de1b5f9de1b0705",
  "wth": "aA0W_oFJK7qV7zYhcmzR1KOXVCHjd2x6c4sOQLvE90Y"
}
~~~
{: title="Example WPT Claims"}

An example of an HTTP request with both the WIT and WPT from prior examples is shown below:

~~~ http
{::include includes/wpt-request.txt.out}
~~~
{: title="Example HTTP Request with WIT and WPT"}

To validate the WPT in the request, the recipient MUST ensure the following:

* There is exactly one `Workload-Proof-Token` header field in the request.
* The `Workload-Proof-Token` header field value is a single and well-formed JWT.
* The WPT signature is valid using the public key from the confirmation claim of the WIT.
* The `typ` JOSE header parameter of the WPT conveys a media type of `wimse-proof+jwt`.
* The `aud` claim of the WPT matches the target URI, or an acceptable alias or normalization thereof, of the HTTP request
 in which the WPT was received, ignoring any query and fragment parts.
* The `exp` claim is present and conveys a time that has not passed. WPTs with an expiration time unreasonably
 far in the future SHOULD be rejected.
* The `wth` claim is present and matches the hash of the token value conveyed in the `Workload-Identity-Token` header.
* Optionally, check that the value of the `jti` claim has not been used before in the time window in which the
 respective WPT would be considered valid.
* If presented in conjunction with an OAuth access token, the value of the `ath` claim matches the hash of that token's value.
* If presented in conjunction with a Txn-Token, the value of the `tth` claim matches the hash of that token's value.
* If presented in conjunction with a token conveying end-user identity or authorization context, the value of
 the `oth` claim matches the hash of that token's value.



## Option 2: Authentication Based on HTTP Message Signatures {#http-sig-auth}

This option uses the WIMSE Identity Token ({{to-wit}}) to sign the request and optionally, the response.
This section defines a profile of the Message Signatures specification {{!RFC9421}}.

The request is signed as per {{RFC9421}}. The following derived components MUST be signed:

* `@method`
* `@request-target`

In addition, the following request headers MUST be signed when they exist:

* `Content-Type`
* `Content-Digest`
* `Authorization`
* `Txn-Token` {{?I-D.ietf-oauth-transaction-tokens}}
* `Workload-Identity-Token`

If the response is signed, the following components MUST be signed:

* `@status`
* `@method;req`
* `@request-target;req`
* `Content-Type` if it exists
* `Content-Digest` if it exists
* `Workload-Identity-Token`

For both requests and responses, the following signature parameters MUST be included:

* `created`
* `expires` - expiration MUST be short, e.g. on the order of minutes. The WIMSE architecture will provide separate
mechanisms in support of long-lived compute processes.
* `nonce`
* `tag` - the value for implementations of this specification is `wimse-workload-to-workload`

Since the signing key is sent along with the message, the `keyid` parameter SHOULD NOT be used.

It is RECOMMENDED to include only one signature with the HTTP message.
If multiple ones are included, then the signature label included in both the `Signature-Input` and `Signature` headers SHOULD
be `wimse`.

A sender MUST ensure that each nonce it generates is unique, at least among messages sent to the same recipient.
To detect message replays,
a recipient MAY reject a message (request or response) if a nonce is repeated.

To promote interoperability, the `ecdsa-p256-sha256` signing algorithm MUST be implemented
by general purpose implementations of this document.

<cref>OPEN ISSUE: do we use the Accept-Signature field to signal that the response must be signed?</cref>

Following is a non-normative example of a signed request and a signed response,
where the caller is using the keys specified in {{example-caller-jwk}}.

~~~ http
{::include includes/sigs-request.txt.out}
~~~
{: title="Signed Request"}

Assuming that the workload being called has the following keypair:

~~~ jwk
{
 "kty":"OKP",
 "crv":"Ed25519",
 "x":"CfaY1XX-aHJpenRP8ATm3yGlbcKA_treqOfwKrilwyg",
 "d":"fycSKS-iHZ6TC1BNwN6cE0sOBP3-4KgR-eqxNpnyhws"
}
~~~
{: title="Callee Private Key"}

A signed response would be:

~~~ http
{::include includes/sigs-response.txt.out}
~~~
{: title="Signed Response"}

## Comparing the DPoP Inspired Option with Message Signatures {#app-level-comparison}

The two workload protection options have different strengths and weaknesses regarding implementation
complexity, extensibility, and security.
Here is a summary of the main differences between
{{dpop-esque-auth}} and {{http-sig-auth}}.

- The DPoP-inspired solution is less HTTP-specific, making it easier to adapt for
other protocols beyond HTTP. This flexibility is particularly valuable for
asynchronous communication scenarios, such as event-driven systems.

- Message Signatures, on the other hand, benefit from an existing HTTP-specific RFC with
some established implementations. This existing groundwork means that this option could
be simpler to deploy, to the extent such implementations are available and easily integrated.

- Given that the WIT (Workload Identity Token) is a type of JWT, the
DPoP-inspired approach that also uses JWT is less complex and technology-intensive than Message
Signatures. In contrast, Message Signatures introduce an additional layer of
technology, potentially increasing the complexity of the overall system.

- Message Signatures offer superior integrity protection, particularly by mitigating
message modification by middleboxes. See also {{middleboxes}}.

- A key advantage of Message Signatures is that they support response signing.
This opens up the possibility for future decisions about whether to make
response signing mandatory, allowing for flexibility in the specification
and/or in specific deployment scenarios.

- In general, Message Signatures provide greater flexibility compared to
the DPoP-inspired approach. Future versions of this draft (and subsequent implementations) can decide
whether specific aspects of message signing, such as coverage of particular fields,
should be mandatory or optional. Covering more fields will constrain the proof
so it cannot be easily reused in another context, which is often a security improvement. The DPoP inspired approach could
be designed to include extensibility to sign other fields, but this would make it closer to
trying to reinvent Message Signatures.

## Coexistence with JWT Bearer Tokens {#coexist}

The WIT and WPT define new HTTP headers. They can therefore be presented along with existing headers used for JWT bearer tokens. This
property allows for transition from mechanisms using identity tokens based on bearer JWTs to proof of possession based WITs.
A workload may implement a policy that accepts both bearer tokens and WITs during a transition period. This policy may be configurable
per-caller to allow the workload to reject bearer tokens from callers that support WITs. Once a deployment fully supports WITs, then the use of
bearer tokens for identity can be disabled through policy.  Implementations should be careful when implementing such a transition strategy,
since the decision which token to prefer is made when the caller's identity has still not been authenticated, and needs to be revalidated following the authentication step.

The WIT can also coexist with tokens used to establish security context, such as transaction tokens {{?I-D.ietf-oauth-transaction-tokens}}. In this case a workload's
authorization policy may take into account both the sending workload's identity and the information in the context token. For example, the
identity in the WIT may be used to establish which API calls can be made and information in the context token may be used to determine
which specific resources can be accessed.

# Using Mutual TLS for Workload To Workload Authentication {#mutual-tls}

As noted in the introduction, for many deployments, transport-level protection
of application traffic using TLS is ideal.

In this solution, the WIMSE workload identity may be carried within an X.509 certificate.
The WIMSE workload identity MUST be encoded in a SubjectAltName extension of type URI.
There MUST be only one SubjectAltName extension of type URI in a WIMSE certificate.
If the workload will act as a TLS server for clients that do not understand WIMSE workload
identities it is RECOMMENDED that the WIMSE certificate contain a SubjectAltName of type
DNSName with the appropriate DNS names for the server.
The certificate may contain SubjectAltName extensions of other types.

WIMSE certificates may be used to authenticate both the server and client side of the connections.  When validating a WIMSE certificate, the relying party MUST use the trust anchors configured for the trust domain in the WIMSE identity to validate the peer's certificate.  Other PKIX {{!RFC5280}} path validation rules apply. WIMSE clients and servers MUST validate that the trust domain portion of the WIMSE certificate matches the expected trust domain for the other side of the connection.

Servers wishing to use the WIMSE certificate for authorizing the client MUST require client certificate authentication in the TLS handshake. Other methods of post handshake authentication are not specified by this document.

WIMSE server certificates SHOULD have the `id-kp-serverAuth` extended key usage {{!RFC5280}} field set and WIMSE client certificates SHOULD have the `id-kp-clientAuth` extended key usage field set. A certificate that is used for both client and server connections may have both fields set. This specification does not make any other requirements beyond {{!RFC5280}} on the contents of WIMSE certificates or on the certification authorities that issue WIMSE certificates.

## Server Name Validation {#server-name}

If the WIMSE client uses a hostname to connect to the server and the server certificate contain a DNS SAN the client MUST perform standard host name validation ({{Section 6.3 of RFC9525}}) unless it is configured with the information necessary to validate the peer's WIMSE identity.
If the client did not perform standard host name validation then the WIMSE client SHOULD further use the WIMSE workload identifier to validate the server.
The host portion of the WIMSE workload identifier is NOT treated as a host name as specified in section 6.4 of {{!RFC9525}} but rather as a trust domain. The server identity is encoded in the path portion of the WIMSE workload identifier in a deployment specific way.
Validating the WIMSE workload identity could be a simple match on the trust domain and path portions of the identifier or validation may be based on the specific details on how the identifier is constructed. The path portion of the WIMSE identifier MUST always be considered in the scope of the trust domain.

## Client Authorization Using the WIMSE Identity {#client-name}

The server application retrieves the WIMSE workload identifier from the client certificate subjectAltName, which in turn is obtained from the TLS layer. The identifier is used in authorization, accounting and auditing.
For example, the full WIMSE workload identifier may be matched against ACLs to authorize actions requested by the peer and the identifier may be included in log messages to associate actions to the client workload for audit purposes.
A deployment may specify other authorization policies based on the specific details of how the WIMSE identifier is constructed. The path portion of the WIMSE identifier MUST always be considered in the scope of the trust domain.

# Security Considerations

## WIMSE Identity

The WIMSE Identifier is scoped within an issuer and therefore any sub-components (path portion of Identifier) are only unique within a trust domain defined by the issuer. Using a WIMSE Identifier without taking into account the trust domain could allow one domain to issue tokens to spoof identities in another domain.  Additionally, the trust domain must be tied to an authorized issuer cryptographic trust anchor through some mechanism such as a JWKS or X.509 certificate chain. The association of an issuer, trust domain and a cryptographic trust anchor MUST be communicated securely out of band.

<cref>TODO: Should there be a DNS name to trust domain mapping defined or some other discovery mechanism?</cref>

## Workload Identity Token and Proof of Possession

The Workload Identity Token (WIT) is bound to a secret cryptographic key and is always presented with a proof of possession as described in {{to-wit}}. The WIT is a general purpose token that can be presented in multiple contexts. The WIT and its PoP are only used in the application-level options, and both are not used in MTLS. The WIT MUST NOT be used as a bearer token. While this helps reduce the sensitivity of the token it is still possible that a token and its proof of possession may be captured and replayed within the PoP's lifetime. The following are some mitigations for the capture and reuse of the proof of possession (PoP):

* Preventing Eavesdropping and Interception with TLS

An attacker observing or intercepting the communication channel can view the token and its proof of possession and attempt to replay it to gain an advantage. In order to prevent this the
token and proof of possession MUST be sent over a secure, server authenticated TLS connection unless a secure channel is provided by some other mechanisms. Host name validation according
to {{mutual-tls}} MUST be performed. The WIT itself is not usable without a proof of possession.

* Limiting Proof of Possession Lifespan

The proof of possession MUST be time limited. A PoP should only be valid over the time necessary for it to be successfully used for the purpose it is needed. This will typically be on the order of minutes.  PoPs received outside their validity time MUST be rejected.

* Limiting Proof of Possession Scope

In order to reduce the risk of theft and replay the PoP should have a limited scope. For example, a PoP may be targeted for use with a specific workload and even a specific transaction to reduce the impact of a stolen PoP. In some cases a workload may wish to reuse a PoP for a period of time or have it accepted by multiple target workloads. A careful analysis is warranted to understand the impacts to the system if a PoP is disclosed allowing it to be presented by an attacker along with a captured WIT.

* Binding to a Timestamp or Nonce

A proof of possession should include information that can be used to uniquely identify it such as a unique timestamp or nonce.  This can be used by the receiver to perform basic replay protection against tokens it has already seen. Depending upon the design of the system it may be difficult to synchronize the replay cache across all token validators. In this case, if the PoP is not sufficiently scoped it may be usable with another workload.
While a fresh nonce could be included in the PoP, a mechanism for distributing a fresh challenge nonce from the validator to provide single use properties of a PoP is outside the scope of this specification.

* Binding to TLS Endpoint

The POP MAY be bound to a transport layer sender such as the client identity of a TLS session or TLS channel binding parameters. The mechanisms for binding are outside the scope of this specification.

## Middle Boxes {#middleboxes}

In some deployments the WIMSE token and proof of possession may pass through multiple systems. The communication between the systems is over TLS, but the token and PoP are available in the clear at each intermediary.  While the intermediary cannot modify the token or the information within the PoP they can attempt to capture and replay the token or modify the data not protected by the PoP. Mitigations listed in the previous section can be used to provide some protection from middle boxes. Deployments should perform analysis on their situation to determine if it is appropriate to trust and allow traffic to pass through a middle box.

## Privacy Considerations

WITs and the proofs of possession may contain private information such as user names or other identities. Care should be taken to prevent the disclosure of this information. The use of TLS helps protect the privacy of WITs and proofs of possession.

WITs and certificates with WIMSE identifiers are typically associated with a workload and not a specific user, however in some deployments the workload may be associated directly to a user. While these are exceptional cases a deployment should evaluate if the disclosure of WITs or certificates can be used to track a user.


# IANA Considerations

TODO: maybe a URI Scheme registration of `wimse` in [URI schemes](https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml) per {{?RFC7595}} but it's only being used in an example right now and might not even be appropriate. Or maybe use an ietf URI scheme a la [URN Namespace for IETF Use](https://www.iana.org/assignments/params/params.xhtml) somehow. Or maybe nothing. Or maybe something else.

TODO: `tth`, `wth` and maybe `oth` claim in [JSON Web Token Claims Registry](https://www.iana.org/assignments/jwt/jwt.xhtml)

## Media Type Registration

TODO: `application/wimse-id+jwt` or appropriately bikeshedded media type name (despite my ongoing unease with using media types for typing JWTs) in [Media Types](https://www.iana.org/assignments/media-types/media-types.xhtml).

TODO: `application/wimse-proof+jwt` ...

## Hypertext Transfer Protocol (HTTP) Field Name Registration

TODO: `Workload-Identity-Token` from {{wit-http-header}}

TODO: `Workload-Proof-Token` from {{dpop-esque-auth}}

--- back

# Document History
<cref>RFC Editor: please remove before publication.</cref>

## latest

* Make `iss` claim in WIT optional and add wording about its relation to key distribution.
* Remove `iss` claim from WPT.
* Make `jti` claim in WIT optional.

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
