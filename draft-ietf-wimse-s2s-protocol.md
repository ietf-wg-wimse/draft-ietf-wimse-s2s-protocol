---
title: "WIMSE Service to Service Authentication"
abbrev: "WIMSE S2S Auth"
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
    fullname: "Daniel Feldman"
    organization: "Independent"
    email: dfeldman.mn@gmail.com
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
chain can have some calls use one protocol and some use the other. Service A can call
Service B with mutual TLS authentication, while the next call from Service B to Service C
would be authenticated at the application level.

--- middle

# Introduction

This document defines authentication and authorization in the context of interaction between two workloads.
This is the core component of the WIMSE architecture {{?I-D.ietf-wimse-arch}}.
For simplicity, this document focuses on HTTP-based services,
and the service-to-service call consists of a single HTTP request and its response.
We define the credentials that both services should possess and how they are used to protect the HTTP exchange.

There are multiple deployment styles in use today, and they result in different security properties.
We propose to address them differently.

* Many use cases have various middleboxes inserted between pairs of services, resulting in a transport layer
that is not end-to-end encrypted. We propose to address these use cases by protecting the HTTP messages at the application
level ({{app-level}}).

* The other commonly deployed architecture has a mutual-TLS connection between each pair of services. This setup
can be addressed by a simpler solution ({{mutual-tls}}).

It is an explicit goal of this protocol that a service deployment can include both architectures across a multi-chain call.
In other words, Service A can call Service B with mutual TLS protection,
while the next call to Service C is protected at the application level.

For application-level protection we currently propose two alternative solutions, one inspired by DPoP {{?RFC9449}} in {{dpop-esque-auth}} and
one which is a profile of HTTP Message Signatures {{!RFC9421}} in {{http-sig-auth}}. The design team believes that we need to pick
one of these two alternatives for standardization, once we have understood their pros and cons.

## Deployment Architecture and Message Flow

Regardless of the transport between the workloads, we assume the following logical architecture:

~~~ aasvg
+------------+               +------------+
|            |               |            |
|            |               | Workload B |
| Workload A |==============>|            |
|            |               |   +--------+
|            |               |   |  PEP   |
+------------+               +---+--------+
      ^                        ^     ^
      |                        |     |
      | +----------------------+     |
      | |                            |
      v v                            v
+------------+               +------------+
|            |               |            |
|  Identity  |               |    PDP     |
|   Server   |               | (optional) |
|            |               |            |
+------------+               +------------+
~~~

The Identity Server provisions credentials to each of the workloads. At least Workload A (and possibly both) must be provisioned
with a credential before the call can proceed. Details of communication with the Identity Server are out of scope
of this document, however we do describe the credential received by the workload.

PEP is a Policy Enforcement Point, the component that allows the call to go through or blocks it. PDP is an optional
Policy Decision Point, which may be deployed in architectures where policy management is centralized. All details of
policy management and message authorization are out of scope of this document.

The high-level message flow is as follows:

* Workload A obtains a credential from the Identity Server. This happens periodically, e.g. once every 24 hours.
* Workload A makes an HTTP call into Workload B. This is a regular HTTP request, with the additional protection
mechanisms defined below.
* Workload B now authenticates Workload A and decides whether to authorize the call.
In certain architectures, Workload B may need to consult with an external server to decide whether to accept the call.
* Workload B returns a response to Workload A, which may be an error response or a regular one.

# Conventions and Definitions

This document uses "service" and "workload" interchangeably. Otherwise, all terms are as defined by {{?I-D.ietf-wimse-arch}}.

{::boilerplate bcp14-tagged}

# Workload Identity {#whimsical-identity}

## Trust Domain

A trust domain is a logical grouping of systems that share a common set of security controls and policies. WIMSE certificates and tokens are issued under the authority of a trust domain. Trust domains SHOULD be identified by a fully qualified domain name belonging to the organization defining the trust domain.
A trust domain maps to one or more trust anchors for validating X.509 certificates and a mechanism to securely obtain a JWK Set {{!RFC7517}} for validating WIMSE WIT tokens. This mapping MUST be obtained through a secure mechanism that ensures the authenticity and integrity of the mapping is fresh and not compromised. This secure mechanism is out of scope for this document.

A single organization may define multiple trust domains for different purposes such as different departments or environments. Each trust domain must have a unique identifier. Workload identifiers are scoped within a trust domain. If two identifiers differ only by trust domain they still refer to two different entities.

## Workload Identifier

This document defines a workload identifier as a URI {{!RFC3986}}. This URI is used in the subject fields in the certificates and tokens defined later in this document. The URI MUST meet the criteria for the URI type of Subject Alternative Name defined in Section 4.2.1.6 of {{!RFC5280}}.

>   The name MUST NOT be a relative URI, and it MUST follow the URI syntax and
>   encoding rules specified in {{!RFC3986}}.  The name MUST include both a
>   scheme and a scheme-specific-part.

In addition the URI MUST include an authority that identifies the trust domain within which the identifier is scoped. The trust domain SHOULD be a fully qualified domain name belonging to the organization defining the trust domain to help provide uniqueness for the trust domain identifier. The scheme and scheme specific part are not defined by this specification. An example of an identifier format that conforms to this definition is [SPIFFE ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md).
While the URI encoding rules allow host names to be specified as IP addresses, IP addresses MUST NOT be used to represent trust domains except in the case where they are needed for compatibility with existing naming schemes.


# Application Level Service To Service Authentication {#app-level}

As noted in the Introduction, for many deployments communication between workloads cannot use
end-to-end TLS. For these deployment styles, this document proposes application-level protections.
For deployments using end-to-end TLS, application-level credentials may be used to enrich the
application security context.

The current version of the document includes three alternatives, all using the newly introduced
Workload Identity Token ({{to-wit}}). The first alternative ({{dpop-esque-auth}}) is inspired by the OAuth DPoP specification.
The second alternative ({{http-sig-auth}}) is based on the HTTP Message Signatures RFC. The third
alternative ({{transport-layer-pop}}) is based on the TLS 1.3 and Token Binding RFCs.
We present the alternatives and expect
the working group to select those that should progress towards IETF consensus.
A comparison of the first two alternatives is attempted in {{app-level-comparison}}.

## The Workload Identity Token {#to-wit}

The Workload Identity Token (WIT) is a JWS {{RFC7515}} signed JWT {{RFC7519}} that represents the identity of a workload.
It is issued by the Identity Server and binds a public key or certificate to the workload identity.
A WIT MUST contain the following:

* in the JOSE header:
    * `alg`: An identifier for a JWS asymmetric digital signature algorithm
     (registered algorithm identifiers are listed in the IANA JOSE Algorithms registry {{IANA.JOSE.ALGS}}). The value `none` MUST NOT be used.
    * `typ`: the WIT is explicitly typed, as recommended in {{Section 3.11 of RFC8725}}, using the `wimse-id+jwt` media type.
* in the JWT claims:
    * `iss`: The issuer of the token, which is the Identity Server, represented by a URI.
    * `sub`: The subject of the token, which is the identity of the workload, represented by a URI.
    * `exp`: The expiration time of the token (as defined in {{Section 4.1.4 of RFC7519}}).
      WITs should be refreshed regularly, e.g. on the order of hours.
    * `jti`: A unique identifier for the token.
    * `cnf`: A confirmation claim containing either the public key of the workload OR a the hash of the X.509 certificate of the workload.
        * The `cnf` MAY contain the `jwk` member as defined in {{Section 3.2 of RFC7800}}. The workload MUST prove possession of the corresponding private key when presenting the WIT to another party, which can be accomplished by using it in conjunction with one of the methods in {{dpop-esque-auth}} or {{http-sig-auth}}. As such, it MUST NOT be used as a bearer token and is not intended for use in the `Authorization` header.
        * The `cnf` MAY contain the `x5t#S256` member as defined in [Section 3.1](https://datatracker.ietf.org/doc/html/rfc8705#section-3.1) of [[RFC7805](https://datatracker.ietf.org/doc/html/rfc8705)]. When this value is provided, Proof-of-possession is delegated to the Transport layer using the method described in {{transport-layer-pop}}. The receiving Workload MUST verify that the `x5t#S256` claim matches the SHA-256 hash of the Client's X.509 Certificate presented at the Transport layer.

An example WIT might look like this (all examples, of course, are non-normative and with line breaks and extra space for readability):

~~~ jwt
eyJ0eXAiOiJ3aW1zZS1pZCtqd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6Ikp1bmUgNSJ9.
eyJpc3MiOiJ3aW1zZTovL2V4YW1wbGUuY29tL3RydXN0ZWQtY2VudHJhbC1hdXRob3Jpd
HkiLCJleHAiOjE3MTc2MTI0NzAsInN1YiI6IndpbXNlOi8vZXhhbXBsZS5jb20vc3BlY2
lmaWMtd29ya2xvYWQiLCJqdGkiOiJ4LV8xQ1RMMmNjYTNDU0U0Y3diX18iLCJjbmYiOns
iandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiX2FtUkMzWXJZYkho
SDFSdFlyTDhjU21URE1oWXRPVVRHNzhjR1RSNWV6ayJ9fX0.rOSUMR8I5WhM5C704l3iV
dY0zFqxhugJ8Jo2xo39G7FqUTbwTzAGdpz2lHp6eL1M486XmRgl3uyjj6R_iuzNOA
~~~
{: #example-wit title="An example Workload Identity Token (WIT)"}

The decoded JOSE header of the WIT from the example above is shown here:

~~~ json
{
 "typ": "wimse-id+jwt",
 "alg": "ES256",
 "kid": "June 5"
}
~~~
{: title="Example WIT JOSE Header"}

The decoded JWT claims of the WIT from the example above are shown here:

~~~ json
{
 "iss": "wimse://example.com/trusted-central-authority",
 "exp": 1717612470,
 "sub": "wimse://example.com/specific-workload",
 "jti": "x-_1CTL2cca3CSE4cwb__",
 "cnf": {
  "jwk": {
   "kty": "OKP",
   "crv": "Ed25519",
   "x": "_amRC3YrYbHhH1RtYrL8cSmTDMhYtOUTG78cGTR5ezk"
  }
 }
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
 "kty":"OKP",
 "crv":"Ed25519",
 "x":"_amRC3YrYbHhH1RtYrL8cSmTDMhYtOUTG78cGTR5ezk",
 "d":"G4lGAYFtFq5rwyjlgSIRznIoCF7MtKDHByyUUZCqLiA"
}
~~~
{: #example-caller-jwk title="Example Workload's Key"}

The afore-exampled WIT is signed with the private key of the Identity Server.
The public key(s) of the Identity Server need to be known to all workloads in order to verify the signature of the WIT.
The Identity Server's public key from this example is shown below in JWK {{RFC7517}} format:

~~~ jwk
{
 "kty":"EC",
 "kid":"June 5",
 "x":"kXqnA2Op7hgd4zRMbw0iFcc_hDxUxhojxOFVGjE2gks",
 "y":"n__VndPMR021-59UAs0b9qDTFT-EZtT6xSNs_xFskLo",
 "crv":"P-256"
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
WIT =  base64url "." base64url "." base64url
~~~~
{: #wit-header-abnf title="Workload-Identity-Token Header Field ABNF"}

The following shows the WIT from {{example-wit}} in an example of a `Workload-Identity-Token` header field:

~~~ http-message
Workload-Identity-Token: eyJ0eXAiOiJ3aW1zZS1pZCtqd3QiLCJhbGciOiJFUzI1
 NiIsImtpZCI6Ikp1bmUgNSJ9.eyJpc3MiOiJ3aW1zZTovL2V4YW1wbGUuY29tL3RydXN
 0ZWQtY2VudHJhbC1hdXRob3JpdHkiLCJleHAiOjE3MTc2MTI0NzAsInN1YiI6IndpbXN
 lOi8vZXhhbXBsZS5jb20vc3BlY2lmaWMtd29ya2xvYWQiLCJqdGkiOiJ4LV8xQ1RMMmN
 jYTNDU0U0Y3diX18iLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU
 1MTkiLCJ4IjoiX2FtUkMzWXJZYkhoSDFSdFlyTDhjU21URE1oWXRPVVRHNzhjR1RSNWV
 6ayJ9fX0.rOSUMR8I5WhM5C704l3iVdY0zFqxhugJ8Jo2xo39G7FqUTbwTzAGdpz2lHp
 6eL1M486XmRgl3uyjj6R_iuzNOA
~~~
{: title="An example Workload Identity Token HTTP Header Field"}

Note that per {{RFC9110}}, header field names are case insensitive;
thus, `Workload-Identity-Token`, `workload-identity-token`, `WORKLOAD-IDENTITY-TOKEN`,
etc., are all valid and equivalent header field names. However, case is significant in the header field value.

## Option 1: DPoP-Inspired Authentication {#dpop-esque-auth}

This option, inspired by the OAuth DPoP specification {{?RFC9449}}, uses a DPoP-like mechanism to authenticate
the calling workload in the context of the request. The WIMSE Identity Token ({{to-wit}}) is sent in the request as
described in {{wit-http-header}}. An additional JWT, the Workload Proof Token (WPT), is signed by the private key
corresponding to the public key in the WIT. The WPT is sent in the `Workload-Proof-Token` header field of the request.
A WPT contains the following:

* in the JOSE header:
    * `alg`: An identifier for an appropriate JWS asymmetric digital signature algorithm corresponding to
     the confirmation key in the associated WIT.
    * `typ`: the WPT is explicitly typed, as recommended in {{Section 3.11 of RFC8725}},
     using the `application/wimse-proof+jwt` media type.
* in the JWT claims:
    * `iss`: The issuer of the token, which is the calling workload, represented by the same value as the `sub` claim
     of the associated WIT.
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
HM6Ly9zZXJ2aWNlLmV4YW1wbGUuY29tL3BhdGgiLCJleHAiOjE3Mjg2NTg2NzIsImlzcy
I6IndpbXNlOi8vZXhhbXBsZS5jb20vc3BlY2lmaWMtd29ya2xvYWQiLCJqdGkiOiI0YjQ
yYzVmNjExZTJiMWNmYTFkMmM0MWIzYTJmYjc4MiIsInd0aCI6Ii1KaThUbE1ORmszcW16
bXBBeEJPXzdXLVl1dGNIXzJfZnVGQUZGU1YxUmcifQ.jrUBsDjWMG_FpuhLo3lNC-IBei
PQXZ4UOuttPdNj8fRmIG4ZDFF9B10y7uGbiNIhbRdpgG_KXEPLHXWnvzLmBA
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
  "aud": "https://service.example.com/path",
  "exp": 1728658672,
  "iss": "wimse://example.com/specific-workload",
  "jti": "4b42c5f611e2b1cfa1d2c41b3a2fb782",
  "wth": "-Ji8TlMNFk3qmzmpAxBO_7W-YutcH_2_fuFAFFSV1Rg"
}
~~~
{: title="Example WPT Claims"}

An example of an HTTP request with both the WIT and WPT from prior examples is shown below:

~~~ http-message
POST /path HTTP/1.1
Host: service.example.com
Content-Type: application/json
Authorization: Bearer 16_mAd0GiwaZokU26_0902100
Workload-Identity-Token: eyJ0eXAiOiJ3aW1zZS1pZCtqd3QiLCJhbGciOiJFUzI1
  NiIsImtpZCI6Ikp1bmUgNSJ9.eyJpc3MiOiJ3aW1zZTovL2V4YW1wbGUuY29tL3RydX
  N0ZWQtY2VudHJhbC1hdXRob3JpdHkiLCJleHAiOjE3MTc2MTI0NzAsInN1YiI6Indpb
  XNlOi8vZXhhbXBsZS5jb20vc3BlY2lmaWMtd29ya2xvYWQiLCJqdGkiOiJ4LV8xQ1RM
  MmNjYTNDU0U0Y3diX18iLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkV
  kMjU1MTkiLCJ4IjoiX2FtUkMzWXJZYkhoSDFSdFlyTDhjU21URE1oWXRPVVRHNzhjR1
  RSNWV6ayJ9fX0.rOSUMR8I5WhM5C704l3iVdY0zFqxhugJ8Jo2xo39G7FqUTbwTzAGd
  pz2lHp6eL1M486XmRgl3uyjj6R_iuzNOA
Workload-Proof-Token: eyJhbGciOiJFZERTQSIsInR5cCI6IndpbXNlLXByb29mK2p
  3dCJ9.eyJhdGgiOiJDTDR3amZwUm1OZi1iZFlJYllMblY5ZDVyTUFSR3dLWUUxMHdVd
  3pDMGpJIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2aWNlLmV4YW1wbGUuY29tL3BhdGgiLCJl
  eHAiOjE3Mjg2NTg2NzIsImlzcyI6IndpbXNlOi8vZXhhbXBsZS5jb20vc3BlY2lmaWM
  td29ya2xvYWQiLCJqdGkiOiI0YjQyYzVmNjExZTJiMWNmYTFkMmM0MWIzYTJmYjc4Mi
  IsInd0aCI6Ii1KaThUbE1ORmszcW16bXBBeEJPXzdXLVl1dGNIXzJfZnVGQUZGU1YxU
  mcifQ.jrUBsDjWMG_FpuhLo3lNC-IBeiPQXZ4UOuttPdNj8fRmIG4ZDFF9B10y7uGbi
  NIhbRdpgG_KXEPLHXWnvzLmBA

{"do stuff":"please"}
~~~
{: title="Example HTTP Request with WIT and WPT"}

To validate the WPT in the request, the recipient MUST ensure the following:

* There is exactly one `Workload-Proof-Token` header field in the request.
* The `Workload-Proof-Token` header field value is a single and well-formed JWT.
* The WPT signature is valid using the public key from the confirmation claim of the WIT.
* The `typ` JOSE header parameter of the WPT conveys a media type of `wimse-proof+jwt`.
* The `iss` claim of the WPT matches the `sub` claim of the WIT. (Note: not sure `iss` in the WPT is useful or necessary.)
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
* `tag` - the value for implementations of this specification is `wimse-service-to-service`

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
{::include includes/sigs-request.out}
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
{::include includes/sigs-response.out}
~~~
{: title="Signed Response"}

## Option 3: Authentication Based on the Transport Layer {#transport-layer-pop}

This option provides authentication of the WIT using Transport Layer credentials. The proof-of-possession for the Workload's Private Key is provided in the WIT via a cryptographically strong hash that MUST match the Transport Layer mutual authentication credential. The cryptographically strong hash binds the WIT to a particular Transport Layer certificate credential, so that it cannot be replayed without proof of the corresponding Workload Private Key.

When an Application receives a Certificate-bound WIT, it MUST treat the WIT as a JWT bound to an X.509 certificate in the manner described in [Section 3.1](https://datatracker.ietf.org/doc/html/rfc8705#section-3.1) of [[RFC8705](https://datatracker.ietf.org/doc/html/rfc8705)]. To authenticate a Certificate-bound WIT using the Transport Layer, Workload-to-Workload communication MUST be secured by Mutually-authenticated [Transport Layer Security 1.3](https://datatracker.ietf.org/doc/html/rfc8446#section-2) (TLS 1.3). Proof-of-possession MUST be conveyed via each Workload's `CertificateVerify` message. In this case, each network peer MUST validate its Peer's Proof-of-possession of the Private Key. Proof-of-possession is conveyed during the TLS 1.3 handshake protocol using each peer's `Certificate` and `CertificateVerify` messages. The Transport Layer MUST cache the SHA-256 hash of the validated Client Certificate in the TLS session, for use at the Application Layer. When the Destination Workload receives a WIT at the Application Layer with `cnf` claim with `x5t#S256` property, it MUST establish Proof-of-possession as follows:

* Validate that the Certificate-bound WIT's `cnf` claim's `x5t#S256` property matches the cached SHA-256 hash of the validated Client Certificate used at the Transport layer.

This ensures that the WIT can only be used by a client with access to the Workload's Private Key.

## Comparing the DPoP Inspired Option with Message Signatures and TLS Authentication {#app-level-comparison}

<cref>
This section is temporarily part of the draft, while we expect the working group
to select among these options.
</cref>

The three workload protection options have different strengths and weaknesses regarding implementation
complexity, extensibility, and security.
Here is a summary of the main differences between
{{dpop-esque-auth}} and {{http-sig-auth}}.

- The DPoP-inspired and TLS authentcation options are less HTTP-specific, making them easier to adapt for
other protocols beyond HTTP. This flexibility is particularly valuable for
asynchronous communication scenarios, such as event-driven systems.

- Message Signatures, on the other hand, benefit from an existing HTTP-specific RFC with
some established implementations. This existing groundwork means that this option could
be simpler to deploy, to the extent such implementations are available and easily integrated.

- Given that the WIT (Workload Identity Token) is a type of JWT, the
DPoP-inspired approach that also uses JWT is less complex and technology-intensive than Message
Signatures. In contrast, Message Signatures introduce an additional layer of
technology, potentially increasing the complexity of the overall system.

- Message Signatures and TLS Authentication offer superior integrity protection, particularly by mitigating
message modification by middleboxes. See also {{middleboxes}}.

- A key advantage of Message Signatures and TLS Authentication with AES-GCM is that they support response signing.
This opens up the possibility for future decisions about whether to make
response signing mandatory, allowing for flexibility in the specification
and/or in specific deployment scenarios.

- In general, Message Signatures and TLS Authentication provide greater flexibility compared to
the DPoP-inspired approach. For Message Signatures, future versions of this draft (and subsequent implementations) can decide
whether specific aspects of message signing, such as coverage of particular fields,
should be mandatory or optional. Covering more fields will constrain the proof
so it cannot be easily reused in another context, which is often a security improvement. For TLS Authentication with AES-GCM,
all messages are integrity-protected. The DPoP inspired approach could
be designed to include extensibility to sign other fields, but this would make it closer to
trying to reinvent Message Signatures.

# Using Mutual TLS for Service To Service Authentication {#mutual-tls}

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

If the WIMSE client uses a hostname to connect to the server and the server certificate contain a DNS SAN the client MUST perform standard host name validation ({{Section 6.3 of RFC9525}}) unless it is configured with the information necessary to validate the peer's WIMSE identity. If the client did not perform standard host name validation then the WIMSE client SHOULD further use the WIMSE workload identifier to validate the server.  The host portion of the WIMSE URI is NOT treated as a host name as specified in section 6.4 of {{!RFC9525}} but rather as a trust domain. The server identity is encoded in the path portion of the WIMSE workload identifier in a deployment specific way. Validating the WIMSE workload identity could be a simple match on the trust domain and path portions of the identifier or validation may be based on the specific details on how the identifier is constructed. The path portion of the WIMSE identifier MUST always be considered in the scope of the trust domain.

## Client Authorization Using the WIMSE Identity {#client-name}

The server application retrieves the client certificate WIMSE URI subjectAltName from the TLS layer for use in authorization, accounting and auditing.  For example, the full WIMSE URI may be matched against ACLs to authorize actions requested by the peer and the URI may be included in log messages to associate actions to the client workload for audit purposes. A deployment may specify other authorization policies based on the specific details of how the WIMSE identifier is constructed. The path portion of the WIMSE identifier MUST always be considered in the scope of the trust domain.

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

<cref>TODO acknowledge.</cref>

Contributors

* Ken McCracken, Google, kenmccracken@google.com
