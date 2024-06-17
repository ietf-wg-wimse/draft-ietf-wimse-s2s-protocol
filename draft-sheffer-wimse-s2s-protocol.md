---
title: "WIMSE Service to Service Authentication"
abbrev: "WIMSE S2S Auth"
category: std

docname: draft-sheffer-wimse-s2s-protocol-latest
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
  github: "yaronf/wimse-s2s"
  latest: "https://yaronf.github.io/wimse-s2s/draft-sheffer-wimse-s2s-protocol.html"

author:
 -
    fullname: "Brian Campbell"
    organization: "Ping Identity"
    email: bcampbell@pingidentity.com
 -
    fullname: "Daniel Feldman"
 -
    fullname: "Joe Salowey"
    organization: Venafi
    email: joe.salowey@gmail.com
 -
    fullname: "Arndt Schwenkschuster"
    organization: Microsoft
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
  IANA.JOSE.ALGS:
    target: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
    title: JSON Web Signature and Encryption Algorithms


--- abstract

TODO Abstract


--- middle

# Introduction

This document defines authentication and authorization in the context of interaction between two workloads.
This is the core component of the WIMSE architecture {{?I-D.ietf-wimse-arch}}.
Assume that Service A needs to call Service B. For simplicity, this document focuses on HTTP-based services,
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

# Application Level Service To Service Authentication {#app-level}

As noted in the Introduction, there are commonly deployments where communication between workloads cannot use
end-to-end TLS. For these deployment styles, this document proposes application-level protections.

The current version of the document includes two alternatives, both using the newly introduced
Workload Identity Token {{to-wit}}. The first alternative {{dpop-esque-auth}} is inspired by the OAuth DPoP specification.
The second {{http-sig-auth}} is based on the HTTP Message Signatures RFC. We present both alternatives and expect
the working group to select one of them as this document progresses towards IETF consensus.

## The Workload Identity Token {#to-wit}

The Workload Identity Token (WIT) is a JWS {{RFC7515}} signed JWT {{RFC7519}} that represents the identity of a workload.
It is issued by the Identity Server and binds a public key to the workload identity.
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
    * `cnf`: A confirmation claim containing the public key of the workload using the `jwk` member as defined in {{Section 3.2 of RFC7800}}.
     The workload MUST prove possession of the corresponding private key when presenting the WIT to another party, which can be accomplished by using it in conjunction with one of the methods in {{dpop-esque-auth}} or {{http-sig-auth}}. As such, it MUST NOT be used as a bearer token and is not intended for use in the `Authorization` header.

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
{: title="Example Workload's Key"}

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

The following shows the WIT from the {{example-wit}} in an example of a `Workload-Identity-Token` header field:

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

## Option 2: Authentication Based on HTTP Message Signatures {#http-sig-auth}

This option uses the WIMSE Identity Token (ref TBD) to sign the request and optionally, the response.
This specification defines a profile of the Message Signatures specification {{!RFC9421}}.

The request is signed as per {{RFC9421}}. The following derived components MUST be signed:

* `@method`
* `@request-target`

In addition, the following headers MUST be signed when they exist:

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
by general purpose implementations of this spec.

OPEN ISSUE: do we use the `Accept-Signature` field to signal that the response must be signed?

Following is a non-normative example of a signed request and a signed response, using the keys mentioned in Section TBD.

~~~ http
GET /gimme-ice-cream?flavor=vanilla HTTP/1.1
Host: example.com
Signature: wimse=:K4dfGnguF5f1L4DKBSp5XeFXosLGj8Y9fiUX06rL/wdOF+x3zTWmsvKWiY0B1oFZaOtm2FHru+YLjdkqa2WfCQ==:
Signature-Input: wimse=("@method" "@request-target" "workload-identity-token");created=1718291357;expires=1718291657;nonce="abcd1111";tag="wimse-service-to-service"
Workload-Identity-Token: aGVhZGVyCg.VGhpcyBpcyBub3QgYSByZWFsIHRva2VuLgo.c2lnbmF0dXJlCg

~~~

Assuming that the workload being called has the following keypair:

~~~ jwk
{
 "kty":"OKP",
 "crv":"Ed25519",
 "x":"CfaY1XX-aHJpenRP8ATm3yGlbcKA_treqOfwKrilwyg",
 "d":"fycSKS-iHZ6TC1BNwN6cE0sOBP3-4KgR-eqxNpnyhws"
}
~~~

A signed response would be:

~~~ http
HTTP/1.1 404 Not Found
Connection: close
Content-Digest: sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:
Content-Type: text/plain
Signature: wimse=:NMrMn3xhI6m9PI8mKVfpnH5qFGcEfuFxiCmsB5PJhGjUHT/5J4612EZwRw3V4kU4gGJmO+ER8RC4DM2HKVOYDQ==:
Signature-Input: wimse=("@status" "workload-identity-token" "content-type" "content-digest" "@method";req "@request-target";req);created=1718295368;expires=1718295670;nonce="abcd2222";tag="wimse-service-to-service"
Workload-Identity-Token: aGVhZGVyCg.VGhpcyBhaW4ndCBvbmUsIHRvby4K.c2lnbmF0dXJlCg

No ice cream today.

~~~

# Using Mutual TLS for Service To Service Authentication {#mutual-tls}

# Security Considerations

TODO Security and Privacy

TLS trust assumptions, server vs mutual auth, middleboxes

# IANA Considerations

TODO IANA

TODO: maybe a URI Scheme registration of `wimse` in [URI schemes](https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml) per {{?RFC7595}} but it's only being used in an example right now and might not even be appropriate. Or maybe use an ietf URI scheme a la [URN Namespace for IETF Use](https://www.iana.org/assignments/params/params.xhtml) somehow. Or maybe nothing. Or maybe something else.


## Media Type Registration

TODO: `application/wimse-id+jwt` or appropriately bikeshedded media type name (despite my ongoing unease with using media types for typing JWTs) in [Media Types](https://www.iana.org/assignments/media-types/media-types.xhtml).

## Hypertext Transfer Protocol (HTTP) Field Name Registration

TODO: `Workload-Identity-Token` from {{wit-http-header}}

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
