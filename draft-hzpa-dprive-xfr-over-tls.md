%%%
    Title = "DNS Zone Transfer over TLS"
    abbrev = "XFR over TLS"
    category = "std"
    docName= "draft-hzpa-dprive-xfr-over-tls-02"
    ipr = "trust200902"
    area = "Internet"
    workgroup = "dprive"
    keyword = ["DNS", "operations", "privacy"]
    date = 2019-07-02T00:00:00Z
    [pi]
    [[author]]
     initials="H."
     surname="Zhang"
     fullname="Han Zhang"
     organization = "Salesforce"
       [author.address]
       email = "hzhang@salesforce.com"
       [author.address.postal]
       city = "San Francisco, CA"
       country = "United States"
   [[author]]
    initials="P."
    surname="Aras"
    fullname="Pallavi Aras"
    organization = "Salesforce"
      [author.address]
      email = "paras@salesforce.com"
      [author.address.postal]
      city = "Herndon, VA"
      country = "United States"
    toc = "yes"
    compact = "yes"
    symrefs = "yes"
    sortrefs = "yes"
    subcompact = "no"
    [[author]]
     initials="W."
     surname="Toorop"
     fullname="Willem Toorop"
     organization = "NLnet Labs"
       [author.address]
       email = "willem@nlnetlabs.nl"
       [author.address.postal]
       streets = ["Science Park 400"]
       city = "Amsterdam"
       code = "1098 XH"
       country = "The Netherlands"
    [[author]]
    initials="S."
    surname="Dickinson"
    fullname="Sara Dickinson"
    organization = "Sinodun IT"
      [author.address]
      email = "sara@sinodun.com"
      [author.address.postal]
      streets = ["Magdalen Centre", "Oxford Science Park"]
      city = "Oxford"
      code = "OX4 4GA"
      country = "United Kingdom"
    [[author]]
     initials="A."
     surname="Mankin"
     fullname="Allison Mankin"
     organization = "Salesforce"
       [author.address]
       email = "allison.mankin@gmail.com"
       [author.address.postal]
       city = "Herndon, VA"
       country = "United States"
%%%

.# Abstract

DNS zone transfers are transmitted in clear text, which gives attackers the
opportunity to collect the content of a zone by eavesdropping on network
connections. The DNS Transaction Signature (TSIG) mechanism is specified to
restrict direct zone transfer to authorized clients only, but it does not add
confidentiality. This document specifies use of DNS-over-TLS to prevent zone
contents collection via passive monitoring of zone transfers.

{mainmatter}

# Introduction

DNS has a number of privacy vulnerabilities, as discussed in detail in
[@!I-D.bortzmeyer-dprive-rfc7626-bis]. Stub client to recursive resolver query
privacy has received the most attention to date. There are now standards track
documents for three encryption capabilities for stub to recursive queries and
more work going on to guide deployment of specifically DNS-over-TLS (DoT)
[@!RFC7858] and DNS-over-HTTPS (DoH) [@!RFC8484].

[@!I-D.bortzmeyer-dprive-rfc7626-bis] established that stub client DNS query
transactions are not public and needed protection, but on zone transfer
[@!RFC1995] [@!RFC5936] it says only:

"Privacy risks for the holder of a zone (the risk that someone gets the data)
are discussed in [RFC5936] and [RFC5155]."

In what way is exposing the full contents of a zone a privacy risk? The contents
of the zone could include information such as names of persons used in names of
hosts. Best practice is not to use personal information for domain names, but
many such domain names exist. There may also be regulatory, policy or other
reasons why the zone contents in full must be treated as private.

Neither of the RFCs mentioned in [@!I-D.bortzmeyer-dprive-rfc7626-bis]
contemplates the risk that someone gets the data through eavesdropping on
network connections, only via enumeration or unauthorised transfer as described
in the following paragraphs.

[@!RFC5155] specifies NSEC3 to prevent zone enumeration, which is when queries
for the authenticated denial of existences records of DNSSEC allow a client to
walk through the entire zone. Note that the need for this protection also
motivates NSEC5 [@!I-D.vcelak-nsec5]; zone walking is now possible with NSEC3
due to crypto-breaking advances, and NSEC5 is a response to this problem.

[@!RFC5155] does not address data obtained outside zone enumeration (nor does
[@!I-D.vcelak-nsec5]). Preventing eavesdropping of zone transfers (this draft)
is orthogonal to preventing zone enumeration, though they aim to protect the
same information.

[@!RFC5936] specifies using TSIG [@!RFC2845] for authorization of the clients of
a zone transfer and for data integrity, but does not express any need for
confidentiality, and TSIG does not offer encryption. Some operators use SSH
tunnelling or IPSec to encrypt the transfer data. 

Because the AXFR zone transfer is typically carried out over TCP from
authoritative DNS protocol implementations, encrypting AXFR using DNS-over-TLS
[@!RFC7858] seems like a simple step forward. This document specifies how to use
DoT to prevent zone collection from zone transfers, including discussion of
approaches for IXFR, which uses UDP or TCP.

NOTE: At this point some discussion of a DSO based mechanism is included in
brackets, still to decide whether or not to include this in the -02 version or
not..

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [@!RFC2119] and
[@!RFC8174] when, and only when, they appear in all capitals, as shown here.

Privacy terminology is as described in Section 3 of [@!RFC6973].

DNS terminology is as described in [@!RFC8499].

DoT: DNS-over-TLS as specified in [@!RFC7858]

DoH: DNS-over-HTTPS as specified in [@!RFC8484]

XoT: Generic XFR-over-TLS mechanisms as specified in this document

AXoT: AXFR-over-TLS

IXoT: IXFR over-TLS

# Use cases for XFR-over-TLS

* Confidentiality. Clearly using an encrypted transport for zone transfers will
  defeat zone content leakage that can occur via passive surveillance.

* Authentication. Use of single or mutual TLS authentication (in combination 
  with ACLs) can complement and potentially be an alternative to TSIG.
  
* Performance. Existing AXFR and IXFR mechanisms have the burden of backwards
  compatibility with older implementations based on the original specifications
  in [@RFC1034] and [@RFC1035]. For example, some older AXFR  implementations
  have restrictions that mean use of sessions for multiple XFRs, or XFRs of
  different zones on the same connection, are inefficient or not supported. A
  specification for XFR-over-TLS could require all implementations to implement
  optimised transfers e.g. transfer of multiple zones over one connection. For
  IXFR, when there are very high rates of transfers opting to use persistent
  connections could offer higher throughput rates (is this true?).

* (Security. For some network configurations it is not desirable to have port 53
  on the secondary open to an untrusted network for the sole purpose of
  receiving NOTIFYs. For the DSO case, secondaries could initiate DSO
  connections to the master and following that server-initiated DSO NOTIFY
  messages could be sent on that connection which could simultaneously be used
  for SOA and IXFR requests. This would allow a firewall to be restricted to
  just allowing outgoing connections from secondary to primary. Note that a
  similar but more constrained mechanism exists for IXFR whereby a short refresh
  period can be configured which triggering periodic SOA/IXFR requests from the
  secondary. TODO: Look at the details of the NSD implementation.)

* (Performance. For the DSO case, a new subscribe/publish mechanism could be
  envisaged that greatly reducing the number of messages required to perform one
  transfer.)

* (Improved error handling and retries. In the DSO case new explicit error codes
  could be defined that allow a server to indicate the reason for a failed XFR
  request.)

* (New command channel. For the DSO case it would be possible to include new
  server-initiated 'control' commands e.g. 'stop serving this zone', 'delete
  this zone'.)

# Connection and data flows in existing XFR mechanisms

The original specification for zone transfers in [@RFC1034] and [@RFC1035] was
based on a polling mechanism: a secondary performed a periodic SOA query (based
on the refresh timer) to determine if an AXFR was required.

[@RFC1995] and [@RFC1996] introduced the concepts of IXFR and NOTIFY
respectively, to provide for prompt propagation of zone updates.

[@RFC5936] subsequently refined the specification of AXFR.

In this document we use the phrase "XFR mechanism" to describe the entire set of
message exchanges between a secondary and a master that concludes in a
successful AXFR or IXFR request/response. This set may or may not include

* NOTIFY messages
* SOA queries 
* Fallback from IXFR to AXFR
* Fallback from IXFR-over-UDP to IXFR-over-TCP

The term is used to encompasses the range of permutations that are possible and
is useful to distinguish the 'XFR mechanism' from a single XFR
request/response exchange.

## AXFR mechanism

1. An AXFR is often (but not always) preceded by a NOTIFY (over UDP) from the
primary to the secondary. A secondary may also initiate an AXFR based on a
refresh timer or scheduled/triggered zone maintenance.

2. The secondary will normally (but not always) make a SOA query to the master
to obtain the serial number of the zone held by the master (since UDP NOTIFY
messages can be trivially spoofed).

2. If the master serial is higher than the secondaries serial, the secondary
makes an AXFR request (over TCP) to the primary after which the AXFR data flows
in one or more AXFR responses on the TCP connection.

[@RFC5936] specifies that AXFR must use TCP as the transport protocol but
details that there is no restriction in the protocol that a single TCP session
must be used only for a single AXFR exchange, or even solely for XFRs. For
example, it outlines that the SOA query can also happen on this connection.
However, this can cause interoperability problems with older implementations
that support only the trivial case of one AXFR per connection.

TODO: Detail the limitations in existing AXFR implementations as outlined in [@RFC5936]

INSERT FLOW DIAGRAM 2 ('Traditional AXFR based on timers - outbound only
connections')

INSERT FLOW DIAGRAM 1 ('Traditional AXFR using notify')

## IXFR mechanism

1. An IXFR is normally (but not always) preceded by a NOTIFY (over UDP) from the
primary to the secondary. A secondary may also initiate an IXFR based on a
refresh timer or scheduled/triggered zone maintenance.

2. The secondary will normally make a SOA query to the master to obtain the
serial number of the zone held by the master (since UDP NOTIFY messages can be
trivially spoofed).

3. If the master serial is higher than the secondaries serial, the secondary
makes an IXFR request (over UDP) to the primary after the master sends an IXFR
response.

[@!RFC1995] specifies that Incremental Transfer may use UDP if the entire IXFR
response can be contained in a single DNS packet, otherwise, TCP is used. In
fact is says in non-normative language:

"Thus, a client should first make an IXFR query using UDP."

So there may be a forth step above where the client falls back to IXFR over TCP.
There may also be a forth step where the secondary must fall back to AXFR
because the master does not support IXFR.

INSERT FLOW DIAGRAM 2 ('Traditional IXFR based on notify')

## Data leakage of NOTIFY and SOA message exchanges

This section attempts to presents a rationale for also encrypting the other
messages in the XFR mechanism.

Since the SOA of the zone can be trivially discovered by simply querying the
authoritative server leakage RR of this is not discussed in the following
sections.

### NOTIFY

Unencrypted NOTIFY messages identify configured secondaries on the master.

[@RFC1996] also states: 

"If ANCOUNT>0, then the answer section represents an
  unsecure hint at the new RRset for this <QNAME,QCLASS,QTYPE>.
  
But since the only supported QTYPE for NOTIFY is SOA, this does not pose a
potential leak.

### SOA

QUESTION: No real leakage here?

# Zone Transfer with DoT - Authentication

## TSIG

## Mutual TLS

## ZONEMD

Zone message digest is a mechanism that can be used to verify the content of an 
AXFR. It is complementary the above mechanisms and can be used in conjunction 
with XFR-over-TLS. TODO: Add reference

# Session Establishment and Closing

## AXFR Sessions

The connection for AXFR via DoT SHOULD be established using port 853, as
specified in [@!RFC7858], unless there is mutual agreement between the secondary
and primary to use a port other than port 853 for XFR over TLS.

TODO: Specify usage of connections SOA queries and for multiple concurrent zone transfers.

TODO: diagram of connection flow for AXFR over TLS

## IXFR Sessions

QUESTION: Given this, how should confidentiality of IXFR be provided?  

To discuss:

* should IXFR have a mode in which TCP is mandatory?  
* should IXFR have a mode in which TLS is mandatory? 
* In workloads where there are frequent IXFRs, is the persistent connection mode
that TCP-Mode would enable (as well as the retries) a benefit?

## Policies for Both AXFR and IXFR

In order to assure the confidentiality of the zone information, entire group of
servers involved in XFR (the primary and all secondaries) MUST have a consistent
policy of requiring confidentiality. If any do not, this is a weak link for
attackers to exploit. How to do this is TBD.

Additionally, the entire group of servers involved in XFR (the primary and all
secondaries) MUST have a consistent policy of requiring Strict or Opportunistic
DoT [@!RFC8310]. How to do this is TBD.

## Multi-master configurations

TODO.

# Performance Considerations

The details in [@!RFC7858] and [@!RFC8310] about e.g. using persistent
connections and TLS Session Resumption [@!RFC5077] are fully applicable to DNS
Zone Transfer over DoT as well.

# Implementation Considerations

TBA

# Implementation Status

The 1.9.2 version of
[Unbound](https://github.com/NLnetLabs/unbound/blob/release-1.9.2/doc/Changelog)
includes an option to perform AXFR over TLS (instead of TCP). This enables the
client (secondary) to authenticate the server (master) using PKIX.

# IANA Considerations

TBD

# Security Considerations

This document specifies a security measure against a DNS risk: the risk that an
attacker collects entire DNS zones through eavesdropping on clear text DNS zone
transfers. It presents a new Security Consideration for DNS. Some questions to
discuss are: 

* Should DoT in this new case be required to use only TLS 1.3 and
higher to avoid residual exposure? 
* How should padding be used in IXFR?
* Should there be an option to 'pad' an AXFR response (i.e. a set of AXFR
  responses on a given connection) to hide the zone size?

# Acknowledgements

The authors thank Benno Overeinder, Shumon Huque and Tim Wicinski for review and
discussions.

# Contributors
The following contributed significantly to the document:

# Changelog

draft-hzpa-dprive-xfr-over-tls-01

* Editorial changes, updates to references.

draft-hzpa-dprive-xfr-over-tls-00

* Initial commit


{backmatter}
