%%%
    Title = "DNS Zone Transfer over TLS"
    abbrev = "XFR over TLS"
    category = "std"
    docName= "draft-hzpa-dprive-xfr-over-tls-00"
    ipr = "trust200902"
    area = "Internet"
    workgroup = "dprive"
    keyword = ["DNS", "operations", "privacy"]
    date = 2019-03-11T00:00:00Z
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
opportunity to collect the content of a zone by eavesdropping on links. The DNS
Transaction Signature (TSIG) is specified to restrict direct zone transfer to
authorized clients, but it does not add confidentiality. This document specifies
use of TLS to prevent zone collection

{mainmatter}

# Introduction

DNS has a number of privacy vulnerabilities, as discussed in detail in
[@!I-D.bortzmeyer-dprive-rfc7626-bis]. Query privacy has received the most attention. There are now
standards for three encryption capabilities for queries and more work going on
to guide deployment [@!RFC7858] [@!RFC8484].

[@!RFC7626] established that the query transactions are not public and needed
protection, but on zone transfer it says only: Privacy risks for the holder of a
zone (the risk that someone gets the data) are discussed in [@!RFC5936] and
[@!RFC5155].

In what way is exposing the full content of a zone a privacy risk?  
The contents of the zone could include information such as names
of persons used in names of hosts.  Best practice is not to use personal
information for domain names, but many such domain names exist.  There
may also be regulatory or other reasons why the zone content in full must be
treated as private. 

Neither of the RFCs mentioned by RFC7626 contemplates the risk that someone
gets the data through link eavesdropping.  

[@!RFC5155] 
specifies NSEC3 to prevent zone enumeration, which is when queries for the 
authenticated denial of existences records of DNSSEC allow a client to 
walk through the entire zone.   Note that the need for
this protection also motivates NSEC5; zone walking is now possible with NSEC3
due to crypto-breaking advances, and NSEC5 is a response to this problem.

[@!RFC5155] does not address data obtained outside zone enumeration (nor does
NSEC5). Preventing eavesdropping of zone transfers (this draft) is orthogonal to
preventing zone enumeration, though they aim to protect the same information.

[@!RFC5936] specifies using TSIG [@!RFC2845] for authorization of the clients of
a zone transfer and for data integrity, but does not express any need for
confidentiality, and TSIG does not offer encryption. Some operators use SSH
tunneling or IPSEC to encrypt the transfer data. Because the AXFR zone transfer
is carried out over TCP from DNS protocol implementations, encrypting AXFR using
DNS over TLS [@!RFC7858], aka DOT, seems like a simple step forward. This
document specifies how to use DOT to prevent zone collection from zone
transfers, including discussion of approaches for IXFR, which uses UDP or TCP.

Next steps: work on questions at DNS table during Hackathon, expand this draft, then solicit discussion on
the DPRIVE mailing list.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [@!RFC2119] and
[@!RFC8174] when, and only when, they appear in all capitals, as shown here.

Privacy terminology is as described in Section 3 of [@!RFC6973].

DNS terminology is as described in [@!RFC8499].

# Zone Transfer Confidentiality Overview

# Zone Transfer with DOT - Authentication

## TSIG

## Mutual TLS 

# Session Establishment and Closing

## AXFR Sessions

The connection flow in AXFR is a NOTIFY from the primary server to the 
secondary server, and then an AXFR request from the secondary to the 
primay after which the data flows.  


The connection for AXFR SHOULD be established using port 853, as specified in
[@!RFC7858]. If there is no response on port 853, the connection MAY be
attempted using port 443.

TODO: diagram of connection flow for AXFR, without and with DOT

## IXFR Sessions (?)

[@!RFC1995] specifies that Incremental Transfer may use UDP
if the entire IXFR response can be contained in 
a single DNS packet, otherwise, TCP is used.

Given this, how should confidentiality of IXFR be provided?  To discuss: 
should IXFR have a mode in which TCP is mandatory?  or should there be an
approach of starting with DNS over DTLS, and switching to DNS over TLS with a
TCP switch?  In workloads where there are frequent IXFRs, is the persistent mode
that TCP-Mode would enable (as well as the retries, a benefit?

## Policies for Both AXFR and IXFR

In order to assure the confidentiality of the zone information, all the servers
(primary and secondary) MUST have a consistent confidentiality use. If any do 
not, this is a weak link for attackers to exploit.  How to do this is TBD. 


The entire group (the primary and all secondaries) MUST have a consistent
policy on Strict or Non-Strict mode of operation.  How to do this is TBD.


## Next Steps


Upcoming open hackathon experiments will feed into this Session
Establishment and Closing section, as much about this needs exploration as well
as dicussion on the mailing list.

# Performance Considerations

The details in [@!RFC7858] about using persistent connections and TLS Session
Resume are fully applicable to DNS Transfer over DOT as well.

# Implementation Considerations

TBA

# IANA Considerations

TBD

# Security Considerations

This document specifies a security measure against a DNS risk, the risk that an
attacker collects entire DNS zones through eavesdropping on plaintext DNS zone
transfers. It presents a new Security Consideration for DNS. Some questions to
discuss are: should DOT in this new case be required to use only TLS1.3 and
higher to avoid residual exposure? How should padding be used (if it should)?

# Acknowledgements

Benno, Shumon, Tim

# Contributors
The following contributed significantly to the document:

# Changelog

draft-hzpa-dprive-xfr-over-tls-00

* Initial commit


{backmatter}
