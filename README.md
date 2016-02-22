PASN1
=====

This is a simple library for doing marshalling of python objects that
uses a profile/subset of ASN.1.  This library is not designed to be a
general ASN.1 parser, but designed to be super simple to use, and
secure.

The following python types are supported: bool, int (and long), bytes,
null (as None), float, unicode, datetime, list, set and dict.  If you
need to serialize other types/instances, a coerce function maybe
provided which is required to return the above string and an object
implementing the correct methods.  See the ASN1Coder's __init__
method's doc string for more information.

ASN.1 has a number of different types of strings, but only UTF8String
is used by this library.  In order to support dict types, it uses the
Private Constructed type 0.  The contents are pairs of key value objects.
bytes (aka str in Python 2) is mapped to the octet string type.  The
minimal encoding is used so that the same data will be encoded as the
same string, similar to the ASN.1 DER encoding.
