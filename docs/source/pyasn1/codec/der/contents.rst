
Distinguished Encoding Rules
----------------------------

.. autofunction:: pyasn1.codec.der.encoder.encode(value, asn1Spec=None)

.. autofunction:: pyasn1.codec.der.decoder.decode(substrate, asn1Spec=None)

The DER decoder runs in strict DER mode by default: non-canonical encodings
(non-minimal INTEGER or length octets, a BOOLEAN other than ``0x00``/``0xFF``,
non-zero unused BIT STRING bits, constructed string forms, a non-minimal tag,
or an out-of-order SET/SET OF) raise :class:`~pyasn1.error.PyAsn1Error` on
both the schema-driven and schemaless paths, including nested explicit and
implicit tags, CHOICE and open types. Pass ``strictDER=False`` to restore the
historical permissive decode. BER and CER ignore the keyword and retain their
legal lenient behavior.
