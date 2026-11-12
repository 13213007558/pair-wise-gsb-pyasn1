#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import io
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.error import PyAsn1Error
from pyasn1.error import SubstrateUnderrunError
from pyasn1.type import char
from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ


# Each entry is (rule name, non-canonical bytes, schema or None). The same
# bytes are BER-legal but must fail strict DER on both decode paths.
NON_CANONICAL_CASES = (
    ('INTEGER redundant leading 0x00',
     b'\x02\x02\x00\x00', univ.Integer()),
    ('INTEGER redundant leading 0xFF',
     b'\x02\x02\xff\xff', univ.Integer()),
    ('ENUMERATED redundant leading 0x00',
     b'\x0a\x02\x00\x01', univ.Enumerated()),
    ('BOOLEAN TRUE encoded as 0x01',
     b'\x01\x01\x01', univ.Boolean()),
    ('BOOLEAN TRUE encoded as 0x7F',
     b'\x01\x01\x7f', univ.Boolean()),
    ('BIT STRING non-zero unused bits',
     b'\x03\x02\x01\x81', univ.BitString()),
    ('constructed OCTET STRING',
     b'\x24\x06\x04\x01a\x04\x01b', univ.OctetString()),
    ('constructed UTF8String',
     b'\x2c\x06\x0c\x01A\x0c\x01B', char.UTF8String()),
    ('non-minimal length 0x81 0x01',
     b'\x02\x81\x01\x01', univ.Integer()),
    ('non-minimal length 0x82 0x00 0x80',
     b'\x02\x82\x00\x80' + b'\x00' * 128, univ.Integer()),
    ('non-minimal long-form tag (tag 0)',
     b'\x9f\x00\x01\x01',
     univ.Integer().subtype(implicitTag=tag.Tag(
         tag.tagClassContext, tag.tagFormatSimple, 0))),
    ('SET OF out of order',
     b'\x31\x06\x02\x01\x02\x02\x01\x01',
     univ.SetOf(componentType=univ.Integer())),
)

# Cases whose non-universal/implicit tag makes a schemaless decode
# impossible in any codec; these are only compared on the schema path.
SCHEMA_ONLY_CASES = frozenset((
    'non-minimal long-form tag (tag 0)',
))


class StrictDerDifferentialTestCase(BaseTestCase):
    """The same non-canonical bytes: BER accepts, strict DER rejects.

    Every case is exercised without a schema (tag-driven TYPE/TAG path) and,
    where a schema exists, with one (the TYPE_MAP path that historically
    bypassed DER strictness).
    """

    def _assertRejected(self, substrate, kwargs, label):
        try:
            der_decoder.decode(substrate, **kwargs)
        except PyAsn1Error:
            pass
        else:
            assert 0, '%s tolerated non-canonical DER: %s' % (
                label, substrate.hex())

    def testNonCanonicalBytes(self):
        for name, substrate, schema in NON_CANONICAL_CASES:
            # BER control: the encoding is legal under the lenient codec.
            ber_decoder.decode(substrate, asn1Spec=schema)

            # Strict DER rejects on the schema-driven path.
            self._assertRejected(
                substrate, {'asn1Spec': schema}, name + ' (schema)')

            # Strict DER rejects on the schemaless path too, whenever the
            # tag is universally decodable without a schema.
            if name not in SCHEMA_ONLY_CASES:
                self._assertRejected(
                    substrate, {}, name + ' (schemaless)')

    def testStrictDerFalseRestoresLegacyBehavior(self):
        # The historical permissive DER decoder stays reachable per call.
        for name, substrate, schema in NON_CANONICAL_CASES:
            value, tail = der_decoder.decode(
                substrate, asn1Spec=schema, strictDER=False)
            assert value is not None
            assert tail == b''

    def testBerIgnoresStrictDerOption(self):
        # BER must not become strict just because the keyword was supplied:
        # the option only acts on a decoder whose dialect implements it.
        for name, substrate, schema in NON_CANONICAL_CASES:
            value, tail = ber_decoder.decode(
                substrate, asn1Spec=schema, strictDER=True)
            assert tail == b''
            assert value is not None


class StrictDerCanonicalAcceptanceTestCase(BaseTestCase):
    """Canonical encodings still decode under strict mode."""

    CANONICAL_CASES = (
        (b'\x02\x01\x00', univ.Integer()),
        (b'\x02\x01\x80', univ.Integer()),
        (b'\x02\x02\x00\x80', univ.Integer()),
        (b'\x02\x02\xff\x7f', univ.Integer()),
        (b'\x01\x01\xff', univ.Boolean()),
        (b'\x01\x01\x00', univ.Boolean()),
        (b'\x03\x02\x01\x80', univ.BitString()),
        (b'\x03\x02\x00\xff', univ.BitString()),
        (b'\x03\x01\x00', univ.BitString()),
        (b'\x04\x03abc', univ.OctetString()),
        # 128 needs two length octets; 0x81 0x80 is therefore minimal.
        (b'\x04\x81\x80' + b'a' * 128, univ.OctetString()),
        (b'\x31\x06\x02\x01\x01\x02\x01\x02',
         univ.SetOf(componentType=univ.Integer())),
    )

    def testCanonicalBytesAccepted(self):
        for substrate, schema in self.CANONICAL_CASES:
            value, tail = der_decoder.decode(substrate, asn1Spec=schema)
            assert tail == b''
            assert value is not None


class StrictDerTaggedAndNestedTestCase(BaseTestCase):
    """Strictness follows the options channel into nested decodings."""

    def testNonCanonicalIntegerInsideExplicitTag(self):
        explicit = univ.Integer().subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 0))
        substrate = b'\xa0\x04\x02\x02\x00\x00'

        ber_decoder.decode(substrate, asn1Spec=explicit)

        for kwargs in ({}, {'asn1Spec': explicit}):
            try:
                der_decoder.decode(substrate, **kwargs)
            except PyAsn1Error:
                pass
            else:
                assert 0, 'explicit-tag wrapper hid non-canonical INTEGER'

    def testNonCanonicalIntegerInsideImplicitTag(self):
        implicit = univ.Integer().subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 0))
        substrate = b'\x80\x02\x00\x00'

        ber_decoder.decode(substrate, asn1Spec=implicit)

        try:
            der_decoder.decode(substrate, asn1Spec=implicit)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'implicit-tag wrapper hid non-canonical INTEGER'

    def testNonCanonicalChoiceAlternative(self):
        choice = univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('integer', univ.Integer()),
            namedtype.NamedType('boolean', univ.Boolean())))
        substrate = b'\x01\x01\x01'

        ber_decoder.decode(substrate, asn1Spec=choice)

        try:
            der_decoder.decode(substrate, asn1Spec=choice)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'CHOICE hid non-canonical BOOLEAN alternative'

    def testNonCanonicalOpenTypeContents(self):
        open_type = opentype.OpenType('id', {1: univ.Integer()})
        sequence = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('id', univ.Integer()),
            namedtype.NamedType(
                'blob', univ.Any(), openType=open_type)))
        inner = b'\x02\x02\x00\x00'  # non-minimal INTEGER
        body = b'\x02\x01\x01' + inner
        substrate = b'\x30' + bytes([len(body)]) + body

        ber_decoder.decode(
            substrate, asn1Spec=sequence, decodeOpenTypes=True)

        try:
            der_decoder.decode(
                substrate, asn1Spec=sequence, decodeOpenTypes=True)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'open type re-decode bypassed strict DER'

    def testOrderedSetAcceptedBothPaths(self):
        set_spec = univ.Set(componentType=namedtype.NamedTypes(
            namedtype.NamedType('flag', univ.Boolean()),
            namedtype.NamedType('count', univ.Integer())))
        # Tag 0x01 (BOOLEAN) sorts before 0x02 (INTEGER).
        substrate = b'\x31\x06\x01\x01\xff\x02\x01\x01'

        value, tail = der_decoder.decode(substrate)
        assert tail == b''
        value, tail = der_decoder.decode(substrate, asn1Spec=set_spec)
        assert tail == b''

    def testUnorderedSetRejectedBothPaths(self):
        set_spec = univ.Set(componentType=namedtype.NamedTypes(
            namedtype.NamedType('flag', univ.Boolean()),
            namedtype.NamedType('count', univ.Integer())))
        substrate = b'\x31\x06\x02\x01\x01\x01\x01\xff'

        ber_decoder.decode(substrate, asn1Spec=set_spec)

        for kwargs in ({}, {'asn1Spec': set_spec}):
            try:
                der_decoder.decode(substrate, **kwargs)
            except PyAsn1Error:
                pass
            else:
                assert 0, 'unordered SET tolerated: %s' % kwargs


class StrictDerStreamingTestCase(BaseTestCase):
    """Strict rejection preserves the resumable streaming protocol."""

    class AlternatingStream(io.BytesIO):
        block = False

        def read(self, size=-1):
            self.block = not self.block
            if self.block:
                return
            return io.BytesIO.read(self, size)

    def _drive(self, substrate, schema=None):
        iterator = iter(der_decoder.StreamingDecoder(
            self.AlternatingStream(substrate), asn1Spec=schema))
        underruns = 0
        for _ in range(300):
            try:
                obj = next(iterator)
            except PyAsn1Error as exc:
                return 'rejected', underruns, type(exc).__name__
            if isinstance(obj, SubstrateUnderrunError):
                underruns += 1
            else:
                return 'decoded', underruns, type(obj).__name__
        assert 0, 'streaming decoder did not terminate'

    def testCanonicalInputResumesAndDecodes(self):
        outcome, underruns, kind = self._drive(b'\x02\x01\x01', univ.Integer())
        assert outcome == 'decoded'
        assert kind == 'Integer'
        assert underruns > 0

    def testNonCanonicalInputResumesThenRejects(self):
        outcome, underruns, kind = self._drive(
            b'\x02\x02\x00\x00', univ.Integer())
        assert outcome == 'rejected'
        assert kind == 'PyAsn1Error'
        assert underruns > 0

    def testUnorderedSetResumesThenRejects(self):
        set_spec = univ.Set(componentType=namedtype.NamedTypes(
            namedtype.NamedType('flag', univ.Boolean()),
            namedtype.NamedType('count', univ.Integer())))
        outcome, underruns, kind = self._drive(
            b'\x31\x06\x02\x01\x01\x01\x01\xff', set_spec)
        assert outcome == 'rejected'
        assert kind == 'PyAsn1Error'
        assert underruns > 0


class StrictDerLimitsPreservedTestCase(BaseTestCase):
    """The pre-existing decoder limits keep firing under strict mode."""

    def testNestingDepthLimit(self):
        inner = b'\x05\x00'
        for _ in range(200):
            length = len(inner)
            length_bytes = length.to_bytes(
                (length.bit_length() + 7) // 8, 'big')
            inner = (b'\x30' + bytes([0x80 | len(length_bytes)]) +
                     length_bytes + inner)
        try:
            der_decoder.decode(inner)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'nesting depth limit not enforced under strict DER'

    def testTagOctetLimit(self):
        try:
            der_decoder.decode(b'\x1f' + b'\x80' * 21 + b'\x01\x01\x00')
        except PyAsn1Error:
            pass
        else:
            assert 0, 'tag octet limit not enforced under strict DER'

    def testLengthOctetLimit(self):
        try:
            der_decoder.decode(b'\x02\x89\x01' + b'\x00' * 8)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'length octet limit not enforced under strict DER'

    def testOidLeadingZeroOctet(self):
        try:
            der_decoder.decode(b'\x06\x09\x80' + b'\x80' * 7 + b'\x01')
        except PyAsn1Error:
            pass
        else:
            assert 0, 'invalid OID octet tolerated under strict DER'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
