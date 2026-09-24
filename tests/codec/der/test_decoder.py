#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest
import io

from tests.base import BaseTestCase

from pyasn1 import error
from pyasn1.type import tag
from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type import univ
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.error import PyAsn1Error


class BitStringDecoderTestCase(BaseTestCase):
    def testShortMode(self):
        assert decoder.decode(
            bytes((3, 127, 6) + (170,) * 125 + (128,))
        ) == (((1, 0) * 501), b'')

    def testIndefMode(self):
        try:
            decoder.decode(
                bytes((35, 128, 3, 2, 0, 169, 3, 2, 1, 138, 0, 0))
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, 'indefinite length encoding tolerated'

    def testDefModeChunked(self):
        try:
            assert decoder.decode(
                bytes((35, 8, 3, 2, 0, 169, 3, 2, 1, 138))
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, 'chunked encoding tolerated'


class OctetStringDecoderTestCase(BaseTestCase):
    def testShortMode(self):
        assert decoder.decode(
            '\004\017Quick brown fox'.encode()
        ) == ('Quick brown fox'.encode(), ''.encode())

    def testIndefMode(self):
        try:
            decoder.decode(
                bytes((36, 128, 4, 15, 81, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110, 32, 102, 111, 120, 0, 0))
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, 'indefinite length encoding tolerated'

    def testChunkedMode(self):
        try:
            decoder.decode(
                bytes((36, 23, 4, 2, 81, 117, 4, 2, 105, 99, 4, 2, 107, 32, 4, 2, 98, 114, 4, 2, 111, 119, 4, 1, 110))
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, 'chunked encoding tolerated'


class BooleanStrictnessDecoderTestCase(BaseTestCase):
    """DER requires the canonical Boolean payload (X.690 11.1) both with
    and without an ASN.1 schema guiding the decoder."""

    def testCanonicalForms(self):
        for asn1Spec in None, univ.Boolean():
            assert decoder.decode(
                bytes((1, 1, 255)), asn1Spec=asn1Spec) == (1, b'')
            assert decoder.decode(
                bytes((1, 1, 0)), asn1Spec=asn1Spec) == (0, b'')

    def testNonCanonicalTrue(self):
        for asn1Spec in None, univ.Boolean():
            try:
                decoder.decode(bytes((1, 1, 1)), asn1Spec=asn1Spec)
            except PyAsn1Error:
                pass
            else:
                assert 0, 'non-canonical Boolean tolerated'


class ConstructedEncodingDecoderTestCase(BaseTestCase):
    """DER prohibits the constructed encoding form of string types
    (X.690 10.2) both with and without an ASN.1 schema guiding
    the decoder."""

    def setUp(self):
        BaseTestCase.setUp(self)

        self.primitiveOctetString = bytes((4, 1, 65))
        self.constructedOctetString = bytes((36, 3, 4, 1, 65))

    def testPrimitiveOctetString(self):
        for asn1Spec in None, univ.OctetString():
            assert decoder.decode(
                self.primitiveOctetString, asn1Spec=asn1Spec) == (b'A', b'')

    def testConstructedOctetString(self):
        for asn1Spec in None, univ.OctetString():
            try:
                decoder.decode(self.constructedOctetString, asn1Spec=asn1Spec)
            except PyAsn1Error:
                pass
            else:
                assert 0, 'constructed OCTET STRING tolerated'

    def testConstructedBitString(self):
        for asn1Spec in None, univ.BitString():
            assert decoder.decode(
                bytes((3, 2, 0, 170)), asn1Spec=asn1Spec
            ) == ((1, 0, 1, 0, 1, 0, 1, 0), b'')

            try:
                decoder.decode(bytes((35, 4, 3, 2, 0, 170)), asn1Spec=asn1Spec)
            except PyAsn1Error:
                pass
            else:
                assert 0, 'constructed BIT STRING tolerated'

    def testConstructedOctetStringImplicitTag(self):
        asn1Spec = univ.OctetString().subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 0))

        try:
            decoder.decode(bytes((160, 3, 4, 1, 65)), asn1Spec=asn1Spec)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'constructed OCTET STRING tolerated'

    def testConstructedOctetStringExplicitTag(self):
        asn1Spec = univ.OctetString().subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 0))

        try:
            decoder.decode(bytes((160, 5, 36, 3, 4, 1, 65)), asn1Spec=asn1Spec)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'constructed OCTET STRING tolerated'

    def testConstructedOctetStringChoice(self):
        asn1Spec = univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('blob', univ.OctetString())))

        value, _ = decoder.decode(self.primitiveOctetString, asn1Spec=asn1Spec)
        assert value['blob'] == b'A'

        try:
            decoder.decode(self.constructedOctetString, asn1Spec=asn1Spec)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'constructed OCTET STRING tolerated'

    def testConstructedOctetStringSequenceMember(self):
        asn1Spec = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('blob', univ.OctetString())))

        value, _ = decoder.decode(
            bytes((48, 3, 4, 1, 65)), asn1Spec=asn1Spec)
        assert value['blob'] == b'A'

        try:
            decoder.decode(
                bytes((48, 5, 36, 3, 4, 1, 65)), asn1Spec=asn1Spec)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'constructed OCTET STRING tolerated'

    def testConstructedOctetStringSetMember(self):
        asn1Spec = univ.Set(componentType=namedtype.NamedTypes(
            namedtype.NamedType('blob', univ.OctetString())))

        value, _ = decoder.decode(
            bytes((49, 3, 4, 1, 65)), asn1Spec=asn1Spec)
        assert value['blob'] == b'A'

        try:
            decoder.decode(
                bytes((49, 5, 36, 3, 4, 1, 65)), asn1Spec=asn1Spec)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'constructed OCTET STRING tolerated'

    def testConstructedOctetStringOpenType(self):
        openType = opentype.OpenType('id', {1: univ.OctetString()})
        asn1Spec = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('id', univ.Integer()),
            namedtype.NamedType('blob', univ.Any(), openType=openType)))

        value, _ = decoder.decode(
            bytes((48, 6, 2, 1, 1, 4, 1, 65)),
            asn1Spec=asn1Spec, decodeOpenTypes=True)
        assert value['blob'] == b'A'

        try:
            decoder.decode(
                bytes((48, 8, 2, 1, 1, 36, 3, 4, 1, 65)),
                asn1Spec=asn1Spec, decodeOpenTypes=True)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'constructed OCTET STRING tolerated'

    def testConstructedOctetStringChunked(self):
        class NonBlockingStream(io.BytesIO):
            block = False

            def read(self, size=-1):
                self.block = not self.block
                if self.block:
                    return  # this is what non-blocking streams sometimes do

                return io.BytesIO.read(self, size)

        iterator = iter(decoder.StreamingDecoder(
            NonBlockingStream(self.constructedOctetString),
            asn1Spec=univ.OctetString()))

        try:
            while True:
                chunk = next(iterator)
                assert isinstance(chunk, error.SubstrateUnderrunError), (
                    'unverified object yielded as a value: %r' % (chunk,))
        except PyAsn1Error:
            pass
        else:
            assert 0, 'constructed OCTET STRING tolerated'


class LargeTagDecoderTestCase(BaseTestCase):
    def testExcessiveLongTag(self):
        # 1 << 140 is the smallest tag ID needing 21 octets, one over the limit
        excessiveTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1 << 140)
        asn1Spec = univ.Integer().subtype(implicitTag=excessiveTag)
        substrate = encoder.encode(univ.Integer(1).subtype(implicitTag=excessiveTag))

        try:
            decoder.decode(substrate, asn1Spec=asn1Spec)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'excessive long tag tolerated'


class RealDecoderTestCase(BaseTestCase):
    def testCanonicalLargeBinaryReal(self):
        substrate = encoder.encode(univ.Real((1, 2, 1000000)))
        assert substrate == bytes((9, 5, 0x82, 0x0f, 0x42, 0x40, 1))

        value, rest = decoder.decode(substrate)

        assert tuple(value) == (1, 2, 1000000)
        assert rest == b''

    def testLargeBinaryRoundTrip(self):
        substrate = encoder.encode(univ.Real((-1, 2, 76354972)))
        value, rest = decoder.decode(substrate)

        assert tuple(value) == (-1, 2, 76354972)
        assert rest == b''


class SequenceDecoderWithUntaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('blob', univ.Any(), openType=openType)
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 6, 2, 1, 1, 2, 1, 12)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1] == 12

    def testDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes((48, 16, 2, 1, 2, 4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 2
        assert s[1] == univ.OctetString('quick brown')

    def testDecodeOpenTypesUnknownType(self):
        try:
            s, r = decoder.decode(
                bytes((48, 6, 2, 1, 2, 6, 1, 39)), asn1Spec=self.s,
                decodeOpenTypes=True
            )

        except PyAsn1Error:
            pass

        else:
            assert False, 'unknown open type tolerated'

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 6, 2, 1, 3, 6, 1, 39)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1] == univ.OctetString(hexValue='060127')

    def testDontDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 6, 2, 1, 1, 2, 1, 12)), asn1Spec=self.s
        )
        assert not r
        assert s[0] == 1
        assert s[1] == bytes((2, 1, 12))

    def testDontDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes((48, 16, 2, 1, 2, 4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110)), asn1Spec=self.s
        )
        assert not r
        assert s[0] == 2
        assert s[1] == bytes((4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110))


class SequenceDecoderWithImplicitlyTaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType(
                    'blob', univ.Any().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)), openType=openType
                )
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 131, 3, 2, 1, 12)), asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 3, 131, 3, 2, 1, 12)), asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1] == univ.OctetString(hexValue='02010C')


class SequenceDecoderWithExplicitlyTaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType(
                    'blob', univ.Any().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)), openType=openType
                )
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 163, 3, 2, 1, 12)), asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 3, 163, 3, 2, 1, 12)), asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1] == univ.OctetString(hexValue='02010C')


class SequenceDecoderWithUnaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('blob', univ.SetOf(componentType=univ.Any()),
                                    openType=openType)
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 49, 3, 2, 1, 12)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == 12

    def testDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes((48, 18, 2, 1, 2, 49, 13, 4, 11, 113, 117, 105, 99,
                       107, 32, 98, 114, 111, 119, 110)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 2
        assert s[1][0] == univ.OctetString('quick brown')

    def testDecodeOpenTypesUnknownType(self):
        try:
            s, r = decoder.decode(
                bytes((48, 6, 2, 1, 2, 6, 1, 39)), asn1Spec=self.s,
                decodeOpenTypes=True
            )

        except PyAsn1Error:
            pass

        else:
            assert False, 'unknown open type tolerated'

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 3, 49, 3, 2, 1, 12)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1][0] == univ.OctetString(hexValue='02010c')

    def testDontDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 49, 3, 2, 1, 12)), asn1Spec=self.s
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == bytes((2, 1, 12))

    def testDontDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes((48, 18, 2, 1, 2, 49, 13, 4, 11, 113, 117, 105, 99,
                       107, 32, 98, 114, 111, 119, 110)), asn1Spec=self.s
        )
        assert not r
        assert s[0] == 2
        assert s[1][0] == bytes((4, 11, 113, 117, 105, 99, 107, 32, 98, 114,
                                     111, 119, 110))


class SequenceDecoderWithImplicitlyTaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType(
                    'blob', univ.SetOf(
                        componentType=univ.Any().subtype(
                            implicitTag=tag.Tag(
                                tag.tagClassContext, tag.tagFormatSimple, 3))),
                    openType=openType
                )
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 10, 2, 1, 1, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 10, 2, 1, 3, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1][0] == univ.OctetString(hexValue='02010C')


class SequenceDecoderWithExplicitlyTaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType(
                    'blob', univ.SetOf(
                        componentType=univ.Any().subtype(
                            explicitTag=tag.Tag(
                                tag.tagClassContext, tag.tagFormatSimple, 3))),
                    openType=openType
                )
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 10, 2, 1, 1, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes( (48, 10, 2, 1, 3, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1][0] == univ.OctetString(hexValue='02010C')


class NestingDepthLimitTestCase(BaseTestCase):
    """Test DER decoder protection against deeply nested structures."""

    def testDefiniteLenNesting(self):
        """Deeply nested definite-length SEQUENCEs must raise PyAsn1Error."""
        inner = b'\x05\x00'  # NULL
        for _ in range(200):
            length = len(inner)
            if length < 128:
                inner = b'\x30' + bytes([length]) + inner
            else:
                length_bytes = length.to_bytes(
                    (length.bit_length() + 7) // 8, 'big')
                inner = b'\x30' + bytes([0x80 | len(length_bytes)]) + \
                    length_bytes + inner
        try:
            decoder.decode(inner)
        except PyAsn1Error:
            pass
        else:
            assert False, 'Deeply nested definite-length SEQUENCEs not rejected'

    def testNoRecursionError(self):
        """Must raise PyAsn1Error, not RecursionError."""
        inner = b'\x05\x00'
        for _ in range(200):
            length = len(inner)
            if length < 128:
                inner = b'\x30' + bytes([length]) + inner
            else:
                length_bytes = length.to_bytes(
                    (length.bit_length() + 7) // 8, 'big')
                inner = b'\x30' + bytes([0x80 | len(length_bytes)]) + \
                    length_bytes + inner
        try:
            decoder.decode(inner)
        except PyAsn1Error:
            pass
        except RecursionError:
            assert False, 'Got RecursionError instead of PyAsn1Error'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
