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
from pyasn1.codec.cer import decoder as cer_decoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.error import PyAsn1Error
from pyasn1.error import SubstrateUnderrunError
from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ


class BothEntriesTestCase(BaseTestCase):
    # CER and DER restrictions (canonical Boolean, prohibited constructed
    # form, no indefinite length) must fire whether or not an asn1Spec
    # is supplied, while BER keeps accepting its lenient superset.

    def assertAccepted(self, dec, substrate, spec, expected):
        for asn1Spec in (None, spec):
            value, rest = dec.decode(substrate, asn1Spec=asn1Spec)
            assert value == expected, (
                'unexpected value %r (asn1Spec=%r)' % (value, asn1Spec))
            assert not rest

    def assertRejected(self, dec, substrate, spec, message):
        for asn1Spec in (None, spec):
            try:
                dec.decode(substrate, asn1Spec=asn1Spec)

            except PyAsn1Error:
                pass

            else:
                assert 0, '%s (asn1Spec=%r)' % (message, asn1Spec)


class BooleanStrictnessTestCase(BothEntriesTestCase):
    # BOOLEAN TRUE as 0x01: legal BER, non-canonical for CER/DER
    nonCanonicalTrue = bytes((1, 1, 1))
    canonicalTrue = bytes((1, 1, 255))
    canonicalFalse = bytes((1, 1, 0))

    def testBerAcceptsNonCanonicalTrue(self):
        self.assertAccepted(
            ber_decoder, self.nonCanonicalTrue, univ.Boolean(), 1)

    def testCerRejectsNonCanonicalTrue(self):
        self.assertRejected(
            cer_decoder, self.nonCanonicalTrue, univ.Boolean(),
            'non-canonical Boolean tolerated')

    def testDerRejectsNonCanonicalTrue(self):
        self.assertRejected(
            der_decoder, self.nonCanonicalTrue, univ.Boolean(),
            'non-canonical Boolean tolerated')

    def testCanonicalValuesAccepted(self):
        for dec in (ber_decoder, cer_decoder, der_decoder):
            self.assertAccepted(dec, self.canonicalTrue, univ.Boolean(), 1)
            self.assertAccepted(dec, self.canonicalFalse, univ.Boolean(), 0)


class ConstructedOctetStringStrictnessTestCase(BothEntriesTestCase):
    # constructed OCTET STRING, definite length: "a" + "b"
    definiteConstructed = bytes((36, 6, 4, 1, 97, 4, 1, 98))
    # constructed OCTET STRING, indefinite length
    indefiniteConstructed = bytes((36, 128, 4, 1, 97, 4, 1, 98, 0, 0))
    primitive = bytes((4, 2, 97, 98))

    def testDefiniteConstructed(self):
        self.assertAccepted(
            ber_decoder, self.definiteConstructed, univ.OctetString(), b'ab')
        self.assertAccepted(
            cer_decoder, self.definiteConstructed, univ.OctetString(), b'ab')
        self.assertRejected(
            der_decoder, self.definiteConstructed, univ.OctetString(),
            'constructed OCTET STRING tolerated')

    def testIndefiniteConstructed(self):
        self.assertAccepted(
            ber_decoder, self.indefiniteConstructed, univ.OctetString(), b'ab')
        self.assertAccepted(
            cer_decoder, self.indefiniteConstructed, univ.OctetString(), b'ab')
        self.assertRejected(
            der_decoder, self.indefiniteConstructed, univ.OctetString(),
            'indefinite length tolerated')

    def testPrimitiveAccepted(self):
        for dec in (ber_decoder, cer_decoder, der_decoder):
            self.assertAccepted(dec, self.primitive, univ.OctetString(), b'ab')


class ImplicitTagStrictnessTestCase(BothEntriesTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.implicitBoolean = univ.Boolean().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        self.implicitOctetString = univ.OctetString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))

    def testBooleanNonCanonicalTrue(self):
        substrate = bytes((128, 1, 1))
        value, rest = ber_decoder.decode(
            substrate, asn1Spec=self.implicitBoolean)
        assert value == 1
        assert not rest
        for dec in (cer_decoder, der_decoder):
            try:
                dec.decode(substrate, asn1Spec=self.implicitBoolean)

            except PyAsn1Error:
                pass

            else:
                assert 0, 'non-canonical Boolean tolerated'

    def testBooleanCanonicalTrue(self):
        substrate = bytes((128, 1, 255))
        for dec in (ber_decoder, cer_decoder, der_decoder):
            value, rest = dec.decode(substrate, asn1Spec=self.implicitBoolean)
            assert value == 1
            assert not rest

    def testConstructedOctetString(self):
        substrate = bytes((160, 6, 4, 1, 97, 4, 1, 98))
        for dec in (ber_decoder, cer_decoder):
            value, rest = dec.decode(
                substrate, asn1Spec=self.implicitOctetString)
            assert value == b'ab'
            assert not rest
        try:
            der_decoder.decode(substrate, asn1Spec=self.implicitOctetString)

        except PyAsn1Error:
            pass

        else:
            assert 0, 'constructed OCTET STRING tolerated'


class ExplicitTagStrictnessTestCase(BothEntriesTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.explicitBoolean = univ.Boolean().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))

    def testBooleanNonCanonicalTrue(self):
        substrate = bytes((160, 3, 1, 1, 1))
        value, rest = ber_decoder.decode(
            substrate, asn1Spec=self.explicitBoolean)
        assert value == 1
        assert not rest
        for dec in (cer_decoder, der_decoder):
            try:
                dec.decode(substrate, asn1Spec=self.explicitBoolean)

            except PyAsn1Error:
                pass

            else:
                assert 0, 'non-canonical Boolean tolerated'

    def testBooleanCanonicalTrue(self):
        substrate = bytes((160, 3, 1, 1, 255))
        for dec in (ber_decoder, cer_decoder, der_decoder):
            value, rest = dec.decode(substrate, asn1Spec=self.explicitBoolean)
            assert value == 1
            assert not rest


class ChoiceStrictnessTestCase(BothEntriesTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.choice = univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('flag', univ.Boolean()),
                namedtype.NamedType('blob', univ.OctetString())
            )
        )

    def testBooleanNonCanonicalTrue(self):
        substrate = bytes((1, 1, 1))
        value, rest = ber_decoder.decode(substrate, asn1Spec=self.choice)
        assert value.getComponentByName('flag') == 1
        assert not rest
        for dec in (cer_decoder, der_decoder):
            try:
                dec.decode(substrate, asn1Spec=self.choice)

            except PyAsn1Error:
                pass

            else:
                assert 0, 'non-canonical Boolean tolerated'

    def testBooleanCanonicalTrue(self):
        substrate = bytes((1, 1, 255))
        for dec in (ber_decoder, cer_decoder, der_decoder):
            value, rest = dec.decode(substrate, asn1Spec=self.choice)
            assert value.getComponentByName('flag') == 1
            assert not rest

    def testConstructedOctetString(self):
        substrate = bytes((36, 6, 4, 1, 97, 4, 1, 98))
        for dec in (ber_decoder, cer_decoder):
            value, rest = dec.decode(substrate, asn1Spec=self.choice)
            assert value.getComponentByName('blob') == b'ab'
            assert not rest
        try:
            der_decoder.decode(substrate, asn1Spec=self.choice)

        except PyAsn1Error:
            pass

        else:
            assert 0, 'constructed OCTET STRING tolerated'


class ContainerMemberStrictnessTestCase(BothEntriesTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.sequence = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('flag', univ.Boolean())
            )
        )
        self.set = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('blob', univ.OctetString())
            )
        )

    def testSequenceBooleanMemberNonCanonical(self):
        substrate = bytes((48, 3, 1, 1, 1))
        value, rest = ber_decoder.decode(substrate, asn1Spec=self.sequence)
        assert value[0] == 1
        assert not rest
        for dec in (cer_decoder, der_decoder):
            try:
                dec.decode(substrate, asn1Spec=self.sequence)

            except PyAsn1Error:
                pass

            else:
                assert 0, 'non-canonical Boolean tolerated'

    def testSequenceBooleanMemberCanonical(self):
        substrate = bytes((48, 3, 1, 1, 255))
        for dec in (ber_decoder, cer_decoder, der_decoder):
            value, rest = dec.decode(substrate, asn1Spec=self.sequence)
            assert value[0] == 1
            assert not rest

    def testSetConstructedOctetStringMember(self):
        substrate = bytes((49, 8, 36, 6, 4, 1, 97, 4, 1, 98))
        for dec in (ber_decoder, cer_decoder):
            value, rest = dec.decode(substrate, asn1Spec=self.set)
            assert value[0] == b'ab'
            assert not rest
        try:
            der_decoder.decode(substrate, asn1Spec=self.set)

        except PyAsn1Error:
            pass

        else:
            assert 0, 'constructed OCTET STRING tolerated'


class OpenTypeStrictnessTestCase(BothEntriesTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        openType = opentype.OpenType('id', {1: univ.Boolean()})
        self.sequence = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('blob', univ.Any(), openType=openType)
            )
        )

    def testOpenTypeBooleanNonCanonical(self):
        substrate = bytes((48, 6, 2, 1, 1, 1, 1, 1))
        value, rest = ber_decoder.decode(
            substrate, asn1Spec=self.sequence, decodeOpenTypes=True)
        assert value[0] == 1
        assert value[1] == 1
        assert not rest
        for dec in (cer_decoder, der_decoder):
            try:
                dec.decode(
                    substrate, asn1Spec=self.sequence, decodeOpenTypes=True)

            except PyAsn1Error:
                pass

            else:
                assert 0, 'non-canonical Boolean tolerated'

    def testOpenTypeBooleanCanonical(self):
        substrate = bytes((48, 6, 2, 1, 1, 1, 1, 255))
        for dec in (ber_decoder, cer_decoder, der_decoder):
            value, rest = dec.decode(
                substrate, asn1Spec=self.sequence, decodeOpenTypes=True)
            assert value[0] == 1
            assert value[1] == 1
            assert not rest


class DribbleStream(io.IOBase):
    # Non-seekable stream releasing a single octet per read

    def __init__(self, data):
        self._data = data
        self._pos = 0

    def read(self, size=-1):
        if self._pos >= len(self._data):
            return b''

        chunk = self._data[self._pos:self._pos + 1]
        self._pos += 1

        return chunk


class SegmentedInputStrictnessTestCase(BothEntriesTestCase):
    def streamValues(self, dec, substrate, spec):
        underruns = []
        values = []

        for item in dec.StreamingDecoder(
                DribbleStream(substrate), asn1Spec=spec):
            if isinstance(item, SubstrateUnderrunError):
                underruns.append(item)

            else:
                values.append(item)

        return underruns, values

    def testSegmentedCanonicalBoolean(self):
        substrate = bytes((1, 1, 255))
        for dec in (ber_decoder, cer_decoder, der_decoder):
            for spec in (None, univ.Boolean()):
                underruns, values = self.streamValues(dec, substrate, spec)
                assert values == [1]

    def testSegmentedPrimitiveOctetString(self):
        substrate = bytes((4, 2, 97, 98))
        for dec in (ber_decoder, cer_decoder, der_decoder):
            for spec in (None, univ.OctetString()):
                underruns, values = self.streamValues(dec, substrate, spec)
                assert underruns, 'segmented input did not underrun'
                assert values == [b'ab']

    def testSegmentedNonCanonicalBooleanRejected(self):
        substrate = bytes((1, 1, 1))
        for dec in (cer_decoder, der_decoder):
            for spec in (None, univ.Boolean()):
                values = []
                try:
                    for item in dec.StreamingDecoder(
                            DribbleStream(substrate), asn1Spec=spec):
                        if not isinstance(item, SubstrateUnderrunError):
                            values.append(item)

                except PyAsn1Error:
                    pass

                else:
                    assert 0, 'non-canonical Boolean tolerated'

                assert not values, 'unverified object yielded before error'

    def testSegmentedConstructedOctetStringRejectedByDer(self):
        substrate = bytes((36, 6, 4, 1, 97, 4, 1, 98))
        for spec in (None, univ.OctetString()):
            values = []
            try:
                for item in der_decoder.StreamingDecoder(
                        DribbleStream(substrate), asn1Spec=spec):
                    if not isinstance(item, SubstrateUnderrunError):
                        values.append(item)

            except PyAsn1Error:
                pass

            else:
                assert 0, 'constructed OCTET STRING tolerated'

            assert not values, 'unverified object yielded before error'

    def testSegmentedConstructedOctetStringReadByBerAndCer(self):
        substrate = bytes((36, 6, 4, 1, 97, 4, 1, 98))
        for dec in (ber_decoder, cer_decoder):
            for spec in (None, univ.OctetString()):
                underruns, values = self.streamValues(dec, substrate, spec)
                assert values == [b'ab']


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
