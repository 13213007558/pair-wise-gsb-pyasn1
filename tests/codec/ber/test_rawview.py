#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2026, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import io
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type import univ
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber.rawview import RawView
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1 import error


class NonSeekableStream(io.RawIOBase):
    def __init__(self, data):
        self._stream = io.BytesIO(data)

    def readable(self):
        return True

    def seekable(self):
        return False

    def read(self, size=-1):
        return self._stream.read(size)


class DefiniteLengthSpanTestCase(BaseTestCase):
    def testNonCanonicalLongFormLength(self):
        substrate = bytes((0x30, 0x04, 0x02, 0x81, 0x01, 0x05))
        view = RawView()

        root, tail = decoder.decode(substrate, rawView=view)

        assert not tail

        span = view.lookup(root, (0,))

        assert span.tagRange == (2, 3)
        assert span.lengthRange == (3, 5)
        assert span.valueRange == (5, 6)
        assert span.fullRange == (2, 6)
        assert not span.indefinite

        assert bytes(span.tagOctets) == b'\x02'
        assert bytes(span.lengthOctets) == b'\x81\x01'
        assert bytes(span.valueOctets) == b'\x05'
        assert bytes(span.fullOctets) == substrate[2:6]

    def testNonMinimalInteger(self):
        substrate = bytes((0x02, 0x02, 0x00, 0x7F))
        view = RawView()

        root, tail = decoder.decode(substrate, rawView=view)

        assert root == 127

        span = view.spanFor(root)

        assert bytes(span.valueOctets) == b'\x00\x7f'
        assert bytes(span.fullOctets) == substrate

    def testReceivedBytesNotRegenerated(self):
        # non-canonical but legal BER: long-form length and non-minimal
        # INTEGER; DER re-encoding would produce different octets
        substrate = bytes((0x30, 0x05, 0x02, 0x81, 0x02, 0x00, 0x7F))
        view = RawView()

        root, tail = decoder.decode(substrate, rawView=view)

        assert der_encoder.encode(root) != substrate

        assert bytes(view.spanFor(root).fullOctets) == substrate
        assert bytes(view.lookup(root, (0,)).fullOctets) == substrate[2:7]

    def testZeroCopySlices(self):
        substrate = bytes((0x30, 0x04, 0x02, 0x81, 0x01, 0x05))
        view = RawView()

        root, tail = decoder.decode(substrate, rawView=view)

        span = view.lookup(root, (0,))

        assert isinstance(span.fullOctets, memoryview)
        assert span.fullOctets.obj is substrate
        assert view.layers[0].isZeroCopy

    def testFieldPathLookup(self):
        substrate = bytes((0x30, 0x08, 0x02, 0x01, 0x01, 0x30, 0x03, 0x02, 0x01, 0x02))
        view = RawView()

        root, tail = decoder.decode(substrate, rawView=view)

        span = view.lookup(root, (1, 0))

        assert bytes(span.fullOctets) == substrate[7:10]

        assert view.lookup(root, (0,)).fullRange == (2, 5)
        assert view.spanFor(root).fullRange == (0, 10)


class IndefiniteLengthSpanTestCase(BaseTestCase):
    substrate = bytes((0x24, 0x80, 0x04, 0x02, 0x61, 0x62, 0x00, 0x00))

    def testFullRangeIncludesEoc(self):
        view = RawView()

        root, tail = decoder.decode(self.substrate, rawView=view)

        assert root == univ.OctetString('ab')

        span = view.spanFor(root)

        assert span.indefinite
        assert span.tagRange == (0, 1)
        assert span.lengthRange == (1, 2)
        assert span.valueRange == (2, 6)
        assert span.fullRange == (0, 8)

        assert bytes(span.valueOctets) == self.substrate[2:6]
        assert bytes(span.fullOctets) == self.substrate
        assert bytes(span.fullOctets).endswith(b'\x00\x00')

    def testIndefiniteSequence(self):
        substrate = bytes((0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00))
        view = RawView()

        root, tail = decoder.decode(substrate, rawView=view)

        span = view.spanFor(root)

        assert span.indefinite
        assert bytes(span.fullOctets) == substrate

        componentSpan = view.lookup(root, (0,))
        assert componentSpan.fullRange == (2, 5)
        assert not componentSpan.indefinite


class ExplicitTagSpanTestCase(BaseTestCase):
    def testOuterWrapperAndInnerValueAreDistinct(self):
        substrate = bytes((0xA0, 0x03, 0x02, 0x01, 0x05))
        view = RawView()

        root, tail = decoder.decode(substrate, rawView=view)

        assert root == 5

        spans = view.spansFor(root)

        assert len(spans) == 2

        innerSpan, outerSpan = spans

        assert innerSpan.fullRange == (2, 5)
        assert bytes(innerSpan.fullOctets) == substrate[2:5]

        assert outerSpan.fullRange == (0, 5)
        assert bytes(outerSpan.fullOctets) == substrate
        assert bytes(outerSpan.valueOctets) == substrate[2:5]

        # the outermost wrapper is the default answer
        assert view.spanFor(root) is outerSpan


class OpenTypesSpanTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        openType = opentype.OpenType(
            'id', {1: univ.Integer()})
        self.spec = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('blob', univ.Any(), openType=openType)
            )
        )

    def testAnyOpenTypeKeepsBothSourceLayers(self):
        # the ANY payload is a non-canonical INTEGER encoding
        substrate = bytes((0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x81, 0x01, 0x2A))
        view = RawView()

        root, tail = decoder.decode(
            substrate, asn1Spec=self.spec, decodeOpenTypes=True,
            rawView=view)

        assert root['blob'] == 42

        assert len(view.layers) == 2

        innerSpan = view.lookup(root, ('blob',))

        # inner TLV is located in the ANY octets source
        assert innerSpan.source is view.layers[1]
        assert innerSpan.fullRange == (0, 4)
        assert bytes(innerSpan.fullOctets) == b'\x02\x81\x01\x2a'

        # the ANY field itself remains located in the original source
        anySpan = innerSpan.source.parentSpan

        assert anySpan is not None
        assert anySpan.source is view.layers[0]
        assert anySpan.fullRange == (5, 9)
        assert bytes(anySpan.fullOctets) == substrate[5:9]
        assert bytes(anySpan.fullOctets) == bytes(innerSpan.fullOctets)


class StreamingSpanTestCase(BaseTestCase):
    def testSecondTopLevelObjectSharesTheSource(self):
        substrate = bytes((0x02, 0x01, 0x01, 0x02, 0x81, 0x01, 0x02))
        view = RawView()

        objects = list(decoder.StreamingDecoder(
            io.BytesIO(substrate), rawView=view))

        assert len(objects) == 2

        firstSpan = view.spanFor(objects[0])
        secondSpan = view.spanFor(objects[1])

        assert firstSpan.fullRange == (0, 3)
        assert secondSpan.fullRange == (3, 7)
        assert secondSpan.source is firstSpan.source
        assert bytes(secondSpan.fullOctets) == substrate[3:7]

    def testOffsetsStayAbsoluteOnNonSeekableStreams(self):
        payload = bytes(9000)  # beyond the caching wrapper drop threshold
        substrate = (
            bytes((0x30, 0x82, 0x23, 0x2F)) +
            bytes((0x04, 0x82, 0x23, 0x28)) + payload +
            bytes((0x02, 0x01, 0x05))
        )
        view = RawView()

        root, tail = decoder.decode(
            NonSeekableStream(substrate), rawView=view)

        componentSpan = view.lookup(root, (1,))

        assert componentSpan.tagRange == (9008, 9009)
        assert bytes(componentSpan.fullOctets) == substrate[9008:]


class StreamSourceTestCase(BaseTestCase):
    substrate = bytes((0x24, 0x80, 0x04, 0x02, 0x61, 0x62, 0x00, 0x00))

    def testCallbackReceivesReceivedBytes(self):
        collected = []
        view = RawView(
            onRawEncoding=lambda span, octets: collected.append(
                (span, bytes(octets))))

        root, tail = decoder.decode(
            NonSeekableStream(self.substrate), rawView=view)

        assert not tail
        assert root == univ.OctetString('ab')

        assert collected
        assert collected[-1][1] == self.substrate

        innerTlvs = [octets for span, octets in collected[:-1]]
        assert bytes((0x04, 0x02, 0x61, 0x62)) in innerTlvs

    def testSpansReadFromRecording(self):
        view = RawView()

        root, tail = decoder.decode(
            NonSeekableStream(self.substrate), rawView=view)

        span = view.spanFor(root)

        assert not span.source.isZeroCopy
        assert bytes(span.fullOctets) == self.substrate

    def testRelease(self):
        view = RawView()

        root, tail = decoder.decode(
            NonSeekableStream(self.substrate), rawView=view)

        span = view.spanFor(root)

        view.release()

        assert span.fullRange == (0, 8)

        try:
            span.fullOctets
        except error.PyAsn1Error:
            pass
        else:
            assert 0, 'octet access on a released view tolerated'


class BytesSourceReleaseTestCase(BaseTestCase):
    def testRelease(self):
        substrate = bytes((0x02, 0x01, 0x05))
        view = RawView()

        root, tail = decoder.decode(substrate, rawView=view)

        span = view.spanFor(root)

        assert bytes(span.fullOctets) == substrate

        view.release()

        assert span.fullRange == (0, 3)

        try:
            span.fullOctets
        except error.PyAsn1Error:
            pass
        else:
            assert 0, 'octet access on a released view tolerated'


class ValueEqualityTestCase(BaseTestCase):
    def testViewDoesNotAffectAsn1Values(self):
        substrate = bytes((0x30, 0x04, 0x02, 0x81, 0x01, 0x05))

        withView, tail = decoder.decode(substrate, rawView=RawView())
        withoutView, tail = decoder.decode(substrate)

        assert withView == withoutView
        assert withView[0] == univ.Integer(5)


class DerDecoderSpanTestCase(BaseTestCase):
    def testDerDecoderRecordsSpans(self):
        substrate = bytes((0x30, 0x03, 0x02, 0x01, 0x05))
        view = RawView()

        root, tail = der_decoder.decode(substrate, rawView=view)

        span = view.lookup(root, (0,))

        assert span.fullRange == (2, 5)
        assert bytes(span.fullOctets) == substrate[2:5]


class UntaggedChoiceSpanTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.spec = univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.OctetString())
            )
        )

    def testNestedValueOnlySpan(self):
        substrate = bytes((0x02, 0x01, 0x07))
        view = RawView()

        root, tail = decoder.decode(
            substrate, asn1Spec=self.spec, rawView=view)

        outerSpan = view.spanFor(root)

        assert outerSpan.fullRange == (0, 3)
        assert bytes(outerSpan.fullOctets) == substrate

        # the untagged component decodes in a nested pass that starts
        # past the tag and length octets
        innerSpan = view.spanFor(root.getComponent())

        assert innerSpan.tagRange == (2, 2)
        assert innerSpan.lengthRange == (2, 2)
        assert innerSpan.valueRange == (2, 3)
        assert bytes(innerSpan.valueOctets) == b'\x07'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
