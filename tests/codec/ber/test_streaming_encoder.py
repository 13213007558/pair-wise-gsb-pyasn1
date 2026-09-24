#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import io
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.type import constraint
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.error import PyAsn1Error
from pyasn1.error import SubstrateUnderrunError


def streamingDecode(substrate, asn1Spec=None):
    asn1Objects = []

    for asn1Object in decoder.StreamingDecoder(
            io.BytesIO(substrate), asn1Spec=asn1Spec):
        assert not isinstance(asn1Object, SubstrateUnderrunError)
        asn1Objects.append(asn1Object)

    return asn1Objects


class StreamingSequenceOfEncoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.streamingEncoder = encoder.StreamingEncoder()
        self.spec = univ.SequenceOf(componentType=univ.Integer())
        self.value = univ.SequenceOf(componentType=univ.Integer())
        self.value.extend(range(10))

    def testIndefiniteLengthChunks(self):
        chunks = list(self.streamingEncoder(self.value, defMode=False))

        assert chunks[0] == bytes((0x30, 0x80))
        assert chunks[-1] == bytes((0, 0))
        assert b''.join(chunks) == encoder.encode(self.value, defMode=False)

    def testDefiniteLengthChunks(self):
        chunks = list(self.streamingEncoder(self.value))

        assert b''.join(chunks) == encoder.encode(self.value)

    def testBareValueWithSchema(self):
        chunks = list(self.streamingEncoder(
            [1, 2, 3], asn1Spec=self.spec, defMode=False))

        assert b''.join(chunks) == encoder.encode(
            [1, 2, 3], asn1Spec=self.spec, defMode=False)

    def testEmptySetOfIndefinite(self):
        chunks = list(self.streamingEncoder(univ.SetOf(), defMode=False))

        assert b''.join(chunks) == bytes((0x31, 0x80, 0, 0))
        assert b''.join(chunks) == encoder.encode(univ.SetOf(), defMode=False)

    def testEmptySequenceOfDefinite(self):
        chunks = list(self.streamingEncoder(univ.SequenceOf()))

        assert b''.join(chunks) == bytes((0x30, 0))
        assert b''.join(chunks) == encoder.encode(univ.SequenceOf())

    def testEmptySequenceOfIfNotEmpty(self):
        chunks = list(self.streamingEncoder(
            univ.SequenceOf(), defMode=False, ifNotEmpty=True))

        assert chunks == []
        assert encoder.encode(
            univ.SequenceOf(), defMode=False, ifNotEmpty=True) == b''

    def testExplicitTagIndefinite(self):
        spec = univ.SequenceOf(componentType=univ.Integer()).subtype(
            explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 3))

        chunks = list(self.streamingEncoder(
            [1, 2], asn1Spec=spec, defMode=False))

        substrate = b''.join(chunks)

        assert substrate == encoder.encode([1, 2], asn1Spec=spec, defMode=False)
        # outermost explicit tag opens first, both containers close last
        assert substrate[:2] == bytes((0xa3, 0x80))
        assert substrate[-4:] == bytes((0, 0, 0, 0))

    def testExplicitTagDefinite(self):
        spec = univ.SequenceOf(componentType=univ.Integer()).subtype(
            explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 3))

        chunks = list(self.streamingEncoder([1, 2], asn1Spec=spec))

        assert b''.join(chunks) == encoder.encode([1, 2], asn1Spec=spec)

    def testNestedSequenceOfIndefinite(self):
        inner1 = univ.SequenceOf(componentType=univ.Integer())
        inner1.extend([1, 2])
        inner2 = univ.SequenceOf(componentType=univ.Integer())
        inner2.extend([3])
        outer = univ.SequenceOf(
            componentType=univ.SequenceOf(componentType=univ.Integer()))
        outer.extend([inner1, inner2])

        chunks = list(self.streamingEncoder(outer, defMode=False))

        assert b''.join(chunks) == encoder.encode(outer, defMode=False)

    def testOpenTypeWrapper(self):
        chunks = list(self.streamingEncoder(
            [univ.Integer(1)], asn1Spec=self.spec, defMode=False,
            wrapType=univ.Any()))

        assert b''.join(chunks) == encoder.encode(
            [univ.Integer(1)], asn1Spec=self.spec, defMode=False,
            wrapType=univ.Any())

    def testRoundTripThroughStreamingDecoder(self):
        substrate = b''.join(self.streamingEncoder(self.value, defMode=False))

        asn1Objects = streamingDecode(substrate)

        assert len(asn1Objects) == 1
        assert asn1Objects[0] == self.value
        assert asn1Objects[0] == decoder.decode(
            encoder.encode(self.value, defMode=False))[0]

    def testRoundTripThroughStreamingDecoderWithSchema(self):
        substrate = b''.join(self.streamingEncoder(
            range(10), asn1Spec=self.spec, defMode=False))

        asn1Objects = streamingDecode(substrate, asn1Spec=self.spec)

        assert len(asn1Objects) == 1
        assert list(asn1Objects[0]) == list(range(10))


class StreamingElementSourceTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.streamingEncoder = encoder.StreamingEncoder()
        self.spec = univ.SequenceOf(componentType=univ.Integer())

    def testGeneratorSourceIndefinite(self):
        def source():
            for i in range(5):
                yield univ.Integer(i)

        chunks = list(self.streamingEncoder(
            source(), asn1Spec=self.spec, defMode=False))

        assert b''.join(chunks) == encoder.encode(
            list(range(5)), asn1Spec=self.spec, defMode=False)

    def testFirstChunkDoesNotExhaustSource(self):
        consumed = []

        def source():
            for i in range(100):
                consumed.append(i)
                yield univ.Integer(i)

        chunks = self.streamingEncoder(
            source(), asn1Spec=self.spec, defMode=False)

        firstChunk = next(chunks)

        assert firstChunk == bytes((0x30, 0x80))
        assert len(consumed) <= 1

    def testOneShotDefiniteLengthRejected(self):
        def source():
            yield univ.Integer(1)

        try:
            list(self.streamingEncoder(source(), asn1Spec=self.spec))
        except PyAsn1Error:
            pass
        else:
            assert 0, 'one-shot definite-length encoding tolerated'

    def testOneShotDefiniteLengthBoundedBuffer(self):
        def source():
            for i in range(5):
                yield univ.Integer(i)

        chunks = list(self.streamingEncoder(
            source(), asn1Spec=self.spec, maxBufferedOctets=1024))

        assert b''.join(chunks) == encoder.encode(
            list(range(5)), asn1Spec=self.spec)

    def testOneShotDefiniteLengthBufferOverflow(self):
        def source():
            for i in range(100):
                yield univ.Integer(i)

        try:
            list(self.streamingEncoder(
                source(), asn1Spec=self.spec, maxBufferedOctets=8))
        except PyAsn1Error:
            pass
        else:
            assert 0, 'buffer overflow tolerated'

    def testConstraintFailurePropagates(self):
        spec = univ.SequenceOf(componentType=univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, 2)))

        def source():
            yield univ.OctetString(b'ab')
            yield univ.OctetString(b'abcdef')

        chunks = []

        try:
            for chunk in self.streamingEncoder(
                    source(), asn1Spec=spec, defMode=False):
                chunks.append(chunk)
        except PyAsn1Error as exc:
            # element position is reported, original exception is chained
            assert '#1' in str(exc)
            assert exc.__context__ is not None
        else:
            assert 0, 'constraint violation tolerated'

        # only the header and the first component made it out,
        # no end-of-octets marker fakes a successful completion
        assert b''.join(chunks) == bytes((0x30, 0x80, 0x04, 0x02)) + b'ab'


class StreamingOctetStringEncoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.streamingEncoder = encoder.StreamingEncoder()
        self.value = univ.OctetString(b'x' * 10)

    def testChunkedIndefinite(self):
        chunks = list(self.streamingEncoder(
            self.value, defMode=False, maxChunkSize=3))

        assert len(chunks) > 2
        assert chunks[0] == bytes((0x24, 0x80))
        assert chunks[-1] == bytes((0, 0))
        assert b''.join(chunks) == encoder.encode(
            self.value, defMode=False, maxChunkSize=3)

    def testChunkedDefinite(self):
        chunks = list(self.streamingEncoder(self.value, maxChunkSize=3))

        assert b''.join(chunks) == encoder.encode(self.value, maxChunkSize=3)

    def testUnchunked(self):
        chunks = list(self.streamingEncoder(self.value))

        assert b''.join(chunks) == encoder.encode(self.value)

    def testExplicitTagChunkedIndefinite(self):
        value = univ.OctetString(b'y' * 8).subtype(
            explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 5))

        chunks = list(self.streamingEncoder(
            value, defMode=False, maxChunkSize=3))

        assert b''.join(chunks) == encoder.encode(
            value, defMode=False, maxChunkSize=3)

    def testRoundTripThroughStreamingDecoder(self):
        substrate = b''.join(self.streamingEncoder(
            self.value, defMode=False, maxChunkSize=3))

        asn1Objects = streamingDecode(substrate)

        assert len(asn1Objects) == 1
        assert asn1Objects[0] == self.value


class StreamingEncoderFallbackTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.streamingEncoder = encoder.StreamingEncoder()

    def testSequence(self):
        value = univ.Sequence()
        value.setComponentByPosition(0, univ.Integer(5))

        chunks = list(self.streamingEncoder(value))

        assert b''.join(chunks) == encoder.encode(value)

    def testBitStringChunked(self):
        value = univ.BitString((1,) * 33)

        chunks = list(self.streamingEncoder(
            value, defMode=False, maxChunkSize=2))

        assert b''.join(chunks) == encoder.encode(
            value, defMode=False, maxChunkSize=2)

    def testNotAsn1Value(self):
        try:
            list(self.streamingEncoder(object()))
        except PyAsn1Error:
            pass
        else:
            assert 0, 'non-ASN.1 value tolerated'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
