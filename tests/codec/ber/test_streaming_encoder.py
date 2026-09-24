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

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type.error import ValueConstraintError
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.codec.ber.decoder import StreamingDecoder
from pyasn1.error import PyAsn1Error


class StreamingEncoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.encoder = encoder.StreamingEncoder()
        self.schema = univ.SequenceOf(componentType=univ.Integer())

    def testConstructedValueChunks(self):
        value = univ.SequenceOf(componentType=univ.Integer())
        value.extend([1, 2])

        chunks = list(self.encoder(value))

        assert chunks[0] == bytes((0x30, 0x80))
        assert chunks[-1] == bytes((0, 0))
        assert b''.join(chunks) == encoder.encode(value, defMode=False)

    def testOneShotComponentSource(self):
        chunks = list(self.encoder(
            iter([1, 2, 3]), asn1Spec=self.schema))

        assert b''.join(chunks) == encoder.encode(
            [1, 2, 3], asn1Spec=self.schema, defMode=False)

    def testExplicitTagsNestedContainers(self):
        value = univ.SequenceOf(componentType=univ.Integer())
        value.extend([1, 2])
        value = value.subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 3))

        substrate = b''.join(self.encoder(value))

        assert substrate == encoder.encode(value, defMode=False)
        assert substrate.startswith(bytes((0xa3, 0x80)))
        assert substrate.endswith(bytes((0, 0, 0, 0)))

    def testNestedSequenceOf(self):
        inner = univ.SequenceOf(componentType=univ.Integer())
        inner.extend([1, 2])
        outer = univ.SequenceOf(
            componentType=univ.SequenceOf(componentType=univ.Integer()))
        outer.append(inner)

        substrate = b''.join(self.encoder(outer))

        assert substrate == encoder.encode(outer, defMode=False)

    def testChunkedOctetString(self):
        value = univ.OctetString(b"abcdef")

        chunks = list(self.encoder(value, maxChunkSize=2))

        assert len(chunks) > 1
        assert b''.join(chunks) == encoder.encode(
            value, defMode=False, maxChunkSize=2)

    def testChunkedOctetStringWithSchema(self):
        substrate = b''.join(self.encoder(
            b"abcdef", asn1Spec=univ.OctetString(), maxChunkSize=2))

        assert substrate == encoder.encode(
            b"abcdef", asn1Spec=univ.OctetString(),
            defMode=False, maxChunkSize=2)

    def testChunkedExplicitlyTaggedOctetString(self):
        value = univ.OctetString(b"abcdef").subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 3))

        substrate = b''.join(self.encoder(value, maxChunkSize=2))

        assert substrate == encoder.encode(
            value, defMode=False, maxChunkSize=2)

    def testEmptySequenceOf(self):
        substrate = b''.join(self.encoder(
            univ.SequenceOf(componentType=univ.Integer())))

        assert substrate == bytes((0x30, 0x80, 0, 0))

    def testEmptySetOf(self):
        substrate = b''.join(self.encoder(
            univ.SetOf(componentType=univ.Integer())))

        assert substrate == bytes((0x31, 0x80, 0, 0))

    def testPrimitiveValue(self):
        chunks = list(self.encoder(univ.Integer(5)))

        assert b''.join(chunks) == encoder.encode(univ.Integer(5))

    def testSequenceValue(self):
        value = univ.Sequence()
        value.setComponentByPosition(0, univ.Integer(5))

        substrate = b''.join(self.encoder(value))

        assert substrate == encoder.encode(value, defMode=False)


class StreamingEncoderLazinessTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.encoder = encoder.StreamingEncoder()
        self.schema = univ.SequenceOf(componentType=univ.Integer())

    def testFirstChunkDoesNotDrainSource(self):
        consumed = []

        def source():
            for idx in range(10):
                consumed.append(idx)
                yield idx

        stream = self.encoder(source(), asn1Spec=self.schema)

        chunk = next(stream)

        assert chunk == bytes((0x30, 0x80))
        assert consumed == []

        list(stream)

        assert consumed == list(range(10))


class StreamingEncoderErrorHandlingTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.encoder = encoder.StreamingEncoder()

    def testConstraintFailurePreservesExceptionAndPosition(self):
        schema = univ.SequenceOf(componentType=char.IA5String().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, 4)))

        collected = []

        try:
            for chunk in self.encoder(
                    iter(['ok', 'waytoolong', 'never']), asn1Spec=schema):
                collected.append(chunk)

        except ValueConstraintError as exc:
            assert 'position 1' in str(exc)

        else:
            assert 0, 'constraint violation tolerated'

        # no end-of-octets marker past the failing component
        assert bytes((0, 0)) not in collected

    def testDelegatedConstraintFailureUnwrapsOriginalException(self):
        schema = univ.SequenceOf(componentType=univ.ObjectIdentifier().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, 3)))

        try:
            list(self.encoder(iter(['1.2.3', '1.2.3.4.5']), asn1Spec=schema))

        except ValueConstraintError as exc:
            assert 'position 1' in str(exc)

        else:
            assert 0, 'constraint violation tolerated'


class StreamingEncoderDefiniteLengthTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.encoder = encoder.StreamingEncoder()
        self.schema = univ.SequenceOf(componentType=univ.Integer())

    def testSizedSourceIsSpooled(self):
        value = univ.SequenceOf(componentType=univ.Integer())
        value.extend([1, 2])

        substrate = b''.join(self.encoder(value, defMode=True))

        assert substrate == encoder.encode(value, defMode=True)

    def testOneShotSourceIsRejected(self):
        consumed = []

        def source():
            consumed.append(1)
            yield 1

        try:
            list(self.encoder(
                source(), asn1Spec=self.schema, defMode=True))

        except PyAsn1Error:
            pass

        else:
            assert 0, 'definite-length encoding of one-shot source tolerated'

        # the source must not be consumed even once
        assert consumed == []

    def testSpoolLimit(self):
        try:
            list(self.encoder(
                list(range(100)), asn1Spec=self.schema,
                defMode=True, maxSpoolSize=10))

        except PyAsn1Error:
            pass

        else:
            assert 0, 'spooled substrate above the limit tolerated'


class StreamingEncoderDecoderInterOpTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.encoder = encoder.StreamingEncoder()

    def testStreamingDecoderRoundTrip(self):
        schema = univ.SequenceOf(
            componentType=univ.OctetString()).subtype(
            explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 3))

        values = [b'ab', b'cdef', b'']

        streamed = b''.join(self.encoder(
            list(values), asn1Spec=schema, maxChunkSize=2))

        assert streamed == encoder.encode(
            list(values), asn1Spec=schema, defMode=False, maxChunkSize=2)

        streamedObject = list(StreamingDecoder(
            io.BytesIO(streamed), asn1Spec=schema))[0]

        referenceObject, _ = decoder.decode(
            encoder.encode(list(values), asn1Spec=schema), asn1Spec=schema)

        assert streamedObject == referenceObject
        assert [x.asOctets() for x in streamedObject] == values


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
