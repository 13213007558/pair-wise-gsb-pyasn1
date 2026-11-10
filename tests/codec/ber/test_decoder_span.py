#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import hashlib
import io
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder as berEncoder
from pyasn1.codec.der import decoder as derDecoder
from pyasn1.codec.der import encoder as derEncoder
from pyasn1.error import SubstrateUnderrunError
from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ


class SpanCollector(object):
    """Collect spanFun reports and index them by object identity."""

    def __init__(self):
        self.ordered = []
        self.byId = {}

    def __call__(self, asn1Object, start, end):
        assert isinstance(start, int) and isinstance(end, int)
        assert 0 <= start <= end
        self.ordered.append((asn1Object, start, end))
        self.byId[id(asn1Object)] = (start, end)

    def spanOf(self, asn1Object):
        return self.byId[id(asn1Object)]

    def sliceOf(self, substrate, asn1Object):
        start, end = self.spanOf(asn1Object)
        return substrate[start:end]


class SchemalessSpanTestCase(BaseTestCase):
    def testDefiniteLength(self):
        substrate = b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03'

        spans = SpanCollector()
        asn1Object, tail = decoder.decode(substrate, spanFun=spans)

        assert tail == b''
        assert spans.spanOf(asn1Object) == (0, 11)

        # anonymous components are reported nevertheless
        components = [asn1Object[idx] for idx in range(len(asn1Object))]
        assert [spans.spanOf(c) for c in components] == [(2, 5), (5, 8), (8, 11)]

        # children complete before their container
        assert spans.ordered[-1][0] is asn1Object

        # every reported span slices out a TLV that re-decodes to the
        # very same value
        for component, start, end in spans.ordered:
            fragment, rest = decoder.decode(substrate[start:end])
            assert rest == b''
            assert fragment == component

    def testExplicitTagSchemaless(self):
        substrate = bytes((0xa3, 3, 2, 1, 5))

        spans = SpanCollector()
        asn1Object, _ = decoder.decode(substrate, spanFun=spans)

        # the explicit tag wrapper is transparent to the value: one
        # object, reported once per tag layer, innermost first, so the
        # last report covers the whole TLV
        assert isinstance(asn1Object, univ.Integer)
        assert asn1Object == 5
        assert [(start, end) for _, start, end in spans.ordered] == [(2, 5), (0, 5)]
        assert spans.spanOf(asn1Object) == (0, 5)


class SchemaGuidedSpanTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        class ImplicitInt(univ.Integer):
            tagSet = univ.Integer.tagSet.tagImplicitly(
                tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

        class ExplicitInt(univ.Integer):
            tagSet = univ.Integer.tagSet.tagExplicitly(
                tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))

        class Record(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('implicit', ImplicitInt()),
                namedtype.NamedType('explicit', ExplicitInt()),
                namedtype.NamedType('values', univ.SequenceOf(
                    componentType=univ.Integer())))

        self.substrate = bytes.fromhex('300d') + bytes.fromhex('830105') + \
            bytes.fromhex('a403020107') + bytes.fromhex('3003020108')
        self.schema = Record()

    def testNamedAndAnonymousComponents(self):
        spans = SpanCollector()
        asn1Object, tail = decoder.decode(
            self.substrate, asn1Spec=self.schema, spanFun=spans)

        assert tail == b''
        assert spans.spanOf(asn1Object) == (0, 15)

        # implicit tag: span covers the context-specific tag, not the
        # universal one it replaces
        assert spans.sliceOf(self.substrate, asn1Object['implicit']) == \
            bytes.fromhex('830105')

        # explicit tag: span covers the whole explicit wrapper
        assert spans.sliceOf(self.substrate, asn1Object['explicit']) == \
            bytes.fromhex('a403020107')

        # anonymous SequenceOf elements carry no name, still get spans
        values = asn1Object['values']
        assert spans.sliceOf(self.substrate, values) == bytes.fromhex('3003020108')
        assert spans.spanOf(values[0]) == (12, 15)

    def testDerDecoderInheritsRecording(self):
        asn1Object, _ = decoder.decode(self.substrate, asn1Spec=self.schema)
        substrate = derEncoder.encode(asn1Object)

        spans = SpanCollector()
        decoded, _ = derDecoder.decode(
            substrate, asn1Spec=self.schema, spanFun=spans)

        assert spans.spanOf(decoded) == (0, len(substrate))
        assert spans.sliceOf(substrate, decoded['implicit']) == \
            derEncoder.encode(decoded['implicit'])


class ChoiceSpanTestCase(BaseTestCase):
    def testUntaggedChoice(self):
        class Choice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.OctetString()))

        substrate = bytes.fromhex('020107')

        spans = SpanCollector()
        asn1Object, _ = decoder.decode(
            substrate, asn1Spec=Choice(), spanFun=spans)

        # untagged CHOICE shares its TLV with the chosen component
        assert spans.spanOf(asn1Object) == (0, 3)
        assert spans.spanOf(asn1Object['a']) == (0, 3)

    def testExplicitlyTaggedChoiceMember(self):
        class Choice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer().subtype(
                    explicitTag=tag.Tag(
                        tag.tagClassContext, tag.tagFormatConstructed, 2))))

        substrate = bytes.fromhex('a203020107')

        spans = SpanCollector()
        asn1Object, _ = decoder.decode(
            substrate, asn1Spec=Choice(), spanFun=spans)

        assert asn1Object['a'] == 7
        # the Choice node absorbs the explicit tag layer...
        assert spans.spanOf(asn1Object) == (0, 5)
        # ...while the component points at its own inner TLV
        assert spans.spanOf(asn1Object['a']) == (2, 5)


class ConstructedAndIndefiniteSpanTestCase(BaseTestCase):
    def testConstructedOctetStringDefinite(self):
        # constructed OCTET STRING of two primitive chunks
        substrate = bytes.fromhex('2409040261620403636465')

        spans = SpanCollector()
        asn1Object, _ = decoder.decode(substrate, spanFun=spans)

        assert bytes(asn1Object) == b'abcde'
        assert spans.spanOf(asn1Object) == (0, 11)

        # the chunks are real TLVs of the input and get reported as such
        chunkSpans = [(start, end) for _, start, end in spans.ordered[:-1]]
        assert chunkSpans == [(2, 6), (6, 11)]

    def testConstructedOctetStringIndefinite(self):
        substrate = bytes.fromhex('24800402616204036364650000')

        spans = SpanCollector()
        asn1Object, _ = decoder.decode(substrate, spanFun=spans)

        assert bytes(asn1Object) == b'abcde'
        # span end includes the end-of-contents octets
        assert spans.spanOf(asn1Object) == (0, 13)
        assert spans.sliceOf(substrate, asn1Object).endswith(b'\x00\x00')

    def testIndefiniteSequenceSchemaless(self):
        substrate = bytes.fromhex('30800201010201020000')

        spans = SpanCollector()
        asn1Object, _ = decoder.decode(substrate, spanFun=spans)

        # end-of-contents octets belong to the container's span
        assert spans.spanOf(asn1Object) == (0, 10)
        assert spans.spanOf(asn1Object[0]) == (2, 5)
        assert spans.spanOf(asn1Object[1]) == (5, 8)


class OpenTypeSpanTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        openType = opentype.OpenType(
            'id', {1: univ.Integer(), 2: univ.OctetString()})

        self.schema = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('id', univ.Integer()),
            namedtype.NamedType('blob', univ.Any(), openType=openType)))

    def testOpenTypeValueSpan(self):
        substrate = bytes((48, 6, 2, 1, 1, 2, 1, 5))

        spans = SpanCollector()
        asn1Object, _ = decoder.decode(
            substrate, asn1Spec=self.schema, decodeOpenTypes=True,
            spanFun=spans)

        # the open type value got decoded into an Integer replacing the
        # ANY placeholder; its span still points at the original TLV
        assert isinstance(asn1Object['blob'], univ.Integer)
        assert spans.sliceOf(substrate, asn1Object['blob']) == bytes((2, 1, 5))

    def testOpenTypeContainerSpan(self):
        openType = opentype.OpenType(
            'id', {3: univ.SequenceOf(componentType=univ.Integer())})

        schema = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('id', univ.Integer()),
            namedtype.NamedType('blob', univ.Any(), openType=openType)))

        substrate = bytes((48, 11, 2, 1, 3, 48, 6, 2, 1, 7, 2, 1, 8))

        spans = SpanCollector()
        asn1Object, _ = decoder.decode(
            substrate, asn1Spec=schema, decodeOpenTypes=True, spanFun=spans)

        blob = asn1Object['blob']
        assert isinstance(blob, univ.SequenceOf)
        assert spans.sliceOf(substrate, blob) == bytes((48, 6, 2, 1, 7, 2, 1, 8))
        # elements of the re-decoded container map into the original input
        assert spans.sliceOf(substrate, blob[0]) == bytes((2, 1, 7))
        assert spans.sliceOf(substrate, blob[1]) == bytes((2, 1, 8))


class IndefiniteOpenTypeSpanTestCase(BaseTestCase):
    def testOpenTypeValueSpanIndefinite(self):
        openType = opentype.OpenType('id', {1: univ.Integer()})

        schema = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('id', univ.Integer()),
            namedtype.NamedType('blob', univ.Any(), openType=openType)))

        substrate = bytes((48, 128, 2, 1, 1, 2, 1, 5, 0, 0))

        spans = SpanCollector()
        asn1Object, _ = decoder.decode(
            substrate, asn1Spec=schema, decodeOpenTypes=True, spanFun=spans)

        # re-decoded open type value lands in the original coordinates
        # even for an indefinite-length container
        assert spans.sliceOf(substrate, asn1Object['blob']) == bytes((2, 1, 5))
        assert spans.spanOf(asn1Object) == (0, 10)


class DripFeedStream(object):
    """Non-seekable stream serving the input in small chunks."""

    def __init__(self, data, chunkSize=5):
        self._data = data
        self._position = 0
        self._chunkSize = chunkSize

    def seekable(self):
        return False

    def read(self, size=-1):
        if self._position >= len(self._data):
            return b''

        if size == -1:
            size = self._chunkSize

        size = min(size, self._chunkSize, len(self._data) - self._position)
        chunk = self._data[self._position:self._position + size]
        self._position += size
        return chunk


class StreamingSpanTestCase(BaseTestCase):
    def testOffsetsSurvivePauseResumeAndCacheReset(self):
        # Enough small top-level items to overflow the caching stream
        # wrapper's buffer several times over: the wrapper drops its
        # cache and re-bases tell(), span offsets must not notice.
        count = io.DEFAULT_BUFFER_SIZE // 3 + 100
        substrate = b''.join(
            berEncoder.encode(univ.Integer(idx % 100)) for idx in range(count))

        spans = SpanCollector()
        values = [
            item for item in decoder.StreamingDecoder(
                DripFeedStream(substrate), spanFun=spans)
            if not isinstance(item, SubstrateUnderrunError)
        ]

        assert len(values) == count

        # all offsets are relative to the same input origin and slice
        # the exact TLV of each item
        for idx, asn1Object in enumerate(values):
            start, end = spans.spanOf(asn1Object)
            fragment = substrate[start:end]
            assert fragment == berEncoder.encode(univ.Integer(idx % 100))

        assert spans.spanOf(values[0]) == (0, 3)
        assert spans.spanOf(values[-1])[1] == len(substrate)


class SignatureEnvelopeExampleTestCase(BaseTestCase):
    """Verify a digest over the original bytes of a nested payload.

    The signer computed the digest over the exact TLV of the payload as
    transmitted. Since decode-then-encode does not necessarily reproduce
    those bytes, the verifier slices them out of the received substrate
    using the recorded span.
    """

    def setUp(self):
        BaseTestCase.setUp(self)

        class Payload(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('data', univ.OctetString()))

        class SignedEnvelope(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('payload', Payload()),
                namedtype.NamedType('digest', univ.OctetString()))

        self.SignedEnvelope = SignedEnvelope()

        payload = Payload()
        payload['id'] = 42
        payload['data'] = 'attack at dawn'
        self.payload = payload

    @staticmethod
    def _wrapEnvelope(payloadTlv, digest, indefinite):
        digestTlv = derEncoder.encode(univ.OctetString(digest))
        content = payloadTlv + digestTlv

        if indefinite:
            return b'\x30\x80' + content + b'\x00\x00'

        return b'\x30' + bytes((len(content),)) + content

    def testDigestRecomputedFromSpanSlice(self):
        # the sender used BER indefinite-length encoding; a DER
        # re-encode of the decoded payload would not reproduce it
        payloadTlv = berEncoder.encode(self.payload, defMode=False)
        digest = hashlib.sha256(payloadTlv).digest()
        envelope = self._wrapEnvelope(payloadTlv, digest, indefinite=True)

        spans = SpanCollector()
        asn1Object, tail = decoder.decode(
            envelope, asn1Spec=self.SignedEnvelope, spanFun=spans)

        assert tail == b''

        signedBytes = spans.sliceOf(envelope, asn1Object['payload'])
        assert signedBytes == payloadTlv
        assert hashlib.sha256(signedBytes).digest() == bytes(asn1Object['digest'])

        # the naive decode-then-encode route loses the signed bytes
        assert derEncoder.encode(asn1Object['payload']) != signedBytes

    def testEqualValuesDifferentRepresentations(self):
        # The signer signed the minimal-length form of the payload.
        # Two envelopes on the wire carry the same logical values --
        # same payload, same digest -- but one re-encodes the payload
        # with indefinite lengths. Decoded values compare equal, spans
        # tell the signed objects apart.
        payloadTlvDer = derEncoder.encode(self.payload)
        payloadTlvBer = berEncoder.encode(self.payload, defMode=False)
        assert payloadTlvDer != payloadTlvBer

        digest = hashlib.sha256(payloadTlvDer).digest()

        envelopeDer = self._wrapEnvelope(payloadTlvDer, digest, indefinite=False)
        envelopeBer = self._wrapEnvelope(payloadTlvBer, digest, indefinite=True)

        spansDer, spansBer = SpanCollector(), SpanCollector()
        decodedDer, _ = decoder.decode(
            envelopeDer, asn1Spec=self.SignedEnvelope, spanFun=spansDer)
        decodedBer, _ = decoder.decode(
            envelopeBer, asn1Spec=self.SignedEnvelope, spanFun=spansBer)

        # same decoded values, digest included...
        assert decodedDer == decodedBer
        assert decodedDer['payload'] == decodedBer['payload']

        # ...but different spans over different signed bytes
        assert spansDer.spanOf(decodedDer['payload']) != \
            spansBer.spanOf(decodedBer['payload'])
        sliceDer = spansDer.sliceOf(envelopeDer, decodedDer['payload'])
        sliceBer = spansBer.sliceOf(envelopeBer, decodedBer['payload'])
        assert sliceDer != sliceBer

        # only the slice of the representation the signer used verifies
        assert hashlib.sha256(sliceDer).digest() == digest
        assert hashlib.sha256(sliceBer).digest() != digest


class SpanRecordingDisabledTestCase(BaseTestCase):
    substrate = b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03'

    def testDefaultDecodeContractUnchanged(self):
        asn1Object, tail = decoder.decode(self.substrate)

        assert isinstance(asn1Object, univ.SequenceOf)
        assert tail == b''
        assert [int(x) for x in asn1Object] == [1, 2, 3]

    def testExplicitNoneContractUnchanged(self):
        withSpanFun, _ = decoder.decode(self.substrate, spanFun=lambda *args: None)
        withoutSpanFun, tail = decoder.decode(self.substrate, spanFun=None)

        assert withSpanFun == withoutSpanFun
        assert tail == b''

    def testStreamingContractUnchanged(self):
        values = list(decoder.StreamingDecoder(io.BytesIO(self.substrate)))
        assert [int(x) for x in values[0]] == [1, 2, 3]


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
