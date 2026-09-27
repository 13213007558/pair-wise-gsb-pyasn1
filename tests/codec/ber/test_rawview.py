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
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.codec.ber import decoder
from pyasn1.codec.der import encoder as derEncoder
from pyasn1 import error


class RawViewDefiniteLengthTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.s = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('a', univ.Integer()),
            namedtype.NamedType('b', univ.OctetString())
        ))

        # non-canonical but valid BER: long-form length on a 1-byte INTEGER
        self.substrate = bytes((
            0x30, 0x09, 0x02, 0x81, 0x01, 0x05, 0x04, 0x03, 0x01, 0x02, 0x03))

    def testSpans(self):
        view = decoder.RawView()
        s, r = decoder.decode(self.substrate, asn1Spec=self.s, rawView=view)

        assert not r

        assert view.tag(()) == bytes((0x30,))
        assert view.length(()) == bytes((0x09,))
        assert view.tlv(()) == self.substrate

        assert view.tag((0,)) == bytes((0x02,))
        assert view.length((0,)) == bytes((0x81, 0x01))
        assert view.value((0,)) == bytes((0x05,))
        assert view.tlv((0,)) == bytes((0x02, 0x81, 0x01, 0x05))

        assert view.tlv((1,)) == bytes((0x04, 0x03, 0x01, 0x02, 0x03))

    def testNamedPath(self):
        view = decoder.RawView()
        decoder.decode(self.substrate, asn1Spec=self.s, rawView=view)

        assert view.tlv(('a',)) == view.tlv((0,))
        assert view.tlv(('b',)) == view.tlv((1,))

    def testReceivedBytesNotReencoded(self):
        view = decoder.RawView()
        s, r = decoder.decode(self.substrate, asn1Spec=self.s, rawView=view)

        # DER canonicalizes the long-form length away
        assert derEncoder.encode(s) != self.substrate

        # the view hands back the received octets
        assert view.tlv((0,)) == self.substrate[2:6]
        assert bytes(view.tlv(())) == self.substrate

    def testZeroCopySlice(self):
        view = decoder.RawView()
        decoder.decode(self.substrate, asn1Spec=self.s, rawView=view)

        piece = view.tlv((0,))

        assert isinstance(piece, memoryview)
        assert piece.obj is self.substrate

    def testSchemaless(self):
        view = decoder.RawView()
        s, r = decoder.decode(self.substrate, rawView=view)

        assert view.tlv(()) == self.substrate
        assert view.tlv((0,)) == bytes((0x02, 0x81, 0x01, 0x05))
        assert view.tlv((1,)) == bytes((0x04, 0x03, 0x01, 0x02, 0x03))

    def testDecodedValuesUnchanged(self):
        withView, _ = decoder.decode(
            self.substrate, asn1Spec=self.s, rawView=decoder.RawView())
        plain, _ = decoder.decode(self.substrate, asn1Spec=self.s)

        assert withView == plain
        assert withView.isSameTypeWith(plain)

    def testClear(self):
        view = decoder.RawView()
        decoder.decode(self.substrate, asn1Spec=self.s, rawView=view)

        assert view.roots
        assert view.sources

        view.clear()

        assert not view.roots
        assert not view.sources

        try:
            view.span(())

        except error.PyAsn1Error:
            pass

        else:
            assert 0, 'query on a cleared view tolerated'


class RawViewIndefiniteLengthTestCase(BaseTestCase):
    def testConstructedOctetString(self):
        substrate = bytes((
            0x24, 0x80, 0x04, 0x01, 0x61, 0x04, 0x01, 0x62, 0x00, 0x00))

        view = decoder.RawView()
        s, r = decoder.decode(substrate, rawView=view)

        assert not r
        assert s == b'ab'

        span = view.span(())

        # the complete range includes the item's own EOC
        assert span.tlv == (0, 10)
        assert view.tlv(()) == substrate
        assert view.tag(()) == bytes((0x24,))
        assert view.length(()) == bytes((0x80,))

    def testNestedIndefinite(self):
        substrate = bytes((0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00))

        view = decoder.RawView()
        s, r = decoder.decode(
            substrate, asn1Spec=univ.SequenceOf(
                componentType=univ.Integer()), rawView=view)

        assert not r

        assert view.tlv(()) == substrate
        assert view.span(()).tlv == (0, 7)
        assert view.tlv((0,)) == bytes((0x02, 0x01, 0x05))
        assert view.span((0,)).tlv == (2, 5)


class RawViewExplicitTagTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.substrate = bytes((0xa0, 0x03, 0x02, 0x01, 0x05))
        self.s = univ.Integer().subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 0))

    def testWrapperAndInnerAreSeparateLayers(self):
        view = decoder.RawView()
        s, r = decoder.decode(self.substrate, asn1Spec=self.s, rawView=view)

        assert s == 5

        layers = view.spans(())

        assert len(layers) == 2

        outer, inner = layers

        # the explicit wrapper and the inner value are distinct ranges
        assert outer.tlv == (0, 5)
        assert inner.tlv == (2, 5)

        assert view.slice(outer) == self.substrate
        assert view.slice(inner) == bytes((0x02, 0x01, 0x05))

        # convenience accessors take the innermost layer
        assert view.tag(()) == bytes((0x02,))
        assert view.tlv(()) == bytes((0x02, 0x01, 0x05))


class RawViewOpenTypeTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        openType = opentype.OpenType(
            'id', {1: univ.Integer(), 2: univ.OctetString()})

        self.s = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('id', univ.Integer()),
            namedtype.NamedType('blob', univ.Any(), openType=openType)
        ))

        self.substrate = bytes((48, 6, 2, 1, 1, 2, 1, 12))

    def testBothLayersPreserved(self):
        view = decoder.RawView()
        s, r = decoder.decode(
            self.substrate, asn1Spec=self.s, decodeOpenTypes=True,
            rawView=view)

        assert not r
        assert s[1] == 12

        layers = view.spans((1,))

        assert len(layers) == 2

        anySpan, unwrappedSpan = layers

        # outer layer: the ANY as received, in the original substrate
        assert anySpan.source is view.sources[0]
        assert anySpan.tlv == (5, 8)

        # inner layer: the open type decode, relative to the ANY octets
        assert unwrappedSpan.source is view.sources[1]
        assert unwrappedSpan.tlv == (0, 3)
        assert view.sources[1].parent is anySpan

        assert view.tlv((1,)) == bytes((2, 1, 12))

        # the inner layer maps back onto the received bytes
        absolute = view.absolute(unwrappedSpan)
        assert absolute.tlv == (5, 8)
        assert view.slice(absolute) == bytes((2, 1, 12))

    def testUndecodedAnyIsSingleLayer(self):
        view = decoder.RawView()
        s, r = decoder.decode(self.substrate, asn1Spec=self.s, rawView=view)

        layers = view.spans((1,))

        assert len(layers) == 1
        assert layers[0].tlv == (5, 8)
        assert view.tlv((1,)) == bytes((2, 1, 12))


class RawViewStreamingTestCase(BaseTestCase):
    def testConsecutiveTopLevelObjects(self):
        view = decoder.RawView()

        objects = list(decoder.StreamingDecoder(
            io.BytesIO(bytes((2, 1, 1, 2, 1, 2))), rawView=view))

        assert objects == [1, 2]
        assert len(view.roots) == 2

        first = view.span(root=0)
        second = view.span(root=1)

        # both top-level objects index into the same source
        assert first.source is second.source
        assert first.tlv == (0, 3)
        assert second.tlv == (3, 6)

        assert view.tlv(root=0) == bytes((2, 1, 1))
        assert view.tlv(root=1) == bytes((2, 1, 2))

    def testRootByObject(self):
        view = decoder.RawView()

        objects = list(decoder.StreamingDecoder(
            io.BytesIO(bytes((2, 1, 1, 2, 1, 2))), rawView=view))

        assert view.span(root=objects[1]).tlv == (3, 6)

    def testAmbiguousRoot(self):
        view = decoder.RawView()

        list(decoder.StreamingDecoder(
            io.BytesIO(bytes((2, 1, 1, 2, 1, 2))), rawView=view))

        try:
            view.span(())

        except error.PyAsn1Error:
            pass

        else:
            assert 0, 'ambiguous root tolerated'


class RawViewStreamSinkTestCase(BaseTestCase):
    class Stream(object):
        """Minimal seekable stream that is not a BytesIO."""

        def __init__(self, data):
            self._data = data
            self._pos = 0

        def read(self, size=-1):
            if size < 0:
                size = len(self._data) - self._pos
            chunk = self._data[self._pos:self._pos + size]
            self._pos += len(chunk)
            return chunk

        def seek(self, offset, whence=0):
            if whence == 0:
                self._pos = offset
            elif whence == 1:
                self._pos += offset
            else:
                self._pos = len(self._data) + offset
            return self._pos

        def tell(self):
            return self._pos

        def seekable(self):
            return True

    def setUp(self):
        BaseTestCase.setUp(self)

        self.s = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('a', univ.Integer()),
            namedtype.NamedType('b', univ.OctetString())
        ))

        self.substrate = bytes((
            0x30, 0x09, 0x02, 0x81, 0x01, 0x05, 0x04, 0x03, 0x01, 0x02, 0x03))

    def testSinkReceivesConsumedOctets(self):
        saved = bytearray()

        def sink(offset, data):
            end = offset + len(data)
            if len(saved) < end:
                saved.extend(bytes(end - len(saved)))
            saved[offset:end] = data

        view = decoder.RawView(sink=sink)

        s, r = decoder.decode(
            self.Stream(self.substrate), asn1Spec=self.s, rawView=view)

        assert s[0] == 5

        # caller-assembled octets match the recorded spans
        span = view.span((0,))
        assert bytes(saved[span.tagStart:span.valueEnd]) == bytes(
            (0x02, 0x81, 0x01, 0x05))

        span = view.span(())
        assert bytes(saved[span.tagStart:span.valueEnd]) == self.substrate

    def testStreamOctetsNotRetained(self):
        view = decoder.RawView()

        decoder.decode(
            self.Stream(self.substrate), asn1Spec=self.s, rawView=view)

        # spans are still recorded and index into caller-saved octets
        assert view.span((0,)).tlv == (2, 6)

        try:
            view.tlv((0,))

        except error.PyAsn1Error:
            pass

        else:
            assert 0, 'slicing a caller-owned source tolerated'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)

