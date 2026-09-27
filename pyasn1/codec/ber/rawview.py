#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2026, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import io

from pyasn1 import error
from pyasn1.type import univ

__all__ = ['RawView', 'RawSpan', 'RawSourceLayer', 'RecordingStream']


class RecordingStream(io.IOBase):
    """Seekable byte stream that records everything it reads.

    Wraps an arbitrary (possibly non-seekable) stream. Every byte pulled
    from the wrapped stream is appended to an internal buffer, so all
    previously read positions remain seekable and stream offsets stay
    absolute for the lifetime of the decode.
    """

    def __init__(self, rawStream):
        self._rawStream = rawStream
        self._recorded = bytearray()
        self._position = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    @property
    def recorded(self):
        """Bytes consumed from the wrapped stream so far."""
        return self._recorded

    def tell(self):
        return self._position

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            position = offset

        elif whence == io.SEEK_CUR:
            position = self._position + offset

        elif whence == io.SEEK_END:
            position = len(self._recorded) + offset

        else:
            raise ValueError('Invalid whence: %r' % (whence,))

        if not 0 <= position <= len(self._recorded):
            raise ValueError(
                'Seek outside recorded data: %r' % (position,))

        self._position = position

        return position

    def read(self, size=-1):
        if size is None or size < 0:
            if self._position < len(self._recorded):
                chunk = bytes(self._recorded[self._position:])
                self._position = len(self._recorded)
                return chunk

            chunk = self._rawStream.read()

            if chunk:
                self._recorded += chunk
                self._position = len(self._recorded)

            return chunk

        available = len(self._recorded) - self._position

        if available >= size:
            chunk = bytes(
                self._recorded[self._position:self._position + size])
            self._position += size
            return chunk

        start = self._position

        chunk = self._rawStream.read(size - available)

        if chunk is None:  # non-blocking stream can do this
            if not available:
                return None

        else:
            self._recorded += chunk

        self._position = len(self._recorded)

        return bytes(self._recorded[start:self._position])


class RawSpan(object):
    """Byte ranges of one decoded TLV within its source layer.

    All offsets are absolute positions in the source the layer was
    built from. For an indefinite-length TLV, `valueRange` covers
    the content octets only, while `fullRange` additionally
    includes the trailing end-of-octets marker.
    """

    __slots__ = ('source', 'asn1Object', 'tagStart', 'tagEnd',
                 'valueStart', 'valueEnd', 'tlvEnd', 'indefinite')

    def __init__(self, source, asn1Object, tagStart, tagEnd,
                 valueStart, valueEnd, tlvEnd, indefinite):
        self.source = source
        self.asn1Object = asn1Object
        self.tagStart = tagStart
        self.tagEnd = tagEnd
        self.valueStart = valueStart
        self.valueEnd = valueEnd
        self.tlvEnd = tlvEnd
        self.indefinite = indefinite

    @property
    def tagRange(self):
        """(start, end) offsets of the tag octets."""
        return self.tagStart, self.tagEnd

    @property
    def lengthRange(self):
        """(start, end) offsets of the length octets."""
        return self.tagEnd, self.valueStart

    @property
    def valueRange(self):
        """(start, end) offsets of the content octets (EOC excluded)."""
        return self.valueStart, self.valueEnd

    @property
    def fullRange(self):
        """(start, end) offsets of the whole TLV (EOC included)."""
        return self.tagStart, self.tlvEnd

    @property
    def tagOctets(self):
        return self.source._slice(self.tagStart, self.tagEnd)

    @property
    def lengthOctets(self):
        return self.source._slice(self.tagEnd, self.valueStart)

    @property
    def valueOctets(self):
        return self.source._slice(self.valueStart, self.valueEnd)

    @property
    def fullOctets(self):
        return self.source._slice(self.tagStart, self.tlvEnd)

    def __repr__(self):
        return '%s(%r..%r)' % (
            self.__class__.__name__, self.tagStart, self.tlvEnd)


class RawSourceLayer(object):
    """Coordinate space of a single substrate stream.

    Most decodes have exactly one layer. A new layer appears whenever
    the decoder starts reading from a different stream, e.g. when an
    ANY value is re-decoded as an open type: the inner TLVs are then
    located relative to the ANY octets, and `parentSpan` links
    back to the ANY span in the original source.
    """

    def __init__(self, stream, buffer, parentSpan):
        self.stream = stream
        self.parentSpan = parentSpan
        self._buffer = buffer
        self._spansByObjectId = {}
        self._released = False

    @property
    def isZeroCopy(self):
        """Whether octet slices are zero-copy views of the source."""
        return self._buffer is not None

    def _slice(self, start, end):
        if self._released:
            raise error.PyAsn1Error(
                'Raw encoding view source has been released')

        if self._buffer is not None:
            return self._buffer[start:end]

        if isinstance(self.stream, RecordingStream):
            return bytes(self.stream.recorded[start:end])

        raise error.PyAsn1Error(
            'No raw octets were recorded for this source')

    def release(self):
        """Drop this layer's reference to its source octets."""
        self._buffer = None

        if isinstance(self.stream, RecordingStream):
            self.stream = None

        self._released = True


class RawView(object):
    """Collects raw substrate ranges of decoded TLVs.

    Pass an instance as the `rawView` option to
    :py:class:`~pyasn1.codec.ber.decoder.Decoder` or
    :py:class:`~pyasn1.codec.ber.decoder.StreamingDecoder` (the
    CER and DER decoders accept it as well). After decoding, the byte
    ranges of the tag, length, value and full TLV of every decoded
    object can be looked up by the object itself or by a field path,
    without any metadata being attached to (or changing the equality
    of) the ASN.1 values.

    For `bytes`-like substrates the octet accessors of
    :py:class:`RawSpan` return zero-copy
    :py:class:`memoryview` slices of the caller's buffer. For
    stream substrates the consumed input is recorded internally and the
    `onRawEncoding` callback, if given, is invoked with each
    completed TLV so the caller can save the bytes; the recording is
    referenced by this view until :py:meth:`release` is called.

    Parameters
    ----------
    onRawEncoding: callable
        Optional `callback(span, octets)` invoked on every
        completed TLV, where `octets` are the full TLV bytes as
        received.
    """

    def __init__(self, onRawEncoding=None):
        self._onRawEncoding = onRawEncoding
        self._layers = []
        self._adaptedBuffers = {}
        self._pendingSourceObject = None

    @property
    def layers(self):
        """Source layers seen so far, in order of appearance."""
        return tuple(self._layers)

    def adaptSubstrate(self, substrate):
        """Prepare a substrate for decoding with this view.

        Returns the substrate to decode from, possibly wrapped, and
        arranges for the source octets to be available to the spans
        recorded later. Called by the decoder entry points.
        """
        if isinstance(substrate, (RecordingStream, io.BytesIO)):
            return substrate

        if isinstance(substrate, (bytes, bytearray, memoryview)):
            stream = io.BytesIO(substrate)
            self._adaptedBuffers[id(stream)] = (
                stream, memoryview(substrate))
            return stream

        if isinstance(substrate, univ.OctetString):
            octets = substrate.asOctets()
            stream = io.BytesIO(octets)
            self._adaptedBuffers[id(stream)] = (
                stream, memoryview(octets))
            return stream

        try:
            substrate.seekable()

        except AttributeError:
            raise error.UnsupportedSubstrateError(
                'Cannot convert ' + substrate.__class__.__name__ +
                ' to a seekable bit stream.')

        return RecordingStream(substrate)

    def linkNextSource(self, asn1Object):
        """Mark the next decoder-created source as derived from an object.

        Used by the decoder when an ANY value is re-decoded as an open
        type: the new source layer is linked to the span of
        `asn1Object` in the original source.
        """
        self._pendingSourceObject = asn1Object

    def spansFor(self, asn1Object):
        """Return all spans recorded for an ASN.1 object.

        A single object can decode through nested TLVs (explicit
        tagging): the returned list is ordered innermost first, so the
        last span is the outermost wrapper.
        """
        for layer in reversed(self._layers):
            spans = layer._spansByObjectId.get(id(asn1Object))
            if spans:
                return list(spans)

        return []

    def spanFor(self, asn1Object):
        """Return the outermost span recorded for an ASN.1 object."""
        spans = self.spansFor(asn1Object)

        if spans:
            return spans[-1]

    def lookup(self, rootObject, path):
        """Return the outermost span of a component by field path.

        `path` is a sequence of component positions (int) and/or
        component names (str) applied to `rootObject`.
        """
        asn1Object = rootObject

        for element in path:
            asn1Object = asn1Object[element]

        return self.spanFor(asn1Object)

    def release(self):
        """Drop this view's references to the source octets.

        Ranges remain queryable afterwards, but the octet accessors of
        existing spans raise
        :py:class:`~pyasn1.error.PyAsn1Error`. References the
        view holds to decoded ASN.1 objects are kept, as they key the
        lookup tables.
        """
        for layer in self._layers:
            layer.release()

        self._adaptedBuffers.clear()

    def _layerFor(self, substrate):
        for layer in self._layers:
            if layer.stream is substrate:
                return layer

        adapted = self._adaptedBuffers.pop(id(substrate), None)

        if adapted is not None:
            buffer = adapted[1]

        elif isinstance(substrate, io.BytesIO):
            buffer = substrate.getbuffer()

        else:
            buffer = None

        parentSpan = None

        if self._pendingSourceObject is not None:
            parentSpan = self.spanFor(self._pendingSourceObject)
            self._pendingSourceObject = None

        layer = RawSourceLayer(substrate, buffer, parentSpan)

        self._layers.append(layer)

        return layer

    def _record(self, substrate, asn1Object, tagStart, tagEnd,
                valueStart, valueEnd, tlvEnd, indefinite):
        layer = self._layerFor(substrate)

        span = RawSpan(
            layer, asn1Object, tagStart, tagEnd,
            valueStart, valueEnd, tlvEnd, indefinite)

        layer._spansByObjectId.setdefault(id(asn1Object), []).append(span)

        if self._onRawEncoding is not None:
            self._onRawEncoding(span, layer._slice(tagStart, tlvEnd))

