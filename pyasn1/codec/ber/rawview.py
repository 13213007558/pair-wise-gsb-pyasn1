#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2026, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import io

from pyasn1 import error

__all__ = ['RawSpan', 'RawSource', 'RawView']


class RawSpan(object):
    """Location of a single encoded item within a raw source.

    All offsets are half-open [start, end) positions into the
    RawSource this span belongs to (its 'source' attribute).
    Offsets are always relative to that source; use RawView.absolute
    to map a span onto the original decode substrate.
    """

    __slots__ = ('source', 'tagStart', 'tagEnd', 'valueStart', 'valueEnd')

    def __init__(self, source, tagStart, tagEnd, valueStart, valueEnd):
        self.source = source
        self.tagStart = tagStart
        self.tagEnd = tagEnd
        self.valueStart = valueStart
        self.valueEnd = valueEnd

    @property
    def tag(self):
        """Offsets of the tag octets, as a (start, end) tuple."""
        return self.tagStart, self.tagEnd

    @property
    def length(self):
        """Offsets of the length octets, as a (start, end) tuple."""
        return self.tagEnd, self.valueStart

    @property
    def value(self):
        """Offsets of the content octets, as a (start, end) tuple.

        For indefinite-length items the content octets include the
        trailing end-of-octets marker.
        """
        return self.valueStart, self.valueEnd

    @property
    def tlv(self):
        """Offsets of the complete TLV, as a (start, end) tuple.

        For indefinite-length items the complete TLV includes the
        terminating end-of-octets marker.
        """
        return self.tagStart, self.valueEnd

    def __repr__(self):
        return '%s(tag=%r, length=%r, value=%r)' % (
            self.__class__.__name__, self.tag, self.length, self.value)


class RawSource(object):
    """A byte source that RawSpan offsets index into.

    The first source of a RawView is the original decode substrate.
    A further source appears whenever a decoded ANY value is decoded
    once more as an open type: the new source covers the ANY octets
    and links back, via 'parent', to the ANY span those octets were
    taken from, so both layers of provenance are kept.

    Attributes
    ----------
    parent: RawSpan or None
        The ANY span this source was derived from. None for the
        original decode substrate.
    parentBase: int or None
        Offset within the parent source at which this source's octets
        begin. None if it could not be determined (or if 'parent'
        is None).
    """

    __slots__ = ('_buffer', '_stream', 'parent', 'parentBase')

    def __init__(self, buffer=None, stream=None, parent=None, parentBase=None):
        self._buffer = buffer
        self._stream = stream
        self.parent = parent
        self.parentBase = parentBase

    @property
    def buffered(self):
        """Whether raw octets are retained and available for slicing."""
        return self._buffer is not None or self._stream is not None

    def _slice(self, start, end):
        if self._buffer is None:
            if self._stream is None:
                raise error.PyAsn1Error(
                    'raw octets are not retained for this source; decode '
                    'from a bytes-like substrate or pass a sink callback')

            self._buffer = memoryview(self._stream.getbuffer())
            self._stream = None

        return self._buffer[start:end]


class _Node(object):
    __slots__ = ('span', 'obj')

    def __init__(self):
        self.span = None
        self.obj = None


class _TeeStream(object):
    """Pass-through stream reporting consumed octets to a sink."""

    def __init__(self, raw, sink):
        object.__setattr__(self, '_raw', raw)
        object.__setattr__(self, '_sink', sink)

    def __getattr__(self, name):
        return getattr(self._raw, name)

    def __setattr__(self, name, value):
        setattr(self._raw, name, value)

    def read(self, size=-1):
        offset = self._raw.tell()
        data = self._raw.read(size)
        if data and self._sink is not None:
            self._sink(offset, data)
        return data


class RawView(object):
    """Collect raw encoding locations of decoded ASN.1 objects.

    Signature verification needs the exact octets that were received,
    not a re-encoding (which may canonicalize them). Pass a RawView
    to the BER decoder and it records, for every decoded item, the
    offsets of its tag, length, value and complete TLV as found in
    the input:

    .. code-block:: pycon

        >>> view = RawView()
        >>> asn1Object, tail = decode(substrate, asn1Spec=spec, rawView=view)
        >>> view.tlv((0,))  # raw TLV of the first component

    The view is a side table: nothing is attached to the decoded ASN.1
    objects and their equality semantics are untouched. Locations are
    queried by field path -- a tuple of component positions (ints)
    and/or component names (strings) walking down the decoded
    structure.

    Parameters
    ----------
    sink: callable or None
        Only used with stream substrates, whose octets the view does
        not retain. sink(offset, data) is called with the absolute
        stream offset and the octets consumed at that offset, as the
        decoder consumes them; the caller is expected to save them
        (e.g. into a bytearray) and owns that copy. The same offset
        may be reported more than once (with identical data) when the
        decoder back-tracks. Spans recorded for a stream substrate
        index into the caller's saved octets.

    Notes
    -----
    Ownership: the view holds strong references to the decoded ASN.1
    objects, to the source buffers (for bytes-like substrates, without
    copying them) and to the decode streams, all released by clear().
    Octets reported through sink are owned by the caller and never
    retained by the view.

    One view tracks one decoder at a time. Non-seekable stream
    substrates are supported best-effort: offsets are only meaningful
    while the decoder's read cache has not been trimmed, so prefer
    bytes or seekable streams when raw locations matter.
    """

    def __init__(self, sink=None):
        self._sink = sink
        self._sources = []
        self._streamIds = {}
        self._keepalive = []
        self._roots = []
        self._stack = []
        self._index = {}

    @property
    def roots(self):
        """Top-level ASN.1 objects decoded into this view, as a tuple."""
        return tuple(node.obj for node in self._roots)

    @property
    def sources(self):
        """Raw sources known to this view, as a tuple of RawSource."""
        return tuple(self._sources)

    def clear(self):
        """Drop all recorded spans, sources and decoded object references."""
        self._sources = []
        self._streamIds = {}
        self._keepalive = []
        self._roots = []
        self._stack = []
        self._index = {}

    def spans(self, path=(), root=None):
        """Look up all encoding layers of the item at path.

        Parameters
        ----------
        path: tuple
            Component positions (ints) and/or component names (strings)
            walking from root down to the item of interest. The empty
            tuple addresses the top-level object itself.

        root: ASN.1 object, int or None
            The top-level decoded object to start from: the object
            itself or its index into roots. May be omitted when
            exactly one top-level object was decoded.

        Returns
        -------
        tuple of RawSpan
            Spans ordered outermost first. A plain field yields a
            single span; an explicitly tagged field yields the wrapper
            TLV span followed by the inner value span; an ANY field
            decoded as an open type yields the received ANY span
            followed by the span of the re-decoded value (relative to
            the ANY octets).
        """
        nodes = self._resolve(path, root)

        spans = []
        source = nodes[0].span.source
        while source.parent is not None:
            spans.insert(0, source.parent)
            source = source.parent.source

        spans.extend(node.span for node in nodes)

        return tuple(spans)

    def span(self, path=(), root=None):
        """Look up the innermost encoding span of the item at path.

        Takes the same arguments as spans().
        """
        return self.spans(path, root)[-1]

    def tag(self, path=(), root=None):
        """Raw tag octets of the item at path, as a memoryview."""
        span = self.span(path, root)
        return span.source._slice(span.tagStart, span.tagEnd)

    def length(self, path=(), root=None):
        """Raw length octets of the item at path, as a memoryview."""
        span = self.span(path, root)
        return span.source._slice(span.tagEnd, span.valueStart)

    def value(self, path=(), root=None):
        """Raw content octets of the item at path, as a memoryview."""
        span = self.span(path, root)
        return span.source._slice(span.valueStart, span.valueEnd)

    def tlv(self, path=(), root=None):
        """Complete raw TLV of the item at path, as a memoryview."""
        return self.slice(self.span(path, root))

    def slice(self, span):
        """Slice the complete raw TLV of span from its source."""
        return span.source._slice(span.tagStart, span.valueEnd)

    def absolute(self, span):
        """Map span onto the original decode substrate.

        Follows the source parent chain (e.g. of an open type decoded
        out of an ANY value) and returns an equivalent RawSpan whose
        offsets index into the top-level source.
        """
        source = span.source
        offsets = [span.tagStart, span.tagEnd, span.valueStart, span.valueEnd]

        while source.parent is not None:
            if source.parentBase is None:
                raise error.PyAsn1Error(
                    'cannot map span onto the original substrate: source '
                    'origin is unknown')

            offsets = [offset + source.parentBase for offset in offsets]
            source = source.parent.source

        return RawSpan(source, *offsets)

    def _resolve(self, path, root):
        if root is None:
            if len(self._roots) != 1:
                raise error.PyAsn1Error(
                    'pass the root explicitly: %d top-level objects were '
                    'decoded into this view' % len(self._roots))

            obj = self._roots[0].obj

        elif isinstance(root, int):
            obj = self._roots[root].obj

        else:
            obj = root

        for element in path:
            if isinstance(element, str):
                element = obj.componentType.getPositionByName(element)

            obj = obj.getComponentByPosition(element, instantiate=False)

        nodes = self._index.get(id(obj))

        if not nodes:
            raise error.PyAsn1Error(
                'no raw encoding recorded for the requested path')

        # inner items complete before their explicit-tag wrappers
        return sorted(
            nodes, key=lambda node: (node.span.tagStart, -node.span.valueEnd))

    def _track(self, stream, substrate=None):
        """Bind a top-level decode stream to a new source."""
        if id(stream) in self._streamIds:
            return stream

        if isinstance(substrate, (bytes, bytearray, memoryview)):
            source = RawSource(buffer=memoryview(substrate))

        elif isinstance(stream, io.BytesIO):
            source = RawSource(stream=stream)

        else:
            source = RawSource()
            stream = _TeeStream(stream, self._sink)

        self._sources.append(source)
        self._streamIds[id(stream)] = source
        self._keepalive.append(stream)

        return stream

    def _derive(self, stream, parentObj):
        """Bind a stream re-decoding a previously decoded ANY value."""
        if id(stream) in self._streamIds:
            return stream

        parentSpan = None
        parentBase = None

        nodes = self._index.get(id(parentObj))

        if nodes:
            size = len(parentObj.asOctets())

            for node in nodes:
                span = node.span
                if size == span.valueEnd - span.tagStart:
                    parentSpan, parentBase = span, span.tagStart
                    break
                elif size == span.valueEnd - span.valueStart:
                    parentSpan, parentBase = span, span.valueStart
                    break

            else:
                # provenance without a known origin offset
                parentSpan = nodes[0].span

        source = RawSource(
            stream=stream, parent=parentSpan, parentBase=parentBase)

        self._sources.append(source)
        self._streamIds[id(stream)] = source
        self._keepalive.append(stream)

        return stream

    def _open(self):
        self._stack.append(_Node())

    def _close(self, stream, tagStart, tagEnd, valueStart, valueEnd, obj):
        if not self._stack:
            return

        node = self._stack.pop()

        source = self._streamIds.get(id(stream))

        if source is None:
            source = RawSource()
            self._sources.append(source)
            self._streamIds[id(stream)] = source
            self._keepalive.append(stream)

        node.span = RawSpan(source, tagStart, tagEnd, valueStart, valueEnd)
        node.obj = obj

        if not self._stack:
            self._roots.append(node)

        self._index.setdefault(id(obj), []).append(node)

