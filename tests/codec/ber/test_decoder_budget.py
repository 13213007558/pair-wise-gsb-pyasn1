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

from pyasn1.codec.ber import decoder
from pyasn1.codec.ber.decoder import DecodeBudget
from pyasn1.error import PyAsn1Error
from pyasn1.error import SubstrateUnderrunError
from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ


class NonBlockingStream(io.BytesIO):
    block = False

    def read(self, size=-1):
        self.block = not self.block
        if self.block:
            return  # this is what non-blocking streams sometimes do

        return io.BytesIO.read(self, size)


class DecodeBudgetConfigurationTestCase(BaseTestCase):

    def testDefaultsAreUnbounded(self):
        budget = DecodeBudget()
        assert budget.maxElements is None
        assert budget.maxContentOctets is None
        assert budget.maxNestingDepth is None

    def testNegativeLimitRejected(self):
        try:
            DecodeBudget(maxElements=-1)
        except PyAsn1Error:
            pass
        else:
            assert False, 'Negative decode budget tolerated'

    def testNonIntegerLimitRejected(self):
        try:
            DecodeBudget(maxContentOctets='100')
        except PyAsn1Error:
            pass
        else:
            assert False, 'Non-integer decode budget tolerated'

    def testNestingDepthOnlyTightensHardLimit(self):
        budget = DecodeBudget(maxNestingDepth=decoder.MAX_NESTING_DEPTH + 1000)
        assert budget.maxNestingDepth == decoder.MAX_NESTING_DEPTH

    def testLoosenedNestingDepthStillRejected(self):
        # 150 nested indefinite-length SEQUENCEs: 30 80 ... 00 00 ...
        substrate = b'\x30\x80' * 150 + b'\x00\x00' * 150

        try:
            decoder.decode(
                substrate,
                decodeBudget=DecodeBudget(maxNestingDepth=1000))
        except PyAsn1Error as exc:
            assert 'nesting depth' in str(exc)
        else:
            assert False, 'Nesting past the hard limit tolerated'


class ElementBudgetTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        # SET (31) of five NULLs: short substrate, many elements.
        # One element for the container plus one per NULL: 6 in total.
        self.substrate = bytes((0x31, 10) + (0x05, 0x00) * 5)

    def testAtLimitDecodes(self):
        s, r = decoder.decode(
            self.substrate, decodeBudget=DecodeBudget(maxElements=6))

        assert not r
        assert len(s) == 5

    def testOneOverLimitRejected(self):
        try:
            decoder.decode(
                self.substrate, decodeBudget=DecodeBudget(maxElements=5))
        except PyAsn1Error as exc:
            assert 'element' in str(exc)
        else:
            assert False, 'Excessive decoded elements tolerated'


class ContentOctetBudgetTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        # Constructed OCTET STRING (24) in three forms, each assembling
        # the same four content octets AA BB CC DD from two fragments
        self.substrates = (
            # definite-length constructed
            bytes((0x24, 0x08,
                   0x04, 0x02, 0xAA, 0xBB,
                   0x04, 0x02, 0xCC, 0xDD)),
            # indefinite-length constructed, terminated by EOO
            bytes((0x24, 0x80,
                   0x04, 0x02, 0xAA, 0xBB,
                   0x04, 0x02, 0xCC, 0xDD,
                   0x00, 0x00)),
            # indefinite-length constructed of definite-length constructed
            # fragments: nesting must not hand out fresh budget
            bytes((0x24, 0x80,
                   0x24, 0x04, 0x04, 0x02, 0xAA, 0xBB,
                   0x24, 0x04, 0x04, 0x02, 0xCC, 0xDD,
                   0x00, 0x00)),
        )

    def testAtLimitDecodes(self):
        for substrate in self.substrates:
            with self.subTest(substrate=substrate):
                s, r = decoder.decode(
                    substrate, decodeBudget=DecodeBudget(maxContentOctets=4))

                assert not r
                assert s == univ.OctetString(bytes((0xAA, 0xBB, 0xCC, 0xDD)))

    def testOneOverLimitRejected(self):
        for substrate in self.substrates:
            with self.subTest(substrate=substrate):
                try:
                    decoder.decode(
                        substrate, decodeBudget=DecodeBudget(maxContentOctets=3))
                except PyAsn1Error as exc:
                    assert 'content octets' in str(exc)
                else:
                    assert False, 'Excessive content octets tolerated'

    def testOversizedLengthRejectedBeforeReadingValue(self):
        # Primitive OCTET STRING declaring 1024 content octets, of which
        # only 10 are actually present: the budget must trip on the
        # declared length, before the value octets are read
        substrate = bytes((0x04, 0x82, 0x04, 0x00)) + b'x' * 10

        try:
            decoder.decode(
                substrate, decodeBudget=DecodeBudget(maxContentOctets=100))
        except SubstrateUnderrunError:
            assert False, 'Got SubstrateUnderrunError instead of budget error'
        except PyAsn1Error as exc:
            assert 'content octets' in str(exc)
        else:
            assert False, 'Oversized declared content tolerated'


class NestingDepthBudgetTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        # SEQUENCE { SEQUENCE { INTEGER 5 } }: nesting levels 0, 1, 2
        self.substrate = bytes((0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x05))

    def testAtLimitDecodes(self):
        s, r = decoder.decode(
            self.substrate, decodeBudget=DecodeBudget(maxNestingDepth=2))

        assert not r

    def testOneOverLimitRejected(self):
        try:
            decoder.decode(
                self.substrate, decodeBudget=DecodeBudget(maxNestingDepth=1))
        except PyAsn1Error as exc:
            assert 'nesting depth' in str(exc)
        else:
            assert False, 'Excessive nesting depth tolerated'


class OpenTypeBudgetTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType(
                    'blob', univ.Any().subtype(
                        implicitTag=tag.Tag(
                            tag.tagClassContext, tag.tagFormatSimple, 3)),
                    openType=openType
                )
            )
        )

        # SEQUENCE { id INTEGER 1, blob [3] ANY (INTEGER 12) }: the open
        # type payload is decoded twice (as ANY, then as INTEGER), and
        # both passes draw on the same budget: 4 elements and
        # 1 + 3 + 1 content octets in total
        self.substrate = bytes((48, 8, 2, 1, 1, 131, 3, 2, 1, 12))

    def testAtLimitDecodes(self):
        s, r = decoder.decode(
            self.substrate, asn1Spec=self.s, decodeOpenTypes=True,
            decodeBudget=DecodeBudget(maxElements=4, maxContentOctets=5))

        assert not r
        assert s[0] == 1
        assert s[1] == 12

    def testOneElementOverLimitRejected(self):
        try:
            decoder.decode(
                self.substrate, asn1Spec=self.s, decodeOpenTypes=True,
                decodeBudget=DecodeBudget(maxElements=3))
        except PyAsn1Error as exc:
            assert 'element' in str(exc)
        else:
            assert False, 'Open type decode regained element budget'

    def testOneContentOctetOverLimitRejected(self):
        try:
            decoder.decode(
                self.substrate, asn1Spec=self.s, decodeOpenTypes=True,
                decodeBudget=DecodeBudget(maxContentOctets=4))
        except PyAsn1Error as exc:
            assert 'content octets' in str(exc)
        else:
            assert False, 'Open type decode regained content octet budget'


class StreamingBudgetTestCase(BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)

        # SEQUENCE OF two OCTET STRINGs 'quick brown': 3 elements and
        # 22 content octets in total
        self.source = (bytes((48, 26, 4, 11)) + b'quick brown' +
                       bytes((4, 11)) + b'quick brown')

    def testResumeAccumulatesWithoutDoubleCharging(self):
        budget = DecodeBudget(maxElements=3, maxContentOctets=22)
        stream = NonBlockingStream(self.source)

        iterator = iter(decoder.StreamingDecoder(stream, decodeBudget=budget))

        counts = []
        result = None

        while result is None:
            res = next(iterator)

            if isinstance(res, SubstrateUnderrunError):
                state = res.context['_decodeBudget']
                counts.append((state.elementsUsed, state.contentOctetsUsed))

            else:
                result = res

        assert isinstance(result, univ.SequenceOf)
        assert len(result) == 2

        # counters only ever accumulate across pauses, never restart
        assert counts, 'No underrun observed on non-blocking stream'
        for previous, current in zip(counts, counts[1:]):
            assert previous[0] <= current[0]
            assert previous[1] <= current[1]

        assert counts[-1] == (3, 22)

    def testUnderrunRemainsRecoverable(self):
        budget = DecodeBudget(maxElements=10)
        stream = NonBlockingStream(self.source)

        iterator = iter(decoder.StreamingDecoder(stream, decodeBudget=budget))

        res = next(iterator)
        assert isinstance(res, SubstrateUnderrunError)

        result = None
        while result is None:
            res = next(iterator)
            if not isinstance(res, SubstrateUnderrunError):
                result = res

        assert len(result) == 2

    def testInterleavedDecodersHaveIndependentCounters(self):
        # SEQUENCE { NULL }: 2 elements per decoder; a shared counter
        # would accumulate 4 and trip the budget of 2
        budget = DecodeBudget(maxElements=2)
        substrate = bytes((0x30, 0x02, 0x05, 0x00))

        iterators = [
            iter(decoder.StreamingDecoder(
                NonBlockingStream(substrate), decodeBudget=budget)),
            iter(decoder.StreamingDecoder(
                NonBlockingStream(substrate), decodeBudget=budget)),
        ]

        results = [None, None]

        for _ in range(20):
            for idx, iterator in enumerate(iterators):
                if results[idx] is None:
                    res = next(iterator)
                    if not isinstance(res, SubstrateUnderrunError):
                        results[idx] = res

        assert all(isinstance(result, univ.SequenceOf) for result in results)

    def testMutationDuringDecodeDoesNotApply(self):
        budget = DecodeBudget(maxElements=2)
        substrate = bytes((0x30, 0x02, 0x05, 0x00))

        iterator = iter(decoder.StreamingDecoder(
            NonBlockingStream(substrate), decodeBudget=budget))

        res = next(iterator)
        assert isinstance(res, SubstrateUnderrunError)

        # tightening the configuration object now must not change the
        # limits of the decode already in progress
        budget.maxElements = 1

        result = None
        for _ in range(10):
            res = next(iterator)
            if not isinstance(res, SubstrateUnderrunError):
                result = res
                break

        assert isinstance(result, univ.SequenceOf)

        # a decode started later does see the mutated configuration
        try:
            decoder.decode(substrate, decodeBudget=budget)
        except PyAsn1Error as exc:
            assert 'element' in str(exc)
        else:
            assert False, 'Mutated budget not picked up by a new decode'

    def testBudgetErrorDoesNotContinueWithNextMessage(self):
        # SEQUENCE { NULL, NULL } (3 elements, over the budget of 2)
        # followed by a well-formed INTEGER: the budget error must
        # surface, not skip ahead to the second message
        substrate = (bytes((0x30, 0x04, 0x05, 0x00, 0x05, 0x00)) +
                     bytes((0x02, 0x01, 0x05)))

        iterator = iter(decoder.StreamingDecoder(
            io.BytesIO(substrate), decodeBudget=DecodeBudget(maxElements=2)))

        try:
            next(iterator)
        except PyAsn1Error as exc:
            assert 'element' in str(exc)
        else:
            assert False, 'Excessive decoded elements tolerated'

        try:
            next(iterator)
        except StopIteration:
            pass
        else:
            assert False, 'Decoder continued with the next message'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
