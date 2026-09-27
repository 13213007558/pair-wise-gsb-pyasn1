#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, pyasn1 contributors
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import schema_compat
from pyasn1.type import tag
from pyasn1.type import univ


def integer_schema(start, stop):
    class Integer(univ.Integer):
        subtypeSpec = constraint.ConstraintsIntersection(
            constraint.ValueRangeConstraint(start, stop))

    return Integer()


class SchemaCompatibilityTestCase(BaseTestCase):

    def assert_old_witness_rejected(self, result, new_schema):
        assert result.status == schema_compat.INCOMPATIBLE
        witness = result.counterexample
        assert witness is not None
        encoded = encoder.encode(witness)
        try:
            decoded, rest = decoder.decode(encoded, asn1Spec=new_schema)
        except PyAsn1Error:
            return
        assert rest == b''
        if decoded.isInconsistent:
            return
        try:
            encoder.encode(decoded)
        except PyAsn1Error:
            return
        assert False, 'new schema accepted counterexample'

    def test_integer_range_tightening_is_incompatible(self):
        result = schema_compat.compare_schemas(
            integer_schema(0, 10), integer_schema(0, 5))

        assert result.status == schema_compat.INCOMPATIBLE
        assert result.path == ()
        assert result.counterexample == 6
        self.assert_old_witness_rejected(result, integer_schema(0, 5))

    def test_integer_range_widening_is_compatible(self):
        result = schema_compat.compare_schemas(
            integer_schema(0, 5), integer_schema(0, 10))

        assert result.status == schema_compat.COMPATIBLE
        assert result.compatible
        assert result.tag_compatible

    def test_enumerated_value_set_uses_value_domain(self):
        class OldEnum(univ.Enumerated):
            namedValues = namedval.NamedValues(('a', 1), ('b', 2))

        class NewEnum(univ.Enumerated):
            namedValues = namedval.NamedValues(('a', 1))

        result = schema_compat.compare_schemas(OldEnum(), NewEnum())

        assert result.status == schema_compat.INCOMPATIBLE
        assert result.counterexample == 2
        self.assert_old_witness_rejected(result, NewEnum())

    def test_decidable_union_direction(self):
        old_schema = univ.Integer(subtypeSpec=constraint.ConstraintsUnion(
            constraint.ValueRangeConstraint(0, 2),
            constraint.ValueRangeConstraint(4, 5)))
        widened = integer_schema(0, 10)
        narrowed = univ.Integer(subtypeSpec=constraint.ConstraintsUnion(
            constraint.ValueRangeConstraint(0, 2)))

        assert schema_compat.compare_schemas(old_schema, widened).compatible
        result = schema_compat.compare_schemas(old_schema, narrowed)
        assert result.status == schema_compat.INCOMPATIBLE
        assert result.counterexample == 4
        self.assert_old_witness_rejected(result, narrowed)

    def test_size_tightening_is_incompatible(self):
        class OldOf(univ.SequenceOf):
            componentType = univ.Integer()
            subtypeSpec = constraint.ConstraintsIntersection(
                constraint.ValueSizeConstraint(0, 2))

        class NewOf(univ.SequenceOf):
            componentType = univ.Integer()
            subtypeSpec = constraint.ConstraintsIntersection(
                constraint.ValueSizeConstraint(0, 1))

        result = schema_compat.compare_schemas(OldOf(), NewOf())

        assert result.status == schema_compat.INCOMPATIBLE
        assert result.path == ()
        assert result.counterexample_native == [1, 1]
        self.assert_old_witness_rejected(result, NewOf())

    def test_of_element_tightening_reports_element_path(self):
        class OldOf(univ.SequenceOf):
            componentType = integer_schema(0, 10)

        class NewOf(univ.SequenceOf):
            componentType = integer_schema(0, 5)

        result = schema_compat.compare_schemas(OldOf(), NewOf())

        assert result.status == schema_compat.INCOMPATIBLE
        assert result.path == (0,)
        assert result.counterexample_native == [6]
        self.assert_old_witness_rejected(result, NewOf())

    def test_sequence_required_field_added(self):
        class OldSequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()))

        class NewSequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.Integer()))

        result = schema_compat.compare_schemas(OldSequence(), NewSequence())

        assert result.status == schema_compat.INCOMPATIBLE
        assert result.path == ('b',)
        assert result.counterexample_native == {'a': 0}
        self.assert_old_witness_rejected(result, NewSequence())

    def test_sequence_optional_field_added_is_compatible(self):
        class OldSequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()))

        class NewSequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.OptionalNamedType('b', univ.Integer()))

        result = schema_compat.compare_schemas(OldSequence(), NewSequence())

        assert result.compatible

    def test_sequence_optional_becomes_required(self):
        class OldSequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.OptionalNamedType('b', univ.Integer()))

        class NewSequence(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', univ.Integer()),
                namedtype.NamedType('b', univ.Integer()))

        result = schema_compat.compare_schemas(OldSequence(), NewSequence())

        assert result.status == schema_compat.INCOMPATIBLE
        assert result.path == ('b',)
        assert result.counterexample_native == {'a': 0}
        self.assert_old_witness_rejected(result, NewSequence())

    def test_sequence_nested_field_tightening(self):
        class InnerOld(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('value', integer_schema(0, 10)))

        class InnerNew(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('value', integer_schema(0, 5)))

        class OuterOld(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('inner', InnerOld()))

        class OuterNew(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('inner', InnerNew()))

        result = schema_compat.compare_schemas(OuterOld(), OuterNew())

        assert result.path == ('inner', 'value')
        assert result.counterexample_native == {'inner': {'value': 6}}
        self.assert_old_witness_rejected(result, OuterNew())

    def test_choice_alternative_removed(self):
        class OldChoice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('number', univ.Integer()),
                namedtype.NamedType('bytes', univ.OctetString()))

        class NewChoice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('number', univ.Integer()))

        result = schema_compat.compare_schemas(OldChoice(), NewChoice())

        assert result.status == schema_compat.INCOMPATIBLE
        assert result.path == ('bytes',)
        assert result.counterexample_native == {'bytes': b'a'}
        self.assert_old_witness_rejected(result, NewChoice())

    def test_choice_alternative_added_is_compatible(self):
        class OldChoice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('number', univ.Integer()))

        class NewChoice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('number', univ.Integer()),
                namedtype.NamedType('bytes', univ.OctetString()))

        assert schema_compat.compare_schemas(OldChoice(), NewChoice()).compatible

    def test_choice_alternative_value_tightening(self):
        class OldChoice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('number', integer_schema(0, 10)))

        class NewChoice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('number', integer_schema(0, 5)))

        result = schema_compat.compare_schemas(OldChoice(), NewChoice())

        assert result.path == ('number',)
        assert result.counterexample_native == {'number': 6}
        self.assert_old_witness_rejected(result, NewChoice())

    def test_tag_conflict_has_wire_reason(self):
        tagged_integer = univ.Integer().subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 0))

        result = schema_compat.compare_schemas(
            tagged_integer, univ.Integer())

        assert result.status == schema_compat.INCOMPATIBLE
        assert not result.tag_compatible
        assert result.path == ()
        assert result.wire_reason is not None
        self.assert_old_witness_rejected(result, univ.Integer())

    def test_recursive_schema_uses_visited_pairs(self):
        class OldNode(univ.Sequence):
            pass

        class NewNode(univ.Sequence):
            pass

        OldNode.componentType = namedtype.NamedTypes(
            namedtype.NamedType('value', integer_schema(0, 10)),
            namedtype.OptionalNamedType('next', OldNode()))
        NewNode.componentType = namedtype.NamedTypes(
            namedtype.NamedType('value', integer_schema(0, 5)),
            namedtype.OptionalNamedType('next', NewNode()))

        result = schema_compat.compare_schemas(OldNode(), NewNode())

        assert result.status == schema_compat.INCOMPATIBLE
        assert result.path == ('value',)
        assert result.counterexample_native == {'value': 6}
        self.assert_old_witness_rejected(result, NewNode())

    def test_identical_recursive_schema_is_compatible(self):
        class Node(univ.Sequence):
            pass

        Node.componentType = namedtype.NamedTypes(
            namedtype.NamedType('value', univ.Integer()),
            namedtype.OptionalNamedType('next', Node()))

        assert schema_compat.compare_schemas(Node(), Node()).compatible

    def test_custom_python_constraint_is_unknown(self):
        class CustomConstraint(constraint.AbstractConstraint):
            def _testValue(self, value, idx):
                if value != 1:
                    raise constraint.error.ValueConstraintError(value)

        old_schema = univ.Integer(
            subtypeSpec=constraint.ConstraintsIntersection(
                CustomConstraint(1)))

        result = schema_compat.compare_schemas(old_schema, univ.Integer())

        assert result.status == schema_compat.UNKNOWN
        assert not result.compatible
        assert result.counterexample is None
        assert result.reason


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
