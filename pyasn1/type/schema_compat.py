#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, pyasn1 contributors
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
from pyasn1.type import base
from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

__all__ = ['COMPATIBLE', 'INCOMPATIBLE', 'UNKNOWN',
           'CompatibilityResult', 'compare_schemas', 'is_compatible']

COMPATIBLE = 'compatible'
INCOMPATIBLE = 'incompatible'
UNKNOWN = 'unknown'

INFINITY = float('inf')


class _UnknownDomain(object):
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = object.__new__(cls)
        return cls._instance


UNKNOWN_DOMAIN = _UnknownDomain()


class _IntervalSet(object):
    def __init__(self, intervals):
        self.intervals = tuple(intervals)

    def sample(self):
        candidates = []
        for start, stop in self.intervals:
            candidates.append((abs(start), start))
            if start <= 0 <= stop:
                candidates.append((0, 0))
        if not candidates:
            return None
        return min(candidates)[1]


def _canonical_intervals(intervals):
    valid = []
    for start, stop in intervals:
        if start <= stop:
            valid.append((start, stop))
    if not valid:
        return ()
    valid.sort()
    merged = []
    for start, stop in valid:
        if not merged or start > merged[-1][1] + 1:
            merged.append([start, stop])
        elif stop > merged[-1][1]:
            merged[-1][1] = stop
    return tuple((start, stop) for start, stop in merged)


def _domain(intervals):
    intervals = _canonical_intervals(intervals)
    if not intervals:
        return None
    return _IntervalSet(intervals)


def _union_domains(left, right):
    if left is UNKNOWN_DOMAIN or right is UNKNOWN_DOMAIN:
        return UNKNOWN_DOMAIN
    if left is None:
        return right
    if right is None:
        return left
    return _domain(left.intervals + right.intervals)


def _intersect_domains(left, right):
    if left is UNKNOWN_DOMAIN or right is UNKNOWN_DOMAIN:
        return UNKNOWN_DOMAIN
    if left is None or right is None:
        return None
    intervals = []
    for left_start, left_stop in left.intervals:
        for right_start, right_stop in right.intervals:
            start = max(left_start, right_start)
            stop = min(left_stop, right_stop)
            if start <= stop:
                intervals.append((start, stop))
    return _domain(intervals)


def _difference_domains(left, right):
    if left is UNKNOWN_DOMAIN or right is UNKNOWN_DOMAIN:
        return UNKNOWN_DOMAIN
    if left is None:
        return None
    if right is None:
        return left
    result = []
    for start, stop in left.intervals:
        pieces = [(start, stop)]
        for other_start, other_stop in right.intervals:
            next_pieces = []
            for piece_start, piece_stop in pieces:
                if other_stop < piece_start or other_start > piece_stop:
                    next_pieces.append((piece_start, piece_stop))
                else:
                    if piece_start < other_start:
                        next_pieces.append((piece_start, other_start - 1))
                    if other_stop < piece_stop:
                        next_pieces.append((other_stop + 1, piece_stop))
            pieces = next_pieces
        result.extend(pieces)
    return _domain(result)


def _domain_contains(outer, inner):
    if outer is UNKNOWN_DOMAIN or inner is UNKNOWN_DOMAIN:
        return False
    if inner is None:
        return True
    if outer is None:
        return False
    return _difference_domains(inner, outer) is None


class _Outcome(object):
    def __init__(self, status, path=(), reason=None, witness=None,
                 wire=False, tag_compatible=None, unknown_reasons=None):
        self.status = status
        self.path = tuple(path)
        self.reason = reason
        self.witness = witness
        self.wire = wire
        self.tag_compatible = tag_compatible
        self.unknown_reasons = tuple(unknown_reasons or ())


COMPATIBLE_OUTCOME = _Outcome(COMPATIBLE, tag_compatible=True)


class CompatibilityResult(object):
    """Result of an old-to-new ASN.1 schema value-set comparison."""

    def __init__(self, outcome):
        self.__status = outcome.status
        self.__path = tuple(outcome.path)
        self.__reason = outcome.reason
        self.__counterexample = outcome.witness
        self.__wire = bool(outcome.wire)
        self.__tag_compatible = outcome.tag_compatible
        self.__unknown_reasons = tuple(outcome.unknown_reasons)

    def __bool__(self):
        return self.__status == COMPATIBLE

    def __nonzero__(self):
        return self.__bool__()

    def __repr__(self):
        return '<CompatibilityResult %s path=%r>' % (
            self.__status, self.__path)

    @property
    def status(self):
        return self.__status

    @property
    def compatible(self):
        return self.__status == COMPATIBLE

    @property
    def tag_compatible(self):
        return self.__tag_compatible

    @property
    def path(self):
        return self.__path

    @property
    def reason(self):
        return self.__reason

    @property
    def counterexample(self):
        return self.__counterexample

    @property
    def counterexample_native(self):
        return _native_value(self.__counterexample)

    @property
    def wire_reason(self):
        if self.__wire:
            return self.__reason

    @property
    def unknown_reasons(self):
        return self.__unknown_reasons

    def as_dict(self):
        return {
            'status': self.status,
            'compatible': self.compatible,
            'tag_compatible': self.tag_compatible,
            'path': self.path,
            'reason': self.reason,
            'counterexample': self.counterexample,
            'counterexample_native': self.counterexample_native,
            'wire_reason': self.wire_reason,
            'unknown_reasons': self.unknown_reasons
        }


def _native_value(value):
    if value is None:
        return None
    if isinstance(value, univ.SequenceOfAndSetOfBase):
        return [_native_value(component) for component in value]
    if isinstance(value, univ.Choice):
        if value._currentIdx is None:
            return None
        name = value.componentType[value._currentIdx].name
        return {name: _native_value(value.getComponent())}
    if isinstance(value, univ.SequenceAndSetBase):
        result = {}
        for idx, component in enumerate(value.components):
            if component is univ.noValue or not component.isValue:
                continue
            name = value.componentType.getNameByPosition(idx)
            result[name] = _native_value(component)
        return result
    if isinstance(value, base.SimpleAsn1Type):
        return value._value
    return value


def _schema(schema):
    if isinstance(schema, type):
        return schema()
    return schema


def _is_choice(schema):
    return isinstance(schema, univ.Choice)


def _is_sequence(schema):
    return isinstance(schema, univ.Sequence) and not _is_choice(schema)


def _is_of(schema):
    return isinstance(schema, univ.SequenceOfAndSetOfBase)


def _is_numeric(schema):
    return isinstance(schema, (univ.Integer, univ.Enumerated))


def _tag_signature(schema):
    return tuple((item.tagClass, item.tagFormat, item.tagId)
                 for item in schema.tagSet.superTags)


def _named_types(schema):
    component_type = getattr(schema, 'componentType', None)
    if not isinstance(component_type, namedtype.NamedTypes):
        return ()
    return tuple(component_type)


def _has_open_type(schema):
    return any(item.openType for item in _named_types(schema))


def _numeric_domain(schema):
    if isinstance(schema, univ.Enumerated) and len(schema.namedValues):
        named_domain = _domain(
            (value, value) for value in schema.namedValues.values())
    else:
        named_domain = _domain(((-INFINITY, INFINITY),))
    return _intersect_domains(
        named_domain, _constraint_domain(schema.subtypeSpec, True))


def _size_domain(schema):
    if _is_choice(schema):
        default_domain = _domain(((1, 1),))
    else:
        default_domain = _domain(((0, INFINITY),))
    if not getattr(schema, 'subtypeSpec', None):
        return default_domain
    constrained = _constraint_domain(schema.subtypeSpec, False)
    if constrained is UNKNOWN_DOMAIN:
        return UNKNOWN_DOMAIN
    if constrained is None:
        return default_domain
    return _intersect_domains(default_domain, constrained)


def _constraint_domain(spec, numeric):
    if not spec:
        if numeric:
            return None
        return _domain(((0, INFINITY),))
    spec_type = type(spec)
    if spec_type is constraint.ConstraintsIntersection:
        domain = None if numeric else _domain(((0, INFINITY),))
        for child in spec:
            domain = _intersect_domains(
                domain, _constraint_domain(child, numeric))
        return domain
    if spec_type is constraint.ConstraintsUnion:
        domain = None
        for child in spec:
            domain = _union_domains(
                domain, _constraint_domain(child, numeric))
        return domain
    if spec_type is constraint.ConstraintsExclusion:
        domain = None if numeric else _domain(((0, INFINITY),))
        for child in spec:
            domain = _difference_domains(
                domain, _constraint_domain(child, numeric))
        return domain
    if numeric:
        if spec_type is constraint.ValueRangeConstraint:
            return _domain(((spec.start, spec.stop),))
        if spec_type is constraint.SingleValueConstraint:
            return _domain((value, value) for value in spec._values)
        if spec_type is constraint.ContainedSubtypeConstraint:
            direct = _domain(
                (value, value) for value in spec._set
                if not isinstance(value, constraint.AbstractConstraint))
            nested = None
            for child in spec._values:
                if isinstance(child, constraint.AbstractConstraint):
                    nested = _intersect_domains(
                        nested, _constraint_domain(child, True))
            if nested is None:
                return direct
            if direct is None:
                return nested
            return _intersect_domains(direct, nested)
    elif spec_type is constraint.ValueSizeConstraint:
        return _domain(((spec.start, spec.stop),))
    return UNKNOWN_DOMAIN


def _scalar_family(schema):
    if isinstance(schema, univ.Enumerated):
        return 'enumerated'
    if isinstance(schema, univ.Integer):
        return 'integer'
    if isinstance(schema, univ.Boolean):
        return 'boolean'
    if isinstance(schema, univ.Null):
        return 'null'
    if isinstance(schema, char.AbstractCharacterString):
        return 'character-string'
    if isinstance(schema, univ.OctetString):
        return 'octet-string'
    if isinstance(schema, univ.BitString):
        return 'bit-string'
    if isinstance(schema, univ.Real):
        return 'real'
    if isinstance(schema, univ.ObjectIdentifier):
        return 'object-identifier'
    if isinstance(schema, univ.RelativeOID):
        return 'relative-object-identifier'
    return 'unknown'


def _container_constraint_is_provable(schema):
    spec = getattr(schema, 'subtypeSpec', None)
    if not spec:
        return True
    if _is_choice(schema):
        if len(spec) == 1:
            child = spec[0]
            return (type(child) is constraint.ValueSizeConstraint and
                    child.start == 1 and child.stop == 1)
        return False
    return False


def _tag_conflict(old_schema, new_schema):
    old_tags = _tag_signature(old_schema)
    new_tags = _tag_signature(new_schema)
    if old_tags == new_tags:
        return None
    return 'wire tag %r is not accepted by new tag %r' % (
        old_tags, new_tags)


def _sample_scalar(schema):
    if _is_numeric(schema):
        domain = _numeric_domain(schema)
        value = 0
        if domain is not UNKNOWN_DOMAIN and domain is not None:
            value = domain.sample()
        return schema.clone(value=value)
    family = _scalar_family(schema)
    if family == 'character-string':
        return schema.clone(value='a')
    if family in ('octet-string', 'bit-string'):
        try:
            return schema.clone(value=b'a')
        except Exception:
            return None
    if family == 'null':
        try:
            return schema.clone(value='')
        except Exception:
            return None
    return None


def _sample_schema(schema, active=None):
    if active is None:
        active = set()
    key = (id(schema), ())
    if key in active:
        return None
    active.add(key)
    if isinstance(schema, base.SimpleAsn1Type):
        try:
            return _sample_scalar(schema)
        finally:
            active.remove(key)
    if _is_of(schema):
        component = schema.componentType
        if component is None:
            result = None
        else:
            size_domain = _size_domain(schema)
            length = 0
            if size_domain is not UNKNOWN_DOMAIN and size_domain is not None:
                length = int(size_domain.sample())
            value = schema.clone()
            result = value
            for _ in range(length):
                item = _sample_schema(component, active)
                if item is None:
                    result = None
                    break
                value.append(item)
        active.remove(key)
        return result
    if _is_choice(schema):
        result = None
        for item in _named_types(schema):
            component = _sample_schema(item.asn1Object, active)
            if component is not None:
                value = schema.clone()
                value[item.name] = component
                result = value
                break
        active.remove(key)
        return result
    if _is_sequence(schema):
        value = schema.clone()
        result = value
        for item in _named_types(schema):
            if item.isOptional or item.isDefaulted:
                continue
            component = _sample_schema(item.asn1Object, active)
            if component is None:
                result = None
                break
            value[item.name] = component
        active.remove(key)
        return result
    active.remove(key)
    return None


def _make_witness(schema, target, active=None):
    if active is None:
        active = set()
    if not target:
        return _sample_schema(schema)
    key = (id(schema), target)
    if key in active:
        return None
    active.add(key)
    step = target[0]
    rest = target[1:]
    try:
        if _is_of(schema):
            component = schema.componentType
            if component is None or not isinstance(step, int):
                return None
            value = schema.clone()
            for idx in range(step + 1):
                if idx == step:
                    item = _make_witness(component, rest, active)
                else:
                    item = _sample_schema(component, active)
                if item is None:
                    return None
                value.append(item)
            return value
        if _is_choice(schema):
            if not isinstance(step, str):
                return None
            for item in _named_types(schema):
                if item.name != step:
                    continue
                component = _make_witness(item.asn1Object, rest, active)
                if component is None:
                    return None
                value = schema.clone()
                value[item.name] = component
                return value
            return None
        if _is_sequence(schema):
            if not isinstance(step, str):
                return None
            items = _named_types(schema)
            value = schema.clone()
            for item in items:
                if item.name == step:
                    component = _make_witness(item.asn1Object, rest, active)
                    if component is None:
                        return None
                    value[item.name] = component
                    break
                if not item.isOptional and not item.isDefaulted:
                    component = _sample_schema(item.asn1Object, active)
                    if component is None:
                        return None
                    value[item.name] = component
            else:
                return None
            return value
    finally:
        active.remove(key)
    return None


def _wrap_sequence_witness(schema, field_name, child_witness):
    value = schema.clone()
    found = False
    active = set()
    for item in _named_types(schema):
        if item.name == field_name:
            value[field_name] = child_witness
            found = True
        elif not item.isOptional and not item.isDefaulted:
            component = _sample_schema(item.asn1Object, active)
            if component is None:
                return None
            value[item.name] = component
    if not found:
        return None
    return value


def _of_witness(schema, size):
    component = schema.componentType
    if component is None:
        return None
    value = schema.clone()
    for _ in range(size):
        item = _sample_schema(component)
        if item is None:
            return None
        value.append(item)
    return value


def _validated(outcome, old_schema, new_schema):
    if outcome.status != INCOMPATIBLE:
        return outcome
    if outcome.witness is None:
        return _Outcome(UNKNOWN, outcome.path,
                        'incompatibility suspected but no provable value: %s'
                        % outcome.reason, None, outcome.wire, None,
                        (outcome.reason,))
    from pyasn1.codec.ber import decoder
    from pyasn1.codec.ber import encoder
    try:
        encoded_old = encoder.encode(outcome.witness)
        decoded_new, trailing = decoder.decode(
            encoded_old, asn1Spec=new_schema.clone())
        if trailing:
            raise ValueError('trailing substrate remains')
        if not decoded_new.isValue or decoded_new.isInconsistent:
            raise ValueError('decoded value is not a complete schema value')
        encoder.encode(decoded_new)
    except Exception:
        return outcome
    return _Outcome(UNKNOWN, outcome.path,
                    'counterexample was accepted by the new schema',
                    None, False, None, (outcome.reason,))


class _CompatibilityComparator(object):
    def __init__(self):
        self.active = set()

    def compare(self, old_schema, new_schema):
        key = (id(old_schema), id(new_schema))
        if key in self.active:
            return COMPATIBLE_OUTCOME
        self.active.add(key)
        try:
            return self._compare_unchecked(old_schema, new_schema)
        finally:
            self.active.remove(key)

    def _unknown(self, path, reason):
        return _Outcome(UNKNOWN, path, reason, None, False, True, (reason,))

    def _compare_unchecked(self, old_schema, new_schema):
        if isinstance(old_schema, univ.Any) or isinstance(new_schema, univ.Any):
            return self._unknown((), 'ANY value domain cannot be proved')
        if isinstance(old_schema, univ.Set) and not _is_choice(old_schema):
            return self._unknown((), 'SET compatibility is not decidable here')
        if isinstance(new_schema, univ.Set) and not _is_choice(new_schema):
            return self._unknown((), 'SET compatibility is not decidable here')
        if not isinstance(old_schema, base.Asn1Type) or not isinstance(
                new_schema, base.Asn1Type):
            return self._unknown((), 'inputs are not ASN.1 schema objects')
        if _has_open_type(old_schema) or _has_open_type(new_schema):
            return self._unknown((), 'open type value domain cannot be proved')

        tag_reason = _tag_conflict(old_schema, new_schema)
        if tag_reason is not None and not (
                _is_choice(old_schema) or _is_choice(new_schema)):
            witness = _sample_schema(old_schema)
            return _validated(
                _Outcome(INCOMPATIBLE, (), tag_reason, witness, True,
                         False),
                old_schema, new_schema)

        if _is_choice(old_schema) or _is_choice(new_schema):
            return self._compare_choice_root(old_schema, new_schema)

        old_of = _is_of(old_schema)
        new_of = _is_of(new_schema)
        if old_of != new_of:
            witness = _sample_schema(old_schema)
            reason = 'wire construction form changed between schema types'
            return _validated(
                _Outcome(INCOMPATIBLE, (), reason, witness, True, True),
                old_schema, new_schema)

        if old_of and new_of:
            return self._compare_of(old_schema, new_schema)

        old_sequence = _is_sequence(old_schema)
        new_sequence = _is_sequence(new_schema)
        if old_sequence != new_sequence:
            witness = _sample_schema(old_schema)
            reason = 'wire construction form changed between schema types'
            return _validated(
                _Outcome(INCOMPATIBLE, (), reason, witness, True, True),
                old_schema, new_schema)

        if old_sequence and new_sequence:
            return self._compare_sequence(old_schema, new_schema)

        return self._compare_scalar(old_schema, new_schema)

    def _compare_scalar(self, old_schema, new_schema):
        old_family = _scalar_family(old_schema)
        new_family = _scalar_family(new_schema)
        if old_family != new_family:
            witness = _sample_schema(old_schema)
            reason = ('wire payload family %r is not accepted by new payload '
                      'family %r' % (old_family, new_family))
            return _validated(
                _Outcome(INCOMPATIBLE, (), reason, witness, True, True),
                old_schema, new_schema)
        if _is_numeric(old_schema):
            old_domain = _numeric_domain(old_schema)
            new_domain = _numeric_domain(new_schema)
            if old_domain is UNKNOWN_DOMAIN or new_domain is UNKNOWN_DOMAIN:
                return self._unknown(
                    (), 'integer or enumerated constraint cannot be decided')
            difference = _difference_domains(old_domain, new_domain)
            if difference is UNKNOWN_DOMAIN:
                return self._unknown(
                    (), 'integer or enumerated constraint cannot be decided')
            if difference is not None:
                witness = old_schema.clone(value=difference.sample())
                outcome = _Outcome(
                    INCOMPATIBLE, (), 'value lies outside new value domain',
                    witness, False, True)
                return _validated(outcome, old_schema, new_schema)
            return COMPATIBLE_OUTCOME
        if old_family in ('octet-string', 'character-string', 'bit-string'):
            old_domain = _size_domain(old_schema)
            new_domain = _size_domain(new_schema)
            if old_domain is UNKNOWN_DOMAIN or new_domain is UNKNOWN_DOMAIN:
                return self._unknown(
                    (), 'string constraint cannot be decided')
            difference = _difference_domains(old_domain, new_domain)
            if difference is not None:
                length = int(difference.sample())
                if old_family == 'character-string':
                    value = 'a' * length
                else:
                    value = b'a' * length
                witness = old_schema.clone(value=value)
                outcome = _Outcome(
                    INCOMPATIBLE, (), 'size lies outside new size domain',
                    witness, False, True)
                return _validated(outcome, old_schema, new_schema)
            return COMPATIBLE_OUTCOME
        return self._unknown((), 'value domain for %r cannot be proved' % (
            old_family,))

    def _compare_of(self, old_schema, new_schema):
        old_size = _size_domain(old_schema)
        new_size = _size_domain(new_schema)
        if old_size is UNKNOWN_DOMAIN or new_size is UNKNOWN_DOMAIN:
            return self._unknown((), 'container size constraint is not decidable')
        size_difference = _difference_domains(old_size, new_size)
        if size_difference is UNKNOWN_DOMAIN:
            return self._unknown((), 'container size constraint is not decidable')
        if size_difference is not None:
            length = int(size_difference.sample())
            witness = _of_witness(old_schema, length)
            outcome = _Outcome(
                INCOMPATIBLE, (), 'size lies outside new size domain',
                witness, False, True)
            return _validated(outcome, old_schema, new_schema)
        old_component = old_schema.componentType
        new_component = new_schema.componentType
        if old_component is None or new_component is None:
            return self._unknown((), 'untyped OF component cannot be proved')
        component_outcome = self.compare(old_component, new_component)
        if component_outcome.status == INCOMPATIBLE:
            witness = _wrap_of_witness(old_schema, component_outcome.witness)
            outcome = _Outcome(
                INCOMPATIBLE, (0,) + component_outcome.path,
                component_outcome.reason, witness,
                component_outcome.wire, True)
            return _validated(outcome, old_schema, new_schema)
        if component_outcome.status == UNKNOWN:
            return self._unknown(
                (0,) + component_outcome.path,
                component_outcome.reason)
        return COMPATIBLE_OUTCOME

    def _compare_sequence(self, old_schema, new_schema):
        if not _container_constraint_is_provable(old_schema):
            return self._unknown(
                (), 'SEQUENCE constraint is not decidable')
        if not _container_constraint_is_provable(new_schema):
            return self._unknown(
                (), 'new SEQUENCE constraint is not decidable')
        old_items = _named_types(old_schema)
        new_items = _named_types(new_schema)
        new_by_tag = {}
        new_by_name = {}
        for item in new_items:
            new_by_tag.setdefault(
                _tag_signature(item.asn1Object), []).append(item)
            new_by_name.setdefault(item.name, []).append(item)
        matched_new = set()
        outcomes = []
        unknown_outcomes = []

        for old_item in old_items:
            matches = new_by_tag.get(_tag_signature(old_item.asn1Object))
            if matches is None:
                matches = new_by_name.get(old_item.name)
            new_item = matches[0] if matches else None
            if new_item is not None:
                matched_new.add(new_item.name)
                outcome = self._compare_sequence_field(
                    old_schema, new_schema, old_item, new_item)
            else:
                witness = _make_witness(old_schema, (old_item.name,))
                outcome = _Outcome(
                    INCOMPATIBLE, (old_item.name,),
                    'field accepted by old schema is absent from new schema',
                    witness, False, True)
                outcome = _validated(outcome, old_schema, new_schema)
            if outcome.status == INCOMPATIBLE:
                outcomes.append(outcome)
            elif outcome.status == UNKNOWN:
                unknown_outcomes.append(outcome)

        for new_item in new_items:
            if new_item.name in matched_new or new_item.isOptional or new_item.isDefaulted:
                continue
            witness = _sample_schema(old_schema)
            outcome = _Outcome(
                INCOMPATIBLE, (new_item.name,),
                'new required field may be absent in an old value',
                witness, False, True)
            outcome = _validated(outcome, old_schema, new_schema)
            if outcome.status == INCOMPATIBLE:
                outcomes.append(outcome)
            else:
                unknown_outcomes.append(outcome)

        if outcomes:
            return min(outcomes, key=lambda outcome: (
                len(outcome.path), outcomes.index(outcome)))
        if unknown_outcomes:
            return unknown_outcomes[0]
        return COMPATIBLE_OUTCOME

    def _compare_sequence_field(self, old_parent, new_parent,
                                old_item, new_item):
        tag_reason = _tag_conflict(
            old_item.asn1Object, new_item.asn1Object)
        if tag_reason is not None:
            witness = _wrap_sequence_witness(
                old_parent, old_item.name,
                _sample_schema(old_item.asn1Object))
            return _validated(
                _Outcome(INCOMPATIBLE, (old_item.name,), tag_reason,
                         witness, True, False),
                old_parent, new_parent)

        old_can_be_absent = old_item.isOptional or old_item.isDefaulted
        new_can_be_absent = new_item.isOptional or new_item.isDefaulted
        if old_can_be_absent and not new_can_be_absent:
            witness = _sample_schema(old_parent)
            return _validated(
                _Outcome(
                    INCOMPATIBLE, (old_item.name,),
                    'field may be absent in old value but is required in new schema',
                    witness, False, True),
                old_parent, new_parent)

        child_outcome = self.compare(
            old_item.asn1Object, new_item.asn1Object)
        if child_outcome.status == INCOMPATIBLE:
            witness = _wrap_sequence_witness(
                old_parent, old_item.name, child_outcome.witness)
            outcome = _Outcome(
                INCOMPATIBLE, (old_item.name,) + child_outcome.path,
                child_outcome.reason, witness, child_outcome.wire,
                child_outcome.tag_compatible)
            return _validated(outcome, old_parent, new_parent)
        if child_outcome.status == UNKNOWN:
            return self._unknown(
                (old_item.name,) + child_outcome.path,
                child_outcome.reason)
        return COMPATIBLE_OUTCOME

    def _compare_choice_root(self, old_schema, new_schema):
        old_choice = _is_choice(old_schema)
        new_choice = _is_choice(new_schema)
        if old_choice and new_choice:
            if _tag_signature(old_schema) != _tag_signature(new_schema):
                witness = _sample_schema(old_schema)
                return _validated(
                    _Outcome(
                        INCOMPATIBLE, (),
                        _tag_conflict(old_schema, new_schema), witness,
                        True, False),
                    old_schema, new_schema)
            return self._compare_choice_alternatives(old_schema, new_schema)
        if old_choice and not _tag_signature(old_schema):
            return self._compare_choice_to_schema(old_schema, new_schema)
        if new_choice and not _tag_signature(new_schema):
            return self._compare_schema_to_choice(old_schema, new_schema)
        witness = _sample_schema(old_schema)
        reason = 'wire construction form changed between schema types'
        return _validated(
            _Outcome(INCOMPATIBLE, (), reason, witness, True, True),
            old_schema, new_schema)

    def _compare_choice_alternatives(self, old_schema, new_schema):
        new_alternatives = {}
        for item in _named_types(new_schema):
            new_alternatives.setdefault(
                _tag_signature(item.asn1Object), []).append(item)
        outcomes = []
        unknown_outcomes = []
        for old_item in _named_types(old_schema):
            matches = new_alternatives.get(
                _tag_signature(old_item.asn1Object))
            if matches is None:
                witness = _choice_witness(
                    old_schema, old_item.name,
                    _sample_schema(old_item.asn1Object))
                outcome = _Outcome(
                    INCOMPATIBLE, (old_item.name,),
                    'choice alternative is absent from new schema',
                    witness, False, True)
            else:
                new_item = matches[0]
                child_outcome = self.compare(
                    old_item.asn1Object, new_item.asn1Object)
                if child_outcome.status == INCOMPATIBLE:
                    witness = _choice_witness(
                        old_schema, old_item.name,
                        child_outcome.witness)
                    outcome = _Outcome(
                        INCOMPATIBLE,
                        (old_item.name,) + child_outcome.path,
                        child_outcome.reason, witness,
                        child_outcome.wire, child_outcome.tag_compatible)
                elif child_outcome.status == UNKNOWN:
                    unknown_outcomes.append(self._unknown(
                        (old_item.name,) + child_outcome.path,
                        child_outcome.reason))
                    continue
                else:
                    continue
            outcome = _validated(outcome, old_schema, new_schema)
            if outcome.status == INCOMPATIBLE:
                outcomes.append(outcome)
            else:
                unknown_outcomes.append(outcome)
        if outcomes:
            return min(outcomes, key=lambda outcome: (
                len(outcome.path), outcomes.index(outcome)))
        if unknown_outcomes:
            return unknown_outcomes[0]
        return COMPATIBLE_OUTCOME

    def _compare_choice_to_schema(self, choice_schema, other_schema):
        alternatives = _named_types(choice_schema)
        outcomes = []
        for item in alternatives:
            outcome = self.compare(item.asn1Object, other_schema)
            if outcome.status == INCOMPATIBLE:
                witness = _choice_witness(
                    choice_schema, item.name, outcome.witness)
                outcomes.append(_Outcome(
                    INCOMPATIBLE, (item.name,) + outcome.path,
                    outcome.reason, witness, outcome.wire,
                    outcome.tag_compatible))
            elif outcome.status == UNKNOWN:
                return self._unknown(
                    (item.name,) + outcome.path, outcome.reason)
        if outcomes:
            outcome = min(outcomes, key=lambda outcome: (
                len(outcome.path), outcomes.index(outcome)))
            return _validated(
                outcome, choice_schema, other_schema)
        return COMPATIBLE_OUTCOME

    def _compare_schema_to_choice(self, other_schema, choice_schema):
        other_tag = _tag_signature(other_schema)
        for item in _named_types(choice_schema):
            if _tag_signature(item.asn1Object) != other_tag:
                continue
            outcome = self.compare(other_schema, item.asn1Object)
            if outcome.status == INCOMPATIBLE:
                return _Outcome(
                    INCOMPATIBLE, outcome.path, outcome.reason,
                    outcome.witness, outcome.wire,
                    outcome.tag_compatible)
            if outcome.status == UNKNOWN:
                return self._unknown(outcome.path, outcome.reason)
            return COMPATIBLE_OUTCOME
        witness = _sample_schema(other_schema)
        reason = 'wire tag %r is not accepted by any new CHOICE alternative' % (
            other_tag,)
        return _validated(
            _Outcome(INCOMPATIBLE, (), reason, witness, True, False),
            other_schema, choice_schema)


def _wrap_of_witness(schema, child_witness):
    value = schema.clone()
    if child_witness is not None:
        value.append(child_witness)
    return value


def _choice_witness(schema, alternative_name, child_witness):
    value = schema.clone()
    if child_witness is not None:
        value[alternative_name] = child_witness
    return value


def compare_schemas(old_schema, new_schema):
    """Return whether old-schema values are accepted by new_schema."""
    old_schema = _schema(old_schema)
    new_schema = _schema(new_schema)
    comparator = _CompatibilityComparator()
    outcome = comparator.compare(old_schema, new_schema)
    return CompatibilityResult(_validated(outcome, old_schema, new_schema))


def is_compatible(old_schema, new_schema):
    """Return True only when a compatibility result is compatible."""
    return compare_schemas(old_schema, new_schema).compatible
