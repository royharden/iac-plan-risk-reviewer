"""Direct tests for declared pure parser signatures; candidate import absent."""
import json


CASES = []


def case(function):
    CASES.append(function)
    return function


def denied(api, operation):
    try:
        operation()
    except api.Denied as error:
        assert type(error) is api.Denied
        return
    raise AssertionError('exact source Denied absent')


@case
def canonical_input_exact_bytes_unique_keys_and_finite_numbers(api):
    # decode_canonical is the source's declared pure function, forwarded only.
    assert api.decode_canonical(b'{"a":1}') == {'a': 1}
    for raw in ('{"a":1}', bytearray(b'{"a":1}'), memoryview(b'{"a":1}'),
                b'\xef\xbb\xbf{"a":1}', b'{"a":1}\n', b' {"a":1}',
                b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}',
                b'[]', b'null', b'{"b":2,"a":1}', b'{"a": 1}',
                b'{"a":1}{}', b'\xff'):
        denied(api, lambda: api.decode_canonical(raw))


@case
def canonical_cap_boundary_and_ascii_domain(api):
    raw = b'{"a":"' + b'x' * 20 + b'"}'
    assert api.decode_canonical(raw, cap=len(raw)) == {'a': 'x' * 20}
    denied(api, lambda: api.decode_canonical(raw, cap=len(raw) - 1))
    denied(api, lambda: api.decode_canonical(b'x' * 65537))
    canonical = json.dumps({'a': '\u00e9'}, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=True, allow_nan=False).encode('utf-8')
    assert api.decode_canonical(canonical) == {'a': '\u00e9'}
    denied(api, lambda: api.decode_canonical('{"a":"\u00e9"}'.encode('utf-8')))


@case
def exact_value_strict_scalar_container_subclass_types(api):
    class StringSubclass(str):
        pass
    class DictSubclass(dict):
        pass
    for actual, expected in [(True, 1), (1, 1.0), ([1], (1,)),
                             (StringSubclass('a'), 'a'),
                             (DictSubclass(a=1), {'a': 1}),
                             ({'a': True}, {'a': 1}),
                             ({'a': 1, 'b': None}, {'a': 1})]:
        assert api.exact_value(actual, expected) is False
    assert api.exact_value({'a': [1, True, None]}, {'a': [1, True, None]}) is True
