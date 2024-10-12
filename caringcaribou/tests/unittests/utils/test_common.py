import pytest
import can

from unittest.mock import Mock

from caringcaribou.utils.common import (
    parse_int_dec_or_hex,
    str_to_int_list,
    int_from_byte_list,
    list_to_hex_str,
    hex_str_to_nibble_list,
    msg_to_candump_format,
)


@pytest.mark.parametrize(
    "str_int, parsed_int",
    [
        ("0", 0),
        ("1", 1),
        ("0x000", 0x0),
        ("0xA7", 167),
        ("0xFF", 255),
        ("1234", 1234),
        ("0x000A5", 0xA5),
        ("0xC0FEE", 790510),
    ],
)
def test_parse_int_dec_or_hex(str_int, parsed_int):
    assert parse_int_dec_or_hex(str_int) == parsed_int


@pytest.mark.parametrize(
    "str_int, parsed_list",
    [
        ("", []),
        ("ff", [0xFF]),
        ("0123", [0x01, 0x23]),
        ("0000", [0x0, 0x0]),
        ("deadbeef", [0xDE, 0xAD, 0xBE, 0xEF]),
        ("0102C0FFEE", [0x01, 0x02, 0xC0, 0xFF, 0xEE]),
    ],
)
def test_str_to_int_list(str_int, parsed_list):
    assert str_to_int_list(str_int) == parsed_list


@pytest.mark.parametrize(
    "byte_list, parsed_int",
    [
        (([0xFF], 0, 1), 0xFF),
        (([0x11, 0x22, 0x33], 0), 0x112233),
        (([0x11, 0x22, 0x33, 0x44],), 0x11223344),
        (([0x11, 0x22, 0x33, 0x44], 1, 2), 0x2233),
        (([0x11, 0x22, 0x33, 0x44], 2, 2), 0x3344),
    ],
)
def test_int_from_byte_list(byte_list, parsed_int):
    assert int_from_byte_list(*byte_list) == parsed_int


@pytest.mark.parametrize(
    "byte_list, parsed_str",
    [
        (([],), ""),
        (([0xFF], "-"), "ff"),
        (([0xFF, 0xFF], "-"), "ff-ff"),
        (([10, 100, 200],), "0a64c8"),
        (([0x07, 0xFF, 0x6C], "."), "07.ff.6c"),
        (([0xDE, 0xAD, 0xBE, 0xEF], " "), "de ad be ef"),
    ],
)
def test_list_to_hex_str(byte_list, parsed_str):
    assert list_to_hex_str(*byte_list) == parsed_str


@pytest.mark.parametrize(
    "parsed_str, list_of_nibbles",
    [
        (None, None),
        ("", []),
        ("01", [0x0, 0x1]),
        ("12ABF7", [0x1, 0x2, 0xA, 0xB, 0xF, 0x7]),
        ("deadbeef", [0xD, 0xE, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF]),
    ],
)
def test_hex_str_to_nibble_list(parsed_str, list_of_nibbles):
    assert hex_str_to_nibble_list(parsed_str) == list_of_nibbles


def test_msg_to_candump_format():
    msg = Mock(spec=can.Message)
    msg.timestamp = 565680600.123456
    msg.channel = "can0"
    msg.is_extended_id = False
    msg.arbitration_id = 0x123
    msg.data = [0x11, 0x22, 0xAA, 0xBB]

    expected_output = "(565680600.123456) can0 123#1122aabb"
    assert msg_to_candump_format(msg) == expected_output

    msg.is_extended_id = True
    expected_output = "(565680600.123456) can0 00000123#1122aabb"
    assert msg_to_candump_format(msg) == expected_output
