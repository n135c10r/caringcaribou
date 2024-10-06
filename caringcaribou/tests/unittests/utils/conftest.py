import pytest
from unittest.mock import patch
from caringcaribou.utils.iso15765_2 import IsoTp


@pytest.fixture
def bus_mock():
    with patch('caringcaribou.utils.iso15765_2.can.Bus') as bus_mock:
        bus_mock.return_value.name = "DUMMY_INTERFACE"
        yield bus_mock


@pytest.fixture
def message_mock():
    with patch('caringcaribou.utils.iso15765_2.can.Message') as message_mock:
        yield message_mock


@pytest.fixture
def isotp_mocked_bus(bus_mock):
    isotp = IsoTp(arb_id_request=0x7E0, arb_id_response=0x7E8)

    yield isotp
