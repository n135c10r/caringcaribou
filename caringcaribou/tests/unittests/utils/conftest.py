import pytest
from unittest.mock import patch
from caringcaribou.utils.iso15765_2 import IsoTp

dummy_request_id = 0x7E0
dummy_response_id = 0x7E8


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
    isotp = IsoTp(arb_id_request=dummy_request_id, arb_id_response=dummy_response_id)

    isotp.MAX_SF_LENGTH = 7
    isotp.MAX_FF_LENGTH = 6
    isotp.MAX_CF_LENGTH = 7
    isotp.SF_PCI_LENGTH = 1
    isotp.CF_PCI_LENGTH = 1
    isotp.FF_PCI_LENGTH = 2
    isotp.FC_PCI_LENGTH = 3
    isotp.FC_FS_CTS = 0
    isotp.FC_FS_WAIT = 1
    isotp.FC_FS_OVFLW = 2
    isotp.SF_FRAME_ID = 0
    isotp.FF_FRAME_ID = 1
    isotp.CF_FRAME_ID = 2
    isotp.FC_FRAME_ID = 3
    isotp.N_BS_TIMEOUT = 1.5
    isotp.MAX_FRAME_LENGTH = 8
    isotp.MAX_MESSAGE_LENGTH = 4095

    yield isotp
