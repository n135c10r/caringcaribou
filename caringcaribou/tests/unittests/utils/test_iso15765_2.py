import pytest

from unittest.mock import MagicMock, patch

from caringcaribou.utils.constants import ARBITRATION_ID_MAX_EXTENDED
from caringcaribou.utils.iso15765_2 import IsoTp


class TestIso15765_2:

    dummy_request_id = 0x7E0
    dummy_response_id = 0x7E8
    DUMMY_EXTENDED_ID = 0x800

    def test_isotp_initialization_default_bus(self, isotp_mocked_bus):
        assert isotp_mocked_bus.arb_id_request == self.dummy_request_id
        assert isotp_mocked_bus.arb_id_response == self.dummy_response_id
        assert isotp_mocked_bus.padding_value == 0x00
        assert isotp_mocked_bus.padding_enabled is True
        assert isotp_mocked_bus.bus.name == "DUMMY_INTERFACE"

    def test_isotp_initialization_custom_bus(self):
        isotp = IsoTp(self.dummy_request_id, self.dummy_response_id, bus="DUMMY_INTERFACE", padding_value=0xAA)
        assert isotp.padding_value == 0xAA
        assert isotp.padding_enabled is True
        assert isotp.bus == "DUMMY_INTERFACE"

    def test_isotp_initialization_no_padding(self, bus_mock):
        isotp = IsoTp(self.dummy_request_id, self.dummy_response_id, padding_value=None)
        assert isotp.padding_enabled is False

    def test_isotp_initialization_invalid_padding_type(self, bus_mock):
        expected_err_message = f"IsoTp: padding must be an integer or None, received 'invalid'"
        with pytest.raises(TypeError) as err_message:
            IsoTp(self.dummy_request_id, self.dummy_response_id, padding_value='invalid')

        assert expected_err_message == str(err_message.value)

    def test_isotp_initialization_invalid_padding_value(self, bus_mock):
        expected_err_message = "IsoTp: padding must be in range 0x00-0xFF (0-255), got '511'"
        with pytest.raises(ValueError) as err_message:
            IsoTp(self.dummy_request_id, self.dummy_response_id, padding_value=0x1FF)

        assert expected_err_message == str(err_message.value)

    def test_isotp__exit__(self, bus_mock):
        with IsoTp(self.dummy_request_id, self.dummy_response_id) as isotp:
            assert isotp.padding_value == 0x00
        isotp.bus.shutdown.assert_called_once()

    def test_set_filter_single_arbitration_id(self, isotp_mocked_bus):
        isotp_mocked_bus.set_filter_single_arbitration_id(0x123)
        expected_filter = [{"can_id": 0x123, "can_mask": ARBITRATION_ID_MAX_EXTENDED}]

        isotp_mocked_bus.bus.set_filters.assert_called_once_with(expected_filter)

    def test_clear_filters(self, isotp_mocked_bus):
        isotp_mocked_bus.clear_filters()

        isotp_mocked_bus.bus.set_filters.assert_called_once_with(None)

    def test_send_message_standard_id(self, isotp_mocked_bus, message_mock):
        isotp_mocked_bus.send_message(data=[0x01, 0x02, 0x03], arbitration_id=0x123)

        message_mock.assert_called_once_with(arbitration_id=0x123, data=[0x01, 0x02, 0x03], is_extended_id=False)
        isotp_mocked_bus.bus.send.assert_called_once_with(message_mock.return_value)

    def test_send_message_extended_id(self, isotp_mocked_bus, message_mock):
        isotp_mocked_bus.send_message(data=[0x03, 0x02, 0x01], arbitration_id=0x800)

        message_mock.assert_called_once_with(arbitration_id=0x800, data=[0x03, 0x02, 0x01], is_extended_id=True)
        isotp_mocked_bus.bus.send.assert_called_once_with(message_mock.return_value)

    # Decode Signle Frame
    def test_decode_sf_valid_frame(self, isotp_mocked_bus):
        frame = bytearray([0x02, 0xAA, 0xBB])

        sf_data_len, data = isotp_mocked_bus.decode_sf(frame)

        assert sf_data_len == 2
        assert data == [0xAA, 0xBB]

    def test_decode_sf_frame_too_short(self, isotp_mocked_bus):
        frame = bytearray([0x01])
        isotp_mocked_bus.SF_PCI_LENGTH = 2

        sf_data_len, data = isotp_mocked_bus.decode_sf(frame)

        assert sf_data_len is None
        assert data is None

    def test_decode_sf_no_additional_data(self, isotp_mocked_bus):
        # TODO: should this work that way? No relation between frame len and PCI value.
        frame = bytearray([0x01])

        sf_data_len, data = isotp_mocked_bus.decode_sf(frame)

        assert sf_data_len == 1
        assert data == []

    def test_decode_sf_max_length_data(self, isotp_mocked_bus):
        frame = bytearray([0x07] + [0xFF] * 7)

        sf_data_len, data = isotp_mocked_bus.decode_sf(frame)

        assert sf_data_len == 7
        assert data == [0xFF] * 7

    # Decode First Frame
    def test_decode_ff_valid_frame_len1(self, isotp_mocked_bus):
        # TODO: this should work in this way? No relation between ff_data_len and frame length.
        frame = bytearray([0x10, 0x01, 0xAA, 0xBB])

        ff_data_len, data = isotp_mocked_bus.decode_ff(frame)

        assert ff_data_len == 1
        assert data == [0xAA, 0xBB]

    def test_decode_ff_valid_frame_len4095(self, isotp_mocked_bus):
        frame = bytearray([0x1F, 0xFF, 0xAA, 0xBB])

        ff_data_len, data = isotp_mocked_bus.decode_ff(frame)

        assert ff_data_len == 4095
        assert data == [0xAA, 0xBB]

    def test_decode_ff_frame_too_short(self, isotp_mocked_bus):
        frame = bytearray([0x10])

        ff_data_len, data = isotp_mocked_bus.decode_ff(frame)

        assert ff_data_len is None
        assert data is None

    def test_decode_ff_valid_frame_max_bytes(self, isotp_mocked_bus):
        frame = bytearray([0x10, 0x06] + [0xFF] * 6)

        ff_data_len, data = isotp_mocked_bus.decode_ff(frame)

        assert ff_data_len == 6
        assert data == [0xFF] * 6

    # Decode Consecutive Frame
    def test_decode_cf_valid_frame(self, isotp_mocked_bus):
        frame = bytearray([0x02, 0xAA, 0xBB])

        cf_data_len, data = isotp_mocked_bus.decode_cf(frame)

        assert cf_data_len == 2
        assert data == [0xAA, 0xBB]

    def test_decode_cf_frame_too_short(self, isotp_mocked_bus):
        frame = bytearray([0x01])
        isotp_mocked_bus.CF_PCI_LENGTH = 2

        cf_data_len, data = isotp_mocked_bus.decode_cf(frame)

        assert cf_data_len is None
        assert data is None

    def test_decode_cf_no_additional_data(self, isotp_mocked_bus):
        # TODO: should this work that way? No relation between frame len and PCI value.
        frame = bytearray([0x01])

        cf_data_len, data = isotp_mocked_bus.decode_cf(frame)

        assert cf_data_len == 1
        assert data == []

    def test_decode_cf_max_length_data(self, isotp_mocked_bus):
        frame = bytearray([0x07] + [0xFF] * 7)

        cf_data_len, data = isotp_mocked_bus.decode_cf(frame)

        assert cf_data_len == 7
        assert data == [0xFF] * 7

    # Decode Flow Control
    def test_decode_fc_valid_frame(self, isotp_mocked_bus):
        # FlowSatus=0, BlockSize=5, STmin=10ms
        frame = bytearray([0x30, 0x05, 0x0A])

        flow_status, block_size, st_min = isotp_mocked_bus.decode_fc(frame)

        assert flow_status == 0
        assert block_size == 5
        assert st_min == 10

    def test_decode_fc_frame_too_short(self, isotp_mocked_bus):
        frame = bytearray([0x30, 0x05])

        flow_status, block_size, st_min = isotp_mocked_bus.decode_fc(frame)

        assert flow_status is None
        assert block_size is None
        assert st_min is None

    def test_decode_fc_zero_values(self, isotp_mocked_bus):
        frame = bytearray([0x00, 0x00, 0x00])

        flow_status, block_size, st_min = isotp_mocked_bus.decode_fc(frame)

        assert flow_status == 0
        assert block_size == 0
        assert st_min == 0

    def test_decode_fc_max_values(self, isotp_mocked_bus):
        frame = bytearray([0x3F, 0xFF, 0xFF])

        flow_status, block_size, st_min = isotp_mocked_bus.decode_fc(frame)

        assert flow_status == 15
        assert block_size == 255
        assert st_min == 255

    # Encode Flow Control
    def test_encode_fc_valid_values(self, isotp_mocked_bus):
        flow_status = 0x0
        block_size = 0x05
        st_min = 0x10

        result = isotp_mocked_bus.encode_fc(flow_status, block_size, st_min)

        expected_result = [0x30, 0x05, 0x10, 0, 0, 0, 0, 0]
        assert result == expected_result

    def test_encode_fc_max_values(self, isotp_mocked_bus):
        flow_status = 0xF
        block_size = 0xFF
        st_min = 0xFF

        result = isotp_mocked_bus.encode_fc(flow_status, block_size, st_min)

        expected_result = [0x3F, 0xFF, 0xFF, 0, 0, 0, 0, 0]
        assert result == expected_result

    def test_encode_fc_min_values(self, isotp_mocked_bus):
        flow_status = 0x0
        block_size = 0x00
        st_min = 0x00

        result = isotp_mocked_bus.encode_fc(flow_status, block_size, st_min)

        expected_result = [0x30, 0x00, 0x00, 0, 0, 0, 0, 0]
        assert result == expected_result

    # Get Frames from Message
    def test_single_frame_without_padding(self, isotp_mocked_bus):
        message = [0x01, 0x02, 0x03]
        frames = isotp_mocked_bus.get_frames_from_message(message, padding_value=None)

        assert frames == [[0x03, 0x01, 0x02, 0x03]]

    def test_single_frame_with_padding(self, isotp_mocked_bus):
        message = [0x01, 0x02, 0x03]
        frames = isotp_mocked_bus.get_frames_from_message(message, padding_value=0xAA)

        assert frames == [[0x03, 0x01, 0x02, 0x03, 0xAA, 0xAA, 0xAA, 0xAA]]

    def test_multiple_frames(self, isotp_mocked_bus):
        # Sending longer message, so it need to be chunked
        message = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]
        frames = isotp_mocked_bus.get_frames_from_message(message, padding_value=0x00)

        assert frames == [
            # It should be split to frames with 8 bytes each.
            # FF
            [0x10, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            # CF
            [0x21, 0x07, 0x08, 0x09, 0x0A, 0x00, 0x00, 0x00]
        ]

    def test_maximum_length_message(self, isotp_mocked_bus):
        """
        There should be 586 frames in total for this message:
        Message with length of 4095 bytes,
        First frame will carry 6 bytes of payload,
        all rest will be sent by Consecutive Frames by 7 bytes payload in each.
        1 FF: 4095 bytes - 6 bytes = 4089 bytes
        585 CF: 4089 / 7 = 584.14 (this mean that last message will contain padding)

        """
        message = [0x55] * isotp_mocked_bus.MAX_MESSAGE_LENGTH
        frames = isotp_mocked_bus.get_frames_from_message(message, padding_value=0x00)
        assert len(frames) == 586

    def test_message_too_long(self, isotp_mocked_bus):
        message = [0x55] * (isotp_mocked_bus.MAX_MESSAGE_LENGTH + 1)

        with pytest.raises(ValueError) as err_message:
            isotp_mocked_bus.get_frames_from_message(message, padding_value=0x00)

        assert "Message too long for ISO-TP. Max allowed length is 4095 bytes, received 4096 bytes" == str(err_message.value)

    def test_empty_message_no_padding(self, isotp_mocked_bus):
        message = []
        frames = isotp_mocked_bus.get_frames_from_message(message, padding_value=None)
        # TODO: should that work this way?
        assert frames == [[0x00]]

    def test_empty_message_with_padding(self, isotp_mocked_bus):
        message = []
        frames = isotp_mocked_bus.get_frames_from_message(message)
        # TODO: should that work this way?
        assert frames == [[0x0] * 8]

    # Transmit
    def test_transmit_no_frames(self, isotp_mocked_bus):
        result = isotp_mocked_bus.transmit([], self.dummy_request_id, self.dummy_response_id)
        assert result is None

    def test_transmit_one_frame(self, isotp_mocked_bus):
        frames_to_send = [[0x01, 0x02, 0x03]]
        isotp_mocked_bus.send_message = MagicMock()

        isotp_mocked_bus.transmit(frames_to_send, self.dummy_request_id, self.dummy_response_id)

        isotp_mocked_bus.send_message.assert_called_once_with(frames_to_send[0], 0x7E0)

    def test_transmit_multiple_frames_flow_control(self, isotp_mocked_bus):
        frames_to_send = [
            # FF
            [0x10, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            # CF
            [0x21, 0x07, 0x08, 0x09, 0x0A],
        ]
        isotp_mocked_bus.send_message = MagicMock()
        isotp_mocked_bus.decode_fc = MagicMock(return_value=(IsoTp.FC_FS_CTS, 10, 0))  # Continue to send
        isotp_mocked_bus.bus = MagicMock()
        isotp_mocked_bus.bus.recv = MagicMock(return_value=MagicMock(arbitration_id=0x7E8, data=[0x30, 0x05, 0x00]))
        isotp_mocked_bus.transmit(frames_to_send, self.dummy_request_id, self.dummy_response_id)
        assert isotp_mocked_bus.send_message.call_count == 2

    def test_transmit_multiple_frames_flow_control_wait(self, isotp_mocked_bus):
        frames = [
            # FF
            [0x10, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            # CF
            [0x21, 0x07, 0x08, 0x09, 0x0A],
        ]
        isotp_mocked_bus.send_message = MagicMock()
        isotp_mocked_bus.decode_fc = MagicMock(return_value=(IsoTp.FC_FS_WAIT, 0, 0))  # Wait
        isotp_mocked_bus.bus = MagicMock()
        isotp_mocked_bus.bus.recv = MagicMock(side_effect=[MagicMock(arbitration_id=self.dummy_response_id, data=[0x30, 0x05, 0x00]), None])

        result = isotp_mocked_bus.transmit(frames, self.dummy_request_id, self.dummy_response_id)

        # The transmission should be interrupted, CF shall not be sent.
        isotp_mocked_bus.send_message.assert_called_once_with(frames[0], self.dummy_request_id)
        assert result is None

    def test_transmit_multiple_frames_flow_control_overflow(self, isotp_mocked_bus):
        frames = [
            # FF
            [0x10, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            # CF
            [0x21, 0x07, 0x08, 0x09, 0x0A],
        ]
        isotp_mocked_bus.send_message = MagicMock()
        isotp_mocked_bus.decode_fc = MagicMock(return_value=(IsoTp.FC_FS_OVFLW, 0, 0))  # Overflow
        isotp_mocked_bus.bus = MagicMock()
        isotp_mocked_bus.bus.recv = MagicMock(return_value=MagicMock(arbitration_id=self.dummy_response_id, data=[0x30, 0x05, 0x00]))

        result = isotp_mocked_bus.transmit(frames, self.dummy_request_id, self.dummy_response_id)

        # The transmission should be interrupted, CF shall not be sent.
        isotp_mocked_bus.send_message.assert_called_once_with(frames[0], self.dummy_request_id)
        assert result is None

    def test_transmit_multiple_frames_timeout(self, isotp_mocked_bus):
        frames = [
            # FF
            [0x10, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            # CF
            [0x21, 0x07, 0x08, 0x09, 0x0A],
        ]
        isotp_mocked_bus.send_message = MagicMock()
        isotp_mocked_bus.bus = MagicMock()
        isotp_mocked_bus.bus.recv = MagicMock(return_value=None)  # No response from the bus

        result = isotp_mocked_bus.transmit(frames, self.dummy_request_id, self.dummy_response_id)

        # The transmission should be interrupted, CF shall not be sent.
        isotp_mocked_bus.send_message.assert_called_once_with(frames[0], self.dummy_request_id)
        assert result is None

    @patch('time.sleep', return_value=None)
    def test_transmit_multiple_frames_stmin(self, mock_sleep, isotp_mocked_bus):
        frames = [
            # FF
            [0x10, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            # CF1
            [0x21, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D],
            # CF2
            [0x22, 0x0E, 0x0F]
        ]
        isotp_mocked_bus.send_message = MagicMock()
        isotp_mocked_bus.decode_fc = MagicMock(return_value=(IsoTp.FC_FS_CTS, 10, 10))  # STmin = 10 ms
        isotp_mocked_bus.bus = MagicMock()
        isotp_mocked_bus.bus.recv = MagicMock(return_value=MagicMock(arbitration_id=self.dummy_response_id, data=[0x30, 0x05, 0x00]))

        isotp_mocked_bus.transmit(frames, self.dummy_request_id, self.dummy_response_id)

        # Sleep should be called with value of the STmin.
        mock_sleep.assert_called_with(0.01)
        assert isotp_mocked_bus.send_message.call_count == 3
