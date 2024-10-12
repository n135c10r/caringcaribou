import pytest

from unittest.mock import MagicMock, patch

from caringcaribou.utils.constants import ARBITRATION_ID_MAX_EXTENDED
from caringcaribou.utils.iso15765_2 import IsoTp


class TestIso15765_2:
    def test_isotp_initialization_default_bus(self, isotp_mocked_bus):
        assert isotp_mocked_bus.arb_id_request == 0x7E0
        assert isotp_mocked_bus.arb_id_response == 0x7E8
        assert isotp_mocked_bus.padding_value == 0x00
        assert isotp_mocked_bus.padding_enabled is True
        assert isotp_mocked_bus.bus.name == "DUMMY_INTERFACE"

    def test_isotp_initialization_custom_bus(self):
        isotp = IsoTp(0x7E0, 0x7E8, bus="DUMMY_INTERFACE", padding_value=0xAA)
        assert isotp.padding_value == 0xAA
        assert isotp.padding_enabled is True
        assert isotp.bus == "DUMMY_INTERFACE"

    def test_isotp_initialization_no_padding(self, bus_mock):
        isotp = IsoTp(0x7E0, 0x7E8, padding_value=None)
        assert isotp.padding_enabled is False

    def test_isotp_initialization_invalid_padding_type(self, bus_mock):
        expected_err_message = "IsoTp: padding must be an integer or None, received 'invalid'"
        with pytest.raises(TypeError) as err_message:
            IsoTp(0x7E0, 0x7E8, padding_value="invalid")

        assert expected_err_message == str(err_message.value)

    def test_isotp_initialization_invalid_padding_value(self, bus_mock):
        expected_err_message = "IsoTp: padding must be in range 0x00-0xFF (0-255), got '511'"
        with pytest.raises(ValueError) as err_message:
            IsoTp(0x7E0, 0x7E8, padding_value=0x1FF)

        assert expected_err_message == str(err_message.value)

    def test_isotp__exit__(self, bus_mock):
        with IsoTp(0x7E0, 0x7E8) as isotp:
            assert isotp.padding_value == 0x00
        isotp.bus.shutdown.assert_called_once()

    def test_set_filter_single_arbitration_id(self, isotp_mocked_bus):
        isotp_mocked_bus.set_filter_single_arbitration_id(0x123)
        expected_filter = [{"can_id": 0x123, "can_mask": ARBITRATION_ID_MAX_EXTENDED}]

        isotp_mocked_bus.bus.set_filters.assert_called_once_with(expected_filter)

    def test_clear_filters(self, isotp_mocked_bus):
        isotp_mocked_bus.clear_filters()

        isotp_mocked_bus.bus.set_filters.assert_called_once_with(None)


class TestSendMessage:
    def test_send_message_standard_id(self, isotp_mocked_bus, message_mock):
        isotp_mocked_bus.send_message(data=[0x01, 0x02, 0x03], arbitration_id=0x123)

        message_mock.assert_called_once_with(arbitration_id=0x123, data=[0x01, 0x02, 0x03], is_extended_id=False)
        isotp_mocked_bus.bus.send.assert_called_once_with(message_mock.return_value)

    def test_send_message_extended_id(self, isotp_mocked_bus, message_mock):
        isotp_mocked_bus.send_message(data=[0x03, 0x02, 0x01], arbitration_id=0x800)

        message_mock.assert_called_once_with(arbitration_id=0x800, data=[0x03, 0x02, 0x01], is_extended_id=True)
        isotp_mocked_bus.bus.send.assert_called_once_with(message_mock.return_value)


class TestDecodeFrames:
    # Decode Single Frame
    def test_decode_sf_valid_frame(self, isotp_mocked_bus):
        frame = [
            0x02,  # The first nibble indicates the Frame Type, second nibble represents the payload length.
            0xAA,
            0xBB,
        ]

        sf_data_len, data = isotp_mocked_bus.decode_sf(frame)

        assert sf_data_len == 2
        assert data == [0xAA, 0xBB]

    def test_decode_sf_frame_too_short(self, isotp_mocked_bus):
        frame = [0x01]
        isotp_mocked_bus.SF_PCI_LENGTH = 2

        sf_data_len, data = isotp_mocked_bus.decode_sf(frame)

        assert sf_data_len is None
        assert data is None

    def test_decode_sf_no_additional_data(self, isotp_mocked_bus):
        # TODO: should this work that way? No relation between frame len and PCI value.
        frame = [0x01]

        sf_data_len, data = isotp_mocked_bus.decode_sf(frame)

        assert sf_data_len == 1
        assert data == []

    def test_decode_sf_max_length_data(self, isotp_mocked_bus):
        frame = [0x07] + [0xFF] * 7

        sf_data_len, data = isotp_mocked_bus.decode_sf(frame)

        assert sf_data_len == 7
        assert data == [0xFF] * 7

    # Decode First Frame
    def test_decode_ff_valid_frame_len1(self, isotp_mocked_bus):
        # TODO: this should work in this way? No relation between ff_data_len and frame length.
        frame = [
            0x10,  # The first nibble of the first byte indicates the Frame Type,
            # second nibble represents the upper 4 bits of the payload length.
            0x01,  # The second byte contains the lower 8 bits of the payload length.
            0xAA,
            0xBB,
        ]

        ff_data_len, data = isotp_mocked_bus.decode_ff(frame)

        assert ff_data_len == 1
        assert data == [0xAA, 0xBB]

    def test_decode_ff_valid_frame_len4095(self, isotp_mocked_bus):
        frame = [0x1F, 0xFF, 0xAA, 0xBB]

        ff_data_len, data = isotp_mocked_bus.decode_ff(frame)

        assert ff_data_len == 4095
        assert data == [0xAA, 0xBB]

    def test_decode_ff_frame_too_short(self, isotp_mocked_bus):
        frame = [0x10]

        ff_data_len, data = isotp_mocked_bus.decode_ff(frame)

        assert ff_data_len is None
        assert data is None

    def test_decode_ff_valid_frame_max_bytes(self, isotp_mocked_bus):
        frame = [0x10, 0x06] + [0xFF] * 6

        ff_data_len, data = isotp_mocked_bus.decode_ff(frame)

        assert ff_data_len == 6
        assert data == [0xFF] * 6

    # Decode Consecutive Frame
    def test_decode_cf_valid_frame(self, isotp_mocked_bus):
        frame = [0x02, 0xAA, 0xBB]

        cf_data_len, data = isotp_mocked_bus.decode_cf(frame)

        assert cf_data_len == 2
        assert data == [0xAA, 0xBB]

    def test_decode_cf_frame_too_short(self, isotp_mocked_bus):
        frame = [0x01]
        isotp_mocked_bus.CF_PCI_LENGTH = 2

        cf_data_len, data = isotp_mocked_bus.decode_cf(frame)

        assert cf_data_len is None
        assert data is None

    def test_decode_cf_no_additional_data(self, isotp_mocked_bus):
        # TODO: should this work that way? No relation between frame len and PCI value.
        frame = [0x01]

        cf_data_len, data = isotp_mocked_bus.decode_cf(frame)

        assert cf_data_len == 1
        assert data == []

    def test_decode_cf_max_length_data(self, isotp_mocked_bus):
        frame = [0x07] + [0xFF] * 7

        cf_data_len, data = isotp_mocked_bus.decode_cf(frame)

        assert cf_data_len == 7
        assert data == [0xFF] * 7

    # Decode Flow Control
    def test_decode_fc_valid_frame(self, isotp_mocked_bus):
        # Flow Control Frame: FlowSatus=0, BlockSize=5, STmin=10ms
        frame = [0x30, 0x05, 0x0A]

        flow_status, block_size, st_min = isotp_mocked_bus.decode_fc(frame)

        assert flow_status == 0
        assert block_size == 5
        assert st_min == 10

    def test_decode_fc_frame_too_short(self, isotp_mocked_bus):
        frame = [0x30, 0x05]

        flow_status, block_size, st_min = isotp_mocked_bus.decode_fc(frame)

        assert flow_status is None
        assert block_size is None
        assert st_min is None

    def test_decode_fc_zero_values(self, isotp_mocked_bus):
        frame = [0x00, 0x00, 0x00]

        flow_status, block_size, st_min = isotp_mocked_bus.decode_fc(frame)

        assert flow_status == 0
        assert block_size == 0
        assert st_min == 0

    def test_decode_fc_max_values(self, isotp_mocked_bus):
        frame = [0x3F, 0xFF, 0xFF]

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


class TestGetFramesFromMessage:
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
            [0x21, 0x07, 0x08, 0x09, 0x0A, 0x00, 0x00, 0x00],
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

        assert "Message too long for ISO-TP. Max allowed length is 4095 bytes, received 4096 bytes" == str(
            err_message.value
        )

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


class TestIndication:
    # Indication
    def test_indication_single_frame(self, isotp_mocked_bus):
        # SF with 3 bytes of data
        single_frame = [0x03, 0x11, 0x22, 0x33]
        isotp_mocked_bus.bus.recv = MagicMock(return_value=MagicMock(arbitration_id=0x7E0, data=single_frame))

        result = isotp_mocked_bus.indication()

        assert result == [0x11, 0x22, 0x33]

    def test_indication_single_frame_unknown_arb_id(self, isotp_mocked_bus):
        single_frame = [0x03, 0x11, 0x22, 0x33]
        isotp_mocked_bus.bus.recv = MagicMock(return_value=MagicMock(arbitration_id=0x777, data=single_frame))

        result = isotp_mocked_bus.indication()

        assert result is None

    def test_indication_single_frame_timeout(self, isotp_mocked_bus):
        single_frame = [0x03, 0x11, 0x22, 0x33]
        isotp_mocked_bus.bus.recv = MagicMock(return_value=MagicMock(arbitration_id=0x7E0, data=single_frame))

        result = isotp_mocked_bus.indication(wait_window=0)

        assert result is None

    def test_indication_multi_frame(self, isotp_mocked_bus):
        # First Frame with info about 10 bytes of payload length
        first_frame = [0x10, 0x0A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        # Consecutive Frame with sequence number 1
        consecutive_frame = [0x21, 0x77, 0x88, 0x99, 0xAA, 0x00, 0x00, 0x00]

        isotp_mocked_bus.bus.recv = MagicMock(
            side_effect=[
                MagicMock(arbitration_id=0x7E0, data=first_frame),
                MagicMock(arbitration_id=0x7E0, data=consecutive_frame),
            ]
        )
        # Default trim_padding is True
        result = isotp_mocked_bus.indication(trim_padding=True)

        assert result == [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA]

    def test_indication_no_trim_padding(self, isotp_mocked_bus):
        first_frame = [0x10, 0x0A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        consecutive_frame = [0x21, 0x77, 0x88, 0x99, 0xAA, 0x00, 0x00, 0x00]

        isotp_mocked_bus.bus.recv = MagicMock(
            side_effect=[
                MagicMock(arbitration_id=0x7E0, data=first_frame),
                MagicMock(arbitration_id=0x7E0, data=consecutive_frame),
            ]
        )

        result = isotp_mocked_bus.indication(trim_padding=False)

        assert result == [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0x00, 0x00, 0x00]

    def test_indication_first_frame_only(self, isotp_mocked_bus):
        first_frame = [0x10, 0x0A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        consecutive_frame = [0x21, 0x77, 0x88, 0x99, 0xAA, 0x00, 0x00, 0x00]

        isotp_mocked_bus.bus.recv = MagicMock(
            side_effect=[
                MagicMock(arbitration_id=0x7E0, data=first_frame),
                MagicMock(arbitration_id=0x7E0, data=consecutive_frame),
            ]
        )

        result = isotp_mocked_bus.indication(first_frame_only=True)

        assert result == [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]


class TestTransmit:
    # Transmit
    def test_transmit_no_frames(self, isotp_mocked_bus):
        result = isotp_mocked_bus.transmit([], arbitration_id=0x7E0, arbitration_id_flow_control=0x7E8)
        assert result is None

    def test_transmit_one_frame(self, isotp_mocked_bus):
        frames_to_send = [[0x01, 0x02, 0x03]]
        isotp_mocked_bus.send_message = MagicMock()

        isotp_mocked_bus.transmit(frames_to_send, 0x7E0, 0x7E8)

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
        isotp_mocked_bus.transmit(frames_to_send, 0x7E0, 0x7E8)
        assert isotp_mocked_bus.send_message.call_count == 2

    def test_transmit_multiple_frames_flow_control_wait(self, isotp_mocked_bus):
        frames = [
            # FF
            [0x10, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            # CF
            [0x21, 0x07, 0x08, 0x09, 0x0A],
        ]
        isotp_mocked_bus.send_message = MagicMock()
        # Wait
        isotp_mocked_bus.decode_fc = MagicMock(return_value=(IsoTp.FC_FS_WAIT, 0, 0))
        isotp_mocked_bus.bus = MagicMock()
        isotp_mocked_bus.bus.recv = MagicMock(
            side_effect=[MagicMock(arbitration_id=0x7E8, data=[0x30, 0x05, 0x00]), None]
        )

        result = isotp_mocked_bus.transmit(frames, 0x7E0, 0x7E8)

        # The transmission should be interrupted, CF shall not be sent.
        isotp_mocked_bus.send_message.assert_called_once_with(frames[0], 0x7E0)
        assert result is None

    def test_transmit_multiple_frames_flow_control_overflow(self, isotp_mocked_bus):
        frames = [
            # FF
            [0x10, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            # CF
            [0x21, 0x07, 0x08, 0x09, 0x0A],
        ]
        isotp_mocked_bus.send_message = MagicMock()
        # Overflow
        isotp_mocked_bus.decode_fc = MagicMock(return_value=(IsoTp.FC_FS_OVFLW, 0, 0))
        isotp_mocked_bus.bus = MagicMock()
        isotp_mocked_bus.bus.recv = MagicMock(return_value=MagicMock(arbitration_id=0x7E8, data=[0x30, 0x05, 0x00]))

        result = isotp_mocked_bus.transmit(frames, 0x7E0, 0x7E8)

        # The transmission should be interrupted, CF shall not be sent.
        isotp_mocked_bus.send_message.assert_called_once_with(frames[0], 0x7E0)
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
        # No response from the bus
        isotp_mocked_bus.bus.recv = MagicMock(return_value=None)

        result = isotp_mocked_bus.transmit(frames, 0x7E0, 0x7E8)

        # The transmission should be interrupted, CF shall not be sent.
        isotp_mocked_bus.send_message.assert_called_once_with(frames[0], 0x7E0)
        assert result is None

    @patch("time.sleep", return_value=None)
    def test_transmit_multiple_frames_stmin(self, mock_sleep, isotp_mocked_bus):
        frames = [
            # FF
            [0x10, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            # CF1
            [0x21, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D],
            # CF2
            [0x22, 0x0E, 0x0F],
        ]
        isotp_mocked_bus.send_message = MagicMock()
        isotp_mocked_bus.decode_fc = MagicMock(return_value=(IsoTp.FC_FS_CTS, 10, 10))  # STmin = 10 ms
        isotp_mocked_bus.bus = MagicMock()
        isotp_mocked_bus.bus.recv = MagicMock(return_value=MagicMock(arbitration_id=0x7E8, data=[0x30, 0x05, 0x00]))

        isotp_mocked_bus.transmit(frames, 0x7E0, 0x7E8)

        # Sleep should be called with value of the STmin.
        mock_sleep.assert_called_with(0.01)
        assert isotp_mocked_bus.send_message.call_count == 3
