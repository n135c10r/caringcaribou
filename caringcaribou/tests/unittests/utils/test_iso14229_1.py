from unittest.mock import MagicMock
from caringcaribou.utils.iso14229_1 import ServiceID, Constants, NegativeResponseCodes


class Test_iso14229_1:

    def test_get_service_response_id(self, iso14229_1):
        request_id = 0x10
        expected_response_id = request_id + 0x40

        assert iso14229_1.get_service_response_id(request_id) == expected_response_id

    def test_get_service_request_id(self, iso14229_1):
        response_id = 0x50
        expected_request_id = response_id - 0x40

        assert iso14229_1.get_service_request_id(response_id) == expected_request_id

    def test_send_request(self, iso14229_1):
        data = [0x01, 0x02, 0x03]
        iso14229_1.tp.send_request = MagicMock()
        iso14229_1.send_request(data)

        iso14229_1.tp.send_request.assert_called_once_with(data)

    def test_send_response(self, iso14229_1):
        data = [0x10, 0x20]
        iso14229_1.tp.send_response = MagicMock()
        iso14229_1.send_response(data)

        iso14229_1.tp.send_response.assert_called_once_with(data)

    def test_receive_response_timeout(self, iso14229_1):
        iso14229_1.tp.indication = MagicMock(return_value=None)
        result = iso14229_1.receive_response(iso14229_1.P3_CLIENT)

        assert result is None

    def test_receive_response_pending(self, iso14229_1):
        expected_response = [0x50, 0x02, 0x03]
        pending_response = [Constants.NR_SI, 0x01, NegativeResponseCodes.REQUEST_CORRECTLY_RECEIVED_RESPONSE_PENDING]
        iso14229_1.tp.indication = MagicMock(side_effect=[pending_response, expected_response])
        result = iso14229_1.receive_response(iso14229_1.P3_CLIENT)

        assert result == expected_response

    def test_is_positive_response(self, iso14229_1):
        positive_response = [0x50, 0x01]
        negative_response = [Constants.NR_SI, 0x28, 0x22]

        assert not iso14229_1.is_positive_response(negative_response)
        assert iso14229_1.is_positive_response(positive_response)

    def test_is_negative_response(self, iso14229_1):
        positive_response = [0x50, 0x01]
        negative_response = [Constants.NR_SI, 0x28, 0x22]

        assert not iso14229_1.is_negative_response(positive_response)
        assert iso14229_1.is_negative_response(negative_response)

    def test_read_data_by_identifier(self, iso14229_1):
        expected_response = [0x62, 0x12, 0x34]
        did = [0x1234]
        iso14229_1.tp.indication = MagicMock(return_value=expected_response)
        iso14229_1.tp.send_request = MagicMock()
        expected_request = [ServiceID.READ_DATA_BY_IDENTIFIER, 0x12, 0x34]
        response = iso14229_1.read_data_by_identifier(did)

        iso14229_1.tp.send_request.assert_called_once_with(expected_request)
        assert response == expected_response

    def test_write_data_by_identifier(self, iso14229_1):
        expected_response = [0x6E, 0x12, 0x34]
        did = 0x1234
        data = [0x56, 0x78]
        iso14229_1.tp.indication = MagicMock(return_value=expected_response)
        iso14229_1.tp.send_request = MagicMock()
        expected_request = [ServiceID.WRITE_DATA_BY_IDENTIFIER, 0x12, 0x34, 0x56, 0x78]
        response = iso14229_1.write_data_by_identifier(did, data)

        iso14229_1.tp.send_request.assert_called_once_with(expected_request)
        assert response == expected_response

    def test_input_output_control_by_identifier(self, iso14229_1):
        expected_response = [0x6F, 0x12, 0x34]
        routine_id = 0x1234
        data = [0x56, 0x78]
        iso14229_1.tp.indication = MagicMock(return_value=expected_response)
        iso14229_1.tp.send_request = MagicMock()
        expected_request = [ServiceID.INPUT_OUTPUT_CONTROL_BY_IDENTIFIER, 0x12, 0x34, 0x56, 0x78]
        response = iso14229_1.input_output_control_by_identifier(routine_id, data)

        iso14229_1.tp.send_request.assert_called_once_with(expected_request)
        assert response == expected_response

    def test_dynamically_define_data_identifier_success(self, iso14229_1):
        expected_response = []
        iso14229_1.receive_response = MagicMock(return_value=expected_response)
        iso14229_1.tp.send_request = MagicMock()
        identifier = 0x1234
        sub_function = 0x01
        sub_function_arg = [
            MagicMock(sourceDataIdentifier=0x1234, positionInSourceDataRecord=0x01, memorySize=0x01)
        ]

        response = iso14229_1.dynamically_define_data_identifier(identifier, sub_function, sub_function_arg)

        iso14229_1.tp.send_request.assert_called_once()
        assert response == expected_response

    def test_dynamically_define_data_identifier_invalid_args(self, iso14229_1):
        response = iso14229_1.dynamically_define_data_identifier(None, None, None)
        assert response is None

    def test_diagnostic_session_control_success(self, iso14229_1):
        expected_response = [0x50, 0x01]
        iso14229_1.receive_response = MagicMock(return_value=expected_response)
        iso14229_1.tp.send_request = MagicMock()
        session_type = 0x01

        response = iso14229_1.diagnostic_session_control(session_type)

        iso14229_1.tp.send_request.assert_called_once_with([ServiceID.DIAGNOSTIC_SESSION_CONTROL, session_type])
        assert response == expected_response

    def test_ecu_reset_success(self, iso14229_1):
        expected_response = [0x51, 0x02]
        iso14229_1.receive_response = MagicMock(return_value=expected_response)
        iso14229_1.tp.send_request = MagicMock()
        reset_type = 0x02

        response = iso14229_1.ecu_reset(reset_type)

        iso14229_1.tp.send_request.assert_called_once_with([ServiceID.ECU_RESET, reset_type])
        assert response == expected_response

    def test_security_access_request_seed(self, iso14229_1):
        expected_response = [0x67, 0x03, 0xAA, 0xBB, 0xCC, 0xDD]
        iso14229_1.receive_response = MagicMock(return_value=expected_response)
        iso14229_1.tp.send_request = MagicMock()
        sec_acc_lvl = 0x03

        response = iso14229_1.security_access_request_seed(sec_acc_lvl)

        iso14229_1.tp.send_request.assert_called_once_with([ServiceID.SECURITY_ACCESS, sec_acc_lvl])
        assert response == expected_response

    def test_security_access_request_seed_data_record(self, iso14229_1):
        expected_response = [0x67, 0x03, 0xAA, 0xBB, 0xCC, 0xDD]
        iso14229_1.receive_response = MagicMock(return_value=expected_response)
        iso14229_1.tp.send_request = MagicMock()
        sec_acc_lvl = 0x03
        data_record = [0x12, 0x34]

        response = iso14229_1.security_access_request_seed(sec_acc_lvl, data_record)

        iso14229_1.tp.send_request.assert_called_once_with([ServiceID.SECURITY_ACCESS, sec_acc_lvl, 0x12, 0x34])
        assert response == expected_response

    def test_security_access_send_key_success(self, iso14229_1):
        expected_response = [0x67, 0x04]
        iso14229_1.receive_response = MagicMock(return_value=expected_response)
        iso14229_1.tp.send_request = MagicMock()
        sec_acc_lvl = 0x04
        key = [0x12, 0x34, 0x56, 0x78]

        response = iso14229_1.security_access_send_key(sec_acc_lvl, key)

        iso14229_1.tp.send_request.assert_called_once_with(
            [
                ServiceID.SECURITY_ACCESS,
                sec_acc_lvl,
                0x12, 0x34, 0x56, 0x78],
        )
        assert response == expected_response

    def test_read_data_by_periodic_identifier_success(self, iso14229_1):
        expected_response = [0x11, 0xBE, 0xEF]
        iso14229_1.receive_response = MagicMock(return_value=expected_response)
        iso14229_1.tp.send_request = MagicMock()
        transmission_mode = 0x01
        identifier = [0x11]

        response = iso14229_1.read_data_by_periodic_identifier(transmission_mode, identifier)

        iso14229_1.tp.send_request.assert_called_once_with(
            [
                ServiceID.READ_DATA_BY_PERIODIC_IDENTIFIER,
                transmission_mode,
                0x11
            ]
        )
        assert response == expected_response

    def test_read_data_by_periodic_identifier_invalid_args(self, iso14229_1):
        response = iso14229_1.read_data_by_periodic_identifier(None, None)
        assert response is None
