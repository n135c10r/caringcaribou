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
        pending_response = [Constants.NR_SI, 0x01, NegativeResponseCodes.REQUEST_CORRECTLY_RECEIVED_RESPONSE_PENDING]
        iso14229_1.tp.indication = MagicMock(side_effect=[pending_response, [0x50, 0x02, 0x03]])
        result = iso14229_1.receive_response(iso14229_1.P3_CLIENT)

        assert result == [0x50, 0x02, 0x03]

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
        identifier = [0x1234]
        iso14229_1.tp.indication = MagicMock(return_value=[0x62, 0x12, 0x34])
        iso14229_1.tp.send_request = MagicMock()
        expected_request = [ServiceID.READ_DATA_BY_IDENTIFIER, 0x12, 0x34]
        response = iso14229_1.read_data_by_identifier(identifier)

        iso14229_1.tp.send_request.assert_called_once_with(expected_request)
        assert response == [0x62, 0x12, 0x34]

    def test_write_data_by_identifier(self, iso14229_1):
        identifier = 0x1234
        data = [0x56, 0x78]
        iso14229_1.tp.indication = MagicMock(return_value=[0x6E, 0x12, 0x34])
        iso14229_1.tp.send_request = MagicMock()
        expected_request = [ServiceID.WRITE_DATA_BY_IDENTIFIER, 0x12, 0x34, 0x56, 0x78]
        response = iso14229_1.write_data_by_identifier(identifier, data)

        iso14229_1.tp.send_request.assert_called_once_with(expected_request)
        assert response == [0x6E, 0x12, 0x34]
