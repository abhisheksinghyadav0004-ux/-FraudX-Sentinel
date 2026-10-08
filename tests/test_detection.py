import unittest

from backend.detection import detect_event


class Event:
    def __init__(self, event_type, device_id="device-1", source_ip="203.0.113.2", risk_context="", metadata_json="{}"):
        self.event_type = event_type
        self.device_id = device_id
        self.source_ip = source_ip
        self.risk_context = risk_context
        self.metadata_json = metadata_json


class DetectionTests(unittest.TestCase):
    def test_payment_rule_detects_high_value_new_beneficiary(self):
        event = Event("TRANSACTION", metadata_json='{"amount": 50000, "new_beneficiary": true}')
        finding = detect_event(event, [event], {"RULE-PAY-001"})
        self.assertEqual(finding[2], "Payment Fraud")

    def test_disabled_rule_does_not_detect(self):
        event = Event("TRANSACTION", metadata_json='{"amount": 50000, "new_beneficiary": true}')
        self.assertIsNone(detect_event(event, [event], set()))

    def test_booking_rule_requires_velocity(self):
        events = [Event("BOOKING_REQUEST", device_id="shared-device") for _ in range(6)]
        finding = detect_event(events[-1], events, {"RULE-BOOK-001"})
        self.assertEqual(finding[0], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
