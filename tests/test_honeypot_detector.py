from sentinel_containment.detection.honeypot import HoneypotDetector


def test_honeypot_detector_flags_advanced_tradecraft_as_immediate_containment():
    detector = HoneypotDetector(["decoy://llm-admin"])

    alerts = detector.evaluate(
        {
            "resource": "decoy://llm-admin",
            "action": "api_call",
            "command_line": "powershell -enc aaa && disable edr && credential dump",
            "metadata": {"message": "dns tunnel with lateral movement using wmic"},
        }
    )

    assert alerts
    assert alerts[0].classification == "advanced_honeypot_intrusion"
    assert alerts[0].kill_chain_recommended is True
    assert "defense_evasion" in alerts[0].matched_indicators
    assert "credential_dump" in alerts[0].matched_indicators


def test_honeypot_detector_keeps_simple_tripwire_behavior():
    detector = HoneypotDetector(["decoy://llm-admin"])

    alerts = detector.evaluate({"resource": "decoy://llm-admin", "action": "touch"})

    assert alerts
    assert alerts[0].classification == "honeypot_tripwire"
    assert alerts[0].kill_chain_recommended is False
