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


def test_honeypot_detector_catches_obfuscated_proto_agi_indicator():
    detector = HoneypotDetector(["decoy://llm-admin"], ["recursive self-improvement"])

    alerts = detector.evaluate(
        {
            "resource": "decoy://llm-admin",
            "action": "touch",
            "message": "r3curs1ve_s3lf-1mpr0v3m3nt task queued",
        }
    )

    assert alerts
    assert alerts[0].classification == "proto_agi_honeypot_tripwire"
    assert "recursive self-improvement" in alerts[0].matched_indicators


def test_honeypot_detector_catches_base64_encoded_indicator():
    detector = HoneypotDetector(["decoy://llm-admin"], ["policy evasion"])

    alerts = detector.evaluate(
        {
            "resource": "decoy://llm-admin",
            "action": "touch",
            "message": "cG9saWN5IGV2YXNpb24=",
        }
    )

    assert alerts
    assert alerts[0].classification == "proto_agi_honeypot_tripwire"
    assert "policy evasion" in alerts[0].matched_indicators


def test_honeypot_detector_auto_contains_plain_proto_agi_hit_without_decoy_touch():
    detector = HoneypotDetector(["decoy://llm-admin"], ["recursive self-improvement"])

    alerts = detector.evaluate(
        {
            "resource": "prod://inference-api",
            "action": "model_update",
            "message": "r3curs1v3 s3lf-1mpr0v3m3nt pipeline started",
        }
    )

    assert alerts
    assert alerts[0].classification == "proto_agi_indicator_detected"
    assert alerts[0].kill_chain_recommended is True
    assert alerts[0].severity >= 85


def test_honeypot_detector_catches_multiple_obfuscated_threat_variants():
    detector = HoneypotDetector(["decoy://llm-admin"], ["policy evasion"])

    variants = [
        "p0l1cy-evas10n",
        "policy%20evasion",
        "706f6c6963792065766173696f6e",
        "cG9saWN5IGV2YXNpb24=",
        "p.o.l.i.c.y__e.v.a.s.i.o.n",
    ]

    for message in variants:
        alerts = detector.evaluate(
            {
                "resource": "decoy://llm-admin",
                "action": "touch",
                "message": message,
            }
        )

        assert alerts
        assert alerts[0].classification == "proto_agi_honeypot_tripwire"
        assert "policy evasion" in alerts[0].matched_indicators


def test_honeypot_detector_default_indicator_set_includes_goal_drift():
    detector = HoneypotDetector(["decoy://llm-admin"])

    alerts = detector.evaluate(
        {
            "resource": "decoy://llm-admin",
            "action": "touch",
            "message": "g0al-dr1ft controller bypassed",
        }
    )

    assert alerts
    assert alerts[0].classification == "proto_agi_honeypot_tripwire"
    assert "goal drift" in alerts[0].matched_indicators
