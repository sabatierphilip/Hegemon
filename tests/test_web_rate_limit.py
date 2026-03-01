from sentinel_containment.web.app import EventTriggeredBurstGuard


def test_event_triggered_burst_mode_blocks_flooding_client():
    current_time = 100.0

    def now_fn():
        return current_time

    guard = EventTriggeredBurstGuard(
        base_window_seconds=1.0,
        base_limit=3,
        trigger_window_seconds=2.0,
        trigger_limit=4,
        burst_window_seconds=1.0,
        burst_limit=1,
        burst_duration_seconds=5.0,
        now_fn=now_fn,
    )

    assert guard.allow("10.0.0.1")
    assert guard.allow("10.0.0.1")
    assert guard.allow("10.0.0.2")
    assert guard.allow("10.0.0.3")

    # Trigger threshold has been reached globally; burst mode now applies.
    assert guard.allow("10.0.0.4")
    assert not guard.allow("10.0.0.4")

    current_time += 1.1
    assert guard.allow("10.0.0.4")



def test_guard_recovers_after_burst_duration():
    current_time = 0.0

    def now_fn():
        return current_time

    guard = EventTriggeredBurstGuard(
        base_window_seconds=1.0,
        base_limit=2,
        trigger_window_seconds=2.0,
        trigger_limit=2,
        burst_window_seconds=1.0,
        burst_limit=1,
        burst_duration_seconds=2.0,
        now_fn=now_fn,
    )

    assert guard.allow("1.1.1.1")
    assert guard.allow("2.2.2.2")
    assert guard.allow("3.3.3.3")
    assert not guard.allow("3.3.3.3")

    current_time += 2.1
    assert guard.allow("3.3.3.3")
    assert guard.allow("3.3.3.3")
    assert not guard.allow("3.3.3.3")
