"""
heartrate.py – DFRobot SEN0203 sensor driver (digital mode)
GPIO26 = D2/D3 på FireBeetle Covers Gravity Shield
"""

from machine import Pin
import time

DIGITAL_PIN   = 26
MIN_BEAT_MS   = 300
MAX_BEAT_MS   = 2000
NUM_SAMPLES   = 10
MAX_HISTORY   = 100   # Maks antal BPM-målinger vi gemmer i RAM


class HeartRateSensor:

    def __init__(self, pin_num=DIGITAL_PIN):
        self._pin          = Pin(pin_num, Pin.IN, Pin.PULL_DOWN)
        self._last_state   = 0
        self._last_edge_ms = None
        self._intervals    = []
        self._bpm          = 0
        self._history      = []   # liste af (timestamp_ms, bpm)

    def sample(self):
        """Kald ~50x/sek. Returnerer aktuel BPM (0 = ingen måling endnu)."""
        state = self._pin.value()
        now   = time.ticks_ms()

        if state == 1 and self._last_state == 0:
            if self._last_edge_ms is not None:
                interval = time.ticks_diff(now, self._last_edge_ms)
                if MIN_BEAT_MS <= interval <= MAX_BEAT_MS:
                    self._intervals.append(interval)
                    if len(self._intervals) > NUM_SAMPLES:
                        self._intervals.pop(0)
                    if len(self._intervals) >= 3:
                        avg = sum(self._intervals) / len(self._intervals)
                        self._bpm = int(60000 / avg)
                        self._record(now, self._bpm)
            self._last_edge_ms = now

        self._last_state = state
        return self._bpm

    def _record(self, ts, bpm):
        self._history.append((ts, bpm))
        if len(self._history) > MAX_HISTORY:
            self._history.pop(0)

    @property
    def bpm(self):
        return self._bpm

    @property
    def history(self):
        """Returnerer liste af (timestamp_ms, bpm) tuples."""
        return list(self._history)

    def history_json(self):
        """Returnerer historik som JSON-string til web-server."""
        entries = ["{{\"t\":{},\"bpm\":{}}}".format(t, b) for t, b in self._history]
        return "[" + ",".join(entries) + "]"