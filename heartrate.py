"""
heartrate.py – DFRobot SEN0203 sensor driver (digital mode)
GPIO26 = D2/D3 på FireBeetle Covers Gravity Shield

Persistent logging: readings gemmes til heartrate_log.json på flash
RAM buffer: kun seneste MAX_HISTORY_RAM readings for live graph
"""

from machine import Pin
import time
import json

DIGITAL_PIN   = 26
MIN_BEAT_MS   = 300
MAX_BEAT_MS   = 2000
NUM_SAMPLES   = 10
MAX_HISTORY_RAM = 20  # Små RAM buffer til live graph
LOG_FILE = "heartrate_log.json"


class HeartRateSensor:

    def __init__(self, pin_num=DIGITAL_PIN):
        self._pin          = Pin(pin_num, Pin.IN, Pin.PULL_DOWN)
        self._last_state   = 0
        self._last_edge_ms = None
        self._intervals    = []
        self._bpm          = 0
        self._history      = []   # Små RAM buffer (seneste lesninger til web)
        self._save_count   = 0    # Counter for at gemme hver N lesninger

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
        """Gem lesning til RAM buffer + fil."""
        self._history.append((ts, bpm))
        if len(self._history) > MAX_HISTORY_RAM:
            self._history.pop(0)
        
        # Gem til fil hver 10. lesning (spare flash writes)
        self._save_count += 1
        if self._save_count >= 10:
            self._save_count = 0
            self._append_to_file(ts, bpm)

    def _append_to_file(self, ts, bpm):
        """Append lesning til heartrate_log.json."""
        try:
            # Læs eksisterende log
            try:
                with open(LOG_FILE, "r") as f:
                    content = f.read()
                    if content.strip():
                        data = json.loads(content)
                    else:
                        data = []
            except:
                data = []
            
            # Tilføj ny lesning
            data.append({"t": ts, "bpm": bpm})
            
            # Bevar kun seneste 1000 lesninger (spare flash space)
            if len(data) > 1000:
                data = data[-1000:]
            
            # Skriv tilbage (overskriver hele filen)
            with open(LOG_FILE, "w") as f:
                json.dump(data, f, separators=(',', ':'))
        except Exception as e:
            print("[HeartRate] Fil-skrivefejl: {}".format(e))

    @property
    def bpm(self):
        return self._bpm

    @property
    def history(self):
        """Returnerer seneste RAM-buffered lesninger (til live graph)."""
        return list(self._history)

    def history_json(self):
        """Returnerer RAM-buffer som JSON-string til web-server (live graph)."""
        entries = ["{{\"t\":{},\"bpm\":{}}}".format(t, b) for t, b in self._history]
        return "[" + ",".join(entries) + "]"
    
    def get_full_history(self):
        """Læs alle lesninger fra fil. Returnerer liste af dicts."""
        try:
            with open(LOG_FILE, "r") as f:
                content = f.read()
                if content.strip():
                    return json.loads(content)
        except:
            pass
        return []
    
    def get_full_history_json(self):
        """Returnerer alle lesninger fra fil som JSON-string."""
        try:
            with open(LOG_FILE, "r") as f:
                return f.read()
        except:
            return "[]"
    
    def clear_history(self):
        """Slet al data fra fil og RAM buffer."""
        try:
            with open(LOG_FILE, "w") as f:
                f.write("[]")
        except:
            pass
        self._history = []
        self._save_count = 0