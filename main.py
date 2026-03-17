import socket
import time
import gc
import json

from heartrate    import HeartRateSensor
from wifi_manager import WiFiManager
from ota          import OTAUpdater

SAMPLE_INTERVAL_MS = 20


def main():
    print("\n" + "="*48)
    print("  HeartRate Monitor v1.0")
    print("  ESP32 WROOM-32D + DFRobot SEN0203")
    print("="*48 + "\n")

    # 1. OTA-tjek ved opstart
    try:
        with open("config.json") as f:
            cfg = json.load(f)
        ota_url = cfg.get("ota_url", "")
    except:
        ota_url = ""

    if ota_url and "github" in ota_url.lower():
        ota = OTAUpdater(ota_url)
        ota.run_if_triggered()
    else:
        ota = None

    # 2. Initialiser sensor
    sensor = HeartRateSensor(pin_num=26)
    print("[Sensor] Initialiseret på GPIO26")

    # 3. WiFi
    wifi = WiFiManager()
    connected = wifi.connect_sta(timeout=20)

    if not connected:
        print("[WiFi] Starter Access Point + captive portal...")
        wifi.start_ap()
    else:
        wifi.stop_ap()
        print("[WiFi] Tilsluttet. Web-server på http://{}".format(wifi.ip))
        # mDNS - boardet kan findes på http://heartscan.local
        try:
            import network
            network.hostname("heartscan")
            print("[mDNS] Tilgaengelig paa http://heartscan.local")
        except Exception as e:
            print("[mDNS] Ikke tilgaengelig: {}".format(e))

    # 4. Start HTTP server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 80))
    server.listen(3)
    server.setblocking(False)
    print("[Web] Lytter på port 80")

    # 5. Hoved-loop
    last_sample = time.ticks_ms()
    last_gc     = time.ticks_ms()

    print("\n[Loop] Kører...\n")

    while True:
        now = time.ticks_ms()

        # Sensor sampling
        if time.ticks_diff(now, last_sample) >= SAMPLE_INTERVAL_MS:
            sensor.sample()
            last_sample = now

        # DNS (kun aktiv under AP-mode)
        wifi.handle_dns()

        # HTTP
        try:
            conn, addr = server.accept()
            conn.setblocking(True)
            try:
                wifi.handle_request(conn, addr, sensor=sensor)
            except Exception as e:
                print("[Web] Fejl: {}".format(e))
                try:
                    conn.close()
                except:
                    pass
        except OSError:
            pass

        # OTA + GC hver 30 sek
        if time.ticks_diff(now, last_gc) >= 30000:
            if ota:
                ota.run_if_triggered()
            gc.collect()
            last_gc = now


try:
    main()
except KeyboardInterrupt:
    print("\n[Stop] Afbrudt af bruger.")
except Exception as e:
    import sys
    print("\n[FATAL] {}".format(e))
    sys.print_exception(e)
    time.sleep(5)
    import machine
    machine.reset()