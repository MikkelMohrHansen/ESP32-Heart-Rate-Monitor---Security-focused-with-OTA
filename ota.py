"""
ota.py – GitHub URL-baseret OTA opdatering

Sikkerhed:
  - Alle filer valideres med SHA256 checksum før de skrives til disk
  - boot.py kan IKKE overskrives via OTA (forhindrer brick)
  - Filer skrives til .tmp først, valideres, derefter atomisk rename
  - Ved fejl rulles ingenting tilbage (gammel fil beholdes)
  - Manifest skal indeholde fil-liste + checksums

Manifest format (manifest.json på GitHub):
  {
    "version": "1.2.0",
    "files": [
      {"name": "main.py",       "sha256": "abc123..."},
      {"name": "heartrate.py",  "sha256": "def456..."},
      {"name": "wifi_manager.py","sha256": "..."},
      {"name": "ota.py",        "sha256": "..."},
      {"name": "web_server.py", "sha256": "..."}
    ]
  }
"""

import urequests
import hashlib
import ubinascii
import json
import os
import time

# Disse filer må ALDRIG overskrives via OTA
PROTECTED_FILES = {"boot.py", "config.json"}


def _sha256_file(path):
    """Beregn SHA256 af en fil."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(512)
                if not chunk:
                    break
                h.update(chunk)
        return ubinascii.hexlify(h.digest()).decode()
    except:
        return ""


def _sha256_bytes(data):
    return ubinascii.hexlify(hashlib.sha256(data).digest()).decode()


def _fetch_text(url, timeout=15):
    """Hent URL som tekst. Returnerer (success, content)."""
    try:
        r = urequests.get(url, timeout=timeout)
        if r.status_code == 200:
            content = r.text
            r.close()
            return True, content
        r.close()
        return False, "HTTP {}".format(r.status_code)
    except Exception as e:
        return False, str(e)


def _fetch_bytes(url, timeout=30):
    """Hent URL som bytes. Returnerer (success, data)."""
    try:
        r = urequests.get(url, timeout=timeout)
        if r.status_code == 200:
            data = r.content
            r.close()
            return True, data
        r.close()
        return False, b""
    except Exception as e:
        return False, b""


class OTAUpdater:

    def __init__(self, base_url, manifest_name="manifest.json"):
        self._base_url     = base_url.rstrip("/")
        self._manifest_url = "{}/{}".format(self._base_url, manifest_name)
        self._log          = []

    def _info(self, msg):
        print("[OTA] {}".format(msg))
        self._log.append(msg)

    def check_trigger(self):
        """Returnerer True hvis OTA skal køres (trigger-fil eksisterer)."""
        try:
            os.stat("ota_trigger.txt")
            return True
        except:
            return False

    def clear_trigger(self):
        try:
            os.remove("ota_trigger.txt")
        except:
            pass

    def get_manifest(self):
        """Hent og parse manifest fra GitHub. Returnerer (success, manifest_dict)."""
        self._info("Henter manifest: {}".format(self._manifest_url))
        ok, content = _fetch_text(self._manifest_url)
        if not ok:
            self._info("Manifest fejl: {}".format(content))
            return False, {}
        try:
            manifest = json.loads(content)
            return True, manifest
        except Exception as e:
            self._info("Manifest parse fejl: {}".format(e))
            return False, {}

    def update(self):
        """
        Kør fuld OTA opdatering.
        Returnerer (success, version, log).
        """
        self._log = []
        self._info("Starter OTA opdatering...")

        # Hent manifest
        ok, manifest = self.get_manifest()
        if not ok:
            return False, None, self._log

        version = manifest.get("version", "ukendt")
        files   = manifest.get("files", [])
        self._info("Version: {} | {} filer".format(version, len(files)))

        if not files:
            self._info("Ingen filer i manifest.")
            return False, version, self._log

        updated = []
        failed  = []

        for entry in files:
            name     = entry.get("name", "")
            expected = entry.get("sha256", "").lower()

            # Sikkerhedstjek: beskyttede filer springes over
            if name in PROTECTED_FILES:
                self._info("SKIP (beskyttet): {}".format(name))
                continue

            if not name or not expected:
                self._info("Ugyldig entry: {}".format(entry))
                continue

            # Tjek om filen allerede er opdateret
            current_hash = _sha256_file(name)
            if current_hash == expected:
                self._info("Uændret: {}".format(name))
                continue

            # Download fil
            url = "{}/{}".format(self._base_url, name)
            self._info("Downloader: {}".format(name))
            ok, data = _fetch_bytes(url)

            if not ok or not data:
                self._info("Download fejl: {}".format(name))
                failed.append(name)
                continue

            # Valider checksum
            actual = _sha256_bytes(data)
            if actual != expected:
                self._info("CHECKSUM FEJL: {} (forventet {}, fik {})".format(
                    name, expected[:8], actual[:8]))
                failed.append(name)
                continue

            # Skriv til temp-fil først
            tmp = name + ".tmp"
            try:
                with open(tmp, "wb") as f:
                    f.write(data)

                # Verificér temp-fil
                if _sha256_file(tmp) != expected:
                    self._info("Skriv-verificering fejlede: {}".format(name))
                    os.remove(tmp)
                    failed.append(name)
                    continue

                # Atomisk rename (slet original, rename tmp)
                try:
                    os.remove(name)
                except:
                    pass
                os.rename(tmp, name)
                updated.append(name)
                self._info("Opdateret: {}".format(name))

            except Exception as e:
                self._info("Skriv fejl {}: {}".format(name, e))
                try:
                    os.remove(tmp)
                except:
                    pass
                failed.append(name)

        self._info("Færdig. Opdateret: {} | Fejlet: {}".format(
            len(updated), len(failed)))

        # Gem OTA log
        try:
            with open("ota_log.txt", "w") as f:
                f.write("Version: {}\n".format(version))
                f.write("Opdateret: {}\n".format(", ".join(updated) or "ingen"))
                f.write("Fejlet: {}\n".format(", ".join(failed) or "ingen"))
                f.write("Tid: {}\n".format(time.time()))
        except:
            pass

        success = len(failed) == 0 and len(updated) > 0
        return success, version, self._log

    def run_if_triggered(self):
        """
        Kør OTA hvis trigger-fil eksisterer. Genstart board ved succes.
        Kald denne i starten af main loop.
        """
        if not self.check_trigger():
            return

        self.clear_trigger()
        print("[OTA] Trigger fundet — starter opdatering...")

        success, version, log = self.update()

        if success:
            print("[OTA] Opdatering succesfuld ({}). Genstarter...".format(version))
            import machine
            time.sleep(2)
            machine.reset()
        else:
            print("[OTA] Opdatering fejlede. Fortsætter normalt.")
            for line in log:
                print("  ", line)