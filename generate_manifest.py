#!/usr/bin/env python3
"""
generate_manifest.py – Kør dette på din PC/Mac/Linux maskine
før du pusher filer til GitHub, for at generere korrekte SHA256 checksums.

Brug:
  python3 generate_manifest.py --version 1.1.0
  python3 generate_manifest.py  (bruger version fra eksisterende manifest.json)

Output: manifest.json (klar til at pulle til GitHub repo)
"""

import hashlib
import json
import sys
import os

OTA_FILES = [
    "main.py",
    "heartrate.py",
    "wifi_manager.py",
    "ota.py",
]

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    version = "1.0.0"

    # Læs version fra args eller eksisterende manifest
    if "--version" in sys.argv:
        idx = sys.argv.index("--version")
        if idx + 1 < len(sys.argv):
            version = sys.argv[idx + 1]
    elif os.path.exists("manifest.json"):
        try:
            with open("manifest.json") as f:
                old = json.load(f)
            version = old.get("version", version)
        except:
            pass

    files = []
    missing = []

    for name in OTA_FILES:
        if os.path.exists(name):
            checksum = sha256_file(name)
            files.append({"name": name, "sha256": checksum})
            print("✓ {}  {}".format(name, checksum[:16] + "..."))
        else:
            missing.append(name)
            print("✗ {} – FIL MANGLER".format(name))

    manifest = {"version": version, "files": files}

    with open("manifest.json", "w") as f:
        json.dump(manifest, f, indent=4)

    print("\nmanifest.json genereret (version: {})".format(version))

    if missing:
        print("ADVARSEL: Følgende filer mangler og er ikke inkluderet:")
        for m in missing:
            print("  -", m)

    print("\nNæste trin:")
    print("  git add manifest.json", " ".join(OTA_FILES))
    print("  git commit -m 'OTA update v{}'".format(version))
    print("  git push")

if __name__ == "__main__":
    main()