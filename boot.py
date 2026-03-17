# boot.py – køres ved opstart før main.py
# Hold denne minimal — OTA må ikke overskrive denne fil

import gc
gc.collect()
import main