# Replay of real Windows events (public sample set)

The blue side of this drill is **real**: three small `.evtx` files from the public
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) repository (GPL-3.0). The script fetches them when it runs. They are not copied into Lowtide.

The operator side is **synthetic**: six lines written to line up with the real timestamps, because no public operator logs exist for these events. Nothing here ran on GOAD.

```
pip install evtx          # a separate package; Lowtide itself has no dependencies
python replay.py
```

It converts nine real Security events (4720 account created, 4624 and 4625 logons, 4798 and 4799 local group enumeration) into the blue timeline format,
imports the synthetic operator log, and runs the purple review. The events are raw telemetry, so they score as L0 ("telemetry exists, nobody looked").

Expected: 5 of 6 actions seen, 1 not seen (a directory read with no event in the samples), no unexplained blue events.
Needs `git` and network access to github.com.
