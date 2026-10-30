# GOAD-shaped replay (synthetic data)

This is **not** a run on GOAD. It replays made-up files that have the same shape as a GOAD exercise, so the whole pipeline can be checked without building the lab:

- `operator-log.csv`: eight actions by two operators, using the host names of GOAD's published layout (`kingslanding`, `winterfell`, `castelblack`).
- `blue-timeline.csv`: five blue events in the exact columns the Windows Security-log export writes (`time,host,source,summary,level`), including event IDs 4625, 4720 and 4726.

```
python replay.py
```

It imports the log twice (the second import adds nothing), runs the purple review and writes an ATT&CK Navigator layer. Expected: 3 of 8 actions seen,
and one blue event no action explains (a failed logon by an account the operators never touched).

When a real range is available, replace the two CSV files with the real operator log and the real export. Nothing else changes.
