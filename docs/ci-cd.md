# Closeout gate in CI

If your engagement folder lives in a private git repository, you can make the repository refuse to merge or release while anything is still open.

## GitHub Actions

```yaml
name: closeout
on: [pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: 1337exe/redsweep@v0.1.0
        with:
          home: .redsweep          # where the engagement folder is
          mode: check             # check (default) | close
```

The job fails (exit code 2) when there are blockers and prints each one. With `mode: close` it also writes the report, seal and pack and uploads them as a build artifact.
Journals that fail their hash check fail the job with exit code 3.

## Any other CI

```bash
pip install git+https://github.com/1337exe/redsweep
redsweep close --check --home .redsweep     # exit 0 clean, 2 blockers
redsweep verify --home .redsweep            # exit 3 if a journal was edited
```

## A warning

Pipelines run other people's code. Keep engagement folders in a **private** repository and give the pipeline read access only.
Capture and rollback commands are not run by `close --check`; it only reads the journal.
