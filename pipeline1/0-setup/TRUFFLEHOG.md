# trufflehog

The [`trufflehog`](https://github.com/feeltheajf/trufflehog3) job runs the `trufflehog.py` script which uses `subprocess` to run `trufflehog3` against a project's code to search for secrets that may have been committed.

The job can accept a config file as long as it is named `trufflehog-config.yaml` and it is in the root of a project and a project or group level CI variable named `TRUFFLEHOG_CONFIG` exists. The value of the variable can be anything, as long as it is not blank/empty in the UI.

An example config file looks like the following

```yaml
exclude:
  - message: Ignore secretstorage
    # These are the false positives we want to ignore
    # will only be skipped in corresponding files
    pattern: secretstorage
    paths:
      - config/linux-64/repodata.json
```
