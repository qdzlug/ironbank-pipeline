# To use this script

### In config.yaml

- Change `tester` to your name (or whatever you want your group name in the dest to be)
- Change `pipeline_branch` to the pipeline branch you want to test
- Change `dest_gitlab_url` to your test env
- Uncomment or add any projects you want to test with

### Create secrets.yaml or export env vars

- Add src or dest creds as needed

### To run the script

```sh
poetry install
poetry shell
cd kickoff_staging_pipeline
python3 kickoff.py
```

# Notes:

- If you switch destination envs, you'll need to delete everything out of the local clone repo dir first, or the old remotes will continue to be used. Improvements to this functionality are being tracked in [this ticket](https://repo1.dso.mil/ironbank-tools/ironbank-pipeline/-/issues/775)
