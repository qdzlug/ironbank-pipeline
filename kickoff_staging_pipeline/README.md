# To use this script

### Right versions of poetry and python
You will want to make sure to have at least python 3.10 installed, you may check via `python3 --version` and using `which python` might give you a hint as to how you have it installed and can update it.

python3 is installed by default on a Mac, it is recommended that you use brew to install/override/manage/update it

Once you have >python3.10 installed, you may install poetry:
`curl -sSL https://install.python-poetry.org | python3 -`

### Install gecko

Download the right gecko package:
https://github.com/mozilla/geckodriver/releases/

`sudo cp ~/Downloads geckodriver /usr/local/bin`
`which gecko`

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
