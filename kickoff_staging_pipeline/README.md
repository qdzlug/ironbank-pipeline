# To use this script

### Right versions of poetry and python

You will want to make sure to have at least python 3.10 installed, you may check via `python3 --version` and using `which python` might give you a hint as to how you have it installed and can update it.

python3 is installed by default on a Mac, it is recommended that you use brew to install/override/manage/update it

Once you have >python3.10 installed, you may install poetry:
`curl -sSL https://install.python-poetry.org | python3 -`

### Install gecko

Download the right gecko package:
https://github.com/mozilla/geckodriver/releases/

`sudo tar -xvzf geckodriver-<version>.tar.gz`
`sudo cp ~/Downloads/geckodriver /usr/local/bin`
`which geckodriver`

### Set up your own config and secrets files

We have example files set up here that you will want to copy to be your own personal setup files. We have set up gitignore on these so that your personal files don't conflict or get sent back up to the remote.

```bash
cp config.yaml.example config.yaml
cp secrets.yaml.example secrets.yaml
```

In your config.yaml, perform the following tasks:

- Change `tester` to your name (or whatever you want your group name in the dest to be)
- Change `pipeline_branch` to the pipeline branch you want to test
- Change `dest_gitlab_url` to your test env
- Uncomment or add any projects you want to test with

In secrets.yaml, add source and dest creds as needed. When testing in staging, you will need to update the 2 `dest` fields. The password will be a token that you create for the user in the destination Gitlab instance.

### To run the script

```sh
poetry install
poetry shell
cd kickoff_staging_pipeline
python3 kickoff.py
```

# Notes:

- If you switch destination envs, you'll need to delete everything out of the local clone repo dir first, or the old remotes will continue to be used. Improvements to this functionality are being tracked in [this ticket](https://repo1.dso.mil/ironbank-tools/ironbank-pipeline/-/issues/775)
- If testing in staging, you will need to be connected to the VPN and have a port-forward running. These are covered in onboarding.
- If using the socks5 proxy set the value **use_socks_proxy** to true in the config.yaml
