import json
import os
from os import read
import sys

# Pulled from most recent ubi8 test pipeline run 3/23/201 9:00 AM EDT
with open(f'{os.environ["ARTIFACTS_PATH"]}/vat_api_findings.json', 'r') as api_findings:
    api = json.load(api_findings)
with open(f'{os.environ["ARTIFACTS_PATH"]}/vat_findings.json', 'r') as db_findings:
    db = json.load(db_findings)

i = 0
j = 0
api_list = []
db_list = []

while i < len(api['findings']):
    api_entry = (
        api['findings'][i]['identifier'],
        api['findings'][i]['source'],
        api['findings'][i]['description'],
        api['findings'][i]['package'] if "package" in api['findings'][i] else None,
        api['findings'][i]['packagePath'] if "packagePath" in api['findings'][i]  else None
    )
    if api_entry not in api_list:
        api_list.append(api_entry)
    i += 1

while j < len(db['redhat/ubi/ubi8']):
    db_entry = (
        db['redhat/ubi/ubi8'][j]['finding'],
        db['redhat/ubi/ubi8'][j]['scan_source'],
        db['redhat/ubi/ubi8'][j]['scan_result_description'],
        db['redhat/ubi/ubi8'][j]['package'] if "package" in  db['redhat/ubi/ubi8'][j] else None,
        db['redhat/ubi/ubi8'][j]['package_path'] if "package_path" in  db['redhat/ubi/ubi8'][j] else None,
    )
    if db_entry not in db_list:
        db_list.append(db_entry)
    j += 1

print('API_FINDINGS\n')
[print(a) for a in api_list]
print('\n')
print('DB_FINDINGS\n')
[print(d) for d in db_list]
print('\n')

if api_list == db_list:
    print('Findings are the same!')
else:
    print('Findings are NOT the same!')
    delta = api_list.difference(db_list)
    [print(d) for d in delta]
    sys.exit(4)
