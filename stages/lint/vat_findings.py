import json

# Pulled from most recent ubi8 test pipeline run 3/23/201 9:00 AM EDT
api_findings = open('./vat_api_findings.json', )
db_findings = open('./vat_findings.json', )

api = json.load(api_findings)
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
    if db['redhat/ubi/ubi8'][j]['finding'] not in db_list:
        db_list.append(db['redhat/ubi/ubi8'][j]['finding'])
    j += 1

print('API_FINDINGS\n')
print(api_list)
print('\n')
print('DB_FINDINGS\n')
print(db_list)
print('\n')

if api_list == db_list:
    print('Findings are the same!')
else:
    print('Findings are NOT the same!')
    li_dif = [i for i in api_list + db_list if i not in api_list or i not in db_list]
    print(li_dif)

api_findings.close()
db_findings.close()