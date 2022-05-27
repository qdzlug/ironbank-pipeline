import access_log_parser as alp
import sbom_parser as sbp
from utils.sbom import Package

access_packages = alp.parse_access_log("/Users/cmiller/Desktop/ubi8/access_log", True)

sbom_packages = sbp.parse_sbom("/Users/cmiller/Desktop/ubi8/sbom-json.json", True)


print("\n\n In SBOM, not in Access Log \n" + "="*46)
for package in set(sbom_packages) - set(access_packages):
    print(f"\t{package.package}  {package.version}  {package.type}")

print("\n\n In Access Log, not in SBOM \n" + "="*46)
for package in set(access_packages) - set(sbom_packages):
    print(f"\t{package.package}  {package.version}  {package.type}")

print("\n\n In Both \n" + "="*46)
for package in set(access_packages) & set(sbom_packages):
    print(f"\t{package.package}  {package.version}  {package.type}")
