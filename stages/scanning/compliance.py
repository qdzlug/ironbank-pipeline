## FOR MON RETURN OSCAP CONTAINER
#!/usr/bin/python3
import os
import sys 
print os.environ["base_image_type"]
TYPE = os.getenv('base_image_type')

oscap_guides = {ubi8-container: {'profile': 'xccdf_org.ssgproject.content_profile_stig', 'securityGuide': 'scap-security-guide-${OSCAP_VERSION}/ssg-rhel8-ds.xml'},
                ubi7-container: {'profile': 'xccdf_org.ssgproject.content_profile_stig', 'securityGuide': 'scap-security-guide-${OSCAP_VERSION}/ssg-rhel7-ds.xml'},
                ubi8-minimal-container: {'profile': 'xccdf_org.ssgproject.content_profile_stig', 'securityGuide': 'scap-security-guide-${OSCAP_VERSION}/ssg-rhel8-ds.xml'},
                ubi7-minimal-container: {'profile': 'xccdf_org.ssgproject.content_profile_stig', 'securityGuide': 'scap-security-guide-${OSCAP_VERSION}/ssg-rhel7-ds.xml'},
                ol8-container: {'profile': 'xccdf_org.ssgproject.content_profile_standard', 'securityGuide': 'scap-security-guide-${OSCAP_VERSION}/ssg-ol8-ds.xml'},
                ol7-container: {'profile': 'xccdf_org.ssgproject.content_profile_stig', 'securityGuide': 'scap-security-guide-${OSCAP_VERSION}/ssg-ol7-ds.xml'},
                centos8-container: {'profile': 'xccdf_org.ssgproject.content_profile_standard', 'securityGuide': 'scap-security-guide-${OSCAP_VERSION}/ssg-centos8-ds.xml'},
                centos7-container: {'profile': 'xccdf_org.ssgproject.content_profile_standard', 'securityGuide': 'scap-security-guide-${OSCAP_VERSION}/ssg-centos7-ds.xml'},
                debian10-container: {'profile': 'xccdf_org.ssgproject.content_profile_anssi_np_nt28_high', 'securityGuide': 'scap-security-guide-${OSCAP_VERSION}/ssg-debian10-ds.xml'},
                debian9-container: {'profile': 'xccdf_org.ssgproject.content_profile_anssi_np_nt28_high', 'securityGuide': 'scap-security-guide-${OSCAP_VERSION}/ssg-debian9-ds.xml'},
                ubuntu1804-container: {'profile': 'xccdf_org.ssgproject.content_profile_anssi_np_nt28_high', 'securityGuide': 'scap-security-guide-${OSCAP_VERSION}/ssg-ubuntu1804-ds.xml'},
                ubuntu1604-container: {'profile': 'xccdf_org.ssgproject.content_profile_anssi_np_nt28_high', 'securityGuide': 'scap-security-guide-${OSCAP_VERSION}/ssg-ubuntu1604-ds.xml'}}
#print (oscap_guides)
oscap_container = oscap_guides[TYPE]   # ??? 
print oscap_container
sys.exit(0)
