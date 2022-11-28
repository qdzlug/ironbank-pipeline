## This MR (Sandbox example) tests a malware scanner as part of Gitlab CI using YARA rules.

## Summary

The IronBank Pipeline threat detection systems lacks the ability to scan images with file size above 4GB for rootkits or hidden malware.
This MR tests a solution that would use Deepfence's YaraHunter to scan IronBank's container images to find indicators of malware.

## Requirements
[] Scan built container for known malware signatures
[] Send scan output to VAT

## Background
According to the official documentation (which can be found at https: / /yara. readthedocs. io/en/v3. 8 .1/), YARA is a tool aimed at helping malware researchers (and forensic examiners-both computer and mobile, of course) to identify and classify malware samples.

With the help of YARA, an examiner can write rules based on textual or binary patterns. Here is an example of such a rule:

rule test_rule

{

meta:

description ="Test YARA rule"

author = " Stephen Ako"

strings:

$string = "teststring"

condition:

$string

}
The Yara tool will scan through a docker file or container images with a provided rule and identify any files that match the patterns in the rule.




## Implementing the steps to build and test (scan) the IronBank image using Yara rule

# Gitlab CI Integration

stages:
  - build

# Build and push the Docker image to the GitLab image
# registry using Docker-in-Docker.
dind-build:
  stage: build

  image:
    name: docker:stable

  # This will run a Docker daemon in a container
  # (Docker-In-Docker), which will be available at
  # thedockerhost:2375. If you make e.g. port 5000 public in
  # Docker (`docker run -p 5000:5000 yourimage`) it will be
  # exposed at thedockerhost:5000.
  services:
   - name: docker:dind
     alias: dockerdaemon

  variables:
    # Tell docker CLI how to talk to Docker daemon.
    DOCKER_HOST: tcp://dockerdaemon:2375/
    # Use the overlays driver for improved performance.
    DOCKER_DRIVER: overlay2
    # Disable TLS since we're running inside local network.
    DOCKER_TLS_CERTDIR: ""

  script:
# Login to our private registry
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
# Pull our private image
    - docker pull spat846/yara:001
    - docker run --rm --name=deepfence-yuara -v /var/run/docker.sock:/var/run/docker.sock deepfenceio/deepfence-yaradare:latest --image-name spat846/yara:001

# In the preceding case,   

## Review of output
# Scripts executed to scan container image

 Running with gitlab-runner 15.6.0~beta.186.ga889181a (a889181a)
  on blue-4.shared.runners-manager.gitlab.com/default J2nyww-s
Preparing the "docker+machine" executor
00:39
Using Docker executor with image docker:stable ...
Starting service docker:dind ...
Pulling docker image docker:dind ...
Using docker image sha256:d67b5e9608a2fa20e31859452fe8615da2f087e582a55508fb6dc1786255c8ab for docker:dind with digest docker@sha256:80e81aecd51d80e63ae4cbbd5eb1968e84edd151b90ef2c2f17e1004c7a3832b ...
Waiting for services to be up and running (timeout 30 seconds)...
Pulling docker image docker:stable ...
Using docker image sha256:b0757c55a1fdbb59c378fd34dde3e12bd25f68094dd69546cf5ca00ddbaa7a33 for docker:stable with digest docker@sha256:fd4d028713fd05a1fb896412805daed82c4a0cc84331d8dad00cb596d7ce3e3a ...
Preparing environment
00:02
Running on runner-j2nyww-s-project-41254016-concurrent-0 via runner-j2nyww-s-shared-1669132571-e483ac5f...
Getting source from Git repository
00:02
$ eval "$CI_PRE_CLONE_SCRIPT"
Fetching changes with git depth set to 20...
Initialized empty Git repository in /builds/spat84/yara-sandbox-test/.git/
Created fresh repository.
Checking out b2b259f0 as main...
Skipping Git submodules setup
Executing "step_script" stage of the job script
02:25
Using docker image sha256:b0757c55a1fdbb59c378fd34dde3e12bd25f68094dd69546cf5ca00ddbaa7a33 for docker:stable with digest docker@sha256:fd4d028713fd05a1fb896412805daed82c4a0cc84331d8dad00cb596d7ce3e3a ...
$ docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
WARNING! Using --password via the CLI is insecure. Use --password-stdin.
WARNING! Your password will be stored unencrypted in /root/.docker/config.json.
Configure a credential helper to remove this warning. See
https://docs.docker.com/engine/reference/commandline/login/#credentials-store
Login Succeeded
$ docker pull spat846/yara:001
001: Pulling from spat846/yara
9160faa7ad21: Pulling fs layer
2d58bca6d106: Pulling fs layer
2d58bca6d106: Verifying Checksum
2d58bca6d106: Download complete
9160faa7ad21: Verifying Checksum
9160faa7ad21: Download complete
9160faa7ad21: Pull complete
2d58bca6d106: Pull complete
Digest: sha256:6b768985cc373e301904bae251953c49c5bcca6e4e90a1585dddc31ef64684bb
Status: Downloaded newer image for spat846/yara:001
docker.io/spat846/yara:001
$ docker run --rm --name=deepfence-yuara -v /var/run/docker.sock:/var/run/docker.sock deepfenceio/deepfence-yaradare:latest --image-name spat846/yara:001
Unable to find image 'deepfenceio/deepfence-yaradare:latest' locally
latest: Pulling from deepfenceio/deepfence-yaradare


## Output displayed

# When the scan completes successfully, we see something similar to the following output. This tells us that the image was scanned  with Yara rules. 

{
  "Timestamp": "2022-11-22 15:59:56.648485081 +00:00",
  "Image Name": "spat846/yara:001",
  "Image ID": "b2c91449692dd233e97666bac28bd4fe4545b191c5d31362336d92641012108a",
  "Malware match detected are": [
    {
      "Matched Rule Name": "RooterStrings",
      "Strings to match are":
            "seed",
            "prot",
            "nown",
      "Category": [Rooter Family],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/lib/systemd/libsystemd-shared-239.so",
      "description": Rooter Identifying Strings 
      "author": Seth Hardy 
      "last_modified": 2014-07-10 
      "Summary": The file /tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/lib/systemd/libsystemd-shared-239.so has a Family match.The file has a rule match that  Rooter Identifying Strings .The matched rule file's  author  is Seth Hardy .The matched rule file's  last_modified  is 2014-07-10 .,
    }
,
    {
      "Matched Rule Name": "Rooter",
      "Strings to match are":
      "Category": [Family],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/lib/systemd/libsystemd-shared-239.so",
      "description": Rooter 
      "author": Seth Hardy 
      "last_modified": 2014-07-10 
      "Summary": The file /tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/lib/systemd/libsystemd-shared-239.so has a Family match.The file has a rule match that  Rooter .The matched rule file's  author  is Seth Hardy .The matched rule file's  last_modified  is 2014-07-10 .,
    }
,
    {
      "Matched Rule Name": "with_sqlite",
      "Strings to match are":
            "SQLite format 3",
      "Category": [sqlite],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/lib64/libsqlite3.so.0.8.6",
      "author": Julian J. Gonzalez <info@seguridadparatodos.es> 
      "reference": http://www.st2labs.com 
      "description": Rule to detect the presence of SQLite data in raw image 
      "Summary": The file /tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/lib64/libsqlite3.so.0.8.6 has a sqlite match.The matched rule file's  author  is Julian J. Gonzalez <info@seguridadparatodos.es> .The matched rule file's  reference  is http://www.st2labs.com .The file has a rule match that  Rule to detect the presence of SQLite data in raw image .,
    }
,
    {
      "Matched Rule Name": "PM_Email_Sent_By_PHP_Script",
      "Strings to match are":
            "/usr/bin/php",
      "Category": [],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/share/misc/magic",
    }
,
    {
      "Matched Rule Name": "Cerberus",
      "Strings to match are":
            "cerberus",
      "Category": [RAT memory],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/share/misc/magic",
      "description": Cerberus 
      "author": Jean-Philippe Teissier / @Jipe_ 
      "date": 2013-01-12 
      "filetype": memory 
      "version": 1.0 
      "Summary": The file /tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/share/misc/magic has a memory match.The file has a rule match that  Cerberus .The matched rule file's  author  is Jean-Philippe Teissier / @Jipe_ .The matched rule file's  date  is 2013-01-12 .The matched rule file's  filetype  is memory .The matched rule file's  version  is 1.0 .,
    }
,
    {
      "Matched Rule Name": "PM_Email_Sent_By_PHP_Script",
      "Strings to match are":
            "/usr/bin/php",
      "Category": [],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/share/misc/magic.mgc",
    }
,
    {
      "Matched Rule Name": "with_sqlite",
      "Strings to match are":
            "SQLite format 3",
      "Category": [sqlite],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/share/misc/magic.mgc",
      "author": Julian J. Gonzalez <info@seguridadparatodos.es> 
      "reference": http://www.st2labs.com 
      "description": Rule to detect the presence of SQLite data in raw image 
      "Summary": The file /tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/share/misc/magic.mgc has a sqlite match.The matched rule file's  author  is Julian J. Gonzalez <info@seguridadparatodos.es> .The matched rule file's  reference  is http://www.st2labs.com .The file has a rule match that  Rule to detect the presence of SQLite data in raw image .,
    }
,
    {
      "Matched Rule Name": "RooterStrings",
      "Strings to match are":
            "seed",
            "prot",
            "nown",
      "Category": [Rooter Family],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/lib/systemd/libsystemd-shared-239.so",
      "description": Rooter Identifying Strings 
      "author": Seth Hardy 
      "last_modified": 2014-07-10 
      "Summary": The file /tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/lib/systemd/libsystemd-shared-239.so has a Family match.The file has a rule match that  Rooter Identifying Strings .The matched rule file's  author  is Seth Hardy .The matched rule file's  last_modified  is 2014-07-10 .,
    }
,
    {
      "Matched Rule Name": "Rooter",
      "Strings to match are":
      "Category": [Family],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/lib/systemd/libsystemd-shared-239.so",
      "description": Rooter 
      "author": Seth Hardy 
      "last_modified": 2014-07-10 
      "Summary": The file /tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/lib/systemd/libsystemd-shared-239.so has a Family match.The file has a rule match that  Rooter .The matched rule file's  author  is Seth Hardy .The matched rule file's  last_modified  is 2014-07-10 .,
    }
,
    {
      "Matched Rule Name": "with_sqlite",
      "Strings to match are":
            "SQLite format 3",
      "Category": [sqlite],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/lib64/libsqlite3.so.0.8.6",
      "author": Julian J. Gonzalez <info@seguridadparatodos.es> 
      "reference": http://www.st2labs.com 
      "description": Rule to detect the presence of SQLite data in raw image 
      "Summary": The file /tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/lib64/libsqlite3.so.0.8.6 has a sqlite match.The matched rule file's  author  is Julian J. Gonzalez <info@seguridadparatodos.es> .The matched rule file's  reference  is http://www.st2labs.com .The file has a rule match that  Rule to detect the presence of SQLite data in raw image .,
    }
,
    {
      "Matched Rule Name": "PM_Email_Sent_By_PHP_Script",
      "Strings to match are":
            "/usr/bin/php",
      "Category": [],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/share/misc/magic",
    }
,
    {
      "Matched Rule Name": "Cerberus",
      "Strings to match are":
            "cerberus",
      "Category": [RAT memory],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/share/misc/magic",
      "description": Cerberus 
      "author": Jean-Philippe Teissier / @Jipe_ 
      "date": 2013-01-12 
      "filetype": memory 
      "version": 1.0 
      "Summary": The file /tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/share/misc/magic has a memory match.The file has a rule match that  Cerberus .The matched rule file's  author  is Jean-Philippe Teissier / @Jipe_ .The matched rule file's  date  is 2013-01-12 .The matched rule file's  filetype  is memory .The matched rule file's  version  is 1.0 .,
    }
,
    {
      "Matched Rule Name": "PM_Email_Sent_By_PHP_Script",
      "Strings to match are":
            "/usr/bin/php",
      "Category": [],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/share/misc/magic.mgc",
    }
,
    {
      "Matched Rule Name": "with_sqlite",
      "Strings to match are":
            "SQLite format 3",
      "Category": [sqlite],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/share/misc/magic.mgc",
      "author": Julian J. Gonzalez <info@seguridadparatodos.es> 
      "reference": http://www.st2labs.com 
      "description": Rule to detect the presence of SQLite data in raw image 
      "Summary": The file /tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/f581d462d94b6767f6c50b3550fe879cd690a08c0c5b432d27d57aace81d4102/usr/share/misc/magic.mgc has a sqlite match.The matched rule file's  author  is Julian J. Gonzalez <info@seguridadparatodos.es> .The matched rule file's  reference  is http://www.st2labs.com .The file has a rule match that  Rule to detect the presence of SQLite data in raw image .,
    }
,
    {
      "Matched Rule Name": "with_sqlite",
      "Strings to match are":
            "SQLite format 3",
      "Category": [sqlite],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/9b3aec254afdb290cc8c170aa9fa82f739e438b1cf4368483671798f4c2a099b/etc/pki/nssdb/cert9.db",
      "author": Julian J. Gonzalez <info@seguridadparatodos.es> 
      "reference": http://www.st2labs.com 
      "description": Rule to detect the presence of SQLite data in raw image 
      "Summary": The file /tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/9b3aec254afdb290cc8c170aa9fa82f739e438b1cf4368483671798f4c2a099b/etc/pki/nssdb/cert9.db has a sqlite match.The matched rule file's  author  is Julian J. Gonzalez <info@seguridadparatodos.es> .The matched rule file's  reference  is http://www.st2labs.com .The file has a rule match that  Rule to detect the presence of SQLite data in raw image .,
    }
,
    {
      "Matched Rule Name": "with_sqlite",
      "Strings to match are":
            "SQLite format 3",
      "Category": [sqlite],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/9b3aec254afdb290cc8c170aa9fa82f739e438b1cf4368483671798f4c2a099b/etc/pki/nssdb/key4.db",
      "author": Julian J. Gonzalez <info@seguridadparatodos.es> 
      "reference": http://www.st2labs.com 
      "description": Rule to detect the presence of SQLite data in raw image 
      "Summary": The file /tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/9b3aec254afdb290cc8c170aa9fa82f739e438b1cf4368483671798f4c2a099b/etc/pki/nssdb/key4.db has a sqlite match.The matched rule file's  author  is Julian J. Gonzalez <info@seguridadparatodos.es> .The matched rule file's  reference  is http://www.st2labs.com .The file has a rule match that  Rule to detect the presence of SQLite data in raw image .,
    }
,
    {
      "Matched Rule Name": "spyeye",
      "Strings to match are":
            "data_end",
      "Category": [banker],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/9b3aec254afdb290cc8c170aa9fa82f739e438b1cf4368483671798f4c2a099b/usr/lib64/libnftnl.so.11.2.0",
      "author": Jean-Philippe Teissier / @Jipe_ 
      "description": SpyEye X.Y memory 
      "date": 2012-05-23 
      "version": 1.0 
      "filetype": memory 
      "Summary": The file /tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/9b3aec254afdb290cc8c170aa9fa82f739e438b1cf4368483671798f4c2a099b/usr/lib64/libnftnl.so.11.2.0 has a banker match.The matched rule file's  author  is Jean-Philippe Teissier / @Jipe_ .The file has a rule match that  SpyEye X.Y memory .The matched rule file's  date  is 2012-05-23 .The matched rule file's  version  is 1.0 .The matched rule file's  filetype  is memory .,
    }
,
    {
      "Matched Rule Name": "with_sqlite",
      "Strings to match are":
            "SQLite format 3",
      "Category": [sqlite],
      "File Name": "/tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/9b3aec254afdb290cc8c170aa9fa82f739e438b1cf4368483671798f4c2a099b/var/lib/dnf/history.sqlite",
      "author": Julian J. Gonzalez <info@seguridadparatodos.es> 
      "reference": http://www.st2labs.com 
      "description": Rule to detect the presence of SQLite data in raw image 
      "Summary": The file /tmp/Deepfence/YaRadare/df_spat846yara001/ExtractedFiles/9b3aec254afdb290cc8c170aa9fa82f739e438b1cf4368483671798f4c2a099b/var/lib/dnf/history.sqlite has a sqlite match.The matched rule file's  author  is Julian J. Gonzalez <info@seguridadparatodos.es> .The matched rule file's  reference  is http://www.st2labs.com .The file has a rule match that  Rule to detect the presence of SQLite data in raw image .,
    }
  ]
}
Cleaning up project directory and file based variables
00:00
Job succeeded


## Results 
 We ran our malware scanning tool as a Docker container and got our results in json format. We pulled a Red Hat Universal Base Image 8 (UBI8) from Registry 1 and ran our scan against it. Here, we are looking for related string patterns within the image that may indicate the presence of malware. The scan results indicate the pipeline job was succesfully completed and our test passed. The scan report is shown above.


## Requirements to add Yara Rule (Yara Hunter) job to IronBank pipeline

 # Meet with VAT team to discuss adding of Yara Rule job
 # Add reference to Yara scanning job in README
 # Add the use of artifacts from scripts
 # Add all references to Yara Rule cve as a dependency
 # Update the vat stage to use pipeline artifacts from the Yara rule malware scanning stages as well as populate the (VAT)

## Challenges 
 Applying Automatic ruleset updates to ward off zero day or new malware not accounted for (Feed service)

## Conclusion

  ClamAV is unable to scan container images larger than 4GB. Limiting malware scans to files sizes less than 4 Gigs is not always the best thing to do –  we could download and execute some malicious code in a larger container image (7GB+) that could compromise our entire software supply chain. By leveraging Yara rules for malware scans we can ensure a more robust defense ofthe P1 software supply chain.
 In this Markdown document, we experimented with Yara rules deployed within the Gitlab CI pipeline for malware scanning.The Gitlab CI pipeline test passed and produced scan results. We hope this high level overview has provided some thoughtful insights on how Yara rules can be used in conjuction with Anchore and Twistlock to prevent a compromised image from reaching our production environment.  
