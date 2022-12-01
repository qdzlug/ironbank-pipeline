"""
Use Case: Run development branches and immediately rerun them to confirm whether that resolves issues with the vat_findings_api in the (removed) vat compare stage
Status: Incomplete, has issues with connection being broken after rerunning all pipelines and checking status. Needs to be updated to avoid that issue. Likely due to too many api calls or pipeline.cancel causing issues. 
Potential Related Uses (would need to update script or just pull relevant code from script):
    - Simple example for using the gitlab api to run/stop pipelines
    - Run development pipeline for a list of projects to update CVEs in the VAT
    - Automate rerunning a pipeline after another one finishes
    - A solid example of spaghetti code
"""
import gitlab
import os
import sys
import logging
import glob
import csv
import time


def get_vat_compare_failed(gl):
    """
    Parse csv from trigger to get the list of projects that have issues with vat compare
    """
    extension = "csv"
    files = glob.glob("finished_pipleines_*.{}".format(extension))
    vat_diff = {}
    for file in files:
        with Path(file).open(newline="") as csvfile:
            csv_reader = csv.reader(csvfile, delimiter=",", quotechar="|")
            proj_pipeline_list = []
            for row in csv_reader:
                if "vat compare" in row and ("success" in row or "harbor" in row):
                    proj_name = str(row[0]).split("/")[-1]
                    pipeline_job_id = row[1]
                    project = gl.projects.get(row[0])
                    # print(project)
                    pipeline = project.pipelines.create({"ref": "development"})
                    print(f"Pipeline created for {project.web_url}")
                    proj_pipeline_list.append((project, pipeline))
    return proj_pipeline_list


def get_pipeline_status(gl, proj_pipeline_list, rerun=False):
    """
    Check pipeline status for list of pipelines
    Pop pipeline from list if complete, add to rerun list if successful
    """
    rerun_list = []
    failed_vat_compare = []
    while len(proj_pipeline_list) != 0:
        for p in proj_pipeline_list:
            project = gl.projects.get(p[0].id)
            pipeline = project.pipelines.get(p[1].id)
            print(pipeline.web_url)
            print(pipeline.status)
            if pipeline.status != "running" and pipeline.status != "pending":
                proj_pipeline_list.remove(p)
                if pipeline.status == "success":
                    rerun_list.append(project)
            elif rerun:
                vat_compare_job = [
                    job for job in pipeline.jobs.list() if job.name == "vat compare"
                ][0]
                # if pipeline failed the job, cancel it
                if vat_compare_job.status == "failed":
                    failed_vat_compare.append(pipeline.web_url)
                    pipeline.cancel()
        time.sleep(2)
    if rerun:
        return failed_vat_compare
    else:
        return rerun_list


def rerun_pipelines(rerun_list):
    """
    Run piplines included in rerun list

    """
    proj_pipeline_list = []
    for proj in rerun_list:
        pipeline = proj.pipelines.create({"ref": "development"})
        print(f"Pipeline created for {proj.web_url}")
        proj_pipeline_list.append((proj, pipeline))
    return proj_pipeline_list


logging.basicConfig(level=logging.INFO)
gl = gitlab.Gitlab("https://repo1.dso.mil", private_token=os.environ["GL_KEY"])
proj_pipeline_list = get_vat_compare_failed(gl)
rerun_list = get_pipeline_status(gl, proj_pipeline_list)
proj_pipeline_list = rerun_pipelines(rerun_list)
failed_vat_compare = get_pipeline_status(gl, proj_pipeline_list, rerun=True)
print(failed_vat_compare)
with Path("failed_vat_compare.txt").open("w") as f:
    for failed in failed_vat_compare:
        f.write(f"{failed}\n")
