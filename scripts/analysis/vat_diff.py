"""
Use Case: find all of the recent jobs run from trigger that failed on the "vat compare" stage of the pipeline, combine the results, and export everything to a file
Status: done? It doesn't do very much but accomplished what we needed it for when analyzing the VAT API vs VAT query. Also, another solid example of spaghetti code
"""

import gitlab
import os
import sys
import logging
import zipfile
import shutil
import glob
import csv
import json
from pathlib import Path


def get_project(gl, group, project):
    project_obj = gl.projects.get("%s/%s" % (group, project))
    return project_obj


def get_job_artifacts(gl, project_obj):
    for j in project_obj.jobs.list():
        if j.stage == "dry run":
            logging.INFO("Dry Run, continuing to find the last relevant job")
        else:
            file_name = "__artifacts.zip"
            with Path(file_name).open("wb") as f:
                j.artifacts(streamed=True, action=f.write)
            zip = zipfile.ZipFile(file_name)
            zip.extractall()
            break
    return zip


def extract_reqd_files(dir, glob_string):
    for file in glob.glob(glob_string, recursive=True):
        if "development" in file:
            dest_name = "finished_pipleines_development.csv"
        elif "master" in file:
            dest_name = "finished_pipleines_master.csv"
        else:
            print("unexpected file path or name, exiting")
        shutil.copy2(file, dest_name)

    shutil.rmtree(".artifacts/")
    os.remove("__artifacts.zip")


# def get_pipeline_info(gl):
#    if project_id and project_id != '':
#        get_project(gl)
#        pipeline_list = project_obj.pipelines.list()
#        pipeline_obj = project_obj.pipelines.get(pipeline_list[0].id)


def parse_trigger_files(gl, files):
    extension = "csv"
    files = glob.glob("finished_pipleines_*.{}".format(extension))
    vat_diff = {}
    for file in files:
        with Path(file).open(newline="") as csvfile:
            csv_reader = csv.reader(csvfile, delimiter=",", quotechar="|")
            for row in csv_reader:
                if "vat compare" in row:
                    proj_name = str(row[0]).split("/")[-1]
                    pipeline_job_id = row[1]
                    projects = gl.projects.get(row[0])
                    project = gl.projects.get(projects.id)
                    pipeline = project.pipelines.get(pipeline_job_id)
                    for j in pipeline.jobs.list():
                        if j.name == "vat compare":
                            job_id = j.id
                            job = project.jobs.get(job_id)
                            file_name = "%s_%s_vat_diff.json" % (
                                proj_name,
                                pipeline_job_id,
                            )
                            try:
                                vat_diff[
                                    proj_name + "-" + pipeline_job_id
                                ] = json.loads(
                                    job.artifact("ci-artifacts/compare/vat_diff.json")
                                )
                            except:
                                print("404")
    with Path("vat_complete_diff.json").open("w") as f:
        json.dump(vat_diff, f, indent=4)


logging.basicConfig(level=logging.INFO)
gl = gitlab.Gitlab("https://repo1.dso.mil", private_token=os.environ["GL_KEY"])
group = "ironbank-tools"
project = "trigger"
project_obj = get_project(gl, group, project)
get_job_artifacts(gl, project_obj)
extract_reqd_files(dir=".artifacts", glob_string=".artifacts/**/finished_pipelines.csv")
parse_trigger_files(gl, files="finished_pipelines_*.csv")
