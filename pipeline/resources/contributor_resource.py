from pipeline.resources.http_resource import HTTPResource
from pipeline.resources.docker_resource import DockerResource
from pipeline.resources.s3_resource import S3Resource
import json


class ContributorResourceValidation:
    pass

class ContributorResourceAuth:
    auth_type: str = None
    id: str = None
    region: str = NoneClosu


class ContributorResource:
    internal_docker_repo: str = ''
    internal_http_repo: str = ''
    namespace: str = ''
    context = None
    validation: ContributorResourceValidation = None
    auth: ContributorResourceAuth = None
    url: str = ''

    type_map = {
        'docker': DockerResource,
        's3': S3Resource,
        'https': HTTPResource,
        'http': HTTPResource,
    }

    @classmethod
    def create_specific_instance(cls, resource_dict: dict):
        try:
            resource = cls.type_map[resource_dict['url'].split(':')[0]]()
        except KeyError:
            raise KeyError(f'{resource_dict["url"]} is not a valid resource URL!')

        if resource is not None:
            return resource

    def sanity_check(self):
        raise NotImplementedError('ContributorResource is an Interface')

    def stage_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')

    def import_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')
