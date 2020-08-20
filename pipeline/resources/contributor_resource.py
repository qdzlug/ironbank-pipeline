import json
import re
from urllib.parse import urlparse
from pipeline.common import validate_aws_region

class ContributorResourceValidation:
    pass

class ContributorResourceAuth:
    auth_map = {
        'types': ['basic', 'aws', 'x509'],
    }
    _auth_type: str = None
    _id: str = None
    _region: str = None

    def __init__(self, auth_dict):
        self.auth_type = auth_dict['type']
        self.id = auth_dict.get('id', 'default-credentials')

    @property
    def auth_type(self):
        return self._auth_type

    @auth_type.setter
    def auth_type(self, auth_type):
        if auth_type not in self.auth_map['types']:
            raise ValueError(f'Invalid Auth Type: {auth_type} - Must Be {self.auth_map["types"]}')
        self._auth_type = auth_type

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, id):
        r = re.compile(r"[<>/{}[\]~ \\,()*&^%$#@!\"'`~]")
        if bool(r.search(id)):
            raise ValueError(f'Invalid Characters Detected in ID: {id}')
        self._id = id

    @property
    def region(self):
        return self._region

    @region.setter
    def region(self, region):
        if not validate_aws_region(region):


class ContributorResource:
    internal_docker_repo: str = ''
    internal_http_repo: str = ''
    namespace: str = ''
    context = None
    validation: ContributorResourceValidation = None
    auth: ContributorResourceAuth = None
    url: str = ''

    def sanity_check(self):
        if not bool(urlparse(self.url).scheme):
            raise ValueError(f'Invalid URL in Resource: {self.url}')
        return True

    def stage_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')

    def import_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')

class DockerResource(ContributorResource):
    def sanity_check(self):
        raise NotImplementedError('ContributorResource is an Interface')

    def stage_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')

    def import_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')

class FileResource(ContributorResource):

    def __init__(self, resource_dict):
        self.url = resource_dict['url']
        auth = resource_dict['auth']
        if auth:
            self.auth = ContributorResourceAuth(auth)

    def sanity_check(self):
        super().sanity_check()

    def stage_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')

    def import_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')

class HTTPResource(FileResource):
    def sanity_check(self):
        raise NotImplementedError('ContributorResource is an Interface')

    def stage_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')

    def import_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')

class S3Resource(FileResource):
    def sanity_check(self):
        raise NotImplementedError('ContributorResource is an Interface')

    def stage_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')

    def import_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')


def generate_resource(resource_dict: dict):
    resource_map = {
        'docker': DockerResource,
        's3': S3Resource,
        'https': HTTPResource,
        'http': HTTPResource,
    }

    try:
        resource = resource_map[resource_dict['url'].split(':')[0]](resource_dict)
    except KeyError:
        raise KeyError(f'{resource_dict["url"]} is not a valid resource URL!')

    if resource is not None:
        return resource
