import json
import re
from urllib.parse import urlparse
from pipeline.common import validate_aws_region, validate_url
import requests
import responses

class ContributorResourceValidation:
    pass

class ContributorResourceAuth:
    """
    Rough translation from ContributorResourceAuth.groovy
    Makes the same sort of construct for storing authentication details for
        a specific type of Resource
    """
    auth_map = {
        'types': ['basic', 'aws', 'x509'],
    }
    _auth_type: str = None
    _id: str = None
    _region: str = None

    def __init__(self, auth_dict):
        self.auth_type = auth_dict['type']
        self.id = auth_dict.get('id', 'default-credentials')
        if self.auth_type == 'aws':
            self.region = auth_dict['region']

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
            raise ValueError(f'Invalid AWS Region: {region}')
        self._region = region


class ContributorResource:
    """
    Roughly translated from ContributorResource.groovy
    Creates a base interface class that other more specific Resource types can inherit from
    Uses Properties to give a more methodical approach to validation logic per attribute
        - this makes more sense than a whole "Validate()" function, imho
    """
    _internal_docker_repo: str = ''
    _internal_http_repo: str = ''
    _namespace: str = ''
    _context = None
    _validation: ContributorResourceValidation = None
    _auth: ContributorResourceAuth = None
    _url: str = ''

    @property
    def internal_docker_repo(self) -> str:
        return self._internal_docker_repo

    @internal_docker_repo.setter
    def internal_docker_repo(self, repo: str):
        if not validate_url(repo):
            raise ValueError(f'Invalid URL for Docker Repo: {repo}')

    @property
    def internal_http_repo(self) -> str:
        return self._internal_http_repo

    @internal_http_repo.setter
    def internal_http_repo(self, repo: str):
        if not validate_url(repo):
            raise ValueError(f'Invalid URL for HTTP Repo: {repo}')

    @property
    def namespace(self) -> str:
        return self._namespace

    @namespace.setter
    def namespace(self, namespace: str):
        self._namespace = namespace

    @property
    def context(self) -> str:
        """
        TODO: Unsure if this is necessary outside of the groovy code
        :return:
        """
        return self._context

    @context.setter
    def context(self, context: str):
        self._context = context

    @property
    def validation(self) -> ContributorResourceValidation:
        return self._validation

    @validation.setter
    def validation(self, validation: ContributorResourceValidation):
        self._validation = validation

    @property
    def auth(self) -> ContributorResourceAuth:
        return self._auth

    @auth.setter
    def auth(self, auth: ContributorResourceAuth):
        self._auth = auth

    @property
    def url(self) -> str:
        return self._url

    @url.setter
    def url(self, url: str):
        if not validate_url(url):
            raise ValueError(f'Invalid URL: {url}')

    def stage_resource(self):
        """
        From what I can tell, the old Groovy code was using these two functions
        to both push and pull resources to/from an internal repository
        :return:
        """
        raise NotImplementedError('ContributorResource is an Interface')

    def upload_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')

class DockerResource(ContributorResource):

    def stage_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')

    def upload_resource(self):
        raise NotImplementedError('ContributorResource is an Interface')

class FileResource(ContributorResource):

    _filename: str = ''

    def __init__(self, resource_dict):
        self.url = resource_dict['url']
        auth_data = resource_dict['auth']
        if auth_data:
            self.auth = ContributorResourceAuth(auth_data)

    @property
    def filename(self):
        return self._filename

    @filename.setter
    def filename(self, filename):
        self._filename = filename

    def stage_resource(self):
        pass

    def upload_resource(self):
        pass

class HTTPResource(FileResource):

    def stage_resource(self):
        pass

    def upload_resource(self):
        pass

class S3Resource(FileResource):

    def stage_resource(self):
        pass

    def upload_resource(self):
        pass


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
