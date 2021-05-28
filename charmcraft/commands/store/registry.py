# Copyright 2021 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# For further info, check https://github.com/canonical/charmcraft

"""Module to work with OCI registries."""

import base64
import gzip
import hashlib
import io
import json
import logging
import os
import tarfile
import tempfile
from urllib.request import parse_http_list, parse_keqv_list

import requests
import requests_unixsocket

from charmcraft.cmdbase import CommandError

logger = logging.getLogger(__name__)

# some mimetypes
CONFIG_MIMETYPE = 'application/vnd.docker.container.image.v1+json'
MANIFEST_LISTS = 'application/vnd.docker.distribution.manifest.list.v2+json'
MANIFEST_V2_MIMETYPE = 'application/vnd.docker.distribution.manifest.v2+json'
LAYER_MIMETYPE = 'application/vnd.docker.image.rootfs.diff.tar.gzip'
JSON_RELATED_MIMETYPES = {
    'application/json',
    'application/vnd.docker.distribution.manifest.v1+prettyjws',  # signed manifest
    MANIFEST_LISTS,
    MANIFEST_V2_MIMETYPE,
}
OCTET_STREAM_MIMETYPE = 'application/octet-stream'

# downloads and uploads happen in chunks
CHUNK_SIZE = 2 ** 20

# the address of the dockerd socket
LOCAL_DOCKER_BASE_URL = 'http+unix://%2Fvar%2Frun%2Fdocker.sock'


def assert_response_ok(response, expected_status=200):
    """Assert the response is ok."""
    if response.status_code != expected_status:
        ct = response.headers.get('Content-Type', '')
        if ct.split(';')[0] in JSON_RELATED_MIMETYPES:
            errors = response.json().get('errors')
        else:
            errors = None
        raise CommandError(
            "Wrong status code from server (expected={}, got={}) errors={} headers={}".format(
                expected_status, response.status_code, errors, response.headers))

    if response.headers.get('Content-Type') not in JSON_RELATED_MIMETYPES:
        return

    result = response.json()
    if 'errors' in result:
        raise CommandError("Response with errors from server: {}".format(result['errors']))
    return result


class OCIRegistry:
    """Interface to a generic OCI Registry."""

    def __init__(self, server, image_name, *, username='', password=''):
        self.server = server
        self.image_name = image_name
        self.auth_token = None

        if username:
            _u_p = "{}:{}".format(username, password)
            self.auth_encoded_credentials = base64.b64encode(_u_p.encode('ascii')).decode('ascii')
        else:
            self.auth_encoded_credentials = None

    def _authenticate(self, auth_info):
        """Get the auth token."""
        headers = {}
        if self.auth_encoded_credentials is not None:
            headers['Authorization'] = 'Basic {}'.format(self.auth_encoded_credentials)

        logger.debug("Authenticating! %s", auth_info)
        url = "{realm}?service={service}&scope={scope}".format_map(auth_info)
        response = requests.get(url, headers=headers)

        result = assert_response_ok(response)
        auth_token = result['token']
        return auth_token

    def _get_url(self, subpath):
        """Build the URL completing the subpath."""
        return "{}/v2/{}/{}".format(self.server, self.image_name, subpath)

    def _get_auth_info(self, response):
        """Parse a 401 response and get the needed auth parameters."""
        www_auth = response.headers['Www-Authenticate']
        if not www_auth.startswith("Bearer "):
            raise ValueError("Bearer not found")
        info = parse_keqv_list(parse_http_list(www_auth[7:]))
        return info

    def _hit(self, method, url, headers=None, log=True, **kwargs):
        """Hit the specific URL, taking care of the authentication."""
        if headers is None:
            headers = {}
        if self.auth_token is not None:
            headers['Authorization'] = 'Bearer {}'.format(self.auth_token)

        if log:
            logger.debug("Hitting the registry: %s %s", method, url)
        response = requests.request(method, url, headers=headers, **kwargs)
        if response.status_code == 401:
            # token expired or missing, let's get another one and retry
            try:
                auth_info = self._get_auth_info(response)
            except (ValueError, KeyError) as exc:
                raise CommandError(
                    "Bad 401 response: {}; headers: {!r}".format(exc, response.headers))
            self.auth_token = self._authenticate(auth_info)
            headers['Authorization'] = 'Bearer {}'.format(self.auth_token)
            response = requests.request(method, url, headers=headers, **kwargs)

        return response

    def _is_item_already_uploaded(self, url):
        """Verify if a generic item is uploaded."""
        response = self._hit('HEAD', url)

        if response.status_code == 200:
            # item is there, done!
            uploaded = True
        elif response.status_code == 404:
            # confirmed item is NOT there
            uploaded = False
        else:
            # something else is going on, log what we have and return False so at least
            # we can continue with the upload
            logger.debug(
                "Bad response when checking for uploaded %r: %r (headers=%s)",
                url, response.status_code, response.headers)
            uploaded = False
        return uploaded

    def is_manifest_already_uploaded(self, reference):
        """Verify if the manifest is already uploaded, using a generic reference.

        If yes, return its digest.
        """
        logger.debug("Checking if manifest is already uploaded")
        url = self._get_url("manifests/{}".format(reference))
        return self._is_item_already_uploaded(url)

    def is_blob_already_uploaded(self, reference):
        """Verify if the blob is already uploaded, using a generic reference.

        If yes, return its digest.
        """
        logger.debug("Checking if the blob is already uploaded")
        url = self._get_url("blobs/{}".format(reference))
        return self._is_item_already_uploaded(url)

    def upload_manifest(self, manifest_data, reference, *, multiple_manifest=False):
        """Upload a manifest."""
        mimetype = MANIFEST_LISTS if multiple_manifest else MANIFEST_V2_MIMETYPE
        url = self._get_url("manifests/{}".format(reference))
        headers = {
            'Content-Type': mimetype,
        }
        logger.debug("Uploading manifest with reference %s", reference)
        response = self._hit('PUT', url, headers=headers, data=manifest_data.encode('utf8'))
        assert_response_ok(response, expected_status=201)
        logger.debug("Manifest uploaded OK")

    def upload_blob(self, filepath, size, digest):
        """Upload the blob from a file."""
        # get the first URL to start pushing the blob
        logger.debug("Getting URL to push the blob")
        url = self._get_url("blobs/uploads/")
        response = self._hit('POST', url)
        assert_response_ok(response, expected_status=202)
        upload_url = response.headers['Location']
        range_from, range_to_inclusive = [int(x) for x in response.headers['Range'].split('-')]
        logger.debug("Got upload URL ok with range %s-%s", range_from, range_to_inclusive)
        if range_from != 0:
            raise CommandError("Server error: bad range received")
        if range_to_inclusive == 0:
            range_to_inclusive = -1

        # start the chunked upload
        from_position = range_to_inclusive + 1
        with open(filepath, 'rb') as fh:
            fh.seek(from_position)
            while True:
                chunk = fh.read(CHUNK_SIZE)
                if not chunk:
                    break

                end_position = from_position + len(chunk)
                headers = {
                    'Content-Length': str(len(chunk)),
                    'Content-Range': '{}-{}'.format(from_position, end_position),
                    'Content-Type': OCTET_STREAM_MIMETYPE,
                }
                progress = 100 * end_position / size
                print("Uploading.. {:.2f}%\r".format(progress), end='', flush=True)
                response = self._hit('PATCH', upload_url, headers=headers, data=chunk, log=False)
                assert_response_ok(response, expected_status=202)

                upload_url = response.headers['Location']
                from_position += len(chunk)

        headers = {
            'Content-Length': '0',
            'Connection': 'close',
        }
        logger.debug("Closing the upload")
        closing_url = "{}&digest={}".format(upload_url, digest)

        response = self._hit('PUT', closing_url, headers=headers, data='')
        assert_response_ok(response, expected_status=201)
        logger.debug("Upload finished OK")
        if response.headers['Docker-Content-Digest'] != digest:
            raise CommandError("Server error: the upload is corrupted")


class HashingTemporaryFile(io.FileIO):
    """A temporary file that keeps the hash and length of what is written."""

    def __init__(self):
        tmp_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
        self.file_handler = tmp_file.file
        super().__init__(tmp_file.name, mode='wb')
        self.total_length = 0
        self.hasher = hashlib.sha256()

    @property
    def hexdigest(self):
        """Calculate the digest."""
        return self.hasher.hexdigest()

    def write(self, data):
        """Intercept real write to feed hasher and length count."""
        self.total_length += len(data)
        self.hasher.update(data)
        super().write(data)


class ImageHandler:
    """Provide specific functionalities around images."""

    def __init__(self, registry):
        self.registry = registry

    def check_in_registry(self, digest):
        """Verify if the image is present in the registry."""
        return self.registry.is_manifest_already_uploaded(digest)

    def _extract_file(self, image_tar, name, compress=False):
        """Extract a file from the tar and return its info. Optionally, gzip the content."""
        logger.debug("Extracting file %r from local tar (compress=%s)", name, compress)
        src_fh = image_tar.extractfile(name)
        mtime = image_tar.getmember(name).mtime

        hashing_temp_file = HashingTemporaryFile()
        if compress:
            # open the gzip file using the temporary file handler; use the original name and time
            # as 'filename' and 'mtime' correspondingly as those go to the gzip headers,
            # to ensure same final hash across different runs
            dst_filehandler = gzip.GzipFile(
                fileobj=hashing_temp_file, mode='wb', filename=os.path.basename(name), mtime=mtime)
        else:
            dst_filehandler = hashing_temp_file
        while True:
            chunk = src_fh.read(CHUNK_SIZE)
            if not chunk:
                break
            dst_filehandler.write(chunk)
        dst_filehandler.close()
        # gzip does not automatically close the underlying file handler, so let's do it manually
        hashing_temp_file.close()

        digest = 'sha256:{}'.format(hashing_temp_file.hexdigest)
        return hashing_temp_file.name, hashing_temp_file.total_length, digest

    def _upload_blob(self, filepath, size, digest):
        """Upload the blob (if necessary)."""
        # if it's already uploaded, nothing to do
        if self.registry.is_blob_already_uploaded(digest):
            logger.debug("Blob was already uploaded")
        else:
            self.registry.upload_blob(filepath, size, digest)

        # finally remove the temp filepath
        os.unlink(filepath)

    def upload_from_local(self, digest):
        """Upload the image from the local registry."""
        session = requests_unixsocket.Session()

        # validate the image is present locally
        logger.debug("Checking image is present locally")
        response = session.get(LOCAL_DOCKER_BASE_URL + '/images/{}/json'.format(digest))
        if response.status_code == 200:
            # image is there, we're fine
            pass
        elif response.status_code == 404:
            # image not found (known error)
            return
        else:
            logger.debug("Bad response when validation local image: %s", response.status_code)
            return
        local_image_size = response.json()['Size']

        logger.debug("Getting the image from the local repo; size=%s", local_image_size)
        response = session.get(
            LOCAL_DOCKER_BASE_URL + '/images/{}/get'.format(digest), stream=True)

        tmp_exported = tempfile.NamedTemporaryFile(mode='wb')
        extracted_total = 0
        for chunk in response.iter_content(2 ** 20):
            extracted_total += len(chunk)
            progress = 100 * extracted_total / local_image_size
            print("Extracting... {:.2f}%\r".format(progress), end='', flush=True)
            tmp_exported.file.write(chunk)

        # open the image tar and inspect it to get the config and layers for the manifest
        tmp_exported.file.flush()
        image_tar = tarfile.open(tmp_exported.name)
        tmp_exported.close()  # closing implies deletion, but the tar lib already grabbed it ok
        local_manifest = json.load(image_tar.extractfile('manifest.json'))
        (local_manifest,) = local_manifest
        config_name = local_manifest.get('Config')
        layer_names = local_manifest['Layers']
        manifest = {
            'mediaType': MANIFEST_V2_MIMETYPE,
            'schemaVersion': 2,
        }

        if config_name is not None:
            fpath, size, digest = self._extract_file(image_tar, config_name)
            logger.debug("Uploading config blob, size=%s, digest=%s", size, digest)
            self._upload_blob(fpath, size, digest)
            manifest['config'] = {
                'digest': digest,
                'mediaType': CONFIG_MIMETYPE,
                'size': size,
            }

        manifest['layers'] = manifest_layers = []
        for idx, layer_name in enumerate(layer_names, 1):
            fpath, size, digest = self._extract_file(image_tar, layer_name, compress=True)
            logger.debug(
                "Uploading layer blob %s/%s, size=%s, digest=%s",
                idx, len(layer_names), size, digest)
            self._upload_blob(fpath, size, digest)
            manifest_layers.append({
                'digest': digest,
                'mediaType': LAYER_MIMETYPE,
                'size': size,
            })

        # upload the manifest
        manifest_data = json.dumps(manifest)
        digest = 'sha256:{}'.format(hashlib.sha256(manifest_data.encode('utf8')).hexdigest())
        self.registry.upload_manifest(manifest_data, digest)
        return digest
