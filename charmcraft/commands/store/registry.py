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
import hashlib
import json
import logging
import os
from urllib.request import parse_http_list, parse_keqv_list

import requests

from charmcraft.cmdbase import CommandError

logger = logging.getLogger(__name__)

# some mimetypes
MANIFEST_LISTS = 'application/vnd.docker.distribution.manifest.list.v2+json'
MANIFEST_V2_MIMETYPE = 'application/vnd.docker.distribution.manifest.v2+json'
LAYER_MIMETYPE = 'application/vnd.docker.image.rootfs.diff.tar.gzip'
JSON_RELATED_MIMETYPES = {
    'application/json',
    'application/vnd.docker.distribution.manifest.v1+prettyjws',  # signed manifest
    MANIFEST_LISTS,
    MANIFEST_V2_MIMETYPE,
}

# downloads and uploads happen in chunks
CHUNK_SIZE = 2 ** 20  # 65536


def assert_response_ok(response, expected_status=200):
    """Assert the response is ok."""
    if response.status_code != expected_status:
        if response.headers.get('Content-Type') in JSON_RELATED_MIMETYPES:
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

    def get_manifest(self, reference):
        """Get the manifest for the indicated reference."""
        url = self._get_url("manifests/{}".format(reference))
        logger.debug("Getting manifests list for %s", reference)
        headers = {
            'Accept': MANIFEST_LISTS,
        }
        response = self._hit('GET', url, headers=headers)
        result = assert_response_ok(response)
        digest = response.headers['Docker-Content-Digest']

        # the response can be the manifest itself or a list of manifests (only determined
        # by the presence of the 'manifests' key
        manifests = result.get('manifests')

        if manifests is not None:
            return (manifests, digest, response.text)

        logger.debug("Got the manifest directly, schema %s", result['schemaVersion'])
        if result['schemaVersion'] != 2:
            # get the manifest in v2! cannot request it directly, as that will avoid us
            # getting the manifests list when available
            headers = {
                'Accept': MANIFEST_V2_MIMETYPE,
            }
            response = self._hit('GET', url, headers=headers)
            result = assert_response_ok(response)
            if result.get('schemaVersion') != 2:
                raise CommandError(
                    "Manifest v2 requested but got something else: {}".format(result))
            logger.debug("Got the v2 manifest ok")
            digest = response.headers['Docker-Content-Digest']
        return (None, digest, response.text)

    def upload_manifest(self, manifest, reference, *, multiple_manifest=False):
        """Upload a manifest."""
        mimetype = MANIFEST_LISTS if multiple_manifest else MANIFEST_V2_MIMETYPE
        url = self._get_url("manifests/{}".format(reference))
        headers = {
            'Content-Type': mimetype,
        }
        logger.debug("Uploading manifest with reference %s", reference)
        response = self._hit('PUT', url, headers=headers, data=manifest.encode('utf8'))
        assert_response_ok(response, expected_status=201)
        logger.debug("Manifest uploaded OK")

    def download_blob(self, filepath, blob_size, blob_digest):
        """Download the blob to a temp file."""
        hash_method, hash_value = blob_digest.split(':')
        logger.debug("Downloading the blob")
        url = self._get_url("blobs/{}".format(blob_digest))

        while True:
            response = self._hit('GET', url, stream=True)
            if response.status_code == 200:
                # let's pull the bytes
                break

            if response.status_code in (302, 307):
                url = response.headers['Location']
                logger("Got a redirection to %s", url)
                continue

            # something else is going on
            raise CommandError(
                "Got wrong response when downloading an image: {!r}".format(response))

        hasher = hashlib.new(hash_method)
        downloaded_total = 0
        with open(filepath, 'wb') as fh:
            for chunk in response.iter_content(CHUNK_SIZE):
                downloaded_total += len(chunk)
                progress = 100 * downloaded_total / blob_size
                print("Downloading.. {:.2f}%\r".format(progress), end='', flush=True)
                hasher.update(chunk)
                fh.write(chunk)

        digest = hasher.hexdigest()
        logger.debug("Downloading done, size=%s digest=%s", downloaded_total, digest)
        if digest != hash_value or downloaded_total != blob_size:
            raise CommandError("Download corrupted")

    def upload_blob(self, filepath, size, digest):
        """Upload the blob from a file."""
        # push the blob
        logger.debug("Getting URL to push the blob")
        url = self._get_url("blobs/uploads/")
        response = self._hit('POST', url)
        assert_response_ok(response, expected_status=202)
        upload_url = response.headers['Location']
        range_from, range_to_inclusive = [int(x) for x in response.headers['Range'].split('-')]
        logger.debug("Got upload URL ok with range %s-%s", range_from, range_to_inclusive)
        if range_from != 0:
            raise CommandError("Bad range received")
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
                    'Content-Type': 'application/octet-stream',
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
            raise CommandError("Upload corrupted")


class ImageHandler:
    """Provide specific functionalities around images."""

    def __init__(self, src_registry, dst_registry):
        self.temp_filepaths = []  # FIXME: delete all this when the process is done
        self.src_registry = src_registry
        self.dst_registry = dst_registry

    def _process_blob(self, blob_size, blob_digest):
        """Download and reupload a blob."""
        logger.debug("Processing blob, size=%s, digest=%s", blob_size, blob_digest)

        # if it's already uploaded, nothing to do
        if self.dst_registry.is_blob_already_uploaded(blob_digest):
            logger.debug("Blob was already uploaded")
            return

        # don't need to re-download the blog if the file for it is there and with correct digest
        logger.debug("Verify if we need to download it")
        blob_filepath = '/tmp/{}.bin'.format(blob_digest)  # FIXME: find a better location for this
        self.temp_filepaths.append(blob_filepath)
        need_to_download = True
        if os.path.exists(blob_filepath):
            with open(blob_filepath, 'rb') as fh:
                hasher = hashlib.sha256(fh.read())
            digest = 'sha256:{}'.format(hasher.hexdigest())
            if blob_digest == digest:
                need_to_download = False

        if need_to_download:
            self.src_registry.download_blob(blob_filepath, blob_size, blob_digest)

        # upload
        self.dst_registry.upload_blob(blob_filepath, blob_size, blob_digest)

    def _process_manifest(self, raw_manifest):
        """Process a v2 schema 2 manifest.

        https://docs.docker.com/registry/spec/manifest-v2-2/
        """
        manifest = json.loads(raw_manifest)
        logger.debug("Processing manifest version %r", manifest.get('schemaVersion'))

        # download the config blob
        blob = manifest.get('config')
        if blob is not None:
            logger.debug("Found config blob")
            self._process_blob(blob['size'], blob['digest'])

        # and all the layers
        layers = manifest['layers']
        for idx, blob in enumerate(layers, 1):
            logger.debug("Found layer blob %s/%s", idx, len(layers))
            if blob['mediaType'] != LAYER_MIMETYPE:
                logger.debug("Ignoring layer: %s", blob)
                continue
            self._process_blob(blob['size'], blob['digest'])

    def copy_image(self, reference):
        """Copy an image from source registry to destination registry."""
        # get the manifest or manifests; we cannot check before if the original reference is
        # already in the destination registry, as the reference may be a tag pointing to a
        # different image (so we need the digest from the source registry)
        (sublist, digest, raw_manifest) = self.src_registry.get_manifest(reference)

        # handle the case of a direct manifest
        if sublist is None:
            logger.info("Got a single manifest with digest %s", digest)

            # check if it's already uploaded
            if self.dst_registry.is_manifest_already_uploaded(digest):
                logger.info("Manifest was already uploaded")
                return digest

            self._process_manifest(raw_manifest)
            self.dst_registry.upload_manifest(raw_manifest, reference)
            return digest

        # handle the case of the manifest being actually a list of manifests
        raw_meta_manifest = raw_manifest
        meta_manifest_digest = digest
        logger.info("Got a multiple manifest (len=%s) with digest %s", len(sublist), digest)

        # check if it's already uploaded
        if self.dst_registry.is_manifest_already_uploaded(digest):
            logger.info("Meta-manifest was already uploaded")
            return digest

        for idx, manifest in enumerate(sublist, 1):
            digest = manifest['digest']
            logger.info(
                "Sub-manifest %s/%s for platform %s, digest %s",
                idx, len(sublist), manifest.get('platform'), digest)

            # check if it's already uploaded
            if self.dst_registry.is_manifest_already_uploaded(digest):
                logger.info("Sub-manifest was already uploaded")
                continue

            # download
            logger.info("Downloading manifest")
            (_, _, raw_manifest) = self.src_registry.get_manifest(digest)

            # process and upload
            self._process_manifest(raw_manifest)
            self.dst_registry.upload_manifest(raw_manifest, digest)

        logger.debug("Uploading meta-manifest")
        self.dst_registry.upload_manifest(raw_meta_manifest, reference, multiple_manifest=True)
        return meta_manifest_digest

    def get_digest(self, reference):
        """Get the fully qualified URL in the Canonical's registry for a tag/digest reference."""
        if not self.dst_registry.is_manifest_already_uploaded(reference):
            raise CommandError(
                "The image {!r} with reference {!r} does not exist in the Canonical's "
                "registry".format(self.dst_registry.image_name, reference))

        # need to actually get the manifest, because this is what we'll end up getting the v2 one
        _, digest, _ = self.dst_registry.get_manifest(reference)
        return digest
