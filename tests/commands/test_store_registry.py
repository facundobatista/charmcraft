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

"""Tests for the OCI Registry related functionality (code in store/registry.py)."""

import io
import json
import logging
from unittest.mock import patch

import pytest
import requests

from charmcraft.cmdbase import CommandError
from charmcraft.commands.store.registry import assert_response_ok, OCIRegistry


# -- tests for response verifications

def create_response(status_code=200, headers=None, raw_content=b'', json_content=None):
    """Create a fake requests' response."""
    if headers is None:
        headers = {}

    if json_content is not None:
        headers.setdefault('Content-Type', 'application/json')
        content_bytes = json.dumps(json_content).encode("utf8")
    else:
        content_bytes = raw_content

    resp = requests.Response()
    resp.status_code = status_code
    resp.raw = io.BytesIO(content_bytes)
    resp.headers = headers  # not case insensitive, but good enough
    return resp


def test_assert_response_ok_simple_json():
    """Simple case for a good response with JSON content."""
    test_content = {'foo': 2, 'bar': 1}
    response = create_response(json_content=test_content)
    result = assert_response_ok(response)
    assert result == test_content


def test_assert_response_ok_not_json():
    """A good non-json response."""
    response = create_response(raw_content=b'stuff')
    result = assert_response_ok(response)
    assert result is None


def test_assert_response_ok_different_status():
    """A good response with a different status code."""
    test_content = {'foo': 2, 'bar': 1}
    response = create_response(json_content=test_content, status_code=201)
    result = assert_response_ok(response, expected_status=201)
    assert result == test_content


def test_assert_response_errors_in_result():
    """Response is as expected but server flags errors."""
    errors = [{'foo': 'bar'}]
    test_content = {'errors': errors}
    response = create_response(json_content=test_content)
    with pytest.raises(CommandError) as cm:
        assert_response_ok(response)
    assert str(cm.value) == "Response with errors from server: {}".format(errors)


def test_assert_response_bad_status_code_with_json_errors():
    """Different status code than expected, with the server including errors."""
    errors = [{'foo': 'bar'}]
    test_content = {'errors': errors}
    response = create_response(status_code=404, json_content=test_content)
    with pytest.raises(CommandError) as cm:
        assert_response_ok(response)
    assert str(cm.value) == (
        "Wrong status code from server (expected=200, got=404) errors={} "
        "headers={{'Content-Type': 'application/json'}}".format(errors))


def test_assert_response_bad_status_code_blind():
    """Different status code than expected, no more info."""
    response = create_response(status_code=500, raw_content=b"stuff")
    with pytest.raises(CommandError) as cm:
        assert_response_ok(response)
    assert str(cm.value) == (
        "Wrong status code from server (expected=200, got=500) errors=None headers={}")


# -- tests for OCIRegistry auth & hit helpers


def test_auth_simple(responses):
    """Simple authentication."""
    responses.add(
        responses.GET,
        "http://auth.fakereg.com?service=test-service&scope=test-scope",
        json={'token': 'test-token'})

    ocireg = OCIRegistry("http://fakereg.com/", "test-orga", "test-image")
    auth_info = dict(realm='http://auth.fakereg.com', service='test-service', scope='test-scope')
    token = ocireg._authenticate(auth_info)
    assert token == 'test-token'
    sent_auth_header = responses.calls[0].request.headers.get('Authorization')
    assert sent_auth_header is None


def test_auth_with_credentials(caplog, responses):
    """Authenticate passing credentials."""
    caplog.set_level(logging.DEBUG, logger="charmcraft")

    responses.add(
        responses.GET,
        "http://auth.fakereg.com?service=test-service&scope=test-scope",
        json={'token': 'test-token'})

    ocireg = OCIRegistry("http://fakereg.com/", "test-orga", "test-image")
    ocireg.auth_encoded_credentials = "some encoded stuff"
    auth_info = dict(realm='http://auth.fakereg.com', service='test-service', scope='test-scope')
    token = ocireg._authenticate(auth_info)
    assert token == 'test-token'
    sent_auth_header = responses.calls[0].request.headers.get('Authorization')
    assert sent_auth_header == "Basic some encoded stuff"

    # generic auth indication is logged but NOT the credentials
    expected = "Authenticating! {}".format(auth_info)
    assert [expected] == [rec.message for rec in caplog.records]


def test_hit_simple_initial_auth_ok(caplog, responses):
    """Simple GET with auth working at once."""
    caplog.set_level(logging.DEBUG, logger="charmcraft")

    # set the Registry with an initial token
    ocireg = OCIRegistry("http://fakereg.com/", "test-orga", "test-image")
    ocireg.auth_token = 'some auth token'

    # fake a 200 response
    responses.add(responses.GET, 'http://fakereg.com/api/stuff')

    # try it
    response = ocireg._hit('GET', 'http://fakereg.com/api/stuff')
    assert response == responses.calls[0].response

    # verify it authed ok
    sent_auth_header = responses.calls[0].request.headers.get('Authorization')
    assert sent_auth_header == "Bearer some auth token"

    # logged what it did
    expected = "Hitting the registry: GET http://fakereg.com/api/stuff"
    assert [expected] == [rec.message for rec in caplog.records]


def test_hit_simple_re_auth_ok(responses):
    """Simple GET but needing to re-authenticate."""
    # set the Registry
    ocireg = OCIRegistry("http://fakereg.com/", "test-orga", "test-image")
    ocireg.auth_token = 'some auth token'

    # need to set up two responses!
    # - the 401 response with the proper info to re-auth
    # - the request that actually works
    headers = {'Www-Authenticate': (
        'Bearer realm="https://auth.fakereg.com/token",'
        'service="fakereg.com",scope="repository:library/stuff:pull"')}
    responses.add(responses.GET, 'http://fakereg.com/api/stuff', headers=headers, status=401)
    responses.add(responses.GET, 'http://fakereg.com/api/stuff')

    # try it, isolating the re-authentication (tested separatedly above)
    with patch.object(ocireg, '_authenticate') as mock_auth:
        mock_auth.return_value = "new auth token"
        response = ocireg._hit('GET', 'http://fakereg.com/api/stuff')
    assert response == responses.calls[1].response
    mock_auth.assert_called_with({
        'realm': 'https://auth.fakereg.com/token',
        'scope': 'repository:library/stuff:pull',
        'service': 'fakereg.com',
    })

    # verify it authed ok both times, with corresponding tokens, and that it stored the new one
    sent_auth_header = responses.calls[0].request.headers.get('Authorization')
    assert sent_auth_header == "Bearer some auth token"
    sent_auth_header = responses.calls[1].request.headers.get('Authorization')
    assert sent_auth_header == "Bearer new auth token"
    assert ocireg.auth_token == "new auth token"


def test_hit_simple_re_auth_problems(responses):
    """Bad response from the re-authentication process."""
    ocireg = OCIRegistry("http://fakereg.com/", "test-orga", "test-image")

    # set only one response, a 401 which is broken and all will end there
    headers = {'Www-Authenticate': 'broken header'}
    responses.add(responses.GET, 'http://fakereg.com/api/stuff', headers=headers, status=401)

    # try it, isolating the re-authentication (tested separatedly above)
    expected = (
        "Bad 401 response: Bearer not found; "
        "headers: {.*'Www-Authenticate': 'broken header'.*}")
    with pytest.raises(CommandError, match=expected):
        ocireg._hit('GET', 'http://fakereg.com/api/stuff')


def test_hit_different_method(responses):
    """Simple request using something else than GET."""
    # set the Registry with an initial token
    ocireg = OCIRegistry("http://fakereg.com/", "test-orga", "test-image")
    ocireg.auth_token = 'some auth token'

    # fake a 200 response
    responses.add(responses.POST, 'http://fakereg.com/api/stuff')

    # try it
    response = ocireg._hit('POST', 'http://fakereg.com/api/stuff')
    assert response == responses.calls[0].response


def test_hit_including_headers(responses):
    """A request including more headers."""
    # set the Registry with an initial token
    ocireg = OCIRegistry("http://fakereg.com/", "test-orga", "test-image")
    ocireg.auth_token = 'some auth token'

    # fake a 200 response
    responses.add(responses.POST, 'http://fakereg.com/api/stuff')

    # try it
    response = ocireg._hit('POST', 'http://fakereg.com/api/stuff', headers={'FOO': 'bar'})
    assert response == responses.calls[0].response

    # check that it sent the requested header AND the automatic auth one
    sent_headers = responses.calls[0].request.headers
    assert sent_headers.get('FOO') == "bar"
    assert sent_headers.get('Authorization') == "Bearer some auth token"


def test_hit_extra_parameters(responses):
    """The request can include extra parameters."""
    ocireg = OCIRegistry("http://fakereg.com/", "test-orga", "test-image")

    # fake a 200 response
    responses.add(responses.PUT, 'http://fakereg.com/api/stuff')

    # try it
    response = ocireg._hit('PUT', 'http://fakereg.com/api/stuff', data=b'test-payload')
    assert response == responses.calls[0].response
    assert responses.calls[0].request.body == b'test-payload'


# -- tests for other OCIRegistry helpers: full url and checkers if stuff uploaded

def test_get_fully_qualified_url():
    """Check that the url is built correctly."""
    ocireg = OCIRegistry("http://fakereg.com/", "test-orga", "test-image")
    url = ocireg.get_fully_qualified_url('sha256:thehash')
    assert url == "http://fakereg.com/test-orga/test-image@sha256:thehash"

def test_():
    """."""
    fixme


# -- tests for the OCIRegistry manifest download and upload

def test_():
    """."""
    fixme


# -- tests for the OCIRegistry blob download and upload

def test_():
    """."""
    fixme


# -- tests for the ImageHandler blob and manifest processing

def test_():
    """."""
    fixme


# -- tests for the ImageHandler 'copy' functionality

def test_():
    """."""
    fixme


# -- tests for the ImageHandler 'get_destination_url' functionality

def test_():
    """."""
    fixme
