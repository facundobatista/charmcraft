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

import pytest
import responses
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


@responses.activate
def test_auth_simple():
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


@responses.activate
def test_auth_with_credentials(caplog):
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
    expected = "Authentication! {}".format(auth_info)
    assert [expected] == [rec.message for rec in caplog.records]


@responses.activate
def test_hit_simple_initial_auth_ok(caplog):
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

    # logged what it did
    expected = "Hitting the registry: GET http://fakereg.com/api/stuff"
    assert [expected] == [rec.message for rec in caplog.records]


def test_hit_simple_re_auth_ok():
    """Simple GET but needing to re-authenticate."""
    fixme


def test_hit_simple_re_auth_problems():
    """Bad response from the re-authentication process."""
    fixme


def test_hit_different_method():
    """Simple request using something else than GET."""
    fixme


def test_hit_including_headers():
    """A request including more headers."""
    fixme


def test_hit_extra_parameters():
    """The request can include extra parameters."""
    fixme



#def test_():
#    """."""
#    fixme
