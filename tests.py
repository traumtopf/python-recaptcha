# -*- coding: utf-8 -*-
################################################################################
#
# Copyright (c) 2012, 2degrees Limited <2degrees-floss@googlegroups.com>.
# All Rights Reserved.
#
# This file is part of python-recaptcha <http://packages.python.org/recaptcha>,
# which is subject to the provisions of the BSD at
# <http://dev.2degreesnetwork.com/p/2degrees-license.html>. A copy of the
# license should accompany this distribution. THIS SOFTWARE IS PROVIDED "AS IS"
# AND ANY AND ALL EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED, INCLUDING, BUT
# NOT LIMITED TO, THE IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST
# INFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE.
#
################################################################################

from json import loads as json_decode
import six
from six.moves.urllib.parse import parse_qs, urlparse

from mock import patch

import unittest

from nose.tools import assert_false
from nose.tools import assert_in
from nose.tools import assert_not_equal
from nose.tools import assert_not_in
from nose.tools import assert_raises
from nose.tools import assert_raises_regexp
from nose.tools import eq_
from nose.tools import ok_

from recaptcha import _RECAPTCHA_API_URL
from recaptcha import RecaptchaClient
from recaptcha import RecaptchaInvalidChallengeError
from recaptcha import RecaptchaInvalidPrivateKeyError


_FAKE_PRIVATE_KEY = 'private key'
_FAKE_PUBLIC_KEY = 'public key'

_FAKE_SOLUTION_TEXT = 'hello world'
_FAKE_CHALLENGE_ID = '12345'
_RANDOM_REMOTE_IP = '192.0.2.0'


class MockResponse(object):
    def __init__(self, resp_data, code=200, msg='OK'):
        self.resp_data = resp_data
        self.code = code
        self.msg = msg
        self.headers = {'content-type': 'text/plain; charset=utf-8'}
 
    def read(self):
        return self.resp_data

    def close(self):
        pass

    def getcode(self):
        return self.code


class TestSolutionVerification(unittest.TestCase):

    def setUp(self):
        "Mock urllib2.urlopen"
        self.patcher = patch('recaptcha.urlopen')
        self.urlopen_mock = self.patcher.start()

    def test_invalid_challenge(self):
        client = RecaptchaClient(_FAKE_PRIVATE_KEY, _FAKE_PUBLIC_KEY)

        correct_response = "false\ninvalid-request-cookie"
        self.urlopen_mock.return_value = MockResponse(correct_response)

        with self.assertRaises(RecaptchaInvalidChallengeError):
            result = client.is_solution_correct(_FAKE_SOLUTION_TEXT, _FAKE_CHALLENGE_ID, _RANDOM_REMOTE_IP)

    def test_invalid_private_key(self):
        client = RecaptchaClient(_FAKE_PRIVATE_KEY, _FAKE_PUBLIC_KEY)

        correct_response = "false\ninvalid-site-private-key"
        self.urlopen_mock.return_value = MockResponse(correct_response)

        with self.assertRaises(RecaptchaInvalidPrivateKeyError):
            result = client.is_solution_correct(_FAKE_SOLUTION_TEXT, _FAKE_CHALLENGE_ID, _RANDOM_REMOTE_IP)

    def test_solution_correct(self):
        client = RecaptchaClient(_FAKE_PRIVATE_KEY, _FAKE_PUBLIC_KEY)

        correct_response = "true"
        self.urlopen_mock.return_value = MockResponse(correct_response)

        result = client.is_solution_correct(_FAKE_SOLUTION_TEXT, _FAKE_CHALLENGE_ID, _RANDOM_REMOTE_IP)

        self.assertTrue(result)

    def test_solution_incorrect(self):
        client = RecaptchaClient(_FAKE_PRIVATE_KEY, _FAKE_PUBLIC_KEY)

        incorrect_response = "false\nincorrect-captcha-sol"
        self.urlopen_mock.return_value = MockResponse(incorrect_response)

        result = client.is_solution_correct(_FAKE_SOLUTION_TEXT, _FAKE_CHALLENGE_ID, _RANDOM_REMOTE_IP)
        self.assertFalse(result)

    def tearDown(self):
        self.patcher.stop()


class TestChallengeURLGeneration(unittest.TestCase):
    def test_public_key_inclusion(self):
        client = RecaptchaClient(_FAKE_PRIVATE_KEY, _FAKE_PUBLIC_KEY)
        urls = client._get_challenge_urls(False, False)

        javascript_challenge_url = urls['javascript_challenge_url']
        javascript_challenge_url_components = urlparse(javascript_challenge_url)
        javascript_challenge_url_query = parse_qs(
            javascript_challenge_url_components.query,
        )

        self.assertIn('k', javascript_challenge_url_query)
        self.assertEqual(client.public_key, javascript_challenge_url_query['k'][0])

        noscript_challenge_url = urls['noscript_challenge_url']
        noscript_challenge_url_components = urlparse(noscript_challenge_url)
        self.assertEqual(
            javascript_challenge_url_components.query,
            noscript_challenge_url_components.query,
        )

    def test_ssl_required(self):
        client = RecaptchaClient(_FAKE_PRIVATE_KEY, _FAKE_PUBLIC_KEY)
        urls = client._get_challenge_urls(False, use_ssl=False)

        javascript_challenge_url = urls['javascript_challenge_url']
        self.assertTrue(javascript_challenge_url.startswith(_RECAPTCHA_API_URL))

        noscript_challenge_url = urls['noscript_challenge_url']
        self.assertTrue(noscript_challenge_url.startswith(_RECAPTCHA_API_URL))

    def test_ssl_not_required(self):
        client = RecaptchaClient(_FAKE_PRIVATE_KEY, _FAKE_PUBLIC_KEY)
        urls = client._get_challenge_urls(False, use_ssl=True)

        javascript_challenge_url = urls['javascript_challenge_url']
        self.assertTrue(javascript_challenge_url.startswith('https://'))

        noscript_challenge_url = urls['noscript_challenge_url']
        self.assertTrue(noscript_challenge_url.startswith('https://'))

    def test_previous_solution_incorrect(self):
        client = RecaptchaClient(_FAKE_PRIVATE_KEY, _FAKE_PUBLIC_KEY)
        urls = client._get_challenge_urls(
            was_previous_solution_incorrect=True,
            use_ssl=False,
        )

        javascript_challenge_url = urls['javascript_challenge_url']
        javascript_challenge_url_components = urlparse(javascript_challenge_url)
        javascript_challenge_url_query = parse_qs(
            javascript_challenge_url_components.query,
        )

        self.assertIn('error', javascript_challenge_url_query)
        self.assertEqual('incorrect-captcha-sol', javascript_challenge_url_query['error'][0])

        noscript_challenge_url = urls['noscript_challenge_url']
        noscript_challenge_url_components = urlparse(noscript_challenge_url)
        self.assertEqual(
            javascript_challenge_url_components.query,
            noscript_challenge_url_components.query
        )

    def test_previous_solution_correct(self):
        client = RecaptchaClient(_FAKE_PRIVATE_KEY, _FAKE_PUBLIC_KEY)
        urls = client._get_challenge_urls(
            was_previous_solution_incorrect=False,
            use_ssl=False,
        )

        javascript_challenge_url = urls['javascript_challenge_url']
        javascript_challenge_url_components = urlparse(javascript_challenge_url)
        javascript_challenge_url_query = parse_qs(
            javascript_challenge_url_components.query,
        )

        self.assertNotIn('error', javascript_challenge_url_query)

        noscript_challenge_url = urls['noscript_challenge_url']
        noscript_challenge_url_components = urlparse(noscript_challenge_url)
        self.assertEqual(
            javascript_challenge_url_components.query,
            noscript_challenge_url_components.query,
        )

    def test_url_paths(self):
        client = RecaptchaClient(_FAKE_PRIVATE_KEY, _FAKE_PUBLIC_KEY)
        urls = client._get_challenge_urls(
            was_previous_solution_incorrect=False,
            use_ssl=False,
        )

        javascript_challenge_url = urls['javascript_challenge_url']
        javascript_challenge_url_components = urlparse(javascript_challenge_url)

        noscript_challenge_url = urls['noscript_challenge_url']
        noscript_challenge_url_components = urlparse(noscript_challenge_url)

        self.assertNotEqual(
            javascript_challenge_url_components.path,
            noscript_challenge_url_components.path,
        )
