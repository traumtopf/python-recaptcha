################################################################################
#
# Copyright (c) 2012, 2degrees Limited <gustavonarea@2degreesnetwork.com>.
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
from urlparse import parse_qs
from urlparse import urlparse

from nose.tools import assert_false
from nose.tools import assert_in
from nose.tools import assert_not_equal
from nose.tools import assert_not_in
from nose.tools import assert_raises_regexp
from nose.tools import eq_
from nose.tools import ok_

from recaptcha import _RECAPTCHA_API_URL
from recaptcha import RecaptchaClient
from recaptcha import RecaptchaInvalidChallengeError
from recaptcha import RecaptchaInvalidPrivateKeyError


__all__ = [
    'TestChallengeOptions',
    'TestChallengeURLsGeneration',
    'TestSolutionVerification',
    ]


_INCORRECT_SOLUTION_RESULT = {
    'is_solution_correct': False,
    'error_code': 'incorrect-captcha-sol',
    }


_FAKE_PRIVATE_KEY = 'private key'
_FAKE_PUBLIC_KEY = 'public key'


_FAKE_SOLUTION_TEXT = 'hello world'
_FAKE_CHALLENGE_ID = '12345'
_RANDOM_REMOTE_IP = '192.0.2.0'


#{ Challenge markup generation tests


class TestChallengeURLsGeneration(object):
    
    def test_public_key_inclusion(self):
        client = _OfflineVerificationClient()
        variables = client._get_challenge_urls(False, False)
        
        javascript_challenge_url = variables['javascript_challenge_url']
        javascript_challenge_url_components = urlparse(javascript_challenge_url)
        javascript_challenge_url_query = parse_qs(
            javascript_challenge_url_components.query,
            )
        assert_in('k', javascript_challenge_url_query)
        eq_(client.public_key, javascript_challenge_url_query['k'][0])
        
        noscript_challenge_url = variables['noscript_challenge_url']
        noscript_challenge_url_components = urlparse(noscript_challenge_url)
        eq_(
            javascript_challenge_url_components.query,
            noscript_challenge_url_components.query,
            )
    
    def test_ssl_required(self):
        client = _OfflineVerificationClient()
        variables = client._get_challenge_urls(
            False,
            use_ssl=False,
            )
        
        javascript_challenge_url = variables['javascript_challenge_url']
        ok_(javascript_challenge_url.startswith(_RECAPTCHA_API_URL))
        
        noscript_challenge_url = variables['noscript_challenge_url']
        ok_(noscript_challenge_url.startswith(_RECAPTCHA_API_URL))
    
    def test_ssl_not_required(self):
        client = _OfflineVerificationClient()
        variables = client._get_challenge_urls(
            False,
            use_ssl=True,
            )
        
        javascript_challenge_url = variables['javascript_challenge_url']
        ok_(javascript_challenge_url.startswith('https://'))
        
        noscript_challenge_url = variables['noscript_challenge_url']
        ok_(noscript_challenge_url.startswith('https://'))
    
    def test_previous_solution_incorrect(self):
        client = _OfflineVerificationClient()
        variables = client._get_challenge_urls(
            was_previous_solution_incorrect=True,
            use_ssl=False,
            )
        
        javascript_challenge_url = variables['javascript_challenge_url']
        javascript_challenge_url_components = urlparse(javascript_challenge_url)
        javascript_challenge_url_query = parse_qs(
            javascript_challenge_url_components.query,
            )
        assert_in('error', javascript_challenge_url_query)
        eq_('incorrect-captcha-sol', javascript_challenge_url_query['error'][0])
        
        noscript_challenge_url = variables['noscript_challenge_url']
        noscript_challenge_url_components = urlparse(noscript_challenge_url)
        eq_(
            javascript_challenge_url_components.query,
            noscript_challenge_url_components.query,
            )
    
    def test_previous_solution_correct(self):
        client = _OfflineVerificationClient()
        variables = client._get_challenge_urls(
            was_previous_solution_incorrect=False,
            use_ssl=False,
            )
        
        javascript_challenge_url = variables['javascript_challenge_url']
        javascript_challenge_url_components = urlparse(javascript_challenge_url)
        javascript_challenge_url_query = parse_qs(
            javascript_challenge_url_components.query,
            )
        assert_not_in('error', javascript_challenge_url_query)
        
        noscript_challenge_url = variables['noscript_challenge_url']
        noscript_challenge_url_components = urlparse(noscript_challenge_url)
        eq_(
            javascript_challenge_url_components.query,
            noscript_challenge_url_components.query,
            )
    
    def test_url_paths(self):
        client = _OfflineVerificationClient()
        variables = client._get_challenge_urls(
            was_previous_solution_incorrect=False,
            use_ssl=False,
            )
        
        javascript_challenge_url = variables['javascript_challenge_url']
        javascript_challenge_url_components = urlparse(javascript_challenge_url)
        
        noscript_challenge_url = variables['noscript_challenge_url']
        noscript_challenge_url_components = urlparse(noscript_challenge_url)
        
        assert_not_equal(
            javascript_challenge_url_components.path,
            noscript_challenge_url_components.path,
            )


class TestChallengeOptions(object):
    
    def test_options(self):
        recaptcha_options = {'key1': 'value', 'key2': 3}
        client = RecaptchaClient(
            _FAKE_PRIVATE_KEY,
            _FAKE_PUBLIC_KEY,
            recaptcha_options=recaptcha_options,
            )
        
        decoded_recaptcha_options = json_decode(client.recaptcha_options_json)
        eq_(recaptcha_options, decoded_recaptcha_options)
    
    def test_no_options(self):
        client = RecaptchaClient(_FAKE_PRIVATE_KEY, _FAKE_PUBLIC_KEY)
        
        decoded_recaptcha_options = json_decode(client.recaptcha_options_json)
        assert_false(decoded_recaptcha_options)


#}


class TestSolutionVerification(object):
    
    def test_empty_solution(self):
        client = _OfflineVerificationClient(_INCORRECT_SOLUTION_RESULT)
        
        is_solution_correct = client.is_solution_correct(
            '',
            _FAKE_CHALLENGE_ID,
            _RANDOM_REMOTE_IP,
            )
        assert_false(is_solution_correct)
        
        # reCAPTCHA must not have been contacted
        eq_(0, client.communication_attempts)
    
    def test_empty_challenge(self):
        client = _OfflineVerificationClient(_INCORRECT_SOLUTION_RESULT)
        
        is_solution_correct = client.is_solution_correct(
            _FAKE_SOLUTION_TEXT,
            '',
            _RANDOM_REMOTE_IP,
            )
        assert_false(is_solution_correct)
        
        # reCAPTCHA must not have been contacted
        eq_(0, client.communication_attempts)
    
    def test_invalid_private_key(self):
        invalid_private_key_result = {
            'is_solution_correct': False,
            'error_code': 'invalid-site-private-key',
            }
        client = _OfflineVerificationClient(invalid_private_key_result)
        
        with assert_raises_regexp(
            RecaptchaInvalidPrivateKeyError,
            client.private_key,
            ):
            client.is_solution_correct(
                _FAKE_SOLUTION_TEXT,
                _FAKE_CHALLENGE_ID,
                _RANDOM_REMOTE_IP,
                )
    
    def test_invalid_challenge(self):
        invalid_challenge_result = {
            'is_solution_correct': False,
            'error_code': 'invalid-request-cookie',
            }
        client = _OfflineVerificationClient(invalid_challenge_result)
        
        with assert_raises_regexp(
            RecaptchaInvalidChallengeError,
            _FAKE_CHALLENGE_ID,
            ):
            client.is_solution_correct(
                _FAKE_SOLUTION_TEXT,
                _FAKE_CHALLENGE_ID,
                _RANDOM_REMOTE_IP,
                )
    
    def test_correct_solution_and_challenge(self):
        correct_solution_result = {'is_solution_correct': True}
        client = _OfflineVerificationClient(correct_solution_result)
        
        is_solution_correct = client.is_solution_correct(
            _FAKE_SOLUTION_TEXT,
            _FAKE_CHALLENGE_ID,
            _RANDOM_REMOTE_IP,
            )
        ok_(is_solution_correct)
    
    def test_incorrect_solution(self):
        client = _OfflineVerificationClient(_INCORRECT_SOLUTION_RESULT)
        
        is_solution_correct = client.is_solution_correct(
            _FAKE_SOLUTION_TEXT,
            _FAKE_CHALLENGE_ID,
            _RANDOM_REMOTE_IP,
            )
        assert_false(is_solution_correct)


#{ Stubs


class _OfflineVerificationClient(RecaptchaClient):
    
    def __init__(self, verification_result=None):
        super(_OfflineVerificationClient, self).__init__(
            _FAKE_PRIVATE_KEY,
            _FAKE_PUBLIC_KEY,
            )
        
        self.verification_result = verification_result
        self.communication_attempts = 0
    
    def _get_recaptcha_response_for_solution(
        self,
        solution_text,
        challenge_id,
        remote_ip,
        ):
        
        self.communication_attempts += 1
        
        return self.verification_result


#}