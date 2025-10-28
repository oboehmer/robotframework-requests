import pytest
from RequestsLibrary import RequestsLibrary
from utests import mock


# @mock.patch('RequestsLibrary.RequestsKeywords.requests.get')
# def test_common_request_none_session(mocked_get):
#     keywords = RequestsLibrary.RequestsKeywords()
#     keywords._common_request('get', None, 'http://mock.rules')
#     mocked_get.assert_called_with('http://mock.rules')

def build_mocked_session_keywords(url=''):
    keywords = RequestsLibrary()
    session = mock.MagicMock()
    session.url = url
    return session, keywords


def test_merge_url_with_none_session():
    keywords = RequestsLibrary()
    url = keywords._merge_url(None, 'http://thisisa.url')
    assert url == 'http://thisisa.url'


def test_merge_url_with_session_url_only():
    session, keywords = build_mocked_session_keywords('http://www.domain.com')
    url = keywords._merge_url(session, '')
    assert url == 'http://www.domain.com'


def test_merge_url_with_session_url_and_uri_endpoint():
    session, keywords = build_mocked_session_keywords('http://www.domain.com')
    url = keywords._merge_url(session, 'endpoint')
    assert url == 'http://www.domain.com/endpoint'


def test_merge_url_with_session_url_slash_and_uri_endpoint():
    session, keywords = build_mocked_session_keywords('http://www.domain.com/')
    url = keywords._merge_url(session, 'endpoint')
    assert url == 'http://www.domain.com/endpoint'


def test_merge_url_with_session_url_and_uri_slash_endpoint():
    session, keywords = build_mocked_session_keywords('http://www.domain.com')
    url = keywords._merge_url(session, '/endpoint')
    assert url == 'http://www.domain.com/endpoint'


# breaking change with 0.8 introduced in 0.9 :( #329
def test_merge_url_with_session_url_path_and_uri_root_endpoint():
    session, keywords = build_mocked_session_keywords('http://www.domain.com/path')
    url = keywords._merge_url(session, '/endpoint')
    assert url == 'http://www.domain.com/path/endpoint'


# breaking change with 0.8 introduced in 0.9 :( #329
def test_merge_url_with_session_url_path_and_uri_endpoint():
    session, keywords = build_mocked_session_keywords('http://www.domain.com/path')
    url = keywords._merge_url(session, 'endpoint')
    assert url == 'http://www.domain.com/path/endpoint'


def test_merge_url_with_session_url_path_slash_and_uri_endpoint():
    session, keywords = build_mocked_session_keywords('http://www.domain.com/path/')
    url = keywords._merge_url(session, 'endpoint')
    assert url == 'http://www.domain.com/path/endpoint'


def test_merge_url_with_session2trailing_and_endpoint():
    session, keywords = build_mocked_session_keywords('http://www.domain.com//')
    url = keywords._merge_url(session, 'endpoint')
    assert url == 'http://www.domain.com/endpoint'


def test_merge_url_with_session_and_slash_endpoint_2trailing():
    session, keywords = build_mocked_session_keywords('http://www.domain.com')
    url = keywords._merge_url(session, '/endpoint//')
    assert url == 'http://www.domain.com/endpoint/'


def test_merge_url_with_url_override_base():
    session, keywords = build_mocked_session_keywords('http://www.domain.com')
    url = keywords._merge_url(session, 'https://new.domain.com')
    assert url == 'https://new.domain.com'


def test_process_secrets_with_no_secrets():
    from RequestsLibrary.utils import process_secrets
    auth = ('user', 'password')
    result = process_secrets(auth)
    assert result == ('user', 'password')


def test_process_secrets_with_secrets():
    try:
        from robot.api.types import Secret
    except (ImportError, ModuleNotFoundError):
        pytest.skip('Secret type not available in tested robot version')

    from RequestsLibrary.utils import process_secrets
    secret_password = Secret('mypassword')
    auth = ('user', secret_password)
    result = process_secrets(auth)
    assert result == ('user', 'mypassword')
    assert not isinstance(result[1], Secret)


def test_process_secrets_with_mixed_secrets():
    try:
        from robot.api.types import Secret
    except (ImportError, ModuleNotFoundError):
        pytest.skip('Secret type not available in tested robot version')

    from RequestsLibrary.utils import process_secrets
    secret_user = Secret('myuser')
    secret_password = Secret('mypassword')
    auth = (secret_user, secret_password)
    result = process_secrets(auth)
    assert result == ('myuser', 'mypassword')
    assert not isinstance(result[0], Secret)
    assert not isinstance(result[1], Secret)
