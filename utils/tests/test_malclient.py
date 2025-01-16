import pytest
from unittest.mock import patch, Mock

from utils.MalClient import MalClient


@pytest.fixture
def mock_access_token():
    return "mock_access_token"

@pytest.fixture
def mal_client(mock_access_token):
    return MalClient(mock_access_token)

@patch("requests.get")
def test_fetch_data_success(mock_get, mal_client):
    # Mock the response from the MAL API
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": [], "paging": {}}
    mock_get.return_value = mock_response

    params = {"fields": "list_status", "limit": 50, "offset": 0}
    response = mal_client.fetch_data(params)

    assert response == {"data": [], "paging": {}}
    mock_get.assert_called_once_with(
        "https://api.myanimelist.net/v2/users/@me/animelist",
        headers={"Authorization": "Bearer mock_access_token"},
        params=params,
    )

@patch("requests.get")
def test_fetch_data_failure(mock_get, mal_client):
    # Mock a failure response from the MAL API
    mock_response = Mock()
    mock_response.status_code = 401
    mock_response.raise_for_status.side_effect = Exception("Unauthorized")
    mock_get.return_value = mock_response

    params = {"fields": "list_status", "limit": 50, "offset": 0}

    with pytest.raises(Exception) as excinfo:
        mal_client.fetch_data(params)

    assert str(excinfo.value) == "Unauthorized"
    mock_get.assert_called_once()

@patch("requests.get")
def test_fetch_data_with_custom_url(mock_get, mock_access_token):
    # Mock the response when using a custom base URL
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": [], "paging": {}}
    mock_get.return_value = mock_response

    # Create MalClient with a custom base URL
    mal_client = MalClient(mock_access_token, base_url="https://custom.api.url/v2/anime")

    params = {"fields": "list_status", "limit": 50, "offset": 0}
    response = mal_client.fetch_data(params)

    # Assert the expected response from the mock
    assert response == {"data": [], "paging": {}}

    # Verify that the API call used the custom base URL
    mock_get.assert_called_once_with(
        "https://custom.api.url/v2/anime",
        headers={"Authorization": "Bearer mock_access_token"},
        params=params,
    )
