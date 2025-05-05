import pytest
import os
import tempfile
import hashlib
import bencodepy
import requests
import requests_mock
import sys
import string  # Import the string module
from unittest.mock import patch, MagicMock

# Import functions from the script
from torrent_stats import (
    generate_peer_id,
    parse_torrent_file,
    calculate_info_hash,
    calculate_total_size,
    get_tracker_urls,
    query_tracker,
    display_stats,
    main,
    PEER_ID_PREFIX,
    DEFAULT_PORT,
)

# --- Fixtures ---

@pytest.fixture
def temp_torrent_file():
    """Creates a temporary valid torrent file for testing."""
    info_dict = {
        b"name": b"test_torrent",
        b"piece length": 262144,
        b"pieces": b"dummy_pieces_hash",
        b"length": 1024,  # Single file torrent
    }
    torrent_data = {
        b"announce": b"http://tracker.example.com/announce",
        b"info": info_dict,
        b"comment": b"Test torrent file",
    }
    bencoded_data = bencodepy.encode(torrent_data)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".torrent") as tmp_file:
        tmp_file.write(bencoded_data)
        file_path = tmp_file.name

    yield file_path, torrent_data, info_dict

    # Cleanup: remove the temporary file
    os.remove(file_path)


@pytest.fixture
def temp_multifile_torrent():
    """Creates a temporary valid multi-file torrent file."""
    info_dict = {
        b"name": b"test_multi_torrent",
        b"piece length": 262144,
        b"pieces": b"dummy_pieces_hash_multi",
        b"files": [
            {b"length": 512, b"path": [b"dir1", b"file1.txt"]},
            {b"length": 1024, b"path": [b"file2.txt"]},
        ],
    }
    torrent_data = {
        b"announce-list": [
            [b"http://tracker1.com/announce"],
            [b"http://tracker2.com/announce", b"https://tracker3.com/announce"],
        ],
        b"info": info_dict,
    }
    bencoded_data = bencodepy.encode(torrent_data)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".torrent") as tmp_file:
        tmp_file.write(bencoded_data)
        file_path = tmp_file.name

    yield file_path, torrent_data, info_dict

    os.remove(file_path)


@pytest.fixture
def temp_invalid_bencode_file():
    """Creates a temporary file with invalid bencode data."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".torrent") as tmp_file:
        tmp_file.write(b"invalid:bencode{data")
        file_path = tmp_file.name
    yield file_path
    os.remove(file_path)


@pytest.fixture
def temp_empty_file():
    """Creates a temporary empty file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".torrent") as tmp_file:
        file_path = tmp_file.name
    yield file_path
    os.remove(file_path)


# --- Test Functions ---

def test_generate_peer_id():
    """Test peer ID generation."""
    peer_id = generate_peer_id()
    assert isinstance(peer_id, bytes)
    assert len(peer_id) == 20
    assert peer_id.startswith(PEER_ID_PREFIX.encode("ascii"))
    # Check if the rest is alphanumeric (or letters/digits as per implementation)
    random_part = peer_id[len(PEER_ID_PREFIX) :]
    assert all(
        c in (string.ascii_letters + string.digits).encode("ascii") for c in random_part
    )


def test_parse_torrent_file_valid(temp_torrent_file):
    """Test parsing a valid torrent file."""
    file_path, expected_data, _ = temp_torrent_file
    parsed_data = parse_torrent_file(file_path)
    assert parsed_data == expected_data


def test_parse_torrent_file_not_found(capsys):
    """Test parsing a non-existent file."""
    non_existent_path = "non_existent_file.torrent"
    parsed_data = parse_torrent_file(non_existent_path)
    assert parsed_data is None
    captured = capsys.readouterr()
    assert f"Error: File not found at {non_existent_path}" in captured.err


def test_parse_torrent_file_invalid_bencode(temp_invalid_bencode_file, capsys):
    """Test parsing a file with invalid bencode data."""
    file_path = temp_invalid_bencode_file
    parsed_data = parse_torrent_file(file_path)
    assert parsed_data is None
    captured = capsys.readouterr()
    assert f"Error: Could not decode Bencoded data in {file_path}" in captured.err


def test_parse_torrent_file_empty(temp_empty_file, capsys):
    """Test parsing an empty file."""
    file_path = temp_empty_file
    parsed_data = parse_torrent_file(file_path)
    assert parsed_data is None
    captured = capsys.readouterr()
    # Check for the specific empty file error message
    assert f"Error: Torrent file is empty: {file_path}" in captured.err


@patch("builtins.open", side_effect=PermissionError("Permission denied"))
def test_parse_torrent_file_read_error(mock_open, capsys):
    """Test handling generic read errors."""
    file_path = "dummy_path.torrent"
    parsed_data = parse_torrent_file(file_path)
    assert parsed_data is None
    captured = capsys.readouterr()
    assert f"Error reading torrent file {file_path}: Permission denied" in captured.err


def test_calculate_info_hash(temp_torrent_file):
    """Test info hash calculation."""
    _, _, info_dict = temp_torrent_file
    expected_bencoded_info = bencodepy.encode(info_dict)
    expected_hash = hashlib.sha1(expected_bencoded_info).digest()
    calculated_hash = calculate_info_hash(info_dict)
    assert calculated_hash == expected_hash


def test_calculate_total_size_single_file(temp_torrent_file):
    """Test total size calculation for single-file torrent."""
    _, _, info_dict = temp_torrent_file
    expected_size = 1024
    assert calculate_total_size(info_dict) == expected_size


def test_calculate_total_size_multi_file(temp_multifile_torrent):
    """Test total size calculation for multi-file torrent."""
    _, _, info_dict = temp_multifile_torrent
    expected_size = 512 + 1024
    assert calculate_total_size(info_dict) == expected_size


def test_calculate_total_size_missing_length():
    """Test total size calculation when length/files key is missing."""
    info_dict_no_length = {b"name": b"no_length"}
    assert calculate_total_size(info_dict_no_length) == 0

    info_dict_empty_files = {b"name": b"empty_files", b"files": []}
    assert calculate_total_size(info_dict_empty_files) == 0

    info_dict_files_no_length = {
        b"name": b"files_no_length",
        b"files": [{b"path": [b"file.txt"]}], # Missing length in file item
    }
    assert calculate_total_size(info_dict_files_no_length) == 0


def test_get_tracker_urls_announce_only():
    """Test getting tracker URL from 'announce' key only."""
    torrent_data = {b"announce": b"http://tracker.a.com/announce"}
    urls = get_tracker_urls(torrent_data)
    assert urls == ["http://tracker.a.com/announce"]


def test_get_tracker_urls_announce_list_only():
    """Test getting tracker URLs from 'announce-list' key only."""
    torrent_data = {
        b"announce-list": [
            [b"http://tracker.b.com/announce"],
            [b"https://tracker.c.com/announce", b"http://tracker.d.com/announce"],
        ]
    }
    urls = get_tracker_urls(torrent_data)
    assert urls == [
        "http://tracker.b.com/announce",
        "https://tracker.c.com/announce",
        "http://tracker.d.com/announce",
    ]


def test_get_tracker_urls_prefer_announce_list():
    """Test that 'announce-list' is preferred over 'announce'."""
    torrent_data = {
        b"announce": b"http://should.be.ignored.com/announce",
        b"announce-list": [[b"http://preferred.com/announce"]],
    }
    urls = get_tracker_urls(torrent_data)
    assert urls == ["http://preferred.com/announce"]


def test_get_tracker_urls_mixed_protocols(capsys):
    """Test filtering of non-HTTP/S URLs."""
    torrent_data = {
        b"announce-list": [
            [b"http://tracker.http.com/announce"],
            [b"udp://tracker.udp.com:80"],
            [b"https://tracker.https.com/announce"],
        ]
    }
    urls = get_tracker_urls(torrent_data)
    assert urls == [
        "http://tracker.http.com/announce",
        "https://tracker.https.com/announce",
    ]
    captured = capsys.readouterr()
    assert "Warning: Only non-HTTP/HTTPS tracker URLs found" not in captured.err # Should not warn if HTTP exists


def test_get_tracker_urls_only_udp(capsys):
    """Test behavior when only non-HTTP/S URLs are present."""
    torrent_data = {
        b"announce-list": [
            [b"udp://tracker.udp.com:80"],
            [b"udp://tracker.udp2.com:6969"],
        ]
    }
    urls = get_tracker_urls(torrent_data)
    assert urls == []
    captured = capsys.readouterr()
    assert "Warning: Only non-HTTP/HTTPS tracker URLs found" in captured.err


def test_get_tracker_urls_invalid_encoding(capsys):
    """Test handling of URLs that cannot be decoded."""
    invalid_bytes = b"http://tracker.invalid.\xff.com/announce"
    torrent_data = {b"announce": invalid_bytes}
    urls = get_tracker_urls(torrent_data)
    assert urls == []
    captured = capsys.readouterr()
    assert f"Warning: Could not decode tracker URL: {invalid_bytes}" in captured.err

    torrent_data_list = {b"announce-list": [[invalid_bytes]]}
    urls_list = get_tracker_urls(torrent_data_list)
    assert urls_list == []
    captured_list = capsys.readouterr()
    assert f"Warning: Could not decode tracker URL: {invalid_bytes}" in captured_list.err


def test_get_tracker_urls_no_trackers():
    """Test torrent data with no tracker keys."""
    torrent_data = {b"info": {b"name": b"no_trackers"}}
    urls = get_tracker_urls(torrent_data)
    assert urls == []


def test_get_tracker_urls_empty_announce_list():
    """Test torrent data with empty announce-list."""
    torrent_data = {b"announce-list": []}
    urls = get_tracker_urls(torrent_data)
    assert urls == []

    torrent_data_nested = {b"announce-list": [[]]}
    urls_nested = get_tracker_urls(torrent_data_nested)
    assert urls_nested == []


# --- Tests for query_tracker (using requests_mock) ---

MOCK_URL = "http://mocktracker.com/announce"
MOCK_INFO_HASH = b"\x12\x34\x56\x78\x90\xab\xcd\xef\x12\x34\x56\x78\x90\xab\xcd\xef\x12\x34"
MOCK_PEER_ID = b"-TS0001-abcdefghijkl"
MOCK_TOTAL_SIZE = 10240


@pytest.fixture
def mock_requests():
    with requests_mock.Mocker() as m:
        yield m


def test_query_tracker_success(mock_requests):
    """Test successful tracker query."""
    response_dict = {
        b"interval": 1800,
        b"complete": 10,
        b"incomplete": 5,
        b"peers": b"dummy_peer_data", # Compact response often binary
    }
    bencoded_response = bencodepy.encode(response_dict)
    mock_requests.get(MOCK_URL, content=bencoded_response, status_code=200)

    stats = query_tracker(MOCK_URL, MOCK_INFO_HASH, MOCK_PEER_ID, MOCK_TOTAL_SIZE)

    from urllib.parse import urlparse, parse_qs, unquote_to_bytes

    assert stats == response_dict
    # Check request parameters (requests_mock stores history)
    history = mock_requests.request_history
    assert len(history) == 1
    req = history[0]
    assert req.method == "GET"

    # Parse the URL and query parameters for robust checking
    parsed_url = urlparse(req.url)
    assert parsed_url.scheme == "http"
    # Extract netloc from MOCK_URL for comparison
    mock_netloc = urlparse(MOCK_URL).netloc
    assert parsed_url.netloc == mock_netloc
    # Extract path from MOCK_URL for comparison
    mock_path = urlparse(MOCK_URL).path
    assert parsed_url.path == mock_path

    # For byte parameters, manually extract from query and unquote
    query_string = parsed_url.query
    params_list = query_string.split('&')
    raw_params = {}
    for param in params_list:
        key, value = param.split('=', 1)
        raw_params[key] = value # Value is still percent-encoded

    assert "info_hash" in raw_params
    assert "peer_id" in raw_params
    assert unquote_to_bytes(raw_params["info_hash"]) == MOCK_INFO_HASH
    assert unquote_to_bytes(raw_params["peer_id"]) == MOCK_PEER_ID

    # For simple string/numeric parameters, parse_qs is fine
    query_params = parse_qs(query_string, keep_blank_values=True)
    assert query_params["port"][0] == str(DEFAULT_PORT)
    assert query_params["uploaded"][0] == "0"
    assert query_params["downloaded"][0] == "0"
    assert query_params["left"][0] == str(MOCK_TOTAL_SIZE)
    assert query_params["compact"][0] == "1"
    assert query_params["event"][0] == "started"


def test_query_tracker_failure_reason(mock_requests, capsys):
    """Test tracker response with 'failure reason'."""
    response_dict = {b"failure reason": b"Invalid info_hash"}
    bencoded_response = bencodepy.encode(response_dict)
    mock_requests.get(MOCK_URL, content=bencoded_response, status_code=200)

    stats = query_tracker(MOCK_URL, MOCK_INFO_HASH, MOCK_PEER_ID, MOCK_TOTAL_SIZE)

    assert stats is None
    captured = capsys.readouterr()
    assert f"Tracker error from {MOCK_URL}: Invalid info_hash" in captured.err


def test_query_tracker_http_error(mock_requests, capsys):
    """Test tracker returning HTTP error status."""
    mock_requests.get(MOCK_URL, status_code=404, reason="Not Found")

    stats = query_tracker(MOCK_URL, MOCK_INFO_HASH, MOCK_PEER_ID, MOCK_TOTAL_SIZE)

    assert stats is None
    captured = capsys.readouterr()
    assert f"Error: Request failed for tracker {MOCK_URL}: 404 Client Error: Not Found" in captured.err


def test_query_tracker_timeout(mock_requests, capsys):
    """Test tracker request timeout."""
    mock_requests.get(MOCK_URL, exc=requests.exceptions.Timeout)

    stats = query_tracker(MOCK_URL, MOCK_INFO_HASH, MOCK_PEER_ID, MOCK_TOTAL_SIZE)

    assert stats is None
    captured = capsys.readouterr()
    assert f"Error: Request timed out for tracker {MOCK_URL}" in captured.err


def test_query_tracker_connection_error(mock_requests, capsys):
    """Test tracker connection error."""
    mock_requests.get(MOCK_URL, exc=requests.exceptions.ConnectionError("DNS lookup failed"))

    stats = query_tracker(MOCK_URL, MOCK_INFO_HASH, MOCK_PEER_ID, MOCK_TOTAL_SIZE)

    assert stats is None
    captured = capsys.readouterr()
    assert f"Error: Request failed for tracker {MOCK_URL}: DNS lookup failed" in captured.err


def test_query_tracker_invalid_bencode_response(mock_requests, capsys):
    """Test tracker response with invalid bencode."""
    mock_requests.get(MOCK_URL, content=b"invalid{bencode", status_code=200)

    stats = query_tracker(MOCK_URL, MOCK_INFO_HASH, MOCK_PEER_ID, MOCK_TOTAL_SIZE)

    assert stats is None
    captured = capsys.readouterr()
    assert f"Error: Could not decode Bencoded response from {MOCK_URL}" in captured.err


def test_query_tracker_empty_response(mock_requests, capsys):
    """Test tracker response that is empty."""
    mock_requests.get(MOCK_URL, content=b"", status_code=200)

    stats = query_tracker(MOCK_URL, MOCK_INFO_HASH, MOCK_PEER_ID, MOCK_TOTAL_SIZE)

    assert stats is None
    captured = capsys.readouterr()
    assert f"Error: Empty response from tracker {MOCK_URL}" in captured.err


# --- Test display_stats ---

def test_display_stats_all_fields(capsys):
    """Test display_stats with all common fields present."""
    stats = {
        b"complete": 50,
        b"incomplete": 25,
        b"downloaded": 100,
        b"interval": 1800,
        b"min interval": 600,
    }
    tracker_url = "http://display.test/announce"
    display_stats(tracker_url, stats)
    captured = capsys.readouterr()

    assert f"--- Stats from: {tracker_url} ---" in captured.out
    assert "Seeders (complete): 50" in captured.out
    assert "Leechers (incomplete): 25" in captured.out
    assert "Completed Downloads (snatches): 100" in captured.out
    assert "Update Interval: 1800 seconds" in captured.out
    assert "Min Update Interval: 600 seconds" in captured.out


def test_display_stats_missing_optional_fields(capsys):
    """Test display_stats when optional fields are missing."""
    stats = {
        b"complete": 5,
        b"incomplete": 2,
        b"interval": 900,
        # Missing 'downloaded' and 'min interval'
    }
    tracker_url = "http://display.missing.test/announce"
    display_stats(tracker_url, stats)
    captured = capsys.readouterr()

    assert f"--- Stats from: {tracker_url} ---" in captured.out
    assert "Seeders (complete): 5" in captured.out
    assert "Leechers (incomplete): 2" in captured.out
    assert "Completed Downloads (snatches):" not in captured.out # Field should not be printed
    assert "Update Interval: 900 seconds" in captured.out
    assert "Min Update Interval:" not in captured.out # Field should not be printed


def test_display_stats_zero_values(capsys):
    """Test display_stats with zero values."""
    stats = {
        b"complete": 0,
        b"incomplete": 0,
        b"downloaded": 0,
        b"interval": 1800,
    }
    tracker_url = "http://display.zero.test/announce"
    display_stats(tracker_url, stats)
    captured = capsys.readouterr()

    assert "Seeders (complete): 0" in captured.out
    assert "Leechers (incomplete): 0" in captured.out
    assert "Completed Downloads (snatches): 0" in captured.out


# --- Test main() using patching ---

@patch("torrent_stats.argparse.ArgumentParser")
@patch("torrent_stats.parse_torrent_file")
@patch("torrent_stats.get_tracker_urls")
@patch("torrent_stats.query_tracker")
@patch("torrent_stats.display_stats")
@patch("torrent_stats.generate_peer_id")
@patch("torrent_stats.calculate_info_hash")
@patch("torrent_stats.calculate_total_size")
@patch("builtins.print")
@patch("sys.exit")
def test_main_success(
    mock_exit, mock_print, mock_calc_size, mock_calc_hash, mock_gen_peer,
    mock_display, mock_query, mock_get_urls, mock_parse, mock_argparse
):
    """Test the main function execution path for a successful case."""
    # --- Mock setup ---
    # Argument parsing
    mock_args = MagicMock()
    mock_args.torrent_file = "test.torrent"
    mock_argparse.return_value.parse_args.return_value = mock_args

    # parse_torrent_file
    mock_info_dict = {b"name": b"mock_torrent"}
    mock_torrent_data = {b"info": mock_info_dict, b"announce": b"http://tracker.mock/announce"}
    mock_parse.return_value = mock_torrent_data

    # calculate_info_hash, calculate_total_size, generate_peer_id
    mock_info_hash = b"mock_hash_1234567890"
    mock_total_size = 2048
    mock_peer_id = b"-TS0001-mockpeer1234"
    mock_calc_hash.return_value = mock_info_hash
    mock_calc_size.return_value = mock_total_size
    mock_gen_peer.return_value = mock_peer_id

    # get_tracker_urls
    mock_urls = ["http://tracker.mock/announce"]
    mock_get_urls.return_value = mock_urls

    # query_tracker
    mock_stats = {b"complete": 10, b"incomplete": 2}
    mock_query.return_value = mock_stats

    # --- Execute main ---
    main()

    # --- Assertions ---
    mock_argparse.assert_called_once()
    mock_parse.assert_called_once_with("test.torrent")
    mock_calc_hash.assert_called_once_with(mock_info_dict)
    mock_calc_size.assert_called_once_with(mock_info_dict)
    mock_gen_peer.assert_called_once()
    mock_get_urls.assert_called_once_with(mock_torrent_data)
    mock_query.assert_called_once_with(
        mock_urls[0], mock_info_hash, mock_peer_id, mock_total_size
    )
    mock_display.assert_called_once_with(mock_urls[0], mock_stats)
    mock_print.assert_any_call(f"Processing torrent file: {mock_args.torrent_file}")
    mock_print.assert_any_call(f"Info Hash: {mock_info_hash.hex()}")
    mock_print.assert_any_call(f"Peer ID: {mock_peer_id.decode('ascii')}")
    mock_print.assert_any_call(f"Total Size: {mock_total_size} bytes")
    mock_print.assert_any_call(f"Querying {mock_urls[0]}...")
    mock_print.assert_any_call("\nFinished.")
    mock_exit.assert_not_called() # Should not exit with error


@patch("torrent_stats.argparse.ArgumentParser")
@patch("torrent_stats.parse_torrent_file")
@patch("builtins.print")
# No longer need to patch sys.exit directly when using pytest.raises
def test_main_parse_fail(mock_print, mock_parse, mock_argparse):
    """Test main when parse_torrent_file fails."""
    mock_args = MagicMock()
    mock_args.torrent_file = "bad.torrent"
    mock_argparse.return_value.parse_args.return_value = mock_args
    mock_parse.return_value = None # Simulate failure

    # Expect SystemExit with code 1
    with pytest.raises(SystemExit) as excinfo:
        main()

    assert excinfo.value.code == 1
    mock_parse.assert_called_once_with("bad.torrent")
    # mock_print assertions could be added if needed, but exit code is primary check


@patch("torrent_stats.argparse.ArgumentParser")
@patch("torrent_stats.parse_torrent_file")
@patch("builtins.print")
# No longer need to patch sys.exit directly when using pytest.raises
def test_main_missing_info(mock_print, mock_parse, mock_argparse):
    """Test main when torrent data is missing the 'info' dictionary."""
    mock_args = MagicMock()
    mock_args.torrent_file = "no_info.torrent"
    mock_argparse.return_value.parse_args.return_value = mock_args
    mock_torrent_data = {b"announce": b"http://tracker.mock/announce"} # No 'info'
    mock_parse.return_value = mock_torrent_data

    # Expect SystemExit with code 1
    with pytest.raises(SystemExit) as excinfo:
        main()

    assert excinfo.value.code == 1
    mock_parse.assert_called_once_with("no_info.torrent")
    mock_print.assert_any_call(
        "Error: Invalid torrent file - missing 'info' dictionary.", file=sys.stderr
    )


@patch("torrent_stats.argparse.ArgumentParser")
@patch("torrent_stats.parse_torrent_file")
@patch("torrent_stats.get_tracker_urls")
@patch("torrent_stats.calculate_info_hash")
@patch("torrent_stats.calculate_total_size")
@patch("torrent_stats.generate_peer_id")
@patch("builtins.print")
@patch("sys.exit")
def test_main_no_trackers(
    mock_exit, mock_print, mock_gen_peer, mock_calc_size, mock_calc_hash,
    mock_get_urls, mock_parse, mock_argparse
):
    """Test main when no suitable tracker URLs are found."""
    mock_args = MagicMock()
    mock_args.torrent_file = "no_trackers.torrent"
    mock_argparse.return_value.parse_args.return_value = mock_args
    mock_info_dict = {b"name": b"mock_torrent"}
    mock_torrent_data = {b"info": mock_info_dict} # No announce/announce-list
    mock_parse.return_value = mock_torrent_data
    mock_calc_hash.return_value = b"mock_hash"
    mock_calc_size.return_value = 100
    mock_gen_peer.return_value = b"mock_peer"
    mock_get_urls.return_value = [] # Simulate no URLs found

    main()

    mock_get_urls.assert_called_once_with(mock_torrent_data)
    mock_print.assert_any_call(
        "Error: No suitable HTTP/HTTPS tracker URLs found in the torrent file.",
        file=sys.stderr,
    )
    mock_exit.assert_called_once_with(1)


@patch("torrent_stats.argparse.ArgumentParser")
@patch("torrent_stats.parse_torrent_file")
@patch("torrent_stats.get_tracker_urls")
@patch("torrent_stats.query_tracker")
@patch("torrent_stats.display_stats")
@patch("torrent_stats.generate_peer_id")
@patch("torrent_stats.calculate_info_hash")
@patch("torrent_stats.calculate_total_size")
@patch("builtins.print")
@patch("sys.exit")
def test_main_all_trackers_fail(
    mock_exit, mock_print, mock_calc_size, mock_calc_hash, mock_gen_peer,
    mock_display, mock_query, mock_get_urls, mock_parse, mock_argparse
):
    """Test main when all tracker queries fail."""
    mock_args = MagicMock()
    mock_args.torrent_file = "fail.torrent"
    mock_argparse.return_value.parse_args.return_value = mock_args
    mock_info_dict = {b"name": b"mock_torrent"}
    mock_torrent_data = {b"info": mock_info_dict, b"announce": b"http://tracker.fail/announce"}
    mock_parse.return_value = mock_torrent_data
    mock_info_hash = b"mock_hash_fail"
    mock_total_size = 512
    mock_peer_id = b"-TS0001-mockpeerfail"
    mock_calc_hash.return_value = mock_info_hash
    mock_calc_size.return_value = mock_total_size
    mock_gen_peer.return_value = mock_peer_id
    mock_urls = ["http://tracker.fail/announce", "https://tracker2.fail/announce"]
    mock_get_urls.return_value = mock_urls
    mock_query.return_value = None # Simulate query failure for all trackers

    main()

    assert mock_query.call_count == len(mock_urls)
    mock_query.assert_any_call(mock_urls[0], mock_info_hash, mock_peer_id, mock_total_size)
    mock_query.assert_any_call(mock_urls[1], mock_info_hash, mock_peer_id, mock_total_size)
    mock_display.assert_not_called()
    mock_print.assert_any_call(f"  Failed to get stats from {mock_urls[0]}")
    mock_print.assert_any_call(f"  Failed to get stats from {mock_urls[1]}")
    mock_print.assert_any_call("\nNo stats could be retrieved from any tracker.")
    mock_exit.assert_called_once_with(1)
