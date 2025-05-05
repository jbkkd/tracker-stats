#!/usr/bin/env python3

import argparse
import hashlib
import random
import string
import bencodepy
import requests
import sys
from typing import List, Dict, Any, Optional

# Constants
CLIENT_NAME = "TS"  # Torrent Stats
CLIENT_VERSION = "0001"
PEER_ID_PREFIX = f"-{CLIENT_NAME}{CLIENT_VERSION}-"

# Ensure the prefix is not too long
assert len(PEER_ID_PREFIX) <= 8

DEFAULT_PORT = 6881
REQUEST_TIMEOUT = 10  # seconds


def generate_peer_id() -> bytes:
    """Generates a 20-byte peer ID."""
    random_part = "".join(
        random.choices(string.ascii_letters + string.digits, k=20 - len(PEER_ID_PREFIX))
    )
    peer_id = PEER_ID_PREFIX + random_part
    return peer_id.encode("ascii")


def parse_torrent_file(file_path: str) -> Optional[Dict[str, Any]]:
    """Reads and decodes a .torrent file."""
    try:
        with open(file_path, "rb") as f:
            content = f.read()
            if not content: # Handle empty file explicitly
                print(f"Error: Torrent file is empty: {file_path}", file=sys.stderr)
                return None
            torrent_data = bencodepy.decode(content)
            return torrent_data
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}", file=sys.stderr)
        return None
    except ValueError as e: # Catch ValueError for bencode decoding errors
        print(
            f"Error: Could not decode Bencoded data in {file_path}: {e}",
            file=sys.stderr,
        )
        return None
    except Exception as e:
        print(f"Error reading torrent file {file_path}: {e}", file=sys.stderr)
        return None


def calculate_info_hash(info_dict: Dict[str, Any]) -> bytes:
    """Calculates the SHA-1 hash of the bencoded info dictionary."""
    bencoded_info = bencodepy.encode(info_dict)
    return hashlib.sha1(bencoded_info).digest()


def calculate_total_size(info_dict: Dict[str, Any]) -> int:
    """Calculates the total size of files in the torrent."""
    total_size = 0
    # Use bytes keys b"files" and b"length"
    if b"files" in info_dict:  # Multi-file torrent
        for file_info in info_dict[b"files"]:
            total_size += file_info.get(b"length", 0)
    elif b"length" in info_dict:  # Single-file torrent
        total_size = info_dict.get(b"length", 0)
    return total_size


def get_tracker_urls(torrent_data: Dict[str, Any]) -> List[str]:
    """Extracts tracker URLs from torrent data, preferring announce-list."""
    urls = []
    if b"announce-list" in torrent_data:
        # Flatten the list of lists (tiers)
        for tier in torrent_data[b"announce-list"]:
            for url_bytes in tier:
                try:
                    urls.append(url_bytes.decode("utf-8"))
                except UnicodeDecodeError:
                    print(
                        f"Warning: Could not decode tracker URL: {url_bytes}",
                        file=sys.stderr,
                    )
    elif b"announce" in torrent_data:
        try:
            urls.append(torrent_data[b"announce"].decode("utf-8"))
        except UnicodeDecodeError:
            print(
                f"Warning: Could not decode tracker URL: {torrent_data[b'announce']}",
                file=sys.stderr,
            )

    # Filter out non-HTTP/HTTPS URLs for now
    http_urls = [
        url for url in urls if url.startswith("http://") or url.startswith("https://")
    ]
    if not http_urls and urls:
        print(
            "Warning: Only non-HTTP/HTTPS tracker URLs found. UDP is not supported yet.",
            file=sys.stderr,
        )

    return http_urls


def query_tracker(
    tracker_url: str, info_hash: bytes, peer_id: bytes, total_size: int
) -> Optional[Dict[str, Any]]:
    """Sends an announce request to an HTTP/HTTPS tracker and returns the parsed response."""
    params = {
        "info_hash": info_hash,
        "peer_id": peer_id,
        "port": DEFAULT_PORT,
        "uploaded": 0,
        "downloaded": 0,
        "left": total_size,
        "compact": 1,
        "event": "started",  # Indicate we are starting
    }

    try:
        # Some trackers require specific bytes objects in params, others work with urlencode
        # requests handles bytes in params correctly for query strings
        response = requests.get(tracker_url, params=params, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        if not response.content:
            print(f"Error: Empty response from tracker {tracker_url}", file=sys.stderr)
            return None

        # Decode the Bencoded response
        try:
            tracker_response = bencodepy.decode(response.content)
            if b"failure reason" in tracker_response:
                failure = tracker_response[b"failure reason"].decode(
                    "utf-8", errors="ignore"
                )
                print(f"Tracker error from {tracker_url}: {failure}", file=sys.stderr)
                return None
            return tracker_response
        except ValueError as e: # Catch ValueError for bencode decoding errors
            print(
                f"Error: Could not decode Bencoded response from {tracker_url}: {e}",
                file=sys.stderr,
            )
            # Optionally print raw response for debugging:
            # print(f"Raw response: {response.content[:200]}...", file=sys.stderr)
            return None
        except Exception as e:
            print(
                f"Error processing tracker response from {tracker_url}: {e}",
                file=sys.stderr,
            )
            return None

    except requests.exceptions.Timeout:
        print(f"Error: Request timed out for tracker {tracker_url}", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error: Request failed for tracker {tracker_url}: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(
            f"An unexpected error occurred while querying {tracker_url}: {e}",
            file=sys.stderr,
        )
        return None


def display_stats(tracker_url: str, stats: Dict[str, Any]):
    """Prints the tracker statistics."""
    print(f"\n--- Stats from: {tracker_url} ---")
    seeders = stats.get(b"complete", "N/A")
    leechers = stats.get(b"incomplete", "N/A")
    downloads = stats.get(b"downloaded", "N/A")  # Optional, not always present
    interval = stats.get(b"interval", "N/A")  # Advised polling interval
    min_interval = stats.get(b"min interval", "N/A")

    print(f"  Seeders (complete): {seeders}")
    print(f"  Leechers (incomplete): {leechers}")
    if downloads != "N/A":
        print(f"  Completed Downloads (snatches): {downloads}")
    if interval != "N/A":
        print(f"  Update Interval: {interval} seconds")
    if min_interval != "N/A":
        print(f"  Min Update Interval: {min_interval} seconds")

    # You could add more fields here if desired, e.g., 'peers' if not compact=1


def main():
    parser = argparse.ArgumentParser(
        description="Get tracker stats from a .torrent file."
    )
    parser.add_argument("torrent_file", help="Path to the .torrent file")
    args = parser.parse_args()

    print(f"Processing torrent file: {args.torrent_file}")

    torrent_data = parse_torrent_file(args.torrent_file)
    if not torrent_data:
        sys.exit(1)

    if b"info" not in torrent_data:
        print(
            "Error: Invalid torrent file - missing 'info' dictionary.", file=sys.stderr
        )
        sys.exit(1)

    info_dict = torrent_data[b"info"]
    info_hash = calculate_info_hash(info_dict)
    total_size = calculate_total_size(info_dict)
    peer_id = generate_peer_id()

    print(f"Info Hash: {info_hash.hex()}")
    print(f"Peer ID: {peer_id.decode('ascii')}")
    print(f"Total Size: {total_size} bytes")

    tracker_urls = get_tracker_urls(torrent_data)
    if not tracker_urls:
        print(
            "Error: No suitable HTTP/HTTPS tracker URLs found in the torrent file.",
            file=sys.stderr,
        )
        sys.exit(1) # Exit if no suitable trackers
    else:
        # Only proceed if tracker URLs were found
        print(f"\nFound {len(tracker_urls)} HTTP/S tracker(s). Querying...")

        results_found = False
        for url in tracker_urls:
            print(f"Querying {url}...")
            stats = query_tracker(url, info_hash, peer_id, total_size)
            if stats:
                display_stats(url, stats)
                results_found = True
            else:
                print(f"  Failed to get stats from {url}")

        # Check if any tracker succeeded *only* if we attempted to query them
        if not results_found:
            print("\nNo stats could be retrieved from any tracker.")
            sys.exit(1) # Exit if all queried trackers failed
        else:
            print("\nFinished.") # Only print Finished if at least one tracker succeeded


if __name__ == "__main__":
    main()
