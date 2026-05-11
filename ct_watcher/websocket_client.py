"""WebSocket client for connecting to certstream server."""

import sys
import time
import traceback
import websocket

from .config import (
    CERTSTREAM_WS_URL,
    WS_PING_INTERVAL,
    WS_PING_TIMEOUT,
    INITIAL_RECONNECT_DELAY,
    MAX_RECONNECT_DELAY,
)
from .state import state
from .processor import process_message


def on_message(ws, message: str) -> None:
    """Handle incoming WebSocket messages."""
    try:
        process_message(message)
    except Exception as e:
        print(f"[!] Unhandled error in on_message: {e}")
        traceback.print_exc()


def on_error(ws, error) -> None:
    """Handle WebSocket errors."""
    print(f"[!] WebSocket error: {error}")


def on_close(ws, close_status_code, close_msg) -> None:
    """Handle WebSocket close."""
    print(f"[!] WebSocket closed: {close_status_code} - {close_msg}")


def on_open(ws) -> None:
    """Handle WebSocket open."""
    state.reconnect_delay = INITIAL_RECONNECT_DELAY
    print("[*] WebSocket connection established")


def run_websocket_client() -> None:
    """Run the WebSocket client with auto-reconnect."""
    print("[*] Starting CertStream watcher...")
    
    while True:
        try:
            print(f"[*] Connecting to {CERTSTREAM_WS_URL} ...")
            
            ws = websocket.WebSocketApp(
                CERTSTREAM_WS_URL,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close,
                on_open=on_open
            )
            
            ws.run_forever(ping_interval=WS_PING_INTERVAL, ping_timeout=WS_PING_TIMEOUT)
            
            # Connection closed, reconnect
            print(f"[*] Connection closed, reconnecting in {state.reconnect_delay} seconds...")
            time.sleep(state.reconnect_delay)
            
            # Exponential backoff
            state.reconnect_delay = min(state.reconnect_delay * 2, MAX_RECONNECT_DELAY)
            
        except KeyboardInterrupt:
            print("\n[*] Shutting down gracefully...")
            sys.exit(0)
        except Exception as e:
            print(f"[!] Unexpected error in main loop: {e}")
            traceback.print_exc()
            print(f"[*] Reconnecting in {state.reconnect_delay} seconds...")
            time.sleep(state.reconnect_delay)
            state.reconnect_delay = min(state.reconnect_delay * 2, MAX_RECONNECT_DELAY)
