"""WebSocket client for connecting to certstream server."""

import asyncio
import traceback
import websockets
import websockets.exceptions

from .config import (
    CERTSTREAM_WS_URL,
    WS_PING_INTERVAL,
    WS_PING_TIMEOUT,
    INITIAL_RECONNECT_DELAY,
    MAX_RECONNECT_DELAY,
)
from .state import state
from .processor import process_message


async def run_websocket_client() -> None:
    """Run the WebSocket client with auto-reconnect."""
    print("[*] Starting CertStream watcher...")
    try:
        while True:
            try:
                print(f"[*] Connecting to {CERTSTREAM_WS_URL} ...")
                async with websockets.connect(
                    CERTSTREAM_WS_URL,
                    ping_interval=WS_PING_INTERVAL,
                    ping_timeout=WS_PING_TIMEOUT,
                ) as ws:
                    state.reconnect_delay = INITIAL_RECONNECT_DELAY
                    print("[*] WebSocket connection established")
                    async for message in ws:
                        msg = message if isinstance(message, str) else bytes(message).decode("utf-8")
                        asyncio.create_task(asyncio.to_thread(process_message, msg))
            except websockets.exceptions.ConnectionClosed as e:
                print(f"[!] WebSocket closed: {e}")
            except Exception as e:
                print(f"[!] Unexpected error in main loop: {e}")
                traceback.print_exc()

            print(f"[*] Reconnecting in {state.reconnect_delay} seconds...")
            await asyncio.sleep(state.reconnect_delay)
            state.reconnect_delay = min(state.reconnect_delay * 2, MAX_RECONNECT_DELAY)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[*] Shutting down gracefully...")
