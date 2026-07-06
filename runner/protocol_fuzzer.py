"""Custom Protocol Fuzzer using asyncio.Protocol."""

import asyncio
import random

class ProtocolFuzzer(asyncio.Protocol):
    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.transport = None
        self.fuzz_data = [b"GET / HTTP/1.1\r\n\r\n", b"\x00\x01\x02", b"USER admin\r\n"]

    def connection_made(self, transport):
        self.transport = transport
        print(f"[*] Connected to {self.target_host}:{self.target_port}")
        # Send initial mutation
        payload = random.choice(self.fuzz_data)
        self.transport.write(payload)

    def data_received(self, data):
        print(f"[*] Received: {data}")
        # Send next mutation
        payload = random.choice(self.fuzz_data)
        self.transport.write(payload)
        
    def connection_lost(self, exc):
        print("[*] Connection closed")

async def start_fuzzing(host: str, port: int):
    loop = asyncio.get_running_loop()
    await loop.create_connection(lambda: ProtocolFuzzer(host, port), host, port)
