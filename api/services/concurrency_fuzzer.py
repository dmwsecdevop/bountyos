"""High-concurrency fuzzer for race condition detection."""

import asyncio
from typing import List, Any
from api.integrations.resilient_http import request_json_async, ConnectorResponse

class ConcurrencyFuzzer:
    """Orchestrates high-concurrency requests to detect race conditions."""

    async def run_burst(
        self,
        url: str,
        method: str = "POST",
        json_body: Any = None,
        burst_size: int = 20
    ) -> List[ConnectorResponse]:
        """Sends a burst of requests concurrently."""
        print(f"[*] Starting concurrency burst of {burst_size} requests to {url}")
        
        tasks = [
            request_json_async(
                provider="concurrency_fuzzer",
                url=url,
                method=method,
                json_body=json_body
            )
            for _ in range(burst_size)
        ]
        
        # Execute in a concentrated burst
        results = await asyncio.gather(*tasks)
        
        # Simple analysis: count status code distribution
        status_counts = {}
        for res in results:
            code = res.status_code or "error"
            status_counts[code] = status_counts.get(code, 0) + 1
            
        print(f"[+] Burst completed. Status counts: {status_counts}")
        return results

concurrency_fuzzer = ConcurrencyFuzzer()
