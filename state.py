from collections import deque, defaultdict
import logging

logger = logging.getLogger("X4G")

connections: dict = {}

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
}

error_logs = deque(maxlen=50)

hourly_traffic: dict = defaultdict(int)
