from elasticsearch import Elasticsearch
import os
import time

class ElasticClient:
    def __init__(self):
        # reads config from env so host/index can change without touching code
        self.enabled = os.getenv("ELASTIC_ENABLED", "false").lower() == "true"
        self.index_name = os.getenv("ELASTIC_INDEX", "guardian-alerts")
        self.client = None

        if self.enabled:
            self.client = Elasticsearch(
                os.getenv("ELASTIC_HOST"),
                api_key=os.getenv("ELASTIC_API_KEY"),
            )

    def index_alert(self, rule_name, alert_data):
        # skips silently if disabled, so local-only mode needs zero code changes
        if not self.enabled:
            return

        document = {
            "timestamp": time.time(),
            "rule": rule_name,
            "process_name": alert_data.get("process_name"),
            "pid": alert_data.get("pid"),
            "details": alert_data,
        }

        try:
            self.client.index(index=self.index_name, document=document)
        except Exception as error:
            # never let a broken elastic connection take down alerting
            print(f"Elastic indexing failed: {error}")