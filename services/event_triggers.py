"""
Crypto Guardian — Event Triggers
Maps external events (webhooks, blockchain events) to perception loop wake-ups.
Bridges the existing monitor alerts into the autonomous reasoning brain.
"""

import time
from typing import Optional


class EventTrigger:
    """A single event that should trigger agent reasoning."""

    def __init__(self, event_type: str, source: str, data: dict, priority: int = 5):
        self.event_type = event_type
        self.source = source
        self.data = data
        self.priority = priority
        self.timestamp = time.time()

    def to_dict(self) -> dict:
        return {
            "type": self.event_type,
            "source": self.source,
            "data": self.data,
            "priority": self.priority,
            "timestamp": self.timestamp,
        }


class TriggerEngine:
    """
    Routes external events into the perception loop.
    Supports: Alchemy webhooks, monitor alerts, custom webhooks.
    """

    def __init__(self, perception_loop=None):
        self._perception = perception_loop
        self._event_count = 0
        self._event_log = []

    def set_perception_loop(self, loop):
        """Set the perception loop reference."""
        self._perception = loop

    def process_alchemy_webhook(self, payload: dict) -> dict:
        """Process an incoming Alchemy webhook notification."""
        self._event_count += 1
        webhook_type = payload.get("type", "unknown")
        event_data = payload.get("event", {})

        # Map Alchemy webhook types to our event types
        event_type_map = {
            "MINED_TRANSACTION": "NEW_TX",
            "ADDRESS_ACTIVITY": "WALLET_ACTIVITY",
            "TOKEN_TRANSFER": "TOKEN_TRANSFER",
            "NFT_ACTIVITY": "NFT_ACTIVITY",
            "GRAPHQL": "CUSTOM_QUERY",
        }

        our_type = event_type_map.get(webhook_type, "WEBHOOK_RECEIVED")

        # Extract wallet addresses from the event
        addresses = []
        if "activity" in event_data:
            for act in event_data.get("activity", []):
                if act.get("fromAddress"):
                    addresses.append(act["fromAddress"])
                if act.get("toAddress"):
                    addresses.append(act["toAddress"])

        trigger = EventTrigger(
            event_type=our_type,
            source="alchemy_webhook",
            data={
                "webhookType": webhook_type,
                "addresses": addresses[:5],
                "rawEvent": {k: v for k, v in event_data.items()
                             if k in ("network", "activity", "hash", "blockNum")},
            },
            priority=8 if our_type in ("NEW_TX", "WALLET_ACTIVITY") else 5,
        )

        self._event_log.append(trigger.to_dict())
        if len(self._event_log) > 100:
            self._event_log = self._event_log[-50:]

        # Push to perception loop
        if self._perception:
            self._perception.trigger_event(trigger.event_type, trigger.data)

        return {
            "status": "accepted",
            "eventType": our_type,
            "triggeredPerception": self._perception is not None,
            "eventId": self._event_count,
        }

    def process_custom_webhook(self, payload: dict) -> dict:
        """Process a generic custom webhook."""
        self._event_count += 1

        event_type = payload.get("event_type", "CUSTOM_EVENT")
        address = payload.get("address", "")
        detail = payload.get("detail", "")

        trigger = EventTrigger(
            event_type=event_type,
            source="custom_webhook",
            data={"address": address, "detail": detail, "raw": payload},
            priority=payload.get("priority", 5),
        )

        self._event_log.append(trigger.to_dict())

        if self._perception:
            self._perception.trigger_event(trigger.event_type, trigger.data)

        return {
            "status": "accepted",
            "eventType": event_type,
            "triggeredPerception": self._perception is not None,
            "eventId": self._event_count,
        }

    def process_monitor_alert(self, alert_data: dict):
        """Bridge: convert a WalletMonitor alert into a perception trigger."""
        alert_type = alert_data.get("alertType", "UNKNOWN")
        priority_map = {
            "LARGE_OUTFLOW": 9,
            "UNLIMITED_APPROVAL": 10,
            "FLAGGED_CONTRACT": 8,
            "NEW_APPROVAL": 5,
            "NEW_ADDRESS_INTERACTION": 4,
        }

        if self._perception:
            self._perception.trigger_event(
                event_type="MONITOR_ALERT_%s" % alert_type,
                data=alert_data,
            )

    def get_stats(self) -> dict:
        return {
            "totalEvents": self._event_count,
            "recentEvents": self._event_log[-10:],
            "perceptionConnected": self._perception is not None,
        }
