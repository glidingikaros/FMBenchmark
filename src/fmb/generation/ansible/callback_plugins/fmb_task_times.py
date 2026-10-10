"""Print how long the slowest tasks of the generation playbook took, as one FMB_TASK_TIMES line at the end."""
from __future__ import annotations

import json
import time

from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "fmb_task_times"
    CALLBACK_NEEDS_ENABLED = False

    def __init__(self):
        super().__init__()
        self.started = time.monotonic()
        self.current = None
        self.totals = {}

    def _close(self):
        if self.current is not None:
            name, began = self.current
            seconds, count = self.totals.get(name, (0.0, 0))
            self.totals[name] = (seconds + time.monotonic() - began, count + 1)
            self.current = None

    def v2_playbook_on_task_start(self, task, is_conditional):
        self._close()
        self.current = (task.get_name(), time.monotonic())

    def v2_playbook_on_handler_task_start(self, task):
        self.v2_playbook_on_task_start(task, False)

    def v2_playbook_on_stats(self, stats):
        self._close()
        slowest = sorted(self.totals.items(), key=lambda row: -row[1][0])[:30]
        self._display.display("FMB_TASK_TIMES " + json.dumps({
            "total_seconds": round(time.monotonic() - self.started, 1),
            "slowest": [{"task": name, "seconds": round(seconds, 1), "runs": count}
                        for name, (seconds, count) in slowest]}, sort_keys=True))
