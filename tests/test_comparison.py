"""Offline checks for the Cowrie comparison harness.

Same contract as the rest of the suite: these run without Docker, without
Ollama and without a network, and they cover the parts that must be correct
whatever the models do. What is tested here is the *scoring*, because that is
where a silent mistake would turn into a wrong number in section 4.4 -- a
miss-detector that is too eager would hand the generative framework a win it
did not earn, and a coherence check blind to the clock would fail a real host
for telling the truth about the time.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.pardir, "benchmarks"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.pardir, "evaluation"))

from cowrie_comparison import BATTERY, is_miss, mask  # noqa: E402


class TestMissDetection:
    """A command is "not answered" only on unmistakable evidence."""

    @pytest.mark.parametrize("body", [
        "bash: lscpu: command not found",
        "cat: /root/.my.cnf: No such file or directory",
        "-bash: crontab: command not found",
        "",
        "   \n  ",
    ])
    def test_non_answers_are_misses(self, body):
        assert is_miss(body) is True

    @pytest.mark.parametrize("body", [
        "root",
        "uid=0(root) gid=0(root) groups=0(root)",
        "Linux srv-web-prod-02 5.15.0-91-generic x86_64 GNU/Linux",
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    ])
    def test_real_output_is_not_a_miss(self, body):
        assert is_miss(body) is False

    def test_a_populated_listing_is_not_a_miss(self):
        # `ls -la /root/.ssh` on a decoy that planted a key: the word "found"
        # must not appear anywhere for this to pass, so the detector cannot be
        # matching too loosely.
        body = ("total 12\ndrwx------ 2 root root 4096 Jan  9 11:02 .\n"
                "-rw------- 1 root root 1679 Jan  9 11:02 id_rsa")
        assert is_miss(body) is False


class TestCoherenceMasking:
    """Volatile fields must not count as incoherence."""

    def test_clock_differences_are_masked(self):
        a = "11:02:41 up 3 days,  4:12,  1 user,  load average: 0.11, 0.09, 0.08"
        b = "11:02:43 up 3 days,  4:12,  1 user,  load average: 0.14, 0.09, 0.08"
        assert mask(a) == mask(b)

    def test_genuine_differences_survive_masking(self):
        # Two reads of /etc/passwd that disagree is exactly the failure the
        # coherence axis exists to catch; masking must not hide it.
        a = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:/var/www:/usr/sbin/nologin"
        b = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:/var/www:/bin/sh"
        assert mask(a) != mask(b)

    def test_masking_is_idempotent(self):
        s = "09:15:00 up 2 days,  1:00,  load average: 0.00, 0.01, 0.05"
        assert mask(mask(s)) == mask(s)


class TestBattery:
    """The stimulus itself has to stay comparable across chapters."""

    def test_battery_is_the_documented_size(self):
        assert len(BATTERY) == 30

    def test_no_duplicate_commands(self):
        commands = [c for c, _ in BATTERY]
        assert len(commands) == len(set(commands))

    def test_every_command_carries_an_attack_technique(self):
        for command, technique in BATTERY:
            assert technique.startswith("T"), command
            assert command.strip() == command


class TestDivergence:
    """Coverage is read against the real host, never on its own."""

    @staticmethod
    def _divergence(arm_cov: dict, ref_cov: dict) -> list:
        return [c for c, v in arm_cov.items()
                if c in ref_cov and v != ref_cov[c]]

    def test_answering_more_than_the_real_host_counts_as_divergence(self):
        # A decoy that produces a .my.cnf where a real Debian has none is not
        # scoring a point: it is diverging from the reference.
        ref = {"whoami": True, "cat /root/.my.cnf": False}
        arm = {"whoami": True, "cat /root/.my.cnf": True}
        assert self._divergence(arm, ref) == ["cat /root/.my.cnf"]

    def test_matching_the_real_host_is_zero_divergence(self):
        ref = {"whoami": True, "which nmap": False}
        assert self._divergence(dict(ref), ref) == []

    def test_answering_less_also_diverges(self):
        ref = {"cat /etc/passwd": True}
        arm = {"cat /etc/passwd": False}
        assert self._divergence(arm, ref) == ["cat /etc/passwd"]
