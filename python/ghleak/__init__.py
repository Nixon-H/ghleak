"""ghleak — GitHub/GitLab secret leak scanner.

Watches the GitHub Archive firehose for commit messages that suggest
a leaked credential, fetches the diff, and runs TruffleHog with
verification enabled. A built-in pattern scanner (ghp_, AKIA, sk-ant-,
xoxb-, …) works with or without TruffleHog.
"""

from . import config, fetcher, classifier, patterns, scanner, reporter

__version__ = "1.3.0"
