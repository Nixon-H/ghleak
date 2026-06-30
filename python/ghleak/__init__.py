"""ghleak — GitHub/GitLab secret leak scanner.

Watches the GitHub Archive firehose for commit messages that suggest
a leaked credential, fetches the diff, and runs TruffleHog with
verification enabled.
"""

from . import config, fetcher, classifier, scanner, reporter

__version__ = "1.1.0"
