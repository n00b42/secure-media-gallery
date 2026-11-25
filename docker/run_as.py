"""Run a command as PUID:PGID (default 1000:1000) when started as root.

Unraid and similar systems mount host folders owned by a specific user (Unraid:
99:100). The entrypoint starts as root only to fix the data folder's ownership,
then every process runs through this helper without root rights.
"""

import os
import sys


def main():
    if len(sys.argv) < 2:
        sys.exit('usage: run_as.py COMMAND [ARGS...]')
    if os.getuid() == 0:
        uid = int(os.environ.get('PUID', '1000'))
        gid = int(os.environ.get('PGID', '1000'))
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        os.environ['HOME'] = os.environ.get('DATA_DIR', '/data')
    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == '__main__':
    main()
