"""
Perl-script infrastructure for bulk MAR (MAC Address Repository) operations.

Provides ``bulk_import_mar_csv`` and ``bulk_remove_mar_csv`` which upload a
Perl helper script to the Enterprise Manager, execute it against a CSV file,
and return the number of entries processed.

Separated from ``ca_common_base.py`` so the base class only contains actual
CA behaviours (SSH, policy, host-info, MAR CRUD) while this module owns the
Perl-script deployment / execution infrastructure.
"""

import os
import re
from pathlib import Path

from framework.connection.connection_pool import CONNECTION_POOL
from framework.log.logger import log

_MAR_BULK_IMPORT_SCRIPT = "mar_bulk_import.pl"
_MAR_BULK_REMOVE_SCRIPT = "mar_bulk_remove.pl"

_REMOTE_BULK_IMPORT_SCRIPT = "/tmp/fs_mar_bulk_import.pl"
_REMOTE_BULK_REMOVE_SCRIPT = "/tmp/fs_mar_bulk_remove.pl"


def _read_script(filename: str) -> str:
    """Read a Perl script from the ``scripts/`` directory in the project root."""
    for d in Path(__file__).resolve().parents:
        candidate = d / "scripts" / filename
        if candidate.exists():
            return candidate.read_text()
    raise FileNotFoundError(f"Script not found: {filename}")


def _run_perl_bulk_script(ca, script_body: str, remote_script: str,
                          csv_path: str, timeout: int) -> int:
    """
    Upload a CSV to the EM, deploy a Perl script, execute it, and return
    the ``ok`` count from the ``done ok=N ...`` output line.

    Args:
        ca:             CounterActBase instance (provides exec_command, connection pool access, etc.).
        script_body:    Content of the Perl script to deploy.
        remote_script:  Remote path where the script will be written.
        csv_path:       Local path to the CSV file to upload.
        timeout:        SSH command timeout in seconds.

    Returns:
        Number of entries successfully processed (parsed from ``ok=N`` in output).
    """
    if not os.path.isfile(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    ca._ensure_mar_category_enabled()

    remote_csv = "/tmp/fs_mar_bulk_data.csv"
    try:
        ca.client = CONNECTION_POOL.get(ca.get_conn_key(), ca._create_connection)
        with ca.client.open_sftp() as sftp:
            sftp.put(csv_path, remote_csv)
            with sftp.open(remote_script, "w") as fh:
                fh.write(script_body)

        cmd = (
            f"cd /usr/local/forescout && "
            f"perl -X -I lib/perl/inc {remote_script} {remote_csv} 2>&1"
        )
        log.info(f"Running bulk MAR script {remote_script} (timeout={timeout}s)")
        output = ca.exec_command(cmd, timeout=timeout)
        log.info(f"Bulk MAR result: {output}")

        m = re.search(r"ok=(\d+)", output)
        return int(m.group(1)) if m else 0
    finally:
        for f in (remote_csv, remote_script):
            try:
                ca.exec_command(f"rm -f {f}", timeout=10)
            except Exception:
                pass


def bulk_import_mar_csv(ca, csv_path: str, timeout: int = 300) -> int:
    """Bulk-import MAR entries from a CSV via a Perl script on the EM."""
    return _run_perl_bulk_script(
        ca, _read_script(_MAR_BULK_IMPORT_SCRIPT),
        _REMOTE_BULK_IMPORT_SCRIPT, csv_path, timeout,
    )


def bulk_remove_mar_csv(ca, csv_path: str, timeout: int = 500) -> int:
    """Bulk-remove MAR entries whose MACs appear in a CSV via a Perl script on the EM."""
    return _run_perl_bulk_script(
        ca, _read_script(_MAR_BULK_REMOVE_SCRIPT),
        _REMOTE_BULK_REMOVE_SCRIPT, csv_path, timeout,
    )
