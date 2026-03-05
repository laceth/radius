"""
Dataclass for MAC Address Repository (MAR) entries.

Used for programmatic creation and bulk import of MAR entries via CSV.
"""
import csv
import io
import os
import random
import re
from dataclasses import dataclass
from typing import List


# CSV header matching the Forescout MAR export/import format
MAR_CSV_HEADER = [
    "dot1x_mac",
    "dot1x_auth_method",
    "dot1x_target_access",
    "dot1x_enforce_access",
    "dot1x_last_assigned_access",
    "dot1x_approved_by",
    "dot1x_mar_comment",
    "dot1x_schedule_mar_action",
    "dot1x_schedule_mar_action_time_on",
    "dot1x_inactive_mar_action",
    "dot1x_inactive_mar_action_time",
]


@dataclass
class MAREntry:
    """
    A single MAC Address Repository entry.

    Mirrors the columns used by the Forescout GUI CSV import/export.

    Example::

        entry = MAREntry(mac="001122334455", comment="printer")
        entry = MAREntry.accept("aa:bb:cc:dd:ee:ff", comment="test")
    """
    mac: str
    auth_method: str = "bypass"
    target_access: str = "vlan:\tIsCOA:false"
    enforce_access: str = ""
    last_assigned_access: str = ""
    approved_by: str = ""
    comment: str = ""
    schedule_action: str = ""
    schedule_action_time_on: str = ""
    inactive_action: str = ""
    inactive_action_time: str = ""

    @classmethod
    def accept(cls, mac: str, comment: str = "") -> "MAREntry":
        """Create an ACCEPT MAR entry."""
        return cls(mac=mac, comment=comment)

    @classmethod
    def reject(cls, mac: str, comment: str = "") -> "MAREntry":
        """Create a REJECT MAR entry."""
        return cls(mac=mac, target_access="reject=dummy", comment=comment)

    def normalized_mac(self) -> str:
        """Return bare lowercase hex MAC (e.g. ``98f2b301a055``)."""
        return re.sub(r'[-:.]', '', self.mac).replace('0x', '').lower()

    def to_csv_row(self) -> list:
        """Return a list of values matching ``MAR_CSV_HEADER``."""
        return [
            self.normalized_mac(),
            self.auth_method,
            self.target_access,
            self.enforce_access,
            self.last_assigned_access,
            self.approved_by,
            self.comment,
            self.schedule_action,
            self.schedule_action_time_on,
            self.inactive_action,
            self.inactive_action_time,
        ]

    @staticmethod
    def generate_random_mac() -> str:
        """Generate a random MAC address as bare hex (12 chars)."""
        return "".join(f"{random.randint(0, 255):02x}" for _ in range(6))

    @staticmethod
    def generate_entries(count: int, comment: str = "bulk_test") -> List["MAREntry"]:
        """
        Generate a list of unique random MAR entries.

        Args:
            count: Number of entries to generate.
            comment: Comment to set on each entry.

        Returns:
            List of MAREntry instances with unique random MACs.
        """
        seen = set()
        entries = []
        while len(entries) < count:
            mac = MAREntry.generate_random_mac()
            if mac not in seen:
                seen.add(mac)
                entries.append(MAREntry.accept(mac, comment=comment))
        return entries

    @staticmethod
    def to_csv_file(entries: List["MAREntry"], path: str) -> str:
        """
        Write a list of MAREntry objects to a CSV file in Forescout MAR format.

        Args:
            entries: List of MAREntry objects.
            path: Destination file path.

        Returns:
            The absolute path of the written file.
        """
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(MAR_CSV_HEADER)
            for entry in entries:
                writer.writerow(entry.to_csv_row())
        return os.path.abspath(path)

    @staticmethod
    def to_csv_string(entries: List["MAREntry"]) -> str:
        """Serialise entries to a CSV string (header + rows)."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(MAR_CSV_HEADER)
        for entry in entries:
            writer.writerow(entry.to_csv_row())
        return buf.getvalue()




