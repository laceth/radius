"""
Dataclass for MAC Address Repository (MAR) entries.

Used for programmatic creation and bulk import of MAR entries via CSV.
"""
from dataclasses import dataclass

from lib.utils.mac import normalize_mac


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

    def to_csv_row(self) -> list:
        """Return a list of values matching ``MAR_CSV_HEADER``."""
        return [
            normalize_mac(self.mac),
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
