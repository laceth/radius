"""
Generic CSV utilities for writing dataclass-like objects to CSV.

Any object that implements a ``to_csv_row() -> list`` method can be
serialised with these helpers.

Example::

    from lib.plugin.radius.models.mar_entry import MAREntry, MAR_CSV_HEADER
    from lib.utils.csv_utils import write_csv, to_csv_string

    entries = [
        MAREntry.accept("aa:bb:cc:dd:ee:ff", comment="printer"),
        MAREntry.reject("11:22:33:44:55:66", comment="blocked device"),
    ]

    # Write to file
    write_csv(entries, "/tmp/mar_export.csv", MAR_CSV_HEADER)

    # Or get as a string
    csv_text = to_csv_string(entries, MAR_CSV_HEADER)
"""
import csv
import io
import os
from typing import List, Protocol, Sequence


class CsvSerializable(Protocol):
    """Any object that can produce a flat list of values for a CSV row."""

    def to_csv_row(self) -> list: ...


def write_csv(
    entries: List[CsvSerializable],
    path: str,
    header: Sequence[str],
) -> str:
    """
    Write a list of CSV-serializable objects to a file.

    Args:
        entries: Objects whose ``to_csv_row()`` provides cell values.
        path: Destination file path.
        header: Column names written as the first row.

    Returns:
        The absolute path of the written file.
    """
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        for entry in entries:
            writer.writerow(entry.to_csv_row())
    return os.path.abspath(path)


def to_csv_string(
    entries: List[CsvSerializable],
    header: Sequence[str],
) -> str:
    """
    Serialise a list of CSV-serializable objects to a CSV string.

    Args:
        entries: Objects whose ``to_csv_row()`` provides cell values.
        header: Column names written as the first row.

    Returns:
        CSV content as a string (header + data rows).
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    for entry in entries:
        writer.writerow(entry.to_csv_row())
    return buf.getvalue()




