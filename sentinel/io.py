"""Strict CSV entry point: preserve the original header contract before pandas renames columns."""

import csv
import io
from pathlib import Path
import pandas as pd


def read_flow_csv(source):
    if isinstance(source, (str, Path)):
        text = Path(source).read_text(encoding="utf-8-sig")
    else:
        source.seek(0)
        value = source.read()
        text = (
            value.decode("utf-8-sig")
            if isinstance(value, bytes)
            else value.lstrip("\ufeff")
        )
    stream = io.StringIO(text)
    header = next(csv.reader(stream), None)
    if not header:
        raise ValueError("CSV input is empty.")
    if any(not column.strip() for column in header):
        raise ValueError("CSV headers cannot be blank.")
    if len(header) != len(set(header)):
        raise ValueError("Duplicate CSV column names are not allowed.")
    if any(column != column.strip() for column in header):
        raise ValueError("CSV headers cannot contain surrounding whitespace.")
    stream.seek(0)
    return pd.read_csv(stream)
