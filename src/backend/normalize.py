"""Readers that turn any supported log format into the canonical frame.

Nothing downstream knows which format arrived -- that is the point. The Entra
path exists so the demo can run a real tenant export through the same detectors
without a code change (docs/data_spec.md).
"""

from __future__ import annotations

import io
from pathlib import Path

import pandas as pd

from src.backend.config import EVENT_COLUMNS

# Entra sign-in export -> canonical. Several spellings per field because exports
# differ between the portal, Graph and the Sentinel connector.
ENTRA_COLUMN_MAP = {
    "timegenerated": "timestamp",
    "createddatetime": "timestamp",
    "date (utc)": "timestamp",
    "userprincipalname": "username",
    "user principal name": "username",
    "identity": "username",
    "ipaddress": "source_ip",
    "ip address": "source_ip",
    "location": "country",
    "locationdetails_countryorregion": "country",
    "country or region": "country",
    "locationdetails_city": "city",
    "city": "city",
    "locationdetails_geocoordinates_latitude": "latitude",
    "latitude": "latitude",
    "locationdetails_geocoordinates_longitude": "longitude",
    "longitude": "longitude",
    "devicedetail_deviceid": "device_id",
    "device id": "device_id",
    "useragent": "user_agent",
    "user agent": "user_agent",
}

# ResultType "0" is success; everything else is a failure. 50126 is the bad
# credential code a spray generates, which is what the KQL in the report keys on.
ENTRA_SUCCESS_CODE = "0"

CANONICAL_MARKERS = {"username", "source_ip", "success"}
ENTRA_MARKERS = {"userprincipalname", "ipaddress", "resulttype"}


def detect_format(columns: list[str]) -> str:
    """Return 'canonical' or 'entra' by sniffing the header row."""
    lowered = {c.strip().lower() for c in columns}
    if CANONICAL_MARKERS.issubset(lowered):
        return "canonical"
    if lowered & ENTRA_MARKERS:
        return "entra"
    raise ValueError(
        "Unrecognised log format. Expected canonical columns "
        f"{sorted(CANONICAL_MARKERS)} or an Entra sign-in export."
    )


def _coerce(df: pd.DataFrame) -> pd.DataFrame:
    """Shared tail end: types, UTC, ordering, stable ids."""
    for column in EVENT_COLUMNS:
        if column not in df.columns:
            df[column] = pd.NA

    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601", utc=True)

    for column in ("latitude", "longitude"):
        df[column] = pd.to_numeric(df[column], errors="coerce")

    for column in ("username", "source_ip", "country", "city", "device_id", "user_agent"):
        df[column] = df[column].astype("string").fillna("unknown")

    df["success"] = df["success"].astype(bool)

    # Rows without the fields every detector needs cannot be scored. Quarantine
    # rather than guess -- a fabricated timestamp would corrupt every window.
    before = len(df)
    df = df.dropna(subset=["timestamp"])
    df = df[(df["username"] != "unknown") & (df["source_ip"] != "unknown")]
    quarantined = before - len(df)

    df = df.sort_values("timestamp").reset_index(drop=True)
    df["event_id"] = range(len(df))
    df = df[EVENT_COLUMNS]
    df.attrs["quarantined"] = quarantined
    return df


def read_canonical(source: str | Path | io.BytesIO) -> pd.DataFrame:
    return _coerce(pd.read_csv(source))


def read_entra(source: str | Path | io.BytesIO) -> pd.DataFrame:
    """Map an Entra sign-in export onto the canonical schema."""
    raw = pd.read_csv(source)
    # Graph exports nest fields; flatten "a.b.c" to "a_b_c" before matching.
    raw.columns = [c.strip().replace(".", "_") for c in raw.columns]
    lookup = {c.lower(): c for c in raw.columns}

    out = pd.DataFrame(index=raw.index)
    for entra_name, canonical in ENTRA_COLUMN_MAP.items():
        key = entra_name.replace(".", "_")
        if key in lookup and canonical not in out.columns:
            out[canonical] = raw[lookup[key]]

    if "resulttype" in lookup:
        result = raw[lookup["resulttype"]].astype("string").str.strip()
        out["success"] = result == ENTRA_SUCCESS_CODE
    else:
        out["success"] = True

    # Portal exports often carry "City, Country" in one Location column.
    if "country" in out.columns and "city" not in out.columns:
        parts = out["country"].astype("string").str.split(",", n=1, expand=True)
        if parts.shape[1] == 2:
            out["city"] = parts[0].str.strip()
            out["country"] = parts[1].str.strip()

    frame = _coerce(out)
    frame.attrs["source_format"] = "entra"
    return frame


def read_events(source: str | Path | io.BytesIO) -> pd.DataFrame:
    """Read any supported format. The returned frame records which it was."""
    if isinstance(source, io.BytesIO):
        header = pd.read_csv(io.BytesIO(source.getvalue()), nrows=0).columns.tolist()
        source.seek(0)
    else:
        header = pd.read_csv(source, nrows=0).columns.tolist()

    fmt = detect_format(header)
    frame = read_entra(source) if fmt == "entra" else read_canonical(source)
    frame.attrs["source_format"] = fmt
    return frame
