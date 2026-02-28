#!/usr/bin/env python3
"""Create a NoCloud seed ISO (CIDATA) with user-data and meta-data."""

from __future__ import annotations

import argparse
from pathlib import Path

import pycdlib


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_iso")
    parser.add_argument("user_data")
    parser.add_argument("meta_data")
    args = parser.parse_args()

    output_iso = Path(args.output_iso)
    user_data = Path(args.user_data)
    meta_data = Path(args.meta_data)

    if not user_data.is_file():
        raise FileNotFoundError(f"Missing user-data file: {user_data}")
    if not meta_data.is_file():
        raise FileNotFoundError(f"Missing meta-data file: {meta_data}")

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="CIDATA")
    iso.add_file(str(user_data), iso_path="/USERDATA.;1", rr_name="user-data", joliet_path="/user-data")
    iso.add_file(str(meta_data), iso_path="/METADATA.;1", rr_name="meta-data", joliet_path="/meta-data")
    iso.write(str(output_iso))
    iso.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
