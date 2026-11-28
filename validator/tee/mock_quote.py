"""Deliberately unsigned local transport fixture."""

PREFIX = b"DEADDROP LOCAL MOCK ONLY\x00"


def mock_quote(report_data):
    return PREFIX + report_data
