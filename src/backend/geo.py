"""Haversine distance and implied travel speed. See docs/detection_spec.md."""

from __future__ import annotations

from math import asin, cos, radians, sin, sqrt

EARTH_RADIUS_KM = 6371.0


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km.

    Uses asin rather than atan2 -- equivalent, and numerically steadier for the
    small distances that dominate ordinary traffic.
    """
    phi1, phi2 = radians(lat1), radians(lat2)
    dphi = radians(lat2 - lat1)
    dlambda = radians(lon2 - lon1)
    a = sin(dphi / 2) ** 2 + cos(phi1) * cos(phi2) * sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_KM * asin(sqrt(min(1.0, a)))


def implied_speed_kmh(distance_km: float, hours: float) -> float | None:
    """Speed implied by covering distance_km in `hours`.

    Returns None when the pair carries no travel signal: non-positive elapsed
    time, or identical coordinates. Both are guards the spec calls for -- a zero
    Δt would otherwise divide by zero, and co-located logins are not travel.
    """
    if hours <= 0 or distance_km <= 0:
        return None
    return distance_km / hours
