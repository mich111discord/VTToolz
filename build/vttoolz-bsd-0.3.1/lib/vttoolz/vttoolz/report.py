"""Parse and pretty-print VirusTotal file reports."""

from __future__ import annotations

from typing import Any


def extract_detections(report: dict[str, Any]) -> dict[str, Any]:
    """
    Extract the most useful fields from a /ui/files/{hash} response.

    Returns a clean dict ready for JSON or terminal output.
    """
    data = report.get("data", {})
    attrs = data.get("attributes", {})

    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})

    detections: list[dict[str, str]] = []
    for engine, info in sorted(results.items()):
        category = info.get("category", "undetected")
        if category in ("malicious", "suspicious"):
            detections.append(
                {
                    "engine": engine,
                    "category": category,
                    "result": info.get("result") or "",
                    "method": info.get("method") or "",
                    "engine_version": info.get("engine_version") or "",
                    "engine_update": info.get("engine_update") or "",
                }
            )

    return {
        "id": data.get("id"),
        "sha256": attrs.get("sha256"),
        "sha1": attrs.get("sha1"),
        "md5": attrs.get("md5"),
        "size": attrs.get("size"),
        "type_description": attrs.get("type_description"),
        "meaningful_name": attrs.get("meaningful_name"),
        "first_submission_date": attrs.get("first_submission_date"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "times_submitted": attrs.get("times_submitted"),
        "stats": stats,
        "detection_count": len(detections),
        "detections": detections,
        "tags": attrs.get("tags", []),
        "popular_threat_classification": attrs.get("popular_threat_classification"),
        "permalink": f"https://www.virustotal.com/gui/file/{data.get('id')}",
    }


def print_report(parsed: dict[str, Any], verbose: bool = False) -> None:
    """Human-readable terminal output."""
    stats = parsed.get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    total = sum(stats.values()) if stats else 0

    print(f"\n{'='*60}")
    print(f"  File : {parsed.get('meaningful_name') or parsed.get('id')}")
    print(f"  SHA256: {parsed.get('sha256')}")
    print(f"  Type  : {parsed.get('type_description')}")
    print(f"  Size  : {parsed.get('size')} bytes")
    print(f"{'='*60}")
    print(f"  Detections: {malicious + suspicious}/{total}")
    print(f"    malicious : {malicious}")
    print(f"    suspicious: {suspicious}")
    print(f"    undetected: {undetected}")
    print(f"{'='*60}")

    if parsed.get("detections"):
        print("\n  Flagged by:")
        for d in parsed["detections"]:
            mark = "!" if d["category"] == "malicious" else "?"
            print(f"    [{mark}] {d['engine']:<25} {d['result']}")
    else:
        print("\n  No malicious / suspicious detections.")

    if verbose:
        print(f"\n  First seen : {parsed.get('first_submission_date')}")
        print(f"  Last analysis: {parsed.get('last_analysis_date')}")
        print(f"  Times submitted: {parsed.get('times_submitted')}")
        print(f"  Tags: {', '.join(parsed.get('tags') or [])}")
        print(f"  Permalink: {parsed.get('permalink')}")

    print()
