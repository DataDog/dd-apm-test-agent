import json
from typing import List

from .checks import CheckTrace
from .tracestats import StatsBucket


def _normalize_statsbuckets(buckets: List[StatsBucket]) -> List[StatsBucket]:
    """Normalize the stats bucket by normalizing the time buckets."""
    # Make a copy of the buckets, note that the sketches are not copied.
    normed_buckets = []
    for bucket in buckets:
        bcopy = bucket.copy()
        bcopy["Stats"] = [
            aggr.copy() for aggr in bucket["Stats"]
        ]  # Copy the aggregations
        normed_buckets.append(bcopy)

    # Order the buckets by time
    normed_buckets = sorted(normed_buckets, key=lambda b: b["Start"])

    # Sort aggr for a bucket alphanumerically
    for bucket in normed_buckets:
        # Sort aggrs by name then resource then hits
        bucket["Stats"] = sorted(
            bucket["Stats"], key=lambda b: (b["Name"], b["Resource"], ["Hits"])
        )

    start = normed_buckets[0]["Start"]
    for b in normed_buckets:
        b["Start"] -= start

    return normed_buckets


def snapshot(
    expected_stats: List[StatsBucket], received_stats: List[StatsBucket]
) -> None:
    # Normalize the stats buckets by making them independent of time. Only ordering matters.

    # Sort the buckets by start time.
    normed_expected = _normalize_statsbuckets(expected_stats)
    normed_received = _normalize_statsbuckets(received_stats)

    # TODO: do better matching and comparing to aid in debugging
    assert len(normed_received) == len(
        normed_expected
    ), f"Number of stats buckets ({len(normed_received)}) doesn't match expected ({len(normed_expected)})."

    with CheckTrace.add_frame(
        f"snapshot compare of {len(normed_received)} stats buckets"
    ):
        # Do a really rough comparison.
        for i, (exp_bucket, rec_bucket) in enumerate(
            zip(normed_expected, normed_received)
        ):
            exp_aggrs = exp_bucket["Stats"]
            rec_aggrs = rec_bucket["Stats"]
            assert len(exp_aggrs) == len(
                rec_aggrs
            ), f"Number of aggregations ({len(rec_aggrs)}) in bucket {i} doesn't match expected ({len(exp_aggrs)})."

            for j, (exp_aggr, rec_aggr) in enumerate(zip(exp_aggrs, rec_aggrs)):
                # Omit duration and sketches for now
                # Duration and sketches will be noisy
                for attr in (
                    "Name",
                    "Resource",
                    "Type",
                    "Synthetics",
                    "Hits",
                    "TopLevelHits",
                    "Errors",
                ):
                    exp_value, rec_value = exp_aggr[attr], rec_aggr[attr]  # type: ignore
                    if exp_value != rec_value:
                        raise AssertionError(
                            f"Expected value ('{exp_value}') for field '{attr}' does not match received value '{rec_value}'"
                        )


def generate(received_stats: List[StatsBucket]) -> str:
    return f"{json.dumps(_normalize_statsbuckets(received_stats), indent=2)}\n"
