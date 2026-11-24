# Collecting a skill corpus for the v5.3.0 scanner

The scanner baseline is Git tag `v5.3.0`, commit `5a93240f3850d912582b0fd2d65603c3a7c0120f`. Use the checkout containing these census commands. The collector uses the Python standard library. The queue builder uses `jsonschema` from `census/requirements.txt` to validate every input row against the shipped v2 schema.

```bash
python -m pip install -r census/requirements.txt
python census/collect_ecosystem.py --output-dir work/corpus --state-db work/state.sqlite3 \
  --checkpoint-dir drive/checkpoints --checkpoint-every 500
python scripts/scan.py --batch-dir work/corpus/packages --format jsonl --output work/scans.jsonl
python census/build_audit_queue.py --scan-jsonl work/scans.jsonl --state-db work/state.sqlite3 \
  --output-dir work/audit --seed 20261124 --ab-sample-size 1500
```

Set `GITHUB_TOKEN` or `GH_TOKEN` in the environment for GitHub Code Search. The scanner returns 1 for D/F findings or 2 for rejected inputs. A completed JSONL stream in either case can feed the queue builder.

## Acquisition

| Collector argument | Meaning |
| --- | --- |
| `--manifest FILE` | Defaults to the adjacent `sources_manifest.json`. Tier 1 lists official repositories. Tier 2 lists registry repositories, explicit Markdown indexes and directories containing immediate Markdown catalog pages. The collector follows GitHub repository, tree and blob links from those pages. Tier 3 supplies code search templates, inclusive byte bounds and fallback directory qualifiers. |
| `--output-dir DIR` | Required corpus root. Each accepted skill is a separate directory directly below `packages/`. Its opaque source ID binds the case-folded repository name, pinned commit and skill root. |
| `--state-db FILE` | Live SQLite discovery and provenance database. Defaults to `OUTPUT_DIR/state.sqlite3`. Reuse it with the same manifest to resume. |
| `--checkpoint-dir DIR` | Optional durable destination for `latest.sqlite3`, written with the SQLite backup API and atomic replacement. |
| `--checkpoint-every N` | Positive interval, default 500. Each committed search page counts once. Each repository transaction adds its package outcomes, or one for an empty/unavailable repository. Checkpoints occur after transactions and again on exit. |

A repository is downloaded as one commit-addressed ZIP. All `SKILL.md` directories are discovered, including skills absent from search results. Each file belongs to the closest skill root. The collector records the default-branch commit, observed star count, reported SPDX license (nullable), skill path, file inventory and all discovery tiers. Repeated discoveries add provenance without downloading a second copy. The effective tier is the highest-priority observed tier, with tier 1 first.

Each package is limited to **10 MiB of combined uncompressed files**. Paths, member types, portable filename collisions and actual byte counts are checked before publication. Files are stored as ordinary data. Nested skills are separate packages and v5.3.0's VCS, cache and environment exclusions apply. The `rejections` table records per-package exclusions. Repository-level refusals and unavailable sources are recorded in `repos.status` and `repos.reason`.

Queries exceeding 900 hits, or reporting incomplete results, are bisected over disjoint inclusive byte ranges. A dense single-byte leaf also schedules the configured `path:` searches and reads up to ten 100-result pages. Unresolved leaves retain `status='partial'` with counts and a reason in `shards`. This makes the API's per-query ceiling and indexing restrictions visible in the coverage denominator. Additional path queries may overlap. A Code Search result count measures files in the GitHub index at query time. [GitHub REST search](https://docs.github.com/en/rest/search/search#search-code) · [Legacy Code Search indexing and qualifiers](https://docs.github.com/en/search-github/searching-on-github/searching-code)

The collector honors primary quota resets, `Retry-After` and secondary-limit backoff. Ordinary permission errors stop the run. Exit 0 means discovery work finished, 1 means a request or local operation failed, and 2 means terminal search coverage gaps remain. The JSON summary includes excluded packages and repository statuses. [GitHub rate-limit behavior](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api#exceeding-the-rate-limit)

After a Colab disconnect, copy `latest.sqlite3` to a separate live `--state-db` and rerun the same command. Keeping `--output-dir` on persistent storage also preserves the corpus. If the package directory was lost, the collector fetches the missing repositories at their **recorded commits**. Completed search pages survive restoration. Transient incomplete/short terminal pages are retried at the next invocation. A saturated one-byte shard retains its recorded coverage gap.

## Audit queue

| Queue argument | Meaning |
| --- | --- |
| `--scan-jsonl FILE` | Required v5.3.0 JSONL from a batch scan of `OUTPUT_DIR/packages`. |
| `--state-db FILE` | Required collector database, opened read-only. Every successful row must match the recorded package source and canonical tree digest. |
| `--output-dir DIR` | Required destination for the three JSONL files below. |
| `--full-grades GRADES` | C, D and F always receive full review. Use `--full-grades B` to include B. Commas and spaces are accepted. |
| `--seed N` | Default 20261124. Ranks trees deterministically by SHA-256 of the seed and tree digest within each stratum. |
| `--ab-sample-size N` | Total sample from remaining A/B trees, default 1500. Zero selects only full-review grades. |

- `malformed_packages.jsonl` retains each valid v2 `complete: false` record and its original error message. Standard output reports counts by error class. Invalid JSON, a schema mismatch, a different scanner version or a missing provenance binding stops the build before new outputs are published.
- `lineage_map.jsonl` groups all distinct repository/commit/skill-path occurrences by `canonical_tree_sha256`, including each origin's metadata and tiers. `clone_count` is `occurrence_count - 1`. Repeated input lines have no effect on this count. The digest measures identical file trees; it supplies no direction of copying.
- `stage2_audit_queue.jsonl` contains one dossier per selected tree. The worst observed grade determines full review. Remaining unique trees are stratified by grade and effective tier. The allocation gives each nonempty stratum one slot when the budget permits, then uses proportional largest remainders. Each UTF-8 JSONL record is at most **12,000 Unicode characters including its LF**. The dossier combines the declared intent, a file list and the scanner's redacted evidence windows. Omission counts identify bounded file and issue lists. File content is never reread to reconstruct evidence.

The queue builder prints a JSON summary with malformed counts, unique trees, full-review and sampled counts, quotas by stratum and the seed.

## Offline verification

```bash
python -m unittest discover -s census/tests -p "test_*.py" -v
```

The loopback service supplies GitHub metadata, pages and repository archives. The end-to-end test invokes `scripts/scan.py --batch-dir` and the queue CLI in subprocesses.
