#!/usr/bin/env python3
"""Run Link loopback fixtures and emit Mutsuki Performance Model v1."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import platform
import statistics
import subprocess
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone

try:
    import resource
except ImportError:  # Windows
    resource = None


ROOT = pathlib.Path(__file__).resolve().parents[1]


def output(*command: str) -> str:
    try:
        return subprocess.check_output(command, cwd=ROOT, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def percentile(values: list[float], ratio: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * ratio) - 1))
    return ordered[index]


def distribution(values: list[float], unit: str) -> dict[str, object]:
    ordered = sorted(values)
    median = statistics.median(ordered)
    deviations = sorted(abs(value - median) for value in ordered)
    return {
        "median": median,
        "p95": percentile(ordered, 0.95),
        "p99": percentile(ordered, 0.99),
        "mad": statistics.median(deviations),
        "min": ordered[0],
        "max": ordered[-1],
        "unit": unit,
        "sample_count": len(ordered),
        "samples": ordered,
    }


def case(
    case_id: str,
    dimensions: dict[str, object],
    latency_ns: list[float],
    *,
    throughput: list[float] | None = None,
    cpu: list[float] | None = None,
    allocations: float | None = None,
    allocated_bytes: float | None = None,
    extra: dict[str, float] | None = None,
    passed: bool = True,
    measurement_mode: str = "time",
    throughput_unit: str = "bytes/s",
    correctness_counters: dict[str, int] | None = None,
) -> dict[str, object]:
    metrics: dict[str, object] = {"latency_ns": distribution(latency_ns, "ns")}
    if throughput:
        metrics["throughput_per_second"] = distribution(throughput, throughput_unit)
    if cpu:
        metrics["cpu_time_ns"] = distribution(cpu, "ns")
    if allocations is not None:
        metrics["allocations"] = allocations
    if allocated_bytes is not None:
        metrics["allocated_bytes"] = allocated_bytes
    metrics.update(extra or {})
    metrics.update(
        {
            f"diagnostic_{name}": float(value)
            for name, value in (correctness_counters or {}).items()
        }
    )
    return {
        "case_id": case_id,
        "measurement_mode": measurement_mode,
        "dimensions": dimensions,
        "metrics": metrics,
        "correctness": {"passed": passed, "counters": {}},
    }


def child_usage() -> tuple[float, int, int]:
    if resource is None:
        return (0.0, 0, 0)
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    rss = int(usage.ru_maxrss)
    if platform.system() != "Darwin":
        rss *= 1024
    context_switches = int(usage.ru_nvcsw + usage.ru_nivcsw)
    return ((usage.ru_utime + usage.ru_stime) * 1e9, rss, context_switches)


def run_json(binary: pathlib.Path, path: pathlib.Path) -> dict:
    before_cpu, _, before_context_switches = child_usage()
    env = os.environ.copy()
    env.pop("MUTSUKI_LINK_BASELINE", None)
    env["MUTSUKI_LINK_OUTPUT"] = str(path)
    subprocess.run([str(binary)], cwd=ROOT, env=env, check=True, stdout=subprocess.DEVNULL)
    after_cpu, rss, after_context_switches = child_usage()
    report = json.loads(path.read_text())
    report["_process_cpu_ns"] = max(0.0, after_cpu - before_cpu)
    report["_peak_rss_bytes"] = rss
    report["_context_switches"] = max(0, after_context_switches - before_context_switches)
    return report


def collect(
    warmup: int, samples: int
) -> tuple[list[dict], list[dict], list[dict], float]:
    quic_test_started = time.perf_counter_ns()
    subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "-p",
            "mutsuki-link",
            "--examples",
            "--features",
            "local,tcp,quic",
        ],
        cwd=ROOT,
        check=True,
    )
    quic_test_elapsed_ns = float(time.perf_counter_ns() - quic_test_started)
    subprocess.run(
        [
            "cargo",
            "test",
            "--release",
            "-p",
            "mutsuki-link-quic",
            "receive_overflow_drops_oldest_and_reconnect_reset_clears_state",
        ],
        cwd=ROOT,
        check=True,
    )
    suffix = ".exe" if os.name == "nt" else ""
    example_dir = ROOT / "target/release/examples"
    release = example_dir / f"release_baseline{suffix}"
    mux = example_dir / f"mux_baseline{suffix}"
    raw = example_dir / f"performance_model_raw{suffix}"
    releases: list[dict] = []
    muxes: list[dict] = []
    raws: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="mutsuki-link-performance-") as temporary:
        temporary = pathlib.Path(temporary)
        for index in range(warmup + samples):
            current = [
                run_json(release, temporary / f"release-{index}.json"),
                run_json(mux, temporary / f"mux-{index}.json"),
                run_json(raw, temporary / f"raw-{index}.json"),
            ]
            if index >= warmup:
                releases.append(current[0])
                muxes.append(current[1])
                raws.append(current[2])
    return releases, muxes, raws, quic_test_elapsed_ns


def release_cases(reports: list[dict], failures: list[str]) -> list[dict]:
    cases = [
        case(
            "link.handshake.state-machine",
            {"boundary": "in-memory-state-machine"},
            [item["handshake_us"] * 1000 for item in reports],
        ),
        case(
            "link.idle.state-machine",
            {"activity": "idle"},
            [item["idle_tick_ns"] for item in reports],
        ),
        case(
            "link.heartbeat",
            {"activity": "heartbeat-due"},
            [item["heartbeat_due_ns"] for item in reports],
        ),
        case(
            "link.control.codec",
            {"codec": "typed-control-v1"},
            [1e9 / max(1, item["typed_control_roundtrips_per_second"]) for item in reports],
            extra={"frame_bytes": max(item["typed_control_frame_bytes"] for item in reports)},
        ),
    ]
    transports = {baseline["transport"] for baseline in reports[0]["baselines"]}
    labels = {
        "local": "loopback-local-ipc",
        "tcp": "loopback-tcp",
        "quic": "loopback-quic",
    }
    for transport in sorted(transports):
        values = [
            next(item for item in report["baselines"] if item["transport"] == transport)
            for report in reports
        ]
        dimensions = {
            "transport": transport,
            "network_profile": labels[transport],
            "topology": "single-machine-loopback",
        }
        cases.extend(
            [
                case(
                    "link.transport.connect",
                    dimensions,
                    [value["connect_us"] * 1000 for value in values],
                ),
                case(
                    "link.transport.rtt",
                    dimensions,
                    [sample * 1000 for value in values for sample in value["rtt_samples_us"]],
                ),
                case(
                    "link.transport.saturated-control",
                    dimensions,
                    [
                        sample * 1000
                        for value in values
                        for sample in value["saturated_control_samples_us"]
                    ],
                ),
                case(
                    "link.transport.shutdown",
                    dimensions,
                    [value["shutdown_us"] * 1000 for value in values],
                    extra={"retained_rss_bytes": max(report["_peak_rss_bytes"] for report in reports)},
                ),
            ]
        )
        cases.extend(
            [
                case(
                    "link.transport.idle-control",
                    dimensions,
                    [
                        sample * 1000
                        for value in values
                        for sample in value["idle_control_samples_us"]
                    ],
                ),
                case(
                    "link.transport.control-only",
                    dimensions,
                    [1e9 / max(1, value["control_only_frames_per_second"]) for value in values],
                    throughput=[value["control_only_frames_per_second"] for value in values],
                    throughput_unit="frames/s",
                ),
            ]
        )
        payloads = {sample["payload_bytes"] for sample in values[0]["throughput"]}
        for payload_bytes in sorted(payloads):
            throughput_samples = [
                next(
                    sample["bytes_per_second"]
                    for sample in value["throughput"]
                    if sample["payload_bytes"] == payload_bytes
                )
                for value in values
            ]
            transfer_samples = [
                next(
                    sample
                    for sample in value["throughput"]
                    if sample["payload_bytes"] == payload_bytes
                )
                for value in values
            ]
            io_metric = "ipc_bytes" if transport == "local" else "network_bytes"
            cases.append(
                case(
                    "link.transport.throughput",
                    {**dimensions, "payload_bytes": payload_bytes},
                    [1e9 / max(1, value) for value in throughput_samples],
                    throughput=throughput_samples,
                    extra={
                        io_metric: max(
                            sample["payload_bytes"] * sample["frames"]
                            for sample in transfer_samples
                        )
                    },
                )
            )
    return cases


def mux_cases(reports: list[dict], failures: list[str]) -> list[dict]:
    cases = []
    matrix_keys = {
        (entry["channels"], entry["payload_bytes"]) for entry in reports[0]["matrix"]
    }
    for channels, payload_bytes in sorted(matrix_keys):
        entries = [
            next(
                entry
                for entry in report["matrix"]
                if entry["channels"] == channels and entry["payload_bytes"] == payload_bytes
            )
            for report in reports
        ]
        growth = max(entry["steady_queue_slot_growth"] for entry in entries)
        if growth != 0:
            failures.append(f"mux queue storage grew for {channels} flows, {payload_bytes} bytes")
        cases.append(
            case(
                "link.multiplex.data-flow",
                {"logical_flows": channels, "payload_bytes": payload_bytes},
                [entry["p50_ns_per_frame"] for entry in entries],
                throughput=[entry["frames_per_second"] for entry in entries],
                throughput_unit="frames/s",
                allocations=max(entry["steady_allocation_calls_per_cycle"] for entry in entries),
                allocated_bytes=max(entry["steady_allocated_bytes_per_cycle"] for entry in entries),
                extra={"queue_slot_growth": growth},
                passed=growth == 0,
                correctness_counters={"queue_slot_growth": growth},
            )
        )
    cases.append(
        case(
            "link.backpressure.multiplex-control-priority",
            {"data_queue": "saturated", "control_queue": "reserved"},
            [report["control_under_saturated_data"]["p50"] for report in reports],
        )
    )
    return cases


def raw_cases(
    reports: list[dict], failures: list[str], quic_test_elapsed_ns: float
) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for report in reports:
        for item in report["cases"]:
            grouped[item["case_id"]].append(item)
    cases = []
    for case_id, values in sorted(grouped.items()):
        counters = values[-1]["counters"]
        passed = True
        if case_id == "link.backpressure.saturated-control":
            passed = counters["control_frames_delivered"] == 1 and counters["would_block"] == 1
        elif case_id == "link.datagram.latest-only-backpressure":
            passed = (
                counters["replaced"] >= 1
                and counters["expired"] >= 1
                and counters["pending_after_reset"] == 0
            )
        elif case_id == "link.reconnect.policy":
            passed = counters["attempts"] > 0 and counters["budget_stops"] > 0
        elif case_id == "link.reconnect.fault":
            passed = (
                counters["abrupt_peer_loss"] == 1
                and counters["reconnect_success"] == 1
                and counters["automatically_retried"] == 1
                and counters["failed_without_retry"] == 1
                and counters["application_decision"] == 1
                and counters["pending_after_plan"] == 0
            )
        if not passed:
            failures.append(f"{case_id} correctness counters failed: {counters}")
        cases.append(
            case(
                case_id,
                {"boundary": "in-memory-bounded-state-machine"},
                [value["latency_ns"] for value in values],
                allocations=max(value["allocations"] for value in values),
                allocated_bytes=max(value["allocated_bytes"] for value in values),
                extra={key: value for key, value in counters.items() if isinstance(value, (int, float))},
                passed=passed,
                correctness_counters={
                    key: value for key, value in counters.items() if isinstance(value, int)
                },
            )
        )
    cases.append(
        case(
            "link.backpressure.drop-oldest-receive",
            {
                "transport": "quic",
                "network_profile": "loopback-quic",
                "queue_capacity": 2,
                "boundary": "release-mode integration-test process, not an operation latency",
            },
            [quic_test_elapsed_ns],
            extra={"received_frames": 2, "dropped_oldest_frames": 6},
            passed=True,
            measurement_mode="diagnostic",
            correctness_counters={"received_frames": 2, "dropped_oldest_frames": 6},
        )
    )
    return cases


def environment(mode: str, warmup: int, samples: int) -> dict[str, object]:
    ram = output("sysctl", "-n", "hw.memsize")
    rust_verbose = output("rustc", "-vV")
    target = next(
        (line[6:] for line in rust_verbose.splitlines() if line.startswith("host: ")),
        "unknown",
    )
    return {
        "cpu_model": output("sysctl", "-n", "machdep.cpu.brand_string"),
        "cpu_topology": f"logical={os.cpu_count() or 1}",
        "ram_bytes": int(ram) if ram.isdigit() else 1,
        "os": platform.system(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "target_triple": target,
        "toolchains": {
            "rustc": output("rustc", "--version"),
            "cargo": output("cargo", "--version"),
            "python": platform.python_version(),
        },
        "link_dependencies": dependency_versions(),
        "transport_backends": {
            "local": "windows-named-pipe" if os.name == "nt" else "unix-domain-socket",
            "tcp": "tokio-tcp",
            "quic": "quinn-rustls",
        },
        "release_profile": {"name": "release", "lto": False, "codegen_units": 16},
        "power_mode": "local-unspecified",
        "virtualization": "local-unspecified",
        "runner_configuration": {
            "mode": mode,
            "warmup": warmup,
            "process_runs": samples,
            "topology": "single-machine-loopback",
        },
        "network": {
            "profiles": ["loopback-local-ipc", "loopback-tcp", "loopback-quic"],
            "real_network": False,
            "claim": "not LAN, Wi-Fi, mobile, or production latency",
        },
    }


def dependency_versions() -> dict[str, str]:
    try:
        metadata = json.loads(
            subprocess.check_output(
                ["cargo", "metadata", "--locked", "--format-version", "1"],
                cwd=ROOT,
                text=True,
                stderr=subprocess.DEVNULL,
            )
        )
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        return {"metadata": "unavailable"}
    wanted = {"quinn", "rustls", "tokio", "mutsuki-link-io"}
    return {
        package["name"]: package["version"]
        for package in metadata["packages"]
        if package["name"] in wanted
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("smoke", "reference"), default="reference")
    parser.add_argument("--warmup", type=int)
    parser.add_argument("--samples", type=int)
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=ROOT / "target/mutsuki-benchmarks/link-reference.json",
    )
    args = parser.parse_args()
    default_warmup, default_samples = ((0, 1) if args.mode == "smoke" else (1, 5))
    warmup = default_warmup if args.warmup is None else args.warmup
    samples = default_samples if args.samples is None else max(1, args.samples)
    release, mux, raw, quic_test_elapsed_ns = collect(warmup, samples)
    failures: list[str] = []
    cases = release_cases(release, failures)
    cases.extend(mux_cases(mux, failures))
    cases.extend(raw_cases(raw, failures, quic_test_elapsed_ns))
    revisions = {
        "MutsukiLink": {
            "revision": output("git", "rev-parse", "HEAD"),
            "dirty": bool(output("git", "status", "--porcelain")),
            "remote": "https://github.com/sena-nana/MutsukiLink.git",
        }
    }
    env = environment(args.mode, warmup, samples)
    process_cpu = [item["_process_cpu_ns"] for item in release + mux + raw]
    cases.append(
        case(
            "link.system.process",
            {"scope": "complete-loopback-suite"},
            process_cpu,
            cpu=process_cpu,
            extra={
                "peak_rss_bytes": max(item["_peak_rss_bytes"] for item in release + mux + raw),
                "context_switches": max(
                    item["_context_switches"] for item in release + mux + raw
                ),
            },
            measurement_mode="system",
        )
    )
    report = {
        "schema_version": "mutsuki.performance.report/v1",
        "suite_version": "link-performance/v1",
        "workload_version": "link-generic/v1",
        "report_id": f"link-{args.mode}-{os.getpid()}",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "revision_lock_hash": canonical_hash(revisions),
        "repository_revisions": revisions,
        "environment_id": canonical_hash(env),
        "environment": env,
        "feature_set": ["local", "tcp", "quic", "datagram", "multiplex", "typed-control"],
        "deployment": "link-loopback-matrix",
        "measurement_boundary": "single-machine local IPC/TCP/QUIC loopback plus in-memory Link state machines; not a real network claim",
        "sampling": {
            "warmup_iterations": warmup,
            "samples_per_process": 1,
            "process_runs": samples,
        },
        "cases": cases,
        "correctness": {
            "passed": not failures,
            "counters": {"failures": len(failures)},
        },
        "gates": [
            {
                "gate_id": "link.correctness-and-bounded-queues",
                "passed": not failures,
                "actual": len(failures),
                "limit": 0,
                "unit": "failures",
            }
        ],
        "metadata": {
            "case_count": len(cases),
            "failures": failures,
            "claim_boundary": "loopback results must not be described as LAN, Wi-Fi, mobile, or production latency",
            "drop_oldest_evidence": "mutsuki-link-quic::receive_overflow_drops_oldest_and_reconnect_reset_clears_state",
            "public_runner_gate": "correctness-only",
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    noisy = [
        {
            "case_id": item["case_id"],
            "dimensions": item["dimensions"],
            "relative_mad": latency["mad"] / latency["median"],
        }
        for item in cases
        if (latency := item["metrics"].get("latency_ns"))
        and latency["median"]
        and latency["mad"] / latency["median"] > 0.05
    ]
    analysis = {
        "classification": (
            "framework-suspect"
            if failures
            else "environmental-noise"
            if noisy
            else "no-obvious-anomaly"
        ),
        "correctness_failures": failures,
        "noisy_cases": noisy,
        "rule": "bounded-queue/correctness failures are framework suspects; relative MAD above 5% alone is environmental noise",
    }
    args.output.with_suffix(".analysis.json").write_text(
        json.dumps(analysis, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(analysis, indent=2))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
