#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from cerebras.cloud.sdk import Cerebras
except ImportError:
    Cerebras = None

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TARGETS_RE = re.compile(r"targets=\[([^\]]*)\]")
PORTS_RE = re.compile(r"ports=\[([^\]]*)\]")
SRC_RE = re.compile(r"\bsrc=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b")
DST_RE = re.compile(r"\bdst=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b")


@dataclass
class NoticeEvent:
    ts: float
    dt: str
    note: str
    msg: str
    identifier: str
    src: Optional[str]
    dst: Optional[str]
    parsed_targets: List[str]
    parsed_ports: List[str]
    raw: Dict[str, Any]


@dataclass
class SynRateEvent:
    ts: float
    dt: str
    src: str
    window_start: float
    window_end: float
    syn_count: int
    syn_rate: float
    distinct_targets: int
    distinct_ports: int
    internal_targets: int
    external_targets: int
    raw: Dict[str, Any]


@dataclass
class CorrelatedIncident:
    source: str
    start_ts: float
    end_ts: float
    start_dt: str
    end_dt: str
    notes: List[str]
    events: List[NoticeEvent]
    distinct_targets: List[str]
    distinct_ports: List[str]
    identifiers: List[str]
    syn_rate_events: List[SynRateEvent]
    heuristic_label: str
    confidence: str
    rationale: str
    ai_analysis: Optional[str] = None


def resolve_secret(cli_value: Optional[str], prompt_text: str) -> str:
    if cli_value and cli_value.strip():
        return cli_value.strip()

    value = getpass.getpass(prompt_text).strip()
    if not value:
        raise RuntimeError("Required API key cannot be empty.")
    return value


def parse_zeek_tsv(path: Path) -> List[Dict[str, str]]:
    fields: Optional[List[str]] = None
    rows: List[Dict[str, str]] = []

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue

            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue

            if line.startswith("#"):
                continue

            if fields is None:
                raise ValueError(f"Could not find #fields header in {path}")

            parts = line.split("\t")
            if len(parts) < len(fields):
                parts += [""] * (len(fields) - len(parts))
            elif len(parts) > len(fields):
                parts = parts[: len(fields)]

            rows.append(dict(zip(fields, parts)))

    return rows


def safe_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: str, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def epoch_to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def normalize_ip(candidate: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(candidate.strip()))
    except ValueError:
        return None


def extract_all_ips(text: str) -> List[str]:
    valid: List[str] = []
    for candidate in IP_RE.findall(text or ""):
        ip = normalize_ip(candidate)
        if ip:
            valid.append(ip)

    out: List[str] = []
    seen = set()
    for ip in valid:
        if ip not in seen:
            out.append(ip)
            seen.add(ip)
    return out


def parse_targets_from_msg(msg: str) -> List[str]:
    m = TARGETS_RE.search(msg or "")
    if not m:
        return []

    content = m.group(1).strip()
    if not content:
        return []

    parts = [p.strip() for p in content.split(",") if p.strip()]
    targets: List[str] = []
    for part in parts:
        ip = normalize_ip(part)
        if ip:
            targets.append(ip)

    out: List[str] = []
    seen = set()
    for ip in targets:
        if ip not in seen:
            out.append(ip)
            seen.add(ip)
    return out


def parse_ports_from_msg(msg: str) -> List[str]:
    m = PORTS_RE.search(msg or "")
    if not m:
        return []

    content = m.group(1).strip()
    if not content:
        return []

    parts = [p.strip() for p in content.split(",") if p.strip()]
    out: List[str] = []
    seen = set()
    for p in parts:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out


def infer_src_dst(row: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
    src_candidates = [
        row.get("src"),
        row.get("id.orig_h"),
        row.get("orig_h"),
    ]
    dst_candidates = [
        row.get("dst"),
        row.get("id.resp_h"),
        row.get("resp_h"),
    ]

    src = next((normalize_ip(x) for x in src_candidates if x and x != "-" and normalize_ip(x)), None)
    dst = next((normalize_ip(x) for x in dst_candidates if x and x != "-" and normalize_ip(x)), None)

    msg = row.get("msg", "")
    identifier = row.get("identifier", "")

    if not src:
        m = SRC_RE.search(msg or "")
        if m:
            src = normalize_ip(m.group(1))

    if not src:
        ips = extract_all_ips(identifier) or extract_all_ips(msg)
        if ips:
            src = ips[0]

    if not dst:
        m = DST_RE.search(msg or "")
        if m:
            dst = normalize_ip(m.group(1))

    if not dst:
        targets = parse_targets_from_msg(msg)
        if len(targets) == 1:
            dst = targets[0]

    if not dst:
        ips = extract_all_ips(msg)
        if src:
            ips = [ip for ip in ips if ip != src]
        if len(ips) == 1:
            dst = ips[0]

    return src, dst


def normalize_notice_rows(rows: List[Dict[str, str]]) -> List[NoticeEvent]:
    events: List[NoticeEvent] = []

    for row in rows:
        ts = safe_float(row.get("ts", "0"))
        note = row.get("note", "")
        msg = row.get("msg", "")
        identifier = row.get("identifier", "")
        src, dst = infer_src_dst(row)
        parsed_targets = parse_targets_from_msg(msg)
        parsed_ports = parse_ports_from_msg(msg)

        events.append(
            NoticeEvent(
                ts=ts,
                dt=epoch_to_iso(ts),
                note=note,
                msg=msg,
                identifier=identifier,
                src=src,
                dst=dst,
                parsed_targets=parsed_targets,
                parsed_ports=parsed_ports,
                raw=row,
            )
        )

    events.sort(key=lambda e: e.ts)
    return events


def normalize_syn_rate_rows(rows: List[Dict[str, str]]) -> List[SynRateEvent]:
    events: List[SynRateEvent] = []

    for row in rows:
        ts = safe_float(row.get("ts", "0"))
        src = normalize_ip(row.get("src", "") or "") or "unknown"

        events.append(
            SynRateEvent(
                ts=ts,
                dt=epoch_to_iso(ts),
                src=src,
                window_start=safe_float(row.get("window_start", "0")),
                window_end=safe_float(row.get("window_end", "0")),
                syn_count=safe_int(row.get("syn_count", "0")),
                syn_rate=safe_float(row.get("syn_rate", "0")),
                distinct_targets=safe_int(row.get("distinct_targets", "0")),
                distinct_ports=safe_int(row.get("distinct_ports", "0")),
                internal_targets=safe_int(row.get("internal_targets", "0")),
                external_targets=safe_int(row.get("external_targets", "0")),
                raw=row,
            )
        )

    events.sort(key=lambda e: e.ts)
    return events


def cluster_notice_events(events: List[NoticeEvent], window_seconds: int) -> List[CorrelatedIncident]:
    by_src: Dict[str, List[NoticeEvent]] = {}
    for ev in events:
        source = ev.src or "unknown"
        by_src.setdefault(source, []).append(ev)

    incidents: List[CorrelatedIncident] = []

    for source, src_events in by_src.items():
        src_events.sort(key=lambda e: e.ts)
        current_cluster: List[NoticeEvent] = []

        for ev in src_events:
            if not current_cluster:
                current_cluster = [ev]
                continue

            if ev.ts - current_cluster[-1].ts <= window_seconds:
                current_cluster.append(ev)
            else:
                incidents.append(build_incident(source, current_cluster))
                current_cluster = [ev]

        if current_cluster:
            incidents.append(build_incident(source, current_cluster))

    incidents.sort(key=lambda i: i.start_ts)
    return incidents


def build_incident(source: str, events: List[NoticeEvent]) -> CorrelatedIncident:
    notes = sorted({ev.note for ev in events if ev.note})
    identifiers = sorted({ev.identifier for ev in events if ev.identifier})

    targets_seen: List[str] = []
    target_seen_set = set()

    ports_seen: List[str] = []
    port_seen_set = set()

    for ev in events:
        candidate_targets = list(ev.parsed_targets)
        if ev.dst and ev.dst not in candidate_targets:
            candidate_targets.append(ev.dst)

        for t in candidate_targets:
            if t and t != source and t not in target_seen_set:
                targets_seen.append(t)
                target_seen_set.add(t)

        for p in ev.parsed_ports:
            if p not in port_seen_set:
                ports_seen.append(p)
                port_seen_set.add(p)

    heuristic_label, confidence, rationale = score_incident(notes, events, [])

    return CorrelatedIncident(
        source=source,
        start_ts=events[0].ts,
        end_ts=events[-1].ts,
        start_dt=events[0].dt,
        end_dt=events[-1].dt,
        notes=notes,
        events=events,
        distinct_targets=targets_seen,
        distinct_ports=ports_seen,
        identifiers=identifiers,
        syn_rate_events=[],
        heuristic_label=heuristic_label,
        confidence=confidence,
        rationale=rationale,
    )


def attach_syn_rate_events(
    incidents: List[CorrelatedIncident],
    syn_events: List[SynRateEvent],
    padding_seconds: int = 120,
) -> None:
    by_src: Dict[str, List[SynRateEvent]] = {}
    for ev in syn_events:
        by_src.setdefault(ev.src, []).append(ev)

    for incident in incidents:
        candidates = by_src.get(incident.source, [])
        attached: List[SynRateEvent] = []

        for ev in candidates:
            starts_before_incident_end = ev.window_start <= (incident.end_ts + padding_seconds)
            ends_after_incident_start = ev.window_end >= (incident.start_ts - padding_seconds)

            if starts_before_incident_end and ends_after_incident_start:
                attached.append(ev)

        incident.syn_rate_events = attached
        label, conf, why = score_incident(incident.notes, incident.events, incident.syn_rate_events)
        incident.heuristic_label = label
        incident.confidence = conf
        incident.rationale = why


def score_incident(
    notes: List[str],
    notice_events: List[NoticeEvent],
    syn_rate_events: List[SynRateEvent],
) -> Tuple[str, str, str]:
    note_set = set(notes)

    has_arp = any("ARP_Sweep" in n for n in note_set)
    has_icmp = any("ICMP_Sweep" in n for n in note_set)
    has_syn_h = any("TCP_SYN_Scan_Horizontal" in n or "Port_Scan_Horizontal" in n for n in note_set)
    has_syn_v = any("TCP_SYN_Scan_Vertical" in n or "Port_Scan_Vertical" in n for n in note_set)

    max_syn_rate = max((e.syn_rate for e in syn_rate_events), default=0.0)
    max_syn_count = max((e.syn_count for e in syn_rate_events), default=0)
    max_distinct_targets = max((e.distinct_targets for e in syn_rate_events), default=0)
    max_distinct_ports = max((e.distinct_ports for e in syn_rate_events), default=0)
    max_internal_targets = max((e.internal_targets for e in syn_rate_events), default=0)

    if has_arp and (has_syn_h or has_syn_v or has_icmp):
        return (
            "multi-stage reconnaissance",
            "high",
            "Host discovery was followed by additional probing activity, which is consistent with adversarial reconnaissance."
        )

    if has_syn_v and max_distinct_ports >= 20 and max_distinct_targets <= 3:
        return (
            "fast vertical TCP reconnaissance",
            "high",
            f"SYN telemetry shows concentrated probing of many ports on few targets (max ports={max_distinct_ports}, max SYN rate={max_syn_rate:.2f}/s)."
        )

    if has_syn_h and max_internal_targets >= 2:
        return (
            "horizontal TCP reconnaissance",
            "high" if max_internal_targets >= 5 else "medium",
            f"SYN telemetry shows one source probing multiple internal hosts on a small set of ports (max internal targets={max_internal_targets}, max SYN rate={max_syn_rate:.2f}/s)."
        )

    if has_icmp and (has_syn_h or has_syn_v):
        return (
            "network discovery followed by service probing",
            "high",
            "ICMP sweep activity was followed by TCP probing, suggesting structured reconnaissance rather than ordinary traffic."
        )

    if has_arp:
        return (
            "layer-2 host discovery",
            "medium",
            "ARP sweep behavior suggests local subnet discovery. Confidence is medium without follow-on TCP or ICMP probing."
        )

    if has_syn_v:
        return (
            "vertical TCP reconnaissance",
            "medium",
            f"One source targeted many ports on one destination. SYN telemetry supports a port-oriented probing pattern (max ports={max_distinct_ports}, max SYN count={max_syn_count})."
        )

    if has_syn_h:
        return (
            "horizontal TCP reconnaissance",
            "medium",
            f"One source targeted multiple hosts on the same port. SYN telemetry supports a host-spread probing pattern (max targets={max_distinct_targets}, max SYN count={max_syn_count})."
        )

    if has_icmp:
        return (
            "ICMP-based host discovery",
            "medium",
            "Repeated ICMP echo requests to multiple targets are consistent with host discovery."
        )

    if syn_rate_events:
        if max_distinct_ports >= 20 and max_distinct_targets <= 3:
            return (
                "possible vertical TCP probing",
                "medium",
                f"SYN telemetry alone suggests focused multi-port probing (max ports={max_distinct_ports}, max targets={max_distinct_targets})."
            )
        if max_internal_targets >= 2 and max_distinct_ports <= 3:
            return (
                "possible horizontal TCP probing",
                "medium",
                f"SYN telemetry alone suggests spread across internal targets (max internal targets={max_internal_targets}, max ports={max_distinct_ports})."
            )
        return (
            "unclassified SYN activity",
            "low",
            f"SYN telemetry exists but does not strongly match a known reconnaissance pattern (max SYN rate={max_syn_rate:.2f}/s)."
        )

    return (
        "unclassified notice cluster",
        "low",
        "The observed alert combination does not strongly match a known reconnaissance pattern."
    )


def incident_to_ai_prompt(incident: CorrelatedIncident) -> str:
    notice_lines = []
    for ev in incident.events:
        notice_lines.append(
            f"- time={ev.dt}, note={ev.note}, src={ev.src}, dst={ev.dst}, "
            f"targets={ev.parsed_targets}, ports={ev.parsed_ports}, msg={ev.msg}"
        )

    syn_lines = []
    for ev in incident.syn_rate_events:
        syn_lines.append(
            f"- ts={ev.dt}, src={ev.src}, window_start={epoch_to_iso(ev.window_start)}, "
            f"window_end={epoch_to_iso(ev.window_end)}, syn_count={ev.syn_count}, "
            f"syn_rate={ev.syn_rate:.2f}, distinct_targets={ev.distinct_targets}, "
            f"distinct_ports={ev.distinct_ports}, internal_targets={ev.internal_targets}, "
            f"external_targets={ev.external_targets}"
        )

    return f"""You are a cybersecurity analyst reviewing Zeek-based smart-home IDS output.

Analyze this incident and decide whether it is most consistent with benign activity, administration, vulnerability scanning, or adversarial reconnaissance.

Incident summary:
- source: {incident.source}
- start: {incident.start_dt}
- end: {incident.end_dt}
- heuristic_label: {incident.heuristic_label}
- heuristic_confidence: {incident.confidence}
- rationale: {incident.rationale}
- distinct_targets_from_notices: {incident.distinct_targets}
- distinct_ports_from_notices: {incident.distinct_ports}
- notes_seen: {incident.notes}

Notice events:
{chr(10).join(notice_lines) if notice_lines else "- none"}

SYN-rate telemetry:
{chr(10).join(syn_lines) if syn_lines else "- none"}

Respond with:
1. Verdict
2. Confidence (low/medium/high)
3. Reasoning
4. Likely attack stage
5. Recommended next investigation step
"""


def list_cerebras_models(api_key: str) -> List[str]:
    if Cerebras is None:
        raise RuntimeError(
            "The Cerebras SDK is not installed. Install it first with: pip install cerebras_cloud_sdk"
        )

    client = Cerebras(api_key=api_key)
    models = client.models.list()

    names: List[str] = []
    for item in getattr(models, "data", []):
        model_id = getattr(item, "id", None)
        if model_id:
            names.append(model_id)

    return names


def analyze_with_cerebras(
    incidents: List[CorrelatedIncident],
    model: str,
    api_key: str,
) -> None:
    if Cerebras is None:
        raise RuntimeError(
            "The Cerebras SDK is not installed. Install it first with: pip install cerebras_cloud_sdk"
        )

    client = Cerebras(api_key=api_key)

    system_prompt = (
        "You are a cybersecurity analyst. Analyze network behavior and Zeek-based IDS incidents. "
        "Be concise, evidence-based, and explain whether the behavior is more consistent with "
        "benign activity, administration, scanning, or adversarial reconnaissance."
    )

    for idx, incident in enumerate(incidents, start=1):
        user_prompt = incident_to_ai_prompt(incident)

        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            incident.ai_analysis = response.choices[0].message.content
        except Exception as e:
            incident.ai_analysis = f"Cerebras analysis failed for incident #{idx}: {e}"
            raise RuntimeError(
                f"Cerebras request failed while using model '{model}'. "
                f"If you are not sure which models your key can access, run with --list-cerebras-models. "
                f"Original error: {e}"
            ) from e


def analyze_with_openai(
    incidents: List[CorrelatedIncident],
    model: str,
    api_key: str,
) -> None:
    if OpenAI is None:
        raise RuntimeError(
            "The OpenAI SDK is not installed. Install it first with: pip install openai"
        )

    client = OpenAI(api_key=api_key)

    system_prompt = (
        "You are a cybersecurity analyst. Analyze network behavior and Zeek-based IDS incidents. "
        "Be concise, evidence-based, and explain whether the behavior is more consistent with "
        "benign activity, administration, scanning, or adversarial reconnaissance."
    )

    for idx, incident in enumerate(incidents, start=1):
        user_prompt = incident_to_ai_prompt(incident)

        try:
            response = client.responses.create(
                model=model,
                instructions=system_prompt,
                input=user_prompt,
            )
            incident.ai_analysis = response.output_text
        except Exception as e:
            incident.ai_analysis = f"OpenAI analysis failed for incident #{idx}: {e}"
            raise RuntimeError(
                f"OpenAI request failed while using model '{model}'. Original error: {e}"
            ) from e


def print_incidents(incidents: List[CorrelatedIncident]) -> None:
    if not incidents:
        print("No incidents found.")
        return

    for idx, inc in enumerate(incidents, start=1):
        print("=" * 80)
        print(f"Incident #{idx}")
        print(f"Source:      {inc.source}")
        print(f"Time range:  {inc.start_dt}  ->  {inc.end_dt}")
        print(f"Notes:       {', '.join(inc.notes) if inc.notes else '(none)'}")
        print(f"Targets:     {', '.join(inc.distinct_targets) if inc.distinct_targets else '(none)'}")
        print(f"Ports:       {', '.join(inc.distinct_ports) if inc.distinct_ports else '(none)'}")
        print(f"Label:       {inc.heuristic_label}")
        print(f"Confidence:  {inc.confidence}")
        print(f"Why:         {inc.rationale}")
        print("Notice events:")
        for ev in inc.events:
            print(
                f"  - [{ev.dt}] {ev.note} | src={ev.src} dst={ev.dst} "
                f"targets={ev.parsed_targets} ports={ev.parsed_ports} | {ev.msg}"
            )
        if inc.syn_rate_events:
            print("SYN-rate events:")
            for ev in inc.syn_rate_events:
                print(
                    f"  - [{ev.dt}] src={ev.src} syn_count={ev.syn_count} "
                    f"syn_rate={ev.syn_rate:.2f}/s targets={ev.distinct_targets} "
                    f"ports={ev.distinct_ports} internal={ev.internal_targets} external={ev.external_targets}"
                )
        if inc.ai_analysis:
            print("AI Analysis:")
            print(inc.ai_analysis)
        print()


def save_json(path: Path, incidents: List[CorrelatedIncident]) -> None:
    serializable = [asdict(inc) for inc in incidents]
    path.write_text(json.dumps(serializable, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("notice_log", type=Path, help="Path to Zeek notice.log")
    parser.add_argument("syn_rate_log", type=Path, nargs="?", help="Path to Zeek syn_rate.log (optional)")
    parser.add_argument("--window", type=int, default=300, help="Correlation window in seconds for notice clustering")
    parser.add_argument("--attach-padding", type=int, default=120, help="Extra seconds around incident when attaching syn-rate windows")
    parser.add_argument("--json-out", type=Path, help="Write correlated incidents to JSON")

    parser.add_argument("--use-ai", action="store_true", help="Send incidents to an AI provider for analysis")
    parser.add_argument("--provider", choices=["cerebras", "openai"], default="cerebras", help="AI provider to use for analysis")

    parser.add_argument("--cerebras-api-key", "--api-key", dest="cerebras_api_key", help="Cerebras API key")
    parser.add_argument("--cerebras-model", default="gpt-oss-120b", help="Cerebras model ID")
    parser.add_argument("--list-cerebras-models", action="store_true", help="List Cerebras models available to your API key and exit")

    parser.add_argument("--openai-api-key", help="OpenAI API key")
    parser.add_argument("--openai-model", default="gpt-5.4-mini", help="OpenAI model ID")

    args = parser.parse_args()

    cerebras_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None

    if args.list_cerebras_models or (args.use_ai and args.provider == "cerebras"):
        cerebras_api_key = resolve_secret(args.cerebras_api_key, "Enter your Cerebras API key: ")

    if args.use_ai and args.provider == "openai":
        openai_api_key = resolve_secret(args.openai_api_key, "Enter your OpenAI API key: ")

    notice_rows = parse_zeek_tsv(args.notice_log)
    notice_events = normalize_notice_rows(notice_rows)
    incidents = cluster_notice_events(notice_events, args.window)

    if args.syn_rate_log and args.syn_rate_log.exists():
        syn_rows = parse_zeek_tsv(args.syn_rate_log)
        syn_events = normalize_syn_rate_rows(syn_rows)
        attach_syn_rate_events(incidents, syn_events, args.attach_padding)
    else:
        print("No syn_rate.log provided or file not found. Continuing with notice.log only.\n")

    if args.list_cerebras_models:
        try:
            models = list_cerebras_models(cerebras_api_key)
            if models:
                print("Models available to this Cerebras API key:")
                for name in models:
                    print(f"  - {name}")
            else:
                print("No models were returned for this API key.")
        except Exception as e:
            print(f"Failed to list Cerebras models: {e}")
        return

    if args.use_ai:
        try:
            if args.provider == "cerebras":
                analyze_with_cerebras(
                    incidents,
                    model=args.cerebras_model,
                    api_key=cerebras_api_key,
                )
            else:
                analyze_with_openai(
                    incidents,
                    model=args.openai_model,
                    api_key=openai_api_key,
                )
        except Exception as e:
            print(f"AI analysis failed: {e}")
            print("Continuing without AI analysis.\n")

    print_incidents(incidents)

    if args.json_out:
        save_json(args.json_out, incidents)
        print(f"Saved JSON to {args.json_out}")


if __name__ == "__main__":
    main()
