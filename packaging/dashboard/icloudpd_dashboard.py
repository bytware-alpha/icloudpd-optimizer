#!/usr/bin/env python3
"""Read-only iCloudPD Optimizer dashboard for a Tailscale-only listener.

The service deliberately reads durable monitor state and emits aggregate data.
It never serves manifests, paths, asset IDs, hashes, sessions, or credentials.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import ipaddress
import json
import os
import re
import subprocess
import time
from collections import Counter
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable


DEFAULT_HOME = Path.home()
DEFAULT_PRIMARY_CONFIG = DEFAULT_HOME / "icloudpd-optimizer" / "service" / "monitor.json"
DEFAULT_SHARED_CONFIG = DEFAULT_HOME / "icloudpd-optimizer" / "service" / "monitor-shared.json"
DEFAULT_AUDIT = DEFAULT_HOME / "icloudpd-optimizer" / "service" / "recovery-20261103" / "deleted-nas-audit.json"
DEFAULT_DAYS_REMAINING = DEFAULT_HOME / "icloudpd" / "DAYS_REMAINING"
DEFAULT_DOCKER_BIN = "/usr/local/bin/docker"
DEFAULT_DOCKER_CONTEXT = "desktop-linux"
DEFAULT_CONTAINER_NAME = "icloudpd"
DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8787
DEFAULT_STUCK_AGE_SECONDS = 6 * 60 * 60
MAX_LOG_BYTES = 2_000_000


HTML_PAGE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>iCloudPD Optimizer</title>
  <style>
    :root { color-scheme: dark; --bg:#0f172a; --panel:#172033; --muted:#9aa8bd;
      --text:#f1f5f9; --line:#293852; --blue:#66a3ff; --green:#4ade80;
      --amber:#fbbf24; --red:#fb7185; }
    * { box-sizing:border-box; }
    body { margin:0; background:linear-gradient(145deg,#0f172a,#111827 60%,#101b31);
      color:var(--text); font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    main { width:min(1180px,100%); margin:auto; padding:24px 18px 48px; }
    header { display:flex; justify-content:space-between; gap:18px; align-items:flex-start; margin-bottom:22px; }
    h1 { margin:0; font-size:clamp(24px,5vw,36px); letter-spacing:-.03em; }
    h2 { font-size:17px; margin:0 0 12px; }
    .subtitle,.meta,.detail { color:var(--muted); }
    .subtitle { margin-top:5px; }
    .meta { text-align:right; font-size:12px; }
    .status { display:inline-flex; align-items:center; gap:7px; border:1px solid var(--line);
      border-radius:999px; padding:5px 10px; font-size:12px; white-space:nowrap; }
    .dot { width:8px; height:8px; border-radius:50%; background:var(--muted); }
    .ok .dot { background:var(--green); } .warn .dot { background:var(--amber); }
    .bad .dot { background:var(--red); } .info .dot { background:var(--blue); }
    .grid { display:grid; grid-template-columns:repeat(12,1fr); gap:14px; }
    .panel { grid-column:span 12; background:rgba(23,32,51,.9); border:1px solid var(--line);
      border-radius:15px; padding:17px; box-shadow:0 12px 28px rgba(0,0,0,.14); }
    .lane { grid-column:span 6; }
    .health { grid-column:span 3; min-height:124px; }
    .metric-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; }
    .metric { border:1px solid var(--line); border-radius:11px; padding:12px; min-height:88px; }
    .metric .value { font-size:24px; font-weight:700; letter-spacing:-.02em; }
    .metric .label { color:var(--muted); font-size:12px; margin-top:2px; }
    .metric .detail { font-size:11px; margin-top:6px; }
    .health h3 { margin:0 0 5px; font-size:14px; }
    .health p { margin:0; font-size:13px; }
    .health .detail { margin-top:4px; font-size:11px; }
    .audit-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; }
    .audit-item { border:1px solid var(--line); border-radius:11px; padding:12px; }
    .audit-item strong { display:block; font-size:20px; }
    .audit-item span { color:var(--muted); font-size:12px; }
    .audit-list { margin:8px 0 0; padding-left:18px; color:var(--muted); font-size:12px; }
    .audit-list li { margin:3px 0; }
    .lane-head { display:flex; justify-content:space-between; align-items:flex-start; gap:10px; margin-bottom:12px; }
    .lane-head h2 { margin:0; }
    .small { font-size:12px; color:var(--muted); }
    .empty { color:var(--muted); padding:6px 0; }
    .notice { margin-top:12px; border-left:3px solid var(--amber); padding:8px 10px; color:#fde68a;
      background:rgba(251,191,36,.08); font-size:12px; }
    .error { color:#fecdd3; }
    @media (max-width:800px) { .lane,.health { grid-column:span 12; }
      .metric-grid { grid-template-columns:repeat(2,1fr); } .audit-grid { grid-template-columns:1fr; }
      header { flex-direction:column; } .meta { text-align:left; } }
    @media (max-width:430px) { main { padding:18px 12px 36px; } .metric-grid { grid-template-columns:1fr 1fr; gap:7px; }
      .panel { padding:13px; } .metric { padding:9px; } .metric .value { font-size:20px; } }
  </style>
</head>
<body>
<main>
  <header>
    <div><h1>iCloudPD Optimizer</h1><div class="subtitle">Read-only home Mac status · Tailscale</div></div>
    <div class="meta"><div id="overall" class="status info"><span class="dot"></span><span>Loading</span></div><div id="updated" style="margin-top:6px"></div></div>
  </header>
  <section id="health" class="grid" aria-live="polite"></section>
  <section id="lanes" class="grid" style="margin-top:14px" aria-live="polite"></section>
  <section id="audit" class="panel" style="margin-top:14px" aria-live="polite"></section>
  <section class="panel" style="margin-top:14px"><div class="small">Evidence boundary</div>
    <div class="detail" style="margin-top:5px">Counts and space saved come from local manifest proof records. A recorded receipt is shown separately from a live hash verification. A missing Recently Deleted result does not establish recovery.</div>
  </section>
</main>
<script>
const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = (n) => typeof n === 'number' ? new Intl.NumberFormat().format(n) : '--';
const bytes = (n) => {
  if (typeof n !== 'number') return '--';
  const units=['B','KiB','MiB','GiB','TiB']; let x=n, i=0;
  while (Math.abs(x)>=1024 && i<units.length-1) { x/=1024; i++; }
  return `${x.toFixed(i ? 1 : 0)} ${units[i]}`;
};
const tone = (s) => s === 'ok' || s === 'running' || s === 'mounted' || s === 'ready' ? 'ok' : (s === 'error' || s === 'missing' || s === 'unavailable' ? 'bad' : 'warn');
const badge = (label, status) => `<span class="status ${tone(status)}"><span class="dot"></span><span>${esc(label)}</span></span>`;
function healthCard(item) {
  return `<article class="panel health"><h3>${esc(item.title)}</h3><p>${badge(item.label, item.status)}</p><div class="detail">${esc(item.detail || '')}</div></article>`;
}
function metric(label, value, detail) {
  return `<div class="metric"><div class="value">${esc(value)}</div><div class="label">${esc(label)}</div><div class="detail">${esc(detail || '')}</div></div>`;
}
function render(data) {
  const h=data.health || {}; const cards=[];
  for (const key of ['primary_monitor','shared_monitor','mount','sync','container']) if (h[key]) cards.push(healthCard(h[key]));
  $('health').innerHTML=cards.join('');
  const lanes=(data.lanes || []).map(l => {
    const m=l.metrics || {}, p=l.progress || {};
    const saved=m.space_saved || {};
    const savedText=saved.status === 'unavailable' ? '--' : bytes(saved.bytes);
    const savedDetail=saved.status === 'exact' ? 'calculated from recorded RAW/HEIC sizes; quota not queried' : (saved.status === 'partial' ? `${fmt(saved.missing_records)} deleted records missing size proofs; quota not queried` : (saved.detail || 'unavailable'));
    const eta=p.eta || 'unknown (no recent throughput)';
    const deletion=l.deletion || {label:'Deletion status unknown',status:'unknown'};
    return `<article class="panel lane"><div class="lane-head"><h2>${esc(l.name)}</h2><div>${badge(l.health.label,l.health.status)} ${badge(deletion.label,deletion.status)}</div></div>
      <div class="metric-grid">
        ${metric('Records',fmt(m.total_records),`${fmt(m.terminal_records)} terminal · ${fmt(m.pending_records)} pending`)}
        ${metric('NAS proof records',fmt(m.nas_proof_records),`${fmt(m.state_counts?.nas_verified || 0)} currently at NAS stage`)}
        ${metric('Uploaded replacements',fmt(m.uploaded_replacements),`${bytes(m.uploaded_heic_bytes)} HEIC bytes`)}
        ${metric('Deleted originals',fmt(m.deleted_originals),`${bytes(m.deleted_raw_bytes)} RAW bytes`)}
        ${metric('Estimated iCloud space saved',savedText,savedDetail)}
        ${metric('Needs review',fmt(m.needs_review_records),`${fmt(m.failed_records)} failed · ${fmt(m.stuck_pending_records)} stuck${m.review_reason_summary ? ` · ${m.review_reason_summary}` : ''}`)}
        ${metric('Recent throughput',p.throughput_label,p.throughput_detail)}
        ${metric('Progress ETA',eta,p.eta_detail || 'ETA is unknown without observed throughput')}
      </div>
      <div class="small" style="margin-top:10px">Pending stages: ${esc(Object.entries(m.pending_stage_counts || {}).map(([k,v]) => `${k} ${fmt(v)}`).join(' · ') || 'none')} · Effect unknown: upload ${fmt(m.upload_effect_unknown_records)} · Shared move ${fmt(m.shared_move_effect_unknown_records)} · live check ${new Date(l.live_checked_at*1000).toLocaleTimeString()}</div>
      ${l.warning ? `<div class="notice">${esc(l.warning)}</div>` : ''}
    </article>`;
  });
  $('lanes').innerHTML=lanes.join('') || '<article class="panel"><div class="empty">No lane data available.</div></article>';
  const a=data.audit || {};
  const ap=a.progress || {};
  const duration=(seconds) => {
    if (typeof seconds !== 'number' || !Number.isFinite(seconds)) return '--';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.round(seconds/60)}m`;
    return `${(seconds/3600).toFixed(1)}h`;
  };
  const progressValue=ap.completed == null || ap.total == null ? '--' : `${fmt(ap.completed)} / ${fmt(ap.total)}`;
  const progressDetail=ap.stale ? 'progress file is stale; ETA withheld' : `${ap.age_seconds == null ? 'age unknown' : `${Math.round(ap.age_seconds/60)}m old`} · source ${ap.source || 'unknown'}`;
  const etaValue=ap.stale ? 'unknown (stale)' : duration(ap.eta_seconds);
  const issueSummary=Object.entries(a.issue_counts || {}).map(([key,value]) => `${key} ${fmt(value)}`).join(' · ');
  const reasonSummary=Object.entries(a.reason_counts || {}).map(([key,value]) => `${key} ${fmt(value)}`).join(' · ');
  const source=a.verification_source || {};
  const sourceDetail=source.verifier_host ? `live NAS hashes verified by ${source.verifier_host}${source.nas_source ? ` · source ${source.nas_source}` : ''}` : 'live verifier source not recorded';
  const examples=(a.issue_examples || []).map(item => {
    const subject=item.filename || item.asset_id || 'record';
    const id=item.asset_id ? ` · asset ${item.asset_id}` : '';
    return `<li>${esc(item.status || 'issue')} · ${esc(subject)}${esc(id)}${item.reason && item.reason !== item.status ? ` · ${esc(item.reason)}` : ''}</li>`;
  }).join('');
  $('audit').innerHTML=`<h2>Deleted NAS verification</h2><div class="small">${esc(a.detail || 'No audit result')}</div><div class="small" style="margin-top:5px">${esc(sourceDetail)} · home Mac NAS mount is reported separately above</div><div class="audit-grid" style="margin-top:12px">
    <div class="audit-item"><strong>${a.recorded_deleted?.count == null ? '--' : fmt(a.recorded_deleted.count)}</strong><span>deleted receipts</span></div>
    <div class="audit-item"><strong>${a.recorded_delete_review?.count == null ? '--' : fmt(a.recorded_delete_review.count)}</strong><span>delete-review receipts</span></div>
    <div class="audit-item"><strong>${a.live_hash_verification?.count == null ? '--' : fmt(a.live_hash_verification.count)}</strong><span>live hash verifications</span></div>
    <div class="audit-item"><strong>${a.unverified?.count == null ? '--' : fmt(a.unverified.count)}</strong><span>deleted not live-verified</span></div>
    <div class="audit-item"><strong>${a.unverified_delete_review?.count == null ? '--' : fmt(a.unverified_delete_review.count)}</strong><span>delete-review not live-verified</span></div>
    <div class="audit-item"><strong>${a.missing?.count == null ? '--' : fmt(a.missing.count)}</strong><span>classified missing</span></div>
    <div class="audit-item"><strong>${esc(progressValue)}</strong><span>audit progress (completed / total)</span><div class="detail">${esc(progressDetail)}</div></div>
    <div class="audit-item"><strong>${ap.bytes_per_second == null ? '--' : `${fmt(Math.round(ap.bytes_per_second))} B/s`}</strong><span>audit hash rate</span></div>
    <div class="audit-item"><strong>${esc(etaValue)}</strong><span>audit ETA</span><div class="detail">${ap.eta_seconds == null ? 'writer did not provide a usable ETA' : 'from audit progress'}</div></div>
  </div>${issueSummary ? `<div class="small" style="margin-top:12px">Issue statuses: ${esc(issueSummary)}</div>` : ''}${reasonSummary ? `<div class="small" style="margin-top:5px">Issue reasons: ${esc(reasonSummary)}</div>` : ''}${examples ? `<div class="small" style="margin-top:12px">Issue examples (basename / asset ID only)<ul class="audit-list">${examples}</ul></div>` : ''}${a.recovery_statement ? `<div class="notice">${esc(a.recovery_statement)}</div>` : ''}`;
  const statuses=[...Object.values(h).map(x=>x.status), ...(data.lanes||[]).map(x=>x.health.status), data.audit?.status];
  const overall=statuses.includes('error')?'error':(statuses.some(s=>['missing','unavailable','unknown','stopped','blocked','exited','degraded','stale','partial'].includes(s))?'warning':'ok');
  $('overall').className=`status ${overall==='ok'?'ok':'warn'}`; $('overall').innerHTML=`<span class="dot"></span><span>${overall==='ok'?'Observed':'Review status'}</span>`;
  $('updated').textContent=`updated ${new Date(data.generated_at*1000).toLocaleString()}`;
}
async function refresh() { try { const r=await fetch('/api/status',{cache:'no-store'}); render(await r.json()); } catch(e) { $('overall').className='status bad'; $('overall').innerHTML='<span class="dot"></span><span>Dashboard unavailable</span>'; } }
refresh(); setInterval(refresh,15000);
</script>
</body>
</html>"""


def _json_object(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _read_json(path: Path) -> Any | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError, TypeError):
        return None


def _read_tail(path: Path, maximum: int = MAX_LOG_BYTES) -> str:
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > maximum:
                handle.seek(size - maximum)
            return handle.read(maximum).decode("utf-8", "replace")
    except OSError:
        return ""


def _as_records(manifest: Any) -> list[dict[str, Any]]:
    if not isinstance(manifest, dict):
        return []
    raw = manifest.get("records")
    if isinstance(raw, dict):
        return [item for item in raw.values() if isinstance(item, dict)]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    return []


def _size(proofs: dict[str, Any], key: str) -> int | None:
    value = proofs.get(key)
    if not isinstance(value, dict):
        return None
    value = value.get("size_bytes")
    return value if isinstance(value, int) and value >= 0 else None


def _timestamp(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        raw = value.strip()
        if raw.endswith("Z"):
            numeric = raw[:-1]
            try:
                return float(numeric)
            except ValueError:
                pass
        try:
            text = raw.replace("Z", "+00:00")
            return dt.datetime.fromisoformat(text).timestamp()
        except ValueError:
            try:
                return float(value)
            except ValueError:
                return None
    return None


def _format_rate(count: int, covered_seconds: float) -> str:
    if count <= 0 or covered_seconds <= 0:
        return "0/hr"
    return f"{count * 3600 / covered_seconds:.1f}/hr"


def _parse_events(text: str, now: float) -> dict[str, Any]:
    events: list[tuple[float, str, dict[str, Any]]] = []
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(event, dict):
            continue
        stamp = _timestamp(event.get("at_unix_seconds", event.get("t_unix_seconds")))
        name = event.get("event")
        if stamp is None or not isinstance(name, str):
            continue
        age = now - stamp
        if 0 <= age <= 15 * 60:
            fields = event.get("fields") if isinstance(event.get("fields"), dict) else {}
            events.append((age, name, fields))
    if not events:
        return {"uploads": 0, "conversions": 0, "deletes": 0, "bytes_saved": 0, "covered_seconds": 0.0}
    uploads = conversions = deletes = bytes_saved = 0
    for _age, name, fields in events:
        if name == "upload_finished" and fields.get("uploaded") is True:
            uploads += 1
        elif name == "conversion_finished" and fields.get("converted") is True:
            conversions += 1
        elif name == "delete_batch_finished":
            value = fields.get("recorded_deletes")
            if isinstance(value, int) and value >= 0:
                deletes += value
            value = fields.get("bytes_saved")
            if isinstance(value, int) and value >= 0:
                bytes_saved += value
    covered = min(15 * 60, max(age for age, _name, _fields in events))
    return {"uploads": uploads, "conversions": conversions, "deletes": deletes, "bytes_saved": bytes_saved, "covered_seconds": covered}


def _latest_log_path(config_path: Path, config: dict[str, Any]) -> Path:
    configured = config.get("stderr_log_path") or config.get("log_path")
    if isinstance(configured, str) and configured:
        return Path(configured).expanduser()
    # The LaunchAgent currently derives these paths from the config basename.
    return config_path.with_suffix(".stderr.log")


def _launch_health(label: str) -> dict[str, Any]:
    try:
        uid = str(os.getuid())
        result = subprocess.run(
            ["/bin/launchctl", "print", f"gui/{uid}/{label}"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {"status": "unknown", "label": "Monitor query unknown", "detail": "launchd query unavailable"}
    if result.returncode != 0:
        return {"status": "unavailable", "label": "Monitor unavailable", "detail": "launchd job is not queryable"}
    output = result.stdout + result.stderr
    if "state = running" in output:
        return {"status": "running", "label": "Monitor running", "detail": "launchd reports running"}
    return {"status": "stopped", "label": "Monitor stopped", "detail": "launchd job is loaded but not running"}


def _mount_health(path: str | None) -> dict[str, Any]:
    if not path:
        return {"status": "unknown", "label": "Mount unknown", "detail": "no configured mount root"}
    root = Path(path).expanduser()
    hint = root.name or "configured mount"
    if not root.exists():
        return {"status": "missing", "label": "Mount unavailable", "detail": f"{hint} is not present"}
    if os.path.ismount(root):
        return {"status": "mounted", "label": "Mount present", "detail": f"{hint} is mounted"}
    return {"status": "unknown", "label": "Mount not verified", "detail": f"{hint} exists but is not an observed mount"}


def _sync_health(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8").strip()
        remaining = int(raw)
        age = max(0.0, time.time() - path.stat().st_mtime)
    except (OSError, ValueError):
        return {"status": "unknown", "label": "Sync unknown", "detail": "DAYS_REMAINING is unavailable"}
    detail = f"DAYS_REMAINING reports {remaining}"
    if age > 24 * 60 * 60:
        detail += "; value is older than 24h"
        return {"status": "stale", "label": "Sync report stale", "detail": detail}
    return {"status": "ready" if remaining == 0 else "reported", "label": "Sync report observed", "detail": detail}


def _docker_container_observation(
    docker_bin: str,
    docker_context: str,
    container_name: str,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Read the named container state without invoking any Docker mutation."""
    command = [
        docker_bin,
        "--context",
        docker_context,
        "container",
        "inspect",
        "--format",
        "{{json .State}}",
        container_name,
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return {"state": "unavailable", "reason": "docker_binary_missing"}
    except subprocess.TimeoutExpired:
        return {"state": "unavailable", "reason": "docker_inspection_timeout"}
    except OSError:
        return {"state": "unavailable", "reason": "docker_inspection_failed"}
    if result.returncode != 0:
        stderr = result.stderr.lower()
        if "no such object" in stderr or "no such container" in stderr:
            reason = "container_missing"
            state = "missing"
        elif "cannot connect" in stderr or "is the docker daemon running" in stderr:
            reason = "docker_daemon_unavailable"
            state = "unavailable"
        else:
            reason = "docker_inspection_failed"
            state = "unavailable"
        return {"state": state, "reason": reason}
    try:
        payload = json.loads(result.stdout.strip())
    except (ValueError, TypeError):
        return {"state": "unavailable", "reason": "docker_state_invalid"}
    if not isinstance(payload, dict):
        return {"state": "unavailable", "reason": "docker_state_invalid"}
    state = payload.get("Status")
    health = payload.get("Health")
    health_status = health.get("Status") if isinstance(health, dict) else None
    return {
        "state": state if isinstance(state, str) else "unknown",
        "health": health_status if isinstance(health_status, str) else None,
        "exit_code": payload.get("ExitCode") if isinstance(payload.get("ExitCode"), int) else None,
    }


def _container_health(
    docker_bin: str = DEFAULT_DOCKER_BIN,
    docker_context: str = DEFAULT_DOCKER_CONTEXT,
    container_name: str = DEFAULT_CONTAINER_NAME,
) -> dict[str, Any]:
    observation = _docker_container_observation(docker_bin, docker_context, container_name)
    state = observation.get("state")
    health = observation.get("health")
    if state == "running" and health in {None, "healthy"}:
        detail = f"{container_name} is running via Docker context {docker_context}"
        if health == "healthy":
            detail += " and reports healthy"
        else:
            detail += "; no Docker health check is configured"
        return {"status": "running", "label": "Container running", "detail": detail}
    if state == "running" and health == "unhealthy":
        return {
            "status": "degraded",
            "label": "Container unhealthy",
            "detail": f"{container_name} is running but Docker reports unhealthy",
        }
    if state == "running" and health == "starting":
        return {
            "status": "degraded",
            "label": "Container health starting",
            "detail": f"{container_name} is running; Docker health is still starting",
        }
    if state in {"exited", "dead", "stopped"}:
        exit_code = observation.get("exit_code")
        suffix = f" (exit code {exit_code})" if isinstance(exit_code, int) else ""
        return {
            "status": "exited",
            "label": "Container exited",
            "detail": f"{container_name} is {state}{suffix}; no restart was attempted",
        }
    if state == "restarting":
        return {
            "status": "degraded",
            "label": "Container restarting",
            "detail": f"{container_name} is restarting; no restart was attempted",
        }
    if state == "missing":
        return {
            "status": "missing",
            "label": "Container missing",
            "detail": f"Docker context {docker_context} cannot find {container_name}",
        }
    reason = observation.get("reason")
    detail = "Docker container inspection is unavailable"
    if reason == "docker_daemon_unavailable":
        detail = f"Docker context {docker_context} is unavailable"
    elif reason == "docker_binary_missing":
        detail = f"Docker binary {docker_bin} is unavailable"
    elif reason == "docker_inspection_timeout":
        detail = "Docker container inspection timed out"
    return {"status": "unavailable", "label": "Container inspection unavailable", "detail": detail}


def _find_count(data: Any, names: Iterable[str]) -> int | None:
    wanted = {name.lower() for name in names}
    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in wanted and isinstance(value, int) and value >= 0:
                return value
        for value in data.values():
            found = _find_count(value, wanted)
            if found is not None:
                return found
    elif isinstance(data, list):
        for value in data:
            found = _find_count(value, wanted)
            if found is not None:
                return found
    return None


AUDIT_PROGRESS_STALE_SECONDS = 15 * 60
AUDIT_EXAMPLE_LIMIT = 20


def _safe_basename(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("\\", "/").rstrip("/")
    basename = normalized.rsplit("/", 1)[-1]
    return basename if basename and basename not in {".", ".."} else None


def _audit_verification_source(data: dict[str, Any]) -> dict[str, str | None]:
    verifier = data.get("verifier_host") if isinstance(data.get("verifier_host"), str) else None
    source = data.get("nas_source") if isinstance(data.get("nas_source"), str) else None
    if verifier:
        verifier = verifier.strip()[:80] or None
    if source:
        # The writer supplies a redacted SMB source. Strip any accidental
        # query or user-info component before showing it on the Tailscale UI.
        source = source.strip().split("?", 1)[0]
        if "@" in source:
            source = source.rsplit("@", 1)[-1]
        source = source[:160] or None
    return {"verifier_host": verifier, "nas_source": source}


def _audit_records(data: dict[str, Any]) -> list[dict[str, Any]]:
    raw = data.get("records")
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def _audit_issue_summary(records: list[dict[str, Any]], reported_issues: Any) -> dict[str, Any]:
    status_counts: Counter[str] = Counter()
    reason_counts: Counter[str] = Counter()
    cohort_issue_counts: dict[str, Counter[str]] = {
        "deleted": Counter(),
        "delete_review": Counter(),
    }
    verified_by_cohort: Counter[str] = Counter()
    examples: list[dict[str, Any]] = []
    for row in records:
        status = row.get("status") if isinstance(row.get("status"), str) else "unknown"
        cohort = row.get("cohort") if row.get("cohort") in {"deleted", "delete_review"} else "unknown"
        if status == "verified":
            if cohort in {"deleted", "delete_review"}:
                verified_by_cohort[cohort] += 1
            continue
        status_counts[status] += 1
        reason = row.get("reason") if isinstance(row.get("reason"), str) and row.get("reason") else status
        reason_counts[reason] += 1
        if cohort in cohort_issue_counts:
            cohort_issue_counts[cohort][status] += 1
        if len(examples) < AUDIT_EXAMPLE_LIMIT:
            examples.append({
                "library": row.get("library") if isinstance(row.get("library"), str) else None,
                "cohort": cohort,
                "status": status,
                "reason": reason,
                "asset_id": row.get("asset_id") if isinstance(row.get("asset_id"), str) else None,
                "filename": _safe_basename(row.get("canonical_path")) or _safe_basename(row.get("resolved_path")),
            })
    issue_total = sum(status_counts.values())
    if not records and isinstance(reported_issues, int) and reported_issues >= 0:
        issue_total = reported_issues
    return {
        "status_counts": dict(status_counts),
        "reason_counts": dict(reason_counts),
        "cohort_issue_counts": {key: dict(value) for key, value in cohort_issue_counts.items()},
        "verified_by_cohort": dict(verified_by_cohort),
        "issue_total": issue_total,
        "examples": examples,
    }


def _audit_progress(progress: dict[str, Any], audit_status: str | None, path: Path, fallback_total: int) -> dict[str, Any]:
    def nonnegative_int(key: str) -> int | None:
        value = progress.get(key)
        return value if isinstance(value, int) and value >= 0 else None

    def nonnegative_number(key: str) -> float | None:
        value = progress.get(key)
        return float(value) if isinstance(value, (int, float)) and value >= 0 else None

    total = nonnegative_int("total")
    used_fallback_total = total is None or (total == 0 and fallback_total)
    if used_fallback_total:
        total = fallback_total or total
    completed = nonnegative_int("completed")
    verified = nonnegative_int("verified")
    bytes_hashed = nonnegative_int("bytes_hashed")
    elapsed_seconds = nonnegative_number("elapsed_seconds")
    bytes_per_second = nonnegative_number("bytes_per_second")
    eta_seconds = nonnegative_number("eta_seconds")
    if completed is None and verified is not None:
        completed = verified
    try:
        age_seconds = max(0.0, time.time() - path.stat().st_mtime)
    except OSError:
        age_seconds = None
    stale = bool(audit_status == "running" and age_seconds is not None and age_seconds > AUDIT_PROGRESS_STALE_SECONDS)
    return {
        "completed": completed,
        "total": total,
        "verified": verified,
        "bytes_hashed": bytes_hashed,
        "elapsed_seconds": elapsed_seconds,
        "bytes_per_second": bytes_per_second,
        "eta_seconds": None if stale else eta_seconds,
        "age_seconds": age_seconds,
        "stale": stale,
        "source": "audit_progress" if progress and not used_fallback_total else ("known_manifest_cohort" if fallback_total else "unknown"),
    }


def _audit_snapshot(path: Path, known_deleted: int = 0, known_delete_review: int = 0) -> dict[str, Any]:
    data = _read_json(path)
    known_total = (known_deleted or 0) + (known_delete_review or 0)
    if data is None:
        return {
            "status": "missing",
            "detail": "Deleted NAS audit is not present",
            "recorded_deleted": {"count": known_deleted or None},
            "recorded_delete_review": {"count": known_delete_review or None},
            "live_hash_verification": {"count": None},
            "unverified": {"count": known_deleted if known_deleted else None},
            "unverified_delete_review": {"count": known_delete_review if known_delete_review else None},
            "unverified_total": {"count": known_total or None},
            "missing": {"count": None},
            "progress": _audit_progress({}, "missing", path, known_total),
            "issue_counts": {},
            "reason_counts": {},
            "issue_examples": [],
            "verification_source": {"verifier_host": None, "nas_source": None},
            "recovery_statement": "No audit result is not evidence that a deleted NAS original can be recovered.",
        }
    audit_status = data.get("status") if isinstance(data.get("status"), str) else None
    counts = data.get("counts") if isinstance(data.get("counts"), dict) else {}
    progress = data.get("progress") if isinstance(data.get("progress"), dict) else {}
    records = _audit_records(data)
    deleted_count = counts.get("deleted") if isinstance(counts.get("deleted"), int) else (known_deleted or None)
    delete_review_count = counts.get("delete_review") if isinstance(counts.get("delete_review"), int) else (known_delete_review or None)
    cohort_total = (deleted_count or 0) + (delete_review_count or 0)
    summary = _audit_issue_summary(records, counts.get("issues"))
    verification_source = _audit_verification_source(data)
    verified = counts.get("verified") if isinstance(counts.get("verified"), int) else None
    if audit_status == "running":
        verified = progress.get("verified") if isinstance(progress.get("verified"), int) else verified
    if audit_status == "blocked_mount_missing":
        verified = 0
    progress_view = _audit_progress(progress, audit_status, path, cohort_total)
    if verified is None:
        verified = progress_view.get("verified")
    total = progress_view.get("total")
    aggregate_unverified = max(total - verified, 0) if isinstance(total, int) and isinstance(verified, int) else None
    verified_by_cohort = summary["verified_by_cohort"]
    if records and deleted_count is not None:
        unverified_deleted = max(deleted_count - verified_by_cohort.get("deleted", 0), 0)
    elif audit_status == "blocked_mount_missing":
        unverified_deleted = deleted_count
    else:
        unverified_deleted = None
    if records and delete_review_count is not None:
        unverified_review = max(delete_review_count - verified_by_cohort.get("delete_review", 0), 0)
    elif audit_status == "blocked_mount_missing":
        unverified_review = delete_review_count
    else:
        unverified_review = None
    unverified_deleted = unverified_deleted if unverified_deleted is not None else aggregate_unverified
    unverified_total = aggregate_unverified
    missing_count = summary["status_counts"].get("missing", 0) if records else None
    if audit_status == "blocked_mount_missing":
        return {
            "status": "blocked",
            "detail": "Audit blocked because the NAS mount is unavailable; no originals were classified as missing",
            "recorded_deleted": {"count": deleted_count},
            "recorded_delete_review": {"count": delete_review_count},
            "live_hash_verification": {"count": 0},
            "unverified": {"count": unverified_deleted},
            "unverified_delete_review": {"count": unverified_review},
            "unverified_total": {"count": known_total or None},
            "missing": {"count": None},
            "progress": progress_view,
            "issue_counts": summary["status_counts"],
            "reason_counts": summary["reason_counts"],
            "issue_examples": summary["examples"],
            "verification_source": verification_source,
            "recovery_statement": "Mount absence leaves the known deleted cohort unverified; it is not evidence of loss or recovery.",
        }
    if audit_status == "manifest_read_failed":
        return {
            "status": "error",
            "detail": "Audit could not read the manifest; verification counts are unavailable",
            "recorded_deleted": {"count": None},
            "recorded_delete_review": {"count": None},
            "live_hash_verification": {"count": None},
            "unverified": {"count": None},
            "unverified_delete_review": {"count": None},
            "unverified_total": {"count": None},
            "missing": {"count": None},
            "progress": progress_view,
            "issue_counts": summary["status_counts"],
            "reason_counts": summary["reason_counts"],
            "issue_examples": summary["examples"],
            "verification_source": verification_source,
            "recovery_statement": "No recovery conclusion is available until the manifest and NAS mount are readable.",
        }
    if audit_status == "running":
        return {
            "status": "partial",
            "detail": "Audit is still running; live hash verification is incomplete" if not progress_view["stale"] else "Audit progress is stale; live hash verification is incomplete",
            "recorded_deleted": {"count": deleted_count},
            "recorded_delete_review": {"count": delete_review_count},
            "live_hash_verification": {"count": verified},
            "unverified": {"count": unverified_deleted},
            "unverified_delete_review": {"count": unverified_review},
            "unverified_total": {"count": aggregate_unverified},
            "missing": {"count": missing_count},
            "progress": progress_view,
            "issue_counts": summary["status_counts"],
            "reason_counts": summary["reason_counts"],
            "issue_examples": summary["examples"],
            "verification_source": verification_source,
            "recovery_statement": "A running audit does not establish recovery for records not yet verified.",
        }
    if audit_status in {"complete", "complete_with_issues"}:
        complete_total = cohort_total or progress_view.get("total")
        complete_unverified = max(complete_total - verified, 0) if isinstance(complete_total, int) and isinstance(verified, int) else (summary["issue_total"] if isinstance(summary["issue_total"], int) else None)
        progress_view["total"] = complete_total
        return {
            "status": "ok" if audit_status == "complete" else "partial",
            "detail": "Live hash verification complete" if audit_status == "complete" else "Live hash verification complete with issues",
            "recorded_deleted": {"count": deleted_count},
            "recorded_delete_review": {"count": delete_review_count},
            "live_hash_verification": {"count": verified},
            "unverified": {"count": unverified_deleted if unverified_deleted is not None else complete_unverified},
            "unverified_delete_review": {"count": unverified_review},
            "unverified_total": {"count": complete_unverified},
            "missing": {"count": missing_count},
            "progress": progress_view,
            "issue_counts": summary["status_counts"],
            "reason_counts": summary["reason_counts"],
            "issue_examples": summary["examples"],
            "verification_source": verification_source,
            "recovery_statement": "Recently Deleted state is not inferred from NAS absence; use the recorded audit status and evidence.",
        }
    detail = "Audit file is present but its verification status is not recognized"
    return {
        "status": "partial",
        "detail": detail,
        "recorded_deleted": {"count": deleted_count},
        "recorded_delete_review": {"count": delete_review_count},
        "live_hash_verification": {"count": verified},
        "unverified": {"count": unverified_deleted},
        "unverified_delete_review": {"count": unverified_review},
        "unverified_total": {"count": aggregate_unverified},
        "missing": {"count": missing_count},
        "progress": progress_view,
        "issue_counts": summary["status_counts"],
        "reason_counts": summary["reason_counts"],
        "issue_examples": summary["examples"],
        "verification_source": verification_source,
        "recovery_statement": "A missing Recently Deleted result is not evidence that recovery is possible.",
    }


def _pending_stage_counts(states: Counter[str]) -> dict[str, int]:
    stages = {
        "discovered": "NAS proof",
        "nas_verified": "original match",
        "converted": "HEIC verification",
        "conversion_verified": "upload",
        "upload_verified": "NAS mirror",
        "delete_eligible": "delete gate",
        "delete_approved": "delete gate",
        "failed": "failed",
        "needs_review": "review",
    }
    counts: Counter[str] = Counter()
    for state, count in states.items():
        stage = stages.get(state)
        if stage and count:
            counts[stage] += count
    return dict(counts)


def _lane_snapshot(name: str, config_path: Path, now: float, monitor_label: str, stuck_age: int) -> dict[str, Any]:
    config = _read_json(config_path)
    config = config if isinstance(config, dict) else {}
    manifest_path = Path(config.get("manifest_path", "")) if isinstance(config.get("manifest_path"), str) else None
    stats_path = Path(config.get("stats_path", "")) if isinstance(config.get("stats_path"), str) else None
    manifest = _read_json(manifest_path) if manifest_path else None
    stats = _read_json(stats_path) if stats_path else None
    records = _as_records(manifest)
    states = Counter(str(record.get("state", "unknown")) for record in records)
    terminal_states = {"deleted", "no_action", "needs_review"}
    failed = states.get("failed", 0)
    pending = sum(value for state, value in states.items() if state not in terminal_states and state != "failed")
    nas = uploaded = uploaded_bytes = uploaded_missing = deleted = deleted_raw = deleted_heic = deleted_missing = 0
    upload_effect_unknown = shared_move_effect_unknown = 0
    delete_review_cohort = 0
    review_reasons: Counter[str] = Counter()
    for record in records:
        proofs = record.get("proofs") if isinstance(record.get("proofs"), dict) else {}
        if isinstance(proofs.get("nas"), dict):
            nas += 1
        if "upload" in proofs:
            uploaded += 1
            heic_bytes = _size(proofs, "heic")
            if heic_bytes is None:
                uploaded_missing += 1
            else:
                uploaded_bytes += heic_bytes
        if "upload_effect_unknown" in proofs:
            upload_effect_unknown += 1
        if "shared_move_effect_unknown" in proofs:
            shared_move_effect_unknown += 1
        if record.get("state") == "needs_review":
            review = proofs.get("delete_recently_deleted_review")
            if isinstance(review, dict):
                delete_review_cohort += 1
            disposition = review.get("disposition") if isinstance(review, dict) else None
            if not isinstance(disposition, str) or not disposition:
                failures = record.get("failures") if isinstance(record.get("failures"), list) else []
                disposition = next((item.get("stage") for item in failures if isinstance(item, dict) and isinstance(item.get("stage"), str)), "needs_review")
            review_reasons[disposition] += 1
        if record.get("state") != "deleted":
            continue
        deleted += 1
        raw_bytes = _size(proofs, "nas")
        replacement_bytes = _size(proofs, "icloudpd_local_mirror")
        if raw_bytes is None or replacement_bytes is None:
            deleted_missing += 1
        else:
            deleted_raw += raw_bytes
            deleted_heic += replacement_bytes
    saved_bytes = max(0, deleted_raw - deleted_heic)
    if deleted_missing == 0:
        saved_status = "exact"
    elif deleted_raw or deleted_heic:
        saved_status = "partial"
    else:
        saved_status = "unavailable"
    stale_pending = 0
    unknown_pending_timestamps = 0
    for record in records:
        state = record.get("state")
        if state in terminal_states or state == "failed":
            continue
        stamp = _timestamp(record.get("updated_at"))
        if stamp is None:
            unknown_pending_timestamps += 1
        elif now - stamp >= stuck_age:
            stale_pending += 1
    events = _parse_events(_read_tail(_latest_log_path(config_path, config)), now)
    throughput_total = events["uploads"] + events["conversions"] + events["deletes"]
    covered = events["covered_seconds"]
    if throughput_total:
        throughput_label = f"{throughput_total} events"
        throughput_detail = f"uploads {events['uploads']} · conversions {events['conversions']} · deletes {events['deletes']} · {_format_rate(throughput_total, covered)}"
        rate_per_hour = throughput_total * 3600 / max(covered, 1)
        eta = f"{pending / rate_per_hour:.1f}h" if pending else "none"
        eta_detail = "proxy from recent observed events"
    else:
        throughput_label = "0 events"
        throughput_detail = "no recent throughput in the observed 15m window"
        eta = "unknown (no recent throughput)"
        eta_detail = "ETA stays unknown until throughput is observed"
    mount_path = config.get("smb_expected_mount_root") if isinstance(config.get("smb_expected_mount_root"), str) else None
    monitor = _launch_health(monitor_label)
    metrics = {
        "total_records": len(records),
        "terminal_records": sum(states.get(state, 0) for state in terminal_states),
        "pending_records": pending,
        "nas_proof_records": nas,
        "uploaded_replacements": uploaded,
        "uploaded_heic_bytes": uploaded_bytes,
        "uploaded_records_missing_size_proofs": uploaded_missing,
        "deleted_originals": deleted,
        "deleted_raw_bytes": deleted_raw,
        "deleted_replacement_heic_bytes": deleted_heic,
        "needs_review_records": states.get("needs_review", 0),
        "failed_records": failed,
        "stuck_pending_records": stale_pending,
        "unknown_pending_timestamps": unknown_pending_timestamps,
        "upload_effect_unknown_records": upload_effect_unknown,
        "shared_move_effect_unknown_records": shared_move_effect_unknown,
        "delete_review_cohort_records": delete_review_cohort,
        "review_reason_counts": dict(review_reasons),
        "review_reason_summary": ", ".join(f"{key} {value}" for key, value in review_reasons.most_common(2)),
        "state_counts": dict(states),
        "pending_stage_counts": _pending_stage_counts(states),
        "space_saved": {
            "status": saved_status,
            "bytes": saved_bytes if saved_status != "unavailable" else None,
            "missing_records": deleted_missing,
            "detail": "lifetime size metric unavailable" if saved_status == "unavailable" else None,
        },
    }
    auto_delete = _bool_setting(config.get("auto_delete"))
    if auto_delete is False:
        deletion = {"status": "paused", "label": "Deletion paused", "detail": "auto_delete=false in lane config"}
    elif auto_delete is True:
        deletion = {"status": "enabled", "label": "Deletion enabled", "detail": "auto_delete=true in lane config"}
    else:
        deletion = {"status": "unknown", "label": "Deletion status unknown", "detail": "auto_delete is absent or invalid"}
    warning = None
    if deleted_missing:
        warning = f"Space saved is {saved_status}; {deleted_missing} deleted records lack complete size proofs."
    if not records:
        warning = "Manifest records are unavailable; aggregate counts are not verified."
    return {
        "name": name,
        "health": {"status": monitor.get("status", "unknown"), "label": monitor.get("label", "Monitor unknown")},
        "metrics": metrics,
        "progress": {
            "throughput_label": throughput_label,
            "throughput_detail": throughput_detail,
            "eta": eta,
            "eta_detail": eta_detail,
        },
        "deletion": deletion,
        "warning": warning,
        "last_scan_finished": _json_number(stats, "last_scan_finished_unix_seconds"),
        "sources": {"manifest": bool(records), "stats": stats is not None, "config": bool(config)},
        "live_checked_at": now,
    }


def _json_number(data: Any, key: str) -> float | None:
    if isinstance(data, dict) and isinstance(data.get(key), (int, float)):
        return float(data[key])
    return None


def _bool_setting(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "on", "1"}:
            return True
        if normalized in {"false", "no", "off", "0"}:
            return False
    return None


def _health_card(title: str, value: dict[str, Any]) -> dict[str, Any]:
    return {"title": title, **value}


class DashboardState:
    def __init__(self, args: argparse.Namespace):
        self.primary_config = Path(args.config).expanduser()
        self.shared_config = Path(args.shared_config).expanduser() if args.shared_config else None
        self.audit_path = Path(args.audit).expanduser()
        self.days_path = Path(args.days_remaining).expanduser()
        self.primary_label = args.monitor_label
        self.shared_label = args.shared_monitor_label
        self.stuck_age = args.stuck_age_seconds
        self.docker_bin = args.docker_bin
        self.docker_context = args.docker_context
        self.container_name = args.container_name

    def snapshot(self) -> dict[str, Any]:
        now = time.time()
        lanes = [_lane_snapshot("Primary", self.primary_config, now, self.primary_label, self.stuck_age)]
        if self.shared_config:
            lanes.append(_lane_snapshot("Shared", self.shared_config, now, self.shared_label, self.stuck_age))
        primary_config = _read_json(self.primary_config)
        primary_config = primary_config if isinstance(primary_config, dict) else {}
        mount_path = primary_config.get("smb_expected_mount_root") if isinstance(primary_config.get("smb_expected_mount_root"), str) else None
        primary_monitor = _launch_health(self.primary_label)
        shared_monitor = _launch_health(self.shared_label) if self.shared_config else None
        health = {
            "primary_monitor": _health_card("Primary monitor", primary_monitor),
            "mount": _health_card("NAS mount", _mount_health(mount_path)),
            "sync": _health_card("iCloud sync", _sync_health(self.days_path)),
            "container": _health_card(
                "Container runtime",
                _container_health(self.docker_bin, self.docker_context, self.container_name),
            ),
        }
        if shared_monitor:
            health["shared_monitor"] = _health_card("Shared monitor", shared_monitor)
        known_deleted = sum(int(lane["metrics"].get("deleted_originals", 0)) for lane in lanes)
        known_review = sum(int(lane["metrics"].get("delete_review_cohort_records", 0)) for lane in lanes)
        return {
            "schema_version": 1,
            "generated_at": now,
            "lanes": lanes,
            "health": health,
            "audit": _audit_snapshot(self.audit_path, known_deleted=known_deleted, known_delete_review=known_review),
        }


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "icloudpd-dashboard/1"

    def do_GET(self) -> None:  # noqa: N802
        self._respond()

    def do_HEAD(self) -> None:  # noqa: N802
        self._respond(head_only=True)

    def _respond(self, head_only: bool = False) -> None:
        if self.path == "/":
            body = HTML_PAGE.encode("utf-8")
            content_type = "text/html; charset=utf-8"
            status = HTTPStatus.OK
        elif self.path == "/api/status":
            body = json.dumps(self.server.dashboard.snapshot(), separators=(",", ":")).encode("utf-8")
            content_type = "application/json; charset=utf-8"
            status = HTTPStatus.OK
        elif self.path == "/healthz":
            body = b'{"ok":true}'
            content_type = "application/json; charset=utf-8"
            status = HTTPStatus.OK
        else:
            body = b"not found\n"
            content_type = "text/plain; charset=utf-8"
            status = HTTPStatus.NOT_FOUND
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        # Do not log request paths or query strings, which could contain user input.
        print(f"dashboard request {self.command} {self.path.split('?', 1)[0]}", flush=True)


class DashboardServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], dashboard: DashboardState):
        super().__init__(address, RequestHandler)
        self.dashboard = dashboard


def _validate_bind(bind: str, allow_loopback: bool = True) -> None:
    try:
        address = ipaddress.ip_address(bind)
    except ValueError as exc:
        raise SystemExit("--bind must be a literal IP address") from exc
    if address.is_unspecified or address.is_multicast:
        raise SystemExit("refusing wildcard or multicast bind; use the Mac's Tailscale address")
    if allow_loopback and address.is_loopback:
        return
    tailscale = ipaddress.ip_network("100.64.0.0/10")
    if address not in tailscale:
        raise SystemExit("refusing non-Tailscale bind; use a 100.64.0.0/10 address")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="serve a read-only Tailscale iCloudPD dashboard")
    parser.add_argument("--bind", default=DEFAULT_BIND)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--config", default=str(DEFAULT_PRIMARY_CONFIG))
    parser.add_argument("--shared-config", default=str(DEFAULT_SHARED_CONFIG))
    parser.add_argument("--audit", default=str(DEFAULT_AUDIT))
    parser.add_argument("--days-remaining", default=str(DEFAULT_DAYS_REMAINING))
    parser.add_argument("--docker-bin", default=DEFAULT_DOCKER_BIN)
    parser.add_argument("--docker-context", default=DEFAULT_DOCKER_CONTEXT)
    parser.add_argument("--container-name", default=DEFAULT_CONTAINER_NAME)
    parser.add_argument("--monitor-label", default="com.icloudpd-optimizer.monitor")
    parser.add_argument("--shared-monitor-label", default="com.icloudpd-optimizer.monitor.shared")
    parser.add_argument("--stuck-age-seconds", type=int, default=DEFAULT_STUCK_AGE_SECONDS)
    parser.add_argument("--once", action="store_true", help="print one JSON snapshot and exit")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    _validate_bind(args.bind)
    if not 1 <= args.port <= 65535:
        raise SystemExit("--port must be between 1 and 65535")
    if args.stuck_age_seconds < 1:
        raise SystemExit("--stuck-age-seconds must be positive")
    dashboard = DashboardState(args)
    if args.once:
        print(json.dumps(dashboard.snapshot(), indent=2, sort_keys=True))
        return 0
    server = DashboardServer((args.bind, args.port), dashboard)
    print(f"dashboard listening on http://{args.bind}:{args.port}", flush=True)
    try:
        server.serve_forever(poll_interval=1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
