#!/usr/bin/env python3
"""
freebsd_vuln_sentinel.py
Centinela de Vigilancia de Commits y Vulnerabilidades en Upstream FreeBSD
García Casado Security Research — Laboratorio de Ciberseguridad

Monitoriza en tiempo real los repositorios upstream de FreeBSD (sys/kern, sys/netinet, sys/dev, sys/vm)
para cazar parches silenciosos de fallos de memoria (OOB, UAF, Races, Overflows) aplicables a PS4 FW 14.00.
"""

import sys
import os
import json
import re
import time
import urllib.request
from datetime import datetime

REPORT_PATH = "/home/adrian/.gemini/antigravity/scratch/ps4-13xx-research/UPSTREAM_KERNEL_ALERTS.md"

SUBSYSTEMS = [
    ("sys/kern", "Subsidios de Kernel / Syscalls / SysV IPC / Descriptores"),
    ("sys/netinet", "Pila de Red IPv4/IPv6 / Mbufs / Sockets"),
    ("sys/dev/sound", "Controladores de Audio sound(4) / Búfers mmap"),
    ("sys/vm", "Gestión de Memoria Virtual / Slab Allocator / UMA"),
    ("sys/fs/nullfs", "Sistemas de Ficheros NullFS (Montajes loopback / Sandbox)")
]

KEYWORDS_HIGH = [
    r"\boverflow\b", r"\bunderflow\b", r"\boob\b", r"\bout-of-bounds\b",
    r"\buse-after-free\b", r"\buaf\b", r"\bdouble[- ]free\b",
    r"\bcve-\d{4}-\d+\b", r"\bsecurity\b", r"\bexploit\b",
    r"\bwrap-around\b", r"\bprecedence\b", r"\bracing\b"
]

KEYWORDS_MEDIUM = [
    r"\brace condition\b", r"\brace\b", r"\bdeadlock\b", r"\bpanic\b",
    r"\bcorrupt\b", r"\bleak\b", r"\binvalid deref\b", r"\bnull deref\b",
    r"\bmissing lock\b", r"\bunlock\b", r"\bsanity check\b", r"\bbounds check\b"
]

def analyze_commit(commit, subsystem_path, subsystem_desc):
    sha = commit["sha"][:8]
    full_sha = commit["sha"]
    author = commit["commit"]["author"]["name"]
    date_str = commit["commit"]["author"]["date"]
    full_msg = commit["commit"]["message"]
    first_line = full_msg.splitlines()[0]
    html_url = commit.get("html_url", f"https://github.com/freebsd/freebsd-src/commit/{full_sha}")

    score = 0
    matched_reasons = []

    # Check High Keywords
    for kw in KEYWORDS_HIGH:
        if re.search(kw, full_msg, re.IGNORECASE):
            score += 10
            matched_reasons.append(f"Alta criticidad: coincide con '{kw}'")

    # Check Medium Keywords
    for kw in KEYWORDS_MEDIUM:
        if re.search(kw, full_msg, re.IGNORECASE):
            score += 4
            matched_reasons.append(f"Media criticidad: coincide con '{kw}'")

    # Extra weight if in core IPC or sound
    if "sysv" in first_line.lower() or "sem" in first_line.lower() or "sound" in subsystem_path:
        score += 5
        matched_reasons.append(f"Subsistema crítico presente en Orbis OS ({subsystem_path})")

    category = "INFO"
    if score >= 10:
        category = "ALTA PRIORIDAD (POTENCIAL 0-DAY/1-DAY PS4)"
    elif score >= 4:
        category = "MODERADA (REVISAR DIF)"

    return {
        "sha": sha,
        "full_sha": full_sha,
        "author": author,
        "date": date_str,
        "title": first_line,
        "full_msg": full_msg,
        "url": html_url,
        "subsystem": subsystem_path,
        "desc": subsystem_desc,
        "score": score,
        "reasons": matched_reasons,
        "category": category
    }

def fetch_subsystem_commits(path, count=15):
    url = f"https://api.github.com/repos/freebsd/freebsd-src/commits?path={path}&per_page={count}"
    headers = {
        "User-Agent": "GarciaCasadoSecurityResearch/1.0 (FreeBSD Research Sentinel)",
        "Accept": "application/vnd.github.v3+json"
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                return data
    except Exception as e:
        print(f"[-] Error consultando {path}: {e}")
    return []

def run_sentinel():
    print("==================================================================")
    print("  GARCÍA CASADO SECURITY RESEARCH — FREEBSD UPSTREAM SENTINEL")
    print("  Monitorización de Commits de Kernel y Vectores para PS4 14.00")
    print("==================================================================\n")

    all_alerts = []
    total_scanned = 0

    for path, desc in SUBSYSTEMS:
        print(f"[*] Escaneando subsistema: {path} ({desc})...")
        commits = fetch_subsystem_commits(path, count=15)
        total_scanned += len(commits)

        for c in commits:
            analyzed = analyze_commit(c, path, desc)
            if analyzed["score"] > 0:
                all_alerts.append(analyzed)
        time.sleep(0.5)

    all_alerts.sort(key=lambda x: (x["score"], x["date"]), reverse=True)

    print(f"\n[+] Total commits analizados: {total_scanned}")
    print(f"[+] Hallazgos relevantes detectados: {len(all_alerts)}\n")

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Generate Markdown Report
    lines = [
        "# FreeBSD Upstream Kernel Vulnerability & Patch Sentinel",
        "",
        "> **Entidad:** García Casado Security Research  ",
        f"> **Último escaneo:** `{now_str}`  ",
        f"> **Commits analizados:** `{total_scanned}` en `{len(SUBSYSTEMS)}` subsistemas críticos  ",
        f"> **Alertas activas:** `{len(all_alerts)}` hallazgos con patrones de fallo de memoria  ",
        "",
        "---",
        "",
        "## 🎯 Resumen de Hallazgos Filtrados para Orbis OS (PS4 FW 14.00)",
        ""
    ]

    if not all_alerts:
        lines.append("No se detectaron commits con patrones críticos en los últimos lotes escaneados.")
    else:
        for idx, alert in enumerate(all_alerts, 1):
            lines.append(f"### {idx}. [{alert['sha']}] {alert['title']}")
            lines.append(f"- **Subsistema:** `{alert['subsystem']}` ({alert['desc']})")
            lines.append(f"- **Nivel de Criticidad:** `{alert['category']}` (Score: `{alert['score']}`)")
            lines.append(f"- **Fecha:** `{alert['date']}` | **Autor:** `{alert['author']}`")
            lines.append(f"- **Enlace al Commit:** [{alert['sha']}]({alert['url']})")
            lines.append("- **Indicadores de Detección:**")
            for r in alert["reasons"]:
                lines.append(f"  - {r}")
            lines.append("- **Mensaje Completo:**")
            lines.append("```text")
            lines.append(alert["full_msg"][:400] + ("..." if len(alert["full_msg"]) > 400 else ""))
            lines.append("```")
            lines.append("")

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[+] Informe actualizado guardado en: {REPORT_PATH}")
    return all_alerts

if __name__ == "__main__":
    run_sentinel()
