#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
termux-file-ninja.py
Herramienta todo‑en‑uno para Termux:
  1️⃣ Renombrar carpetas masivamente
  2️⃣ Eliminar archivos basura con modo cuidadoso
  3️⃣ Escanear URLs usando VirusTotal con cache

Autor: 14 y/o dev que se cansó de tener 6GB de basura
"""

import os
import re
import sys
import json
import time
import hashlib
import pathlib
import argparse
import requests
from tqdm import tqdm
from rich.console import Console
from rich.table import Table
from rich.prompt import Confirm
from rich.panel import Panel

console = Console()

# --------------------------------------------------------------
# CONFIGURACIÓN
# --------------------------------------------------------------
JUNK_PATTERNS = {
    "Thumbs.db", ".DS_Store", "desktop.ini", "~",
    ".tmp", ".temp", ".part", ".crdownload", ".log"
}

SIZE_WARNING = 10 * 1024 # 10 MiB - preguntar si es más grande
FOLDER_PATTERN = "{i:04d}_{name}" # ej. 0001_fotos
VT_API_KEY = os.getenv("VT_API_KEY")

# Paths de cache y logs
CACHE_DIR = pathlib.Path.home() / ".file-ninja"
CACHE_DIR.mkdir(exist_ok=True)
VT_CACHE = CACHE_DIR / "vt_cache.json"
UNDO_LOG = CACHE_DIR / "undo.json"

# --------------------------------------------------------------
# UTILIDADES
# --------------------------------------------------------------
def load_json(path: pathlib.Path, default):
    try:
        return json.loads(path.read_text()) if path.exists() else default
    except:
        return default

def save_json(path: pathlib.Path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))

def is_junk(name: str) -> bool:
    low = name.lower()
    if low in (p.lower() for p in JUNK_PATTERNS):
        return True
    for ext in (".tmp", ".temp", ".part", ".crdownload", ".log"):
        if low.endswith(ext):
            return True
    if low.endswith("~"):
        return True
    return False

def log_undo(action: str, path: str, extra=""):
    undo = load_json(UNDO_LOG, [])
    undo.append({
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "path": path,
        "extra": extra
    })
    save_json(UNDO_LOG, undo)

# --------------------------------------------------------------
# MÓDULO 1: LIMPIEZA
# --------------------------------------------------------------
def clean_junk(root: pathlib.Path, dry_run: bool = False):
    removed = 0
    warned = 0
    bytes_freed = 0

    console.print(Panel(f"[bold cyan]Modo: {'DRY-RUN - No se borra nada' if dry_run else 'EJECUCIÓN REAL'}[/bold cyan]"))

    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            fpath = pathlib.Path(dirpath) / fn

            try:
                size = fpath.stat().st_size
            except:
                continue

            # 1) Basura segura → borrado directo
            if is_junk(fn):
                bytes_freed += size
                if dry_run:
                    console.print(f"[yellow][DRY][/yellow] Borraría: {fpath} ({size/1e6:.2f}MB)")
                else:
                    try:
                        fpath.unlink()
                        removed += 1
                        log_undo("delete", str(fpath))
                        console.print(f"[red][–][/red] Borrado: {fpath}")
                    except PermissionError:
                        console.print(f"[dim][!] Sin permisos: {fpath}[/dim]")
                    except Exception as e:
                        console.print(f"[red][!] Error: {fpath} - {e}[/red]")
                continue

            # 2) Archivo grande → preguntar
            if size > SIZE_WARNING:
                warned += 1
                console.print(f"\n[yellow][?][/yellow] Archivo grande: {fpath} [bold]{size/1e6:.2f}MB[/bold]")
                if dry_run or Confirm.ask("¿Deseas eliminarlo?", default=False):
                    bytes_freed += size
                    if not dry_run:
                        try:
                            fpath.unlink()
                            removed += 1
                            log_undo("delete", str(fpath))
                            console.print(f"[red][–][/red] Borrado: {fpath}")
                        except Exception as e:
                            console.print(f"[red][!] Error: {e}[/red]")
                    else:
                        console.print(f"[yellow][DRY][/yellow] Se borraría")
                else:
                    console.print("[dim][↩] Omitido[/dim]")

    # Resumen
    table = Table(title="✨ Resumen Limpieza")
    table.add_column("Métrica"); table.add_column("Valor", justify="right")
    table.add_row("Archivos borrados", str(removed if not dry_run else 0))
    table.add_row("Archivos grandes revisados", str(warned))
    table.add_row("Espacio liberado", f"{bytes_freed/1e9:.2f} GB")
    console.print(table)

# --------------------------------------------------------------
# MÓDULO 2: RENOMBRAR
# --------------------------------------------------------------
def rename_folders(root: pathlib.Path, dry_run: bool = False):
    dirs = [d for d in root.iterdir() if d.is_dir()]
    dirs.sort()
    renamed = 0

    console.print(Panel(f"[bold cyan]Renombrando {len(dirs)} carpetas[/bold cyan]"))

    for i, folder in enumerate(dirs, start=1):
        # Skip si ya tiene formato 0001_
        if re.match(r'^\d{4}_', folder.name):
            console.print(f"[dim][↩] Ya renombrada: {folder.name}[/dim]")
            continue

        nuevo = FOLDER_PATTERN.format(i=i, name=folder.name)
        destino = folder.parent / nuevo

        if destino.exists():
            console.print(f"[yellow][!] Ya existe: {destino}[/yellow]")
            continue

        if dry_run:
            console.print(f"[yellow][DRY][/yellow] {folder.name} → {nuevo}")
        else:
            try:
                folder.rename(destino)
                renamed += 1
                log_undo("rename", str(folder), str(destino))
                console.print(f"[green][→][/green] {folder.name} → {nuevo}")
            except Exception as e:
                console.print(f"[red][!] Error renombrando: {e}[/red]")

    console.print(f"\n[bold]Total renombradas: {renamed if not dry_run else 0}[/bold]")

# --------------------------------------------------------------
# MÓDULO 3: SCAN URLS CON CACHE
# --------------------------------------------------------------
def extract_urls(txt: str):
    regex = re.compile(r"(https?://[^\s'\"<>]+)", re.IGNORECASE)
    return regex.findall(txt)

def vt_check(url: str):
    if not VT_API_KEY:
        raise RuntimeError("VT_API_KEY no encontrada. export VT_API_KEY=tu_key")

    # Check cache primero
    cache = load_json(VT_CACHE, {})
    url_hash = hashlib.sha1(url.encode()).hexdigest()

    if url_hash in cache:
        stats = cache[url_hash]
        malicious = stats["malicious"] > 0 or stats["suspicious"] > 0
        return malicious, stats, True # True = from cache

    headers = {"x-apikey": VT_API_KEY}
    r = requests.post("https://www.virustotal.com/api/v3/urls",
                      data={"url": url}, headers=headers, timeout=10)
    if r.status_code!= 200:
        raise RuntimeError(f"VT submit error {r.status_code}")
    url_id = r.json()["data"]["id"]

    for _ in range(6):
        time.sleep(10)
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                           headers=headers, timeout=10)
        if resp.status_code!= 200:
            continue
        attrs = resp.json()["data"]["attributes"]
        stats = attrs["last_analysis_stats"]

        # Guardar en cache
        cache[url_hash] = stats
        save_json(VT_CACHE, cache)

        malicious = stats["malicious"] > 0 or stats["suspicious"] > 0
        return malicious, stats, False

    return None, None, False

def scan_links(root: pathlib.Path):
    if not VT_API_KEY:
        console.print("[red][!] Exporta VT_API_KEY primero: export VT_API_KEY=tu_key[/red]")
        return

    sospechosas = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            fpath = pathlib.Path(dirpath) / fn
            for url in extract_urls(fn):
                sospechosas.append((fpath, url))
            if fn.lower().endswith(('.txt', '.md', '.json', '.csv', '.html')):
                try:
                    contenido = fpath.read_text(errors='ignore')
                    for url in extract_urls(contenido):
                        sospechosas.append((fpath, url))
                except:
                    pass

    if not sospechosas:
        console.print("[green]No se detectaron URLs para escanear.[/green]")
        return

    console.print(f"\n[bold]Se encontraron {len(sospechosas)} URLs. Analizando...[/bold]\n")
    maliciosas = 0

    for fpath, url in tqdm(sospechosas, desc="Scaneando"):
        try:
            malo, stats, from_cache = vt_check(url)
            cache_tag = "[dim](cache)[/dim]" if from_cache else ""

            if malo is None:
                console.print(f"[yellow][?][/yellow] Inconcluso: {url} {cache_tag}")
            elif malo:
                maliciosas += 1
                console.print(f"[red][⚠] MALICIOSA:[/red] {url} {cache_tag}")
                console.print(f" Stats: {stats}")
            else:
                console.print(f"[green][✓][/green] Segura: {url} {cache_tag}")
        except Exception as e:
            console.print(f"[red][!] Error: {url} - {e}[/red]")

    console.print(f"\n[bold]URLs maliciosas encontradas: {maliciosas}/{len(sospechosas)}[/bold]")

# --------------------------------------------------------------
# MENÚ INTERACTIVO
# --------------------------------------------------------------
def menu(base_dir: pathlib.Path, dry_run: bool):
    while True:
        console.print(Panel.fit("🥷 [bold cyan]TERMUX FILE NINJA v2.0[/bold cyan]", border_style="cyan"))
        console.print(f"Directorio: [yellow]{base_dir}[/yellow]")
        console.print(f"Modo: [bold]{'DRY-RUN' if dry_run else 'REAL'}[/bold]\n")

        opciones = {
            "1": "Renombrar carpetas masivamente",
            "2": "Eliminar archivos basura con modo cuidadoso",
            "3": "Escanear URLs con VirusTotal",
            "4": "Ejecutar TODO",
            "0": "Salir"
        }

        for key, desc in opciones.items():
            console.print(f"[cyan]{key}[/cyan]. {desc}")

        elec = input("\nSelecciona una opción: ").strip()

        if elec == "0":
            console.print("[green]¡Hasta luego! Undo log en ~/.file-ninja/undo.json[/green]")
            break
        elif elec == "1":
            rename_folders(base_dir, dry_run)
        elif elec == "2":
            clean_junk(base_dir, dry_run)
        elif elec == "3":
            scan_links(base_dir)
        elif elec == "4":
            clean_junk(base_dir, dry_run)
            rename_folders(base_dir, dry_run)
            scan_links(base_dir)
        else:
            console.print("[red]Opción no válida[/red]")

        input("\nPresiona Enter para continuar...")

# --------------------------------------------------------------
# INICIO
# --------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Termux File Ninja - Organiza tu Android como pro"
    )
    parser.add_argument("directory", type=str, help="Ruta al directorio donde operar")
    parser.add_argument("--dry-run", action="store_true", help="Solo muestra, no ejecuta")
    parser.add_argument("--yes", action="store_true", help="Auto-acepta sin menú")

    args = parser.parse_args()
    BASE_DIR = pathlib.Path(args.directory).expanduser().resolve()

    if not BASE_DIR.is_dir():
        console.print(f"[red]❌ {BASE_DIR} no es un directorio válido[/red]")
        sys.exit(1)

    if args.yes:
        clean_junk(BASE_DIR, args.dry_run)
        rename_folders(BASE_DIR, args.dry_run)
        scan_links(BASE_DIR)
    else:
        menu(BASE_DIR, args.dry_run)