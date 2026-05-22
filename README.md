# 🥷 Termux File Ninja

> A clean TUI tool for Termux: mass rename, junk cleaner & VirusTotal URL scanner

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Termux](https://img.shields.io/badge/Termux-Android-black.svg)](https://termux.dev)

**¿Cansado de tener 6GB de basura en tu Android?** Este script lo arregla.

### Features
1️⃣ **Renombrado masivo** → `0001_fotos`, `0002_videos` automático  
2️⃣ **Limpieza inteligente** → Borra `.tmp`, `Thumbs.db`, `~` + pregunta por archivos >10MB  
3️⃣ **Scanner VirusTotal** → Encuentra URLs maliciosas con cache local  
4️⃣ **Dry-run mode** → Ve qué haría sin tocar nada  
5️⃣ **Undo log** → `~/.file-ninja/undo.json` guarda todo

### Instalación
```bash
pkg install python -y
pip install requests tqdm rich
