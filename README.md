<div align="center">

# WiMO
### Wireless Monitor & Orchestrator

**CLI pink untuk audit jaringan** — scan device, deteksi vendor, limit bandwidth, block akses.

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-FF69B4?style=for-the-badge&logo=linux&logoColor=white)](https://www.linux.org/)
[![License](https://img.shields.io/badge/License-MIT-FF1493?style=for-the-badge)](LICENSE)
[![Author](https://img.shields.io/badge/Author-k2202-FF69B4?style=for-the-badge&logo=github)](https://github.com/key2202)

</div>

---

## Apa itu WiMO?

**WiMO** adalah CLI tool untuk **audit jaringan Wi-Fi** — dibuat dengan Python dan Rich. Bisa scan device, deteksi merek, monitor traffic, dan limit bandwidth.

Cocok untuk belajar keamanan jaringan, audit Wi-Fi rumah, dan tugas kuliah.

---

## ✨ Fitur

- 🔍 **Auto Scan** — ping sweep + ARP table
- 📊 **Deteksi Vendor** — Apple, Samsung, Xiaomi, ZTE, TP-Link, dll
- 🏷️ **Deteksi Tipe** — Smartphone, Laptop, Router, IoT, Smart TV
- 📡 **Live Monitor** — real-time RX/TX per-device
- 🚦 **Limit Bandwidth** — batasi per-device
- 🚫 **Block / Free** — blokir akses internet
- 📈 **Stats** — statistik jaringan
- 🔒 **Audit Keamanan** — cek kerentanan ARP
- 📄 **Report** — laporan Markdown + HTML
- 📤 **Export CSV** — simpan hasil scan

---

## 📋 Persyaratan

- **OS**: Linux (Ubuntu/Debian/Arch/Kali)
- **Python**: 3.9+
- **Akses**: sudo / root
- **Sistem**: iproute2, iptables, tc

---

## 🚀 Instalasi

```bash
# Clone repository
git clone https://github.com/key2202/Wimo.git
cd Wimo

# Install dependensi sistem
sudo apt install python3 python3-pip iproute2 iptables -y

# Install library Python
pip3 install --break-system-packages -r requirements.txt

# Install WiMO
pip3 install --break-system-packages -e .

# Jalankan
sudo wimo
