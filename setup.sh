#!/usr/bin/env bash
set -euo pipefail

# setup.sh — Installation rapide des dépendances (Debian)

if [[ ! -f /etc/debian_version ]]; then
  echo "[ERREUR] Ce script est prévu pour Debian uniquement."
  exit 1
fi

if command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  SUDO=""
fi

echo "[1/4] Mise a jour APT..."
${SUDO} apt update

echo "[2/4] Installation des dependances systeme..."
${SUDO} apt install -y \
  ca-certificates curl git \
  whois \
  dnsutils \
  nmap \
  python3 python3-pip python3-venv \
  subfinder 

echo "[3/4] Installation environnement Python..."
if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[4/4] Installation depedances Python..."
pip install --upgrade pip
if [[ -f requirements.txt ]]; then
  pip install -r requirements.txt
else
  echo "[WARN] requirements.txt introuvable, etape pip ignoree."
fi

echo

echo "Installation terminee."
echo "Pour activer l'environnement manuellement : source .venv/bin/activate"
echo "Verification rapide : nmap --version && subfinder -h | head"
