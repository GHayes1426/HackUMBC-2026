#!/bin/zsh
# Port a Potty macOS local helper. Keep this file beside its downloaded .env.
# It performs read-only localhost and system-protection checks, then uploads
# display-only results to the paired hosted dashboard.

set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f .env ]]; then
  echo "Missing .env. Download a fresh Port a Potty helper package from the dashboard."
  read -k 1 "?Press any key to close..."
  exit 1
fi
source ./.env

if [[ -z "${PORT_A_POTTY_API_URL:-}" || -z "${PORT_A_POTTY_ENROLLMENT_TOKEN:-}" ]]; then
  echo "This helper package is incomplete. Download a fresh package from the dashboard."
  read -k 1 "?Press any key to close..."
  exit 1
fi

STATE_DIR="$HOME/Library/Application Support/Port a Potty Helper"
STATE_FILE="$STATE_DIR/device_id.txt"
mkdir -p "$STATE_DIR"
if [[ -f "$STATE_FILE" ]]; then
  DEVICE_ID="$(cat "$STATE_FILE")"
else
  DEVICE_ID="$(uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-')"
  print -r -- "$DEVICE_ID" > "$STATE_FILE"
fi
HOSTNAME="$(scutil --get LocalHostName 2>/dev/null || hostname)"

json_item() {
  # Inputs are fixed strings plus validated port numbers, so they cannot
  # introduce JSON syntax into the upload payload.
  printf '{"label":"%s","status":"%s","detail":"%s"}' "$1" "$2" "$3"
}

join_item() {
  if [[ -n "$1" ]]; then
    print -n "$1,"
  fi
}

# ---- Local Port Assessor ----
RISKY_PORTS=(21 23 25 135 139 445 1433 3306 3389 5900)
PORT_ITEMS=""
OPEN_COUNT=0
for PORT in "${RISKY_PORTS[@]}"; do
  if nc -z -w 1 127.0.0.1 "$PORT" >/dev/null 2>&1; then
    ITEM="$(json_item "Port $PORT" "warning" "Open on this Mac. Confirm the service is needed and restrict it to trusted networks.")"
    OPEN_COUNT=$((OPEN_COUNT + 1))
  else
    ITEM="$(json_item "Port $PORT" "ok" "Closed on localhost.")"
  fi
  PORT_ITEMS="${PORT_ITEMS}${PORT_ITEMS:+,}${ITEM}"
done
if (( OPEN_COUNT > 0 )); then
  PORT_STATUS="warning"
  PORT_SUMMARY="$OPEN_COUNT commonly targeted port(s) open"
else
  PORT_STATUS="ok"
  PORT_SUMMARY="None of the commonly targeted ports are open"
fi
PORT_RESULT="{\"name\":\"Local Port Assessor\",\"description\":\"Scans this Mac for commonly risky open ports\",\"status\":\"$PORT_STATUS\",\"summary\":\"$PORT_SUMMARY\",\"items\":[$PORT_ITEMS]}"

# ---- Listening Services ----
SERVICE_ITEMS=""
SERVICE_COUNT=0
while IFS='|' read -r COMMAND ADDRESS; do
  [[ -z "$ADDRESS" ]] && continue
  PORT="${ADDRESS##*:}"
  [[ "$PORT" == <-> ]] || continue
  SAFE_COMMAND="$(print -r -- "$COMMAND" | tr -cd '[:alnum:]_.-')"
  [[ -n "$SAFE_COMMAND" ]] || SAFE_COMMAND="Unknown program"
  if [[ "$ADDRESS" == 127.0.0.1:* || "$ADDRESS" == \[::1\]:* ]]; then
    STATUS="ok"
    DETAIL="Only reachable from this Mac. Program: $SAFE_COMMAND."
  else
    STATUS="review"
    DETAIL="May be reachable from other devices. Program: $SAFE_COMMAND. Verify this service is intended."
  fi
  ITEM="$(json_item "Port $PORT" "$STATUS" "$DETAIL")"
  SERVICE_ITEMS="${SERVICE_ITEMS}${SERVICE_ITEMS:+,}${ITEM}"
  SERVICE_COUNT=$((SERVICE_COUNT + 1))
  (( SERVICE_COUNT >= 25 )) && break
done < <(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR > 1 {print $1 "|" $9}')
if (( SERVICE_COUNT > 0 )); then
  SERVICE_STATUS="review"
  SERVICE_SUMMARY="$SERVICE_COUNT listening service(s) found"
else
  SERVICE_STATUS="ok"
  SERVICE_SUMMARY="No TCP listening services found"
fi
SERVICE_RESULT="{\"name\":\"Listening Services\",\"description\":\"Programs on this Mac accepting TCP connections\",\"status\":\"$SERVICE_STATUS\",\"summary\":\"$SERVICE_SUMMARY\",\"items\":[$SERVICE_ITEMS]}"

# ---- System Hardening ----
HARDENING_ITEMS=""
HARDENING_WARNINGS=0
add_hardening() {
  HARDENING_ITEMS="${HARDENING_ITEMS}${HARDENING_ITEMS:+,}$(json_item "$1" "$2" "$3")"
  [[ "$2" == "warning" ]] && HARDENING_WARNINGS=$((HARDENING_WARNINGS + 1))
}
FIREWALL="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || true)"
if [[ "$FIREWALL" == *"enabled"* ]]; then
  add_hardening "macOS Firewall" "ok" "On. Blocks unwanted incoming connections."
else
  add_hardening "macOS Firewall" "warning" "Off. Turn it on in System Settings > Network > Firewall."
fi
FILEVAULT="$(fdesetup status 2>/dev/null || true)"
if [[ "$FILEVAULT" == *"FileVault is On"* ]]; then
  add_hardening "FileVault disk encryption" "ok" "On. Protects the disk if this Mac is lost or stolen."
else
  add_hardening "FileVault disk encryption" "warning" "Off. Turn it on in System Settings > Privacy & Security > FileVault."
fi
GATEKEEPER="$(spctl --status 2>/dev/null || true)"
if [[ "$GATEKEEPER" == *"assessments enabled"* ]]; then
  add_hardening "Gatekeeper" "ok" "On. Restricts untrusted apps from opening."
else
  add_hardening "Gatekeeper" "warning" "Could not confirm it is on. Review Privacy & Security settings."
fi
SIP="$(csrutil status 2>/dev/null || true)"
if [[ "$SIP" == *"enabled"* ]]; then
  add_hardening "System Integrity Protection" "ok" "On. Protects core macOS files."
else
  add_hardening "System Integrity Protection" "review" "Could not confirm it from this session."
fi
if (( HARDENING_WARNINGS > 0 )); then
  HARDENING_STATUS="warning"
  HARDENING_SUMMARY="$HARDENING_WARNINGS protection(s) need attention"
else
  HARDENING_STATUS="ok"
  HARDENING_SUMMARY="Checked macOS protections are on"
fi
HARDENING_RESULT="{\"name\":\"System Hardening\",\"description\":\"Built-in macOS protection checks\",\"status\":\"$HARDENING_STATUS\",\"summary\":\"$HARDENING_SUMMARY\",\"items\":[$HARDENING_ITEMS]}"

RESULTS="[$PORT_RESULT,$SERVICE_RESULT,$HARDENING_RESULT]"
echo "Port a Potty Helper is scanning this Mac and sending display-only findings..."
if curl --silent --show-error --fail --connect-timeout 15 --max-time 45 \
  -H "Authorization: Bearer $PORT_A_POTTY_ENROLLMENT_TOKEN" \
  -F "device_id=$DEVICE_ID" \
  -F "hostname=$HOSTNAME" \
  -F "results=$RESULTS" \
  "$PORT_A_POTTY_API_URL/api/agent/scan" >/dev/null; then
  echo "Scan uploaded. Keep this window open; it will scan again every ${PORT_A_POTTY_HELPER_INTERVAL_SECONDS:-60} seconds."
else
  echo "Could not upload the scan. Check your internet connection and download a fresh helper package."
fi

while true; do
  sleep "${PORT_A_POTTY_HELPER_INTERVAL_SECONDS:-60}"
  exec "$0"
done
