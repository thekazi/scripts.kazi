#!/usr/bin/env bash
# =============================================================================
# Cloudways Access Log Analyzer
# Outputs: Bandwidth by type | Top 20 largest files | Top 20 most requested URLs
# =============================================================================

# ── CONFIG ────────────────────────────────────────────────────────────────────
APPS_ROOT="/home/master/applications"
LOG_PATTERN="backend_wordpress-*.access.log"
# ─────────────────────────────────────────────────────────────────────────────

# ── APP DISCOVERY & SELECTION ────────────────────────────────────────────────
declare -a APP_NAMES
declare -a APP_LOG_DIRS

for dir in "$APPS_ROOT"/*/logs; do
  [ -d "$dir" ] || continue
  app=$(basename "$(dirname "$dir")")
  APP_NAMES+=("$app")
  APP_LOG_DIRS+=("$dir")
done

if [ "${#APP_NAMES[@]}" -eq 0 ]; then
  echo "No app log directories found under $APPS_ROOT/*/logs"
  exit 1
fi

echo "============================================================"
echo " Available Applications"
echo "============================================================"
for i in "${!APP_NAMES[@]}"; do
  printf "%3d) %s\n" "$((i+1))" "${APP_NAMES[$i]}"
done
echo ""

read -rp "Select app number to analyze: " SEL

if ! [[ "$SEL" =~ ^[0-9]+$ ]] || [ "$SEL" -lt 1 ] || [ "$SEL" -gt "${#APP_NAMES[@]}" ]; then
  echo "Invalid selection."
  exit 1
fi

IDX=$((SEL-1))
LOG_DIR="${APP_LOG_DIRS[$IDX]}"
APP_NAME="${APP_NAMES[$IDX]}"

# ── DATE RANGE VALIDATION ─────────────────────────────────────────────────────
validate_date() {
  # Expects DD/Mon/YYYY, e.g. 25/Feb/2026
  [[ "$1" =~ ^[0-9]{1,2}/[A-Za-z]{3}/[0-9]{4}$ ]]
}

while true; do
  read -rp "Enter START date (DD/Mon/YYYY, e.g. 25/Feb/2026): " START_DATE
  validate_date "$START_DATE" && break
  echo "Invalid format. Use DD/Mon/YYYY, e.g. 01/Jan/2026"
done

while true; do
  read -rp "Enter END date   (DD/Mon/YYYY, e.g. 17/Mar/2026): " END_DATE
  validate_date "$END_DATE" && break
  echo "Invalid format. Use DD/Mon/YYYY, e.g. 31/Jan/2026"
done

echo ""
echo "Selected app: $APP_NAME"
echo "Log dir     : $LOG_DIR"
echo ""

# Convert DD/Mon/YYYY to a comparable integer YYYYMMDD
date_to_int() {
  local raw="$1"   # e.g. 25/Feb/2026
  local day mon_str year mon_num

  day=$(echo "$raw"   | cut -d'/' -f1)
  mon_str=$(echo "$raw" | cut -d'/' -f2)
  year=$(echo "$raw"  | cut -d'/' -f3)

  case "$mon_str" in
    Jan) mon_num=01 ;; Feb) mon_num=02 ;; Mar) mon_num=03 ;;
    Apr) mon_num=04 ;; May) mon_num=05 ;; Jun) mon_num=06 ;;
    Jul) mon_num=07 ;; Aug) mon_num=08 ;; Sep) mon_num=09 ;;
    Oct) mon_num=10 ;; Nov) mon_num=11 ;; Dec) mon_num=12 ;;
    *) mon_num=00 ;;
  esac

  printf "%04d%02d%02d" "$year" "$mon_num" "$day"
}

START_INT=$(date_to_int "$START_DATE")
END_INT=$(date_to_int "$END_DATE")

if [ "$START_INT" -gt "$END_INT" ]; then
  echo "Error: START date is after END date."
  exit 1
fi

echo "============================================================"
echo " Cloudways Access Log Report"
echo " App    : $APP_NAME"
echo " Period : $START_DATE  →  $END_DATE"
echo " Log dir: $LOG_DIR"
echo "============================================================"
echo ""

# ── COLLECT & FILTER LOGS ────────────────────────────────────────────────────
get_filtered_lines() {
  {
    for f in "$LOG_DIR"/$LOG_PATTERN; do
      [ -f "$f" ] && cat "$f"
    done
    for f in "$LOG_DIR"/${LOG_PATTERN}.*.gz; do
      [ -f "$f" ] && zcat "$f"
    done
  } | awk -v start="$START_INT" -v end="$END_INT" '
    {
      match($0, /\[([0-9]{2}\/[A-Za-z]{3}\/[0-9]{4})/, arr)
      if (RSTART == 0) next
      raw = arr[1]

      split(raw, p, "/")
      day = p[1]; mon_str = p[2]; year = p[3]

      m = 0
      if (mon_str == "Jan") m = 1
      else if (mon_str == "Feb") m = 2
      else if (mon_str == "Mar") m = 3
      else if (mon_str == "Apr") m = 4
      else if (mon_str == "May") m = 5
      else if (mon_str == "Jun") m = 6
      else if (mon_str == "Jul") m = 7
      else if (mon_str == "Aug") m = 8
      else if (mon_str == "Sep") m = 9
      else if (mon_str == "Oct") m = 10
      else if (mon_str == "Nov") m = 11
      else if (mon_str == "Dec") m = 12

      dt = year * 10000 + m * 100 + day
      if (dt >= start && dt <= end) print
    }
  '
}

FILTERED=$(get_filtered_lines)

if [ -z "$FILTERED" ]; then
  echo ":warning:  No log lines found for the specified date range."
  echo "   Check LOG_DIR and log file naming."
  exit 1
fi

TOTAL_LINES=$(echo "$FILTERED" | wc -l)
echo ":white_check_mark: Matched lines: $TOTAL_LINES"
echo ""

# ── HELPER: format bytes ──────────────────────────────────────────────────────
fmt_bytes() {
  awk -v b="$1" 'BEGIN {
    if (b >= 1073741824)      printf "%.2f GB\n", b/1073741824
    else if (b >= 1048576)    printf "%.2f MB\n", b/1048576
    else if (b >= 1024)       printf "%.2f KB\n", b/1024
    else                      printf "%d  B\n", b
  }'
}

# ── 1. BANDWIDTH BY CONTENT TYPE ─────────────────────────────────────────────
echo "============================================================"
echo " BANDWIDTH BY CONTENT TYPE"
echo "============================================================"

echo "$FILTERED" | awk '
{
  uri = $7
  bytes = $10
  if (bytes == "-") bytes = 0

  if (uri ~ /\.(jpg|jpeg|png|gif|webp|svg|ico|bmp|tiff|mp4|webm|mov|avi|mkv|ogg|ogv)(\?|$)/i)
    img += bytes
  else if (uri ~ /\.(js|css|woff|woff2|ttf|eot|map)(\?|$)/i)
    jscss += bytes
  else if (uri ~ /^\/wp-json\// || uri ~ /^\/wp-admin\// || uri ~ /^\/wp-login\.php/ || uri ~ /^\/api\// || uri ~ /\?rest_route=/)
    api += bytes
  else
    html += bytes

  total += bytes
}
END {
  printf "%-22s %12s   %6.1f%%\n", "HTML / Pages",       fmt_human(html),  (total>0 ? html/total*100  : 0)
  printf "%-22s %12s   %6.1f%%\n", "Images / Videos",    fmt_human(img),   (total>0 ? img/total*100   : 0)
  printf "%-22s %12s   %6.1f%%\n", "JS / CSS / Fonts",   fmt_human(jscss), (total>0 ? jscss/total*100 : 0)
  printf "%-22s %12s   %6.1f%%\n", "API / Admin",        fmt_human(api),   (total>0 ? api/total*100   : 0)
  printf "%-22s %12s\n",           "─────── TOTAL ──────", fmt_human(total)
}
function fmt_human(b) {
  if (b >= 1073741824) return sprintf("%.2f GB", b/1073741824)
  if (b >= 1048576)    return sprintf("%.2f MB", b/1048576)
  if (b >= 1024)       return sprintf("%.2f KB", b/1024)
  return sprintf("%d B", b)
}
'
echo ""

# ── 2. TOP 20 LARGEST FILES BY TRANSFER VOLUME ───────────────────────────────
echo "============================================================"
echo " TOP 20 LARGEST FILES BY TOTAL TRANSFER VOLUME"
echo "============================================================"

echo "$FILTERED" | awk '
{
  uri = $7
  bytes = $10
  if (bytes == "-" || bytes+0 == 0) next
  split(uri, parts, "?")
  clean = parts[1]
  vol[clean] += bytes
}
END {
  for (u in vol) print vol[u], u
}
' | sort -rn | head -20 | awk '
NR==1 { printf "%-4s  %-12s  %s\n", "Rank", "Size", "URL" }
{
  bytes = $1
  url = $2
  if (bytes >= 1073741824) size = sprintf("%.2f GB", bytes/1073741824)
  else if (bytes >= 1048576) size = sprintf("%.2f MB", bytes/1048576)
  else if (bytes >= 1024)    size = sprintf("%.2f KB", bytes/1024)
  else                       size = sprintf("%d B",    bytes)
  printf "%-4d  %-12s  %s\n", NR, size, url
}'
echo ""

# ── 3. TOP 20 MOST REQUESTED URLs ────────────────────────────────────────────
echo "============================================================"
echo " TOP 20 MOST REQUESTED URLs"
echo "============================================================"

echo "$FILTERED" | awk '
{
  uri = $7
  split(uri, parts, "?")
  clean = parts[1]
  count[clean]++
}
END {
  for (u in count) print count[u], u
}
' | sort -rn | head -20 | awk '
NR==1 { printf "%-4s  %-10s  %s\n", "Rank", "Requests", "URL" }
{ printf "%-4d  %-10s  %s\n", NR, $1, $2 }'
echo ""

echo "============================================================"
echo " Report complete."
echo "============================================================"
