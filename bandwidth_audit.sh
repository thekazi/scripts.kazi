#!/usr/bin/env bash
# =============================================================================
# Cloudways Access Log Analyzer - Per-Application Breakdown
# Date range: rolling last 30 days (computed at runtime)
# Skips symlinks - runs only on real application directories
# =============================================================================

LOG_BASE="/home/master/applications"
LOG_PATTERN="*.access.log"

TODAY_INT=$(date +"%Y%m%d")
START_INT=$(date -d "30 days ago" +"%Y%m%d")
START_LABEL=$(date -d "30 days ago" +"%d/%b/%Y")
END_LABEL=$(date +"%d/%b/%Y")

echo "============================================================"
echo " Cloudways Access Log Report - Per Application"
echo " Period : $START_LABEL  ->  $END_LABEL  (last 30 days)"
echo " Log base: $LOG_BASE"
echo "============================================================"
echo ""

# Discover real (non-symlink) application directories
APP_DIRS=()
for d in "$LOG_BASE"/*/; do
  [ -L "${d%/}" ] && continue
  [ -d "$d/logs" ] || continue
  APP_DIRS+=("$d")
done

if [ ${#APP_DIRS[@]} -eq 0 ]; then
  echo "No real application directories found under $LOG_BASE"
  exit 1
fi

echo "Found ${#APP_DIRS[@]} real application(s) (symlinks excluded)."
echo ""

# ── SERVER-SIDE BANDWIDTH (vnstat) ────────────────────────────────────────────
echo "============================================================"
echo " SERVER-SIDE BANDWIDTH SUMMARY (vnstat)"
echo " Compare these totals against the per-app log totals below"
echo "============================================================"
echo ""

if ! command -v vnstat &>/dev/null; then
  echo "  vnstat is not installed or not in PATH. Skipping."
else
  # Detect the primary network interface (first non-loopback interface)
  NET_IF=$(vnstat --iflist 2>/dev/null | grep -oP '(?<=Interfaces: ).*' | tr ' ' '\n' | grep -v '^lo$' | head -1)
  if [ -z "$NET_IF" ]; then
    # Fallback: try common interface names
    for iface in eth0 ens3 ens4 enp0s3 bond0; do
      if vnstat -i "$iface" &>/dev/null 2>&1; then
        NET_IF="$iface"
        break
      fi
    done
  fi

  if [ -z "$NET_IF" ]; then
    echo "  Could not detect network interface. Run 'vnstat --iflist' to check."
  else
    echo "  Interface: $NET_IF"
    echo ""

    echo "  --- Daily breakdown (last 30 days) ---"
    echo "  (rx = received/inbound, tx = transmitted/outbound to visitors)"
    echo ""
    vnstat -i "$NET_IF" -d 30 2>/dev/null || vnstat -i "$NET_IF" -d 2>/dev/null
    echo ""

    echo "  --- Monthly breakdown ---"
    echo ""
    vnstat -i "$NET_IF" -m 2>/dev/null
    echo ""
  fi
fi

echo "============================================================"
echo " NOTE: vnstat measures ALL server traffic (including SSH,"
echo " FTP, cron, etc). Log-based totals below cover HTTP only."
echo " Expect vnstat tx to be >= sum of all app log totals."
echo "============================================================"
echo ""

# Global temp file variable so trap can always clean it up
CURRENT_TMP=""
cleanup() { rm -f "$CURRENT_TMP"; }
trap cleanup EXIT INT TERM

# Loop over each real application
APP_NUM=0
for APP_DIR in "${APP_DIRS[@]}"; do
  APP_NUM=$((APP_NUM + 1))
  APP_FOLDER=$(basename "$APP_DIR")

  # Extract all domains from nginx config (all server_name values, all lines)
  NGINX_CONF="$APP_DIR/conf/server.nginx"
  if [ -f "$NGINX_CONF" ]; then
    DOMAINS=$(grep 'server_name' "$NGINX_CONF" 2>/dev/null \
      | sed 's/.*server_name[[:space:]]*//' \
      | tr ';' '\n' \
      | tr ' ' '\n' \
      | sed 's/[[:space:]]//g' \
      | grep -v '^$' \
      | sort -u)
    [ -z "$DOMAINS" ] && DOMAINS="(domain not found)"
  else
    DOMAINS="(no nginx config)"
  fi

  echo ""
  echo "############################################################"
  echo "  APP $APP_NUM / ${#APP_DIRS[@]}"
  echo "  Folder  : $APP_FOLDER"
  echo "  Domains :"
  echo "$DOMAINS" | while IFS= read -r dom; do
    echo "    - $dom"
  done
  echo "############################################################"

  CURRENT_TMP=$(mktemp /tmp/cwlogs_XXXXXX)

  echo ""
  echo "  [1/7] Filtering logs..."

  {
    for f in "$APP_DIR/logs/"$LOG_PATTERN; do
      [ -f "$f" ] && cat "$f"
    done
    for f in "$APP_DIR/logs/"${LOG_PATTERN}.*.gz; do
      [ -f "$f" ] && zcat "$f"
    done
  } | LC_ALL=C awk -v start="$START_INT" -v end="$TODAY_INT" '
  {
    match($0, /\[([0-9]{2}\/[A-Za-z]{3}\/[0-9]{4})/, arr)
    if (RSTART == 0) next
    split(arr[1], p, "/")
    day=p[1]; ms=p[2]; year=p[3]
    if      (ms=="Jan") m=1
    else if (ms=="Feb") m=2
    else if (ms=="Mar") m=3
    else if (ms=="Apr") m=4
    else if (ms=="May") m=5
    else if (ms=="Jun") m=6
    else if (ms=="Jul") m=7
    else if (ms=="Aug") m=8
    else if (ms=="Sep") m=9
    else if (ms=="Oct") m=10
    else if (ms=="Nov") m=11
    else if (ms=="Dec") m=12
    else next
    dt = year*10000 + m*100 + day
    if (dt < start || dt > end) next

    ip     = $1
    uri    = $7
    status = $9
    bytes  = $10
    if (bytes == "-") bytes = 0

    n = split(uri, parts, "?")
    clean_uri = parts[1]

    ua = ""
    for (i = 12; i <= NF; i++) ua = ua (ua==""?"":"\t") $i
    gsub(/^"|"$/, "", ua)
    if (ua == "") ua = "-"

    printf "%s\t%s\t%s\t%s\t%s\n", bytes, ip, clean_uri, status, ua
  }
  ' > "$CURRENT_TMP"

  TOTAL_LINES=$(wc -l < "$CURRENT_TMP")
  if [ "$TOTAL_LINES" -eq 0 ]; then
    echo "  No log lines found for this app in the last 30 days. Skipping."
    rm -f "$CURRENT_TMP"
    CURRENT_TMP=""
    continue
  fi
  echo "  Matched lines: $TOTAL_LINES"

  # Bandwidth by content type
  echo ""
  echo "  [2/7] Bandwidth by content type"
  echo "  ------------------------------------------------------------"
  LC_ALL=C awk -F'\t' '
  function h(b) {
    if (b >= 1073741824) return sprintf("%.2f GB", b/1073741824)
    if (b >= 1048576)    return sprintf("%.2f MB", b/1048576)
    if (b >= 1024)       return sprintf("%.2f KB", b/1024)
    return sprintf("%d B", b)
  }
  {
    bytes = $1+0; uri = $3
    if (uri ~ /\.(jpg|jpeg|png|gif|webp|svg|ico|bmp|tiff|mp4|webm|mov|avi|mkv|ogg|ogv)$/)
      img += bytes
    else if (uri ~ /\.(js|css|woff|woff2|ttf|eot|map)$/)
      jscss += bytes
    else if (uri ~ /^\/wp-json\// || uri ~ /^\/wp-admin\// || uri == "/wp-login.php" || uri ~ /^\/api\//)
      api += bytes
    else
      html += bytes
    total += bytes
  }
  END {
    printf "  %-22s %12s   %6.1f%%\n", "HTML / Pages",     h(html),  (total>0?html/total*100:0)
    printf "  %-22s %12s   %6.1f%%\n", "Images / Videos",  h(img),   (total>0?img/total*100:0)
    printf "  %-22s %12s   %6.1f%%\n", "JS / CSS / Fonts", h(jscss), (total>0?jscss/total*100:0)
    printf "  %-22s %12s   %6.1f%%\n", "API / Admin",      h(api),   (total>0?api/total*100:0)
    printf "  %-22s %12s\n",           "--- TOTAL ---",     h(total)
  }
  ' "$CURRENT_TMP"

  # Top 20 largest files
  echo ""
  echo "  [3/7] Top 20 largest files by transfer volume"
  echo "  ------------------------------------------------------------"
  LC_ALL=C awk -F'\t' '$1+0 > 0 { printf "%s\t%s\n", $3, $1 }' "$CURRENT_TMP" \
    | LC_ALL=C sort -T /tmp -k1,1 \
    | LC_ALL=C awk -F'\t' '
      prev == "" { prev=$1; sum=$2; next }
      $1 == prev { sum += $2; next }
      { print sum"\t"prev; prev=$1; sum=$2 }
      END { if (prev != "") print sum"\t"prev }
    ' \
    | LC_ALL=C sort -T /tmp -t$'\t' -k1,1rn \
    | head -20 \
    | LC_ALL=C awk -F'\t' '
      function h(b) {
        if (b >= 1073741824) return sprintf("%.2f GB", b/1073741824)
        if (b >= 1048576)    return sprintf("%.2f MB", b/1048576)
        if (b >= 1024)       return sprintf("%.2f KB", b/1024)
        return sprintf("%d B", b)
      }
      BEGIN { printf "  %-4s  %-12s  %s\n", "Rank","Size","URL" }
      { printf "  %-4d  %-12s  %s\n", NR, h($1+0), $2 }
    '

  # Top 20 most requested URLs
  echo ""
  echo "  [4/7] Top 20 most requested URLs"
  echo "  ------------------------------------------------------------"
  LC_ALL=C awk -F'\t' '{print $3}' "$CURRENT_TMP" \
    | LC_ALL=C sort -T /tmp \
    | LC_ALL=C uniq -c \
    | LC_ALL=C sort -T /tmp -rn \
    | head -20 \
    | awk '
      BEGIN { printf "  %-4s  %-10s  %s\n", "Rank","Requests","URL" }
      { printf "  %-4d  %-10s  %s\n", NR, $1, $2 }'

  # Top 20 most recurring IPs
  echo ""
  echo "  [5/7] Top 20 most recurring IPs"
  echo "  ------------------------------------------------------------"
  LC_ALL=C awk -F'\t' '{print $2}' "$CURRENT_TMP" \
    | LC_ALL=C sort -T /tmp \
    | LC_ALL=C uniq -c \
    | LC_ALL=C sort -T /tmp -rn \
    | head -20 \
    | awk '
      BEGIN { printf "  %-4s  %-10s  %s\n", "Rank","Requests","IP" }
      { printf "  %-4d  %-10s  %s\n", NR, $1, $2 }'

  # Bot / user-agent analysis
  echo ""
  echo "  [6/7] Bot / user-agent breakdown"
  echo "  --- Known / Legitimate Bots ---"
  LC_ALL=C awk -F'\t' '
  $5 ~ /[Gg]ooglebot|[Bb]ingbot|[Yy]ahoo[Ss]lumber|[Dd]uckDuckBot|[Bb]aidu[Ss]pider|[Yy]andex[Bb]ot|[Ss]emrush[Bb]ot|[Aa]hrefs[Bb]ot|[Mm]j12bot|[Dd]otbot|[Ll]inkedIn[Bb]ot|[Tt]witterbot|[Ff]acebook[Ee]xternal[Hh]it|[Ss]lack[Bb]ot|[Tt]elegram[Bb]ot|[Ww]hats[Aa]pp|[Aa]pple[Bb]ot|[Pp]interest[Bb]ot|[Rr]oger[Bb]ot|[Uu]ptime[Rr]obot|[Gg]oogle[Mm]essages|[Gg]ooglebot-Image|[Dd]ata[Ff]or[Ss]eo|[Mm]ajestic/ {
    print $5
  }' "$CURRENT_TMP" \
    | LC_ALL=C sort -T /tmp \
    | LC_ALL=C uniq -c \
    | LC_ALL=C sort -T /tmp -rn \
    | head -20 \
    | awk '
      BEGIN { printf "  %-10s  %s\n", "Requests","Bot / User-Agent" }
      { cnt=$1; $1=""; sub(/^ +/,""); printf "  %-10s  %s\n", cnt, $0 }'

  echo ""
  echo "  --- Suspicious / Malicious Bots ---"
  LC_ALL=C awk -F'\t' '
  $5 ~ /[Pp]ython-[Rr]equests|[Cc]url\/|[Ww]get\/|[Nn]ikto|[Ss]qlmap|[Mm]asscan|[Hh]eadless[Cc]hrome|[Pp]hantom[Jj][Ss]|[Ss]creaming[Ff]rog|[Pp]etalbot|[Ss]emalt|[Ww]eb[Cc]opier|[Hh]tmtrack|[Gg]rabber|[Ss]craper|[Ll]ib[Ww][Ww][Ww]-[Pp]erl|[Gg]o-[Hh]ttp-[Cc]lient|[Jj]ava\/|[Rr]uby|[Ss]canner|[Zz][Aa][Pp]|[Nn]map|[Aa]ccount[Ll]ooking/ {
    print $5
  }' "$CURRENT_TMP" \
    | LC_ALL=C sort -T /tmp \
    | LC_ALL=C uniq -c \
    | LC_ALL=C sort -T /tmp -rn \
    | head -20 \
    | awk '
      BEGIN { printf "  %-10s  %s\n", "Requests","Bot / User-Agent" }
      { cnt=$1; $1=""; sub(/^ +/,""); printf "  %-10s  %s\n", cnt, $0 }'

  echo ""
  echo "  --- Empty / Blank User-Agents (highly suspicious) ---"
  BLANK_COUNT=$(LC_ALL=C awk -F'\t' '$5=="-" || $5==""' "$CURRENT_TMP" | wc -l)
  echo "  Requests with blank/empty User-Agent: $BLANK_COUNT"
  LC_ALL=C awk -F'\t' '($5=="-" || $5=="") {print $2}' "$CURRENT_TMP" \
    | LC_ALL=C sort -T /tmp \
    | LC_ALL=C uniq -c \
    | LC_ALL=C sort -T /tmp -rn \
    | head -20 \
    | awk '
      BEGIN { printf "  %-10s  %s\n", "Requests","IP" }
      { printf "  %-10s  %s\n", $1, $2 }'

  # HTTP status breakdown
  echo ""
  echo "  [7/7] HTTP status code breakdown"
  echo "  ------------------------------------------------------------"
  LC_ALL=C awk -F'\t' '$4 ~ /^[0-9]+$/ {print $4}' "$CURRENT_TMP" \
    | LC_ALL=C sort -T /tmp \
    | LC_ALL=C uniq -c \
    | LC_ALL=C sort -T /tmp -rn \
    | awk '
      BEGIN { printf "  %-10s  %s\n", "Count","HTTP Status" }
      { printf "  %-10s  HTTP %s\n", $1, $2 }'

  rm -f "$CURRENT_TMP"
  CURRENT_TMP=""
  echo ""
  echo "  --- End of report for $APP_FOLDER ---"
  echo ""

done

echo "============================================================"
echo " All applications processed."
echo "============================================================"
