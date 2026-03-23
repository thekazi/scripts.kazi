#!/usr/bin/env bash
# =============================================================================
# Cloudways Access Log — Bot & Suspicious Traffic Analyzer
# Analyzes two date windows for bot activity, suspicious UAs, attack paths
# Usage: ./analyze_bot_traffic.sh [log-directory]
# =============================================================================

# ── CONFIG ────────────────────────────────────────────────────────────────────
LOG_DIR="${1:-.}"                          # Pass log directory as arg, default = current dir
LOG_PATTERN="backend_wordpress-*.access.log"

# Define analysis windows as pairs: START_DATE END_DATE
WINDOWS=(
  "16/Mar/2026" "18/Mar/2026"
  "20/Mar/2026" "22/Mar/2026"
)
# ─────────────────────────────────────────────────────────────────────────────

# Convert DD/Mon/YYYY to a comparable integer YYYYMMDD
date_to_int() {
  local raw="$1"   # e.g. 16/Mar/2026
  local day mon_str year mon_num

  day=$(echo "$raw"    | cut -d'/' -f1)
  mon_str=$(echo "$raw" | cut -d'/' -f2)
  year=$(echo "$raw"   | cut -d'/' -f3)

  case "$mon_str" in
    Jan) mon_num=01 ;; Feb) mon_num=02 ;; Mar) mon_num=03 ;;
    Apr) mon_num=04 ;; May) mon_num=05 ;; Jun) mon_num=06 ;;
    Jul) mon_num=07 ;; Aug) mon_num=08 ;; Sep) mon_num=09 ;;
    Oct) mon_num=10 ;; Nov) mon_num=11 ;; Dec) mon_num=12 ;;
    *) mon_num=00 ;;
  esac

  printf "%04d%02d%02d" "$year" "$mon_num" "$day"
}

# ── COLLECT & FILTER LOGS for a given date range ─────────────────────────────
get_filtered_lines() {
  local start_int="$1"
  local end_int="$2"

  {
    # Plain log files
    for f in "$LOG_DIR"/$LOG_PATTERN; do
      [ -f "$f" ] && cat "$f"
    done
    # Compressed log files
    for f in "$LOG_DIR"/${LOG_PATTERN}.*.gz; do
      [ -f "$f" ] && zcat "$f"
    done
  } | awk -v start="$start_int" -v end="$end_int" '
    {
      match($0, /\[([0-9]{2}\/[A-Za-z]{3}\/[0-9]{4})/, arr)
      if (RSTART == 0) next
      raw = arr[1]

      split(raw, p, "/")
      day = p[1]; mon_str = p[2]; year = p[3]

      m = 0
      if      (mon_str == "Jan") m = 1
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

# ── KNOWN BOT UA PATTERN (egrep-compatible) ───────────────────────────────────
KNOWN_BOT_PATTERN="[Gg]ooglebot|[Bb]ingbot|BingPreview|msnbot|[Ss]lurp|DuckDuckBot|\
[Bb]aiduspider|[Yy]andexBot|Applebot|facebookexternalhit|FacebookBot|LinkedInBot|\
Twitterbot|Slackbot|[Tt]elegramBot|ia_archiver|archive\.org_bot|[Ss]emrushBot|\
[Aa]hrefsBot|MJ12bot|DotBot|rogerbot|[Uu]ptimeRobot|Pingdom|GTmetrix|[Pp]etalBot|\
AdsBot-Google|Google-InspectionTool|coccocbot|SiteUptime|Site24x7|StatusCake"

# ── SUSPICIOUS UA PATTERN ─────────────────────────────────────────────────────
SUSPICIOUS_PATTERN="sqlmap|[Nn]ikto|[Zz][Mm][Ee][Uu]|zgrab|[Nn]uclei|\
[Aa]cunetix|[Nn]essus|[Oo]pen[Vv][Aa][Ss]|w3af|wfuzz|dirbuster|gobuster|\
ffuf|feroxbuster|[Hh]avij|[Hh][Tt][Tt]rack|python-requests|python-urllib|\
Go-http-client|libwww-perl|LWP::|[Ss]crapy|PhantomJS|[Hh]eadless[Cc]hrome|\
[Hh]eadless|WPScan|wpscan|[Mm]asscan|[Ee]mail[Cc]ollect|[Ww]eb[Cc]opier|\
[Ww]eb[Ss]tripper|[Ww]eb[Zz][Ii][Pp]|[Zz]eus|[Hh]arvest|scrapy|\
WordPress Hash Grabber|AutoSploit|metasploit"

# ── WORDPRESS / SERVER ATTACK PATH PATTERN ───────────────────────────────────
ATTACK_PATH_PATTERN="wp-login\.php|xmlrpc\.php|wp-config|/\.env|\
wp-cron|install\.php|readme\.html|/etc/passwd|base64_decode|\
union.{0,10}select|eval\(|\.\.\/|%2e%2e|cmd=|exec=|shell=|\
phpinfo|/bin/sh|/bin/bash|insert.{0,10}into|drop.{0,10}table|\
%3[Cc]script|javascript:|<script|alert\("

# =============================================================================
# MAIN — iterate over each window pair
# =============================================================================

echo "============================================================"
echo " Cloudways Bot & Suspicious Traffic Report"
echo " Log dir: $LOG_DIR"
echo "============================================================"
echo ""

# Accumulate suspicious IPs across all windows for final blocklist
ALL_SUSP_IPS_FILE=$(mktemp)
trap 'rm -f "$ALL_SUSP_IPS_FILE"' EXIT

i=0
while [ $i -lt ${#WINDOWS[@]} ]; do
  START_DATE="${WINDOWS[$i]}"
  END_DATE="${WINDOWS[$((i+1))]}"
  i=$((i+2))

  START_INT=$(date_to_int "$START_DATE")
  END_INT=$(date_to_int "$END_DATE")

  echo "============================================================"
  echo " WINDOW: $START_DATE  ->  $END_DATE"
  echo "============================================================"
  echo ""

  FILTERED=$(get_filtered_lines "$START_INT" "$END_INT")

  if [ -z "$FILTERED" ]; then
    echo "WARNING: No log lines found for this window."
    echo ""
    continue
  fi

  TOTAL_LINES=$(echo "$FILTERED" | wc -l)
  echo "Matched lines: $TOTAL_LINES"
  echo ""

  # ── 1. KNOWN / LEGITIMATE BOTS ─────────────────────────────────────────────
  echo "------------------------------------------------------------"
  echo " 1. KNOWN / LEGITIMATE BOTS"
  echo "------------------------------------------------------------"

  KNOWN_LINES=$(echo "$FILTERED" | grep -iE "$KNOWN_BOT_PATTERN" || true)
  KNOWN_COUNT=$(echo "$KNOWN_LINES" | grep -c . || true)

  echo "Total requests from known bots: $KNOWN_COUNT"
  echo ""

  if [ "$KNOWN_COUNT" -gt 0 ]; then
    echo "Top known bots (by request count):"
    echo "$KNOWN_LINES" | awk '
    {
      n = split($0, f, "\"")
      ua = (n >= 6) ? f[6] : "-"
      split(ua, t, " ")
      bot = t[1]
      count[bot]++
    }
    END {
      for (b in count) print count[b], b
    }' | sort -rn | head -15 | \
      awk 'NR==1 { printf "%-8s  %s\n", "Requests", "Bot" }
           { printf "%-8s  %s\n", $1, $2 }'
    echo ""

    echo "Top known-bot source IPs:"
    echo "$KNOWN_LINES" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | \
      awk 'NR==1 { printf "%-8s  %s\n", "Requests", "IP" }
           { printf "%-8s  %s\n", $1, $2 }'
    echo ""
  fi

  # ── 2. SUSPICIOUS / MALICIOUS BOTS ─────────────────────────────────────────
  echo "------------------------------------------------------------"
  echo " 2. SUSPICIOUS / MALICIOUS BOTS & TOOLS"
  echo "------------------------------------------------------------"

  SUSP_LINES=$(echo "$FILTERED" | grep -iE "$SUSPICIOUS_PATTERN" || true)
  SUSP_COUNT=$(echo "$SUSP_LINES" | grep -c . || true)

  echo "Total suspicious UA requests: $SUSP_COUNT"
  echo ""

  if [ "$SUSP_COUNT" -gt 0 ]; then
    echo "Suspicious user-agents detected:"
    echo "$SUSP_LINES" | awk '
    {
      n = split($0, f, "\"")
      ua = (n >= 6) ? f[6] : "-"
      count[ua]++
    }
    END {
      for (u in count) print count[u], u
    }' | sort -rn | head -15 | \
      awk 'NR==1 { printf "%-8s  %s\n", "Requests", "User-Agent" }
           { printf "%-8s  %s\n", $1, substr($0, index($0,$2)) }'
    echo ""

    echo "Top offending IPs:"
    echo "$SUSP_LINES" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | \
      awk 'NR==1 { printf "%-8s  %s\n", "Requests", "IP" }
           { printf "%-8s  %s\n", $1, $2 }'
    echo ""

    echo "$SUSP_LINES" | awk '{print $1}' >> "$ALL_SUSP_IPS_FILE"
  fi

  # ── 3. EMPTY / BLANK USER-AGENTS ───────────────────────────────────────────
  echo "------------------------------------------------------------"
  echo " 3. EMPTY / BLANK USER-AGENTS  (highly suspicious)"
  echo "------------------------------------------------------------"

  EMPTY_LINES=$(echo "$FILTERED" | awk '
  {
    n = split($0, f, "\"")
    ua = (n >= 6) ? f[6] : ""
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", ua)
    if (ua == "-" || ua == "" || ua == " ") print
  }' || true)
  EMPTY_COUNT=$(echo "$EMPTY_LINES" | grep -c . || true)

  echo "Requests with blank/empty User-Agent: $EMPTY_COUNT"
  echo ""

  if [ "$EMPTY_COUNT" -gt 0 ]; then
    echo "Top IPs with empty UA:"
    echo "$EMPTY_LINES" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | \
      awk 'NR==1 { printf "%-8s  %s\n", "Requests", "IP" }
           { printf "%-8s  %s\n", $1, $2 }'
    echo ""

    echo "$EMPTY_LINES" | awk '{print $1}' >> "$ALL_SUSP_IPS_FILE"
  fi

  # ── 4. WORDPRESS / SERVER ATTACK PATHS ─────────────────────────────────────
  echo "------------------------------------------------------------"
  echo " 4. WORDPRESS / SERVER ATTACK PATHS"
  echo "------------------------------------------------------------"

  WP_LINES=$(echo "$FILTERED" | grep -iE "$ATTACK_PATH_PATTERN" || true)
  WP_COUNT=$(echo "$WP_LINES" | grep -c . || true)

  echo "Requests hitting sensitive/attack paths: $WP_COUNT"
  echo ""

  if [ "$WP_COUNT" -gt 0 ]; then
    echo "Most targeted paths:"
    echo "$WP_LINES" | awk '
    {
      uri = $7
      split(uri, p, "?")
      clean = p[1]
      count[clean]++
    }
    END { for (u in count) print count[u], u }
    ' | sort -rn | head -15 | \
      awk 'NR==1 { printf "%-8s  %s\n", "Requests", "Path" }
           { printf "%-8s  %s\n", $1, $2 }'
    echo ""

    echo "Top attacking IPs:"
    echo "$WP_LINES" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | \
      awk 'NR==1 { printf "%-8s  %s\n", "Requests", "IP" }
           { printf "%-8s  %s\n", $1, $2 }'
    echo ""

    echo "HTTP status codes for attack path requests:"
    echo "$WP_LINES" | awk '{print $9}' | grep -E '^[0-9]{3}$' | \
      sort | uniq -c | sort -rn | \
      awk 'NR==1 { printf "%-8s  %s\n", "Count", "HTTP Status" }
           { printf "%-8s  HTTP %s\n", $1, $2 }'
    echo ""

    echo "$WP_LINES" | awk '{print $1}' >> "$ALL_SUSP_IPS_FILE"
  fi

  # ── 5. HIGH-FREQUENCY IPs  (>100 requests) ─────────────────────────────────
  echo "------------------------------------------------------------"
  echo " 5. HIGH-FREQUENCY IPs  (> 100 requests in window)"
  echo "------------------------------------------------------------"

  HF_RESULT=$(echo "$FILTERED" | awk '{print $1}' | sort | uniq -c | sort -rn | \
    awk '$1 > 100 { printf "%-8s  %s\n", $1, $2 }' || true)
  HF_COUNT=$(echo "$HF_RESULT" | grep -c . || true)

  echo "IPs exceeding 100 requests: $HF_COUNT"
  echo ""
  if [ "$HF_COUNT" -gt 0 ]; then
    printf "%-8s  %s\n" "Requests" "IP"
    echo "$HF_RESULT"
    echo ""
  fi

  # ── 6. HTTP STATUS CODE BREAKDOWN ──────────────────────────────────────────
  echo "------------------------------------------------------------"
  echo " 6. HTTP STATUS CODE BREAKDOWN"
  echo "------------------------------------------------------------"

  echo "$FILTERED" | awk '{print $9}' | grep -E '^[0-9]{3}$' | \
    sort | uniq -c | sort -rn | head -15 | \
    awk 'NR==1 { printf "%-8s  %s\n", "Count", "HTTP Status" }
         { printf "%-8s  HTTP %s\n", $1, $2 }'
  echo ""

  # ── 7. HOURLY REQUEST DISTRIBUTION ─────────────────────────────────────────
  echo "------------------------------------------------------------"
  echo " 7. HOURLY REQUEST DISTRIBUTION"
  echo "------------------------------------------------------------"

  printf "%-8s  %s\n" "Hour" "Requests"
  echo "$FILTERED" | awk '
  {
    match($0, /\[([0-9]{2}\/[A-Za-z]{3}\/[0-9]{4}):([0-9]{2})/, arr)
    if (RSTART > 0) count[arr[2]]++
  }
  END {
    for (h in count) print h, count[h]
  }' | sort | awk '{ printf "%-8s  %s\n", $1":00", $2 }'
  echo ""

  # ── 8. WINDOW SUMMARY ──────────────────────────────────────────────────────
  echo "============================================================"
  echo " SUMMARY: $START_DATE -> $END_DATE"
  echo "============================================================"

  BOT_TOTAL=$((KNOWN_COUNT + SUSP_COUNT + EMPTY_COUNT))
  PCT=0
  [ "$TOTAL_LINES" -gt 0 ] && PCT=$(( BOT_TOTAL * 100 / TOTAL_LINES ))

  printf "%-32s  %s\n" "Total requests"              "$TOTAL_LINES"
  printf "%-32s  %s\n" "Known bot requests"           "$KNOWN_COUNT"
  printf "%-32s  %s\n" "Suspicious bot requests"      "$SUSP_COUNT"
  printf "%-32s  %s\n" "Empty User-Agent requests"    "$EMPTY_COUNT"
  printf "%-32s  %s\n" "Attack-path hits"             "$WP_COUNT"
  printf "%-32s  ~%s%%\n" "Est. bot/suspicious traffic" "$PCT"
  echo ""

  if [ "$SUSP_COUNT" -gt 0 ] || [ "$EMPTY_COUNT" -gt 50 ] || [ "$WP_COUNT" -gt 20 ]; then
    echo "WARNING: SUSPICIOUS ACTIVITY DETECTED IN THIS WINDOW"
  else
    echo "OK: No significant malicious activity detected"
  fi
  echo ""

done

# =============================================================================
# COMBINED SUSPICIOUS IP BLOCKLIST (all windows)
# =============================================================================
echo "============================================================"
echo " COMBINED SUSPICIOUS IP BLOCKLIST  (all windows)"
echo "============================================================"
echo ""

if [ -s "$ALL_SUSP_IPS_FILE" ]; then
  printf "%-8s  %s\n" "Hits" "IP"
  sort "$ALL_SUSP_IPS_FILE" | uniq -c | sort -rn | \
    awk '{ printf "%-8s  %s\n", $1, $2 }'
  echo ""
  echo "To block in Nginx, add to your server block:"
  echo "  deny <IP>;"
  echo ""
  echo "To block in .htaccess:"
  echo "  Require not ip <IP>"
else
  echo "No suspicious IPs collected across all windows."
fi

echo ""
echo "============================================================"
echo " Report complete."
echo "============================================================"
