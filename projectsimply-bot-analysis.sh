#!/usr/bin/env bash
# =============================================================================
# Cloudways Access Log — Bot & Suspicious Traffic Analyzer
# Prompts for app database(s) and date window(s), then reports on bot
# activity, suspicious UAs, and attack paths for each.
# Usage: ./analyze_bot_traffic.sh
# =============================================================================

# ── CONFIG ────────────────────────────────────────────────────────────────────
BASE_APPS_DIR="/home/master/applications"
LOG_PATTERN="backend_wordpress-*.access.log"

# ── PROMPT FOR APPLICATION(S) ─────────────────────────────────────────────────
if [ ! -d "$BASE_APPS_DIR" ]; then
  echo "ERROR: $BASE_APPS_DIR not found. Run this on the Cloudways server itself."
  exit 1
fi

mapfile -t AVAILABLE_APPS < <(cd "$BASE_APPS_DIR" 2>/dev/null && for d in */; do [ -d "$d" ] && echo "${d%/}"; done | sort)

if [ ${#AVAILABLE_APPS[@]} -eq 0 ]; then
  echo "No applications found under $BASE_APPS_DIR"
  exit 1
fi

echo "Available applications under $BASE_APPS_DIR:"
printf '  %s\n' "${AVAILABLE_APPS[@]}"
echo ""

SELECTED_APPS=()
while [ ${#SELECTED_APPS[@]} -eq 0 ]; do
  read -rp "Enter app database name to check, or ALL: " APP_CHOICE

  if [ -z "$APP_CHOICE" ]; then
    echo "  Please enter an app name or ALL."
    continue
  fi

  if [ "$APP_CHOICE" = "ALL" ] || [ "$APP_CHOICE" = "all" ]; then
    SELECTED_APPS=("${AVAILABLE_APPS[@]}")
  else
    FOUND=0
    for a in "${AVAILABLE_APPS[@]}"; do
      [ "$a" = "$APP_CHOICE" ] && FOUND=1
    done
    if [ $FOUND -eq 0 ]; then
      echo "  '$APP_CHOICE' not found. Pick one from the list above, or type ALL."
      continue
    fi
    SELECTED_APPS=("$APP_CHOICE")
  fi
done
echo ""

# ── PROMPT FOR DATE WINDOWS ───────────────────────────────────────────────────
DATE_RE='^[0-9]{1,2}/[A-Za-z]{3}/[0-9]{4}$'

validate_date() {
  local d="$1"
  if [[ ! "$d" =~ $DATE_RE ]]; then
    return 1
  fi
  local mon_str
  mon_str=$(echo "$d" | cut -d'/' -f2)
  case "$mon_str" in
    Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) return 0 ;;
    *) return 1 ;;
  esac
}

WINDOWS=()

echo "Enter date windows to analyze (format: DD/Mon/YYYY, e.g. 16/Mar/2026)."
echo "These will be applied to every selected application."
echo "Press Enter with no input when done."
echo ""

while true; do
  read -rp "Start date [blank to finish]: " START_DATE
  [ -z "$START_DATE" ] && break

  if ! validate_date "$START_DATE"; then
    echo "  Invalid format. Use DD/Mon/YYYY (e.g. 16/Mar/2026)."
    continue
  fi

  read -rp "End date: " END_DATE

  if ! validate_date "$END_DATE"; then
    echo "  Invalid format. Use DD/Mon/YYYY (e.g. 18/Mar/2026)."
    continue
  fi

  WINDOWS+=("$START_DATE" "$END_DATE")
  echo "  Added window: $START_DATE -> $END_DATE"
  echo ""
done

if [ ${#WINDOWS[@]} -eq 0 ]; then
  echo "No date windows entered. Exiting."
  exit 1
fi
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
  local log_dir="$1"
  local start_int="$2"
  local end_int="$3"

  {
    # Plain log files
    for f in "$log_dir"/$LOG_PATTERN; do
      [ -f "$f" ] && cat "$f"
    done
    # Compressed log files
    for f in "$log_dir"/${LOG_PATTERN}.*.gz; do
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
# MAIN — iterate over each selected application, then each window pair
# =============================================================================

for APP_NAME in "${SELECTED_APPS[@]}"; do
  LOG_DIR="$BASE_APPS_DIR/$APP_NAME/logs"

  echo "############################################################"
  echo "# APPLICATION: $APP_NAME"
  echo "# Log dir: $LOG_DIR"
  echo "############################################################"
  echo ""

  if [ ! -d "$LOG_DIR" ]; then
    echo "WARNING: Log directory not found for '$APP_NAME'. Skipping."
    echo ""
    continue
  fi

  # Accumulate suspicious IPs across all windows for this app's final blocklist
  ALL_SUSP_IPS_FILE=$(mktemp)

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

    FILTERED=$(get_filtered_lines "$LOG_DIR" "$START_INT" "$END_INT")

    if [ -z "$FILTERED" ]; then
      echo "WARNING: No log lines found for this window."
      echo ""
      continue
    fi

    TOTAL_LINES=$(echo "$FILTERED" | wc -l)
    echo "Matched lines: $TOTAL_LINES"
    echo ""

    # ── 1. KNOWN / LEGITIMATE BOTS ───────────────────────────────────────────
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

    # ── 2. SUSPICIOUS / MALICIOUS BOTS ───────────────────────────────────────
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

    # ── 3. EMPTY / BLANK USER-AGENTS ─────────────────────────────────────────
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

    # ── 4. WORDPRESS / SERVER ATTACK PATHS ───────────────────────────────────
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

    # ── 5. HIGH-FREQUENCY IPs  (>100 requests) ───────────────────────────────
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

    # ── 6. HTTP STATUS CODE BREAKDOWN ────────────────────────────────────────
    echo "------------------------------------------------------------"
    echo " 6. HTTP STATUS CODE BREAKDOWN"
    echo "------------------------------------------------------------"

    echo "$FILTERED" | awk '{print $9}' | grep -E '^[0-9]{3}$' | \
      sort | uniq -c | sort -rn | head -15 | \
      awk 'NR==1 { printf "%-8s  %s\n", "Count", "HTTP Status" }
           { printf "%-8s  HTTP %s\n", $1, $2 }'
    echo ""

    # ── 7. HOURLY REQUEST DISTRIBUTION ───────────────────────────────────────
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

    # ── 8. WINDOW SUMMARY ────────────────────────────────────────────────────
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

  # ===========================================================================
  # COMBINED SUSPICIOUS IP BLOCKLIST (all windows, this app)
  # ===========================================================================
  echo "============================================================"
  echo " COMBINED SUSPICIOUS IP BLOCKLIST — $APP_NAME  (all windows)"
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
    echo "No suspicious IPs collected across all windows for $APP_NAME."
  fi

  rm -f "$ALL_SUSP_IPS_FILE"
  echo ""
done

echo "============================================================"
echo " Report complete."
echo "============================================================"
