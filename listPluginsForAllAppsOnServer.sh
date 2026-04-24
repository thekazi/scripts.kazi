#!/bin/bash
# =============================================================================
# WordPress Plugin Audit Script
# Scans all applications under /home/master/applications/*/public_html/
# and outputs active/inactive plugin status for each WordPress installation.
#
# Cloudways fix: WP-CLI is run via `cd $WEBROOT && wp ...` so PHP can resolve
# the relative require('wp-salt.php') inside wp-config.php correctly.
# =============================================================================

WEBROOT_PATTERN="/home/master/applications/*/public_html"
OUTPUT_DIR="/home/master/wp_plugin_audit"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT_FILE="$OUTPUT_DIR/plugin_report_$TIMESTAMP.txt"
CSV_FILE="$OUTPUT_DIR/plugin_report_$TIMESTAMP.csv"

# WP-CLI path — auto-detected, falls back to /usr/local/bin/wp
WPCLI=$(command -v wp || echo "/usr/local/bin/wp")

# -----------------------------------------------------------------------------
# Setup
# -----------------------------------------------------------------------------
mkdir -p "$OUTPUT_DIR"

echo "WordPress Plugin Audit — $TIMESTAMP" | tee "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"
echo ""

# CSV header
echo "Application,Plugin Name,Plugin Slug,Status,Version,Update Available" > "$CSV_FILE"

TOTAL_APPS=0
TOTAL_WP=0
TOTAL_PLUGINS=0

# -----------------------------------------------------------------------------
# Loop through all app webroots
# -----------------------------------------------------------------------------
for WEBROOT in $WEBROOT_PATTERN; do

    # Derive app name from path (e.g. mysite from /home/master/applications/mysite/public_html)
    APP_NAME=$(echo "$WEBROOT" | awk -F'/' '{print $5}')

    # Skip if directory doesn't exist
    [ -d "$WEBROOT" ] || continue

    TOTAL_APPS=$((TOTAL_APPS + 1))

    # Check if this is actually a WordPress install
    if [ ! -f "$WEBROOT/wp-config.php" ] && [ ! -f "$WEBROOT/wp-load.php" ]; then
        echo "[ SKIP ] $APP_NAME — No WordPress installation found" | tee -a "$REPORT_FILE"
        echo "" | tee -a "$REPORT_FILE"
        continue
    fi

    TOTAL_WP=$((TOTAL_WP + 1))

    echo "[ APP ] $APP_NAME" | tee -a "$REPORT_FILE"
    echo "  Path: $WEBROOT" | tee -a "$REPORT_FILE"

    # KEY FIX: cd into the webroot before running WP-CLI.
    # On Cloudways, wp-config.php uses a relative require() for wp-salt.php.
    # Without cd, PHP resolves the path from the wrong working directory and fatals.
    PLUGIN_OUTPUT=$(
        cd "$WEBROOT" && sudo "$WPCLI" plugin list \
            --path="$WEBROOT" \
            --format=csv \
            --fields=name,title,status,version,update \
            --allow-root \
            --no-color \
            2>/dev/null
    )
    WP_EXIT=$?

    # Strip any stray PHP notice/deprecated lines that may bleed into stdout
    PLUGIN_OUTPUT=$(echo "$PLUGIN_OUTPUT" | grep -v "^Deprecated:" | grep -v "^Notice:" | grep -v "^Warning:" | grep -v "^Fatal error:")

    if [ $WP_EXIT -ne 0 ] || [ -z "$PLUGIN_OUTPUT" ]; then
        # Re-run capturing stderr to show the real error
        REAL_ERROR=$(
            cd "$WEBROOT" && sudo "$WPCLI" plugin list \
                --path="$WEBROOT" \
                --format=csv \
                --fields=name,title,status,version,update \
                --allow-root \
                --no-color \
                2>&1 | grep -v "^Deprecated:" | grep -v "^Notice:" | grep -v "^Warning:" | head -3
        )
        echo "  [!] Failed to retrieve plugins. Error: $REAL_ERROR" | tee -a "$REPORT_FILE"
        echo "" | tee -a "$REPORT_FILE"
        continue
    fi

    # Count plugins for this app (skip CSV header line)
    PLUGIN_COUNT=$(echo "$PLUGIN_OUTPUT" | tail -n +2 | wc -l)
    TOTAL_PLUGINS=$((TOTAL_PLUGINS + PLUGIN_COUNT))
    echo "  Plugins found: $PLUGIN_COUNT" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"

    # Pretty-print to report
    printf "  %-40s %-10s %-10s %-10s\n" "Plugin" "Status" "Version" "Update" | tee -a "$REPORT_FILE"
    printf "  %-40s %-10s %-10s %-10s\n" "------" "------" "-------" "------" | tee -a "$REPORT_FILE"

    # Process each plugin row (skip WP-CLI CSV header)
    echo "$PLUGIN_OUTPUT" | tail -n +2 | while IFS=',' read -r SLUG TITLE STATUS VERSION UPDATE; do
        printf "  %-40s %-10s %-10s %-10s\n" "$TITLE" "$STATUS" "$VERSION" "$UPDATE" | tee -a "$REPORT_FILE"
        echo "\"$APP_NAME\",\"$TITLE\",\"$SLUG\",\"$STATUS\",\"$VERSION\",\"$UPDATE\"" >> "$CSV_FILE"
    done

    echo "" | tee -a "$REPORT_FILE"
    echo "---------------------------------------------" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"

done

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo "SUMMARY" | tee -a "$REPORT_FILE"
echo "==============================" | tee -a "$REPORT_FILE"
echo "  Total app directories scanned : $TOTAL_APPS" | tee -a "$REPORT_FILE"
echo "  WordPress installs found      : $TOTAL_WP" | tee -a "$REPORT_FILE"
echo "  Total plugins recorded        : $TOTAL_PLUGINS" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "  Text report : $REPORT_FILE" | tee -a "$REPORT_FILE"
echo "  CSV report  : $CSV_FILE" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "Audit complete — $(date)" | tee -a "$REPORT_FILE"
