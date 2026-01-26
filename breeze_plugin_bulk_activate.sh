#!/bin/bash

# Script to detect WordPress installations and activate Breeze plugin
# Scans /home/master/applications/*/public_html for WordPress sites

BASE_PATH="/home/master/applications"
LOG_FILE="/var/log/wp_breeze_activation.log"

echo "Starting WordPress Breeze activation script at $(date)" >> "$LOG_FILE"

# Check if base path exists
if [ ! -d "$BASE_PATH" ]; then
    echo "Error: Base path $BASE_PATH does not exist" | tee -a "$LOG_FILE"
    exit 1
fi

# Counter for statistics
total_apps=0
wp_found=0
breeze_activated=0
breeze_failed=0

# Loop through all application directories
for app_dir in "$BASE_PATH"/*/public_html; do
    # Check if directory exists
    [ -d "$app_dir" ] || continue
    
    ((total_apps++))
    app_name=$(basename "$(dirname "$app_dir")")
    
    # Check if wp-config.php exists (WordPress indicator)
    if [ -f "$app_dir/wp-config.php" ]; then
        ((wp_found++))
        echo "Found WordPress installation in: $app_name" | tee -a "$LOG_FILE"
        
        # Check if Breeze plugin directory exists
        if [ -d "$app_dir/wp-content/plugins/breeze" ]; then
            # Change to app directory and run wp breeze activate command
            cd "$app_dir" || continue
            
            if wp plugin is-active breeze --allow-root 2>/dev/null; then
                echo "  ✓ Breeze is already active in $app_name" | tee -a "$LOG_FILE"
                ((breeze_activated++))
            else
                echo "  → Activating Breeze for $app_name..." | tee -a "$LOG_FILE"
                activation_output=$(wp plugin activate breeze --allow-root 2>&1)
                if [ $? -eq 0 ]; then
                    echo "  ✓ Successfully activated Breeze for $app_name" | tee -a "$LOG_FILE"
                    ((breeze_activated++))
                else
                    echo "  ✗ Failed to activate Breeze for $app_name" | tee -a "$LOG_FILE"
                    echo "    Error: $activation_output" | tee -a "$LOG_FILE"
                    ((breeze_failed++))
                fi
            fi
            
            cd - > /dev/null || continue
        else
            echo "  ⚠ Breeze plugin not found in $app_name - skipping" | tee -a "$LOG_FILE"
        fi
    fi
done

# Summary
echo "" | tee -a "$LOG_FILE"
echo "===== Summary =====" | tee -a "$LOG_FILE"
echo "Total application directories scanned: $total_apps" | tee -a "$LOG_FILE"
echo "WordPress installations found: $wp_found" | tee -a "$LOG_FILE"
echo "Breeze successfully activated: $breeze_activated" | tee -a "$LOG_FILE"
echo "Breeze activation failures: $breeze_failed" | tee -a "$LOG_FILE"
echo "Script completed at $(date)" | tee -a "$LOG_FILE"
