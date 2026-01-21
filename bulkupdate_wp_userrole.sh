#!/bin/bash

# WordPress Bulk User Role Change Script
# Scans all WordPress apps and changes user role where the user exists

EMAIL=""
NEW_ROLE="subscriber"
WORDPRESS_PATH="/home/master/applications/*/public_html"

echo "=========================================="
echo "WordPress User Role Change Script"
echo "=========================================="
echo "Email: $EMAIL"
echo "New Role: $NEW_ROLE"
echo ""

# Counter for tracking
FOUND_COUNT=0
CHANGED_COUNT=0
NOT_FOUND_COUNT=0

# Loop through all WordPress installations
for WP_DIR in $WORDPRESS_PATH; do
    # Check if directory exists and has wp-config.php
    if [ ! -f "$WP_DIR/wp-config.php" ]; then
        continue
    fi

    APP_NAME=$(basename $(dirname "$WP_DIR"))
    echo "Checking: $APP_NAME"

    # Check if user exists by email
    USER_EXISTS=$(cd "$WP_DIR" && wp user list --search="$EMAIL" --field=ID --allow-root 2>/dev/null | head -1)

    if [ -n "$USER_EXISTS" ]; then
        echo "  ✓ User found (ID: $USER_EXISTS)"
        FOUND_COUNT=$((FOUND_COUNT + 1))

        # Get current role
        CURRENT_ROLE=$(cd "$WP_DIR" && wp user get "$USER_EXISTS" --field=roles --allow-root 2>/dev/null)
        echo "  Current role: $CURRENT_ROLE"

        # Change role
        if cd "$WP_DIR" && wp user set-role "$USER_EXISTS" "$NEW_ROLE" --allow-root 2>/dev/null; then
            echo "  ✓ Role changed to '$NEW_ROLE'"
            CHANGED_COUNT=$((CHANGED_COUNT + 1))
        else
            echo "  ✗ Error changing role"
        fi
    else
        echo "  ✗ User not found"
        NOT_FOUND_COUNT=$((NOT_FOUND_COUNT + 1))
    fi

    echo ""
done

# Summary
echo "=========================================="
echo "Summary"
echo "=========================================="
echo "Total WordPress apps scanned: $(ls -d /home/master/applications/*/public_html 2>/dev/null | wc -l)"
echo "User found in: $FOUND_COUNT app(s)"
echo "Role changed in: $CHANGED_COUNT app(s)"
echo "User not found in: $NOT_FOUND_COUNT app(s)"
echo "=========================================="
