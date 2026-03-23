#!/bin/bash

set -euo pipefail

# Prompt for email and API key
read -p "Enter Client's Cloudways email: " email
read -sp "Enter your Cloudways API key: " api_key
echo

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required but not installed. Please install jq and try again."
    exit 1
fi

# API URLs
token_url="https://api.cloudways.com/api/v1/oauth/access_token"
server_url="https://api.cloudways.com/api/v1/server"

# Generate access token
echo "Generating access token..."
response=$(curl -s -X POST "$token_url" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\",\"api_key\":\"$api_key\"}")

access_token=$(echo "$response" | jq -r '.access_token')

if [[ "$access_token" == "null" || -z "$access_token" ]]; then
    echo "Failed to generate access token. Please check your email and API key."
    exit 1
fi

echo "Access token generated successfully."

# Fetch server information
echo "Retrieving server details..."
server_response=$(curl -s -X GET "$server_url" \
    -H "Authorization: Bearer $access_token" \
    -H "Accept: application/json")

if [[ $(echo "$server_response" | jq -r '.status') != "true" ]]; then
    echo "Failed to retrieve server information."
    exit 1
fi

# Prepare output file
output_file="server_os_versions.txt"
echo "Saving server info to $output_file"
{
    echo "Server OS Details Report"
    echo "========================"
} > "$output_file"

# Extract server info into a temporary array
mapfile -t servers < <(echo "$server_response" | jq -c '.servers[] | {ip: .public_ip, label: .label}')

# Iterate and collect info
for server in "${servers[@]}"; do
    ip=$(echo "$server" | jq -r '.ip')
    label=$(echo "$server" | jq -r '.label')

    echo "Connecting to $ip..."
    os_version=$(ssh -p22 -o StrictHostKeyChecking=no systeam@"$ip" "\
if [ -f /etc/os-release ]; then
    . /etc/os-release
    printf '%s\n' \"\${PRETTY_NAME:-\${NAME:-Unknown} \${VERSION:-}}\"
elif command -v lsb_release >/dev/null 2>&1; then
    lsb_release -ds
else
    uname -sr
fi" 2>/dev/null || true)

    {
        echo "$ip"
        echo "$label"
        if [[ -n "$os_version" ]]; then
            echo "$os_version"
        else
            echo "Operating system version could not be retrieved."
        fi
        echo ""
    } >> "$output_file"
done
