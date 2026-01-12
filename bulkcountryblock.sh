#!/bin/bash

# Point 1: Prompt for email and API key
read -p "Enter Client's Cloudways email: " email
read -sp "Enter your Cloudways API key: " api_key
echo # Newline for readability

# Point 2: Define API URLs
token_url="https://api.cloudways.com/api/v1/oauth/access_token"
server_url="https://api.cloudways.com/api/v1/server"

# Generate access token
echo "Generating access token..."
response=$(curl -s -X POST "$token_url" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\",\"api_key\":\"$api_key\"}")

access_token=$(echo "$response" | jq -r '.access_token')

if [[ $access_token == "null" || -z $access_token ]]; then
    echo "Failed to generate access token. Please check your email and API key."
    exit 1
fi

echo "Access token generated successfully."

# Point 3: Fetch server information and save public IPs
echo "Retrieving server public IPs..."
server_response=$(curl -s -X GET "$server_url" \
    -H "Authorization: Bearer $access_token" \
    -H "Accept: application/json")

if [[ $(echo "$server_response" | jq -r '.status') != "true" ]]; then
    echo "Failed to retrieve server information."
    exit 1
fi

# Extract and save public IPs
echo "$server_response" | jq -c '.servers[] | {PublicIP: .public_ip}' > server_ips.json
echo "Server public IPs saved to server_ips.json."

# Save public IPs to an array
ip=($(cat server_ips.json | jq -r '.PublicIP'))

# Define countries to block (using ISO 3166-1 alpha-2 country codes)
countries_to_block=("KP" "IR" "SY" "RU" "BY" "CU" "AF" "YE" "SO" "SD" "SS" "LY" "IQ" "MM" "ER")

# Country name mapping for reference
declare -A country_names=(
    [KP]="North Korea"
    [IR]="Iran"
    [SY]="Syria"
    [RU]="Russia"
    [BY]="Belarus"
    [CU]="Cuba"
    [AF]="Afghanistan"
    [YE]="Yemen"
    [SO]="Somalia"
    [SD]="Sudan"
    [SS]="South Sudan"
    [LY]="Libya"
    [IQ]="Iraq"
    [MM]="Myanmar"
    [ER]="Eritrea"
)

echo
echo "=========================================="
echo "Imunify360 Country Blacklist Manager"
echo "=========================================="
echo "Countries to be blocked:"
for country_code in "${countries_to_block[@]}"; do
    echo "  - $country_code (${country_names[$country_code]})"
done
echo

# Execute Imunify360 commands on each server
for ip_addr in "${ip[@]}"; do
    echo
    echo "=========================================="
    echo "Processing Server: $ip_addr"
    echo "=========================================="

    # Step 1: Retrieve and save current blacklisted countries
    echo "Step 1: Retrieving current blacklisted countries..."
    ssh -t -p22 -o StrictHostKeyChecking=no systeam@$ip_addr "sudo imunify360-agent blacklist country list" 2>/dev/null | tee backup_${ip_addr}.txt

    if [[ -s backup_${ip_addr}.txt ]]; then
        echo "✓ Current blacklist retrieved and saved to backup_${ip_addr}.txt"
        ssh -t -p22 -o StrictHostKeyChecking=no systeam@$ip_addr "sudo bash -c 'cat > /home/master/old_blacklist.txt'" < backup_${ip_addr}.txt 2>/dev/null
        echo "✓ Backup also saved on server at /home/master/old_blacklist.txt"
    else
        echo "⚠ Warning: Could not retrieve blacklist from $ip_addr"
    fi
    echo

    # Step 2: Remove all countries from blacklist
    echo "Step 2: Removing all countries from blacklist..."
    echo "Running: imunify360-agent blacklist country delete ${countries_to_block[@]}"

    ssh -t -p22 -o StrictHostKeyChecking=no systeam@$ip_addr "sudo imunify360-agent blacklist country delete ${countries_to_block[@]}" 2>/dev/null
    echo "✓ Removal command executed on $ip_addr (ignoring if countries were not in blacklist)"
    echo

    # Step 3: Add required countries to blacklist
    echo "Step 3: Adding required countries to blacklist..."
    echo "Running: imunify360-agent blacklist country add ${countries_to_block[@]}"

    if ssh -t -p22 -o StrictHostKeyChecking=no systeam@$ip_addr "sudo imunify360-agent blacklist country add ${countries_to_block[@]}" 2>/dev/null; then
        echo "✓ Successfully added all countries to blacklist on $ip_addr"
    else
        echo "✗ Failed to add countries to blacklist on $ip_addr"
        continue
    fi
    echo

    # Step 4: Verification - Display final blacklist
    echo "Step 4: Final Verification"
    echo "Displaying final blacklist on $ip_addr:"
    if ssh -t -p22 -o StrictHostKeyChecking=no systeam@$ip_addr "sudo imunify360-agent blacklist country list" 2>/dev/null; then
        echo "✓ Country blacklist update completed successfully on $ip_addr"
    else
        echo "✗ Failed to verify final blacklist on $ip_addr"
    fi
    echo
done

echo "=========================================="
echo "All servers processed at $(date)"
echo "=========================================="
