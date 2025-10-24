#!/bin/bash

# Prompt for email and API key
read -p "Enter Client's Cloudways email: " email
read -sp "Enter your Cloudways API key: " api_key
echo # Newline for readability

# Define API URLs
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

# Fetch server info
echo "�Fetching server information..."
server_response=$(curl -s -X GET \
    -H "Authorization: Bearer $access_token" \
    -H "Accept: application/json" \
    "$server_url")

if [[ $(echo "$server_response" | jq -r '.status') != "true" ]]; then
    echo "�Failed to retrieve server information."
    exit 1
fi

# Output Public IPs to terminal
echo
echo " Public IPs of all servers:"
echo "$server_response" | jq -r '.servers[] | .public_ip'
echo
echo "�Operation completed."
