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
# Point 4: Ask user for action (whitelist, blacklist, or greylist)
echo "Do you want to (1) Whitelist, (2) Blacklist, or (3) Greylist IPs?"
read -p "Enter 1 for Whitelist, 2 for Blacklist, 3 for Greylist: " action
if [[ $action == "1" ]]; then
    command_purpose="white"
    echo "You selected Whitelist."
elif [[ $action == "2" ]]; then
    command_purpose="drop"
    echo "You selected Blacklist."
elif [[ $action == "3" ]]; then
    command_purpose="captcha"
    echo "You selected Greylist."
    read -p "Enter a comment for the greylisted IPs (optional, press Enter to skip): " greylist_comment
else
    echo "Invalid selection. Please run the script again."
    exit 1
fi
# Point 5: Get IPs to process
read -r -p "Enter the IP addresses (separated by spaces): " input_ips
process_ips=($input_ips)  # Convert space-separated input into an array
# Execute Imunify360 command on each server
echo "Running Imunify360 command on servers..."
for ip_addr in "${ip[@]}"; do
    echo "Connecting to $ip_addr..."
    for process_ip in "${process_ips[@]}"; do
        echo "Processing IP: $process_ip ($command_purpose) on $ip_addr..."
        if [[ $action == "3" ]]; then
            if [[ -n $greylist_comment ]]; then
                ssh -t -p22 -o StrictHostKeyChecking=no systeam@$ip_addr "sudo imunify360-agent ip-list local add $process_ip --purpose $command_purpose --comment '$greylist_comment'" 2>/dev/null
            else
                ssh -t -p22 -o StrictHostKeyChecking=no systeam@$ip_addr "sudo imunify360-agent ip-list local add $process_ip --purpose $command_purpose" 2>/dev/null
            fi
        else
            ssh -t -p22 -o StrictHostKeyChecking=no systeam@$ip_addr "sudo imunify360-agent ip-list local add --purpose $command_purpose $process_ip" 2>/dev/null
        fi
        if [[ $? -eq 0 ]]; then
            echo "Successfully processed $process_ip ($command_purpose) on $ip_addr."
        else
            echo "Failed to process $process_ip ($command_purpose) on $ip_addr."
        fi
    done
    echo
done
# Output all results
echo "All operations completed."
