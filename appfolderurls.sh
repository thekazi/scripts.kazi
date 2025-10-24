#!/bin/bash

# Directory containing application folders
app_base_dir=""/home/master/applications""

# Loop through each application directory
ls -d ""$app_base_dir""/* | while read app_dir; do
    # Output the application folder name
    echo ""Application: $(basename ""$app_dir"")""
    
    # Check if server.nginx file exists in the conf directory
    nginx_conf=""${app_dir}/conf/server.nginx""
    if [ -f ""$nginx_conf"" ]; then
        # Extract and print all domains (server_name entries)
        grep -E ""server_name"" ""$nginx_conf"" | awk '{for (i=2; i<=NF; i++) print $i}' | sed 's/;$//'
    else
        echo ""server.nginx file not found""
    fi

    echo ""---------------------------""
done
