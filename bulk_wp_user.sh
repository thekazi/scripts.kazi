#!/bin/bash

hostname=$(cat /etc/hostname)
echo "Server: $hostname"

# Strong password (change if needed)
PASSWORD='Str0ngP@ssw0rd!2026'

for i in $(find /home/master/applications/* -maxdepth 0 -type d -printf '%f\n'); do
    echo "Processing application: $i"

    /bin/su - $i -s /bin/bash -c "
        cd /home/master/applications/$i/public_html || exit

        # Roberto
        wp user create roberto.velasquez roberto.velasquez@breadstack.com --role=administrator --user_pass='$PASSWORD' --allow-root 2>/dev/null || \
        wp user update roberto.velasquez --user_pass='$PASSWORD' --allow-root

        # Juana
        wp user create juana.zambrano juana.zambrano@breadstack.com --role=administrator --user_pass='$PASSWORD' --allow-root 2>/dev/null || \
        wp user update juana.zambrano --user_pass='$PASSWORD' --allow-root

        # Kris
        wp user create kris.hoang kris.hoang@breadstack.com --role=administrator --user_pass='$PASSWORD' --allow-root 2>/dev/null || \
        wp user update kris.hoang --user_pass='$PASSWORD' --allow-root

        # Leah
        wp user create leah.arkle leah.arkle@advesa.com --role=administrator --user_pass='$PASSWORD' --allow-root 2>/dev/null || \
        wp user update leah.arkle --user_pass='$PASSWORD' --allow-root
    "
done

exit
