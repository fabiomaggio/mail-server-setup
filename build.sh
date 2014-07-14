#!/usr/bin/env bash

# Exit on errors
set -e

# Trace what gets executed
#set -x

# Script must be run as root
if [ $(id -u) != "0" ]; then
    echo "You must be root to run this script" >&2
    exit 1
fi

# ================================ #
# Define system specific variables #
# ================================ #

DB_NAME="mailserver"
DB_USER="mailadmin"
DB_PASS=""
MYSQL_ROOT_PASS=""

### Functions
##############################

# Initializes the mailserver
function  init () {
    # Install packages, create database and add virtual domains to the database
    install_packages && create_database && add_domains
}

# Asks the Mysql root password if it is not allready set
function mysql_root () {
    # Ask the Mysql root password only once
    if [ "${MYSQL_ROOT_PASS}" = "" ]; then
        echo "> Enter the MySQL root password:"
        read -s MYSQL_ROOT_PASS
    fi
}

# Installs the packages that are needed
function install_packages () {
    echo -n "> Installing packages..."
    apt-get install -y postfix postfix-mysql dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql mysql-server
    echo "ok"
}

# Creates the basic structure of the database for the mailserver
function create_database () {
    mysql_root

    echo -n "> Creating the basic database structure..."

    # Create the database and set privileges
    sql="CREATE DATABASE IF NOT EXISTS ${DB_NAME};
        GRANT SELECT ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
        FLUSH PRIVILEGES;
        USE ${DB_NAME};"

    # Create a table for the domains that will receive mail
    sql="$sql
        CREATE TABLE IF NOT EXISTS virtual_domains (
            id int(11) NOT NULL auto_increment,
            name varchar(50) NOT NULL,
            PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8;"

    # Create a table for the email users
    sql="$sql
        CREATE TABLE IF NOT EXISTS virtual_users (
            id int(11) NOT NULL auto_increment,
            domain_id int(11) NOT NULL,
            password varchar(106) NOT NULL,
            email varchar(100) NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY email (email),
            FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8;"
    
    # Create a table for email aliases
    sql="$sql
        CREATE TABLE IF NOT EXISTS virtual_aliases (
            id int(11) NOT NULL auto_increment,
            domain_id int(11) NOT NULL,
            source varchar(100) NOT NULL,
            destination varchar(100) NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8;"

    # Execute the query
    mysql -u root -p${MYSQL_ROOT_PASS} -e "$sql"

    echo "ok"
}

# Adds the virtual domains
function add_domains () {
    mysql_root

    # Check if the domains do not allready exist
    sql="SELECT COUNT(id) FROM ${DB_NAME}.virtual_domains"
    existing_domains=$(mysql -u root -p${MYSQL_ROOT_PASS} -ss -e "$sql")

    if [ $existing_domains -gt "0" ]; then
        echo "> Virtual domains exist allready"
        exit 0
    fi

    echo "> Enter the domain:"
    read domain

    sql="INSERT IGNORE INTO ${DB_NAME}.virtual_domains
            (id, name)
        VALUES
            ('1', '$domain'),
            ('2', 'mail.$domain'),
            ('3', 'localhost.$domain');"

    echo -n "> Adding virtual domains..."

    # Execute the query
    mysql -u root -p${MYSQL_ROOT_PASS} -e "$sql"

    echo "ok"
}

function add_user () {
    mysql_root

    echo "> Enter the emailaddress:"
    read email

    echo "> Enter the password:"
    read -s password

    sql="INSERT INTO ${DB_NAME}.virtual_users
            (domain_id, password, email)
        VALUES
            ('1', ENCRYPT('$password', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), '$email');"

    echo -n "> Adding user ${email}..."

    # Execute the query
    mysql -u root -p${MYSQL_ROOT_PASS} -e "$sql"

    echo "ok"
}

function add_alias () {
    mysql_root

    echo "> Enter the source emailaddress:"
    read source_address

    echo "> Enter the destination emailaddress:"
    read destination_address

    sql="INSERT INTO ${DB_NAME}.virtual_aliases
            (domain_id, source, destination)
        VALUES
            ('1', '$source_address', '$destination_address');"

    echo -n "> Adding alias ${destination_address} for ${source_address}..."

    # Execute the query
    mysql -u root -p${MYSQL_ROOT_PASS} -e "$sql"

    echo "ok"
}

function setup_postfix () {
    mv -f /etc/postfix/main.cf.orig /etc/postfix/main.cf

    # Generate self signed SSL certificate if it does not exist allready
    if [ ! -f /etc/ssl/certs/dovecot.pem ]; then
        openssl req -new -x509 -days 1000 -nodes -out "/etc/ssl/certs/dovecot.pem" -keyout "/etc/ssl/private/dovecot.pem"
        echo "> SSL certificate exists allready"
    fi

    # Create a copy of the postfix main configuration file if it does not allready exist
    if [ ! -f /etc/postfix/main.cf.orig ]; then
        cp /etc/postfix/main.cf /etc/postfix/main.cf.orig
        echo "> Backed up the original postfix main configuration file"
    fi

    # Delete the smtpd lines
    sed -i '/^smtpd_/d' /etc/postfix/main.cf
    sed -i '/^smtp_tls_/d' /etc/postfix/main.cf

    # Insert new smtpd lines after the TLS parameters section
    line=$(sed -n '/TLS parameters/=' /etc/postfix/main.cf)
    sed -i "${line} a \\
smtpd_tls_cert_file=/etc/ssl/certs/dovecot.pem \\
smtpd_tls_key_file=/etc/ssl/private/dovecot.pem \\
smtpd_use_tls=yes \\
smtpd_tls_auth_only = yes \\
 \\
# Enabling SMTP for authenticated users, and handing off authentication to Dovecot \\
smtpd_sasl_type = dovecot \\
smtpd_sasl_path = private/auth \\
smtpd_sasl_auth_enable = yes \\
 \\
smtpd_recipient_restrictions = \\
    permit_sasl_authenticated, \\
    permit_mynetworks, \\
    reject_unauth_destination \\
    " /etc/postfix/main.cf

    # Replace the mydestination option
    sed -i 's/^mydestination\ =.*$/mydestination\ =\ localhost/' /etc/postfix/main.cf

    # Add rest of configuration settings
    cat >> /etc/postfix/main.cf <<EOF

# Handing off local delivery to Dovecot's LMTP, and telling it where to store mail
virtual_transport = lmtp:unix:private/dovecot-lmtp

# Virtual domains, users, and aliases
virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf
virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-alias-maps.cf
EOF

    echo "> File '/etc/postfix/main.cf' updated"

    # Create /etc/postfix/mysql-virtual-mailbox-domains.cf
    if [ ! -f /etc/postfix/mysql-virtual-mailbox-domains.cf ]; then
        cat > /etc/postfix/mysql-virtual-mailbox-domains.cf <<EOF
user = ${DB_USER}
password = ${DB_PASS}
hosts = 127.0.0.1
dbname = ${DB_NAME}
query = SELECT 1 FROM virtual_domains WHERE name='%s'
EOF

        echo "> File '/etc/postfix/mysql-virtual-mailbox-domains.cf' created"

        # Restart postfix
        restart_postfix

        # Load the main virtual domain
        mysql_root
        sql="SELECT name FROM ${DB_NAME}.virtual_domains WHERE id = 1 LIMIT 1"
        domain=$(mysql -u root -p${MYSQL_ROOT_PASS} -ss -e "$sql")

        # Check if postfix can find the main domain
        domain_found=$(postmap -q $domain mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf)

        if [ "$domain_found" = "1" ]; then
            echo "> Postfix found the '$domain' domain"
        else
            echo "> Postfix could not find the '$domain' domain"
        fi
    fi

    # Create /etc/postfix/mysql-virtual-mailbox-maps.cf
    if [ ! -f /etc/postfix/mysql-virtual-mailbox-maps.cf ]; then
        cat > /etc/postfix/mysql-virtual-mailbox-maps.cf <<EOF
user = ${DB_USER}
password = ${DB_PASS}
hosts = 127.0.0.1
dbname = ${DB_NAME}
query = SELECT 1 FROM virtual_users WHERE email='%s'
EOF

        echo "> File '/etc/postfix/mysql-virtual-mailbox-maps.cf' created"

        # Restart postfix
        restart_postfix

        # Load the fist emailaddress
        mysql_root
        sql="SELECT email FROM ${DB_NAME}.virtual_users WHERE id = 1 LIMIT 1"
        email=$(mysql -u root -p${MYSQL_ROOT_PASS} -ss -e "$sql")

        # Check if postfix can find the first email
        email_found=$(postmap -q $email mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf)

        if [ "$email_found" = "1" ]; then
            echo "> Postfix found the '$email' emailaddress"
        else
            echo "> Postfix could not find the '$email' emailaddress"
        fi
    fi

    # Create /etc/postfix/mysql-virtual-alias-maps.cf
    if [ ! -f /etc/postfix/mysql-virtual-alias-maps.cf ]; then
        cat > /etc/postfix/mysql-virtual-alias-maps.cf <<EOF
user = ${DB_USER}
password = ${DB_PASS}
hosts = 127.0.0.1
dbname = ${DB_NAME}
query = SELECT destination FROM virtual_aliases WHERE source='%s'
EOF

        echo "> File '/etc/postfix/mysql-virtual-alias-maps.cf' created"

        # Restart postfix
        restart_postfix
    fi

    #mv -f /etc/postfix/master.cf.orig /etc/postfix/master.cf

    # Create a copy of the postfix master configuration file if it does not allready exist
    if [ ! -f /etc/postfix/master.cf.orig ]; then
        cp /etc/postfix/master.cf /etc/postfix/master.cf.orig
        echo "> Backed up the original postfix master configuration file"
    fi

    # Uncomment lines
    sed -i 's/#submission/submission/' /etc/postfix/master.cf
    sed -i 's/#smtps/smtps/' /etc/postfix/master.cf

    echo "> File '/etc/postfix/master.cf' updated"

    # Restart postfix
    restart_postfix

    echo "> Postfix setup ok"
}

function restart_postfix () {
    service postfix restart
    echo "> Postfix restarted"
}

function setup_dovecot () {
    # Backup original configuration files
    cp /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.orig
    cp /etc/dovecot/conf.d/10-mail.conf /etc/dovecot/conf.d/10-mail.conf.orig
    cp /etc/dovecot/conf.d/10-auth.conf /etc/dovecot/conf.d/10-auth.conf.orig
    cp /etc/dovecot/dovecot-sql.conf.ext /etc/dovecot/dovecot-sql.conf.ext.orig
    cp /etc/dovecot/conf.d/10-master.conf /etc/dovecot/conf.d/10-master.conf.orig
    cp /etc/dovecot/conf.d/10-ssl.conf /etc/dovecot/conf.d/10-ssl.conf.orig

    # Insert protocols after the '!include_try /usr/share/dovecot/protocols.d/*.protocol' line
    line=$(sed -n '/!include_try \/usr\/share\/dovecot\/protocols\.d\/*\.protocol/=' /etc/dovecot/dovecot.conf)
    sed -i "${line} a \\
protocols = imap pop3 lmtp \\
" /etc/dovecot/dovecot.conf

    # Replace the 'mail_location' option
    sed -i 's@^#mail_location\ =.*$@mail_location\ =\ maildir:/var/mail/vhosts/%d/%n@' /etc/dovecot/dovecot.conf

    # Replace the 'mail_privileged_group' option
    sed -i 's/^#mail_privileged_group\ =.*$/mail_privileged_group\ =\ mail/' /etc/dovecot/dovecot.conf

    echo "> File '/etc/dovecot/dovecot.conf' updated"

    # Ask the domain
    echo -n "> Enter the domain: "
    read domain

    # Create the directory for the virtual mail hosts
    mkdir -p /var/mail/vhosts/$domain
    echo "> Mail vhosts directory created at '/var/mail/vhosts/$domain'"

    # Create the vmail user and group and set the right persmissions
    #groupadd -g 5000 vmail
    #useradd -g vmail -u 5000 vmail -d /var/mail
    #chown -R vmail:vmail /var/mail
    #echo "> User and group 'vmail' created"

    # Set the new users' password
    #passwd vmail

    # Enable the 'disable_plaintext_auth' option
    sed -i 's/^#disable_plaintext_auth\ =/disable_plaintext_auth\ =/' /etc/dovecot/conf.d/10-auth.conf

    # Change the 'auth_mechanisms' option
    sed -i 's/auth_mechanisms\ =\ plain/auth_mechanisms\ =\ plain\ login/' /etc/dovecot/conf.d/10-auth.conf

    # Comment out the Change the 'auth_mechanisms' option
    sed -i 's/!include auth-system.conf.ext/#!include auth-system.conf.ext/' /etc/dovecot/conf.d/10-auth.conf

    # Enable the 'disable_plaintext_auth' option
    sed -i 's/^#!include auth-sql.conf.ext/!include auth-sql.conf.ext/' /etc/dovecot/conf.d/10-auth.conf

    echo "> File '/etc/dovecot/conf.d/10-auth.conf' updated"

    # Create /etc/dovecot/conf.d/auth-sql.conf.ext
    if [ ! -f /etc/dovecot/conf.d/auth-sql.conf.ext ]; then
        cat > /etc/dovecot/conf.d/auth-sql.conf.ext <<EOF
passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
}
EOF

        echo "> File '/etc/dovecot/dovecot-sql.conf.ext created"
    fi

    # Enable the 'driver' option
    sed -i 's/^#driver\ =/driver\ =\ mysql/' /etc/dovecot/dovecot-sql.conf.ext

    # Enable the 'connect' option
    sed -i "s/^#connect\ =/connect\ =\ host=127.0.0.1 dbname=${DB_NAME} user=${DB_USER} password=${DB_PASS}/" /etc/dovecot/dovecot-sql.conf.ext

    # Enable the 'default_pass_scheme' option
    sed -i 's/^#default_pass_scheme\ =\ MD5/default_pass_scheme\ =\ SHA512-CRYPT/' /etc/dovecot/dovecot-sql.conf.ext

    # Enable the 'password_query' option
    sed -i "s/^#password_query\ =\ \\\/password_query\ =\ SELECT email as user, password FROM virtual_users WHERE email='%u';/" /etc/dovecot/dovecot-sql.conf.ext

    echo "> File '/etc/dovecot/dovecot-sql.conf.ext' updated"

    # Change persmissions on the /etc/dovecot directory
    chown -R vmail:dovecot /etc/dovecot
    echo "> Permissions on /etc/dovecot changed"

    sed -i 's/#port\ =\ 143/port = 0/' /etc/dovecot/conf.d/10-master.conf
    sed -i 's/#port\ =\ 110/port = 0/' /etc/dovecot/conf.d/10-master.conf
    sed -i 's@unix_listener\ lmtp@unix_listener\ /var/spool/postfix/private/dovecot-lmtp@' /etc/dovecot/conf.d/10-master.conf
    sed -i '0,/#mode\ =\ 0666/s/#mode\ =\ 0666/mode\ =\ 0600\n#insert-here/' /etc/dovecot/conf.d/10-master.conf
    
    line=$(sed -n '/#insert-here/=' /etc/dovecot/conf.d/10-master.conf)
    sed -i "${line} a \\
    user = postfix \\
    group = postfix \\
    " /etc/dovecot/conf.d/10-master.conf

    line=$(sed -n '/unix_listener auth-userdb/=' /etc/dovecot/conf.d/10-master.conf)
    sed -i "${line} i \\
    unix_listener /var/spool/postfix/private/auth { \\
      mode = 0666 \\
      user = postfix \\
      group = postfix \\
    } \\
     \\
    " /etc/dovecot/conf.d/10-master.conf

    sed -i '0,/#mode\ =\ 0666/s/#mode\ =\ 0666/mode\ =\ 0600/' /etc/dovecot/conf.d/10-master.conf
    sed -i '0,/#user\ =/s/#user\ =/user\ =\ vmail/' /etc/dovecot/conf.d/10-master.conf
    sed -i 's/#user\ =\ $default_internal_user/user\ =\ dovecot/' /etc/dovecot/conf.d/10-master.conf
    sed -i 's/#user\ =\ root/user\ =\ vmail/' /etc/dovecot/conf.d/10-master.conf

    echo "> File '/etc/dovecot/conf.d/10-master.conf' updated"

    sed -i 's@^ssl_cert\ =$\ .*$@ssl_cert\ =\ </etc/ssl/certs/dovecot.pem@' /etc/dovecot/conf.d/10-ssl.conf
    sed -i 's@^ssl_key\ =$\ .*$@ssl_key\ =\ </etc/ssl/private/dovecot.pem@' /etc/dovecot/conf.d/10-ssl.conf
    sed -i 's/#ssl\ =\ yes/ssl\ =\ required/' /etc/dovecot/conf.d/10-ssl.conf

    echo "> File '/etc/dovecot/conf.d/10-ssl.conf' updated"

    # Restart dovecot
    service dovecot restart
    echo "> Dovecot restarted"
}

### Main
##############################

# At least one argument has to be provided
if [ $# = 0 ]; then
    exit 1
fi

# Process the arguments
while [ "$1" != "" ]; do
    case $1 in
        init) init; shift;;
        add-user) add_user; shift;;
        add-alias) add_alias; shift;;
        setup-postfix) setup_postfix; shift;;
        setup-dovecot) setup_dovecot; shift;;
    esac
    shift
done
