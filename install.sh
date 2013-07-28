#!/bin/bash

#### WARNING : very experimental, never tested.
## if it works pls tell me, so i can remove this warning.

dry=True

echo "be careful, backup your /etc/tor/torrc"
echo "before you continue, otherwise abort with ctrl-c"
read
echo "ok. we'll need your email address for your CA, server and admin cert."
read email
echo "cool. also we need a username for your admin cert"
read name

# create hidden service
dry || {
    echo "adding hidden service"
    sudo cat >>/etc/tor/torrc <<EOT
HiddenServiceDir /var/lib/tor/stash/
HiddenServicePort 443 127.0.0.1:23443
HiddenServicePort 80 127.0.0.1:23080
EOT
    sudo /etc/init.d/tor restart
    hostname=$(sudo cat /var/lib/tor/stash/hostname)
}

# install stash
echo installing stash
git clone https://github.com/stef/stash
cd stash
virtualenv env
source env/bin/activate
pip install -r requirements.txt

# create local CA
echo creating local CA
tlsauth.py CA createca http://$hostname/crl.pem "$hostname CA" $email

# generate server cert
echo generating server cert
tlsauth.py CA newcsr $hostname $email >CA/"${hostname}".key
tlsauth.py CA sign <CA/server.key >CA/"${hostname"}.cert

# create local client CA
echo creating local client CA
tlsauth.py subCA createca http://$hostname/client-crl.pem "$hostname client CA" $email

# deleting master CA key here!!!! you need it in one year when the subCA expires!
echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
echo "rm CA/private/root.pem"
echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'

# generate admin cert
echo generate admin cert
tlsauth.py subCA newcsr $name $email >CA/admin.key
tlsauth.py subCA sign <CA/admin.key >CA/admin.cert
tlsauth.py subCA p12 CA/admin.key <CA/admin.cert >CA/admin.p12

# generate nginx config
dry || {
    echo generate nginx config
    basepath=$(realpath .)
    sudo cat >/etc/nginx/sites-available/stash <<EOF
# change /var/run/stash into wherever your stash instance is located

server {
     # change the IP if you don't run a hidden service
     listen        127.0.0.1:23080;
     server_name $hostname;
     location /cert.pem {
        alias       $basepath/CA/public/root.pem;
     }
}

upload_progress uploads 1m;
server {
     # change the IP if you don't run a hidden service
     listen        127.0.0.1:23443;
     server_name $hostname;

     ssl on;
     ssl_certificate      $basepath/CA/$hostname.cert;
     ssl_certificate_key  $basepath/CA/$hostname.key;
     ssl_client_certificate $basepath/subCA/public/root.pem;
     ssl_verify_client optional;

     location /static/ {
        alias       $basepath/static/;
     }
     location /cert.pem {
        alias       $basepath/CA/public/root.pem;
     }

     client_max_body_size 2048M;

     # This section is required.
     location ^~ /progress {
        upload_progress_json_output;
        report_uploads    uploads;
     }

     location / {
        include uwsgi_params;
        uwsgi_param verified $ssl_client_verify;
        uwsgi_param dn $ssl_client_s_dn;
        uwsgi_pass 127.0.0.1:23023;
        track_uploads       uploads 4s;
     }
}
EOF
    sudo ln -s /etc/nginx/sites-available/stash /etc/nginx/sites-enabled/
    sudo /etc/init.d/nginx restart

    echo generating stash config
    cat >cfg.py <<EOF
import os

CONFIG={
        'admins':['$email'],
        'secret':'$(openssl rand -hex 48)',
        'ca': 'CA',
        'subca': 'subCA',
        'sender':'stash@$hostname',
        'notify':True,
        'gpghome':'.gnupg',
        'root':os.path.dirname(__file__),
}
EOF
(sleep 3; cat <<EOF
Open in your favorite browser the following url:
http://$hostname/cert.pem

Which should offer you to automatically import the CA root certificate
into your browsers, and it also asks you what you want to trust it,
allow your browser to trust this CA with servers and user, but not
software.

Also download and import the admin.p12 certificate generated in
"Create your own client Certificate" into your browser.

Then visit:
 - to create a new stash: https://<hostname>/settings/newstash
 - to list stashes: https://<hostname>/settings/stashes
 - to list user access requests: https://<hostname>/settings/requests

Your friends can now request access to your stash by going to:
https://$hostname/settings/register

However this generates the certificate in your browser, and if you -
as I - do not trust your browser, you might want to generate your keys
and certs offline in a more controlled environment and upload your CSR
here: https://$hostname/settings/request

Also my firefox did not store the generated key in the keystore, so I
had to use a proper CSR anyway.
EOF
) &

echo starting stash
uwsgi --socket 127.0.0.1:23023 --chdir $PWD -pp $PWD/.. -w stash -p 1 --py-auto-reload 1
