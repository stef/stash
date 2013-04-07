#!/bin/bash

# create hidden service
echo adding hidden service
sudo cat >>/etc/tor/torrc <<EOT
HiddenServiceDir /var/lib/tor/stash/
HiddenServicePort 443 127.0.0.1:23443
HiddenServicePort 80 127.0.0.1:23080
EOT
sudo /etc/init.d/tor restart
hostname=$(sudo cat /var/lib/tor/stash/hostname)

# install stash
echo installing stash
git clone https://github.com/stef/stash
cd stash
pip install -r requirements.txt

# create local CA
echo creating local CA
createca.sh CA https://$hostname/crl.pem
cat >CA/ca.cfg <<EOT
crl=https://$hostname/crl.pem
sec=private/root.pem
pub=public/root.pem
serial=conf/serial
incoming=incoming
EOT

# generate server cert
echo generating server cert
servercert.sh CA/$hostname
cd CA
signcert.sh $hostname
mv $hostname.key private
mv $hostname.cert public
rm $hostname.csr

# generate admin cert
echo generate admin cert
gencert.sh admin
signcert.sh admin
cert2pkcs12.sh admin
rm admin.csr

# generate nginx config
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
     ssl_certificate      $basepath/CA/public/$hostname.cert;
     ssl_certificate_key  $basepath/CA/private/$hostname.key;
     ssl_client_certificate $basepath/CA/public/root.pem;
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
echo pls repeat the email address you specified in the user cert
read mail
cat >cfg.py <<EOF
import os

CONFIG={
        'admins':['$mail'],
        'secret':'$(openssl rand -hex 48)',
        'ca': 'CA',
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
