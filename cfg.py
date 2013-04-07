import os

CONFIG={
        'notify':True,
        'ca': 'x509-ca',
        'sender':'pydrop@example.com',
        'gpghome':'.gnupg',
        'root':os.path.dirname(__file__),
        'admins':['s@ctrlc.hu'],
        'secret':'some long random string',
}
