#!/usr/bin/env python
# (c) 2013 s@ctrlc.hu
#
#  This is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.

from cfg import CONFIG

class Dropper(object):
    """ class implementing a WSGI app for uploading files
    """
    def __init__(self,environ, start_response):
        self.environ=environ
        self.resp=start_response
        self.stashid = environ.get('REQUEST_URI').split('/')[1]
        self.path = environ.get('REQUEST_URI').split('/')[2].split('?')[0]
        if not self.stashid.isalnum() and (self.path and not self.path.isalnum()):
            raise
        # parse params
        tmp = environ.get('REQUEST_URI').split('?')
        self.params = {}
        if len(tmp)>1:
            for exp in '?'.join(tmp[1:]).split('&'):
                tmp2 = exp.split('=')
                self.params[tmp2[0]]='='.join(tmp2[1:])
        self.recipients, self.users = self.loadstash()

    def loadstash(self):
        """ loads an upload directory configuration
        """
        with open(CONFIG['root']+'/drop/'+self.stashid+'.cfg','r') as fd:
            recipients=fd.readline().split()
            users=[x.strip() for x in fd.readlines()]
        return recipients, users

    def handle(self):
        if self.path in ['/', '']:
            return self.uploadform()
        if self.path in ['feed', 'feed/']:
            return self.feed()
        return self.fetch('drop/'+self.stashid+'/'+self.path)
        try:
            return self.fetch('drop/'+self.stashid+'/'+self.path)
        except:
            return _404(self.environ,self.resp)

    def uploadform(self):
        msg=''
        if self.environ.get('REQUEST_METHOD') == 'POST':
            if int(self.environ.get('CONTENT_LENGTH', 0)) != 0:
                p=PostUploadParser(self)
                if not p.csrf:
                    status = '303 See Other'
                    # todo add hash of uploaded file to params
                    response_headers = [('Location', '/%s/' % self.stashid)]
                    self.resp(status, response_headers)
                    return []
                else:
                    status = '302 Found'
                    # todo add hash of uploaded file to params
                    response_headers = [('Location', '/%s/?ok=%s' % (self.stashid, p.hash.hexdigest()))]
                    self.resp(status, response_headers)
                    return []
        if not msg and self.params.get('ok','').isalnum():
            msg="Successful upload.<br />SHA256 was %s" % self.params.get('ok')
        return send_template(self.resp,
                             'uploadform.html',
                             msg=msg,
                             jobid=hmac.new(CONFIG['secret'],
                                            repr(time.time()),
                                            hashlib.sha256).hexdigest(),
                             csrf=getcsrf(),
                             isadmin=authorized(self.environ, CONFIG['admins']),
                             )

    def feed(self):
        gpg = gnupg.GPG(gnupghome=CONFIG['gpghome'])
        knownkeys={x['keyid']: x['uids'][0][ x['uids'][0].rfind('<')+1: x['uids'][0].rfind('>')]
                   for x in gpg.list_keys()}
        if not authorized(self.environ, [knownkeys[x] for x in self.recipients]):
            return _404(self.environ, self.resp)
        result = getsubmissions(self.stashid)
        BASEURL="%s://%s" % (self.environ.get('wsgi.url_scheme'),
                             self.environ.get('SERVER_NAME'))
        rss = RSS2.RSS2(
            title = "submission feed",
            link = "%s/feed" % BASEURL,
            description = 'submission feed',
            lastBuildDate = datetime.datetime.utcnow(),
            items = [RSS2.RSSItem( title = "%s" % item[1],
                                   link = "%s/%s" % (BASEURL, item[1]),
                                   description = 'size: %s' % sizeof_fmt(item[2]),
                                   guid = RSS2.Guid("%s/%s" % (BASEURL, item[1])),
                                   pubDate = item[0])
                     for item in result])
        data = rss.to_xml()

        status = '200 OK'
        response_headers = [('Content-type', 'application/rss+xml'),
                            ('Content-Length', str(len(data)))]
        self.resp(status, response_headers)
        return [data]

    def fetch(self, filename):
        gpg = gnupg.GPG(gnupghome=CONFIG['gpghome'])
        knownkeys={x['keyid']: x['uids'][0][ x['uids'][0].rfind('<')+1: x['uids'][0].rfind('>')]
                   for x in gpg.list_keys()}
        if not authorized(self.environ, [knownkeys[x] for x in self.recipients]):
            return _404(self.environ, self.resp)

        status = '200 OK'
        response_headers = [('Content-type', 'application/pgp'),
                            ('Content-Length', str(os.path.getsize(filename)))]
        self.resp(status, response_headers)

        filelike = file(filename, 'rb')
        block_size = 4096

        if 'wsgi.file_wrapper' in self.environ:
            return self.environ['wsgi.file_wrapper'](filelike, block_size)
        else:
            return iter(lambda: filelike.read(block_size), '')

    @staticmethod
    def newstash(owners, uploaders, stashid=None):
        if not os.path.exists(CONFIG['root']+'/drop'): os.mkdir(CONFIG['root']+'/drop')
        # create stash root dir
        if stashid:
            os.mkdir(CONFIG['root']+'/drop/'+stashid)
        else:
            stashid=tempfile.mkdtemp(dir=CONFIG['root']+'/drop', prefix='').split('/')[-1]
        # create stash.cfg
        with open(CONFIG['root']+'/drop/'+stashid+'.cfg', 'w') as fd:
            fd.write(' '.join(owners)+'\n')
            fd.write('\n'.join(uploaders))
        # init gpghome if not existing
        if not os.path.exists(CONFIG['gpghome']):
            os.mkdir(CONFIG['gpghome'])
            os.chmod(CONFIG['gpghome'], 0700)
        # auto-import public keys of owners into local pubkeyring
        gpg = gnupg.GPG(gnupghome=CONFIG['gpghome'])
        allkeyids=[x['keyid'] for x in gpg.list_keys()]
        for kid in owners:
            if not kid in allkeyids:
                f = urllib.urlopen('http://pool.sks-keyservers.net:11371/pks/lookup?op=get&search=%s' % kid)
                key = f.read()
                gpg.import_keys(key)
        return stashid

startfile='Content-Disposition: form-data; name="file"; filename="'
startvar='Content-Disposition: form-data; name="%s"'
contenttxt='Content-Type: '
class PostUploadParser(object):
    """ File-like Object implementing rudimentary parsing of post data
        with uploaded file and optional encryption. The POST data is
        filtered in buffered memory and written through gpg to the
        disk if crypto is enabled (default).
    """
    def __init__(self, dropper):
        self.dropper = dropper
        self.fd=dropper.environ['wsgi.input']
        self.delim='\r\n'+self.fd.readline().strip()
        self.readbuf=''
        self.finished=False
        self.hash=hashlib.sha256()
        self.size=0
        self.gpg = gnupg.GPG(gnupghome=CONFIG['gpghome'])
        self.crypto = True
        self.csrf = None
        while True:
            # parse the stream
            line=self.fd.readline()
            if len(line)==0: break
            line=line.strip()
            if line.startswith(startfile):
                if not (self.csrf and csrf({'csrf': self.csrf})):
                    self.csrf=False
                    return
                # handle file upload part of POST
                self.filterfile(line)
            elif line.startswith(startvar % 'crypto'):
                # handle disabling crypto POST param
                line=self.fd.readline().strip()
                if len(line)>0:
                    raise Exception("y u no empty line!!#@#!@")
                line=self.fd.readline().strip()
                if line.lower()=="on":
                    self.crypto=False
            elif line.startswith(startvar % 'csrf'):
                # handle csrf post param
                line=self.fd.readline().strip()
                if len(line)>0:
                    raise Exception("y u no empty line!!#@#!@")
                line=self.fd.readline().strip()
                self.csrf=line

    def filterfile(self, line):
        """ parsing and handling the mime part of a POST file upload
            param.
            param line: is the first line of the mime part.
        """
        name=line[len(startfile):-1]
        line=self.fd.readline().strip()
        if not line.startswith(contenttxt):
            raise Exception("y u no content_type?!?")
        content_type=line[len(contenttxt):]
        line=self.fd.readline() # drop separating empty line

        dropDir = CONFIG['root'] + '/drop/'+ self.dropper.stashid
        fd, fname = mkstemp(dir=dropDir + '/')
        if self.crypto:
            os.close(fd)
            self.gpg.encrypt_file(self,
                                  self.dropper.recipients,
                                  output=fname,
                                  always_trust=True)
        else:
            fd=os.fdopen(fd, 'w')
            while True:
                buf=self.read(1024)
                if buf=='': break
                fd.write(buf)
        meta="%s\n%s\n%s\n%s" % (
            name,
            content_type,
            self.dropper.environ.get('dn'),
            self.hash.hexdigest())
        if self.crypto:
            meta=self.gpg.encrypt(meta,
                                  self.dropper.recipients,
                                  always_trust=True,
                                  armor=False).data
        with open(fname+'.meta','w') as fd:
            fd.write(meta)
        url=urlunparse((self.dropper.environ.get('wsgi.url_scheme'),
                        self.dropper.environ.get('HTTP_HOST') + \
                               (':'+self.dropper.environ.get('HTTP_HOST')
                                if (self.dropper.environ['wsgi.url_scheme']=='https' and
                                    self.dropper.environ['SERVER_PORT'] != '443') or
                                (self.dropper.environ['wsgi.url_scheme']=='http' and
                                 self.dropper.environ['SERVER_PORT'] != '80')
                                else ''),
                        "/%s/%s" % (self.dropper.stashid, fname.split('/')[-1]),
                        '',
                        '',
                        ''))
        if CONFIG.get('notify'):
            sender=(todn(self.dropper.environ.get('dn',''))['emailAddress']
                    if todn(self.dropper.environ.get('dn','')).get('emailAddress')
                    else "anon@localhost")
            txt = render_template('notification.txt',
                                  path=fname,
                                  name=name,
                                  type=content_type,
                                  url=url,
                                  size=sizeof_fmt(self.size),
                                  sender=sender,
                                  hash=self.hash.hexdigest())
            txt=self.gpg.encrypt(txt,
                                 self.dropper.recipients,
                                 always_trust=True).data
            res=mail(txt,
                     [x['uids'][0]
                      for x in self.gpg.list_keys()
                      if x['keyid'] in self.dropper.recipients])

    def read(self, bytes):
        """ implements a file-like read interface which is used to
            calculate a sha256 sum on the fly and parse until the end
            of the mime part.
        """
        if self.finished: return ''
        if len(self.readbuf)>0:
            # add prefetch and clean it
            data=self.readbuf+self.fd.read(bytes-len(self.readbuf))
            self.readbuf=''
        else:
            # read next block
            data=self.fd.read(bytes)
        # eof
        if len(data)==0:
            return data
        # simple check for delim
        end=data.find(self.delim)
        if end>=0:
            self.hash.update(data[:end])
            self.size+=len(data[:end])
            self.finished=True
            return data[:end]
        # check for delim fragments on packet boundary
        end=len(data)
        while True:
            end=self.delim.rfind(data[-1], 0, end)
            if end < 0: break
            end=end+1
            if self.delim[:end]==data[-end:]:
                trailer=self.fd.read(len(self.delim) - end)
                if trailer.startswith(self.delim[end:]):
                    self.finished=True
                    self.hash.update(data[:-end])
                    self.size+=len(data[:-end])
                    return data[:-end]
                self.readbuf=trailer
            end-=1
        self.hash.update(data)
        self.size+=len(data)
        return data

class AdminHandler(object):
    """ class for handling user registration, and creating new stashes over the web
        provides similar urls as Flask-TLSAuth

        /settings/register           - using keygen tag
        /settings/request            - submit your own CSR
        /settings/requests           - list all user account requests (admin only)
        /settings/newstash           - create a new stash (admin only)
        /settings/accept/<certhash>  - accept a new user request (admin only)
        /settings/reject/<certhash>  - reject a new user request (admin only)
    """
    def __init__(self,environ, start_response):
        self.ca=CertAuthority(CONFIG['ca'])
        self.environ=environ
        self.resp=start_response
        self.action = self.environ.get('REQUEST_URI').split('/')[2]
        if not self.action.isalnum():
            raise
        # parse params
        tmp = environ.get('REQUEST_URI').split('?')
        self.params = {}
        if len(tmp)>1:
            for exp in '?'.join(tmp[1:]).split('&'):
                tmp2 = exp.split('=')
                self.params[tmp2[0]]='='.join(tmp2[1:])

    def handle(self):
        """ main dispatcher of AdminHandler
        """
        if self.action == 'newstash':
            return self.newstash()
        elif self.action == 'register':
            return self.register()
        elif self.action == 'request':
            return self.submitcsr()
        elif self.action == 'requests':
            return self.showcsrs()
        elif self.action == 'accept':
            return self.accept()
        elif self.action == 'reject':
            return self.reject()
        elif self.action == 'stashes':
            return self.stashes()
        elif self.action == 'delete':
            return self.delete()
        return _404(self.environ,self.resp)

    def register(self):
        msg=''
        if self.environ.get('REQUEST_METHOD') == 'POST':
            if int(self.environ.get('CONTENT_LENGTH', 0)) != 0:
                fd=self.environ['wsgi.input']
                params={}
                for exp in fd.readline().split('&'):
                    tmp2 = exp.split('=')
                    params[tmp2[0]]=urllib.unquote('='.join(tmp2[1:]))
                if not csrf(params):
                    msg="Try again from our fine server please."
                elif params.get('email') and params.get('key'):
                    csr=spkac2cert(''.join(params['key']),
                                   params['email'],
                                   name=params.get('name'))
                    self.ca.submit(csr)
                    msg="Success<br />Your request will be reviewed soon."
                else:
                    msg="Sorry but you must supply an email address"

        return send_template(self.resp,
                             'register.html',
                             isadmin=authorized(self.environ, CONFIG['admins']),
                             csrf=getcsrf(),
                             msg=msg)

    def submitcsr(self):
        msg=''
        if self.environ.get('REQUEST_METHOD') == 'POST':
            if int(self.environ.get('CONTENT_LENGTH', 0)) != 0:
                fd=self.environ['wsgi.input']
                params={}
                for exp in fd.readline().split('&'):
                    tmp2 = exp.split('=')
                    params[tmp2[0]]=urllib.unquote('='.join(tmp2[1:])).strip()
                if not csrf(params):
                    msg="Try again from our fine server please."
                elif params.get('csr'):
                    ca=CertAuthority(CONFIG['ca'])
                    tmp=params['csr'].split('\n')
                    csr='\n'.join([urllib.unquote_plus(tmp[0]),
                                   '\n'.join(tmp[1:-1]),
                                   urllib.unquote_plus(tmp[-1])])
                    try:
                        self.ca.submit(csr)
                    except:
                        msg="Fail<br />please submit a valid Certificate Signing Request containing your email."
                    else:
                        msg="Success<br />Your request will be reviewed soon."

        return send_template(self.resp, 'certify.html',
                             isadmin=authorized(self.environ, CONFIG['admins']),
                             csrf=getcsrf(),
                             msg=msg)

    def showcsrs(self):
        email=authorized(self.environ, CONFIG['admins'])
        if not email:
            return _404(self.environ, self.resp)
        return send_template(self.resp,
                               'csrs.html',
                               isadmin=authorized(self.environ, CONFIG['admins']),
                               certs=[(todn(cert.get_subject()),
                                       datetime.datetime.fromtimestamp(os.stat(path).st_mtime),
                                       os.path.basename(path))
                                      for cert, path
                                      in self.ca.incoming()])

    def accept(self):
        """ provides facility for users belonging to `groups` to sign incoming CSRs
        """
        email=authorized(self.environ, CONFIG['admins'])
        if not email:
            return _404(self.environ, self.resp)
        path=self.ca._incoming+'/'+self.environ.get('REQUEST_URI').split('/')[3]
        print "certifying", path
        cert=self.ca.signcsr(load(path))
        mailsigned([cert])
        os.unlink(path)
        status = '302 Found'
        response_headers = [('Location', '/settings/requests')]
        self.resp(status, response_headers)
        return []

    def reject(self):
        """ provides facility for users belonging to `groups` to reject incoming CSRs
        """
        email=authorized(self.environ, CONFIG['admins'])
        if not email:
            return _404(self.environ, self.resp)
        path=self.ca._incoming+'/'+self.environ.get('REQUEST_URI').split('/')[3]
        os.unlink(path)
        status = '302 Found'
        response_headers = [('Location', '/settings/requests')]
        self.resp(status, response_headers)
        return []

    def newstash(self):
        msg=''
        email=authorized(self.environ, CONFIG['admins'])
        if not email:
            return _404(self.environ, self.resp)

        gpg = gnupg.GPG(gnupghome=CONFIG['gpghome'])
        knownkeys={x['uids'][0][ x['uids'][0].rfind('<')+1: x['uids'][0].rfind('>')]:x for x in gpg.list_keys()}
        keyid=knownkeys.get(email, {}).get('keyid')
        if self.environ.get('REQUEST_METHOD') == 'POST':
            if int(self.environ.get('CONTENT_LENGTH', 0)) != 0:
                fd=self.environ['wsgi.input']
                params=defaultdict(list)
                for exp in fd.readline().split('&'):
                    tmp2 = exp.split('=')
                    params[tmp2[0]]=urllib.unquote('='.join(tmp2[1:])).strip()
                if not csrf(params):
                    msg="Try again from our fine server please."
                elif keyid or params.get('keyid') or params.get('pk'):
                    if params.get('pk'):
                        gpg.import_keys(params.get('pk'))
                        knownkeys={x['uids'][0][ x['uids'][0].rfind('<')+1: x['uids'][0].rfind('>')]:x for x in gpg.list_keys()}
                    elif params.get('keyid'):
                        f = urllib.urlopen('http://pool.sks-keyservers.net:11371/pks/lookup?op=get&search=%s' % params.get('keyid'))
                        key = f.read()
                        gpg.import_keys(key)
                        knownkeys={x['uids'][0][ x['uids'][0].rfind('<')+1: x['uids'][0].rfind('>')]:x for x in gpg.list_keys()}
                    keyid=knownkeys.get(email)['keyid']
                    if not keyid:
                        msg="Couldn't locate PGP key for owner, try uploading one"
                    elif not params.get('invited'):
                        msg="You must invite someone to share this stash with"
                    else:
                        stashid=Dropper.newstash([knownkeys[email]['keyid']],
                                                 urllib.unquote_plus(params['invited']).split('\n'),
                                                 urllib.unquote_plus(params.get('name')))
                        # todo sent invitation mail to uploaders
                        status = '302 Found'
                        response_headers = [('Location', '/%s/' % stashid )]
                        self.resp(status, response_headers)
                        return []
                else:
                    msg="You must supply a PGP public key for enabling encryption of stored data"

        return send_template(self.resp, 'newstash.html',
                             isadmin=authorized(self.environ, CONFIG['admins']),
                             msg=msg,
                             csrf=getcsrf(),
                             knownkey=keyid)

    def stashes(self):
        """ lists all stashes for admins
        """
        email=authorized(self.environ, CONFIG['admins'])
        if not email:
            return _404(self.environ, self.resp)
        gpg = gnupg.GPG(gnupghome=CONFIG['gpghome'])
        knownkeys={x['keyid']: x['uids'][0][ x['uids'][0].rfind('<')+1: x['uids'][0].rfind('>')]
                   for x in gpg.list_keys()}
        stashes=[]
        for fname in os.listdir(CONFIG['root']+'/drop'):
            if not fname.endswith('.cfg'):
                continue
            with open(CONFIG['root']+'/drop/'+fname,'r') as fd:
                owner=[knownkeys[kid] for kid in fd.readline().strip().split()]
                friends=[x.strip() for x in fd.readlines()]
            files=[os.stat(CONFIG['root']+'/drop/'+fname[:-4]+'/'+f).st_size
                   for f in os.listdir(CONFIG['root']+'/drop/'+fname[:-4])
                   if not f.endswith('.meta')]
            stashes.append((fname[:-4],
                            owner,
                            friends,
                            sizeof_fmt(sum(files)),
                            len(files)))
        return send_template(self.resp,
                               'stashes.html',
                               isadmin=authorized(self.environ, CONFIG['admins']),
                               stashes=stashes)

    def delete(self):
        """ provides facility for users belonging to `groups` to reject incoming CSRs
        """
        email=authorized(self.environ, CONFIG['admins'])
        if not email:
            return _404(self.environ, self.resp)
        stashid=self.environ.get('REQUEST_URI').split('/')[3]
        if stashid.isalnum():
            path=CONFIG['root']+'/drop/'+stashid
            os.unlink(path+'.cfg')
            shutil.rmtree(path)
        status = '302 Found'
        response_headers = [('Location', '/settings/stashes')]
        self.resp(status, response_headers)
        return []

# various helper functions

def _404(environ, start_response):
    """ helper for displaying an error message"""
    status = '404 Not Found'
    res = """<html><head><title>Not Found</title></head><body><h1>404 Not found</h1></body></html>"""
    response_headers = [('Content-type', 'text/html'),
                        ('Content-Length', str(len(res)))]
    start_response(status, response_headers)
    return [res]

def mail(data, to):
    msg = Message()
    msg.set_type('application/pgp')
    msg.set_param('format', 'text')
    msg.set_param('x-action', 'encrypt')
    msg.set_payload(data)
    composed = msg.as_string()
    s = smtplib.SMTP('localhost', timeout=3)
    if s:
        s.sendmail(CONFIG['sender'], to, composed)
        return True
    else:
        return False

def visitor(res, dirname, names):
    for name in names:
        if name.endswith('.meta'): continue
        res.append((datetime.datetime.fromtimestamp(os.stat(dirname+'/'+name).st_mtime).isoformat(' '),
                    '/'.join(dirname.rsplit('/')[-1:])+'/'+name,
                    os.path.getsize(dirname+'/'+name)))

def getsubmissions(stash):
    result = []
    os.path.walk(CONFIG['root'] + '/drop/'+stash, visitor, result)
    return reversed(sorted(result))

def sizeof_fmt(num):
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f%s" % (num, x)
        num /= 1024.0

def render_template(template, **kwargs):
    t = env.get_template(template)
    return str(t.render(**kwargs))

def send_template(resp, template, **kwargs):
    r = render_template(template, **kwargs)
    status = '200 OK'
    response_headers = [('Content-type', 'text/html'),
                        ('Content-Length', str(len(r)))]
    resp(status, response_headers)
    return [r]

def authorized(env, users=None):
    email=todn(env.get('dn')).get('emailAddress')
    if env.get('verified') == 'SUCCESS':
        #print self.users
        if users and email not in users:
            return False
        return email
    return False

def csrf(params):
    if params.get('csrf','').isalnum() and os.path.exists('/tmp/csrf'+params.get('csrf')):
        if os.path.getmtime('/tmp/csrf'+params.get('csrf'))>time.time()-7200:
            return True
        os.unlink('/tmp/csrf'+params.get('csrf'))

def getcsrf():
    token=hmac.new(CONFIG['secret'],
                   str(time.time())+ssl.rand.bytes(8).encode('hex'),
                   hashlib.sha256).hexdigest()
    with open('/tmp/csrf'+token,'w') as fd:
        fd.write(u"\U0001F34F".encode('utf8'))
    return token

def application(environ, start_response):
    if environ.get('REQUEST_URI').startswith('/settings/'):
        try:
            handler=AdminHandler(environ, start_response)
        except:
            return _404(environ,start_response)
    else:
        try:
            handler=Dropper(environ, start_response)
        except:
            return _404(environ,start_response)
    return handler.handle()

# imports
from tempfile import mkdtemp, mkstemp
from datetime import datetime
from email.message import Message
from collections import defaultdict
from urlparse import urlunparse
from tlsauth import CertAuthority, spkac2cert, MBSTRING_ASC, todn, mailsigned, load
import smtplib, subprocess, gnupg, time, hashlib, urllib, datetime, tempfile, shutil, hmac, sys, os
import PyRSS2Gen as RSS2
import OpenSSL as ssl
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader(['./templates']))
