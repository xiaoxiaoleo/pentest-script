#!/usr/bin/python
"""
QuickPut 1.5 - http://infomesh.net/2001/QuickPut/

This is a program that enables one to load files onto a server using 
the HTTP PUT method. It supports basic and digest authentication.

Usage: QuickPut [ --help ] [ --v ] file http_uri [ uname pswd ]

   --help - Prints this message out
   --v - Turns on "verbose" mode

"file" is the local file to upload, and "http_uri" is the target.
"uname" and "pswd" are optional authentication details.
"""

__author__ = 'Sean B. Palmer'
__license__ = 'Copyright (C) 2001 Sean B. Palmer. GNU GPL 2'
__version__ = '1.5'
__cvsid__ = '$Id$'

import sys, string, re, os, base64, md5, sha, time
import httplib, urlparse, urllib, urllib2

UAID = 'QuickPut/'+__version__+' (http://infomesh.net/2001/QuickPut/)'
if ('-v' in sys.argv) or ('--v' in sys.argv): VERBOSE = 1
else: VERBOSE = 0

def perr(s): 
   """The standard error printing function.
   Can go to STDERR, STDOUT, or both."""
   if VERBOSE: 
      sys.stderr.write(s.strip()+'\n\n')
      print s.strip()+'\n'

def precondition(uri, auth=None): 
   """HEAD a resource, and return the code
   Could be extended to get the ETag, etc."""
   perr('Sending HEAD request to: '+uri)
   u = urlparse.urlparse(uri)
   n, p = u[1], u[2]
   if '@' in n: sys.exit(0)
   h = httplib.HTTP(n)
   h.putrequest('HEAD', p)
   if auth: 
      perr('Auth: '+str(auth))
      if 'type' in auth.keys(): 
         if auth['type'] == 'Basic': authtobasic(auth, h)
         elif auth['type'] == 'Digest': authtodigest(auth, h, uri, 'HEAD')
   h.putheader('Accept', '*/*')
   h.putheader('Accept-Encoding', '*,deflate')
   h.putheader('TE', 'trailers,deflate')
   h.putheader('User-Agent', UAID)
   h.putheader('Connection', 'TE,Keep-Alive')
   h.endheaders()
   errcode, errmsg, headers = h.getreply()
   h.close()
   perr('HEAD response code: '+str(errcode)+'\nResponse headers: '+str(headers))
   if auth: 
      if ('type' in auth.keys()) and (errcode == 401): 
         perr('Authorization failed!\n'+'Auth: '+headers['www-authenticate'])
         sys.exit(0) # Stops it from contunually looping
   return errcode, errmsg, headers

def put(fn, uri, auth=None): 
   errcode, errmsg, headers = precondition(uri, auth=auth)
   if errcode in (301, 302): 
      if not auth: put(fn, headers['Location'])
      else: put(fn, headers['Location'], auth=auth)
   elif errcode == 401: 
      wwwauth = headers['www-authenticate']
      match = re.match('[ \t]*([^ \t]+)[ \t]+realm="([^"]*)"', wwwauth)
      scheme, realm = match.groups()
      if scheme.lower() == 'basic': 
         perr('HTTP Basic authentication spotted')
         if not auth: 
            perr('No authentication details given!')
            sys.exit(0) # Stops it from contunually looping
         auth['type'] = 'Basic'
         put(fn, uri, auth=auth)
      elif scheme.lower() == 'digest': 
         # 2001-07-19 14:08:03 <DanC_tst> pls support digest auth as well as 
         # basic. Don't encourage users to send their passwords in the clear.
         perr('HTTP Digest authentication spotted')
         if not auth: 
            perr('No authentication details given!')
            sys.exit(0)
         auth['type'], auth['data'] = 'Digest', wwwauth
         put(fn, uri, auth=auth)
   elif errcode in (200, 204, 206, 404): putdata(fn, uri, auth=auth)
   else: perr('Got error code: '+str(errcode)) # e.g. 403, 501

# Basic Authentication

def authtobasic(auth, h): 
   """Converts basic auth data into an HTTP header."""
   userpass = auth['uname']+':'+auth['pswd']
   userpass = base64.encodestring(urllib.unquote(userpass)).strip()
   h.putheader('Authorization', 'Basic '+userpass)
   perr('Authorization: Basic '+userpass)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# 
# D I G E S T   A U T H E N T I C A T I O N   S T U F F
# These functions are based on the stuff in urllib2
# 

def authtodigest(auth, h, uri, method):
   user, pw, a = auth['uname'], auth['pswd'], auth['data']
   x = http_digest_auth(a, uri, user, pw, method)
   h.putheader('Authorization', x)
   perr('Authorization: '+x)

def http_digest_auth(a, uri, user, pw, method):
   token, challenge = a.split(' ', 1)
   chal = urllib2.parse_keqv_list(urllib2.parse_http_list(challenge))
   a = get_authorization(chal, uri, user, pw, method)
   if a: return 'Digest %s' % a

def get_authorization(chal, uri, user, pw, method):
   try:
      realm, nonce = chal['realm'], chal['nonce']
      algorithm, opaque = chal.get('algorithm', 'MD5'), chal.get('opaque', None)
   except KeyError: return None
   H, KD = get_algorithm_impls(algorithm)
   if H is None: return None
   A1, A2 = "%s:%s:%s" % (user, realm, pw), "%s:%s" % (method, uri)
   respdig = KD(H(A1), "%s:%s" % (nonce, H(A2)))
   base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
             'response="%s"' % (user, realm, nonce, uri, respdig)
   if opaque: base = base + ', opaque="%s"' % opaque
   if algorithm != 'MD5': base = base + ', algorithm="%s"' % algorithm
   return base

def get_algorithm_impls(algorithm):
   if algorithm == 'MD5':
      H = lambda x, e=urllib2.encode_digest:e(md5.new(x).digest())
   elif algorithm == 'SHA':
      H = lambda x, e=urllib2.encode_digest:e(sha.new(x).digest())
   KD = lambda s, d, H=H: H("%s:%s" % (s, d))
   return H, KD

# 
# End of Digest Authentication functions
# 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # #

def putdata(fn, uri, auth=None): 
   f, u = open(fn, 'r'), urlparse.urlparse(uri)
   b = f.read()
   s = str(len(b))
   n, p = u[1], u[2]
   perr('PUTing to: '+uri+'\nData: Content-Length: '+s+', Snippet: "'+b[:35]+'"')
   h = httplib.HTTP(n)
   h.putrequest('PUT', p)
   h.putheader('Accept', '*/*')
   h.putheader('Allow', 'PUT')
   if auth: 
      if 'type' in auth.keys(): 
         if auth['type'] == 'Basic': authtobasic(auth, h)
         elif auth['type'] == 'Digest': authtodigest(auth, h, uri, 'PUT')
   h.putheader('Accept-Encoding', '*,deflate')
   h.putheader('Expect', '100-continue')
   h.putheader('User-Agent', UAID)
   h.putheader('Connection', 'Keep-Alive')
   h.putheader('Content-Type', 'text/html')
   h.putheader('Content-Length', s)
   h.endheaders()
   h.send(b)
   perr('Getting reply...')
   errcode, errmsg, headers = h.getreply()
   # body = h.getfile().read(500)
   perr('Got reply')
   h.close()
   if errcode in (301, 302): 
      perr('PUT data error code was '+str(errcode))
      if not auth: put(fn, headers['Location'])
      else: put(fn, headers['Location'], auth=auth)
   elif errcode == 401: 
      perr('Authorization failed!\n'+'Auth: '+headers['www-authenticate'])
      sys.exit(0) # Stops it from continually looping
   else: 
      perr('Done: '+str(errcode)+': '+str(errmsg)+'\n'+str(headers))
      if errcode in (200, 201, 204): 
         sys.stderr.write('PUT succeeded!')
         # perr(body)
      elif errcode == 405: sys.stderr.write('PUT failed!')
      elif errcode == 404: perr('PUT failed: 404!')

# Utility functions

def prompt(): 
   """Prompts for the file name and URI to PUT to."""
   sys.stderr.write('Enter the name of the file you want to HTTP PUT: \n')
   fn = raw_input()
   sys.stderr.write('Enter the URI to HTTP PUT to: \n')
   uri = raw_input()
   if uri[-1] == '/':
      sys.stderr.write('URI ends with a "/"; please enter a file name: \n')
      urifn = raw_input()
      uri = uri+urifn
      sys.stderr.write('Thank you. Saving to: '+uri+'\n')
   put(fn, uri)

def help(): 
   print string.strip(__doc__)
   sys.exit(0)

def run(): 
   HelpFlags, argv = ('-help', '--help'), sys.argv[:]
   for x in sys.argv: 
      if x in HelpFlags: help()
      if x[0] == '-': argv.remove(x)
   s = len(argv)-1
   # perr(str(argv)+' '+str(VERBOSE))
   if s == 2: put(argv[1], argv[2])
   elif s == 4: put(argv[1], argv[2], auth={'uname': argv[3], 'pswd': argv[4]})
   else: help()

if __name__=="__main__": 
   run()
