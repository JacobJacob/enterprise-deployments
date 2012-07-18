#!/usr/bin/python
#
# Copyright 2012 Google Inc. All Rights Reserved.

"""Given a list of users and a Message ID or Gmail query, moves message(s) to
   a specified label (defaulting to each user's Trash).

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

###########################################################################
DISCLAIMER:

(i) GOOGLE INC. ("GOOGLE") PROVIDES YOU ALL CODE HEREIN "AS IS" WITHOUT ANY
WARRANTIES OF ANY KIND, EXPRESS, IMPLIED, STATUTORY OR OTHERWISE, INCLUDING,
WITHOUT LIMITATION, ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NON-INFRINGEMENT; AND

(ii) IN NO EVENT WILL GOOGLE BE LIABLE FOR ANY LOST REVENUES, PROFIT OR DATA,
OR ANY DIRECT, INDIRECT, SPECIAL, CONSEQUENTIAL, INCIDENTAL OR PUNITIVE
DAMAGES, HOWEVER CAUSED AND REGARDLESS OF THE THEORY OF LIABILITY, EVEN IF
GOOGLE HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES, ARISING OUT OF
THE USE OR INABILITY TO USE, MODIFICATION OR DISTRIBUTION OF THIS CODE OR ITS
DERIVATIVES.
###########################################################################

Description: Given a specific message ID or a Gmail query, this script moves the messages (using IMAP) to a specified label or, by default, to each user's Trash for all
users listed in the given user_list file. If the message is moved to the Trash,
it can also be automatically purged.

NOTE: IMAP must be turned on for the domain in order to move these messages.

Usage:
imap_email_mover.py [options]

Options:
  -h, --help            show this help message and exit
  --consumer_key=CONSUMER_KEY
                        The OAuth consumer key for the domain. Required.
  --consumer_secret=CONSUMER_SECRET
                        The OAuth consumer secret for the domain. Required.
  --user=EMAIL_ADDRESS
                        The email address of the user to be exported. Required.
  --owner=EMAIL_ADDRESS
                        The email address of the user to own the Drive archive.
                        Optional. Will default to the specified user.
  --query=QUERY
                        A Gmail query to identify messages to be exported.
                        Optional. By default, all messages will be exported.
"""

import base64
import datetime
import gdata.docs.client as docs_client
import gdata.gauth
import hashlib
import hmac
import imaplib
import logging
from optparse import OptionParser
import random
import re
import StringIO
import sys
import time
import urllib


class OAuthEntity(object):
  """Represents consumers and tokens in OAuth."""

  def __init__(self, key, secret):
    self.key = key
    self.secret = secret


def EscapeAndJoin(elems):
  return '&'.join([UrlEscape(x) for x in elems])


def FormatUrlParams(params):
  """Formats parameters into a URL query string.

  Args:
    params: A key-value map.

  Returns:
    A URL query string version of the given parameters.
  """
  param_fragments = []
  for param in sorted(params.iteritems(), key=lambda x: x[0]):
    param_fragments.append('%s=%s' % (param[0], UrlEscape(param[1])))
  return '&'.join(param_fragments)


def UrlEscape(text):
  # See OAUTH 5.1 for a definition of which characters need to be escaped.
  return urllib.quote(text, safe='~-._')


def GenerateOauthSignature(base_string, consumer_secret, token_secret=''):
  key = EscapeAndJoin([consumer_secret, token_secret])
  return GenerateHmacSha1Signature(base_string, key)


def GenerateHmacSha1Signature(text, key):
  digest = hmac.new(key, text, hashlib.sha1)
  return base64.b64encode(digest.digest())


def GenerateSignatureBaseString(method, request_url_base, params):
  """Generates an OAuth signature base string.

  Args:
    method: The HTTP request method, e.g. "GET".
    request_url_base: The base of the requested URL. For example, if the
      requested URL is
      "https://mail.google.com/mail/b/xxx@domain.com/imap/?" +
      "xoauth_requestor_id=xxx@domain.com", the request_url_base would be
      "https://mail.google.com/mail/b/xxx@domain.com/imap/".
    params: Key-value map of OAuth parameters, plus any parameters from the
      request URL.

  Returns:
    A signature base string prepared according to the OAuth Spec.
  """
  return EscapeAndJoin([method, request_url_base, FormatUrlParams(params)])


def FillInCommonOauthParams(params, consumer):
  """Fills in parameters that are common to all oauth requests.

  Args:
    params: Parameter map, which will be added to.
    consumer: An OAuthEntity representing the OAuth consumer.
  """

  params['oauth_consumer_key'] = consumer.key
  params['oauth_nonce'] = str(random.randrange(2**64 - 1))
  params['oauth_signature_method'] = 'HMAC-SHA1'
  params['oauth_version'] = '1.0'
  params['oauth_timestamp'] = str(int(time.time()))


def GenerateXOauthString(consumer, xoauth_requestor_id, method, protocol):
  """Generates an IMAP XOAUTH authentication string.

  Args:
    consumer: An OAuthEntity representing the consumer.
    xoauth_requestor_id: The Google Mail user who's inbox will be
                         searched (full email address)
    method: The HTTP method used in the API request
    protocol: The protocol used in the API request

  Returns:
    A string that can be passed as the argument to an IMAP
    "AUTHENTICATE XOAUTH" command after being base64-encoded.
  """

  url_params = {}
  url_params['xoauth_requestor_id'] = xoauth_requestor_id
  oauth_params = {}
  FillInCommonOauthParams(oauth_params, consumer)

  signed_params = oauth_params.copy()
  signed_params.update(url_params)
  request_url_base = (
      'https://mail.google.com/mail/b/%s/%s/' % (xoauth_requestor_id, protocol))
  base_string = GenerateSignatureBaseString(
      method,
      request_url_base,
      signed_params)

  oauth_params['oauth_signature'] = GenerateOauthSignature(base_string,
                                                           consumer.secret)

  # Build list of oauth parameters
  formatted_params = []
  for k, v in sorted(oauth_params.iteritems()):
    formatted_params.append('%s="%s"' % (k, UrlEscape(v)))
  param_list = ','.join(formatted_params)

  # Append URL parameters to request url, if present
  if url_params:
    request_url = '%s?%s' % (request_url_base,
                             FormatUrlParams(url_params))
  else:
    request_url = request_url_base

  return '%s %s %s' % (method, request_url, param_list)

def CreateFolder(connection, name, owner=None, parent=None):
  """ Creates and assigns ownership of a Drive Collection

  Arguments:
    connection: a gdata.docs.client.DocsClient, the connection to Google Drive
    name: a string, the name of the collection
    owner: the owner of the collection. (None means don't set an ACL)
    parent: the parent collection. (None means use the document root)

  Returns:
    A gdata.docs.data.Resource, the resource locator for the created
    collection
  """
  document = gdata.docs.data.Resource(type='folder',
                                      title=name)

  folder = connection.CreateResource(document, collection=parent)

  if owner:
    acl_entry = gdata.docs.data.AclEntry(
        scope=gdata.acl.data.AclScope(value=owner, type='user'),
        role=gdata.acl.data.AclRole(value='owner'),)

    docs_connection.AddAclEntry(folder, acl_entry, send_notifications=False)

  return folder


def ExportLabelToFolder(imap_connection, docs_connection, label, parent_folder,
                        query, owner):
  """ Exports all messages under an IMAP label to a comparable Drive folder.

  Arguments:
    imap_connection: an imaplib connection, the connection to IMAP
    docs_connection: a gdata.docs.client.DocsClient, the connection to Google
                     Drive
    label: a string, the IMAP label from which to export messages
    parent_folder: a gdata.docs.data.Resource, the resource for the parent
                   folder in Google Drive
    query: a Gmail-style query to restrict the export of messages. (None means
           to export all messages.)
    owner: a string, the email address of the person who should own the export

  Returns:
    Nothing
  """
  try:
    (result, unused_data) = imap_connection.select(label)
  except Exception, e:
    logging.info('Skipping label %s', label)
    return
 
  logging.info('Label %s selected', label)

  unused_type, data = imap_connection.uid('SEARCH', 'X-GM-RAW', query)
  messages = data[0].split()
  total_in_label = len(messages)
  logging.info('Messages in %s: %s', label, total_in_label)

  if messages:
    folder = CreateFolder(docs_connection, label, owner, parent_folder)

    for message_locator in messages:
      (result, message_info) = imap_connection.fetch(message_locator,
                                                     '(RFC822)')

      try:
        (unused_data, message) = message_info[0]
      except Exception, e:
        logging.info('Message not retrieved. Skipping.')
        continue

      try:
        sender_full = (re.search('From: .*[\r\n]', message).group(0))[6:]
      except Exception, e:
        sender_full = ''

      if not sender_full:
        try:
          sender_full = (re.search('Sender: .*[\r\n]', message).group(0))[8:]
        except Exception, e:
          sender_full = '<unknown_user@unknown_domain>'

      try:
        sender = re.search("[a-z0-9\'\-\+\._]*@[a-z0-9\-\.]*",
                           sender_full).group(0).strip()
      except Exception, e:
        sender = 'unknown_sender'

      try:
        subject = (re.search('Subject: .*[\r\n]', message).group(0))[9:].strip()
      except Exception, e:
        subject = 'unknown_subject'

      title = sender + ": " + subject
      document_reference = gdata.docs.data.Resource(type='document',
                                                    title=title)

      media = gdata.data.MediaSource(file_handle=StringIO.StringIO(message),
                                     content_type='text/plain',
                                     content_length=len(message))

      remaining_tries = 5
      while remaining_tries:
        try:
          document = docs_connection.CreateResource(document_reference,
                                                    media=media,
                                                    collection=folder)
          remaining_tries = 0
        except Exception, e:
          remaining_tries -= 1
          if remaining_tries == 0:
            logging.info('Could not add %s to collection %s', title, label)
           
      if owner:
        acl_entry = gdata.docs.data.AclEntry(
            scope=gdata.acl.data.AclScope(value=owner, type='user'),
            role=gdata.acl.data.AclRole(value='owner'),)

        docs_connection.AddAclEntry(document, acl_entry,
                                    send_notifications=False)

      logging.info('Added %s to collection %s', title, label)


def ImapSearch(user, consumer_key, consumer_secret, owner, query, imap_debug):
  """Searches the user inbox for specific messages. Uploads them to Drive.

  Args:
    user: The Google Mail username that we are searching
    consumer_key: a string, the OAuth key for access to Gmail and Drive
    consumer_secret: a string, the OAuth secret for the above key
    owner: The owner of the uploaded Drive files
    query: A query to find messages
    imap_debug: IMAP debug level
  """

  messages_found = 0

  # Setup the IMAP connection and authenticate using OAUTH
  logging.info('[%s] Attempting to login to mailbox', user)
  imap_connection = imaplib.IMAP4_SSL('imap.gmail.com', 993)
  imap_connection.debug = imap_debug

  consumer = OAuthEntity(consumer_key, consumer_secret)
  xoauth_string = GenerateXOauthString(consumer, user, 'GET', 'imap')

  try:
    imap_connection.authenticate('XOAUTH', lambda x: xoauth_string)
  except Exception, e:
    logging.error('Error authenticating with OAUTH credentials provided [%s]',
                  str(e))

  # Setup the Drive connection and authenticate using OAUTH
  logging.info('[%s] Attempting to login to Drive', owner)
  docs_connection = docs_client.DocsClient(source='docs_meta-v1')
  docs_connection.auth_token = gdata.gauth.TwoLeggedOAuthHmacToken(
      consumer_key, consumer_secret, user)

  export_folder_name = user + ' exported ' + GetTimeStamp()
  export_folder = CreateFolder(docs_connection, export_folder_name, owner)

  # By default, we want to search for the message in the All Mail folder since
  # all messages live there. IMAP does not allow us to search for a message in
  # the entire mailbox but luckily Gmail has the "All Mail" folder.
  # We also search for the message in the Spam label since spam messages do not
  # show up in All Mail.

  # Search the labels specified above for the specified message-ID
  #imap_connection.select(label)

  labels = []
  (unused_type, label_list) = imap_connection.list()
  for label_info in label_list:
    label_data = label_info.split('"')
    metadata = label_data[0]
    label = label_data[3]

    if metadata.find('\\Noselect') != -1:
      continue

    labels.append(label)

  for label in labels:
    ExportLabelToFolder(imap_connection, docs_connection, label, 
                        export_folder, query, owner)
    
  imap_connection.close()
  imap_connection.logout()
  logging.info('[%s] IMAP connection sucessfully closed', user)


def GetTimeStamp():
  """Generates a string representing the current time for the log file name.

  Returns:
    A formatted string representing the current date and time.
  """

  now = datetime.datetime.now()
  return now.strftime('%Y.%m.%d@%H:%M:%S')


def ParseInputs():
  """Interprets command line parameters and checks for required parameters.

  Returns:
    The options object of parsed command line options.
  """

  parser = OptionParser()
  parser.add_option('--consumer_key', dest='consumer_key',
                    help='The OAuth consumer key for the domain.')
  parser.add_option('--consumer_secret', dest='consumer_secret',
                    help='The OAuth consumer secret for the domain.')
  parser.add_option('--user', dest='user',
                    help='The Email address of the user to export.')
  parser.add_option('--owner', dest='owner',
                    help='The new owner of the archive in Drive.')
  parser.add_option('--query', dest='query', default='',
                    help='A Gmail query to identify messages.')

  parser.add_option('--imap_debug_level', dest='imap_debug_level', default=0,
                    help="""[OPTIONAL] Sets the imap debug level.
                            Change this to a higher number to enable console
                            debug""",
                    type='int')

  (options, args) = parser.parse_args()
  if args:
    parser.print_help()
    parser.exit(msg='\nUnexpected arguments: %s\n' % ' '.join(args))

  invalid_arguments = False

  if options.consumer_key is None:
    print '--consumer_key is required'
    invalid_arguments = True

  if options.consumer_secret is None:
    print '--consumer_secret is required'
    invalid_arguments = True

  if options.user is None:
    print '--user is required'
    invalid_arguments = True

  if invalid_arguments:
    sys.exit(1)

  return options


def main():
  options = ParseInputs()

  # Set up logging
  log_filename = 'imap_to_drive_%s.log' % GetTimeStamp()
  logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
                      filename=log_filename,
                      level=logging.DEBUG)
  console = logging.StreamHandler()
  console.setLevel(logging.INFO)
  logging.getLogger('').addHandler(console)

  ImapSearch(options.user, options.consumer_key, options.consumer_secret,
             options.owner, options.query, options.imap_debug_level)

  print 'Log file is: %s' % log_filename


if __name__ == '__main__':
  main()
