#!/usr/bin/env python
#
# Copyright 2012 Google Inc. All Rights Reserved.

"""Reports instances of duplicate SMTP message IDs in a user's inbox

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

Example #1: To check one user:
./imap_duplicate_check.py -u administrator \
                          -p mypass \
                          -d mdauphinee.info \
                          -k mdauphinee.info \
                          -s "fffoiuwejhkjkjhsdafxq" \
                          --specific_user=mdauphinee@mdauphinee.info

Example #2: To all users in the domain, 10 threads
./imap_duplicate_check.py -u administrator \
                          -p mypass \
                          -d mdauphinee.info \
                          -k mdauphinee.info \
                          -s "2IxnnYqrkMKgqCMCTGxq" \
                          -t 10

Example #3: For a specific user, run in read only mode and report
            what actions *would be* taken on duplication found in
            a user's account
./imap_duplicate_check.py -u administrator \
                          -p mypass \
                          -d mdauphinee.info \
                          -k mdauphinee.info \
                          -s "2IxnnYqrkMKgqCMCTGxq" \
                          --specific_user=mdauphinee@mdauphinee.info \
                          -l Duplicates

Example #4: For a specific user, leave one copy of duplicates
            unmodified, but apply a label to subsequent copies
            of the message
            NOTE: This only applies the label to the second message
                  found and all subsequent messages.  It does *not*
                  apply the label to the first message found.
./imap_duplicate_check.py -u administrator \
                          -p mypass \
                          -d mdauphinee.info \
                          -k mdauphinee.info \
                          -s "2IxnnYqrkMKgqCMCTGxq" \
                          --specific_user=mdauphinee@mdauphinee.info \
                          -l Duplicates \
                          --modify_messages
"""


import base64
import datetime
import hashlib
import hmac
import imaplib
import logging
from optparse import OptionParser
import Queue
import random
import re
import sys
import threading
import time
import urllib
import gdata.apps.service


class Instruction(object):

  def __init__(self, username):
    self.username = username

  def __str__(self):
    return ('Instruction{UserName:[%s]}' % (self.username))

  def GetUserName(self):
    return self.username


class Worker(threading.Thread):
  """Threaded worker."""

  def __init__(self, consumer_key, consumer_secret, admin_user, admin_pass,
               domain, work_queue, failure_queue, max_retry, max_failures,
               modify_messages, label_to_add, imap_debug_level):

    threading.Thread.__init__(self)
    self.consumer_key = consumer_key
    self.consumer_secret = consumer_secret
    self.admin_user = admin_user
    self.admin_pass = admin_pass
    self.domain = domain
    self.work_queue = work_queue
    self.failure_queue = failure_queue
    self.max_retry = max_retry
    self.max_failures = max_failures
    self.modify_messages = modify_messages
    self.label_to_add = label_to_add
    self.imap_debug_level = imap_debug_level
    self.list_response_pattern = re.compile(
        r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" (?P<name>.*)')

  def run(self):
    """Main worker that manages the jobs and applies changes for each user."""

    while True:

      # get task from queue
      task = self.work_queue.get()

      # retry counter
      retry_count = 0

      # process our users
      if self.failure_queue.qsize() <= self.max_failures:
        while retry_count <= self.max_retry:
          try:
            self._ProcessUser(task)
            break
          except Exception, err:
            logging.warning('\tException when processing [%s]: %s',
                            task.GetUserName(), str(err))
            retry_count += 1
            logging.info('\tRetrying user: [%s] (%s/%s)',
                         task.GetUserName(), retry_count, self.max_retry)
        else:
          logging.error('\tMax retries hit for [%s], skipping',
                        task.GetUserName())
          self.failure_queue.put(task)
      else:
        logging.error("""Max failures reached for this run.
                      Skipping all subsequent entries.""")

      # signals to queue job is done
      self.work_queue.task_done()

  def _GetLocalizedLabelName(self, response, find_label):
    localized_name = ''
    for i in response[1]:
      status, delim, label = self.list_response_pattern.match(i).groups()
      if status.find(find_label) > 0:
        localized_name = label
    return localized_name

  def _ProcessUser(self, task):

    try:
      imap_mngr = ImapConnectionManager(task.GetUserName(),
                                        self.consumer_key,
                                        self.consumer_secret,
                                        self.imap_debug_level)
      imap_conn = imap_mngr.Login()

      status, data = imap_conn.xatom('XLIST', '"" "*"')
      response = imap_conn.response('XLIST')

      trash_label = self._GetLocalizedLabelName(response, 'Trash')
      all_mail_label = self._GetLocalizedLabelName(response, 'AllMail')

      # Select All Mail to search the entire mailbox.
      imap_conn.select(all_mail_label)

      # Create the label to add to all duplicate messages
      if self.modify_messages:
        logging.info("Creating the label [%s] in the account of [%s]",
                     self.label_to_add, task.GetUserName())
        imap_conn.create(self.label_to_add)

      # Search mailbox
      status, data = imap_conn.uid(
          'SEARCH',
          'X-GM-RAW',
          '')

      message_hash = {}

      message_count = 0
      for num in data[0].split():
        message_count += 1
        status, data = imap_conn.uid('FETCH', num,
                                     #'(X-GM-LABELS INTERNALDATE FLAGS BODY.PEEK[HEADER.FIELDS (DATE)] BODY.PEEK[HEADER.FIELDS (SUBJECT)])')
                                     '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])')
        message_id = data[0][1]
        message_id = message_id.strip(' \t\n\r')
        print message_id

        if message_id in message_hash.keys():
          message_hash[message_id] += 1

          # Add the desired label to all duplicates found
          # NOTE: The first message in the set will *not* get the label
          if self.label_to_add:
            if self.modify_messages:
              logging.info("Adding label [%s] to message [%s] for user [%s]",
                           self.label_to_add, message_id, task.GetUserName())
              imap_conn.uid('COPY', num, self.label_to_add)
            else:
              logging.info("Would have applied label [%s] to message [%s]",
                           self.label_to_add, message_id)
        else:
          # First messageID found will not be labeled
          message_hash[message_id] = 1

      for msgid in message_hash.keys():
        if message_hash[msgid] > 1:
          logging.warning('DUPLICATE FOUND for [%s]: [%s] [%s] times',
                          task.GetUserName(), msgid, message_hash[msgid])

       #if self.delete_flag:
       #  logging.info('[%s][%s] Purging records in Trash',
       #              self.name,
       #               task.GetUserName())
       #  # Purge records in Trash older than 60 days
       # imap_conn.select(trash_label)

       #  status, data = imap_conn.uid(
       #      'SEARCH',
       #      'X-GM-RAW',
       #      self._GetTrashSearchQuery(trash_label,
       #                                self.sixty_days_ago_string))
       #
       #  for num in data[0].split():
       #    logging.info('[%s][%s] Applying deleted flag to %s',
       #                 self.name,
       #                 task.GetUserName(),
       #                 num)
       #    imap_conn.uid('STORE', num, '+FLAGS', '\\Deleted')

      imap_mngr.Logout()
    except Exception, err:
      logging.error('\t[%s] Error processing user [%s]: %s',
                    self.name, task.GetUserName(), str(err))
      raise


def ParseInputs():
  """Interprets command line parameters and checks for required parameters."""

  parser = OptionParser()
  parser.add_option('-d', dest='domain',
                    help='The domain name to log into.')
  parser.add_option('-u', dest='admin_user',
                    help='The admin user to use for authentication.')
  parser.add_option('-p', dest='admin_pass',
                    help="The admin user's password")
  parser.add_option('-k', dest='consumer_key',
                    help='The consumer key')
  parser.add_option('-s', dest='consumer_secret',
                    help='The consumer secret')
  parser.add_option('-l', dest='label_to_add',
                    help="""[OPTIONAL] A label to apply to all but one of the
                            duplicated MessageIDs detected""")
  parser.add_option('--specific_user', dest='specific_user',
                    help="""If a specific_user is given, auditing will only be
                            applied to this user, versus all users in the
                            domain.""")
  parser.add_option('--imap_debug_level', dest='imap_debug_level', default=0,
                    help="""[OPTIONAL] Sets the imap debug level.
                            Change this to a higher number to enable console
                            debug""",
                    type='int')
  parser.add_option('-t', dest='threads', default=1, type='int',
                    help="""Number of threads to spawn, max of 100.""")
  parser.add_option('-r', dest='max_retry', default=1, type='int',
                    help="""Number of additional tries a thread will make to
                          perform the ACL before logging the error and
                          moving on.""")
  parser.add_option('-f', dest='max_failures', default=1, type='int',
                    help="""The maximum number of failures allowed before the
                          entire process is terminated.  Failure is defined as
                          a distinct user account that was not able to be
                          updated in the allowable retries.  For example, if
                          max_failures is set to 5 and max_retry is set to
                          3, if there are 6 user accounts for which we tried 4
                          times to update their ACL and failed, we will
                          terminate the process.""")
  parser.add_option('--modify_messages', action='store_true',
                    default=False, dest='modify_messages',
                    help="Unless present, script will run in read only mode.")

  (options, args) = parser.parse_args()
  if args:
    parser.print_help()
    parser.exit(msg='\nUnexpected arguments: %s\n' % ' '.join(args))

  invalid_args = False
  if options.admin_user is None:
    print '-u (admin_user) is required'
    invalid_args = True
  if options.admin_pass is None:
    print '-p (admin_pass) is required'
    invalid_args = True
  if options.domain is None:
    print '-d (domain) is required'
    invalid_args = True
  if options.consumer_key is None:
    print '-k (consumer_key) is required'
    invalid_args = True
  if options.consumer_secret is None:
    print '-s (consumer_secret) is required'
    invalid_args = True

  if invalid_args:
    sys.exit(4)

  return options


def GetProvisionedUsers(admin_user, admin_pass, domain):
  connection = gdata.apps.service.AppsService(
      email='%s@%s' % (admin_user, domain),
      domain=domain,
      password=admin_pass)
  connection.ProgrammaticLogin()
  logging.info('Starting retrieval of all users in the domain')
  user_feed = connection.RetrieveAllUsers()
  logging.info('Finished retrieval of all users in the domain')
  return user_feed


class ImapConnectionManager(object):

  def __init__(self, user, consumer_key, consumer_secret, debug_level):
    self.consumer_key = consumer_key
    self.consumer_secret = consumer_secret
    self.user = user
    self.debug_level = debug_level

  def Login(self):
    xoauth_string = self._GenerateXOauthString(self.consumer_key,
                                               self.consumer_secret,
                                               self.user,
                                               'GET',
                                               'imap')

    ## Setup the IMAP connection and authenticate using OAUTH
    logging.info('[%s] Attempting to login to mailbox', self.user)
    self.imap_connection = imaplib.IMAP4_SSL('imap.gmail.com', 993)
    self.imap_connection.debug = self.debug_level
    try:
      self.imap_connection.authenticate('XOAUTH', lambda x: xoauth_string)
      logging.info('[%s] IMAP connection successfully created', self.user)
    except Exception, e:
      logging.error('Error authenticating with OAUTH credentials provided [%s]',
                    str(e))

    return self.imap_connection

  def Logout(self):
    self.imap_connection.close()
    self.imap_connection.logout()
    logging.info('[%s] IMAP connection successfully closed', self.user)

  def _EscapeAndJoin(self, elems):
    return '&'.join([self._UrlEscape(x) for x in elems])

  def _FormatUrlParams(self, params):
    param_fragments = []
    for param in sorted(params.iteritems(), key=lambda x: x[0]):
      param_fragments.append('%s=%s' % (param[0], self._UrlEscape(param[1])))
    return '&'.join(param_fragments)

  def _UrlEscape(self, text):
    # See OAUTH 5.1 for a definition of which characters need to be escaped.
    return urllib.quote(text, safe='~-._')

  def _GenerateOauthSignature(self, base_string, consumer_secret,
                              token_secret=''):
    key = self._EscapeAndJoin([consumer_secret, token_secret])
    return self._GenerateHmacSha1Signature(base_string, key)

  def _GenerateHmacSha1Signature(self, text, key):
    digest = hmac.new(key, text, hashlib.sha1)
    return base64.b64encode(digest.digest())

  def _GenerateSignatureBaseString(self, method, request_url_base, params):
    return self._EscapeAndJoin([method, request_url_base,
                                self._FormatUrlParams(params)])

  def _FillInCommonOauthParams(self, params, consumer_key):
    params['oauth_consumer_key'] = consumer_key
    params['oauth_nonce'] = str(random.randrange(2**64 - 1))
    params['oauth_signature_method'] = 'HMAC-SHA1'
    params['oauth_version'] = '1.0'
    params['oauth_timestamp'] = str(int(time.time()))

  def _GenerateXOauthString(self, consumer_key, consumer_secret,
                            xoauth_requestor_id, method, protocol):

    url_params = {}
    url_params['xoauth_requestor_id'] = xoauth_requestor_id
    oauth_params = {}
    self._FillInCommonOauthParams(oauth_params, consumer_key)

    signed_params = oauth_params.copy()
    signed_params.update(url_params)
    request_url_base = (
        'https://mail.google.com/mail/b/%s/%s/' % (xoauth_requestor_id,
                                                   protocol))
    base_string = self._GenerateSignatureBaseString(method,
                                                    request_url_base,
                                                    signed_params)

    oauth_params['oauth_signature'] = self._GenerateOauthSignature(
        base_string, consumer_secret)

    # Build list of oauth parameters
    formatted_params = []
    for k, v in sorted(oauth_params.iteritems()):
      formatted_params.append('%s="%s"' % (k, self._UrlEscape(v)))
    param_list = ','.join(formatted_params)

    # Append URL parameters to request url, if present
    if url_params:
      request_url = '%s?%s' % (request_url_base,
                               self._FormatUrlParams(url_params))
    else:
      request_url = request_url_base

    return '%s %s %s' % (method, request_url, param_list)


def GetUserList(options):

  user_list = []
  if options.specific_user:
    user_list.append(options.specific_user)
  else:
    user_feed = GetProvisionedUsers(options.admin_user,
                                    options.admin_pass,
                                    options.domain)
    for user_entry in user_feed.entry:
      user_email = '%s@%s' % (user_entry.login.user_name.lower(),
                              options.domain)
      if user_entry.login.suspended == 'true':
        logging.warning("""User [%s] is suspended, skipping""",
                        user_email)
        continue

      user_list.append(user_email)
  return user_list


def GenerateWorkQueue(user_list):
  work_queue = Queue.Queue()
  for username in user_list:
    work_queue.put(Instruction(username))
    logging.info('Added [%s] to work queue', username)
  return work_queue


def main():

  options = ParseInputs()

  # Set up logging
  log_filename = ('imap_duplicate_check_%s.log' %
                  (datetime.datetime.now().strftime('%Y%m%d%H%M%S')))
  logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
                      filename=log_filename,
                      level=logging.DEBUG)
  console = logging.StreamHandler()
  console.setLevel(logging.INFO)
  logging.getLogger('').addHandler(console)

  logging.info('Pass starting')
  t0 = time.time()

  user_list = GetUserList(options)
  work_queue = GenerateWorkQueue(user_list)
  failure_queue = Queue.Queue()

  # Spawn a pool of threads
  for i in range(options.threads):
    logging.info('Starting thread: %d...', (i + 1))
    t = Worker(options.consumer_key,
               options.consumer_secret,
               options.admin_user,
               options.admin_pass,
               options.domain,
               work_queue,
               failure_queue,
               options.max_retry,
               options.max_failures,
               options.modify_messages,
               options.label_to_add,
               options.imap_debug_level)
    t.setDaemon(True)
    t.start()

  # wait on the queue until everything has been processed
  work_queue.join()

  logging.info('Pass complete')
  duration_in_seconds = time.time() - t0

  logging.info('Pass summary:')
  logging.info('\t[%d] seconds', duration_in_seconds)
  logging.info('\t[%d] users', len(user_list))
  logging.info('\t[%s] sec/user', str((duration_in_seconds/len(user_list))))


if __name__ == '__main__':
  main()
