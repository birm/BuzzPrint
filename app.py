#!/usr/bin/env python

import re
import logging
from os import urandom
from os.path import join
from urllib2 import urlopen, URLError
from urlparse import urlparse
from xml.etree import cElementTree as cET
from werkzeug.utils import secure_filename
from subprocess import check_call, check_output, CalledProcessError
from flask import Flask, request, make_response, render_template, session, url_for, redirect

app = Flask(__name__)
app.secret_key = urandom(16)
app.config['UPLOAD_FOLDER'] = '/tmp'

extensions = set(['pdf'])
protocols = set(['http', 'https'])
callback = "http://webprint.gtisc.gatech.edu/auth"

# Simple init stuff - logging, debug, stuff like that.
def init():
	logfile = '/opt/print_logs'

	handler = logging.FileHandler(logfile)
	handler.setFormatter(logging.Formatter('[%(levelname)s]: %(message)s'))

	if app.debug: app.logger.setLevel(logging.DEBUG)
	else: app.logger.setLevel(logging.INFO)

	app.logger.addHandler(handler)
	app.logger.removeHandler(app.logger.handlers[0])

# Simple validation to make sure user uploads only allowed filetypes
# In: Name of file user wishes to print
# Out: bool - True if file is type user allowed to print
def IsValidFile(filename):
	return '.' in filename and filename.rsplit('.', 1)[1] in extensions

def BuildSuccessStr(filename):
	return 'Your job has been submitted to the print queue with the name {0}'.format(filename)

def BuildErrorStr(text):
	return 'Your job could not be submitted to the print queue because {0}'.format(text)

# Simple validation to make sure user submitted real URL
# In: URL user wishes to download
# Out: book - True if valid URL
def IsValidURL(url):
	seemsLegit = False
	target = urlparse(url)

	app.logger.debug('Submitted URL scheme: {0}'.format(target.scheme))
	app.logger.debug('Submitted URL location: {0}'.format(target.netloc))
	app.logger.debug('Submitted URL path: {0}'.format(target.path))

	if target.scheme not in protocols:
		app.logger.warning('User {0} tried to submit invalid URL {1}'.format(session['username'], url))

	elif target.netloc == 'docs.google.com':
		app.logger.info('Right now I assume all Google Docs URLs are good since I know of no way to verify one')
		seemsLegit = True

	elif target.path.split('.')[-1] in extensions and '/.' not in target.path:
		app.logger.debug('User {0} submitted URL {1} - seems legit'.format(session['username'], url))
		seemsLegit = True

	return seemsLegit

# Validates current user status against CAS
# In: String representing CAS ticket
# Out: (bool, string) - True for active accounts, string is username
def IsValidTicket(ticket):
	seemsLegit = False
	xml = None
	user = ''
	ticketRegex = re.compile('^ST-\d+-[0-9a-zA-Z]+-[0-9a-zA-Z\.]+.gatech.edu$')

	# Sanity check
	app.logger.debug('Sanity checking ticket {0}'.format(ticket))
	if ticketRegex.search(ticket):

		try:
			# Actually validate the ticket
			app.logger.debug('Sanity check passed; validating ticket...')
			response = urlopen('https://login.gatech.edu/cas/serviceValidate?ticket={0}&service={1}'.format(ticket, callback))
			xml = cET.fromstring(response.read())

		except URLError as e:
			app.logger.error('Error making ticket validation call: {0}'.format(str(e.reason)))

		if xml and xml.find('{http://www.yale.edu/tp/cas}authenticationSuccess'):
			user = xml.find('{http://www.yale.edu/tp/cas}authenticationSuccess').find('{http://www.yale.edu/tp/cas}user').text
			app.logger.debug('Successfully validated ticket for user {0}'.format(user))
			seemsLegit = True

	else:
		app.logger.warning('Someone just tried to pass a bad ticket')

	return (seemsLegit, user)

# Calls out to perl script which grabs PDF of URL
# In: String representing URL of desired file
# Out: (string, bool, string) - Path to file, True if no problems, assc. error text
# TODO: Max size for file we download
def ProcessURL(url):
	error = False
	errorText = ''
	path = ''

	if url.find('http') != 0:

		if url.find('docs.google.com') == 0:

			app.logger.debug('URL {0} looks like a Google Docs address - appending https://'.format(url))
			url = 'https://' + url

		# Should catch ftp://, file://, etc.
		elif '://' not in url:

			app.logger.debug('Appended http:// to URL {0}'.format(url))
			url = 'http://' + url

	if IsValidURL(url):
		try:
			# Let's grab the file
			app.logger.info('Grabbing file at URL {0}'.format(url))
			path = str(check_output(['perl', '/opt/url2pdf.pl', url])).strip()
			app.logger.debug('File saved to location {0}'.format(path))

		except CalledProcessError as e:
			app.logger.error('User {0} submitted wonky URL: {1}'.format(session['username'], url))
			error = True
			errorText = 'the server could not download file located at {0}'.format(url)

	else:
		app.logger.warning('User {0} submitted invalid URL {1}'.format(session['username'], url))
		error = True
		errorText = 'the URL {0} does not lead to an allowed document'.format(url)

	return (path, error, errorText)

# Makes sure the user is allowed to print this type of file, saves it to server if so
# In: File to be printed
# Out: (string, bool, string) - Path to file, True if no problems, assc. error text
def ProcessFile(upload):
	error = False
	errorText = ''
	path = ''

	if not IsValidFile(upload.filename):

		app.logger.warning('User {0} tried to upload invalid file: {1}'.format(session['username'], upload.filename))
		error = True
		errorText = 'the file you tried to print is not one of the allowed filetypes'

	else:
		path = join(app.config['UPLOAD_FOLDER'], secure_filename(upload.filename))
		app.logger.debug('Saving file to location {0}'.format(path))
		upload.save(path)

	return (path, error, errorText)

# Determines the correct queue to choose given the user's decision
# In: String representing URL of desired file
# Out: (string, bool, string) - queue name, True if no problems, assc. error text
def ProcessQueue(queueName):
	error = False
	errorText = ''
	queue = ''

	if queueName == 'black': queue = 'mobile_black'
	elif queueName == 'color': queue = 'mobile_color'
	elif queueName == 'staple': queue = 'mobile_staple'
	elif queueName == 'central': queue = 'central'
	else:
		app.logger.warning('User {0} tried to submit to invalid queue: {1}'.format(session['username'], queueName))
		error = True
		errorText = 'you have tried to submit to a queue this website does not support; please try a different queue'

	return (queue, error, errorText)

# Processes user's print request and dispatches accordingly
# In: Request representing user's print job
# Out: (string, string, bool, string) - Print queue, path to file,
#      True if no problems, assc. error text
def ProcessJob(request):
	path = ''
	queue = ''
	error = False
	errorText = ''

	if request.form['type'] == 'url':

		app.logger.debug('Request was for URL')

		if 'url' in request.form and request.form['url'] != '':
			(path, error, errorText) = ProcessURL(request.form['url'])

		else:
			app.logger.warning('User {0} chose URL submission, but did not include URL'.format(session['username']))
			error = True
			errorText = 'you chose to print from a URL but did not include one with your submission'

	elif request.form['type'] == 'file':

		app.logger.debug('Request was for file')

		if 'file' in request.files and request.files['file'].filename != '':
			(path, error, errorText) = ProcessFile(request.files['file'])

		else:
			app.logger.error('User {0} chose file submission, but did not include file'.format(session['username']))
			error = True
			errorText = 'you chose to upload a file but did not include a file to print'

	if not error: (queue, error, errorText) = ProcessQueue(request.form['queue'])

	return (queue, path, error, errorText)

# Dummy endpoint, redirects user to CAS for ticket
@app.route('/')
def index():
	return redirect('https://login.gatech.edu/cas/login?service={0}&gateway=true'.format(callback))

# Simple callback stuff - make sure nobody's blatantly trying to hack us,
# validate the ticket and redirect the user
@app.route('/auth')
def auth():
	hasValidTicket = False

	if 'ticket' in request.args:
		(hasValidTicket, user) = IsValidTicket(request.args.get('ticket'))

	if hasValidTicket:

		session['username'] = user
		return redirect(url_for('main'))

	else:
		return redirect(url_for('login'))
		
# Dummy login while the real one is being built
@app.route('/login')
def login():
	return redirect('https://login.gatech.edu/cas/login?service={0}'.format(callback))

@app.route('/print', methods=['GET', 'POST'])
def main():
	success = None
	failure = None

	if not 'username' in session:

		app.logger.debug('Looks like someone wants to print before they auth')
		return redirect('https://login.gatech.edu/cas/login?service={0}&gateway=true'.format(callback))

	if request.method == 'POST':
		error = False

		if 'type' in request.form and 'queue' in request.form:

			app.logger.debug('Submission from user {0} not missing required fields; processing now'.format(session['username']))
			(queue, path, error, errorText) = ProcessJob(request)

		else:
			app.logger.warning('Submission from user {0} missing required field: type - {1}; queue - {2}'.format(session['username'], 'type' in request.args, 'queue' in request.form))
			error = True
			errorText = 'you either did not choose a job type or a print queue'

		if not error:
			try:
				app.logger.info('Submitting job for user {0} to queue {1}: {2}'.format(session['username'], queue, path.split("/")[-1]))
				check_call(['lpr', '-r', '-P', queue, '-U', session['username'], path])
			except CalledProcessError as e:
				app.logger.error('Problem sending file {0} for user {1} to queue {2}'.format(path.split("/")[-1], session['username'], queue))
				error = True
				errorText = 'there was a problem sending your document to the printers; please try again'

		if not error:

			app.logger.info('Successful job submission for user {0}'.format(session['username']))
			success = BuildSuccessStr(path.split('/')[-1])

		if error:
			failure = BuildErrorStr(errorText)

	return render_template('print.html', username = session['username'],  success = success,  error = failure)

if __name__ == '__main__':
	init()
	app.run(host='0.0.0.0', port=80, threaded=True)