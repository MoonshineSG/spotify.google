#!/usr/bin/env python3

import os, sys, time, threading, atexit
import logging
from logging.handlers import RotatingFileHandler
import requests

import spotipy
import spotipy.util as util
from spotipy.oauth2 import SpotifyOAuth

import pychromecast
from pychromecast.controllers import BaseController

from flask import Flask, jsonify, request, abort

# ================================================================================================================ CONFIGURATION

from config import *  

scope = "user-read-currently-playing user-read-recently-played user-modify-playback-state user-read-playback-state"

# ================================================================================================================ SETUP
log_level = logging.DEBUG
#log_level = logging.INFO

log_path=os.path.join(os.path.dirname(os.path.realpath(__file__)), "spotify.log")
formatter = logging.Formatter('%(asctime)-.30s - %(levelname)-8s %(message)s')

handler = RotatingFileHandler(log_path, maxBytes=100000, backupCount=2)
handler.setFormatter(formatter)
	
app = Flask(__name__)
app.url_map.strict_slashes = False

app.logger.addHandler(handler)
app.logger.setLevel(log_level)

log = logging.getLogger('werkzeug')
log.setLevel(log_level)
log.addHandler(handler)

# ================================================================================================================ spotipy
class Token():
	
	def __init__(self):
		self.__value__ = None
		self.status = threading.Event()
		threading.Thread(target=self.__fetch__).start() #run in parallel
		
	def __fetch__(self):
		start_time = time.time()

		try:
			GOTO = ["https://accounts.spotify.com/en/login", "https://accounts.spotify.com/api/login", "https://open.spotify.com/browse"]
		
			browser_session = requests.session()
			browser_session.cookies.set('__bon' , 'MHwwfDB8MHwxfDF8MXwx', domain='accounts.spotify.com')
			headers = { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36' }

			#1. get csrf
			browser_session.get(GOTO[0], headers=headers)
			csrf_token = browser_session.cookies['csrf_token']
		
			#2. Login
			login_data = dict(username=username, password=password, csrf_token=csrf_token)
			headers['Referer'] = GOTO[0]
			browser_session.post(GOTO[1], data=login_data, headers=headers)

			#3. get token
			browser_session.get(GOTO[2], headers=headers)
			self.__value__ = browser_session.cookies['wp_access_token']
		
		except Exception as e:
			app.logger.error(e)
		
		self.status.set() #unlock
		app.logger.info ("wp_access_token fetch took [%s] seconds", ( time.time() - start_time ))

	@property
	def value(self):
		app.logger.debug ( "Waiting for wp_access_token..." )
		self.status.wait(10) #wait for lock
		app.logger.debug ( "Received wp_access_token [%s]", self.__value__)
		return self.__value__

# ================================================================================================================ pychromecast
class SpotifyController(BaseController):
	def __init__(self):
		super(SpotifyController, self).__init__(
			"urn:x-cast:com.spotify.chromecast.secure.v1", 'CC32E753')
		self.device = None
		self.web_token = Token()
		self.waiting = threading.Event()

	def receive_message(self, message, data):
		app.logger.debug(data)
		if data['type'] == 'setCredentialsResponse':
			self.send_message({'type': 'getInfo', 'payload': {}})
		if data['type'] == 'setCredentialsError':
			self.device = None
			self.waiting.set()
		if data['type'] == 'getInfoResponse':
			self.device = data['payload']['deviceID']
			self.waiting.set()
		return True

	def login(self):
		app.logger.info("Spotify Chromecast login...")
		self.waiting.clear()
		while not self.is_active:
			time.sleep(0.1)
		self.send_message({'type': 'setCredentials', 'credentials': self.web_token.value })

	def wait(self):
		self.waiting.wait(15)
		return self.device

# ================================================================================================================ SCRIPING 
def activate():
	app.logger.info("Activating Spotify on ChromeCast ...")
	
	chromecast = pychromecast.Chromecast(chromecast_ip)
	
	chromecast.wait()
	chromecast.set_volume(volume)
	spotify_controller = SpotifyController()
	chromecast.register_handler(spotify_controller)

	spotify_controller.launch() #start Spotify on Chromecast	
	spotify_controller.login() #login Spotify on Chromecast
	
	device_id = spotify_controller.wait() #wait for the login sequence which returns the device ID
	
	app.logger.debug(chromecast.device)
	app.logger.debug(chromecast.status)
	
	chromecast.disconnect(blocking=False)
	
	return device_id
			
def getChromecast():
	global chromecast_id
	devices = spotify_client.devices()
	if devices:
		app.logger.debug(devices)
		for device in devices['devices']:
			if device['name'] == chromecast: #in case multiple devices are available
				chromecast_id = device['id']
				app.logger.info("ChromeCast active Spotify ID: %s", chromecast_id)
				return chromecast_id
	app.logger.info("Spotify not on ChromeCast. Activating...")
	chromecast_id = activate()
	app.logger.debug("ChromeCast active Spotify ID: %s", chromecast_id)
	app.logger.debug(spotify_client.current_user())
	return chromecast_id

# ================================================================================================================ ERROR HANDLER
def handle_error(e, callback, retry):
	error = str(e)
	app.logger.debug("handle_error: %s",  error)
	handled = False
	if error.endswith("The access token expired"):
		global spotify_client
		app.logger.info("The access token expired. Get new one...")

		new_token = oath.refresh_access_token( oath.get_cached_token()['refresh_token'] )
		app.logger.debug("new_token: %s", new_token)

		spotify_client = spotipy.client.Spotify(auth=new_token['access_token'])
		handled = True
	elif error.endswith("Device not found"):
		app.logger.info("Device not found. Refreshing...")
		getChromecast()
		handled = True
	elif error.endswith("Could not connect to %s:8009"%chromecast_ip):
		app.logger.info("Device offline?? ")
		return "OFFLINE"
	elif error.endswith("Already paused"):		
		if request.endpoint == 'toggle':
			app.logger.debug("*** Retrying toggle [%s]"%retry)
			retry -= 1
			return play(retry)
		app.logger.info("Already paused")
		return "OK"
	elif error.endswith("Not paused"):
		app.logger.info("Not paused")
		return "OK"

	if retry > 0 and handled and callable(callback):
		retry -= 1 
		app.logger.debug("*** Retrying [%s]"%retry)
		return callback(retry)

# ================================================================================================================ ROUTES	
@app.route('/play')
def play(retry = 3):
	try:
		if spotify_client.currently_playing():
			spotify_client.start_playback(device_id = chromecast_id)
		else:
			try:
				recents = spotify_client.current_user_recently_played(1)
				spotify_client.start_playback(device_id = chromecast_id, context_uri = recents['items'][0]['track']['album']['uri'])
			except: #brand new user ?  
				return "EMPTY\n"

	except Exception as e:
		return handle_error(e, play, retry)
	return "OK\n"

@app.route('/pause')
def pause(retry = 3):
	try:
		spotify_client.pause_playback(chromecast_id)
	except Exception as e:
		return handle_error(e, pause, retry)
	return "OK\n"

@app.route('/toggle')
def toggle(retry = 3):
	try:
		spotify_client.pause_playback(chromecast_id)
	except Exception as e:
		return handle_error(e, toggle, retry)
	return "OK\n"
	
@app.route('/previous')
def previous_track(retry = 3):
	try:
		spotify_client.previous_track(chromecast_id)
	except Exception as e:
		return handle_error(e, previous_track, retry)
	return "OK\n"

@app.route('/next')
def next_track(retry = 3):
	try:
		spotify_client.next_track(chromecast_id)
	except Exception as e:
		return handle_error(e, next_track, retry)
	return "OK\n"

# ================================================================================================================ Login free
@app.route('/login')
@app.route('/login/<account>')
def login(account = "default", retry = 3):	
	try:
		if spotify_oath_login(account):
			spotify_client.transfer_playback( getChromecast(), force_play=False)
	except Exception as e:		
		return handle_error(e, login, retry)
	return "OK\n"

@app.route('/off')
def power_off():
	chromecast = pychromecast.Chromecast(chromecast_ip)
	chromecast.quit_app()
	return "OK\n"

@app.route('/reboot')
def reboot():
	chromecast = pychromecast.Chromecast(chromecast_ip)
	chromecast.reboot()
	os.system("sudo systemctl restart spotify")
	return "OK\n"

# ================================================================================================================ Testing
@app.route('/devices')
def devices(retry = 3):
	try:
		return jsonify(spotify_client.devices())
	except Exception as e:
		handle_error(e, devices, retry)
		return "RETRY\n"

@app.route('/now')
def now(retry = 3):
	try:
		playing =  spotify_client.currently_playing()
		if playing:
			return jsonify(playing['item'])
		else:
			return "NONE\n"
	except Exception as e:
		handle_error(e, None, 0)
		return "RETRY\n"
		
@app.route('/recent')
def recent(retry = 3):
	try:
		result = []
		for item in spotify_client.current_user_recently_played()['items']:
			result.append(item['track']['album']['external_urls']['spotify'])
		return jsonify(result)
	except Exception as e:
		handle_error(e, None, 0)
		return "RETRY\n"

@app.route('/status')
def status():
	chromecast = pychromecast.Chromecast(chromecast_ip)
	chromecast.wait()
	chromecast.register_handler(SpotifyController())
	app.logger.info(chromecast.device)
	app.logger.info(chromecast.status)
	chromecast.disconnect(blocking=False)
	return "OK\n"

# ================================================================================================================ Flask Errors
@app.errorhandler(404)
def page_not_found(e):
	app.logger.error(e)
	return "NOT FOUND\n", 404

@app.errorhandler(500)
def internal_server_error(e):
	app.logger.error(e)
	return "SERVER ERROR\n", 500

@app.errorhandler(401)
def credentials_error(e):
	app.logger.error(e)
	return "LOGIN FIRST\n", 401

@app.before_request
def before_request():
	_abort_ = False
	try:
		if spotify_client == None or chromecast_id == None or oath == None: 
			_abort_ = True
	except NameError:
		_abort_ = True

	if _abort_ and request.endpoint not in ['login', 'power_off', 'reboot']:
		if "default" in accounts:
			login()
		else:
			abort(401)

# ================================================================================================================ INITIALIZE
def spotify_oath_login(account):
	global spotify_client, oath, username, password, cached_token
	username = accounts[account]["username"]
	password = accounts[account]["password"]

	cache_path=os.path.join(os.path.dirname(os.path.realpath(__file__)), ".cache-%s"%username)

	oath = SpotifyOAuth(client_id, client_secret, redirect_uri, scope=scope, cache_path=cache_path)

	cached_token = oath.get_cached_token()
	app.logger.debug("cached_token: %s", cached_token)
	if cached_token:
		spotify_client = spotipy.client.Spotify(auth=cached_token['access_token'])
		app.logger.debug(spotify_client.current_user())
	else:
		app.logger.info("SpotifyToken can't be found. Running *** interactive **** OATH2 flow to approve application.")
		if sys.stdin.isatty():
			util.prompt_for_user_token( username, scope, client_id, client_secret, redirect_uri, cache_path )
		else:
			app.logger.error("You must run this via a terminal, at least once.")
		exit()	
	return True
	
# ================================================================================================================ START
try:
	app.run(host='127.0.0.1', port=9999, debug=False, threaded=False)
except KeyboardInterrupt as e:
	pass