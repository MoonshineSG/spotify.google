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

from flask import Flask, jsonify

# ================================================================================================================ CONFIGURATION
#name of the chromecast device
chromecast = ""
chromecast_ip =""

#spotify_client credentials 
username = ""
password = ""

#Application 
client_id = ""
client_secret = ""
redirect_uri = ""

scope = "streaming user-read-currently-playing user-read-recently-played user-modify-playback-state user-read-playback-state"
cache_path=os.path.join(os.path.dirname(os.path.realpath(__file__)), ".cache-%s"%username)

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
		threading.Thread(target=self.fetch).start() #run in parallel
		
	def fetch(self):
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
		
			self.status.set() #unlock 
		except Exception as e:
			app.logger.error(e)
			#try again in 15 seconds
			threading.Timer(15, self.fetch).start()
		
		app.logger.info ("wp_access_token fetch took [%s] seconds", ( time.time() - start_time ))

	@property
	def value(self):
		app.logger.debug ( "Waiting for wp_access_token..." )
		self.status.wait() #wait for lock
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

	def wait(self, timeout=None):
		self.waiting.wait(timeout=timeout)
		return self.device

# ================================================================================================================ SCRIPING 
def activate():
	app.logger.info("Activating Spotify on ChromeCast ...")
	chromecast = pychromecast.Chromecast(chromecast_ip)
	chromecast.wait()
	spotify_controller = SpotifyController()
	chromecast.register_handler(spotify_controller)

	spotify_controller.launch() #start Spotify on Chromecast	
	spotify_controller.login() #login Spotify on Chromecast
	
	device_id = spotify_controller.wait() #wait for the login sequence which returns the device ID
	chromecast.disconnect(blocking=False)
	
	return device_id
			
def getChromecast():
	global denon	
	devices = spotify_client.devices()
	if devices:
		app.logger.debug(devices)
		for device in devices['devices']:
			if device['name'] == chromecast: #in case multiple devices are available
				denon = device['id']
				app.logger.info("Active ChromeCast: %s" ,denon)
				return denon
	app.logger.info("Spotify not on ChromeCast. Activating...")
	denon = activate()
	app.logger.debug("Activated ChromeCast ID: %s", denon)
	return denon

# ================================================================================================================ ERROR HANDLER
def handle_error(e, callback):
	app.logger.debug(e)
	if e.msg.endswith("The access token expired"):
		global spotify_client
		app.logger.info("The access token expired. Get new one...")

		new_token = oath.refresh_access_token( oath.get_cached_token()['refresh_token'] )
		app.logger.debug("new_token: %s", new_token)

		spotify_client = spotipy.client.Spotify(auth=new_token['access_token'])

	elif e.msg.endswith("Device not found"):
		app.logger.info("Device not found. Refreshing...")
		getChromecast()
	elif e.msg.endswith("Already paused"):
		app.logger.info("Already paused")
		return
	elif e.msg.endswith("Not paused"):
		app.logger.info("Not paused")
		return

	if callable(callback):
		callback()

# ================================================================================================================ ROUTES	
@app.route('/play')
def play():
	try:
		if spotify_client.currently_playing():
			spotify_client.start_playback(device_id = denon)
		else:
			recents = spotify_client.current_user_recently_played(1)
			last = recents['items'][0]['track']['album']['uri']
			if last:
				spotify_client.start_playback(device_id = denon, context_uri = last)
	except spotipy.client.SpotifyException as e:
		handle_error(e, play)
		return "RETRY\n"
	return "OK\n"

@app.route('/pause')
def pause():
	try:
		spotify_client.pause_playback(denon)
	except spotipy.client.SpotifyException as e:
		handle_error(e, pause)
		return "RETRY\n"
	return "OK\n"

@app.route('/previous')
def previous_track():
	try:
		spotify_client.previous_track(denon)
	except spotipy.client.SpotifyException as e:
		handle_error(e, previous_track)
		return "RETRY\n"
	return "OK\n"

@app.route('/next')
def next_track():
	try:
		spotify_client.next_track(denon)
	except spotipy.client.SpotifyException as e:
		handle_error(e, next_track)
		return "RETRY\n"
	return "OK\n"

@app.route('/on')
def power_on():
	try:
		spotify_client.transfer_playback( getChromecast(), False )
	except spotipy.client.SpotifyException as e:
		handle_error(e, power_on)
		return "RETRY\n"
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
def devices():
	try:
		return jsonify(spotify_client.devices())
	except spotipy.client.SpotifyException as e:
		handle_error(e, devices)
		return "RETRY\n"

@app.route('/now')
def now():
	try:
		playing =  spotify_client.currently_playing()
		if playing:
			return jsonify(playing['item'])
		else:
			return "NONE\n"
	except spotipy.client.SpotifyException as e:
		handle_error(e, now)
		return "RETRY\n"
		
@app.route('/recent')
def recent():
	try:
		result = []
		for item in spotify_client.current_user_recently_played()['items']:
			result.append(item['track']['album']['external_urls']['spotify'])
		return jsonify(result)
	except spotipy.client.SpotifyException as e:
		handle_error(e, recent)
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

# ================================================================================================================ INITIALIZE

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
	
# ================================================================================================================ START
try:
	app.run(host='127.0.0.1', port=9999, debug=False, threaded=False)
except KeyboardInterrupt as e:
	pass