# ¡¡ Spotify introduced an additional captcha at login which causes the LOGIN part of the script to fail !! 

## Spotify Chromecast control using a Universal Remote 


Chromecasts are not controllable using an IR remote control. This projects adds that function by using a raspberry pi with an IR sensor that receives the remote cotrol codes and converts them into http calls.


#### Based on  https://developers.caffeina.com/reverse-engineering-spotify-and-chromecast-protocols-to-let-my-vocal-assistant-play-music-ada4767efa2

#### Dependencies:

download and install latest version of `spotipy` and `pychromecast` python3 
Using `sudo easy_install3 ...` doesn't work as it retrieves an older version. (why?)

#### Spotify App

Login to the `https://developer.spotify.com` and create a new application. Remember `client_id`, `client_secret` and `redirect_uri`.

- copy `remote.py` and `config.py` to /spotify.google/ (or other folder) then make it executable

- update `config.py` with all the required credentials:

```
#name of the chromecast device
chromecast = "your_chromecast_name"
chromecast_ip = "x.x.x.x"
volume = 0.8

#spotify_client credentials 
accounts = {"default":{"username":"", "password":""}}

#Application
client_id = "as_created_above"
client_secret = "as_created_above"
redirect_uri = "as_created_above"
```

- give your account a short name and you is later in the `login` url. ex: `accounts = {"john":{"username":"john_spotify@gmail.com", "password":"73847893497389478389479374892398"}}` becomes `http://127.0.0.1:9999/login/john`

> The system loggs in to the last used account or to account `"default"` (if present), if no user is logged in yet. (calling `http://127.0.0.1:9999/login` is equivalent to calling `http://127.0.0.1:9999/login/default` if a `default` user has been provided)

- run it once from terminal and follow instructions to activate/authorize Spotify.

#### Service

- create `/lib/systemd/system/spotify.service` with content:

```
[Unit]
Description=Spotify Remote
After=network.target auditd.service

[Service]
ExecStart=/usr/bin/python3 /spotify.google/remote.py
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure

[Install]
WantedBy=multi-user.target
Alias=spotify.service
```

- start service
```
sudo systemctl enable spotify
sudo systemctl start spotify
```


#### IR Receiver

The command map file for `lirc` (`/etc/lirc/lircrc`):

```
begin
prog = irexec
button = SPOTIFY_PLAY
config = curl http://127.0.0.1:9999/play
end
begin
prog = irexec
button = SPOTIFY_PAUSE
config = curl http://127.0.0.1:9999/pause
end
begin
prog = irexec
button = SPOTIFY_PREVIOUS
config = curl http://127.0.0.1:9999/previous
end
begin
prog = irexec
button = SPOTIFY_NEXT
config = curl http://127.0.0.1:9999/next
end
begin
prog = irexec
button = SPOTIFY_ON
config = curl http://127.0.0.1:9999/login/john
end
begin
prog = irexec
button = SPOTIFY_OFF
config = curl http://127.0.0.1:9999/off
end
begin
prog = irexec
button = SPOTIFY_REBOOT
config = curl http://127.0.0.1:9999/reboot
end
```

Where `SPOTIFY_*` buttons in the `lircd.conf` file recorded (`irrecord --disable-namespace -d /dev/lirc0  /etc/lirc/lircd.conf`) or random created codes and then taught to the remote (see https://github.com/MoonshineSG/remote.ir) 

#### Remote control

Setup a new device and a new activity, thne configure the buttons as usual.

### Donate

Accepting [beer tips](https://paypal.me/ovidiuhossu)...

