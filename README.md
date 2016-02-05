# wifibully
Gain exclusive access to Wi-Fi networks by deauthenticating all other clients on the network.

This project was inspired by the frustration of captive portals causing bottlenecks on the public wifi network provided by a certain Irish train company. Running wifibully will deauthenticate all other clients from the network, so you can complete the captive portal and get wifi access without the browser timing out. In heavily congested (public) networks, it can also be used to improve bandwidth.

## Usage
`python wifibully.py -i [Interface] -e [ESSID] -w [Whitelist]`

e.g:
`python wifibully.py -i wlan0 -e public-wifi -w <my mac address>`
This will deathenticate every client on the network `public-wifi`, except those specified in the whitelist.

## Dependencies
wifibully uses the [aircrack](http://www.aircrack-ng.org/) suite. It can be installed by running `apt-get install aircrack-ng`.
