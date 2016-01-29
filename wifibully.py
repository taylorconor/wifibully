#!/usr/bin/python

from parse_args import parse_args
import csv
import re

args = None

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

if __name__ == "__main__":
	args = parse_args()
	print get_clients("/Users/Conor/Desktop/output-01.csv")