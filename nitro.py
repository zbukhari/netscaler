#!/usr/bin/env python2

# Programmer: Zahid Bukhari
# Date: Thu Apr 21 14:58:58 CDT 2016
# Purpose: To assist with Netscaler VIP creation and more in time.
# Requires nitro-python build 63.16 (because of certvalidate = False)

import logging
logging.basicConfig(level=logging.DEBUG,format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s')

import argparse
import sys
from getpass import getpass
from nssrc.com.citrix.netscaler.nitro.exception.nitro_exception import nitro_exception
# To connect
from nssrc.com.citrix.netscaler.nitro.service.nitro_service import nitro_service
# To manipulate lbserver (currently simple add / delete)
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver import lbvserver

# Basic configs
# To manipulate server (currently simple add / delete)
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.server import server
# To manipulate servicegroup (currently simple add / delete)
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.servicegroup import servicegroup

# To bind server to servicegroup (currently simple add / delete)
# servicegroup would work but if someone peeks through documentation, this is an easier pill to digest.
# To bind lbmonitor to servicegroup (currently simple add / delete)
# lbmonitor_servicegroup_binding
# Bindings
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver_servicegroup_binding import lbvserver_servicegroup_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbmonitor_servicegroup_binding import lbmonitor_servicegroup_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.servicegroup_servicegroupmember_binding import servicegroup_servicegroupmember_binding
# from nssrc.com.citrix.netscaler.nitro.resource.config.basic.servicegroup_lbmonitor_binding import servicegroup_lbmonitor_binding

import socket

# Remove this as soon as we have legit signed certs
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Logging (yes it usually is the last thing we think of bwahahaha)
# import logging
# logging.basicConfig(format=%(fasd), level=logging.DEBUG)

# Common steps for creating a LB VIP
# 1. add lb vserver (i.e. add lb vserver VSERVER_NAME SERVICE_TYPE VSERVER_IP VSERVER_PORT ... specifics)
# 2. add server (i.e. add server SERVER_FQDN SERVER_IP)
# 3. add serviceGroup
# 4. bind servers to serviceGroup
# 5. bind serviceGroup -monitorName MONITOR_NAME
# 6. bind serviceGroup to lbvserver (i.e. bind serviceGroup VSERVER_NAME SERVER_FQDN PORT)

# To-do: Create bottled options which we can use with more ease

class Netscaler:
	'''Creates an object instance to perform common Netscaler tasks.'''
	_sess = None

	# @@@ Working @@@
	def __init__(self, ns, username, password):
		'''Initializes a session and stores it as self._sess for future use for all other functions.
		
		@param ns - Netscaler IP or FQDN
		@param username
		@param password
		'''

		#Create an instance of the nitro_service class to connect to the appliance
		self._sess = nitro_service(ns, 'HTTPS')
		self._sess.certvalidation = False # docs say false but that'd fail
		# self._sess.hostnameverification = False # debating

		self._sess.set_credential(username, password)
		# For bulk operations we want to rollback
		self._sess.onerror = 'ROLLBACK'
		self._sess.timeout = 1800 # Default but it doesn't get set so we do it explicitly

		try:
			self._sess.login()
		except nitro_exception as e:
			print('Exception::errorcode=' + str(e.errorcode) + ',message=' + e.message)
		except Exception as e:
			print('Exception::message=' + str(e.args))
		return

	# Working @@@ - add docstring
	def getList(self, msg = None):
		
		myList = []
		while True:
			try:
				x = raw_input('%s.  Ctrl + D to break: ' % msg)
			except EOFError, e:
				break
			else:
				myList.append(x)

		return myList

	# add serviceGroup TMS-t.mplxtms.com-HTTP HTTP -maxClient 0 -maxReq 0 -cip DISABLED -usip NO -useproxyport YES -cltTimeout 180 -svrTimeout 360 -CKA NO -TCPB NO -CMP NO -appflowLog DISABLED
	# Working @@@ Verify defaults above
	def servicegroup(self, action, name, svc_type):
		'''Function to add or remove a service group.

	@param action string: add or delete.
	@param name string: describing the service group.
	@param svc_type string: HTTP, FTP, TCP, UDP, SSL, SSL_BRIDGE, SSL_TCP,
		DTLS, NNTP, RPCSVR, DNS, ADNS, SNMP, RTSP, DHCPRA, ANY,
		SIP_UDP, SIP_TCP, SIP_SSL, DNS_TCP, ADNS_TCP, MYSQL, MSSQL,
		ORACLE, RADIUS, RADIUSListener, RDP, DIAMETER, SSL_DIAMETER,
		TFTP, SMPP, PPTP, GRE, SYSLOGTCP, SYSLOGUDP
'''

		if not self._sess and args != None:
			self.__init__(args.netscaler, args.username, args.password)

		obj = servicegroup()
		obj.servicegroupname = name
		obj.servicetype = svc_type

		try:
			if action == 'add':
				servicegroup.add(self._sess, obj)
			elif action == 'delete':
				servicegroup.delete(self._sess, obj)
		except nitro_exception as e:
			print('Exception::errorcode=' + str(e.errorcode) + ',message=' + e.message)
		except Exception as e:
			print('Exception::message=' + str(e.args))
		else:
			return True

		return False

	# Working
	def servicegroup_servicegroupmember_binding(self, action, fqdns, port, svcGrp):
		'''Function to bind (add) or unbind (delete) server(s) to a servicegroup.

	@param action string: add or delete
	@param fqdns list: list of FQDNs
	@param port int: Destination port for server
	@param svcGrp string: name of service group to bind servers with services to.
'''

		listOfObjs = []

		try:
			for i in range(len(fqdns)):
				listOfObjs.append(servicegroup_servicegroupmember_binding())
				listOfObjs[i].servicegroupname = svcGrp
				listOfObjs[i].servername = fqdns[i]
				listOfObjs[i].port = port

			if action == 'add':
				servicegroup_servicegroupmember_binding.add(self._sess, listOfObjs)
			elif action == 'delete':
				servicegroup_servicegroupmember_binding.delete(self._sess, listOfObjs)
		except nitro_exception as e:
			print('Exception::errorcode=' + str(e.errorcode) + ',message=' + e.message)
		except Exception as e:
			print('Exception::message=' + str(e.args))
		else:
			return True

		return False

# lbmonitor function to create custom monitors
# def lbmonitor(self, action, name, mon_type (str), respcode (str), 
#	 '''Function to add or remove a custom lbmonitor.
# 
#	 @param action string: add or delete
#	 @param name string: name for the custom lbmonitor
#	 @param mon_type string: PING, TCP, HTTP, TCP-ECV, HTTP-ECV, UDP-ECV,
#		 DNS, FTP, LDNS-PING, LDNS-TCP, LDNS-DNS, RADIUS, USER,
#		 HTTP-INLINE, SIP-UDP, SIP-TCP, LOAD, FTP-EXTENDED, SMTP, SNMP,
#		 NNTP, MYSQL, MYSQL-ECV, MSSQL-ECV, ORACLE-ECV, LDAP, POP3,
#		 CITRIX-XML-SERVICE, CITRIX-WEB-INTERFACE, DNS-TCP, RTSP, ARP,
#		 CITRIX-AG, CITRIX-AAC-LOGINPAGE, CITRIX-AAC-LAS, CITRIX-XD-DDC,
#		 ND6, CITRIX-WI-EXTENDED, DIAMETER, RADIUS_ACCOUNTING,
#		 STOREFRONT, APPC, SMPP, CITRIX-XNC-ECV, CITRIX-XDM
#	 @param mon_action string: NONE, LOG, DOWN
#	 @param respcode string: Can be an integer or a hyphenated integer range.
#	 @param httprequest string: For example 'GET /server-status'

	def lbmonitor_servicegroup_binding(self, action, monitorname, servicegroupname):
		'''Function to add lbmonitor to a servicegroup.

	@param action string: add or delete
	@param monitorname string: PING, TCP, HTTP, TCP-ECV, HTTP-ECV, UDP-ECV,
		DNS, FTP, LDNS-PING, LDNS-TCP, LDNS-DNS, RADIUS, USER,
		HTTP-INLINE, SIP-UDP, SIP-TCP, LOAD, FTP-EXTENDED, SMTP, SNMP,
		NNTP, MYSQL, MYSQL-ECV, MSSQL-ECV, ORACLE-ECV, LDAP, POP3,
		CITRIX-XML-SERVICE, CITRIX-WEB-INTERFACE, DNS-TCP, RTSP, ARP,
		CITRIX-AG, CITRIX-AAC-LOGINPAGE, CITRIX-AAC-LAS, CITRIX-XD-DDC,
		ND6, CITRIX-WI-EXTENDED, DIAMETER, RADIUS_ACCOUNTING,
		STOREFRONT, APPC, SMPP, CITRIX-XNC-ECV, CITRIX-XDM
	@param servicegroupname string: Name of service group
'''

		obj = lbmonitor_servicegroup_binding()
		obj.monitorname = monitorname.upper()
		obj.servicegroupname = servicegroupname

		try:
			if action == 'add':
				lbmonitor_servicegroup_binding.add(self._sess, obj)
			elif action == 'delete':
				lbmonitor_servicegroup_binding.delete(self._sess, obj)
		except nitro_exception as e:
			print('Exception::errorcode=' + str(e.errorcode) + ',message=' + e.message)
		except Exception as e:
			print('Exception::message=' + str(e.args))
		else:
			return True

		return False

# 	# @@@@ Not working - this is probably used for custom lbmonitors - not sure
# 	def servicegroup_lbmonitor_binding(self, action, service_group_name, monitor_name, port = False):
# 		'''Function to add lbmonitor to a servicegroup.
# 
# 	@param service_group_name string: Name of service group
# 	@param port integer: Port number for service
# 	@param monitor_name string: Name to give this monitor
# '''
# 
# 		try:
# 			obj = servicegroup_lbmonitor_binding()
# 			obj.servicegroupname = service_group_name
# 			obj.monitor_name = monitor_name
# 			if port:
# 				obj.port = port
# 
# 			if action == 'add':
# 				servicegroup_lbmonitor_binding.add(self._sess, obj)
# 			elif action == 'delete':
# 				servicegroup_lbmonitor_binding.delete(self._sess, obj)
# 		except nitro_exception as e:
# 			print('Exception::errorcode=' + str(e.errorcode) + ',message=' + e.message)
# 		except Exception as e:
# 			print('Exception::message=' + str(e.args))
# 		else:
# 			return True
# 
# 		return False

	# @@@ Working @@@
	def server(self, action, fqdns):
		'''Function to add or remove server(s) from the Netscaler.

	@param action string: add or delete
	@param fqdns list: list of strings representing FQDNs
'''

		listOfObjs = []

		# First we're going to try to ensure all is in order
		for i in range(len(fqdns)):
			try:
				listOfObjs.append(server())
				listOfObjs[i].name = fqdns[i]
				listOfObjs[i].ipaddress = socket.gethostbyname(fqdns[i])
			except socket.gaierror, e:
				print 'Unable to resolve %s to an IPv4 address' % fqdns[i]
				return False
			else:
				i += 1

		# Now we do the actual command
		try:
			if action == 'add':
				server.add(self._sess, listOfObjs)
			elif action == 'delete':
				server.delete(self._sess, listOfObjs)
		except nitro_exception as e:
			print('Exception::errorcode=' + str(e.errorcode) + ',message=' + e.message)
		except Exception as e:
			print('Exception::message=' + str(e.args))
		else:
			return True

		return False

	# @@@ TEST
	def save_config(self):
		'''This method will save the running config to the netscaler.'''

		try:
			self._sess.save_config()
		except nitro_exception as e:
			print('Exception::errorcode=' + str(e.errorcode) + ',message=' + e.message)
		except Exception as e:
			print('Exception::message=' + str(e.args))
		else:
			return True

		return False

	# @@@ Working - Unfortunately it's built to also end python execution.
	def logout(self):
		'''Function to log out of the Netscaler.'''

		try:
			self._sess.logout()
			print 'Good bye!'
			sys.exit(0)
		except nitro_exception as e:
			print('Exception::errorcode=' + str(e.errorcode) + ',message=' + e.message)
		except Exception as e:
			print('Exception::message=' + str(e.args))
		else:
			return True

		return False

	def lbvserver(self, action, name, ipv46, servicetype, port, lbmethod):
		'''This function is interactive and will allow one to add a load-balancing
virtual server.

	param @action string add or delete (delete only requires the name)
	param @name string specifying the name of the virtual server
	param @ipv46 string representation of an IPv4 or IPv6 address
	param @servicetype string: HTTP, FTP, TCP, UDP, SSL, SSL_BRIDGE,
		SSL_TCP, NNTP, DNS, DHCPRA, ANY, SIP_UDP, DNS_TCP, RTSP.
	param @port - integer representing port for this service.
	param @lbmethod string: ROUNDROBIN, LEASTCONNECTION,
		LEASTRESPONSETIME, URLHASH, DOMAINHASH, DESTINATIONIPHASH,
		SOURCEIPHASH, SRCIPDESTIPHASH, LEASTBANDWIDTH, LEASTPACKETS,
		TOKEN, SRCIPDESTIPHASH, CUSTOMLOAD
'''

		# Enable the load balancing feature.
		try:
			features_to_be_enabled = "lb"
			self._sess.enable_features(features_to_be_enabled) # Check into this @@@

			# Create an instance of the virtual server class
			obj = lbvserver()
			# Prepare the variables
			obj.name = name
			obj.ipv46 = ipv46
			obj.servicetype = servicetype
			obj.port = port
			obj.lbmethod = lbmethod

			if action == 'add':
				lbvserver.add(self._sess, obj)
			elif action == 'delete':
				lbvserver.delete(self._sess, obj)
		except nitro_exception as e:
			print("Exception::errorcode="+str(e.errorcode)+",message="+ e.message)
		except Exception as e:
			print("Exception::message="+str(e.args))
		else:
			return True

		return False

	def lbvserver_servicegroup_binding(self, action, lbvservername, servicegroupname):
		'''Function to add or remove a servicegroup from an lbvserver.

	@param action string: add or delete
	@param lbvservername string: Name of lbvserver
	@param servicegroupname string: Name of servicegroup name
'''

		obj = lbvserver_servicegroup_binding()
		obj.name = lbvservername
		obj.servicegroupname = servicegroupname

		try:
			if action == 'add':
				lbvserver_servicegroup_binding.add(self._sess, obj)
			elif action == 'delete':
				lbvserver_servicegroup_binding.delete(self._sess, obj)
		except nitro_exception as e:
			print("Exception::errorcode="+str(e.errorcode)+",message="+ e.message)
		except Exception as e:
			print("Exception::message="+str(e.args))
		else:
			return True

		return False

	def backup(self, f):
		'''Creates a backup of the netscaler config to a specified file.'''

		try:
			#Save the configurations
			# self._sess.save_config()
			return False
		except nitro_exception as e:
			print('Exception::errorcode=' + str(e.errorcode) + ',message=' + e.message)
		except Exception as e:
			print('Exception::message=' + str(e.args))
		else:
			return True

		return False

	def interactive(self):
		'''Function to interactively work with the Netscaler.'''

		return False

class argParse:
	_ns = None

	def __init__(self):
		# parser = argparse.ArgumentParser(add_help=False)
		# Create parser objects
		parser = argparse.ArgumentParser(prog='nitro.py')
		group = parser.add_mutually_exclusive_group()
		subparsers = parser.add_subparsers(
			title='subcommands',
			description='Nothing will be done unless you choose an option below.',
			help='Some extra stuff')

		# Required named arguments
		required_args = parser.add_argument_group('required named arguments')

		required_args.add_argument('-u', '--username',
			help='Specify the username which will be used to log in.')

		required_args.add_argument('-n', '--netscaler',
			help='Specify the Netscaler to connect to.')

		group.add_argument('-p', '--password',
			help='Specify the password. Security risk! Password will be visible in process listing!')

		group.add_argument('-f', '--password-file',
			dest='passfile',
			help='File containing password. Safer option')

		parser.add_argument('-b', '--bulk-failure-behavior',
			default='ROLLBACK',
			help='Specify behavior on failure for bulk operations. Note most actions are handled as bulk operations for safety and the default is rollback.')

		parser.add_argument('-i', '--interactive',
			action='store_true', default=False, help='Enter interactive mode (not ready yet)')

		# lbvserver option (function pass done)
		parser_lbvserver = subparsers.add_parser(
			'lbvserver',
			help='Add or delete a load-balancing virtual server')
		parser_lbvserver.add_argument('action', choices=['add','delete'])
		parser_lbvserver.add_argument('name', help='The load-balancing virtual servers name')
		parser_lbvserver.add_argument('ipv46', help='The IP address')
		parser_lbvserver.add_argument('servicetype',
			choices=['HTTP', 'FTP', 'TCP', 'UDP', 'SSL', 'SSL_BRIDGE', 'SSL_TCP', 'NNTP', 'DNS', 'DHCPRA', 'ANY', 'SIP_UDP', 'DNS_TCP', 'RTSP'],
			help='Choose one from the list (i.e. HTTP).')
		parser_lbvserver.add_argument('port', help='Specify a port for the load-balancing virtual server.', type=int)
		parser_lbvserver.add_argument('lbmethod',
			choices=['ROUNDROBIN', 'LEASTCONNECTION', 'LEASTRESPONSETIME', 'URLHASH', 'DOMAINHASH', 'DESTINATIONIPHASH', 'SOURCEIPHASH', 'SRCIPDESTIPHASH', 'LEASTBANDWIDTH', 'LEASTPACKETS', 'TOKEN', 'SRCIPDESTIPHASH', 'CUSTOMLOAD'])
		parser_lbvserver.set_defaults(func=self.lbvserver)

		# server option (function pass done)
		parser_server = subparsers.add_parser(
			'server',
			help='Add or delete servers')
		parser_server.add_argument('action', choices=['add','delete'])
		parser_server.add_argument('fqdns', nargs='+', help = 'A comma delimited list of FQDNs')
		parser_server.set_defaults(func=self.server)

		# servicegroup option (function pass done)
		parser_servicegroup = subparsers.add_parser('servicegroup',
			help='Add or delete a service group')
		parser_servicegroup.add_argument('action',
			choices=['add','delete'],
			help='Choose the action to use.')
		parser_servicegroup.add_argument('name',
			help='The name of the service group')
		parser_servicegroup.add_argument('servicetype',
			choices=['HTTP', 'FTP', 'TCP', 'UDP', 'SSL', 'SSL_BRIDGE', 'SSL_TCP', 'DTLS', 'NNTP', 'RPCSVR', 'DNS', 'ADNS', 'SNMP', 'RTSP', 'DHCPRA', 'ANY', 'SIP_UDP', 'SIP_TCP', 'SIP_SSL', 'DNS_TCP', 'ADNS_TCP', 'MYSQL', 'MSSQL', 'ORACLE', 'RADIUS', 'RADIUSListener', 'RDP', 'DIAMETER', 'SSL_DIAMETER', 'TFTP', 'SMPP', 'PPTP', 'GRE', 'SYSLOGTCP', 'SYSLOGUDP'],
			help='Choose one from the list (e.g. TCP).')
		parser_servicegroup.set_defaults(func=self.servicegroup)

		# servicegroup_servicegroupmember_binding option (function pass done)
		parser_servicegroup_servicegroupmember_binding = subparsers.add_parser('servicegroup_servicegroupmember_binding',
			help='Bind servers to a service group')
		parser_servicegroup_servicegroupmember_binding.add_argument('action',
			choices=['add','delete'],
			help='Choose the action to use.')
		parser_servicegroup_servicegroupmember_binding.add_argument('servicegroup',
			help='Name of service group to bind FQDNs to')
		parser_servicegroup_servicegroupmember_binding.add_argument('port',
			help='Port that service group members will use.',
			type=int)
		parser_servicegroup_servicegroupmember_binding.add_argument('fqdns',
			nargs='+',
			help='List of FQDNs')
		parser_servicegroup_servicegroupmember_binding.set_defaults(func=self.servicegroup_servicegroupmember_binding)

		# lbmonitor_servicegroup_binding option
		parser_lbmonitor_servicegroup_binding = subparsers.add_parser('lbmonitor_servicegroup_binding',
			help='Bind a load balancing monitor to a service group')
		parser_lbmonitor_servicegroup_binding.add_argument('action',
			choices=['add','delete'],
			help='Choose the action to use.')
		parser_lbmonitor_servicegroup_binding.add_argument('monitorname',
			choices=['PING', 'TCP', 'HTTP', 'TCP-ECV', 'HTTP-ECV', 'UDP-ECV', 'DNS', 'FTP', 'LDNS-PING', 'LDNS-TCP', 'LDNS-DNS', 'RADIUS', 'USER', 'HTTP-INLINE', 'SIP-UDP', 'SIP-TCP', 'LOAD', 'FTP-EXTENDED', 'SMTP', 'SNMP', 'NNTP', 'MYSQL', 'MYSQL-ECV', 'MSSQL-ECV', 'ORACLE-ECV', 'LDAP', 'POP3', 'CITRIX-XML-SERVICE', 'CITRIX-WEB-INTERFACE', 'DNS-TCP', 'RTSP', 'ARP', 'CITRIX-AG', 'CITRIX-AAC-LOGINPAGE', 'CITRIX-AAC-LAS', 'CITRIX-XD-DDC', 'ND6', 'CITRIX-WI-EXTENDED', 'DIAMETER', 'RADIUS_ACCOUNTING', 'STOREFRONT', 'APPC', 'SMPP', 'CITRIX-XNC-ECV', 'CITRIX-XDM'],
			help='Choose one from the list (e.g. PING)')
		parser_lbmonitor_servicegroup_binding.add_argument('servicegroupname', help='Name of service group to bind monitor to.')
		parser_lbmonitor_servicegroup_binding.set_defaults(func=self.lbmonitor_servicegroup_binding)

		# lbvserver_servicegroup_binding option
		parser_lbvserver_servicegroup_binding = subparsers.add_parser('lbvserver_servicegroup_binding', help='Bind a service group to a load-balancing virtual server')
		parser_lbvserver_servicegroup_binding.add_argument('action',
			choices=['add','delete'],
			help='Choose the action to use.')
		parser_lbvserver_servicegroup_binding.add_argument('lbvservername', help='Load-balancing virtual server name')
		parser_lbvserver_servicegroup_binding.add_argument('servicegroupname', help='Service group name')
		parser_lbvserver_servicegroup_binding.set_defaults(func=self.lbvserver_servicegroup_binding)

		args = parser.parse_args()

		# If we passed validation above - we probable are good to go
		if args.password:
			password = args.password
		elif args.passfile:
			f = open(args.passfile, 'r')
			password = f.read().strip('\n')
			f.close()

		self._ns = Netscaler(args.netscaler, args.username, password)

		# At this point all arguments are "legit"-ish.  Let's do it!
		args.func(args)

		self._ns.logout()

	def server(self, args):
		if self._ns.server(args.action, args.fqdns):
			print 'Successfully performed ' + args.action + ' for server.'
		else:
			print 'Failed to ' + args.action + ' for server.'

	def servicegroup(self, args):
		if self._ns.servicegroup(args.action, args.name, args.servicetype):
			print 'Successfully performed ' + args.action + ' for servicegroup.'
		else:
			print 'Failed to ' + args.action + ' for servicegroup.'

	def servicegroup_servicegroupmember_binding(self, args):
		if self._ns.servicegroup_servicegroupmember_binding(args.action, args.fqdns, args.port, args.servicegroup):
			print 'Successfully performed ' + args.action + ' for servicegroup_servicegroupmember_binding.'
		else:
			print 'Failed to ' + args.action + ' for servicegroup_servicegroupmember_binding.'

	def lbmonitor_servicegroup_binding(self, args):
		if self._ns.lbmonitor_servicegroup_binding(args.action, args.monitorname, args.servicegroupname):
			print 'Successfully performed ' + args.action + ' for lbmonitor_servicegroup_binding.'
		else:
			print 'Failed to ' + args.action + ' for lbmonitor_servicegroup_binding.'

	def lbvserver(self, args):
		if self._ns.lbvserver(args.action, args.name, args.ipv46, args.servicetype, args.port, args.lbmethod):
			print 'Successfully performed ' + args.action + ' for lbvserver.'
		else:
			print 'Failed to ' + args.action + ' for lbvserver.'

	def lbvserver_servicegroup_binding(self, args):
		if self._ns.lbvserver_servicegroup_binding(args.action, args.lbvservername, args.servicegroupname):
			print 'Successfully performed ' + args.action + ' for lbvserver_servicegroup_binding.'
		else:
			print 'Failed to ' + args.action + ' for lbvserver_servicegroup_binding.'

if __name__ == '__main__':
	logging.info('butter')
	A = argParse()

