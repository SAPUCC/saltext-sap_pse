"""
SaltStack extension for sapgenpse
Copyright (C) 2022 SAP UCC Magdeburg

sapgenpse state module
======================
SaltStack module that implements states based on sapgenpse functionality.

:codeauthor:    Benjamin Wegener, Alexander Wilke
:maturity:      new
:depends:       N/A
:platform:      Linux

This module implements states that utilize sapgenpse functionality and manages SAP PSEs (Personal Security Environment).

.. note::
    This module can only run on linux platforms.
"""
import logging
import pprint
from datetime import datetime


# Globals
log = logging.getLogger(__name__)

__virtualname__ = "sap_pse"


def __virtual__():
    return __virtualname__


# pylint: disable=invalid-name
def managed(
    name,
    user=None,
    group=None,
    seclogons=None,
    pin=None,
    priv_key=None,
    priv_key_pw=None,
    pub_key=None,
    trusted_certs=None,
    backup=False,
    add_ca_bundle=True,
    dn=None,
    **kwargs,
):
    """
    Create or manage a SAP PSE keystore based on a public / private key pair. If not
    public / private key pair is given, a PSE with the given DN is managed.

    name
        The path to the pse file.

    user
        User to run all commands, e.g. sidadm. If not provided, will default to the either the
        owner of the PSE file or to user that runs the salt minion.

    group
        Group under which all commands are run.

    seclogons:
        List of users to store SSO credentials for. Empyty by default.

    pin
        The pin of the keystore.

    priv_key
        Private key file, e.g. be ``/etc/pki/{{ __grains__["id"] }}.key``

    priv_key_pw
        Private key password, default is None

    pub_key
        Public key file, e.g. be ``/etc/pki/{{ __grains__["id"] }}.crt``

    trusted_certs
        List of trusted certificates that should be added to the PSE.

    backup
        Set to True if a backup of an existing file should be made.

    add_ca_bundle
        Set to False if the VMs CA bundle should **not** be added to the PSE during creation.

    dn
        Distinguished Name of the PSE.

    The intended use of this state is to take a previously signed X.509 keypair and create a PSE
    based on the these files. The PSE can then be consumed by other applications (e.g. Host Agent,
    HANA, NetWeaver etc.).

    .. note::
        Remember to inform the application of changes to the PSE (re-/created)!

    Example:

    .. code-block:: jinja

        SAP Host Agent PSE is managed:
          sap_pse.managed:
            - name: /usr/sap/hostctrl/exe/sec/SAPSSLS.pse
            - user: sapadm
            - group: sapsys
            - seclogons:
              - sapadm
            - pin: __slot__:salt:vault.read_secret(path="certstores/pse", key="/usr/sap/hostctrl/exe/sec/SAPSSLS.pse")
            - priv_key: /etc/pki/{{ grains["id"] }}.key
            - pub_key: /etc/pki/{{ grains["id"] }}.crt
            - backup: True
    """  # pylint: disable=line-too-long
    log.debug("Running function")
    ret = {"name": name, "changes": {"old": [], "new": []}, "comment": "", "result": True}
    if not seclogons:
        seclogons = []
    if not trusted_certs:
        trusted_certs = []

    create_from_x509 = True
    if not priv_key or not pub_key:
        if not dn:
            msg = "Either public / private key pair or DN must be given"
            log.error(f"{msg}")
            ret["comment"] = msg
            ret["result"] = False
            return ret
        log.info("Public / private key not given, creating new PSE")
        create_from_x509 = False

    log.debug("Checking if PSE file exists")
    create_pse = False
    if not __salt__["file.file_exists"](path=name):
        log.debug(f"PSE file {name} does not exist, creating from {pub_key}/{priv_key}")
        create_pse = True
        if not user:
            user = __grains__["username"]
            log.debug(f"PSE owner set to {user}")
        if not group:
            group = __grains__["groupname"]
            log.debug(f"PSE owner group set to {group}")
    else:
        log.debug(f"PSE file {name} does already exist, checking validity")
        pse_owner = __salt__["file.get_user"](name)
        pse_owner_group = __salt__["file.get_group"](name)
        if not user:
            user = pse_owner
            log.debug(f"PSE owner set to {user}")
        if not group:
            group = pse_owner_group
            log.debug(f"PSE owner group set to {group}")
        if user != pse_owner or group != pse_owner_group:
            log.debug(f"Setting PSE owner to {user}:{group}")
            result = __states__["file.managed"](name=name, user=user, group=group)
            log.debug(f"Output of file.managed:\n{result}")
            if not isinstance(result, dict) or "result" not in result or not result["result"]:
                ret["result"] = False
                ret["comment"] = f"Could not change PSE ownership to {user}"
                return ret

        certs_are_equal = True
        result = __salt__["sap_pse.get_my_name"](name, pse_pwd=pin, runas=user, groupas=group)
        if not isinstance(result, dict):
            msg = f"Cannot read PSE file {name}"
            log.error(f"{msg}")
            ret["result"] = False
            ret["comment"] = msg
            return ret
        if not result:
            log.info("Cannot read PSE file, creating new one")
            certs_are_equal = False
        else:
            public_cert_pse = result["MY Certificate"]  # this is the default name given by SAP
            log.debug(f"Public certificate PSE:\n{pprint.pformat(public_cert_pse)}")

            if create_from_x509:
                log.debug("Checking if certificate of the PSE matches the X509 file")
                public_cert_x509 = __salt__["x509.read_certificate"](pub_key)
                log.debug(f"Public certificate X509:\n{pprint.pformat(public_cert_x509)}")

                log.debug("Converting datetime strings for comparison")
                # Info: All data retrieved should be in UTC

                not_after_x509 = datetime.strptime(
                    public_cert_x509["Not After"], "%Y-%m-%d %H:%M:%S"
                )
                pse_not_after = public_cert_pse["Validity not after"].split("(", 1)[0].strip()
                not_after_pse = datetime.strptime(pse_not_after, "%a %b %d %H:%M:%S %Y")

                not_before_x509 = datetime.strptime(
                    public_cert_x509["Not Before"], "%Y-%m-%d %H:%M:%S"
                )
                pse_not_before = public_cert_pse["Validity not before"].split("(", 1)[0].strip()
                not_before_pse = datetime.strptime(pse_not_before, "%a %b %d %H:%M:%S %Y")

                log.debug("Comparing certificate attributes")
                if public_cert_x509["Serial Number"] != public_cert_pse["Serial Number"]:
                    msg = (
                        f"Serial numbers of PSE ({public_cert_pse['Serial Number']}) and X509 "
                        f"({public_cert_x509['Serial Number']}) do not match"
                    )
                    log.debug(msg)
                    certs_are_equal = False
                elif (
                    public_cert_x509["SHA-256 Finger Print"]
                    != public_cert_pse["Certificate fingerprint (SHA256)"]
                ):
                    msg = (
                        f"SHA-256 finger prints of PSE ({public_cert_pse['Certificate fingerprint (SHA256)']}) "
                        f"and X509 ({public_cert_x509['SHA-256 Finger Print']}) do not match"
                    )
                    log.debug(msg)
                    certs_are_equal = False
                elif abs((not_after_x509 - not_after_pse).total_seconds()) > 0:
                    log.debug(
                        f"Not after datetimes of PSE ({not_after_pse}) and X509 ({not_after_x509}) do not match"
                    )
                    diff_sec = abs((not_after_x509 - not_after_pse).total_seconds())
                    log.debug(f"Difference between PSE <> X509: {diff_sec} seconds")
                    certs_are_equal = False
                elif abs((not_before_x509 - not_before_pse).total_seconds()) > 0:
                    log.debug(
                        f"Not before datetimes of PSE ({not_before_pse}) and X509 ({not_before_x509}) do not match"
                    )
                    diff_sec = abs((not_before_x509 - not_before_pse).total_seconds())
                    log.debug(f"Difference between PSE <> X509: {diff_sec} seconds")
                    certs_are_equal = False
            else:
                log.debug("Checking if DN of the PSE matches the target")
                if dn != public_cert_pse["Subject"]:
                    log.debug(f"DN of PSE ({public_cert_pse['Subject']}) does not match ({dn})")
                    certs_are_equal = False

        if not certs_are_equal:
            log.debug("Certificates do not match")
            if seclogons:
                success, result = __salt__["sap_pse.seclogin_contains"](
                    pse_file=name, pse_pwd=pin, runas=user, groupas=group, user=user
                )
                if not success:
                    msg = f"Could not retrieve seclogon status for user {user}"
                    log.error(f"{msg}")
                    ret["result"] = False
                    ret["comment"] = msg
                    return ret
                if result:
                    log.debug(f"Removing credentials of PSE {name}")
                    if __opts__["test"]:
                        ret["changes"]["new"].append(
                            f"Would removed seclogins from PSE file {name}"
                        )
                    else:
                        result = __salt__["sap_pse.seclogin_delete"](
                            pse_file=name, pse_pwd=pin, runas=user
                        )
                        if not isinstance(result, bool) or not result:
                            log.error(f"Could not delete SSO credentials for {name}:\n{result}")
                            ret["result"] = False
                            ret["comment"] = f"Could not delete SSO credentials for {name}"
                            return ret
                        ret["changes"]["new"].append(f"Removed seclogins from PSE file {name}")
            if backup:
                datetime_now_str = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
                dest_name = f"{name}_{datetime_now_str}.bak"
                log.debug(f"Renaming PSE to {dest_name}")
                if __opts__["test"]:
                    ret["changes"]["new"].append(f"Would rename PSE file {name} to {dest_name}")
                else:
                    result = __salt__["file.rename"](src=name, dst=dest_name)
                    if not result:
                        log.error(f"Could not rename PSE file {name} to {dest_name}")
                        raise Exception(f"Could not rename PSE file {name} to {dest_name}")
                    ret["changes"]["new"].append(f"Renamed PSE file {name} to {dest_name}")
            else:
                log.debug(f"Removing {name}")
                if __opts__["test"]:
                    ret["changes"]["new"].append(f"Would remove PSE file {name}")
                else:
                    __salt__["file.remove"](path=name)
                    ret["changes"]["new"].append(f"Removed PSE file {name}")
            create_pse = True
        else:
            log.debug("PSE matches the X509 file")

    if create_pse:
        log.debug(f"Creating PSE {name}")
        if create_from_x509:
            if __opts__["test"]:
                ret["changes"]["new"].append(f"Would create PSE file {name}")
            else:
                result = __salt__["sap_pse.import_p8"](
                    pse_file=name,
                    pub_key=pub_key,
                    priv_key=priv_key,
                    priv_key_pw=priv_key_pw,
                    pse_pwd=pin,
                    runas=user,
                    groupas=group,
                    add_ca_bundle=add_ca_bundle,
                    **kwargs,
                )
                if not result:
                    log.error(f"Could not create PSE file {name} from {pub_key} and {priv_key}")
                    ret[
                        "comment"
                    ] = f"Could not create PSE file {name} from {pub_key} and {priv_key}"
                    ret["result"] = False
                    return ret
                else:
                    ret["changes"]["new"].append(f"Created PSE file {name}")
        else:
            if __opts__["test"]:
                ret["changes"]["new"].append(f"Would create PSE file {name}")
            else:
                result = __salt__["sap_pse.gen_pse"](
                    pse_file=name,
                    dn=dn,
                    pse_pwd=pin,
                    runas=user,
                    groupas=group,
                    add_ca_bundle=add_ca_bundle,
                    **kwargs,
                )
                if not result:
                    log.error(f"Could not create PSE file {name}")
                    ret["comment"] = f"Could not create PSE file {name}"
                    ret["result"] = False
                    return ret
                else:
                    ret["changes"]["new"].append(f"Created PSE file {name}")

    if trusted_certs:
        log.debug("Checking if trusted certs are present in the PSE")
        if __opts__["test"]:
            # because the PSE file may not exist at this point, we cannot get a diff
            ret["changes"]["new"].append("Would maintain list of trusted certificates")
        else:
            pse_certs = __salt__["sap_pse.maintain_pk_list"](
                pse_file=name, pse_pwd=pin, runas=user, grouas=group
            )
            for trusted_cert in trusted_certs:
                log.debug(f"Processing trusted certificate {trusted_cert}")
                try:
                    tc_data = __salt__["x509.read_certificate"](trusted_cert)
                except Exception:  # pylint: disable=broad-except
                    # possible exceptions unclear
                    minion_id = __grains__["id"]  # f-strings cannot evaluate the dunder dicts
                    msg = f"Trusted certificate {trusted_cert} does not exist on {minion_id} and cannot be added"
                    log.error(f"{msg}")
                    ret["result"] = False
                    ret["comment"] = msg
                    return ret
                tc_imported = False
                log.debug(f"Checking for finger print {tc_data['SHA-256 Finger Print']}")
                for pse_cert in pse_certs:
                    log.debug(
                        f"Checking existing cert #{pse_cert['number']} '{pse_cert['Subject']}'"
                    )
                    if (
                        pse_cert["Certificate fingerprint (SHA256)"]
                        == tc_data["SHA-256 Finger Print"]
                    ):
                        log.debug(
                            f"Trusted certificate {trusted_cert} is already imported into the PSE"
                        )
                        tc_imported = True
                        break
                    else:
                        log.debug(
                            f"PSE fingerprint {pse_cert['Certificate fingerprint (SHA256)']} doesn't match"
                        )
                if not tc_imported:
                    log.debug(f"Importing trusted certificate {trusted_cert} into the PSE")
                    success = __salt__["sap_pse.maintain_pk_add"](
                        pse_file=name, pse_pwd=pin, runas=user, groupas=group, certs=[trusted_cert]
                    )
                    if not success:
                        msg = f"Could not import certificate {trusted_cert} into the PSE"
                        log.error(f"{msg}")
                        ret["result"] = False
                        ret["comment"] = msg
                        return ret
                    else:
                        msg = f"Imported certificate {trusted_cert} into PSE file {name}"
                        log.debug(f"{msg}")
                        ret["changes"]["new"].append(msg)

    if seclogons:
        log.debug("Checking if seclogons are set correctly")
        for sl_user in seclogons:
            if __opts__["test"]:
                # because the PSE file may not exist at this point, we cannot get a diff
                ret["changes"]["new"].append(f"Would maintain seclogon for {sl_user}")
            else:
                success, result = __salt__["sap_pse.seclogin_contains"](
                    pse_file=name, pse_pwd=pin, runas=user, groupas=group, user=sl_user
                )
                if not success:
                    msg = f"Could not retrieve seclogon status for user {sl_user}"
                    log.error(f"{msg}")
                    ret["result"] = False
                    ret["comment"] = msg
                    return ret
                if not result:
                    result = __salt__["sap_pse.seclogin_add"](
                        pse_file=name, pse_pwd=pin, runas=user, groupas=group, user=sl_user
                    )
                    if not isinstance(result, bool) or not result:
                        msg = f"Could not add user {sl_user} to seclogon of PSE"
                        log.error(f"{msg}")
                        ret["result"] = False
                        ret["comment"] = msg
                        return ret
                    else:
                        msg = f"Added SSO credentials for user {sl_user} to PSE file {name}"
                        log.debug(f"{msg}")
                        ret["changes"]["new"].append(msg)

    if not ret["changes"]["new"]:
        ret["comment"] = "No changes required"
        del ret["changes"]["new"]
    else:
        ret["comment"] = f"Adapted PSE file {name}"
    log.debug("Returning")
    if not ret["changes"]["old"]:
        del ret["changes"]["old"]
    ret["result"] = True if (not __opts__["test"] or not ret["changes"]) else None
    return ret


# pylint: disable=unused-argument
def absent(name, secudir=None, user=None, pin=None, **kwargs):
    """
    Ensure that a PSE is absent from the system.

    name
        Name of the PSE file.

    secudir
        SECUDIR variable, required to determine location of cred_v2 SSO credential files.

    user
        User to run the command with.

    pin
        The pin of the keystore.
    """
    log.debug("Running function")
    ret = {"name": name, "changes": {"old": [], "new": []}, "comment": "", "result": True}

    if not __salt__["file.file_exists"](name):
        if not secudir:
            secudir = name.rsplit("/", 1)[0]
            log.debug(f"Setting SECUDIR to '{secudir}'")
        if not user:
            user = __grains__["username"]
            log.debug(f"Setting user to '{user}'")

    log.debug(f"Removing SSO credentials for {name}")
    success, result = __salt__["sap_pse.seclogin_contains"](
        pse_file=name, pse_pwd=pin, runas=user, user=user
    )
    if not success:
        msg = f"Could not retrieve seclogon status for user {user}"
        log.error(f"{msg}")
        ret["result"] = False
        ret["comment"] = msg
        return ret
    if result:
        if __opts__["test"]:
            ret["changes"]["new"].append(f"Would remove SSO credentials for {name}")
        else:
            result = __salt__["sap_pse.seclogin_delete"](
                name, pse_pwd=pin, secudir=secudir, runas=user
            )
            if not isinstance(result, bool) or not result:
                log.error(f"Could not delete SSO credentials for {name}:\n{result}")
                ret["result"] = False
                ret["comment"] = f"Could not delete SSO credentials for {name}"
                return ret
            ret["changes"]["new"].append(f"Removed SSO credentials for {name}")
    else:
        log.debug("No SSO credentials to delete")

    log.debug(f"Removing file {name}")
    result = __states__["file.absent"](name)
    if not isinstance(result, dict) or "result" not in result or not result["result"]:
        log.error(f"Could not run file.absent for {name}:\n{result}")
        ret["result"] = False
        ret["comment"] = f"Could not run file.absent for {name}"
        return ret
    log.debug(f"Result of file.absent:\n{result}")
    if result["changes"]:
        ret["changes"]["new"].append(result["comment"])

    if not ret["changes"]["new"]:
        ret["comment"] = "No changes required"
        del ret["changes"]["new"]
    else:
        ret["comment"] = f"Adapted PSE file {name}"
    log.debug("Returning")
    if not ret["changes"]["old"]:
        del ret["changes"]["old"]
    ret["result"] = True if (not __opts__["test"] or not ret["changes"]) else None
    return ret
