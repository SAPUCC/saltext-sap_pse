"""
SaltStack extension for sapgenpse
Copyright (C) 2022 SAP UCC Magdeburg

sapgenpse execution module
==========================
SaltStack execution module that wraps sapgenpse functions.

:codeauthor:    Benjamin Wegener, Alexander Wilke
:maturity:      new
:depends:       yaml
:platform:      Linux

It is assumed that the program ``sapgenpse`` is in the ``PATH`` of the user executing the function.
If not, it is assumed that the SAP Host Agent is installed and that ``/usr/sap/hostctrl/exe/sapgenpse``
can be acessed by the executing user. If the executing user is not provided, the user under which
the salt minion runs is used (usually ``root``).
"""
import logging
import re

import salt.utils.http
import salt.utils.platform
import yaml

# Third Party libs

# Globals
# the following control characters are not allowed in YAML
INVALID_CHARACTERS = [chr(i) for i in range(0x80, 0x9F)]
# default path to sapgenpse
DEFAULT_SAPGENPSE = "/usr/sap/hostctrl/exe/sapgenpse"

log = logging.getLogger(__name__)

__virtualname__ = "sap_pse"


def __virtual__():
    """
    Only work on POSIX-like systems
    """
    if salt.utils.platform.is_windows():
        return False, "This module doesn't work on Windows."
    return __virtualname__


def _which(executable, runas=None):
    """
    Similar to ``salt.utils.path.which()``, but:
     - Only works on Linux
     - Allows runas

    If not runas is given, the salt minion user is used
    """
    ret = __salt__["cmd.run_all"](cmd=f"which {executable}", runas=runas)
    if ret["retcode"]:
        return None
    return ret["stdout"]


def _get_sapgenpse_path(user=None):
    """
    Retrieve the path to sapgenpse.

    .. note::
         Because this depends on the user, we cannot run this in __virtual__().
    """
    # first, try the userspath
    sapgenpse = _which("sapgenpse", runas=user)
    if sapgenpse:
        return sapgenpse
    # if not available, check the default path
    elif __salt__["file.file_exists"](DEFAULT_SAPGENPSE):
        return DEFAULT_SAPGENPSE
    else:
        msg = "No executable sapgenpse could be found"
        log.error(msg)
        raise Exception(msg)


def _remove_invalid_characters(s_string):
    """
    Remove all unprintable characters from a string for yaml loading.
    """
    return "".join(ch for ch in s_string if ch not in INVALID_CHARACTERS)


def _parse_cert_output(lines):
    """
    Parses the ``-vv`` certificate output of sapgenpse
    """
    yaml_data = []
    for line in lines:
        log.trace(f"Processing line '{line.strip()}'")
        if ":" in line:
            # mapping
            key, value = line.split(":", 1)
            if value:
                # quote data if required and remove hashtags from the key -> interpreted as comments
                k_insert = key.replace("#", "_")
                v_insert = value.strip().replace('"', '\\"')
                yaml_line = f'{k_insert}: "{v_insert}"'
            else:
                yaml_line = line.replace("#", "_")
        else:
            # list item
            groups = re.findall(r"( +)(.*)", line)[0]
            groups_0 = groups[0]
            groups_1 = groups[1].replace('"', '\\"')
            yaml_line = f'{groups_0}- "{groups_1}"'
        yaml_data.append(yaml_line)
    data = {}
    try:
        unicode_string = "\n".join(yaml_data)
        old_l = len(unicode_string)
        unicode_string = _remove_invalid_characters(unicode_string)
        if old_l != len(unicode_string):
            msg = (
                "Invalid unicode control characters found in certificate output. "
                "Because these cannot be part of YAML, they will be stripped!"
            )
            log.warning(msg)
        data = yaml.safe_load(unicode_string)
    except Exception:
        yaml_str = "\n".join(yaml_data)
        log.error(f"Got an error when trying to parse the following yaml data:\n{yaml_str}")
        raise
    return data


# pylint: disable=invalid-name,unused-argument
def gen_pse(
    pse_file,
    dn,
    pse_pwd=None,
    algo="RSA:2048:SHA512",
    runas=None,
    groupas=None,
    add_ca_bundle=True,
    **kwargs,
):
    """
    Wrapper for the function ``gen_pse`` of the CLI tool ``sapgenpse``.

    Create a new PSE. This will **not** create a signing request.

    pse_file
        Equivalent to ``-p <pse-file>``, i.e. the path for the PSE.

    dn
        Distinguished name.

    pse_pwd
        Equivalent to ``-x <pin>``, i.e. the PIN/Passphrase for  the PSE. Default is no PIN.

    algo
        Equivalent to ``-a <algo>``, i.e. the algorithm used for the PSE, e.g. DSA, ECDSA or
        RSA (default is ``RSA:2048:SHA512``).

    runas
        User that will run the command, default is the user that runs the salt minion.

    groupas
        Group that will run the command, default is the group that runs the salt minion.

    add_ca_bundle
        If False, will not add the OpenSSL CA bundle returned by
        ``salt.utils.http.get_ca_bundle()`` which is all certificate authorities that are
        trusted by the operating system.

    Returns True / False based on success.

    CLI Example:

    .. code-block:: bash

        salt "*" sap_pse.gen_pse pse_file="/usr/sap/hostctrl/exe/sec/SAPSSLA.pse" dn="cn=ANONYMOUS"
    """
    log.debug("Running function")
    if not runas:
        runas = __grains__["username"]
    if not groupas:
        groupas = __grains__["groupname"]
    genpse_exec = _get_sapgenpse_path(runas)
    log.debug(f"Running with user {runas} and using executable {genpse_exec}")

    if pse_pwd:
        pin = f"-x {pse_pwd}"
    else:
        pin = "-x ''"  # empty PIN set

    cmd = f'{genpse_exec} gen_pse -p {pse_file} -a {algo} {pin} -noreq "{dn}"'
    log.trace(f"Executing '{cmd}'")
    env = {
        "TZ": "UTC",  # required for correct handling
    }
    cmd_ret = __salt__["cmd.run_all"](
        cmd, python_shell=True, runas=runas, group=groupas, timeout=30, env=env
    )
    log.trace(f"Output:\n{cmd_ret}")
    if cmd_ret.get("retcode"):
        out = cmd_ret.get("stderr").strip()
        log.error(f"Could not create {pse_file} :\n{out}")
        return False
    log.debug(f"Created {pse_file}")

    if add_ca_bundle:
        log.debug(f"Adding CA bundle certificates to PSE {pse_file}")
        success = maintain_pk_add(
            pse_file=pse_file, pse_pwd=pse_pwd, runas=runas, certs=[salt.utils.http.get_ca_bundle()]
        )
    else:
        success = True
    return success


# pylint: disable=unused-argument
def import_p8(
    pse_file,
    pub_key,
    priv_key,
    pse_pwd=None,
    priv_key_pwd=None,
    add_certs=None,
    runas=None,
    groupas=None,
    add_ca_bundle=True,
    **kwargs,
):
    """
    Wrapper for the function ``import_p8`` of the CLI tool ``sapgenpse``.

    This function creates a new PSE file from a PKCS#8 format private key
    (optionally protected by PKCS#5 password-based encryption) along with all
    necessary X.509 certs.

    You will have to supply the X.509 certificate matching the private key
    plus all intermediate and root CA certificates which might be necessary
    to build a certificate chain that ends with a self-signed certificate.

    pse_file
        Equivalent to ``-p <pse-file>``, i.e. the path for the PSE.

    pse_pwd
        Equivalent to ``-x <pin>``, i.e. the PIN/Passphrase for  the PSE. Default is no PIN.

    pub_key
        Equivalent to ``-c <cert(s)-file>``, i.e. a X.509 certificate containing the public key.

    priv_key
        Path to the X.509 certificate containing the private key.

    priv_key_pwd
        Equivalent to ``-z <password>``, i.e. the Password/Passphrase for decryption of
        private key. Default is no password.

    add_certs
        Equivalent to ``-r <file2>``, i.e. additional certificate(s) for an incomplete PKCS#8
        file. This list can contain to 10 additional files for building complete certification
        path up to the RootCA (PEM, Base64 or DER binary). Default is no additional
        certificates.

    runas
        User that will run the command, default is the user that runs the salt minion.

    groupas
        Group that will run the command, default is the group that runs the salt minion.

    add_ca_bundle
        If False, will not add the OpenSSL CA bundle returned by
        ``salt.utils.http.get_ca_bundle()`` which is all certificate authorities that are trusted
        by the operating system.

    Returns True / False based on success.

    CLI Example:

    .. code-block:: bash

        salt "*" sap_pse.import_p8 pse_file="/usr/sap/hostctrl/exe/sec/SAPSSLS.pse" pub_key="/etc/pki/cert.crt" priv_key="/etc/pki/cert.key"
    """  # pylint: disable=line-too-long
    log.debug("Running function")
    if not add_certs:
        add_certs = []
    elif len(add_certs) > 10:
        log.error("Only 10 additional files are allowed")
        return False
    if not runas:
        runas = __grains__["username"]
    if not groupas:
        groupas = __grains__["groupname"]
    genpse_exec = _get_sapgenpse_path(runas)
    log.debug(f"Running with user {runas} and using executable {genpse_exec}")

    if pse_pwd:
        pin = f"-x {pse_pwd}"
    else:
        pin = "-x ''"  # empty PIN set

    if add_certs:
        certs = " ".join([f"-r {x}" for x in add_certs])
    else:
        certs = ""

    cmd = f"{genpse_exec} import_p8 -p {pse_file} {pin} -c {pub_key}"
    if priv_key_pwd:
        cmd += f" -z {priv_key_pwd}"
    cmd += f" {certs} {priv_key}"
    log.trace(f"Executing '{cmd}'")
    env = {
        "TZ": "UTC",  # required for correct handling
    }
    log.debug(f"Running the following command: '{cmd}'")
    cmd_ret = __salt__["cmd.run_all"](
        cmd, python_shell=True, runas=runas, group=groupas, timeout=30, env=env
    )
    log.debug(f"Output:\n{cmd_ret}")
    if cmd_ret.get("retcode"):
        out = cmd_ret.get("stderr").strip()
        log.error(f"Could not create {pse_file} from {pub_key}/{priv_key}:\n{out}")
        return False
    log.debug(f"Created {pse_file} from {pub_key}/{priv_key}")

    if add_ca_bundle:
        log.debug(f"Adding CA bundle certificates to PSE {pse_file}")
        success = maintain_pk_add(
            pse_file=pse_file, pse_pwd=pse_pwd, runas=runas, certs=[salt.utils.http.get_ca_bundle()]
        )
    else:
        success = True

    return success


# pylint: disable=unused-argument
def export_p8(
    pse_file, pem_file, pem_pwd, pse_pwd=None, runas=None, groupas=None, secudir=None, **kwargs
):
    """
    Wrapper for the function ``export_p8`` of the CLI tool ``sapgenpse``.

    Exports the key of a PSE into PKCS#8 transfer format (PEM-File) for transfer/export to
    software of other vendors.

    The private key and its corresponding certificat plus forward certificate chain up to and
    including the RootCA's certificate are written into a PEM file.

    pse_file
        Equivalent to ``-p <pse-file>``, i.e. the path of the PSE.

    pem_file
        Path to the PEM file which will contain both public and private key.

    pem_pwd
        Equivalent to ``-z <password>``, i.e. the Password/Passphrase for the encryption
        of the PEM-file.

    pse_pwd
        Equivalent to ``-x <pin>``, i.e. the PIN/Passphrase for PSE file. Default is no PIN.

    runas
        User that will run the command, default is the user that runs the salt minion.

    groupas
        Group that will run the command, default is the group that runs the salt minion.

    secudir
        SECUDIR to use. If not defined, the path of the PSE file will be set as SECUDIR.

    Returns True / False based on success.

    CLI Example:

    .. code-block:: bash

        salt "*" sap_pse.export_p8 pse_file="/usr/sap/hostctrl/exe/sec/SAPSSLS.pse" pem_file="/etc/pki/pse.crt" pem_pwd=Abcd1234
    """  # pylint: disable=line-too-long
    log.debug("Running function")
    if not runas:
        runas = __salt__["file.get_user"](pse_file)
    if not groupas:
        groupas = __salt__["file.get_group"](pse_file)
    genpse_exec = _get_sapgenpse_path(runas)
    log.debug(f"Running with user {runas} and using executable {genpse_exec}")

    if not secudir:
        secudir = pse_file.rsplit("/", 1)[0]
        log.debug(f"Setting SECUDIR to '{secudir}'")

    if pse_pwd:
        pin = f"-x {pse_pwd}"
    else:
        pin = "-x ''"  # empty PIN set

    cmd = f"{genpse_exec} export_p8 -p {pse_file} {pin}"
    cmd += f" -z {pem_pwd}"
    cmd += f" {pem_file}"
    log.trace(f"Executing '{cmd}'")
    env = {"TZ": "UTC", "SECUDIR": secudir}  # required for correct handling
    cmd_ret = __salt__["cmd.run_all"](
        cmd, python_shell=True, runas=runas, group=groupas, timeout=30, env=env, cwd=secudir
    )
    log.trace(f"Output:\n{cmd_ret}")
    if cmd_ret.get("retcode"):
        out = cmd_ret.get("stderr").strip()
        log.error(f"Could not create {pem_file} from {pse_file}:\n{out}")
        return False
    log.debug(f"Created {pem_file} from {pse_file}")
    return True


# pylint: disable=unused-argument
def get_my_name(pse_file, pse_pwd=None, runas=None, groupas=None, secudir=None, **kwargs):
    """
    Wrapper for the function ``get_my_name`` of the CLI tool ``sapgenpse``.

    Displays the attributes/properties of the user/owner certificate in a PSE.

    pse_file
        Equivalent to ``-p <pse-file>``, i.e. the path of the PSE.

    pse_pwd
        Equivalent to ``-x <pin>``, i.e. the PIN/Passphrase for PSE file. Default is no PIN.

    runas
        User that will run the command, default is the user that runs the salt minion.

    groupas
        Group that will run the command, default is the group that runs the salt minion.

    secudir
        SECUDIR to use. If not defined, the path of the PSE file will be set as SECUDIR.

    CLI Example:

    .. code-block:: bash

        salt "*" sap_pse.get_my_name pse_file="/usr/sap/hostctrl/exe/sec/SAPSSLS.pse"
    """
    log.debug("Running function")
    if not runas:
        runas = __salt__["file.get_user"](pse_file)
        log.warning(f"No user defined to run with, using PSE file owner '{runas}'")
    if not groupas:
        groupas = __salt__["file.get_group"](pse_file)
        log.warning(f"No group defined to run with, using PSE file owner group '{groupas}'")
    genpse_exec = _get_sapgenpse_path(runas)
    log.debug(f"Running with user {runas} and using executable {genpse_exec}")

    if not secudir:
        secudir = pse_file.rsplit("/", 1)[0]
        log.debug(f"Setting SECUDIR to '{secudir}'")

    if pse_pwd:
        pin = f"-x {pse_pwd}"
    else:
        pin = "-x ''"  # empty PIN set

    # Note: sapgenpse does not support machine-readable output, but the verbose output
    # can be interpreted as YAML
    cmd = f"{genpse_exec} get_my_name -vv -p {pse_file} {pin}"
    log.trace(f"Executing '{cmd}'")
    env = {"TZ": "UTC", "SECUDIR": secudir}  # required for correct handling
    cmd_ret = __salt__["cmd.run_all"](
        cmd, python_shell=True, runas=runas, group=groupas, timeout=30, env=env, cwd=secudir
    )
    log.trace(f"Output:\n{cmd_ret}")
    if "(Wrong PIN/Passphrase)" in cmd_ret.get("stderr"):
        log.error(f"Cannot open {pse_file} due to wrong PIN")
        return {}
    if cmd_ret.get("retcode"):
        out = cmd_ret.get("stderr").strip()
        log.error(f"Could not retrieve data from pse {pse_file}:\n{out}")
        return False

    data = {}
    out = cmd_ret.get("stdout")
    if not out:
        log.debug("No data over stdout, checking stderr")
        out = cmd_ret.get("stderr")
    lines = out.splitlines()

    i = 0
    while True:
        if i + 1 >= len(lines):
            break
        log.trace(f"Processing line '{lines[i]}'")
        if lines[i].startswith("--------------------------------"):
            cert_name = lines[i - 1].split(":", 1)[0].strip()
            log.debug(f"Processing certificate {cert_name}")
            # all the lines under the element can be interpreted as yaml
            i += 2  # next line is always "Certificate: and can be skipped"
            yaml_data = []
            while True:
                if (
                    i >= len(lines) - 1
                    or not lines[i].strip()
                    or lines[i].startswith("--------------------------------")
                ):
                    cert_data = _parse_cert_output(yaml_data)
                    data[cert_name] = cert_data
                    i += 1
                    break
                else:
                    log.trace(f"Adding line '{lines[i]}'")
                    yaml_data.append(lines[i])
                    i += 1
        i += 1
    log.trace(f"Returning data:\n{data}")
    return data


# pylint: disable=unused-argument
def maintain_pk_add(
    pse_file, certs, runas=None, groupas=None, pse_pwd=None, secudir=None, **kwargs
):
    """
    Wrapper for the function ``maintain_pk`` of the CLI tool ``sapgenpse``.

    Adds certificates to the PK list of a PSE.

    pse_file
        Equivalent to ``-p <pse-file>``, i.e. the path of the PSE.

    certs
        Equivalent to ``-m <cert-file>``, i.e. add multiple certificates from <file>.
        Must be a list.

    pse_pwd
        Equivalent to ``-x <pin>``, i.e. the PIN/Passphrase for PSE file. Default is no PIN.

    runas
        User that will run the command, default is the user that runs the salt minion.

    groupas
        Group that will run the command, default is the group that runs the salt minion.

    secudir
        SECUDIR to use. If not defined, the path of the PSE file will be set as SECUDIR.

    CLI Example:

    .. code-block:: bash

        salt "*" sap_pse.maintain_pk_add pse_file="/usr/sap/hostctrl/exe/sec/SAPSSLS.pse" certs=["/etc/pki/trust/anchors/ca.crt"]
    """  # pylint: disable=line-too-long
    log.debug("Running function")
    if not runas:
        runas = __salt__["file.get_user"](pse_file)
        log.warning(f"No user defined to run with, using PSE file owner '{runas}'")
    if not groupas:
        groupas = __salt__["file.get_group"](pse_file)
        log.warning(f"No group defined to run with, using PSE file owner group '{groupas}'")
    genpse_exec = _get_sapgenpse_path(runas)
    log.debug(f"Running with user {runas} and using executable {genpse_exec}")

    if not secudir:
        secudir = pse_file.rsplit("/", 1)[0]
        log.debug(f"Setting SECUDIR to '{secudir}'")

    if pse_pwd:
        pin = f"-x {pse_pwd}"
    else:
        pin = "-x ''"  # empty PIN set

    certs = " ".join([f"-m {x}" for x in certs])

    cmd = f"{genpse_exec} maintain_pk -y -p {pse_file} {pin} {certs}"
    log.trace(f"Executing '{cmd}'")
    env = {"TZ": "UTC", "SECUDIR": secudir}  # required for correct handling
    cmd_ret = __salt__["cmd.run_all"](
        cmd, python_shell=True, runas=runas, group=groupas, timeout=30, env=env, cwd=secudir
    )
    log.debug(f"Output:\n{cmd_ret}")
    if cmd_ret.get("retcode"):
        out = cmd_ret.get("stderr").strip()
        log.error(f"Could not add certificates {certs} to pse {pse_file}:\n{out}")
        return False

    log.debug(f"Successfully added certificates {certs} to pse {pse_file}")
    return True


# pylint: disable=unused-argument
def maintain_pk_delete(
    pse_file, del_cert, runas=None, groupas=None, pse_pwd=None, secudir=None, **kwargs
):
    """
    Wrapper for the function ``maintain_pk`` of the CLI tool ``sapgenpse``.

    Delete certificates from the PKList of a PSE.

    pse_file
        Equivalent to ``-p <pse-file>``, i.e. the path of the PSE.

    del_cert
        Equivalent to ``"-d <num>`` (delete certificate/key number <num> from PKList) or
        ``-d <string>`` (delete certificates/keys from PKList containing <string>)

    pse_pwd
        Equivalent to ``-x <pin>``, i.e. the PIN/Passphrase for PSE file. Default is no PIN.

    runas
        User that will run the command, default is the user that runs the salt minion.

    groupas
        Group that will run the command, default is the group that runs the salt minion.

    secudir
        SECUDIR to use. If not defined, the path of the PSE file will be set as SECUDIR.

    CLI Example:

    .. code-block:: bash

        salt "*" sap_pse.maintain_pk_delete pse_file="/usr/sap/hostctrl/exe/sec/SAPSSLS.pse" del_cert=0
    """
    log.debug("Running function")
    if not runas:
        runas = __salt__["file.get_user"](pse_file)
        log.warning(f"No user defined to run with, using PSE file owner '{runas}'")
    if not groupas:
        groupas = __salt__["file.get_group"](pse_file)
        log.warning(f"No group defined to run with, using PSE file owner group '{groupas}'")
    genpse_exec = _get_sapgenpse_path(runas)
    log.debug(f"Running with user {runas} and using executable {genpse_exec}")

    if not secudir:
        secudir = pse_file.rsplit("/", 1)[0]
        log.debug(f"Setting SECUDIR to '{secudir}'")

    if pse_pwd:
        pin = f"-x {pse_pwd}"
    else:
        pin = "-x ''"  # empty PIN set

    cmd = f"{genpse_exec} maintain_pk -p {pse_file} {pin} -d {del_cert}"
    log.trace(f"Executing '{cmd}'")
    env = {"TZ": "UTC", "SECUDIR": secudir}  # required for correct handling
    cmd_ret = __salt__["cmd.run_all"](
        cmd, python_shell=True, runas=runas, group=groupas, timeout=30, env=env, cwd=secudir
    )
    log.debug(f"Output:\n{cmd_ret}")
    if cmd_ret.get("retcode"):
        out = cmd_ret.get("stderr").strip()
        log.error(f"Could not delete certificate {del_cert} from pse {pse_file}:\n{out}")
        return False

    log.debug(f"Successfully deleted certificate {del_cert} from pse {pse_file}")
    return True


# pylint: disable=unused-argument
def maintain_pk_list(pse_file, runas=None, groupas=None, pse_pwd=None, secudir=None, **kwargs):
    """
    Wrapper for the function ``maintain_pk`` of the CLI tool ``sapgenpse``.

    List certificates from the PKList of a PSE.

    pse_file
        Equivalent to ``-p <pse-file>``, i.e. the path of the PSE.

    pse_pwd
        Equivalent to ``-x <pin>``, i.e. the PIN/Passphrase for PSE file. Default is no PIN.

    runas
        User that will run the command, default is the user that runs the salt minion.

    groupas
        Group that will run the command, default is the group that runs the salt minion.

    secudir
        SECUDIR to use. If not defined, the path of the PSE file will be set as SECUDIR.

    CLI Example:

    .. code-block:: bash

        salt "*" sap_pse.maintain_pk_list pse_file="/usr/sap/hostctrl/exe/sec/SAPSSLS.pse"
    """
    log.debug("Running function")
    if not runas:
        runas = __salt__["file.get_user"](pse_file)
        log.warning(f"No user defined to run with, using PSE file owner '{runas}'")
    if not groupas:
        groupas = __salt__["file.get_group"](pse_file)
        log.warning(f"No group defined to run with, using PSE file owner group '{groupas}'")
    genpse_exec = _get_sapgenpse_path(runas)
    log.debug(f"Running with user {runas} and using executable {genpse_exec}")

    if not secudir:
        secudir = pse_file.rsplit("/", 1)[0]
        log.debug(f"Setting SECUDIR to '{secudir}'")

    if pse_pwd:
        pin = f"-x {pse_pwd}"
    else:
        pin = "-x ''"  # empty PIN set

    cmd = f"{genpse_exec} maintain_pk -l -p {pse_file} {pin}"
    log.trace(f"Executing '{cmd}'")
    env = {"TZ": "UTC", "SECUDIR": secudir}  # required for correct handling
    cmd_ret = __salt__["cmd.run_all"](
        cmd, python_shell=True, runas=runas, group=groupas, timeout=30, env=env, cwd=secudir
    )
    log.debug(f"Output:\n{cmd_ret}")
    if cmd_ret.get("retcode"):
        out = cmd_ret.get("stderr").strip()
        log.error(f"Could not retrieve certificates for pse {pse_file}:\n{out}")
        return False

    log.debug("Parsing output")
    data = []
    out = cmd_ret.get("stdout")
    if not out:
        log.debug("No data over stdout, checking stderr")
        out = cmd_ret.get("stderr")
    lines = out.splitlines()
    i = 0
    while True:
        if i + 1 >= len(lines):
            break
        log.trace(f"Processing line '{lines[i]}'")
        # when only one certificate is maintained, "Element" is skipped
        if lines[i].startswith(" Element") or (
            lines[i].startswith("PKList") and lines[i + 1].startswith(" Version")
        ):
            cert_number = re.findall(r"Element #([0-9]+):", lines[i].strip())
            if not cert_number:
                # if only one certificate is maintained
                cert_number = 1
            else:
                cert_number = cert_number[0]
            log.debug(f"Processing certificate {cert_number}")
            # all the lines under the element can be interpreted as yaml
            i += 1
            yaml_data = []
            while True:
                if i >= len(lines) or not lines[i].strip() or lines[i].startswith(" Element"):
                    cert_data = _parse_cert_output(yaml_data)
                    cert_data["number"] = cert_number
                    data.append(cert_data)
                    break
                else:
                    log.trace(f"Adding line '{lines[i]}'")
                    yaml_data.append(lines[i])
                    i += 1
        else:
            i += 1
    log.trace(f"Returning data:\n{data}")
    return data


# pylint: disable=unused-argument
def seclogin_add(
    pse_file, pse_pwd=None, user=None, runas=None, groupas=None, secudir=None, **kwargs
):
    """
    Wrapper for the function ``seclogin`` of the CLI tool ``sapgenpse``.

    Creates Single Sign-On (SSO) credentials for a PSE / user.

    pse_file
        Equivalent to ``-p <pse-file>``, i.e. the path of the PSE.

    pse_pwd
        Equivalent to ``-x <pin>``, i.e. the PIN/Passphrase for PSE file. Default is no PIN.

    user
        Equivalent to ``-O <username>``, i.e. create SSO-credential for OTHER user <username>.
        Will be set to runas or salt minion user if None.

    runas
        User that will run the command, default is the user that runs the salt minion.

    groupas
        Group that will run the command, default is the group that runs the salt minion.

    secudir
        SECUDIR to use. If not defined, the path of the PSE file will be set as SECUDIR.

    CLI Example:

    .. code-block:: bash

        salt "*" sap_pse.seclogin_add pse_file="/usr/sap/hostctrl/exe/sec/SAPSSLS.pse" user="sapadm"
    """
    log.debug("Running function")
    if not runas:
        runas = __salt__["file.get_user"](pse_file)
        log.warning(f"No user defined to run with, using PSE file owner '{runas}'")
    if not groupas:
        groupas = __salt__["file.get_group"](pse_file)
        log.warning(f"No group defined to run with, using PSE file owner group '{groupas}'")
    genpse_exec = _get_sapgenpse_path(runas)
    log.debug(f"Running with user {runas} and using executable {genpse_exec}")
    if not user:
        user = runas

    if not secudir:
        secudir = pse_file.rsplit("/", 1)[0]
        log.debug(f"Setting SECUDIR to {secudir}")

    if pse_pwd:
        pin = f"-x {pse_pwd}"
    else:
        pin = "-x ''"  # empty PIN set

    cmd = f"{genpse_exec} seclogin -p {pse_file} {pin} -O {user}"
    log.trace(f"Executing '{cmd}'")
    env = {"TZ": "UTC", "SECUDIR": secudir}  # required for correct handling
    cmd_ret = __salt__["cmd.run_all"](
        cmd, python_shell=True, runas=runas, group=groupas, timeout=30, env=env, cwd=secudir
    )
    log.debug(f"Output:\n{cmd_ret}")
    if cmd_ret.get("retcode"):
        out = cmd_ret.get("stderr").strip()
        log.error(f"Could not create seclogin for pse {pse_file} / user {user}:\n{out}")
        return False
    log.debug(f"Created seclogin for pse {pse_file} / user {user}")
    return True


# pylint: disable=unused-argument
def seclogin_contains(
    pse_file, pse_pwd=None, user=None, runas=None, groupas=None, secudir=None, **kwargs
):
    """
    Wrapper for the function ``seclogin`` of the CLI tool ``sapgenpse``.

    Returns success and if Single Sign-On (SSO) credentials for user already exist.

    pse_file
        Equivalent to ``-p <pse-file>``, i.e. the path of the PSE.

    pse_pwd
        Equivalent to ``-x <pin>``, i.e. the PIN/Passphrase for PSE file. Default is no PIN.

    user
        Equivalent to ``-O <username>``, i.e. create SSO-credential for OTHER user <username>.
        Will be set to runas or salt minion user if None.

    runas
        User that will run the command, default is the user that runs the salt minion.

    groupas
        Group that will run the command, default is the group that runs the salt minion.

    secudir
        SECUDIR to use. If not defined, the path of the PSE file will be set as SECUDIR.

    CLI Example:

    .. code-block:: bash

        salt "*" sap_pse.seclogin_contains pse_file="/usr/sap/hostctrl/exe/sec/SAPSSLS.pse" user="sapadm"
    """
    log.debug("Running function")
    if not runas:
        runas = __salt__["file.get_user"](pse_file)
        log.warning(f"No user defined to run with, using PSE file owner '{runas}'")
    if not groupas:
        groupas = __salt__["file.get_group"](pse_file)
        log.warning(f"No group defined to run with, using PSE file owner group '{groupas}'")
    genpse_exec = _get_sapgenpse_path(runas)
    log.debug(f"Running with user {runas} and using executable {genpse_exec}")
    if not user:
        user = runas

    if not secudir:
        secudir = pse_file.rsplit("/", 1)[0]
        log.debug(f"Setting SECUDIR to '{secudir}'")

    if pse_pwd:
        pin = f"-x {pse_pwd}"
    else:
        pin = "-x ''"  # empty PIN set

    cmd = f"{genpse_exec} seclogin -p {pse_file} {pin} -l -O {user}"
    log.trace(f"Executing '{cmd}'")
    env = {"TZ": "UTC", "SECUDIR": secudir}  # required for correct handling
    cmd_ret = __salt__["cmd.run_all"](
        cmd, python_shell=True, runas=runas, group=groupas, timeout=30, env=env, cwd=secudir
    )
    log.debug(f"Output:\n{cmd_ret}")
    if cmd_ret.get("retcode"):
        out = cmd_ret.get("stderr").strip()
        if cmd_ret.get("retcode") == 21 and "No SSO credentials available" in out:
            log.debug("No credentials available")
            return True, False
        log.error(f"Could not list seclogin for pse {pse_file} / user {user}:\n{out}")
        return False, None

    out = cmd_ret.get("stdout")
    if not out:
        out = cmd_ret.get("stderr")
    m = re.search(
        r"([0-9]+|NO) readable (\(of [0-9]+ matching\) )?SSO-Credentials available( \(total [0-9]+\))?",
        out,
    )
    if not m:
        log.error(f"Could not determine list of SSO credentials for user {user}")
        return False, None
    if m.groups()[0] == "NO":
        return True, False
    return True, True


# pylint: disable=unused-argument
def seclogin_count(pse_file, runas=None, groupas=None, pse_pwd=None, secudir=None, **kwargs):
    """
    Wrapper for the function ``seclogin`` of the CLI tool ``sapgenpse``.

    Returns success and the count of SSO credentials for the given PSE.

    pse_file
        Equivalent to ``-p <pse-file>``, i.e. the path of the PSE.

    pse_pwd
        Equivalent to ``-x <pin>``, i.e. the PIN/Passphrase for PSE file. Default is no PIN.

    runas
        User that will run the command, default is the user that runs the salt minion.

    groupas
        Group that will run the command, default is the group that runs the salt minion.

    secudir
        SECUDIR to use. If not defined, the path of the PSE file will be set as SECUDIR.

    CLI Example:

    .. code-block:: bash

        salt "*" sap_pse.seclogin_count pse_file="/usr/sap/hostctrl/exe/sec/SAPSSLS.pse"
    """
    log.debug("Running function")
    if not runas:
        runas = __salt__["file.get_user"](pse_file)
        log.warning(f"No user defined to run with, using PSE file owner '{runas}'")
    if not groupas:
        groupas = __salt__["file.get_group"](pse_file)
        log.warning(f"No group defined to run with, using PSE file owner group '{groupas}'")
    genpse_exec = _get_sapgenpse_path(runas)
    log.debug(f"Running with user {runas} and using executable {genpse_exec}")

    if not secudir:
        secudir = pse_file.rsplit("/", 1)[0]
        log.debug(f"Setting SECUDIR to '{secudir}'")

    if pse_pwd:
        pin = f"-x {pse_pwd}"
    else:
        pin = "-x ''"  # empty PIN set

    cmd = f"{genpse_exec} seclogin -p {pse_file} {pin} -l"
    log.trace(f"Executing '{cmd}'")
    env = {"TZ": "UTC", "SECUDIR": secudir}  # required for correct handling
    cmd_ret = __salt__["cmd.run_all"](
        cmd, python_shell=True, runas=runas, group=groupas, timeout=30, env=env, cwd=secudir
    )
    log.debug(f"Output:\n{cmd_ret}")
    if cmd_ret.get("retcode"):
        out = cmd_ret.get("stderr").strip()
        log.error(f"Could not list seclogin for pse {pse_file}:\n{out}")
        return False

    out = cmd_ret.get("stdout")
    if not out:
        out = cmd_ret.get("stderr")
    m = re.findall(r"[0-9]+ \(LPS:", out)
    ret = len(m)
    log.debug(f"Returning:\n{ret}")
    return ret


# pylint: disable=unused-argument
def seclogin_delete(pse_file, pse_pwd=None, runas=None, groupas=None, secudir=None, **kwargs):
    """
    Wrapper for the function ``seclogin`` of the CLI tool ``sapgenpse``.

    Removes all SSO credentials for a PSE file.

    pse_file
        Equivalent to ``-p <pse-file>``, i.e. the path of the PSE.

    pse_pwd
        Equivalent to ``-x <pin>``, i.e. the PIN/Passphrase for PSE file. Default is no PIN.

    runas
        User that will run the command, default is the user that runs the salt minion.

    groupas
        Group that will run the command, default is the group that runs the salt minion.

    secudir
        SECUDIR to use. If not defined, the path of the PSE file will be set as SECUDIR.

    CLI Example:

    .. code-block:: bash

        salt "*" sap_pse.seclogin_delete pse_file="/usr/sap/hostctrl/exe/sec/SAPSSLS.pse"
    """
    log.debug("Running function")
    if not runas:
        runas = __salt__["file.get_user"](pse_file)
        log.warning(f"No user defined to run with, using PSE file owner '{runas}'")
    if not groupas:
        groupas = __salt__["file.get_group"](pse_file)
        log.warning(f"No group defined to run with, using PSE file owner group '{groupas}'")
    genpse_exec = _get_sapgenpse_path(runas)
    log.debug(f"Running with user {runas} and using executable {genpse_exec}")

    if not secudir:
        secudir = pse_file.rsplit("/", 1)[0]
        log.debug(f"Setting SECUDIR to '{secudir}'")

    if pse_pwd:
        pin = f"-x {pse_pwd}"
    else:
        pin = "-x ''"  # empty PIN set

    cmd = f"{genpse_exec} seclogin -p {pse_file} {pin} -d"
    log.trace(f"Executing '{cmd}'")
    env = {"TZ": "UTC", "SECUDIR": secudir}  # required for correct handling
    cmd_ret = __salt__["cmd.run_all"](
        cmd, python_shell=True, runas=runas, group=groupas, timeout=30, env=env, cwd=secudir
    )
    log.debug(f"Output:\n{cmd_ret}")
    if cmd_ret.get("retcode"):
        out = cmd_ret.get("stderr").strip()
        log.error(f"Could not delete seclogin for pse {pse_file}:\n{out}")
        return False

    return True


# pylint: disable=unused-argument
def gen_verify_pse(pse_file=None, runas=None, groupas=None, **kwargs):
    """
    Wrapper for the function ``gen_verify_pse`` of the CLI tool ``sapgenpse``.

    Create a new PSE for verification without own key pair.

    pse_file
        Equivalent to ``-p <pse-file>``, i.e. the path of the PSE.

    runas
        User that will run the command, default is the user that runs the salt minion.

    groupas
        Group that will run the command, default is the group that runs the salt minion.

    .. note::
        This will utilze the OpenSSL CA bundle returned by ``salt.utils.http.get_ca_bundle()``.

    CLI Example:

    .. code-block:: bash

        salt "*" sap_pse.seclogin_delete pse_file="/usr/sap/hostctrl/exe/sec/SAPSSLS.pse"
    """
    log.debug("Running function")
    ca_bundle = (
        salt.utils.http.get_ca_bundle()
    )  # On SLES returns /var/lib/ca-certificates/ca-bundle.pem
    if not pse_file:
        pse_file = "SAPVERIFY1.pse"
    if not runas:
        runas = __grains__["username"]
    if not groupas:
        groupas = __grains__["groupname"]
    genpse_exec = _get_sapgenpse_path(runas)

    log.debug(f"Running with user {runas} and using executable {genpse_exec}")
    cmd = f'{genpse_exec} gen_verify_pse -p {pse_file} -x "" -a {ca_bundle}'
    log.trace(f"Executing '{cmd}'")
    env = {
        "TZ": "UTC",  # required for correct handling
    }
    cmd_ret = __salt__["cmd.run_all"](
        cmd, python_shell=True, runas=runas, group=groupas, timeout=30, env=env
    )
    log.debug(f"Output:\n{cmd_ret}")
    if cmd_ret.get("retcode"):
        out = cmd_ret.get("stderr").strip()
        log.error(f"Could not create {pse_file} from {pse_file}:\n{out}")
        return False
    log.debug(f"Created {pse_file} from {pse_file}")
    return True
