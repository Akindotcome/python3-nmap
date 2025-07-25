#  nmap3.py
#
#  Copyright 2019 Wangolo Joel <wangolo@ldap.testlumiotic.com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#

import logging
import typing
import shlex
import subprocess
import sys
import re
import argparse
import asyncio
from xml.etree import ElementTree as ET
from xml.etree.ElementTree import ParseError

from nmap3.nmapparser import NmapCommandParser
from nmap3.utils import (
    get_nmap_path,
    user_is_root,
    _terminate_process,
    _terminate_asyncio_process,
)
from nmap3.exceptions import (
    NmapXMLParserError,
    NmapExecutionError,
    NmapTimeoutError,
)

__author__ = "Wangolo Joel (inquiry@nmapper.com)"
__version__ = "1.9.3"
__last_modification__ = "Jun/14/2025"

OS_TYPE = sys.platform
logger = logging.getLogger(__name__)


class BaseNmap(object):
    """Base class for ``nmap`` operations"""

    def __init__(self, path: typing.Optional[str] = None) -> None:
        """
        Initializes an inatance

        :param path: Path where nmap is installed on a user system. On linux system it's typically on /usr/bin/nmap.
        """
        self.nmaptool = get_nmap_path(path)  # check path, search or raise error
        self.default_args = "{nmap}  {outarg}  -  "
        self.maxport = 65535
        self.target = ""
        self.top_ports: typing.Dict[str, typing.Any] = {}
        self.parser = NmapCommandParser(None)
        self.raw_output: typing.Optional[str] = None
        # self.as_root = False
        # """Whether to run as root/administrator"""

    # With this implementation, this method is redundant
    # def require_root(self, required: bool = True) -> None:
    #     """
    #     Sets or unsets the instance to run command as 'root' user.
    #
    #     :param required: If True, the nmap command will be run with root privileges
    #     :param root: The root command to use (default is "sudo" on Unix-like systems).
    #         Can be "doas' in some Unix distributions
    #     """
    #     self.as_root = required

    def default_command(self) -> str:
        """
        Returns the default/root nmap command
        that will be chained with all others

        e.g nmap -oX -
        """
        command = self.default_args.format(
            nmap=self.nmaptool, outarg="-v -oX"
        )  # adding extra verbosity to feed "task_results" output
        return command

    # This does not reaaly do much and may even introduce a recursion error
    # def default_command_privileged(self):
    #     """
    #     Commands that require root privileges
    #     """
    #     if OS_TYPE == 'win32':
    #         # Elevate privileges and return nmap command
    #         # For windows now is not fully supported so just return the default
    #         return self.default_command()
    #     else:
    #         return self.default_args.format(nmap=self.nmaptool, outarg="-oX")


    def get_xml_et(self, command_output: str) -> ET.Element:
        """
        Parses the command output and returns an XML ElementTree root element

        :param command_output: The output of the nmap command as a string
        :return : An XML ElementTree root element representing the parsed output
        :raises NmapXMLParserError: If the output cannot be parsed as XML
        """
        try:
            self.raw_output = command_output
            return ET.fromstring(command_output)
        except ParseError:
            raise NmapXMLParserError()

    def get_success_xml_et(self, file_name: str) -> ET.Element:
        """
        Returns an XML Element indicating a successful scan

        :param file_name: The name of the file where the scan results are saved
        :return: An XML Element with success message and file path
        """
        root = ET.Element("root")
        success = ET.SubElement(root, "success")
        success.text = "Nmap scan completed successfully."
        file_path = ET.SubElement(root, "file_path")
        file_path.text = "{}".format(file_name)
        return root


class Nmap(BaseNmap):
    """Implements an interface to allows the use of ``nmap`` port scanner tool from within python"""

    def run_command(
        self, cmd: typing.List[str], timeout: typing.Optional[float] = None
    ) -> str:
        """
        Runs the nmap command using popen

        :param cmd: the command we want run, as a list,
            e.g /usr/bin/nmap -oX -  nmmapper.com --top-ports 10
        :param timeout: command subprocess timeout in seconds.
        :return: The output of the command (in the console) as a string
        """
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.debug(f"Created subprocess with PID {process.pid!r}")
        try:
            output, errs = process.communicate(timeout=timeout)
        except subprocess.CalledProcessError as e:
            _terminate_process(process, timeout=0.2)
            raise NmapExecutionError(
                'Error during command: "' + " ".join(cmd) + '"\n\n' + str(e)
            ) from e
        except subprocess.TimeoutExpired as e:
            _terminate_process(process, timeout=0.2)
            raise NmapTimeoutError(
                'Command timed out after {timeout} seconds: "'.format(timeout=timeout)
                + " ".join(cmd)
                + '"\n\n'
                + str(e)
            ) from e
        else:
            if process.returncode != 0:
                raise NmapExecutionError(
                    'Error during command: "'
                    + " ".join(cmd)
                    + '"\n\n'
                    + str(errs.decode("utf-8"))
                )
            # Response is bytes so decode the output and return
            return output.decode("utf-8").strip()

    def scan_command(
        self,
        target: str,
        arg: str,
        args: typing.Optional[str] = None,
        timeout: typing.Optional[float] = None,
    ) -> ET.Element:
        """
        Perform nmap scan using the specified arguments

        :param target: The target to scan (IP address or domain)
        :param arg: The nmap argument to use for the scan (e.g., "-sS", "-sV", etc.)
        :param args: Additional arguments for the scan
        :param timeout: Timeout for the scan command in seconds
        :return: An XML ElementTree root element containing the scan results
        """
        self.target = target

        command_args = "{target}  {default}".format(target=target, default=arg)
        scancommand = self.default_command() + command_args
        if args:
            scancommand += " {0}".format(args)

        scan_shlex = shlex.split(scancommand)
        output = self.run_command(scan_shlex, timeout=timeout)
        file_name_match = re.search(
            r"(\-oX|-oN-|oG)\s+[a-zA-Z-_0-9]{1,100}\.[a-zA-Z]+", scancommand
        )
        if file_name_match:
            file_name = scancommand[
                file_name_match.start() : file_name_match.end()
            ].split(" ")[0]
            return self.get_success_xml_et(file_name)
        xml_root = self.get_xml_et(output)
        return xml_root

    def nmap_version(self) -> typing.Dict[str, typing.Tuple[str, ...]]:
        """
        Returns nmap version and build details

        :return: A dictionary containing nmap version, compiled with, compiled without, and available nsock engines
        """
        # nmap version output is not available in XML format (eg. -oX -)
        output = self.run_command([self.nmaptool, "--version"])
        version_data: typing.Dict[str, typing.Tuple[str, ...]] = {}

        for line in output.splitlines():
            if line.startswith("Nmap version "):
                version_string = line.split(" ")[2]
                version_data["nmap"] = tuple(
                    [part for part in version_string.split(".")]
                )
            elif line.startswith("Compiled with:"):
                compiled_with = line.split(":")[1].strip()
                version_data["compiled_with"] = tuple(compiled_with.split(" "))
            elif line.startswith("Compiled without:"):
                compiled_without = line.split(":")[1].strip()
                version_data["compiled_without"] = tuple(compiled_without.split(" "))
            elif line.startswith("Available nsock engines:"):
                nsock_engines = line.split(":")[1].strip()
                version_data["nsock_engines"] = tuple(nsock_engines.split(" "))
        return version_data

    def scan_top_ports(
        self,
        target: str,
        default: int = 10,
        args: typing.Optional[str] = None,
        timeout: typing.Optional[float] = None,
    ) -> typing.Dict[str, typing.Any]:
        """
        Perform nmap's top ports scan

        :param target: can be IP or domain
        :param default: is the default top port
        :param args: additional arguments for the scan
        :param timeout: timeout for the scan command
        :return: A dictionary containing top ports found on the target

        This top port requires root previledges
        """
        if default > self.maxport:
            raise ValueError("Port can not be greater than default 65535")
        self.target = target

        if args:
            assert isinstance(args, str), "Expected string got {0} instead".format(
                type(args)
            )

        top_port_args = " {target} --top-ports {default}".format(
            target=target, default=default
        )
        scan_command = self.default_command() + top_port_args
        if args:
            scan_command += " {0}".format(args)
        scan_shlex = shlex.split(scan_command)

        # Run the command and get the output
        output = self.run_command(scan_shlex, timeout=timeout)
        if not output:
            # An error was probably raised
            raise ValueError("Unable to perform requested command")

        # Begin parsing the xml response
        xml_root = self.get_xml_et(output)
        self.top_ports = self.parser.filter_top_ports(xml_root)
        return self.top_ports

    def nmap_dns_brute_script(
        self,
        target: str,
        dns_brute: str = "--script dns-brute.nse",
        args: typing.Optional[str] = None,
        timeout: typing.Optional[float] = None,
    ) -> typing.List[typing.Dict[str, typing.Any]]:
        """
        Perform nmap scan using the dns-brute script

        :param target: can be IP or domain.
        :param dns_brute: the dns-brute script to use
        :param args: additional arguments for the scan
        :param timeout: timeout for the scan command
        :return: List of subdomains found by the dns-brute script

        Example usage:
        ```python
        from nmap3 import NmapScanTechniques

        nmap = NmapScanTechniques()
        target = "nmmapper.com"
        dns_brute = "--script dns-brute.nse"
        args = "--script-args dns-brute.timeout=5"
        timeout = 10  # seconds
        subdomains = nmap.nmap_dns_brute_script(target, dns_brute, args, timeout)
        print(subdomains)
        ```
        """
        self.target = target
        dns_brute_args = "{target}  {default}".format(target=target, default=dns_brute)

        if args:
            dns_brute_args += " {0}".format(args)

        dns_brute_command = self.default_command() + dns_brute_args
        dns_brute_shlex = shlex.split(dns_brute_command)  # prepare it for popen

        # Run the command and get the output
        output = self.run_command(dns_brute_shlex, timeout=timeout)

        # Begin parsing the xml response
        xml_root = self.get_xml_et(output)
        subdomains = self.parser.filter_subdomains(xml_root)
        return subdomains

    def nmap_version_detection(
        self,
        target: str,
        arg: str = "-sV",
        args: typing.Optional[str] = None,
        timeout: typing.Optional[float] = None,
    ) -> typing.Dict[str, typing.Any]:
        """
        Perform nmap scan using the dns-brute script

        :param target: can be IP or domain.
        :param arg: nmap argument for version detection, default is "-sV"
        :param args: additional arguments for the scan
        :param timeout: timeout for the scan command
        :return: A dictionary containing service names and their versions

        Example command line usage:
        ```
        nmap -oX - nmmapper.com --script dns-brute.nse
        ```

        Example usage:
        ```python
        from nmap3 import NmapScanTechniques
        nmap = NmapScanTechniques()

        target = "nmmapper.com"
        arg = "-sV"
        args = "--script-args dns-brute.timeout=5"
        timeout = 10  # seconds
        services = nmap.nmap_version_detection(target, arg, args, timeout)
        print(services)
        ```
        """
        xml_root = self.scan_command(target=target, arg=arg, args=args, timeout=timeout)
        services = self.parser.filter_top_ports(xml_root)
        return services

    # Using of basic options for stealth scan
    @user_is_root
    def nmap_stealth_scan(
        self, target: str, arg: str = "-Pn -sZ", args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Perform nmap's stealth scan on the target

        NOTE: This ``nmap`` scan command requires root/administrator privileges

        :param target: can be IP or domain.
        :param arg: nmap argument for stealth scan, default is "-Pn -sZ"
        :param args: additional arguments for the scan
        :return: List of top ports found on the target

        Example command line usage:
        nmap -oX - nmmapper.com -Pn -sZ
        """
        xml_root = self.scan_command(target=target, arg=arg, args=args)
        self.top_ports = self.parser.filter_top_ports(xml_root)
        return self.top_ports

    def nmap_detect_firewall(
        self, target: str, arg: str = "-sA", args: typing.Optional[str] = None
    ) -> ET.Element:  # requires root
        """
        Perform nmap's firewall detection scan on the target

        :param target: can be IP or domain.
        :param arg: nmap argument for firewall detection, default is "-sA"
        :param args: additional arguments for the scan
        :return: XML ElementTree root element containing the scan results

        Example command line usage:
        ```
        nmap -oX - nmmapper.com -sA
        ```
        """
        return self.scan_command(target=target, arg=arg, args=args)
        # TODO

    @user_is_root
    def nmap_os_detection(
        self, target: str, arg: str = "-O", args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:  # requires root
        """
        Perform nmap's OS detection scan on the target

        NOTE: This ``nmap`` scan command requires root/administrator privileges

        :param target: can be IP or domain.
        :param arg: nmap argument for OS detection, default is "-O"
        :param args: additional arguments for the scan
        :return: Dictionary containing OS information and other details

        Example command line usage:
        ```
        nmap -oX - nmmapper.com -O
        ```
        """
        xml_root = self.scan_command(target=target, arg=arg, args=args)
        results = self.parser.os_identifier_parser(xml_root)
        return results

    def nmap_subnet_scan(
        self, target: str, arg: str = "-p-", args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:  # may require root
        """
        Perform nmap's subnet scan on the target

        NOTE: This ``nmap`` scan command may require root/administrator privileges

        :param target: can be IP or domain.
        :param arg: nmap argument for subnet scan, default is "-p-"
        :param args: additional arguments for the scan
        :return: Dictionary containing open ports found in the specified subnet

        Example command line usage:
        ```
        nmap -oX - nmmapper.com -p-
        ```
        """
        xml_root = self.scan_command(target=target, arg=arg, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_list_scan(
        self, target: str, arg: str = "-sL", args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:  # requires root
        """
        The list scan is a degenerate form of target discovery that simply lists each target of the network(s)
        specified, without sending any packets to the target targets.

        NOTE: /usr/bin/nmap  -oX  -  192.168.178.1/24  -sL

        :param target: can be IP or domain.
        :param arg: nmap argument for list scan, default is "-sL"
        :param args: additional arguments for the scan
        :return: List of targets found in the specified network
        """
        self.target = target
        xml_root = self.scan_command(target=target, arg=arg, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results


class NmapScanTechniques(Nmap):
    """
    Extends `Nmap` to include nmap commands
    with different scan techniques

    These scan techniques include:

    1) TCP SYN Scan (-sS)
    2) TCP connect() scan (-sT)
    3) FIN Scan (-sF)
    4) Ping Scan (-sP)
    5) Idle Scan (-sI)
    6) UDP Scan (-sU)
    7) IP Scan (-sO)
    """

    def __init__(self, path: typing.Optional[str] = None):
        super(NmapScanTechniques, self).__init__(path=path)
        self.sync_scan = "-sS"
        self.tcp_connt = "-sT"
        self.fin_scan = "-sF"
        self.ping_scan = "-sP"
        self.idle_scan = "-sL"
        self.udp_scan = "-sU"
        self.ip_scan = "-sO"
        self.scan_types = {
            self.fin_scan,
            self.sync_scan,
            self.tcp_connt,
            self.ping_scan,
            self.idle_scan,
            self.udp_scan,
            self.ip_scan,
        }

    def scan_command(  # type: ignore[override]
        self,
        scan_type: str,
        target: str,
        args: typing.Optional[str] = None,
        timeout: typing.Optional[float] = None,
    ) -> ET.Element:
        """
        Perform nmap scan using the specified scan type

        :param scan_type: The type of scan to perform (e.g., "-sS", "-sT", etc.)
        :param target: The target to scan (IP address or domain)
        :param args: Additional arguments for the scan
        :param timeout: Timeout for the scan command in seconds
        """
        if scan_type not in self.scan_types:
            raise ValueError(
                f"Invalid scan type: {scan_type}. Valid types are: {self.scan_types}"
            )

        scan = " {target} {default}".format(target=target, default=scan_type)
        scan_type_command = self.default_command() + scan

        if args:
            scan_type_command += " {0}".format(args)

        scan_shlex = shlex.split(scan_type_command)
        output = self.run_command(scan_shlex, timeout=timeout)
        xml_root = self.get_xml_et(output)
        return xml_root

    @user_is_root
    def nmap_fin_scan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Perform scan using nmap's fin scan

        NOTE: This ``nmap`` scan command requires root/administrator privileges

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sF 192.168.178.1
        ```
        """
        xml_root = self.scan_command(self.fin_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    @user_is_root
    def nmap_syn_scan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Perform syn scan on this given target

        NOTE: This ``nmap`` scan command requires root/administrator privileges

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sS 192.168.178.1
        ```
        """
        xml_root = self.scan_command(self.sync_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_tcp_scan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Scan target using the nmap tcp connect

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sT 192.168.178.1
        ```
        """
        if args:
            assert isinstance(args, str), "Expected string got {0} instead".format(
                type(args)
            )
        xml_root = self.scan_command(self.tcp_connt, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    @user_is_root
    def nmap_udp_scan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Scan target using the nmap tcp connect

        NOTE: This ``nmap`` scan command requires root/administrator privileges

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sU 192.168.178.1
        ```
        """

        if args:
            assert isinstance(args, str), "Expected string got {0} instead".format(
                type(args)
            )
        xml_root = self.scan_command(self.udp_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_ping_scan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Scan target using nmap's ping scan

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sP 192.168.178.1
        ```
        """
        xml_root = self.scan_command(self.ping_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_idle_scan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Scan target using nmap's idle scan

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sL 192.168.178.1
        ```
        """
        xml_root = self.scan_command(self.idle_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_ip_scan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Scan target using nmap's ip scan

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sO 192.168.178.1
        ```
        """
        xml_root = self.scan_command(self.ip_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results


class NmapHostDiscovery(Nmap):
    """
    Extends `Nmap` to include nmap commands to perform host discovery

    1) Only port scan    (-Pn)
    2) Only host discover    (-sn)
    3) Arp discovery on a local network  (-PR)
    4) Disable DNS resolution    (-n)
    """

    def __init__(self, path: str = "") -> None:
        super(NmapHostDiscovery, self).__init__(path=path)

        self.port_scan_only = "-Pn"
        self.no_port_scan = "-sn"
        self.arp_discovery = "-PR"
        self.disable_dns = "-n"
        self.scan_types = {
            self.port_scan_only,
            self.no_port_scan,
            self.arp_discovery,
            self.disable_dns,
        }
        self.parser = NmapCommandParser(None)

    def scan_command(  # type: ignore[override]
        self,
        scan_type: str,
        target: str,
        args: typing.Optional[str] = None,
        timeout: typing.Optional[float] = None,
    ) -> ET.Element:
        """
        Perform host discovery scan using the specified scan type

        :param scan_type: The type of scan to perform (e.g., "-Pn", "-sn", etc.)
        :param target: The target to scan (IP address or domain)
        :param args: Additional arguments for the scan
        :param timeout: Timeout for the scan command in seconds
        """
        if scan_type not in self.scan_types:
            raise ValueError(
                f"Invalid scan type: {scan_type}. Valid types are: {self.scan_types}"
            )

        scan = " {target} {default}".format(target=target, default=scan_type)
        scan_type_command = self.default_command() + scan

        if args:
            scan_type_command += " {0}".format(args)

        scan_shlex = shlex.split(scan_type_command)
        output = self.run_command(scan_shlex, timeout=timeout)
        xml_root = self.get_xml_et(output)
        return xml_root

    def nmap_portscan_only(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Scan target using the nmap tcp connect

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -Pn 192.168.178.1
        ```
        """
        xml_root = self.scan_command(self.port_scan_only, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_no_portscan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Scan target using the nmap tcp connect

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sn 192.168.178.1
        ```
        """
        if args:
            assert isinstance(args, str), "Expected string got {0} instead".format(
                type(args)
            )
        xml_root = self.scan_command(self.no_port_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_arp_discovery(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Scan target using the nmap tcp connect

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -PR 192.168.178.1
        ```
        """
        if args:
            assert isinstance(args, str), "Expected string got {0} instead".format(
                type(args)
            )
        xml_root = self.scan_command(self.arp_discovery, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    def nmap_disable_dns(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Scan target using the nmap tcp connect

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -n 192.168.178.1
        ```
        """
        if args:
            assert isinstance(args, str), "Expected string got {0} instead".format(
                type(args)
            )
        xml_root = self.scan_command(self.disable_dns, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results


class NmapAsync(BaseNmap):
    """Implements an interface to allows the use of nmap port scanner tool from within python using asyncio"""

    def __init__(self, path: typing.Optional[str] = None) -> None:
        super(NmapAsync, self).__init__(path=path)
        self.stdout = asyncio.subprocess.PIPE
        self.stderr = asyncio.subprocess.PIPE

    async def run_command(
        self,
        cmd: typing.Union[str, typing.List[str]],
        timeout: typing.Optional[float] = None,
    ) -> str:
        """
        Runs the nmap command using asyncio subprocess

        :param cmd: the command we want run, as a string or list
        :param timeout: command subprocess timeout in seconds.
        :return: The output of the command as a string
        """
        if isinstance(cmd, list):
            cmd = " ".join(cmd)

        # There is possibility of shell injection vulnerabilities due to shell expansion.
        # Especially with unsanitized input or user-provided commands.
        # But, the full shell functionality is needed here,
        # so using `create_subprocess_exec` (safer) is not possible.
        process = await asyncio.create_subprocess_shell(
            cmd, stdout=self.stdout, stderr=self.stderr
        )
        logger.debug(f"Created subprocess with PID {process.pid!r}")
        try:
            data, stderr = await process.communicate()
        except asyncio.TimeoutError:
            await _terminate_asyncio_process(process, timeout=0.2)
            raise NmapTimeoutError(
                'Command timed out after {timeout} seconds: "'.format(timeout=timeout)
                + cmd
                + '"'
            )
        except asyncio.CancelledError:
            await _terminate_asyncio_process(process, timeout=0.2)
            raise  # Re-propagate the CancelledError
        except Exception as e:
            await _terminate_asyncio_process(process, timeout=0.2)
            raise NmapExecutionError(
                'Error during command: "' + cmd + '"\n\n' + str(e)
            ) from e
        else:
            if process.returncode != 0:
                raise NmapExecutionError(
                    'Error during command: "' + cmd + '"\n\n' + stderr.decode("utf-8")
                )

            # Response is bytes so decode the output and return
            return data.decode("utf-8").strip()

    async def scan_command(
        self,
        target: str,
        arg: str,
        args: typing.Optional[str] = None,
        timeout: typing.Optional[float] = None,
    ) -> ET.Element:
        """
        Perform nmap scan using the specified scan type

        :param scan_type: The type of scan to perform (e.g., "-sS", "-sT", etc.)
        :param target: The target to scan (IP address or domain)
        :param args: Additional arguments for the scan
        :param timeout: Timeout for the scan command in seconds
        """
        self.target = target

        command_args = "{target}  {default}".format(target=target, default=arg)
        scancommand = self.default_command() + command_args
        if args:
            scancommand += " {0}".format(args)

        output = await self.run_command(scancommand, timeout=timeout)
        xml_root = self.get_xml_et(output)
        return xml_root

    async def scan_top_ports(
        self,
        target: str,
        default: int = 10,
        args: typing.Optional[str] = None,
        timeout: typing.Optional[float] = None,
    ) -> typing.Dict[str, typing.Any]:
        """
        Perform nmap's top ports scan

        :param target: can be IP or domain
        :param default: is the default top port

        This top port requires root previledges
        """
        if default > self.maxport:
            raise ValueError("Port can not be greater than default 65535")
        self.target = target

        if args:
            assert isinstance(args, str), "Expected string got {0} instead".format(
                type(args)
            )

        top_port_args = " {target} --top-ports {default}".format(
            target=target, default=default
        )
        command = self.default_command() + top_port_args
        if args:
            command += " {0}".format(args)

        output = await self.run_command(command, timeout=timeout)
        if not output:
            # Probaby and error was raise
            raise ValueError("Unable to perform requested command")

        # Begin parsing the xml response
        xml_root = self.get_xml_et(output)
        self.top_ports = self.parser.filter_top_ports(xml_root)
        return self.top_ports

    async def nmap_dns_brute_script(
        self,
        target: str,
        dns_brute: str = "--script dns-brute.nse",
        args: typing.Optional[str] = None,
        timeout: typing.Optional[float] = None,
    ) -> typing.List[typing.Dict[str, typing.Any]]:
        """
        Perform nmap scan using the dns-brute script

        :param target: can be IP or domain.
        :param dns_brute: the dns-brute script to use
        :param args: additional arguments for the scan
        :param timeout: timeout for the scan command
        :return: List of subdomains found by the dns-brute script

        Example usage:
        ```python
        from nmap3 import NmapScanTechniquesAsync

        nmap = NmapScanTechniquesAsync()
        target = "nmmapper.com"
        dns_brute = "--script dns-brute.nse"
        args = "--script-args dns-brute.timeout=5"
        timeout = 10  # seconds
        subdomains = await nmap.nmap_dns_brute_script(target, dns_brute, args, timeout)
        print(subdomains)
        ```
        """
        self.target = target

        dns_brute_args = "{target}  {default}".format(target=target, default=dns_brute)
        dns_brute_command = self.default_command() + dns_brute_args

        if args:
            dns_brute_command += " {0}".format(args)

        # Run the command and get the output
        output = await self.run_command(dns_brute_command, timeout=timeout)

        # Begin parsing the xml response
        xml_root = self.get_xml_et(output)
        subdomains = self.parser.filter_subdomains(xml_root)
        return subdomains

    async def nmap_version_detection(
        self,
        target: str,
        arg: str = "-sV",
        args: typing.Optional[str] = None,
        timeout: typing.Optional[float] = None,
    ) -> typing.Dict[str, typing.Any]:
        """
        Perform nmap scan using the dns-brute script

        :param target: can be IP or domain.
        :param arg: nmap argument for version detection, default is "-sV"
        :param args: additional arguments for the scan
        :param timeout: timeout for the scan command
        :return: List of services and their versions found on the target

        Example command line usage:
        ```
        nmap -oX - nmmapper.com --script dns-brute.nse
        ```

        Example usage:
        ```python
        from nmap3 import NmapScanTechniquesAsync
        nmap = NmapScanTechniquesAsync()

        target = "nmmapper.com"
        arg = "-sV"
        args = "--script-args dns-brute.timeout=5"
        timeout = 10  # seconds
        services = await nmap.nmap_version_detection(target, arg, args, timeout)
        print(services)
        ```
        """
        xml_root = await self.scan_command(
            target=target, arg=arg, args=args, timeout=timeout
        )
        services = self.parser.filter_top_ports(xml_root)
        return services

    # Using of basic options for stealth scan
    @user_is_root
    async def nmap_stealth_scan(
        self, target: str, arg: str = "-Pn -sZ", args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Perform nmap's stealth scan on the target

        NOTE: This ``nmap`` scan command requires root/administrator privileges

        :param target: can be IP or domain.
        :param arg: nmap argument for stealth scan, default is "-Pn -sZ"
        :param args: additional arguments for the scan
        :return: List of top ports found on the target

        Example command line usage:
        ```
        nmap -oX - nmmapper.com -Pn -sZ
        ```
        """
        xml_root = await self.scan_command(target=target, arg=arg, args=args)
        self.top_ports = self.parser.filter_top_ports(xml_root)
        return self.top_ports

    @user_is_root
    async def nmap_os_detection(
        self, target: str, arg: str = "-O", args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:  # requires root
        """
        Perform nmap's os detection on the target

        NOTE: This ``nmap`` scan command requires root/administrator privileges

        :param target: can be IP or domain.
        :param arg: nmap argument for os detection, default is "-O"
        :param args: additional arguments

        Example command line usage:
        ```
        nmap -oX - nmmapper.com -O
        ```
        NOTE: Requires root
        """
        xml_root = await self.scan_command(target=target, arg=arg, args=args)
        results = self.parser.os_identifier_parser(xml_root)
        return results

    async def nmap_subnet_scan(
        self, target: str, arg: str = "-p-", args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:  # may require root
        """
        Scan target using nmap's subnet scan

        NOTE: This ``nmap`` scan command may require root/administrator privileges

        :param target: can be IP or domain.
        :param arg: nmap argument for subnet scan, default is "-p-"
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -oX - nmmapper.com -p-
        ```
        """
        xml_root = await self.scan_command(target=target, arg=arg, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    async def nmap_list_scan(
        self, target: str, arg: str = "-sL", args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        The list scan is a degenerate form of target discovery that simply lists each target of the network(s)
        specified, without sending any packets to the target targets.

        NOTE: /usr/bin/nmap  -oX  -  192.168.178.1/24  -sL

        :param target: can be IP or domain.
        :param arg: nmap argument for list scan, default is "-sL"
        :param args: additional arguments for the scan
        :return: List of targets found in the specified network
        """
        xml_root = await self.scan_command(target=target, arg=arg, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results


class NmapScanTechniquesAsync(NmapAsync):
    """
    Extends `NmapAsync` to include nmap commands
    with different scan techniques

    These scan techniques include:

    1) TCP SYN Scan (-sS)
    2) TCP connect() scan (-sT)
    3) FIN Scan (-sF)
    4) Ping Scan (-sP)
    5) Idle Scan (-sI)
    6) UDP Scan (-sU)
    7) IP Scan (-sO)
    """

    def __init__(self, path: typing.Optional[str] = None):
        super(NmapScanTechniquesAsync, self).__init__(path=path)
        self.sync_scan = "-sS"
        self.tcp_connt = "-sT"
        self.fin_scan = "-sF"
        self.ping_scan = "-sP"
        self.idle_scan = "-sL"
        self.udp_scan = "-sU"
        self.ip_scan = "-sO"
        self.scan_types = {
            self.fin_scan,
            self.sync_scan,
            self.tcp_connt,
            self.ping_scan,
            self.idle_scan,
            self.udp_scan,
            self.ip_scan,
        }

    async def scan_command(  # type: ignore[override]
        self,
        scan_type: str,
        target: str,
        args: typing.Optional[str] = None,
        timeout: typing.Optional[float] = None,
    ) -> ET.Element:
        """
        Perform nmap scan using the specified scan type

        :param scan_type: The type of scan to perform (e.g., "-sS", "-sT", etc.)
        :param target: The target to scan (IP address or domain)
        :param args: Additional arguments for the scan
        :param timeout: Timeout for the scan command in seconds
        """
        if scan_type not in self.scan_types:
            raise ValueError(
                f"Invalid scan type: {scan_type}. Valid types are: {self.scan_types}"
            )

        scan = " {target} {default}".format(target=target, default=scan_type)
        scan_type_command = self.default_command() + scan

        if args:
            scan_type_command += " {0}".format(args)

        output = await self.run_command(scan_type_command, timeout=timeout)
        xml_root = self.get_xml_et(output)
        return xml_root

    async def nmap_udp_scan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Scan target using the nmap tcp connect

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sU 192.168.178.1
        ```
        """
        if args:
            assert isinstance(args, str), "Expected string got {0} instead".format(
                type(args)
            )
        xml_root = await self.scan_command(self.udp_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    @user_is_root
    async def nmap_fin_scan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Perform scan using nmap's fin scan

        NOTE: This ``nmap`` scan command requires root/administrator privileges

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sF 192.168.178.1
        ```
        """
        xml_root = await self.scan_command(self.fin_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    @user_is_root
    async def nmap_syn_scan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Perform syn scan on this given target

        NOTE: This ``nmap`` scan command requires root/administrator privileges

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sS 192.168.178.1
        ```
        """
        xml_root = await self.scan_command(self.sync_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    async def nmap_tcp_scan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Scan target using the nmap tcp connect

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sT 192.168.178.1
        ```
        """
        if args:
            assert isinstance(args, str), "Expected string got {0} instead".format(
                type(args)
            )
        xml_root = await self.scan_command(self.tcp_connt, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    async def nmap_ping_scan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Scan target using nmap's ping scan

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sP 192.168.178.1
        ```
        """
        xml_root = await self.scan_command(self.ping_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    async def nmap_idle_scan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Scan target using nmap's idle scan

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sL 192.168.178.1
        ```
        """
        xml_root = await self.scan_command(self.idle_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results

    async def nmap_ip_scan(
        self, target: str, args: typing.Optional[str] = None
    ) -> typing.Dict[str, typing.Any]:
        """
        Scan target using nmap's ip scan

        :param target: can be IP or domain.
        :param args: additional arguments for the scan
        :return: A dictionary of open ports found on the target

        Example command line usage:
        ```
        nmap -sO 192.168.178.1
        ```
        """
        xml_root = await self.scan_command(self.ip_scan, target=target, args=args)
        results = self.parser.filter_top_ports(xml_root)
        return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Python3 nmap")
    parser.add_argument("-d", "--target", help="Target IP or domain", required=True)
    args = parser.parse_args()

    nmap = NmapScanTechniquesAsync()
    # asyncio.run() wont work in the lowest python version supported `3.6`
    # asyncio.run(nmap.nmap_udp_scan(target="127.0.0.1"))
    loop = asyncio.get_event_loop()
    try:
        result = loop.run_until_complete(nmap.nmap_udp_scan(target=args.target))
        print(result)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        loop.close()
