"""Implements an improved AtiSignature class with more helpers"""
import json
import logging

from lib.cuckoo.common.abstracts import Signature

LOG = logging.getLogger(__name__)


class AtiSignature(Signature):
    """Improved signature class with more helpers than what Cuckoo provides"""

    current_call_pretty_value_cache = None
    _current_call_pretty_value_dict = None
    ttp_urls = []
    ati_ttps = []
    possible_marks = []
    markcount = 50

    # List of safe processes
    safelistprocs = [
        "iexplore.exe",
        "firefox.exe",
        "chrome.exe",
        "safari.exe",
        "acrord32.exe",
        "acrord64.exe",
        "wordview.exe",
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "mspub.exe",
    ]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    def temp_mark_call(self):
        mark = {
            "type": "call",
            "pid": self.pid,
            "cid": self.cid,
            "call": self.call,
        }

        self.possible_marks.append(mark)

    def has_suricata_sids(self, *match_sids):
        """Returns true if all sids appear in the alerts"""
        alerts = self.get_results("suricata", {}).get("alerts", [])
        sids = [x.get("sid", "") for x in alerts]

        return all(x in sids for x in match_sids)

    def has_either_suricata_sids(self, *match_sids):
        """Returns true if either of the sids appears in the alers"""
        alerts = self.get_results("suricata", {}).get("alerts", [])
        sids = [x.get("sid", "") for x in alerts]

        return any(x in sids for x in match_sids)

    def get_pretty_value(self, call, name):
        """Retrieves the pretty_value of a specific argument from an API call.
        @param call: API call object.
        @param name: name of the argument to retrieve.
        @return: pretty_value of the required argument.
        """
        # Check if the call passed to it was cached already.
        # If not, we can start caching it and store a copy converted to a dict.
        if call is not self.current_call_pretty_value_cache:
            self.current_call_pretty_value_cache = call
            self._current_call_pretty_value_dict = {
                argument["name"]: argument["pretty_value"] for argument in call["arguments"] if "pretty_value" in argument
            }

        # Return the required argument.
        if name in self._current_call_pretty_value_dict:
            return self._current_call_pretty_value_dict[name]

        return None

    def mark_ioc(self, category, ioc, description=None):
        """Mark an IOC as explanation as to why the current signature
        matched."""
        mark = {
            "type": "ioc",
            "category": category,
            "ioc": ioc,
            "description": description,
        }

        # Prevent duplicates.
        if mark not in self.data:
            self.data.append(mark)

    def mark_config(self, config):
        """Mark configuration from this malware family."""
        if not isinstance(config, dict) or "family" not in config:
            raise CuckooCriticalError("Invalid call to mark_config().")

        self.data.append(
            {
                "type": "config",
                "config": config,
            }
        )

    def mark(self, **kwargs):
        """Mark arbitrary data."""
        mark = {
            "type": "generic",
        }
        mark.update(kwargs)
        self.data.append(mark)

    def has_marks(self, count=None):
        """Returns true if this signature has one or more marks."""
        if count is not None:
            return len(self.data) >= count
        self.mark_mitre()
        return not not self.data

    def mark_mitre(self):
        ttp_urls = []
        if self.ati_ttps and self.description.startswith("ATI"):
            self.description += " | MITRE ATT&CK Technique IDs: "
            for t in self.ati_ttps:
                ttp_urls.append("https://attack.mitre.org/techniques/" + t + "/")
                self.description += t + ", "

    def get_summary(self, key=None, default=[]):
        """Get one or all values related to the global summary."""
        summary = self.get_results("behavior", {}).get("summary", {})
        return summary.get(key, default) if key else summary

    def get_wmi_queries(self):
        """Retrieves all executed WMI queries."""
        return self.get_summary("wmi_query")


class AtiSuricataSignature(AtiSignature):
    """Signature that relies only on Suricata SIDs to identify malware and C&Cs.
    Set the _client_sids and _server_sids attributes in init() as int arrays of SIDs for traffic.
    Set _malware_type and _malware_family as strings used to describe the malware.
    By default, default init() sets them as empty arrays for safety in case you forget to overload.
    """

    def __init__(self, *args, **kwargs):
        """OVERLOAD THIS!!! Set _client_sids and _server_sids as empty arrays for safety."""
        # print('AICI SE INITIALIZEAZA ATI SURICATA')
        self._client_sids = []
        self._server_sids = []
        self._malware_type = None
        self._malware_family = None
        Signature.__init__(self, *args, **kwargs)
        AtiSignature.__init__(self, *args, **kwargs)

    def get_suricata_sids(self):
        sids_ips = {}
        for alert in self.results.get("suricata", {}).get("alerts", []):
            sid = alert.get("sid", 0)
            src_ip = alert.get("srcip")
            dst_ip = alert.get("dstip")
            domains = self.results["network"].get("domains")
            # domain_list = []
            # for domain in self.results.get("domains",{}):
            #    if domain['ip'] in [src_ip,dst_ip]:
            #        domain_list.append(domain['domain'])
            url = ""  # NEED TO ADD THIS
            ips_for_sid = sids_ips.get(sid, [])
            ips_for_sid.append((src_ip, dst_ip, domains, url))
            sids_ips[sid] = ips_for_sid
        return sids_ips

    def on_complete(self):
        """Returns True/False depending on any client and/or server hits. marks IOCs - IP address, ati_malware_type, ati_malware_family"""

        # order Suricata info as {SID:[(server_ip, client_ip, domain, url)]}

        """
		alerts = self.get_results('suricata', {}).get('alerts', [])
		sids_ips = {}
		for x in alerts:
			sid = x.get('sid', '')
			src_ip = x.get('src_ip')
			dst_ip = x.get('dst_ip')
			domain_list = []
			domains = self.get_results('network', {}).get('domains', [])
			for domain in domains:
				if domain['ip'] in [src_ip,dst_ip]:
					domain_list.append(domain['domain'])
			domain = domain_list
			url = x.get('http', {}).get('url')

			ips_for_sid = sids_ips.get(sid, [])
			ips_for_sid.append((src_ip, dst_ip, domain, url))

			sids_ips[sid] = ips_for_sid
		"""
        # print("AICI INCEPE IN COMPLETE SURICATA")
        sids_ips = self.get_suricata_sids()
        # print(sids_ips)
        has_results = False

        for server_sid in self._server_sids:
            for server_ip, _, domain, url in sids_ips.get(server_sid, []):
                # matched a C&C server
                LOG.info("%s/%s C&C Server Identified!" % (self._malware_type, self._malware_family))
                # TODO/AH: pointless right now since we can't safely and correctly match to Cuckoo's mapping of fields
                # extraction was done based on Suricata eve.json hierarchy but Cuckoo maps it differently and
                # it's hard to certainly say which flow/hostname/url are involved without risking FPs.
                self.mark_ioc("ip", server_ip, description=json.dumps({"domain": domain, "url": url}))
                self.mark_ioc("ati_malware_type", self._malware_type)
                self.mark_ioc("ati_malware_family", self._malware_family)
                has_results = True
                self.mark_config(
                    {"family": self._malware_family, "cnc": "%s" % (server_ip), "type": self._malware_type, "domains": domain}
                )

        for client_sid in self._client_sids:
            for _, _, _, _ in sids_ips.get(client_sid, []):
                # no C&C server but we did the check-in so mark the binary
                LOG.info("%s/%s Binary Identified!" % (self._malware_type, self._malware_family))
                self.mark_ioc("ati_malware_type", self._malware_type)
                self.mark_ioc("ati_malware_family", self._malware_family)
                has_results = True
                self.mark_config({"family": self._malware_family, "type": self._malware_type})

        return has_results
