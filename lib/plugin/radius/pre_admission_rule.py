import abc
import re
from contextlib import suppress
from typing import Any, Dict, List

import paramiko as paramiko

from framework.log.logger import log

DEFAULT_CONDITION_LOOP_UP = "config.defpol_cond1.value="
DEFAULT_LOCAL_PROPERTY_FILE_PATH = "/usr/local/forescout/plugin/dot1x/local.properties"
DEFAULT_CONDITION_LOOKUP_PREFIX = "config.defpol_cond"  # support for _lookup_for_slot()


class D1xOption(abc.ABC):
    @abc.abstractmethod
    def return_admission_rule_entry(self, rule_dict):
        pass


class D1XComboStringCriterion(D1xOption):
    base_entry = (
        '"field":"%s","value":"%s","critClass":"forescout.plugin.dot1x.default_policy.D1XComboStringCriterion","selected":"%s"'
    )

    def return_admission_rule_entry(self, rule_dict):
        option = rule_dict["rule_name"]
        selected = rule_dict["fields"][0]
        return self.base_entry % (option, selected, selected)


class D1XStringCriterion(D1xOption):
    map = {
        "startswith": '"filType":"startswith","input":"%s","field":"%s","value":"\\\\\\\\Q%s\\\\\\\\E.*","critClass":"forescout.plugin.dot1x.default_policy.D1XStringCriterion"',
        "endswith": '"filType":"endswith","input":"%s","field":"%s","value":".*\\\\\\\\Q%s\\\\\\\\E","critClass":"forescout.plugin.dot1x.default_policy.D1XStringCriterion"',
        "contains": '"filType":"contains","input":"%s","field":"%s","value":".*\\\\\\\\Q%s\\\\\\\\E.*","critClass":"forescout.plugin.dot1x.default_policy.D1XStringCriterion"',
        "matches": '"filType":"equals","input":"%s","field":"%s","value":"\\\\\\\\Q%s\\\\\\\\E","critClass":"forescout.plugin.dot1x.default_policy.D1XStringCriterion"',
        "matchesexpression": '"filType":"regexp","input":"%s","field":"%s","value":"%s","critClass":"forescout.plugin.dot1x.default_policy.D1XStringCriterion"',
        "anyvalue": '"filType":"any","input":"","field":"%s","value":".*","critClass":"forescout.plugin.dot1x.default_policy.D1XStringCriterion"',
    }

    def return_admission_rule_entry(self, rule_dict):
        if rule_dict["fields"][0].lower().replace(" ", "") not in self.map:
            raise Exception("Invalid match type: %s" % rule_dict["fields"][0])
        if rule_dict["fields"][0].lower().replace(" ", "") == "anyvalue":
            return self.map["anyvalue"] % (rule_dict["rule_name"])
        return self.map[rule_dict["fields"][0].lower().replace(" ", "")] % (
            rule_dict["fields"][1],
            rule_dict["rule_name"],
            rule_dict["fields"][1],
        )


class D1XSimpleStringCriterion(D1xOption):
    def return_admission_rule_entry(self, rule_dict):
        raise NotImplementedError


class D1XEKUCheckboxListCriterion(D1xOption):
    """UI EKU checkbox list criteria as implemented in local.properties."""

    base_entry = (
        '"field":"%s","value":"%s",'
        '"critClass":"forescout.plugin.dot1x.default_policy.D1XEKUCheckboxListCriterion",'
        '"selected":"%s"'
    )

    def return_admission_rule_entry(self, rule_dict: Dict[str, Any]) -> str:
        field = rule_dict["rule_name"]
        entries = rule_dict.get("fields", [])
        if not entries:
            raise Exception("EKU criterion requires at least one entry")

        joined = ",".join(entries)
        if not joined.endswith(","):
            joined = joined + ","  # UI/plugin stores trailing comma

        return self.base_entry % (field, joined, joined)


class D1XMSCACheckboxListCriterion(D1xOption):
    """UI MSCA checkbox list criteria as implemented in local.properties."""

    base_entry = '"field":"%s","value":"%s","critClass":"forescout.plugin.dot1x.default_policy.D1XMSCACheckboxListCriterion","selected":"%s"'

    def return_admission_rule_entry(self, rule_dict: Dict[str, Any]) -> str:
        field = rule_dict["rule_name"]
        entries = rule_dict.get("fields", [])
        if not entries:
            raise Exception("MSCA criterion requires at least one entry")

        joined = ",".join(entries)
        if not joined.endswith(","):
            joined = joined + ","  # UI/plugin stores trailing comma

        return self.base_entry % (field, joined, joined)


class D1XTimeRestrictionsCriterion(D1xOption):
    def return_admission_rule_entry(self, rule_dict):
        raise NotImplementedError


class D1XBooleanCriterion(D1xOption):
    def return_admission_rule_entry(self, rule_dict):
        raise NotImplementedError


class Context:
    combo_string_set = ["NAS-Port-Type", "EAP-Type", "Tunneled-Method", "Authentication-Type"]
    string_set = [
        "User-Name",
        "Tunneled-User-Name",
        "Calling-Station-ID",
        "Called-Station-ID",
        "SSID",
        "NAS-Identifier",
        "NAS-IP-Address",
        "NAS-IPv6-Address",
        "Certificate-Issuer",
        "Certificate-Common-Name",
        "Certificate-Subject",
        "Certificate-Subject-Alternate-Name-Email",
        "Certificate-Subject-Alternative-Name",
        "Certificate-EAP-TLS-Certificate-Template",
        "MAR Comment",
    ]
    simple_string_set = ["LDAP-Group"]
    ku_checkbox_set = ["Certificate-Extended-Key-Usage"]
    sca_checkbox_set = ["Certificate-MS-Certificate-Authority"]
    time_restriction_set = ["Day and Time Restriction"]
    boolean_set = ["MAC Found in MAR"]

    def get_handler(self, rule):
        if rule["rule_name"] in self.combo_string_set:
            return D1XComboStringCriterion()
        if rule["rule_name"] in self.string_set:
            return D1XStringCriterion()
        if rule["rule_name"] in self.simple_string_set:
            return D1XSimpleStringCriterion()
        if rule["rule_name"] in self.ku_checkbox_set:
            return D1XEKUCheckboxListCriterion()
        if rule["rule_name"] in self.sca_checkbox_set:
            return D1XMSCACheckboxListCriterion()
        if rule["rule_name"] in self.time_restriction_set:
            return D1XTimeRestrictionsCriterion()
        if rule["rule_name"] in self.boolean_set:
            return D1XBooleanCriterion()
        raise Exception("%s does not match any existing options" % rule["rule_name"])

    def get_rule(self, rule):
        handler = self.get_handler(rule)
        if not handler:
            raise Exception("no handler for rule %s" % rule["rule_name"])
        return "{%s}" % (handler.return_admission_rule_entry(rule))

    def get_line(self, rules):
        res = []
        for rule in rules:
            entry = self.get_rule(rule)
            res.append(entry)
        return "[" + ",".join(res) + "]"


def _lookup_for_slot(condition_slot: int) -> str:
    if not isinstance(condition_slot, int) or condition_slot < 1:
        raise ValueError("condition_slot must be an int >= 1")
    return f"{DEFAULT_CONDITION_LOOKUP_PREFIX}{condition_slot}.value="


def to_file(new_entry_string: str, node, file_path: str = DEFAULT_LOCAL_PROPERTY_FILE_PATH, lookup: str = None):
    if lookup is None:
        lookup = _lookup_for_slot(1)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(node.ipaddress, username=node.username, password=node.password)

    try:
        sftp = ssh.open_sftp()

        with sftp.open(file_path, "r") as file:
            lines = file.readlines()

        for i, line in enumerate(lines):
            if line.startswith(lookup):
                lines[i] = f"{lookup}{new_entry_string}\n"
                break
        else:
            lines.append(f"{lookup}{new_entry_string}\n")

        with sftp.open(file_path, "w") as file:
            file.writelines(lines)
    finally:
        sftp.close()
        ssh.close()




def edit_pre_admission_rule(rules: List[Dict[str, Any]], node, condition_slot: int = 1):
    """
    Set pre-admission rules by editing config.defpol_cond{slot}.value in local.properties.
    """
    if len(rules) == 1 and rules[0].get("rule_name") == "Plain":
        to_file(rules[0]["fields"][0], node, lookup=_lookup_for_slot(condition_slot))
        return

    context = Context()
    new_entry_string = context.get_line(rules)
    to_file(new_entry_string, node, lookup=_lookup_for_slot(condition_slot))


def set_pre_admission_rules_remote(
    rules: List[Dict[str, Any]],
    node,
    file_path: str = DEFAULT_LOCAL_PROPERTY_FILE_PATH,
    max_slots: int = 10,
) -> None:
    """
    rules example (recommended):
      [
        {"cond_rules": [<your rule dicts>], "auth": "vlan:\tIsCOA:false"},
        {"cond_rules": [<your rule dicts>], "auth": "reject=dummy"},
      ]

    Also supports:
      {"cond": "<already-built string>", "auth": "<auth>"}
    """
    ctx = Context()

    kv: Dict[str, str] = {}
    kv["config.defpol.size.value"] = str(len(rules))

    log.info(f"Building pre-admission rules: {len(rules)} rule(s)")
    for idx, r in enumerate(rules, start=1):
        cond_key = f"config.defpol_cond{idx}.value"
        auth_key = f"config.defpol_auth{idx}.value"

        if "cond" in r and r["cond"] is not None:
            cond_val = r["cond"]
        else:
            cond_rules = r.get("cond_rules") or r.get("rules")
            if not cond_rules:
                raise ValueError(f"rule {idx} missing 'cond' or 'cond_rules'")
            cond_val = ctx.get_line(cond_rules)

        auth_val = r.get("auth")
        if auth_val is None:
            raise ValueError(f"rule {idx} missing 'auth'")

        log.info(f"Rule {idx}: condition={cond_val}")
        log.info(f"Rule {idx}: auth={auth_val}")
        kv[cond_key] = cond_val
        kv[auth_key] = auth_val

    # Note: We don't clear stale slots with empty values as this can confuse the plugin
    # The size.value tells the plugin how many rules to read

    _to_file_multi(kv, node, file_path=file_path)


def _to_file_multi(kv: Dict[str, str], node, file_path: str = DEFAULT_LOCAL_PROPERTY_FILE_PATH) -> None:
    """
    Remote upsert multiple 'key=value' entries in local.properties in ONE SSH/SFTP session.
    Preserves other lines and comments.
    """
    log.info(f"Writing {len(kv)} key-value pairs to {file_path} on {node.ipaddress}")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(node.ipaddress, username=node.username, password=node.password)

    sftp = None
    try:
        sftp = ssh.open_sftp()

        with sftp.open(file_path, "r") as f:
            lines = f.readlines()

        # index existing keys -> line index
        key_to_idx: Dict[str, int] = {}
        for i, line in enumerate(lines):
            if not line or line.lstrip().startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_.]+)\s*=\s*(.*)$", line)
            if m:
                key_to_idx[m.group(1)] = i

        def upsert(key: str, value: str) -> None:
            new_line = f"{key}={value}\n"
            if key in key_to_idx:
                lines[key_to_idx[key]] = new_line
            else:
                key_to_idx[key] = len(lines)
                lines.append(new_line)

        for k, v in kv.items():
            upsert(k, v)

        with sftp.open(file_path, "w") as f:
            f.writelines(lines)

        log.info(f"Successfully wrote pre-admission rules to {file_path}")

        # Verify what was written by reading back the relevant keys
        with sftp.open(file_path, "r") as f:
            written_lines = f.readlines()

        for line in written_lines:
            line = line.strip()
            if line.startswith("config.defpol"):
                log.info(f"  Verified: {line[:200]}")

    finally:
        with suppress(Exception):
            if sftp:
                sftp.close()
        with suppress(Exception):
            ssh.close()
