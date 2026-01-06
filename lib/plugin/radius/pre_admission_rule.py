import abc
import re

import paramiko as paramiko

DEFAULT_CONDITION_LOOP_UP = "config.defpol_cond1.value="
DEFAULT_LOCAL_PROPERTY_FILE_PATH = "/usr/local/forescout/plugin/dot1x/local.properties"


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
    def return_admission_rule_entry(self, rule_dict):
        raise NotImplementedError


class D1XMSCACheckboxListCriterion(D1xOption):
    def return_admission_rule_entry(self, rule_dict):
        raise NotImplementedError


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


def to_file(new_entry_string, ca, file_path=DEFAULT_LOCAL_PROPERTY_FILE_PATH, lookup=DEFAULT_CONDITION_LOOP_UP):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ca.ipaddress, username=ca.username, password=ca.password)

    try:
        sftp = ssh.open_sftp()
        # Read the file from the remote host
        with sftp.open(file_path, "r") as file:
            lines = file.readlines()

        # Modify the file content
        for i, line in enumerate(lines):
            if line.startswith(lookup):
                match = re.search(r"=(\[.*\])", line)
                if match:
                    lines[i] = ("%s%s\n") % (lookup, new_entry_string)
                break

        # Write the updated content back to the remote file
        with sftp.open(file_path, "w") as file:
            file.writelines(lines)

    finally:
        sftp.close()
        ssh.close()


def edit_pre_admission_rule(rules, ca):
    """Set pre-admission rules on a remote RADIUS server.
    Args:
        rules: list: List of pre-admission rules to set.
        ie. [{'rule_name': 'Tunneled-User-Name', 'fields': ['matches expression', 'expression_value']},
            {'rule_name': 'NAS-IP-Address', 'fields': ['matches', '192.168.1.1']},
            {'rule_name': 'NAS-Port-Type', 'fields': ['Ethernet']}]
    """
    # backdoor to write in plain message line (not recommended)
    if len(rules) == 1 and rules[0]["rule_name"] == "Plain":
        to_file(rules[0]["fields"][0])
        return
    context = Context()
    new_entry_string = context.get_line(rules)
    to_file(new_entry_string, ca)
