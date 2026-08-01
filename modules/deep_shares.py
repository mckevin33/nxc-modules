# deep_shares.py - walk the readable shares and report which user or group has WRITE
# on which path, straight from the NTFS DACL.
#
# Give it SIDs/names to hunt, or nothing to list every non-admin principal. It reports
# the NTFS grant; the share-level permission can still cap it (e.g. NETLOGON), and a
# grant to someone other than you can't be verified over SMB. Pass VERIFY to keep only
# the paths you can really write, confirmed with a create+delete probe.
#
#   nxc smb <targets> -u user -p pass -M deep_shares
#   nxc smb <targets> -u user -p pass -M deep_shares -o SIDS=dev,helpdesk
#   nxc smb <targets> -u user -p pass -M deep_shares -o SHARE=SYSVOL,NETLOGON
#   nxc smb <targets> -u user -p pass -M deep_shares -o VERIFY=true
#   nxc smb <targets> -u user -p pass -M deep_shares -o ALL_SHARES=true

import os
from contextlib import suppress
from io import BytesIO

from impacket.smb3structs import (
    READ_CONTROL, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE,
    FILE_OPEN, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, SMB2_0_INFO_SECURITY,
    FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_DELETE_CHILD, DELETE,
    WRITE_DAC, WRITE_OWNER, GENERIC_WRITE, GENERIC_ALL,
)
from impacket.ldap.ldaptypes import (
    SR_SECURITY_DESCRIPTOR, ACE, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE,
)
from impacket.dcerpc.v5 import lsad, lsat, srvs, transport
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.srvs import STYPE_MASK, STYPE_DISKTREE, STYPE_SPECIAL
from nxc.helpers.misc import CATEGORY

# Derived from impacket constants; these two have no single impacket symbol.
FILE_SHARE_ALL = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
SEC_OWNER_GROUP_DACL = 0x07                 # OWNER|GROUP|DACL security-information flags
FILE_ALL_ACCESS = 0x001F01FF                # file "Full control" mask (not exposed by impacket)

INHERITED_ACE = ACE.INHERITED_ACE
ACCESS_ALLOWED_TYPES = (ACCESS_ALLOWED_ACE.ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE)
WRITE_MASK_ANY = (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE
                  | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL)

MAX_DEPTH = 5                # default recursion cap below each share root (override with DEPTH)
LSA_USE_UNRESOLVED = (7, 8)  # SID_NAME_USE: SidTypeInvalid / SidTypeUnknown

# Names for SIDs that are not AD objects (LDAP/LSA won't resolve these).
WELL_KNOWN_SIDS = {
    "S-1-1-0": "Everyone", "S-1-3-0": "CREATOR OWNER", "S-1-5-7": "Anonymous Logon",
    "S-1-5-9": "Enterprise Domain Controllers", "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "NT AUTHORITY\\SYSTEM", "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE", "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users", "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-548": "BUILTIN\\Account Operators", "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators", "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
}
# In "everyone" mode (no SIDS given) these expected/privileged holders are hidden as
# noise; hunt one explicitly via SIDS to include it.
ADMIN_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-3-0", "S-1-5-9",
              "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551"}
ADMIN_RID_SUFFIXES = ("-512", "-519", "-518", "-516", "-517", "-521", "-498", "-500", "-502")


class NXCModule:
    """Environment-wide audit of which principal can write where (from the DACL)."""

    name = "deep_shares"
    description = "Audit accessible shares and report which user/group has WRITE on which path"
    category = CATEGORY.ENUMERATION
    supported_protocols = ["smb"]
    opsec_safe = True       # read-only by default; VERIFY creates+deletes a temp file
    multiple_hosts = True

    # -------------------------------------------------------------------------------
    def options(self, context, module_options):
        """
        SIDS        Principals to hunt: comma-separated SIDs and/or names (default: all non-admin)
        SHARE       Shares to scan: comma-separated (default: all readable, minus admin shares C$/ADMIN$)
        FILES       Also inspect file ACLs, not just directories (default: false)
        VERIFY      Keep only paths you can really write, confirmed by a temp-file write (default: false)
        ALL_SHARES  Also scan admin shares C$/ADMIN$/drive letters - huge & slow (default: false)
        DEPTH       How deep to recurse below each share root (default: 5)
        """
        raw = module_options.get("SIDS")
        self.hunt_sids, self.hunt_names, self.hunt_all = set(), [], False
        if not raw or raw.strip().lower() in ("*", "all"):
            self.hunt_all = True
        else:
            for tok in raw.split(","):
                tok = tok.strip()
                if not tok:
                    continue
                if tok.upper().startswith("S-1-"):
                    self.hunt_sids.add(tok)
                else:
                    self.hunt_names.append(tok)

        share = module_options.get("SHARE")
        self.shares_opt = [s.strip() for s in share.split(",") if s.strip()] if share else None
        self.files = module_options.get("FILES", "").lower() in ("true", "1", "yes")
        self.verify = module_options.get("VERIFY", "").lower() in ("true", "1", "yes")
        self.all_shares = module_options.get("ALL_SHARES", "").lower() in ("true", "1", "yes")
        self.depth = int(module_options.get("DEPTH", MAX_DEPTH))

    # -------------------------------------------------------------------------------
    def on_login(self, context, connection):
        self.host = connection.host
        self.conn = connection
        self._names = {}
        self._rpc_setup(context)

        try:
            hunt = set(self.hunt_sids)
            for name in self.hunt_names:
                sid = self._name_to_sid(context, name)
                if sid:
                    hunt.add(sid)
                else:
                    context.log.fail(f"could not resolve name '{name}' to a SID")
            self.hunt = hunt

            shares = self._select_shares(context)
            if not shares:
                context.log.fail("no shares to scan")
                return

            rows = []
            for share in shares:
                self._scan_share(context, share, rows)
            if self.verify:
                rows = self._verify_writes(context, rows)
            self._print_table(context, rows)
        finally:
            self._rpc_teardown()

    # =============================================================================== #
    #  Scan (per-share invariants kept as instance state, not threaded through args)  #
    # =============================================================================== #
    def _select_shares(self, context):
        # connection.shares() is the nxc idiom, but it prints the full --shares
        # table as a side effect; we keep the output clean and probe read access here.
        if self.shares_opt:
            return self.shares_opt
        readable = []
        try:
            for entry in self.conn.conn.listShares():
                name = entry["shi1_netname"].rstrip("\x00")
                stype = entry["shi1_type"]
                # Classify by the server's own share type (same fields nxc's smb.py reads):
                # non-DISKTREE -> not a filesystem share; STYPE_SPECIAL -> C$/ADMIN$/drive letters.
                if not name or (stype & STYPE_MASK) != STYPE_DISKTREE:
                    continue                       # IPC$, print queue, device - never walkable
                if not self.all_shares and (stype & STYPE_SPECIAL):
                    context.log.debug(f"skipping admin share {name} (pass ALL_SHARES=true to include)")
                    continue
                with suppress(Exception):
                    self.conn.conn.listPath(name, "*")
                    readable.append(name)
        except Exception as e:
            context.log.fail(f"listing shares failed ({self._err(e)})")
        context.log.debug(f"readable shares -> {', '.join(readable) or '(none)'}")
        return readable

    def _scan_share(self, context, share, rows):
        self.smb = self.conn.conn.getSMBServer()   # low-level SMB3 (only path to read a file SD)
        self.share = share
        try:
            self.tid = self.smb.connectTree(share)
        except Exception as e:
            context.log.fail(f"cannot open share {share} ({self._err(e)})")
            return
        # Share-level rights (admin-gated): used to drop grants the share caps. None when
        # unreadable - there is no usable fallback (the root-NTFS proxy would false-negative
        # deep grants like SYSVOL\scripts), so we simply don't confirm on the low-priv path.
        self.share_acl = self._read_share_acl(context, share)
        context.log.debug(f"{share} share-rights = {'server SD' if self.share_acl is not None else 'unavailable'}")
        try:
            self._walk(context, "", 0, rows, frozenset())
        finally:
            with suppress(Exception):
                self.smb.disconnectTree(self.tid)

    def _walk(self, context, base, depth, rows, parent_writers):
        # parent_writers = SIDs an ancestor already grants write to; used to collapse
        # subdirectories that merely inherit that grant, so the table stays readable.
        writers = self._report_object(context, base, rows, parent_writers, is_dir=True)
        if depth >= self.depth:
            return
        try:
            entries = self.conn.conn.listPath(self.share, (base + "\\*") if base else "*")
        except Exception as e:
            context.log.debug(f"cannot list \\{base} in {self.share} ({self._err(e)})")
            return
        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            child = (base + "\\" + name) if base else name
            if entry.is_directory():
                self._walk(context, child, depth + 1, rows, writers)
            elif self.files:
                # Collapse against THIS dir's grants (writers): a file that merely inherits
                # the directory grant is hidden; only files with their own explicit ACE show.
                self._report_object(context, child, rows, writers, is_dir=False)

    def _report_object(self, context, path, rows, parent_writers, is_dir=True):
        """Append a row for each hunted principal that has write here. Returns the set of
        write-granted SIDs on this object (union with ancestors, for collapse).
        """
        grants = self._write_grants(context, path, is_dir)
        if grants is None:
            return parent_writers
        writers = set(parent_writers) | set(grants.keys())
        for sid, rec in grants.items():
            # Collapse a grant merely inherited from an already-seen ancestor.
            if sid in parent_writers and not rec["explicit"]:
                continue
            # Effective confirmation: drop grants the share level denies write to (only
            # possible when we could read the real server share SD - admin).
            if self.share_acl is not None and not self._share_allows_write(self.share_acl, sid):
                continue
            rows.append({
                "principal": self._name(context, sid),
                "rights": self._rights_label(rec["mask"]),
                "share": self.share, "path": path, "is_dir": is_dir,
            })
        return writers

    def _verify_writes(self, context, rows):
        """VERIFY mode: keep only rows on directories the CURRENT user can really write
        (create + delete a temp file). Removes share-capped false positives (e.g.
        NETLOGON). Confirms YOUR access, not the listed principal's - the only thing
        checkable over SMB without being them.
        """
        cache, kept = {}, []
        for r in rows:
            if not r.get("is_dir", True):
                kept.append(r)                  # never write over a file; keep as-is
                continue
            key = (r["share"], r["path"])
            if key not in cache:
                cache[key] = self._can_write(r["share"], r["path"])
            if cache[key]:
                kept.append(r)
        dropped = len(rows) - len(kept)
        if dropped:
            context.log.debug(f"VERIFY removed {dropped} row(s) not writable by the current user")
        return kept

    def _can_write(self, share, dir_path):
        """Write test: create a tiny temp file in dir_path, then delete it."""
        name = ((dir_path + "\\") if dir_path else "") + f"_acltest_{os.urandom(4).hex()}.tmp"
        try:
            self.conn.conn.putFile(share, name, BytesIO(b"acltest").read)
        except Exception:
            return False
        with suppress(Exception):
            self.conn.conn.deleteFile(share, name)      # best-effort cleanup
        return True

    def _write_grants(self, context, path, is_dir):
        """Return {sid: {mask, explicit}} for hunted principals that have write here,
        or None on read failure.
        """
        try:
            sd = self._read_dacl(path, is_dir)
        except Exception as e:
            context.log.debug(f"cannot read ACL of \\{path} in {self.share} ({self._err(e)})")
            return None
        if sd["Dacl"] is None:               # NULL DACL == everyone full control
            return {"S-1-1-0": {"mask": FILE_ALL_ACCESS, "explicit": True}}
        agg = {}
        for sid, mask, inherited in _iter_allow_aces(sd):
            if not (mask & WRITE_MASK_ANY) or not self._hunt_match(sid):
                continue
            rec = agg.setdefault(sid, {"mask": 0, "explicit": False})
            rec["mask"] |= mask
            if not inherited:
                rec["explicit"] = True
        return agg

    def _read_dacl(self, path, is_dir):
        """create(READ_CONTROL) -> queryInfo(SECURITY, OWNER|GROUP|DACL) -> parse. This is
        the only way to read a file/dir security descriptor over SMB (no high-level nxc API).
        """
        opts = FILE_DIRECTORY_FILE if is_dir else FILE_NON_DIRECTORY_FILE
        # SMB3.create arg order: desiredAccess, shareMode, creationOptions,
        # creationDisposition, fileAttributes - pass by keyword to stay correct.
        fid = self.smb.create(self.tid, path, desiredAccess=READ_CONTROL, shareMode=FILE_SHARE_ALL,
                              creationOptions=opts, creationDisposition=FILE_OPEN, fileAttributes=0)
        try:
            data = self.smb.queryInfo(self.tid, fid, infoType=SMB2_0_INFO_SECURITY, fileInfoClass=0,
                                      additionalInformation=SEC_OWNER_GROUP_DACL)
        finally:
            with suppress(Exception):
                self.smb.close(self.tid, fid)
        sd = SR_SECURITY_DESCRIPTOR()
        sd.fromString(bytes(data))
        return sd

    # =============================================================================== #
    #  Matching / labels                                                              #
    # =============================================================================== #
    def _hunt_match(self, sid):
        if self.hunt:                    # explicit hunt list wins
            return sid in self.hunt
        if not self.hunt_all:
            return False
        # "all" mode: skip expected/privileged holders to cut noise (hunt their SID to include).
        return not (sid in ADMIN_SIDS or any(sid.endswith(x) for x in ADMIN_RID_SUFFIXES))

    @staticmethod
    def _share_allows_write(share_acl, sid):
        """Does the SHARE-level ACL grant this principal write? Direct grant, or via a
        broad group it is (almost certainly) a member of (Everyone/Auth Users/Users/Domain Users).
        """
        if share_acl.get(sid, 0) & WRITE_MASK_ANY:
            return True
        for s, m in share_acl.items():
            if (s in ("S-1-1-0", "S-1-5-11", "S-1-5-32-545") or s.endswith("-513")) and (m & WRITE_MASK_ANY):
                return True
        return False

    @staticmethod
    def _rights_label(mask):
        if (mask & GENERIC_ALL) or ((mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS):
            return "FULL CONTROL"
        if mask & (FILE_WRITE_DATA | GENERIC_WRITE) and mask & (DELETE | FILE_DELETE_CHILD):
            base = "MODIFY+DELETE"
        elif mask & (FILE_WRITE_DATA | GENERIC_WRITE):
            base = "WRITE"
        elif mask & FILE_APPEND_DATA:
            base = "WRITE (add files/subdirs)"
        elif mask & (DELETE | FILE_DELETE_CHILD):
            base = "DELETE"
        else:
            base = "write"
        tags = []
        if mask & WRITE_DAC:
            tags.append("WriteDACL")
        if mask & WRITE_OWNER:
            tags.append("WriteOwner")
        return base + (" +" + "+".join(tags) if tags else "")

    def _print_table(self, context, rows):
        if not rows:
            context.log.display("No write grants matched.")
            return

        def loc(r):
            return f"{r['share']}\\{r['path']}" if r["path"] else f"{r['share']}\\"

        rows.sort(key=lambda r: (r["principal"].lower(), loc(r).lower()))
        head = ("Principal", "Rights", "Location")
        w_pri = max(len(head[0]), max(len(r["principal"]) for r in rows))
        w_rig = max(len(head[1]), max(len(r["rights"]) for r in rows))

        def fmt(a, b, c):
            return f"{a:<{w_pri}}   {b:<{w_rig}}   {c}"

        lines = [fmt(*head), fmt("-" * len(head[0]), "-" * len(head[1]), "-" * len(head[2]))]
        lines += [fmt(r["principal"], r["rights"], loc(r)) for r in rows]
        for line in lines:
            context.log.highlight(line)     # nxc idiom: findings go through highlight()

    # =============================================================================== #
    #  RPC (LSA + srvsvc) bound once per host; SID <-> name via well-known + LSA       #
    # =============================================================================== #
    def _dce_connect(self, context, pipe, uuid):
        """Bind a DCE/RPC pipe over the existing SMB session; None if it fails."""
        try:
            rpc = transport.SMBTransport(self.host, self.conn.port, pipe, smb_connection=self.conn.conn)
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.bind(uuid)
            return dce
        except Exception as e:
            context.log.debug(f"RPC bind {pipe} failed ({self._err(e)})")
            return None

    def _rpc_setup(self, context):
        self._lsa_dce = self._lsa_policy = self._srvsvc_dce = None
        lsa = self._dce_connect(context, r"\lsarpc", lsat.MSRPC_UUID_LSAT)
        if lsa is not None:
            try:
                self._lsa_policy = lsad.hLsarOpenPolicy2(lsa, MAXIMUM_ALLOWED)["PolicyHandle"]
                self._lsa_dce = lsa
            except Exception as e:
                context.log.debug(f"LSA policy open failed ({self._err(e)})")
        if self._lsa_dce is None:
            context.log.debug("LSA unavailable, names will show as raw SIDs")
        self._srvsvc_dce = self._dce_connect(context, r"\srvsvc", srvs.MSRPC_UUID_SRVS)

    def _rpc_teardown(self):
        for dce in (self._lsa_dce, self._srvsvc_dce):
            if dce is not None:
                with suppress(Exception):
                    dce.disconnect()
        self._lsa_dce = self._lsa_policy = self._srvsvc_dce = None

    def _read_share_acl(self, context, share):
        """Share-level DACL as {sid: mask} via srvsvc NetrShareGetInfo(502); None if
        unreadable (admin-gated).
        """
        if self._srvsvc_dce is None:
            return None
        try:
            resp = srvs.hNetrShareGetInfo(self._srvsvc_dce, share + "\x00", 502)
            raw = resp["InfoStruct"]["ShareInfo502"]["shi502_security_descriptor"]
            raw = b"".join(raw) if raw else b""
            if not raw:
                return None
            sd = SR_SECURITY_DESCRIPTOR()
            sd.fromString(bytes(raw))
            return self._masks_from_sd(sd)
        except Exception as e:
            context.log.debug(f"share SD of {share} unreadable ({self._err(e)})")
            return None

    @staticmethod
    def _masks_from_sd(sd):
        """Collapse a parsed security descriptor into {sid: OR-ed allow mask}."""
        if sd["Dacl"] is None:                 # NULL DACL == everyone full
            return {"S-1-1-0": FILE_ALL_ACCESS}
        acl = {}
        for sid, mask, _inherited in _iter_allow_aces(sd):
            acl[sid] = acl.get(sid, 0) | mask
        return acl

    def _name(self, context, sid):
        if sid in self._names:
            return self._names[sid]
        name = WELL_KNOWN_SIDS.get(sid)
        if name is None and self._lsa_dce is not None:
            name = self._lsa_name(context, sid)
        self._names[sid] = name or sid
        return self._names[sid]

    def _name_to_sid(self, context, name):
        # Well-known reverse lookup first (Everyone, Authenticated Users, ...).
        for sid, wk in WELL_KNOWN_SIDS.items():
            if name.lower() in (wk.lower(), wk.split("\\")[-1].lower()):
                return sid
        if self._lsa_dce is None:
            return None
        try:
            r = lsat.hLsarLookupNames(self._lsa_dce, self._lsa_policy, [name])
            t = r["TranslatedSids"]["Sids"][0]
            if t["Use"] in LSA_USE_UNRESOLVED:
                return None
            dom_sid = r["ReferencedDomains"]["Domains"][t["DomainIndex"]]["Sid"].formatCanonical()
            return f"{dom_sid}-{t['RelativeId']}"
        except Exception:
            return None

    def _lsa_name(self, context, sid):
        try:
            r = lsat.hLsarLookupSids(self._lsa_dce, self._lsa_policy, [sid],
                                     lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            tn = r["TranslatedNames"]["Names"][0]
            if tn["Use"] in LSA_USE_UNRESOLVED:
                return None
            di = tn["DomainIndex"]
            dom = r["ReferencedDomains"]["Domains"][di]["Name"] if (di is not None and di >= 0) else ""
            return f"{dom}\\{tn['Name']}" if dom and tn["Name"] else (tn["Name"] or None)
        except Exception:
            return None

    @staticmethod
    def _err(exc):
        try:
            s = exc.getErrorString()
            return str(s[0] if isinstance(s, tuple) else s) or exc.__class__.__name__
        except Exception:
            return str(exc) or exc.__class__.__name__


def _iter_allow_aces(sd):
    """Yield (sid, mask, inherited) for each ALLOWED ACE in a descriptor's DACL. Callers
    handle the NULL-DACL case themselves (it means different things to each).
    """
    for ace in sd["Dacl"]["Data"]:
        if ace["AceType"] not in ACCESS_ALLOWED_TYPES:
            continue
        # Sid and Mask are always populated on these ACE types, so nothing is caught here; a
        # malformed descriptor propagates to the caller that read it, which debug-logs it.
        yield ace["Ace"]["Sid"].formatCanonical(), ace["Ace"]["Mask"]["Mask"], bool(ace["AceFlags"] & INHERITED_ACE)
