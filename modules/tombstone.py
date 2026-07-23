from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldaptypes
from impacket.ldap.ldapasn1 import Control, SDFlagsControl
from impacket.examples.utils import init_ldap_session
from impacket.uuid import bin_to_string, string_to_bin
from ldap3 import MODIFY_REPLACE, MODIFY_DELETE, SUBTREE
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_bytes
from nxc.modules.daclread import WELL_KNOWN_SIDS
from nxc.parsers.ldap_results import parse_result_attributes, sid_to_str
from nxc.helpers.misc import CATEGORY

# LDAP_SERVER_SHOW_DELETED_OID - required to list and modify tombstoned objects
SHOW_DELETED_OID = "1.2.840.113556.1.4.417"

# Extended right "Reanimate-Tombstones" - the control-access right that lets a principal
# restore a deleted object. Evaluated on the domain naming-context root, not on the
# Deleted Objects container or the tombstone itself.
REANIMATE_TOMBSTONES_GUID = "45ec5156-db7e-47bb-b53f-dbeb2d03c40f"

# The right is granted via a control-access (extended) right, or via full control.
ADS_RIGHT_DS_CONTROL_ACCESS = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
ADS_RIGHT_GENERIC_ALL = ldaptypes.ACCESS_MASK.GENERIC_ALL

# ACE types that grant access (as opposed to deny/audit); the *_OBJECT variants also
# carry an ObjectType GUID scoping the grant to a specific right.
ALLOWED_ACE_TYPES = (
    ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE,
    ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,
    ldaptypes.ACCESS_ALLOWED_CALLBACK_ACE.ACE_TYPE,
    ldaptypes.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE.ACE_TYPE,
)
OBJECT_ACE_TYPES = (
    ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,
    ldaptypes.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE.ACE_TYPE,
)


class NXCModule:
    """Module by Fabrizzio: @Fabrizzio53"""

    name = "tombstone"
    description = "Query, restore, delete and audit reanimation rights of AD Deleted Objects"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        ACTION  Action to run: query (default), restore or delete
        ID      objectGUID of the object to restore (required for ACTION=restore)
        DN      distinguishedName of the object to delete (required for ACTION=delete)
        SCHEME  ldap or ldaps for restore/delete (default: ldaps)

        query    (default) list every tombstone AND the principals that can reanimate them
        restore  reanimate the object with objectGUID=ID
        delete   permanently delete the object with distinguishedName=DN

        Usage:
            nxc ldap $DC-IP -u user -p pass -M tombstone
            nxc ldap $DC-IP -u user -p pass -M tombstone -o ACTION=restore ID=5ad162c9-97b1-4a90-a17c-5c2aedb7d1e3
            nxc ldap $DC-IP -u user -p pass -M tombstone -o ACTION=delete DN="CN=test,OU=Users,DC=test,DC=local"
            nxc ldap $DC-IP -u user -p pass -M tombstone -o ACTION=restore ID=5ad162c9-97b1-4a90-a17c-5c2aedb7d1e3 SCHEME=ldap
        """
        self.action = module_options.get("ACTION", "query")
        self.id = module_options.get("ID", "")
        self.deleteDN = module_options.get("DN", "")
        # ldaps by default; only fall back to plaintext ldap when explicitly asked
        self.ssl = module_options.get("SCHEME", "ldaps").lower() != "ldap"

        self.ready = True
        if self.action == "restore" and not self.id:
            context.log.fail("ID is required for the restore action")
            self.ready = False
        if self.action == "delete" and not self.deleteDN:
            context.log.fail("DN is required for the delete action")
            self.ready = False

    def _deleted_objects_dn(self):
        return "CN=Deleted Objects," + self.__base_dn

    def _write_session(self, context):
        """Open an ldap3 session for write actions (restore/delete), or None if it fails."""
        # If Kerberos is used, the FQDN acts as the KDC host (like impacket's -dc-host).
        if self.__doKerberos:
            self.__kdcHost = self.__host
        try:
            _, ldap_session = init_ldap_session(
                self.__domain, self.__username, self.__password, self.__lmhash,
                self.__nthash, self.__doKerberos, self.__host, self.__kdcHost,
                self.__aesKey, self.ssl,
            )
            return ldap_session
        except (LDAPException, OSError) as e:
            # LDAPS is the default, but many DCs (e.g. no TLS cert) reset the connection.
            # Surface the real error and, on LDAPS, point the user at SCHEME=ldap.
            if self.ssl:
                context.log.fail(
                    f"Could not open an LDAPS write session ({e}). If the DC has no TLS cert, "
                    "retry with SCHEME=ldap to use plaintext LDAP on port 389."
                )
            else:
                context.log.fail(f"Could not open an LDAP write session: {e}")
            return None

    def _search_deleted(self, context, connection):
        """Return the list of tombstoned objects (excluding the container itself), or None on error."""
        base = self._deleted_objects_dn()

        show_deleted = Control()
        show_deleted["controlType"] = SHOW_DELETED_OID
        show_deleted["criticality"] = True

        try:
            context.log.debug("Search Filter=(isDeleted=TRUE)")
            resp = connection.ldap_connection.search(
                base,
                2,  # subtree
                searchFilter="(isDeleted=TRUE)",
                attributes=["sAMAccountName", "distinguishedName", "name", "objectSid", "isDeleted", "lastKnownParent", "description"],
                sizeLimit=0,
                searchControls=[show_deleted],
            )
        except ldap_impacket.LDAPSearchError as e:
            if "sizeLimitExceeded" in e.getErrorString():
                context.log.debug("sizeLimitExceeded, processing the results received so far")
                resp = e.getAnswers()
            else:
                context.log.debug(e)
                return None

        objects = []
        for obj in parse_result_attributes(resp):
            # The Deleted Objects container is the search base and also matches
            # (isDeleted=TRUE), so it comes back too - skip it by its DN.
            if obj.get("distinguishedName", "").lower() == base.lower():
                continue
            objects.append(obj)
        return objects

    def _print_object(self, context, obj):
        context.log.highlight(f"sAMAccountName    {obj.get('sAMAccountName', '')}")
        context.log.highlight(f"dn                {obj.get('distinguishedName', '')}")
        context.log.highlight(f"ID                {obj.get('name', '').split(':')[-1]}")
        # sid_to_str formats ldap3's raw objectSid bytes (write path) and passes an already
        # formatted S-1-... string (impacket read path) through unchanged.
        context.log.highlight(f"objectSid         {sid_to_str(obj.get('objectSid', ''))}")
        context.log.highlight(f"isDeleted         {obj.get('isDeleted', '')}")
        context.log.highlight(f"lastKnownParent   {obj.get('lastKnownParent', '')}")
        context.log.highlight(f"description       {obj.get('description', '')}")
        context.log.highlight("")

    def enumerate_tombstones(self, context, connection):
        """Default action: list the deleted objects and who can reanimate them."""
        self.query_deleted_objects(context, connection)
        self.analyze_reanimate_rights(context, connection)

    def query_deleted_objects(self, context, connection):
        objects = self._search_deleted(context, connection)
        if not objects:
            context.log.fail("No deleted objects found (AD Recycle Bin may be disabled).")
            return

        context.log.display(f"Found {len(objects)} deleted object(s)")
        context.log.highlight("")
        for obj in objects:
            self._print_object(context, obj)

    def _resolve_sid(self, context, connection, sid):
        """Resolve a SID to a readable name (well-known map first, then LDAP objectSid lookup)."""
        if sid in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[sid]
        try:
            resp = connection.ldap_connection.search(
                searchFilter=f"(objectSid={sid})",
                attributes=["sAMAccountName"],
            )
            parsed = parse_result_attributes(resp)
            if parsed and parsed[0].get("sAMAccountName"):
                return parsed[0]["sAMAccountName"]
        except Exception as e:
            context.log.debug(f"Could not resolve SID {sid}: {e}")
        return ""

    def _ace_grants_reanimate(self, ace):
        """Return the trustee SID if this ACE grants the Reanimate-Tombstones right, else None.

        Mirrors GhostHound's check: an allow ACE (not inherit-only) whose mask carries a
        control-access right or GenericAll, and which is either unscoped (grants all extended
        rights) or scoped to exactly the Reanimate-Tombstones GUID.
        """
        if ace["AceType"] not in ALLOWED_ACE_TYPES:
            return None
        # INHERIT_ONLY_ACE propagates to children only, so it doesn't grant on the root itself
        if ace["AceFlags"] & ldaptypes.ACE.INHERIT_ONLY_ACE:
            return None

        mask = ace["Ace"]["Mask"]["Mask"]
        if not (mask & ADS_RIGHT_DS_CONTROL_ACCESS or mask & ADS_RIGHT_GENERIC_ALL):
            return None

        # Only object ACEs carry an ObjectType GUID; a non-object ACE grants ALL extended rights.
        obj_type = None
        if ace["AceType"] in OBJECT_ACE_TYPES and ace["Ace"]["ObjectTypeLen"] != 0:
            obj_type = bin_to_string(ace["Ace"]["ObjectType"]).lower()

        if obj_type is None or obj_type == REANIMATE_TOMBSTONES_GUID:
            return ace["Ace"]["Sid"].formatCanonical()
        return None

    def analyze_reanimate_rights(self, context, connection):
        context.log.display(f"Reading DACL of domain root {self.__base_dn} to find who can reanimate tombstones")

        try:
            resp = connection.ldap_connection.search(
                self.__base_dn,
                0,  # base object
                searchFilter="(objectClass=*)",
                attributes=["nTSecurityDescriptor"],
                searchControls=[SDFlagsControl(criticality=False, flags=0x04)],  # DACL only
            )
        except ldap_impacket.LDAPSearchError as e:
            context.log.fail(f"Could not read the domain root security descriptor: {e}")
            return

        parsed = parse_result_attributes(resp)
        if not parsed or not parsed[0].get("nTSecurityDescriptor"):
            context.log.fail("Domain root returned no nTSecurityDescriptor (missing READ_CONTROL?).")
            return

        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=parsed[0]["nTSecurityDescriptor"])
        if sd["Dacl"] is None:
            context.log.fail("Domain root security descriptor has no DACL.")
            return

        sids = set()
        for ace in sd["Dacl"]["Data"]:
            sid = self._ace_grants_reanimate(ace)
            if sid:
                sids.add(sid)

        if not sids:
            context.log.fail("No principal holds the Reanimate-Tombstones right on the domain root.")
            return

        context.log.display(f"{len(sids)} principal(s) can reanimate deleted objects:")
        context.log.highlight("")
        for sid in sorted(sids):
            name = self._resolve_sid(context, connection, sid)
            context.log.highlight(f"{name or 'UNKNOWN'}    ({sid})")

    def restore_deleted_object(self, context, connection):
        context.log.display(f"Searching for deleted object with ID {self.id}")

        ldap_session = self._write_session(context)
        if ldap_session is None:
            return

        entries = self._search_deleted_by_guid(
            ldap_session,
            ["sAMAccountName", "distinguishedName", "name", "objectSid", "isDeleted", "lastKnownParent", "description", "msDS-LastKnownRDN"],
        )
        if not entries:
            context.log.fail(f"No deleted object found with ID {self.id}")
            return

        entry = entries[0]
        target = {k: (v[0] if v else "") for k, v in entry.entry_attributes_as_dict.items()}
        target["distinguishedName"] = entry.entry_dn

        last_parent = target.get("lastKnownParent", "")
        # RDN to reanimate under: prefer the server's msDS-LastKnownRDN, then the first line of
        # `name` (deleted objects carry "OldName\x0ADEL:<guid>"), finally sAMAccountName.
        rdn = (
            target.get("msDS-LastKnownRDN")
            or target.get("name", "").splitlines()[0]
            or target.get("sAMAccountName", "")
        )

        context.log.success("Found target:")
        self._print_object(context, target)

        if not rdn or not last_parent:
            context.log.fail("Target is missing a last-known RDN or lastKnownParent; cannot rebuild its DN.")
            return

        restored_dn = f"CN={rdn},{last_parent}"
        # Reanimation is a single modify that BOTH sets the live DN and drops isDeleted. Order matters:
        # distinguishedName must come before isDeleted (mirrors bloodyAD), otherwise some DCs apply
        # only the RDN rename and leave the object tombstoned.
        ldap_session.modify(
            dn=entry.entry_dn,
            changes={
                "distinguishedName": [(MODIFY_REPLACE, [restored_dn])],  # move it out to its live DN
                "isDeleted": [(MODIFY_DELETE, [])],                      # drop the isDeleted attribute
            },
            controls=[(SHOW_DELETED_OID, True, None)],
        )

        # ldap3 can report success on a modify that only renamed the tombstone, so
        # re-check the object and only report success once it is no longer deleted.
        if self._still_deleted(ldap_session):
            context.log.fail(f"Restore did not take effect - object is still a tombstone (LDAP result: {ldap_session.result.get('description')}).")
            context.log.fail("This DC did not honor the single-modify reanimation; a ModifyDN-based tool such as bloodyAD's 'set restore' may be needed.")
            return
        context.log.success(f'Restored "{restored_dn}"')

    def _search_deleted_by_guid(self, ldap_session, attributes):
        """Search the Deleted Objects container for the tombstone with objectGUID=self.id and
        return ldap_session.entries. objectGUID is binary and impacket's filter parser corrupts
        bytes >= 0x80, so this lookup runs over the ldap3 session, which escapes binary correctly."""
        guid_filter = escape_bytes(string_to_bin(self.id))
        ldap_session.search(
            self._deleted_objects_dn(),
            f"(&(isDeleted=TRUE)(objectGUID={guid_filter}))",
            search_scope=SUBTREE,
            attributes=attributes,
            controls=[(SHOW_DELETED_OID, True, None)],
        )
        return ldap_session.entries

    def _still_deleted(self, ldap_session):
        """Return True if the object with objectGUID=self.id is still a tombstone (isDeleted=TRUE)."""
        return bool(self._search_deleted_by_guid(ldap_session, ["isDeleted"]))

    def delete_object(self, context, connection):
        ldap_session = self._write_session(context)
        if ldap_session is None:
            return

        context.log.display(f"Deleting {self.deleteDN}")
        success = ldap_session.delete(self.deleteDN)

        if success:
            context.log.success(f'Deleted "{self.deleteDN}"')
        else:
            context.log.fail(f'Failed to delete "{self.deleteDN}": {ldap_session.result}')

    def on_login(self, context, connection):
        if not self.ready:
            return
        self.__domain = connection.domain
        self.__base_dn = connection.baseDN
        self.__username = connection.username
        self.__password = connection.password
        self.__host = connection.host
        self.__kdcHost = connection.kdcHost
        self.__aesKey = context.aesKey
        self.__doKerberos = connection.kerberos
        self.__lmhash = ""
        self.__nthash = ""

        if context.hash and context.hash[0]:
            nt = context.hash[0]
            if ":" in nt:
                self.__lmhash, self.__nthash = nt.split(":")
            else:
                self.__lmhash = "00000000000000000000000000000000"
                self.__nthash = nt

        actions = {
            "query": self.enumerate_tombstones,
            "restore": self.restore_deleted_object,
            "delete": self.delete_object,
        }
        handler = actions.get(self.action)
        if handler is None:
            context.log.fail(f'Unknown action "{self.action}" (use query, restore or delete)')
            return
        handler(context, connection)
