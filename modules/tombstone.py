from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldaptypes
from impacket.ldap.ldapasn1 import Control, SDFlagsControl, SimplePagedResultsControl
from impacket.uuid import bin_to_string
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

# What _print_object displays for every tombstone.
TOMBSTONE_ATTRIBUTES = [
    "sAMAccountName", "distinguishedName", "name",
    "objectSid", "isDeleted", "lastKnownParent", "description",
]


class NXCModule:
    """Module by Fabrizzio: @Fabrizzio53

    Reads and writes go through connection.ldap_connection - the session nxc already
    authenticated - so they inherit its transport. That matters on a DC enforcing LDAP
    signing with no TLS certificate, where an ldap3 session cannot bind at all: ldap3
    does not implement a SASL security layer, and LDAPS is unavailable without a cert.
    """

    name = "tombstone"
    description = "Query, restore, delete and audit reanimation rights of AD Deleted Objects"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        ACTION  Action to run: query (default), restore or delete
        ID      objectGUID of the object to restore (required for ACTION=restore)
        DN      distinguishedName of the object to delete (required for ACTION=delete)

        query    (default) list every tombstone AND the principals that can reanimate them
        restore  reanimate the object with objectGUID=ID
        delete   permanently delete the object with distinguishedName=DN

        Usage:
            nxc ldap $DC-IP -u user -p pass -M tombstone
            nxc ldap $DC-IP -u user -p pass -M tombstone -o ACTION=restore ID=5ad162c9-97b1-4a90-a17c-5c2aedb7d1e3
            nxc ldap $DC-IP -u user -p pass -M tombstone -o ACTION=delete DN="CN=test,OU=Users,DC=test,DC=local"
        """
        self.action = module_options.get("ACTION", "query")
        self.id = module_options.get("ID", "")
        self.delete_dn = module_options.get("DN", "")

        self.ready = True
        if self.action == "restore" and not self.id:
            context.log.fail("ID is required for the restore action")
            self.ready = False
        if self.action == "delete" and not self.delete_dn:
            context.log.fail("DN is required for the delete action")
            self.ready = False

    def _deleted_objects_dn(self):
        return "CN=Deleted Objects," + self.__base_dn

    def _search_deleted(self, connection, search_filter="(isDeleted=TRUE)", attributes=None):
        """Return the matching tombstones (excluding the container itself)."""
        base = self._deleted_objects_dn()
        # connection.search() only adds its own paged-results control when searchControls is
        # empty, so paging has to be passed explicitly next to SHOW_DELETED - otherwise the DC
        # caps the answer at 1000 tombstones. Error handling and logging live in that function.
        controls = [show_deleted_control(), SimplePagedResultsControl(criticality=True, size=1000)]
        resp = connection.search(search_filter, attributes or TOMBSTONE_ATTRIBUTES, baseDN=base, searchControls=controls)

        objects = []
        for obj in parse_result_attributes(resp):
            # The Deleted Objects container is the search base and also matches
            # (isDeleted=TRUE), so it comes back too - skip it by its DN.
            if obj.get("distinguishedName", "").lower() == base.lower():
                continue
            objects.append(obj)
        return objects

    def _find_by_guid(self, connection, attributes=None):
        r"""Return the tombstone whose objectGUID is self.id, or None.

        Matched on the "OldName\x0ADEL:<guid>" suffix AD stamps onto a deleted object's
        `name` rather than on objectGUID, because neither GUID route works here: impacket's
        filter parser UTF-8-expands escaped bytes >= 0x80, so a server-side (objectGUID=...)
        filter never matches, and comparing client-side fails too because nxc's
        parse_result_attributes decodes objectGUID with UUID(bytes=...) instead of
        UUID(bytes_le=...), byte-swapping its first three fields.
        """
        objects = self._search_deleted(connection, search_filter=f"(&(isDeleted=TRUE)(name=*DEL:{self.id}))", attributes=attributes)
        return objects[0] if objects else None

    def _print_object(self, context, obj):
        context.log.highlight(f"sAMAccountName    {obj.get('sAMAccountName', '')}")
        context.log.highlight(f"dn                {obj.get('distinguishedName', '')}")
        context.log.highlight(f"ID                {obj.get('name', '').split(':')[-1]}")
        # sid_to_str passes an already formatted S-1-... string through unchanged.
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
        objects = self._search_deleted(connection)
        if not objects:
            context.log.fail("No deleted objects found (AD Recycle Bin may be disabled).")
            return

        context.log.display(f"Found {len(objects)} deleted object(s)")
        context.log.highlight("")
        for obj in objects:
            self._print_object(context, obj)

    def _resolve_sid(self, connection, sid):
        """Resolve a SID to a readable name (well-known map first, then LDAP objectSid lookup)."""
        if sid in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[sid]
        parsed = parse_result_attributes(connection.search(f"(objectSid={sid})", ["sAMAccountName"]))
        return parsed[0]["sAMAccountName"] if parsed and parsed[0].get("sAMAccountName") else ""

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

        # The only search here that cannot go through connection.search(): that helper takes its
        # scope from the connection (subtree), and reading just the domain root's own DACL needs
        # a baseObject scope - a subtree search from the root would pull the whole domain.
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
            name = self._resolve_sid(connection, sid)
            context.log.highlight(f"{name or 'UNKNOWN'}    ({sid})")

    def restore_deleted_object(self, context, connection):
        context.log.display(f"Searching for deleted object with ID {self.id}")

        target = self._find_by_guid(connection, [*TOMBSTONE_ATTRIBUTES, "msDS-LastKnownRDN"])
        if target is None:
            context.log.fail(f"No deleted object found with ID {self.id}")
            return

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
        try:
            connection.ldap_connection.modify(
                target["distinguishedName"],
                # Reanimation is a single modify that BOTH sets the live DN and drops isDeleted.
                # Order matters (impacket preserves this dict's order): distinguishedName must
                # come first (mirrors bloodyAD), otherwise some DCs apply only the RDN rename
                # and leave the object tombstoned.
                {
                    "distinguishedName": [(ldap_impacket.MODIFY_REPLACE, [restored_dn])],
                    "isDeleted": [(ldap_impacket.MODIFY_DELETE, [])],
                },
                controls=[show_deleted_control()],
            )
        except ldap_impacket.LDAPSessionError as e:
            context.log.fail(f"Restore was rejected: {e}")
            return

        # A DC can accept the modify but apply only the rename, leaving the object tombstoned,
        # so report success only once it is gone from the Deleted Objects container.
        if self._find_by_guid(connection, ["isDeleted"]) is not None:
            context.log.fail("Restore did not take effect - object is still a tombstone.")
            context.log.fail("This DC did not honor the single-modify reanimation; a ModifyDN-based tool such as bloodyAD's 'set restore' may be needed.")
            return
        context.log.success(f'Restored "{restored_dn}"')

    def delete_object(self, context, connection):
        context.log.display(f"Deleting {self.delete_dn}")

        try:
            connection.ldap_connection.delete(self.delete_dn, controls=[show_deleted_control()])
        except ldap_impacket.LDAPSessionError as e:
            context.log.fail(f'Failed to delete "{self.delete_dn}": {e}')
            return
        context.log.success(f'Deleted "{self.delete_dn}"')

    def on_login(self, context, connection):
        if not self.ready:
            return
        self.__base_dn = connection.baseDN

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


def show_deleted_control():
    """LDAP_SERVER_SHOW_DELETED - makes the DC return and accept writes on tombstones."""
    control = Control()
    control["controlType"] = SHOW_DELETED_OID
    control["criticality"] = True
    return control
