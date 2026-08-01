# trust_enum.py - remote AD trust security-posture analyzer for NetExec.
#
# Enumerates trustedDomain objects (like `nxc ldap --dc-list`) but adds the
# interpretation layer that no remote/Linux tool provides: SID filtering,
# TGT delegation, transitivity, authentication level and trust flavor -
# ported from Carsten Sandker's (@0xcsandker) Enum-ADTrusts.ps1.
#
# All analysis is offline bitmask logic over a single LDAP query; every
# attribute is readable by any authenticated domain user. Values that deviate
# from a safe default in a security-relevant way are printed in red.

from termcolor import colored  # hard nxc dependency (used by nxc/logger.py)

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes

# --- trustAttributes flags (MS-ADTS 6.1.6.7.9) ---------------------------------
NON_TRANSITIVE = 0x00000001
UPLEVEL_ONLY = 0x00000002
QUARANTINED_DOMAIN = 0x00000004  # a.k.a. "SID filtering / filter SIDs"
FOREST_TRANSITIVE = 0x00000008
CROSS_ORGANIZATION = 0x00000010
WITHIN_FOREST = 0x00000020
TREAT_AS_EXTERNAL = 0x00000040
USES_RC4_ENCRYPTION = 0x00000080
CROSS_ORG_NO_TGT_DELEGATION = 0x00000200
PIM_TRUST = 0x00000400
CROSS_ORG_ENABLE_TGT_DELEGATION = 0x00000800

TRUST_ATTRIBUTE_NAMES = {
    NON_TRANSITIVE: "NON_TRANSITIVE",
    UPLEVEL_ONLY: "UPLEVEL_ONLY",
    QUARANTINED_DOMAIN: "QUARANTINED_DOMAIN",
    FOREST_TRANSITIVE: "FOREST_TRANSITIVE",
    CROSS_ORGANIZATION: "CROSS_ORGANIZATION",
    WITHIN_FOREST: "WITHIN_FOREST",
    TREAT_AS_EXTERNAL: "TREAT_AS_EXTERNAL",
    USES_RC4_ENCRYPTION: "USES_RC4_ENCRYPTION",
    CROSS_ORG_NO_TGT_DELEGATION: "CROSS_ORGANIZATION_NO_TGT_DELEGATION",
    PIM_TRUST: "PIM_TRUST",
    CROSS_ORG_ENABLE_TGT_DELEGATION: "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION",
}

DIRECTION_NAMES = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
TRUST_TYPE_NAMES = {1: "Windows NT (downlevel)", 2: "Active Directory (uplevel)", 3: "MIT/Kerberos", 4: "DCE"}

# --- msDS-SupportedEncryptionTypes flags ---------------------------------------
ENC_TYPE_NAMES = {
    0x01: "DES_CBC_CRC",
    0x02: "DES_CBC_MD5",
    0x04: "RC4_HMAC",
    0x08: "AES128_CTS_HMAC_SHA1_96",
    0x10: "AES256_CTS_HMAC_SHA1_96",
}
WEAK_ENC_NAMES = {"DES_CBC_CRC", "DES_CBC_MD5", "RC4_HMAC"}


class NXCModule:
    """Analyze AD trust security posture (SID filtering, TGT delegation, transitivity). Ported from @0xcsandker Enum-ADTrusts.ps1"""

    name = "trust_enum"
    description = "Enumerate AD trusts and interpret their security posture (SID filtering, TGT delegation, transitivity)"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        Enumerate AD trusts and interpret their security posture. No options.

        Usage:
            nxc ldap $DC -u user -p pass -M trust_enum
        """

    def on_login(self, context, connection):
        # Use the queried DC's own naming context, not the -d flag: reading a
        # partner DC cross-forest would otherwise mislabel whose trusts these are.
        local_domain = dn_to_domain(connection.baseDN) or connection.domain or ""
        context.log.display(f"Enumerating trusts of {local_domain or connection.host}...")

        # connection.search() logs its own failure and returns [], so no error handling here.
        resp = connection.search("(objectClass=trustedDomain)", ["trustPartner", "flatName", "trustDirection", "trustType", "trustAttributes", "msDS-SupportedEncryptionTypes"])

        trusts = parse_result_attributes(resp)
        if not trusts:
            context.log.display("No trust relationships found.")
            return

        context.log.success(f"Found {len(trusts)} trust relationship(s)")

        for trust in trusts:
            try:
                partner = trust.get("trustPartner") or trust.get("flatName", "?")
                attrs = int(trust.get("trustAttributes", 0))
                direction = int(trust.get("trustDirection", 0))
                trust_type = int(trust.get("trustType", 0))
            except (ValueError, TypeError) as e:
                context.log.fail(f"Could not parse trust entry {trust}: {e}")
                continue

            flavor = get_trust_flavor(trust_type, attrs)
            trans_status = get_transitivity(attrs)
            auth_status = get_authentication_level(attrs)
            tgt_status, tgt_alert = get_tgt_delegation(attrs)
            sidf_status, sidf_alert = get_sid_filtering(attrs, trust_type, partner)

            flag_names = decode_flags(attrs, TRUST_ATTRIBUTE_NAMES) or ["<none>"]
            enc_val = trust.get("msDS-SupportedEncryptionTypes")
            enc_names = decode_flags(int(enc_val), ENC_TYPE_NAMES) if enc_val else []
            enc_weak = any(n in WEAK_ENC_NAMES for n in enc_names)

            context.log.highlight(f"=== {local_domain} <-> {partner} ===")
            self._row(context, "Direction", DIRECTION_NAMES.get(direction, str(direction)))
            self._row(context, "Type", TRUST_TYPE_NAMES.get(trust_type, str(trust_type)))
            self._row(context, "Flavor", flavor)
            self._row(context, "Transitivity", trans_status)
            self._row(context, "SID Filtering", sidf_status, alert=sidf_alert)
            self._row(context, "TGT Delegation", tgt_status, alert=tgt_alert)
            self._row(context, "Auth Level", auth_status)
            self._row(context, "Attributes", ", ".join(flag_names))
            self._row(context, "Supported Enc", ", ".join(enc_names) if enc_names else "not set", alert=enc_weak)

    def _row(self, context, label, value, alert=False):
        # Default color stays as-is (highlight = yellow); security-relevant
        # deviations from the safe default are switched to red.
        if alert:
            value = colored(value, "red")
        context.log.highlight(f"  {label:<15}: {value}")


def decode_flags(value, name_map):
    """Return the list of flag names set in an integer bitmask."""
    return [name for bit, name in name_map.items() if value & bit]


def dn_to_domain(dn):
    """'DC=corp,DC=local' -> 'corp.local'. Reflects the DC actually queried."""
    return ".".join(p.strip()[3:] for p in (dn or "").split(",") if p.strip().upper().startswith("DC="))


def get_trust_flavor(trust_type, attrs):
    """Coarse flavor - the only distinction that drives the posture matrix.

    The intra-forest ParentChild/CrossLink/TreeRoot sub-type is cosmetic and
    can't be told apart without extra trustParent lookups, so it's a single
    'Intra-Forest' label here rather than a name-suffix guess.
    """
    if trust_type == 3:
        return "Kerberos (Realm)"
    if trust_type == 4:
        return "Unknown (DCE)"
    if attrs & WITHIN_FOREST:
        return "Intra-Forest"
    if attrs & FOREST_TRANSITIVE:
        return "Forest"
    return "External"


def get_authentication_level(attrs):
    if attrs & WITHIN_FOREST:
        return "ForestWideAuthentication"
    if attrs & CROSS_ORGANIZATION:
        return "SelectiveAuthentication"
    if attrs & FOREST_TRANSITIVE:
        return "ForestWideAuthentication"
    return "DomainWideAuthentication"


def get_transitivity(attrs):
    if attrs & NON_TRANSITIVE:
        return "Disabled"
    if (attrs & WITHIN_FOREST) or (attrs & FOREST_TRANSITIVE):
        return "Enabled"
    return "Disabled"


def get_tgt_delegation(attrs):
    """Returns (status, alert). alert=True when cross-forest TGT delegation is
    explicitly enabled - the non-default, attack-relevant state (per [MS-KILE] 3.3.5.7.5).
    """
    if attrs & CROSS_ORG_NO_TGT_DELEGATION:
        return "Disabled", False
    if attrs & QUARANTINED_DOMAIN:
        return "Disabled", False
    if attrs & CROSS_ORG_ENABLE_TGT_DELEGATION:
        return "Enabled", True
    if attrs & WITHIN_FOREST:
        return "Enabled", False  # intra-forest: normal / expected
    # No decisive flag on a cross-forest trust: not encoded in trustAttributes,
    # so the effective state is the DC default - Disabled since the 2019 fixes
    # (CVE-2019-1040 era), Enabled by default before that.
    return "Not explicitly set (effective default: Disabled on DCs patched since 2019)", False


def get_sid_filtering(attrs, trust_type, partner):
    """Returns (status, alert). alert=True when SID filtering is effectively
    disabled on a cross-forest trust - i.e. SID-history injection is viable.
    The intra/forest/external bucket is derived from the trustAttributes flags,
    not from a display label.
    """
    if trust_type in (3, 4):  # MIT/Kerberos or DCE - SID filtering doesn't apply
        return "Unknown", False
    if attrs & WITHIN_FOREST:
        # Intra-forest SID filtering is disabled by default and that IS the norm.
        if attrs & QUARANTINED_DOMAIN:
            return f"Enabled (only SIDs from {partner} allowed)", False
        return "Disabled (intra-forest default - only specific SIDs filtered)", False
    # Cross-forest (Forest if transitive, else External).
    if attrs & QUARANTINED_DOMAIN:
        return f"Enabled (only SIDs from {partner} allowed)", False
    if (attrs & TREAT_AS_EXTERNAL) or attrs == 0:
        return "Disabled (only specific SIDs filtered)", True
    scope = f"the forest of {partner}" if (attrs & FOREST_TRANSITIVE) else partner
    return f"Enabled (only SIDs from {scope} allowed)", False
