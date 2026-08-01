# bh_diff.py - differential BloodHound collection across two accounts.
#
# BloodHound sees a domain through the eyes of the account it collected with. Two accounts
# in the same domain see different things: an object can be wholly invisible, visible but
# without its DACL (no READ_CONTROL -> a shorter Aces list, and that is where attack paths
# vanish), or with a trimmed set of attributes. This module collects with nxc's built-in
# collector under the current account and diffs the result against a set collected earlier
# with a different account.
#
# The pure functions (load_zip / diff_sets / render) import stdlib only, so they run under
# plain python3 without the nxc venv - which is how the test suite exercises them.

import json
import os
import re
import shutil
import zipfile
from datetime import datetime

from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH


# Fields that identify an ACE. The rest (InheritanceHash, IsPermissionForOwnerRightsSid...)
# is noise that can differ between runs without any permission difference.
ACE_KEY_FIELDS = ("PrincipalSID", "PrincipalType", "RightName", "IsInherited")

# Keys handled by earlier layers of diff_object(); ObjectIdentifier is identical by
# construction, since it is the key we join objects on.
SKIP_KEYS = {"Properties", "Aces", "ObjectIdentifier"}

# Sub-key that tells us the collector was denied an enumeration (Sessions, RegistrySessions,
# etc. have the shape {Collected, FailureReason, Results}). A change on it is a PERMISSION
# difference, not time drift - so render flags it with a distinct marker.
DENIAL_KEY = "Collected"


class NXCModule:
    """Differential BloodHound collection across two accounts.

    Module by Michal Stepniewski
    """

    name = "bh_diff"
    description = "Collect BloodHound as the current account and show what it sees that a prior account did not"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        BASELINE  Path to the reference zip (account #1). Default: the newest set from a
                  different user in ~/.nxc/modules/bh_diff/<DOMAIN>/
        CURRENT   Path to a zip to compare instead of collecting live.
                  BASELINE + CURRENT = a pure offline diff, no network traffic.
        COLLECT   Collection methods passed to nxc's built-in collector. Default: All.
                  DCOnly gives a deterministic, pure-LDAP diff (no sessions).
        FORCE     Compare even when the two sets are from different domains. Use: FORCE=true
        """
        self.baseline = module_options.get("BASELINE")
        self.current = module_options.get("CURRENT")
        self.collect = module_options.get("COLLECT", "All")
        self.force = module_options.get("FORCE", "").lower() in ("true", "1", "yes")

    def _collect(self, context, connection):
        """Drive nxc's built-in collector (the same code as `nxc ldap --bloodhound`)."""
        produced = f"{connection.output_filename}_bloodhound.zip"
        prev = connection.args.collection
        connection.args.collection = self.collect
        try:
            connection.bloodhound()
        # BloodHound.connect() calls sys.exit(1) when it cannot find a DC - without
        # SystemExit in this tuple the whole nxc would die instead of just this module.
        except (Exception, SystemExit) as e:
            context.log.fail(f"BloodHound collection failed: {e.__class__.__name__} - {e}")
            context.log.fail("If this is 'Could not find a domain controller', add --dns-server <DC IP>")
            return None
        finally:
            connection.args.collection = prev

        # connection.bloodhound() returns nothing - judge success by whether the file exists.
        if not os.path.exists(produced):
            context.log.fail(f"Collector produced no zip: {produced}")
            return None
        return produced

    def on_login(self, context, connection):
        domain = (connection.domain or "").upper()
        user = connection.username or "unknown"

        if self.baseline and self.current:
            context.log.display("Offline mode: comparing the given zips, no collection")
            b_path = self.current
        elif self.current:
            b_path = self.current
            context.log.display(f"Using the given set as current: {b_path}")
        else:
            produced = self._collect(context, connection)
            if not produced:
                return
            b_path = os.path.join(store_dir(domain), store_name(user, datetime.now()))
            shutil.move(produced, b_path)
            context.log.success(f"Set saved: {b_path}")

        a_path = self.baseline or pick_baseline(store_dir(domain), user)
        if not a_path:
            context.log.display("No set from another account in this domain - baseline saved.")
            context.log.display("Run again from a second account to see the difference.")
            return
        if not self.current:
            context.log.display(f"Baseline: {a_path}")

        for path in (a_path, b_path):
            if not os.path.isfile(path):
                context.log.fail(f"No such file: {path}")
                return

        try:
            a, a_errors = load_zip(a_path)
            b, b_errors = load_zip(b_path)
        except zipfile.BadZipFile as e:
            context.log.fail(f"Corrupt zip: {e}")
            return

        for side, errors in (("A", a_errors), ("B", b_errors)):
            if errors:
                context.log.fail(f"{side}: skipped unparseable entries: {', '.join(errors)}")

        a_dom, b_dom = zip_domain(a), zip_domain(b)
        if a_dom and b_dom and a_dom != b_dom and not self.force:
            context.log.fail(f"Different domains: A={a_dom}, B={b_dom}. Use FORCE=true to compare anyway.")
            return

        only_a_kinds, only_b_kinds = scope_diff(a, b)
        if only_a_kinds or only_b_kinds:
            context.log.fail("Sets collected with a DIFFERENT scope - some differences come "
                             "from scope, not from permissions")
            if only_a_kinds:
                context.log.fail(f"  types only in A: {', '.join(only_a_kinds)}")
            if only_b_kinds:
                context.log.fail(f"  types only in B: {', '.join(only_b_kinds)}")

        if user_of(a_path) == user_of(b_path):
            context.log.fail("Both sets are from the same account - the diff measures time drift, not permissions")

        context.log.highlight(f"=== bh_diff: {b_dom or domain} ===")
        context.log.highlight(f"A (baseline): {os.path.basename(a_path)}")
        context.log.highlight(f"B (current) : {os.path.basename(b_path)}")

        diff = diff_sets(a, b)
        for line in render(diff, a, b):
            context.log.highlight(line)
        context.log.highlight(f"=== summary === {summary_line(diff)}")


def obj_label(obj):
    """Readable object label: name -> distinguishedname -> ObjectIdentifier."""
    props = obj.get("Properties") or {}
    return props.get("name") or props.get("distinguishedname") or obj.get("ObjectIdentifier") or "?"


def load_zip(path):
    """BloodHound(-CE) zip -> ({type: {oid: obj}}, [names of unparseable entries]).

    Type comes from meta["type"] (authoritative), not the filename - nxc prefixes files
    with a timestamp, so the name is only a fallback. An unparseable entry does not sink
    the whole diff, it just lands on the error list.
    """
    data, errors = {}, []
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if not name.lower().endswith(".json"):
                continue
            try:
                blob = json.loads(z.read(name))
            except (ValueError, UnicodeDecodeError):
                errors.append(name)
                continue
            kind = (blob.get("meta") or {}).get("type") or os.path.basename(name)[:-5].rsplit("_", 1)[-1]
            bucket = data.setdefault(kind, {})
            for obj in blob.get("data") or []:
                oid = obj.get("ObjectIdentifier")
                if oid:
                    bucket[oid] = obj
    return data, errors


def _canon(value):
    """Canonical form - a key for lists whose elements (dicts) are not hashable."""
    return json.dumps(value, sort_keys=True, default=str)


def ace_key(a):
    return tuple(str(a.get(f, "")) for f in ACE_KEY_FIELDS)


def _list_diff(a, b, key=_canon):
    """Set difference of two lists; `key` decides when two elements are the same element."""
    a_map = {key(x): x for x in a}
    b_map = {key(x): x for x in b}
    out = {}
    only_b = [b_map[k] for k in b_map if k not in a_map]
    only_a = [a_map[k] for k in a_map if k not in b_map]
    if only_b:
        out["only_b"] = only_b
    if only_a:
        out["only_a"] = only_a
    return out


def _dict_diff(a, b):
    """Flat difference of two dicts - for Properties, where values are simple."""
    out = {}
    added = {k: b[k] for k in b if k not in a}
    removed = {k: a[k] for k in a if k not in b}
    changed = {k: (a[k], b[k]) for k in a if k in b and a[k] != b[k]}
    if added:
        out["added"] = added
    if removed:
        out["removed"] = removed
    if changed:
        out["changed"] = changed
    return out


def _value_diff(av, bv):
    """Difference of two values of any shape: {"only_a"/"only_b"} or {"changed"}."""
    if isinstance(av, list) and isinstance(bv, list):
        return _list_diff(av, bv)
    return {"changed": (av, bv)}


def _subdict_diff(a, b):
    """Per-sub-key difference when a value is itself a dict.

    Without this, dict-valued object keys (GPOChanges, Sessions, Status, ContainedBy) fell
    into the "scalar" branch and reached the output as one unreadable JSON blob - yet
    GPOChanges.LocalAdmins or Sessions.Collected is exactly the signal one reaches for this
    module to see.
    """
    out = {}
    for k in sorted(set(a) | set(b)):
        if a.get(k) != b.get(k):
            out[k] = _value_diff(a.get(k), b.get(k))
    return out


def diff_object(a, b):
    """Three layers of one object's difference: Properties, Aces, everything else.

    Empty sections are pruned, so identical objects yield {}.
    """
    # The vast majority of objects are identical on both sides - that is the whole premise
    # of this module. One C-level compare here is cheaper than a field-by-field walk.
    if a == b:
        return {}

    diff = {}

    props = _dict_diff(a.get("Properties") or {}, b.get("Properties") or {})
    if props:
        diff["properties"] = props

    aces = _list_diff(a.get("Aces") or [], b.get("Aces") or [], key=ace_key)
    if aces:
        diff["aces"] = aces

    # Generic instead of hardcoding Members / ChildObjects / Links / Trusts / SPNTargets...
    # - shorter code and resilient to BHCE format changes.
    other = {}
    for key in set(a) | set(b):
        if key in SKIP_KEYS:
            continue
        av, bv = a.get(key), b.get(key)
        if av == bv:
            continue
        if isinstance(av, dict) and isinstance(bv, dict):
            sub = _subdict_diff(av, bv)
            if sub:
                other[key] = {"sub": sub}
        else:
            other[key] = _value_diff(av, bv)
    if other:
        diff["other"] = other

    return diff


def diff_sets(a, b):
    """{type: {"only_b": [oid], "only_a": [oid], "changed": {oid: diff_object}}} - no empty types."""
    result = {}
    for kind in sorted(set(a) | set(b)):
        a_objs = a.get(kind) or {}
        b_objs = b.get(kind) or {}
        entry = {
            "only_b": sorted(set(b_objs) - set(a_objs)),
            "only_a": sorted(set(a_objs) - set(b_objs)),
            "changed": {},
        }
        for oid in sorted(set(a_objs) & set(b_objs)):
            d = diff_object(a_objs[oid], b_objs[oid])
            if d:
                entry["changed"][oid] = d
        if entry["only_b"] or entry["only_a"] or entry["changed"]:
            result[kind] = entry
    return result


def scope_diff(a, b):
    """File types present on only one side -> (only_a, only_b).

    The collector writes a file for every type it tried to collect, regardless of how many
    objects it saw. A difference in the set of types is therefore a difference in collection
    SCOPE (e.g. All adds ADCS files that DCOnly lacks), not a permission difference.
    meta["methods"] is no use for this - bloodhound_ce in nxc 1.5.1 writes 0 in every file.
    """
    return sorted(set(a) - set(b)), sorted(set(b) - set(a))


def zip_domain(data):
    """Set's domain: the 'domains' node name, fallback to any object's Properties.domain."""
    for obj in (data.get("domains") or {}).values():
        name = (obj.get("Properties") or {}).get("name")
        if name:
            return name.upper()
    for objects in data.values():
        for obj in objects.values():
            dom = (obj.get("Properties") or {}).get("domain")
            if dom:
                return dom.upper()
    return ""


def name_map(*datasets):
    """{ObjectIdentifier: label} across every set, so SIDs/GUIDs resolve to names.

    Earlier sets win on collision (they are passed current-first), but both sides should
    agree on an object's label anyway.
    """
    names = {}
    for data in datasets:
        for objects in data.values():
            for oid, obj in objects.items():
                names.setdefault(oid, obj_label(obj))
    return names


def _resolve(names, ident):
    """SID/GUID -> collected object's name, or the raw identifier when it is foreign."""
    return names.get(ident, ident)


def _item_str(item, names):
    """One list element as a readable line: resolve principals, collapse {oid,type} blobs.

    An ACE prints as `PRINCIPAL (Type) Right [inherited]`; a graph edge like a group member
    or child object prints as `NAME (Type)` instead of a raw JSON blob. Anything else falls
    back to canonical JSON so no data is silently dropped.
    """
    if isinstance(item, dict):
        if "PrincipalSID" in item:  # an ACE
            s = f"{_resolve(names, item.get('PrincipalSID'))} ({item.get('PrincipalType')}) {item.get('RightName')}"
            return s + (" [inherited]" if item.get("IsInherited") else "")
        if "ObjectIdentifier" in item:  # a graph edge {ObjectIdentifier, ObjectType}
            otype = item.get("ObjectType")
            return _resolve(names, item["ObjectIdentifier"]) + (f" ({otype})" if otype else "")
    return _canon(item)


def _value_lines(label, sub, names, denial=False):
    """Lines for one value difference: {"changed"} or {"only_a"/"only_b"}."""
    pad = label.ljust(12)
    out = []
    if "changed" in sub:
        old, new = sub["changed"]
        if denial:
            side = "A" if not old else "B"
            out.append(f"        {pad} [ !] enumeration denied on side {side} "
                       f"- this is a PERMISSION difference, not time drift")
        else:
            out.append(f"        {pad} [ ~] {_canon(old)} -> {_canon(new)}")
    out.extend(f"        {pad} [+B] {_item_str(item, names)}" for item in sub.get("only_b") or [])
    out.extend(f"        {pad} [-A] {_item_str(item, names)}" for item in sub.get("only_a") or [])
    return out


def _object_detail_lines(d, names):
    """Indented detail lines for one changed object."""
    lines = []

    props = d.get("properties") or {}
    for key, value in sorted((props.get("added") or {}).items()):
        lines.append(f"        {'Properties'.ljust(12)} [+B] {key} = {value!r}")
    for key, value in sorted((props.get("removed") or {}).items()):
        lines.append(f"        {'Properties'.ljust(12)} [-A] {key} = {value!r}")
    for key, (old, new) in sorted((props.get("changed") or {}).items()):
        lines.append(f"        {'Properties'.ljust(12)} [ ~] {key}: {old!r} -> {new!r}")

    lines.extend(_value_lines("Aces", d.get("aces") or {}, names))

    for key in sorted(d.get("other") or {}):
        sub = d["other"][key]
        if "sub" in sub:
            for skey in sorted(sub["sub"]):
                lines.extend(_value_lines(f"{key}.{skey}", sub["sub"][skey], names,
                                          denial=(skey == DENIAL_KEY)))
        else:
            lines.extend(_value_lines(key, sub, names))
    return lines


def render(diff, a_data, b_data):
    """Difference structure -> list of lines. No limits: everything goes to the output.

    Every principal and graph edge is resolved to a name; the raw SID/GUID trails the name
    on object lines so nothing that identifies an object is lost.
    """
    names = name_map(b_data, a_data)
    lines = []
    for kind in sorted(diff):
        entry = diff[kind]
        lines.append(f"--- {kind}  (+B {len(entry['only_b'])}  "
                     f"-A {len(entry['only_a'])}  ~ {len(entry['changed'])}) ---")
        lines.extend(f"[+B] {_resolve(names, oid)}   {oid}" for oid in entry["only_b"])
        lines.extend(f"[-A] {_resolve(names, oid)}   {oid}" for oid in entry["only_a"])
        for oid, d in entry["changed"].items():
            lines.append(f"[ ~] {_resolve(names, oid)}   {oid}")
            lines.extend(_object_detail_lines(d, names))
    return lines


def summary_line(diff):
    if not diff:
        return "no differences"
    parts = [f"{kind}: +B {len(e['only_b'])}, -A {len(e['only_a'])}, ~ {len(e['changed'])}"
             for kind, e in sorted(diff.items())]
    return " | ".join(parts)


def safe_name(s):
    """Account name -> safe path fragment (blocks '../' escapes)."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def store_name(user, when):
    """Canonical store filename. Paired with user_of() - keep them together."""
    return f"{safe_name(user)}_{when:%Y%m%d_%H%M%S}.zip"


def user_of(path):
    """The account a set was collected with - the inverse of store_name()."""
    return os.path.basename(path).rsplit("_", 2)[0]


def store_dir(domain):
    path = os.path.join(NXC_PATH, "modules", "bh_diff", safe_name(domain.upper()))
    os.makedirs(path, exist_ok=True)
    return path


def pick_baseline(dirpath, current_user):
    """Newest zip from a DIFFERENT user in the domain directory; None if there is none."""
    want = safe_name(current_user)
    candidates = [
        os.path.join(dirpath, f)
        for f in os.listdir(dirpath)
        if f.endswith(".zip") and user_of(f) != want
    ]
    return max(candidates, key=os.path.getmtime) if candidates else None
