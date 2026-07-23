# NetExec custom modules

A small set of custom [NetExec](https://github.com/Pennyw0rth/NetExec) (nxc) modules for
Active Directory enumeration, plus a script that installs them for you.

They focus on the parts that most tools skip: who can actually *write* where across SMB
shares, what security settings hide inside GPOs, AD trust posture, and tombstoned objects.
Everything runs from a normal authenticated domain user unless noted otherwise.

## Table of contents

- [Requirements](#requirements)
- [Install](#install)
- [Modules](#modules)
  - [deep_shares](#deep_shares-smb)
  - [gpo_audit](#gpo_audit-smb)
  - [trust_enum](#trust_enum-ldap)
  - [tombstone](#tombstone-ldap)
- [Adding your own module](#adding-your-own-module)
- [Credits](#credits)

## Requirements

- [NetExec](https://github.com/Pennyw0rth/NetExec) installed and on your `PATH` (`nxc` or `netexec`).
- Python 3. The modules use libraries NetExec already ships with (impacket, ldap3, pycryptodome, termcolor).

## Install

NetExec loads user modules from a single directory (`~/.nxc/modules`). Copy this folder to a
box that has NetExec, then run:

```bash
./install.sh
```

The script copies every module into `~/.nxc/modules`, then checks that nxc loads each one
under the protocol it declares. It is safe to re-run.

If your nxc uses a different modules path, point the script at it:

```bash
NXC_MODULES_DIR=/some/other/modules ./install.sh
```

## Modules

### deep_shares (smb)

Walks every readable share and reports which user or group has **write** access on which
path, read straight from the NTFS DACL. Useful for finding writable locations (logon
scripts, config drops, GPO paths) that a root-only share check misses.

```bash
# every non-admin principal that can write, on every readable share
nxc smb <target> -u user -p pass -M deep_shares

# only hunt specific principals (SIDs or names)
nxc smb <target> -u user -p pass -M deep_shares -o SIDS=dev,helpdesk

# limit to specific shares, and confirm you can really write (create+delete probe)
nxc smb <target> -u user -p pass -M deep_shares -o SHARE=SYSVOL,NETLOGON VERIFY=true
```

| Option       | Description                                                                 |
|--------------|-----------------------------------------------------------------------------|
| `SIDS`       | Principals to hunt (comma-separated SIDs and/or names). Default: all non-admin. |
| `SHARE`      | Shares to scan. Default: all readable shares, minus admin shares.           |
| `FILES`      | Also inspect file ACLs, not just directories. Default: off.                 |
| `VERIFY`     | Keep only paths you can really write, confirmed by a temp-file write.        |
| `ALL_SHARES` | Also scan admin shares (`C$`, `ADMIN$`, drive letters). Slow. Default: off.  |

It reports the NTFS grant. The share-level permission can still cap it, and a grant to
someone other than you can't be confirmed over SMB without being them or an admin, so use
`VERIFY` to keep the paths you can write yourself.

### gpo_audit (smb)

Dumps the security-relevant settings of every GPO in SYSVOL and highlights anomalies in
red. Any authenticated user can read SYSVOL, so this needs no special rights.

The anomaly rule is simple: Microsoft's default templates only grant sensitive rights to
built-in principals, never to a specific domain account. So any domain account (SID with
RID >= 1000) sitting in a privileged slot was put there by a human and gets flagged red.

```bash
nxc smb <target> -u user -p pass -M gpo_audit
```

It covers SecEdit sections (privilege rights, registry key / file / service ACLs, group
membership) and GPP files, including decrypting any `cpassword` it finds in `Groups.xml`
and friends. No options.

### trust_enum (ldap)

Enumerates AD trusts and interprets their security posture: SID filtering, TGT delegation,
transitivity, authentication level and trust flavor. All of it is offline bitmask logic
over a single LDAP query, and every attribute is readable by any authenticated user.
Settings that deviate from a safe default in a security-relevant way are printed in red.

```bash
nxc ldap <dc-ip> -u user -p pass -M trust_enum
```

No options.

### tombstone (ldap)

Queries, restores, deletes and audits reanimation rights of AD Deleted Objects. The
default action lists every tombstone and every principal that holds the
Reanimate-Tombstones right on the domain root.

```bash
# list tombstones + who can reanimate them (default)
nxc ldap <dc-ip> -u user -p pass -M tombstone

# restore a deleted object by its objectGUID
nxc ldap <dc-ip> -u user -p pass -M tombstone -o ACTION=restore ID=5ad162c9-97b1-4a90-a17c-5c2aedb7d1e3

# permanently delete an object by its DN
nxc ldap <dc-ip> -u user -p pass -M tombstone -o ACTION=delete DN="CN=test,OU=Users,DC=test,DC=local"
```

| Option   | Description                                                          |
|----------|--------------------------------------------------------------------|
| `ACTION` | `query` (default), `restore` or `delete`.                          |
| `ID`     | objectGUID of the object to restore (required for `restore`).      |
| `DN`     | distinguishedName of the object to delete (required for `delete`). |
| `SCHEME` | `ldaps` (default) or `ldap` for restore/delete.                    |

`restore` and `delete` change directory state, so use them only where you are allowed to.

## Adding your own module

Drop a `.py` file into `modules/` (the filename must match the module's `name`), then
re-run `./install.sh`.

## Credits

- **tombstone** by [@Fabrizzio53](https://github.com/Fabrizzio53).
- **trust_enum** ported from [@0xcsandker](https://github.com/csandker)'s `Enum-ADTrusts.ps1`.
