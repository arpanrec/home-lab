# -*- coding: utf-8 -*-
"""
This module contains the VaultInventoryBuilder plugin for Ansible.
This plugin allows users to use HashiCorp Vault as a dynamic inventory source.

It uses the BaseInventoryPlugin class from the ansible.plugins.inventory module as a base class,
and the Templar class from ansible.template for template rendering.

It also uses the ipaddress and json standard library modules for IP address and JSON handling, respectively,
and the urlsplit function from urllib.parse for URL parsing.

The module defines a BaseModel subclass for the data model,
and uses the Field and computed_field functions from pydantic for field definition and computed fields,
respectively. It also uses the to_jsonable_python function from pydantic_core for serialization.

Author: Arpan Mandal
Requirements: Python 3 or higher
"""
import ipaddress
import json
import os
from typing import Any, Dict, List, Union
from urllib.parse import urlsplit

from ansible.inventory.data import InventoryData  # type: ignore
from ansible.parsing.dataloader import DataLoader  # type: ignore
from ansible.plugins.inventory import BaseInventoryPlugin  # type: ignore
from ansible.template import Templar  # type: ignore
from ansible.utils.display import Display  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore
from cryptography.hazmat.primitives import serialization
from hvac.exceptions import InternalServerError, VaultDown  # type: ignore
from pydantic_core import to_jsonable_python
from requests import ConnectTimeout
from requests.exceptions import RequestException
from vaultops.builder.vault_config import build_vault_config
from vaultops.builder.vault_raft_node import build_raft_server_nodes_map
from vaultops.models.vault_config import VaultConfig
from vaultops.models.vault_raft_node import VaultRaftNode
from vaultops.models.vault_secrets import VaultSecrets
from vaultops.models.vault_server import VaultServer
from vaultops.vault_setup import VaultHaClient, create_ha_client

DOCUMENTATION = r"""
name: instance
author:
    - Arpan Mandal
requirements:
    - python >= 3.10
description:
    - This plugin allows users to use Cloud as a dynamic inventory source.
    - Localhost is added to the inventory.
    - If ansible_inventory_extra_group is provided, then the group is added to the inventory.
    - This module provides the following variables:
          - root_ca_key_passphrase: Root CA key passphrase
          - root_ca_key_pem: Root CA key PEM
          - root_ca_cert_pem: Root CA certificate PEM
          - vault_vm_server_ssh_user_known_hosts_file: Path to the known hosts file
          - ansible_ssh_public_key_content: SSH Public key from the Root CA key
          - vault_ha_client: Vault HA client for vault operations
          - ansible_ssh_private_key_file: Path to the SSH private key file
          - pv_vault_dr_lost_quorum_recovery_nodes: Vault Disaster Recovery lost quorum recovery nodes
          - pv_vault_raft_node_details: Vault Raft node details.
          - pv_vault_raft_nodes_in_host: Vault Raft nodes in host.
          - host_keys: Host keys
          - cs_<vault_server_name, - replaced with _>_ip: Vault server IP
    - Change the root CA key to ssh private key and add it to the inventory under `ansible_ssh_private_key_file`
extends_documentation_fragment:
    - constructed
options:
    plugin:
        description: Name of the plugin
        required: true
        choices: ["blr_home_lab_inv"]
        type: str
        default: blr_home_lab_inv
    vaultops_tmp_dir_path:
        description: Path to the temporary directory for storing Vault configuration files.
        required: true
        type: srt
    storage_config:
        description:
            - Vault Storage configuration.
            - This can be dict or path to the file containing the storage configuration.
        required: true
        type: dict | str
    vault_config:
        description:
            - Vault configuration.
            - This can be dict or path to the file containing the Vault configuration.
        required: true
        type: dict | str
"""

display = Display()


class InventoryModule(BaseInventoryPlugin):
    """
    Ansible dynamic inventory plugin for Hashicorp Vault
    """

    NAME = "blr_home_lab_inv"  # used internally by Ansible, it should match the file name but not required
    loader: Any
    templar: Templar
    ansible_vault_server_group_name = "vault_vm_servers"
    ansible_vault_node_servers_group_name = "vault_nodes_servers"

    def verify_file(self, path: str) -> bool:
        """return true/false if this is possibly a valid file for this plugin to consume"""
        valid = False  # this means it will be ignored unless set to True later
        if path.endswith(("inventory.yml", "inventory.yaml")):
            valid = True
        return valid

    # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    def parse(self, inventory: InventoryData, loader: DataLoader, path: str, cache: bool = True) -> None:
        """parse and populate the inventory with data"""
        super().parse(inventory, loader, path, cache)
        self.loader = loader
        self.templar = Templar(loader=loader)
        self.inventory = inventory

        self.inventory.add_host("localhost")

        display.v(f"Vault Inventory Builder Plugin: Parsing inventory file: {path}")

        self.inventory.add_group(self.ansible_vault_server_group_name)
        self.inventory.add_group(self.ansible_vault_node_servers_group_name)
        ansible_inventory_dict = self._read_config_data(path)
        # print(self.templar.template(ansible_inventory_dict["vault_config"]))
        vault_config: VaultConfig = build_vault_config(ansible_inventory_dict)
        vault_config.storage_config.add_to_ansible_inventory(self.inventory)
        vault_secrets: VaultSecrets = vault_config.vault_secrets

        vault_vm_server_ssh_user_known_hosts_file = os.path.join(
            vault_config.vaultops_tmp_dir_path, "UserKnownHostsFile"
        )
        self.inventory.set_variable(
            "all", "root_ca_key_passphrase", vault_secrets.root_pki_details.root_ca_key_password
        )
        self.inventory.set_variable("all", "root_ca_key_pem", vault_secrets.root_pki_details.root_ca_key_pem)
        self.inventory.set_variable("all", "root_ca_cert_pem", vault_secrets.root_pki_details.root_ca_cert_pem)
        self.inventory.set_variable("all", "vaultops_tmp_dir_path", vault_config.vaultops_tmp_dir_path)
        self.inventory.set_variable(
            "all", "vault_vm_server_ssh_user_known_hosts_file", vault_vm_server_ssh_user_known_hosts_file
        )
        rsa_root_ca_key = serialization.load_pem_private_key(
            data=vault_secrets.root_pki_details.root_ca_key_pem.encode("utf-8"),
            password=vault_secrets.root_pki_details.root_ca_key_password.encode("utf-8"),
            backend=default_backend(),
        )

        rsa_root_ca_openssh_pub_key_bytes: bytes = rsa_root_ca_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH
        )
        rsa_root_ca_openssh_no_pass_key_bytes: bytes = rsa_root_ca_key.private_bytes(  # type: ignore
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.inventory.set_variable(
            "all", "ansible_ssh_public_key_content", rsa_root_ca_openssh_pub_key_bytes.decode("utf-8")
        )
        self.inventory.set_variable(
            "all", "ansible_ssh_common_args", f"-o UserKnownHostsFile={vault_vm_server_ssh_user_known_hosts_file}"
        )

        vault_ha_client: VaultHaClient = create_ha_client(
            vault_config=vault_config,
            rsa_root_ca_key=rsa_root_ca_key,
            rsa_root_ca_cert=None,
        )
        try:
            vault_ha_client.evaluate_token()
        except (ConnectTimeout, VaultDown, InternalServerError, ConnectionError, RequestException) as e:
            display.warning(f"Vault ha client is down: {e}")

        self.inventory.set_variable("all", "vault_ha_client", vault_ha_client.model_dump())
        ssh_private_key_temp_file = os.path.join(vault_config.vaultops_tmp_dir_path, "ansible_ssh_private_key_file")

        with open(ssh_private_key_temp_file, "wb") as ssh_private_key_buffer:
            ssh_private_key_buffer.write(rsa_root_ca_openssh_no_pass_key_bytes)
        os.chmod(ssh_private_key_temp_file, 0o600)

        server_raft_nodes: Dict[str, Dict[str, VaultRaftNode]] = build_raft_server_nodes_map(vault_config)

        # Create all raft nodes dict
        raft_nodes_list: Dict[str, VaultRaftNode] = {}
        for vault_server_name, raft_nodes in server_raft_nodes.items():
            for node_id, raft_node_details in raft_nodes.items():
                raft_nodes_list[node_id] = raft_node_details.model_copy(deep=True)

        # Create DR lost quorum recovery nodes
        dr_lost_quorum_recovery_nodes: List[Dict[str, Union[str, bool]]] = []
        for node_id, raft_node_details in raft_nodes_list.items():
            cluster_url_split = urlsplit(raft_node_details.cluster_addr)
            dr_lost_quorum_recovery_nodes.append(
                {"id": node_id, "address": f"{cluster_url_split.hostname}:{cluster_url_split.port}", "non_voter": False}
            )
        self.inventory.set_variable("all", "pv_vault_dr_lost_quorum_recovery_nodes", dr_lost_quorum_recovery_nodes)

        vault_servers: Dict[str, VaultServer] = vault_config.vault_servers
        for vault_server_name, vault_server_details in vault_servers.items():
            ip: str = str(vault_server_details.ansible_opts.get("ansible_host", None))
            try:
                ip_address = ipaddress.ip_address(ip)
                if ip_address.is_loopback or ip_address.is_link_local or ip_address.is_multicast:
                    raise ValueError(f"Invalid IP address: {ip}")
            except ValueError as e:
                raise ValueError(f"Invalid IP address: {ip}") from e

            for ansible_inventory_extra_group in vault_server_details.ansible_inventory_extra_groups:
                if ansible_inventory_extra_group in [
                    "all",
                    "ungrouped",
                    self.ansible_vault_server_group_name,
                    self.ansible_vault_node_servers_group_name,
                ]:
                    raise ValueError(
                        f"Invalid ansible_inventory_extra_group: {ansible_inventory_extra_group}"
                        f" for Vault Server: {vault_server_name}, Its a reserved group name"
                    )
                self.inventory.add_group(ansible_inventory_extra_group)
                self.inventory.add_host(vault_server_name, group=ansible_inventory_extra_group)
            self.inventory.set_variable(vault_server_name, "host_keys", vault_server_details.host_keys)
            self.inventory.set_variable(
                "all",
                f"cs_{vault_server_name.replace('-', '_')}_ip",
                vault_server_details.ansible_opts["ansible_host"],
            )
            for ansible_opt_key, ansible_opt_value in vault_server_details.ansible_opts.items():
                self.inventory.set_variable(vault_server_name, ansible_opt_key, ansible_opt_value)
            if vault_server_details.root_ca_key_pem_as_ansible_priv_ssh_key:
                self.inventory.set_variable(
                    vault_server_name, "ansible_ssh_private_key_file", ssh_private_key_temp_file
                )
            if not vault_server_details.is_vault_server:
                continue

            self.inventory.add_host(vault_server_name, group=self.ansible_vault_server_group_name)
            raft_nodes_id_details: Dict[str, VaultRaftNode] = server_raft_nodes[vault_server_name]

            for node_id, raft_node_details in raft_nodes_id_details.items():
                self.inventory.add_host(node_id, group=self.ansible_vault_node_servers_group_name)

                if vault_server_details.root_ca_key_pem_as_ansible_priv_ssh_key:
                    self.inventory.set_variable(node_id, "ansible_ssh_private_key_file", ssh_private_key_temp_file)

                self.inventory.set_variable(node_id, "host_keys", vault_server_details.host_keys)
                for ansible_opt_key, ansible_opt_value in vault_server_details.ansible_opts.items():
                    self.inventory.set_variable(node_id, ansible_opt_key, ansible_opt_value)

                retry_join_nodes: Dict[str, VaultRaftNode] = raft_nodes_list.copy()
                retry_join_nodes.pop(node_id)

                if (
                    raft_node_details.explicit_retry_join_nodes is not None
                    and len(raft_node_details.explicit_retry_join_nodes) > 0
                ):
                    for explicit_retry_join_node_id in raft_node_details.explicit_retry_join_nodes:
                        if explicit_retry_join_node_id not in retry_join_nodes:
                            raise ValueError(
                                f"Vault Server: {vault_server_name}, Vault Node: {node_id}, "
                                f"retry_join_node_id {explicit_retry_join_node_id} not found in inventory"
                            )

                    retry_join_nodes_keys: List[str] = list(retry_join_nodes.keys())
                    for retry_join_node_id in retry_join_nodes_keys:
                        if retry_join_node_id not in raft_node_details.explicit_retry_join_nodes:
                            retry_join_nodes.pop(retry_join_node_id)

                if raft_node_details.explicit_retry_join_nodes is None:
                    retry_join_nodes = {}

                raft_node_details.retry_join_nodes = json.loads(
                    json.dumps(retry_join_nodes, default=to_jsonable_python)
                )

                self.inventory.set_variable(
                    node_id,
                    "pv_vault_raft_node_details",
                    json.loads(json.dumps(raft_node_details, default=to_jsonable_python)),
                )

            self.inventory.set_variable(
                vault_server_name,
                "pv_vault_raft_nodes_in_host",
                json.loads(json.dumps(raft_nodes_id_details, default=to_jsonable_python)),
            )
