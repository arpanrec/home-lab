# *-* coding: utf-8 *-*
"""
This module defines the `VaultHaClient` class, which represents
 a client for interacting with HashiCorp Vault in a high-availability (HA) setup.

Classes:
    VaultHaClient: A Pydantic model that encapsulates the configuration and methods required
      to interact with a HashiCorp Vault HA setup.

Attributes:
    model_config (ConfigDict): Configuration for the Pydantic model allowing arbitrary types.
    _vault_client (Optional[hvac.Client]): An optional hvac client instance.
    admin_user (str): The admin username for Vault authentication.
    admin_password (str): The admin password for Vault authentication.
    userpass_mount (str): The mount point for userpass authentication.
    policy_name (str): The name of the policy to be used.
    client_cert_pem (str): The client certificate in PEM format.
    client_key_pem (str): The client key in PEM format.
    vault_ha_hostname (str): The hostname of the Vault HA instance.
    vault_ha_port (int): The port of the Vault HA instance.
    client_cert_p12_base64 (str): The client certificate in PKCS12 format, base64 encoded.
    client_cert_p12_passphrase (str): The passphrase for the PKCS12 client certificate.
    root_ca_cert_pem (str): The root CA certificate in PEM format.
    token (Optional[str]): The authentication token for Vault.
    vault_root_ca_cert_file (Optional[str]): The file path for the root CA certificate.
    vault_client_cert_file (Optional[str]): The file path for the client certificate.
    vault_client_key_file (Optional[str]): The file path for the client key.
    _hvac_client (Optional[hvac.Client]): A private attribute for the hvac client instance.

Methods:
    __init__(self, vault_config: Optional[VaultConfig] = None, **data: Any) -> None:
        Initializes the VaultHaClient instance with the provided configuration and data.

    __prepare__(self) -> None:
        Prepares the client by writing certificates to files and configuring the hvac client.

    hvac_client(self) -> hvac.Client:
        Returns the hvac client object, authenticating if necessary.

    evaluate_token(self) -> None:
        Sets the token for the client by retrieving it from the hvac client.
"""

import base64
from typing import Any, Optional

import hvac  # type: ignore
import requests
import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr
from requests.sessions import HTTPAdapter
from urllib3 import Retry

from ..models.vault_config import VaultConfig


class VaultHaClient(BaseModel):
    """
    Represents a client for interacting with HashiCorp Vault in a high-availability (HA) setup.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)
    _vault_client: Optional[hvac.Client] = None
    admin_user: str = Field(default=...)
    admin_password: str = Field(default=...)
    userpass_mount: str = Field(default=...)
    policy_name: str = Field(default=...)
    client_cert_pem: str = Field(default=...)
    client_key_pem: str = Field(default=...)
    vault_ha_hostname: str = Field(default=...)
    vault_ha_port: int = Field(default=...)
    client_cert_p12_base64: str = Field(default=...)
    client_cert_p12_passphrase: str = Field(default=...)
    root_ca_cert_pem: str = Field(default=...)
    token: Optional[str] = Field(default=None)

    vault_root_ca_cert_file: Optional[str] = Field(default=None)
    vault_client_cert_file: Optional[str] = Field(default=None)
    vault_client_key_file: Optional[str] = Field(default=None)
    _hvac_client: Optional[hvac.Client] = PrivateAttr(default=None)

    def __init__(self, vault_config: Optional[VaultConfig] = None, **data: Any) -> None:
        super().__init__(**data)
        if not vault_config:
            return
        with open(f"{vault_config.vaultops_tmp_dir_path}/vault-ha-client.yml", "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False)

        self.vault_root_ca_cert_file = f"{vault_config.vaultops_tmp_dir_path}/vault-ha-root-ca.pem"
        self.vault_client_cert_file = f"{vault_config.vaultops_tmp_dir_path}/vault-ha-client-cert.pem"
        self.vault_client_key_file = f"{vault_config.vaultops_tmp_dir_path}/vault-ha-client-priv.key"
        with open(f"{vault_config.vaultops_tmp_dir_path}/vault-ha-client-cert.p12", "wb") as f:
            f.write(base64.b64decode(self.client_cert_p12_base64))

        self.__prepare__()

    def __prepare__(self) -> None:
        with open(str(self.vault_root_ca_cert_file), "w", encoding="utf-8") as f:
            f.write(self.root_ca_cert_pem)

        with open(str(self.vault_client_cert_file), "w", encoding="utf-8") as f:
            f.write(self.client_cert_pem)

        with open(str(self.vault_client_key_file), "w", encoding="utf-8") as f:
            f.write(self.client_key_pem)

        adapter = HTTPAdapter(max_retries=Retry(total=2, backoff_factor=2))
        session: requests.Session = requests.Session()
        session.verify = self.vault_root_ca_cert_file
        session.cert = (str(self.vault_client_cert_file), str(self.vault_client_key_file))
        session.mount("https://", adapter)
        hvac_client = hvac.Client(
            url=f"https://{self.vault_ha_hostname}:{self.vault_ha_port}", session=session, timeout=2
        )
        self._hvac_client = hvac_client

    def hvac_client(self) -> hvac.Client:
        """
        Returns the hvac client object
        """
        if not self._hvac_client:
            self.__prepare__()
        if self._hvac_client and not self._hvac_client.is_authenticated():
            self._hvac_client.auth.userpass.login(
                username=self.admin_user, password=self.admin_password, mount_point=self.userpass_mount
            )
        return self._hvac_client

    def evaluate_token(self) -> None:
        """
        Sets the token for the client
        """
        self.token = self.hvac_client().token
