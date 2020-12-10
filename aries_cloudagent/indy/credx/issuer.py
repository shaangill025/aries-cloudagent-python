"""Indy issuer implementation."""

import asyncio
import logging

from typing import Sequence, Tuple

from aries_askar import StoreError

from indy_credx import (
    Credential,
    CredentialDefinition,
    CredentialOffer,
    CredxError,
    RevocationRegistryDefinition,
    RevocationRegistryDelta,
    Schema,
)

from ...askar.profile import AskarProfile

from ..issuer import (
    IndyIssuer,
    IndyIssuerError,
    DEFAULT_CRED_DEF_TAG,
    DEFAULT_SIGNATURE_TYPE,
)

LOGGER = logging.getLogger(__name__)

CATEGORY_CRED_DEF = "credential_definition"
CATEGORY_CRED_DEF_PRIVATE = "credential_definition_private"
CATEGORY_CRED_DEF_KEY_PROOF = "credential_definition_key_proof"
CATEGORY_SCHEMA = "schema"
CATEGORY_REV_REG_DEF = "revocation_registry_definition"
CATEGORY_REV_REG_ISSUER = "revocation_registry_issuer"

REV_REGS = {}


class IndyCredxIssuer(IndyIssuer):
    """Indy-Credx issuer class."""

    def __init__(self, profile: AskarProfile):
        """
        Initialize an IndyCredxIssuer instance.

        Args:
            profile: The active profile instance

        """
        self._profile = profile

    @property
    def profile(self) -> AskarProfile:
        """Accessor for the profile instance."""
        return self._profile

    async def create_schema(
        self,
        origin_did: str,
        schema_name: str,
        schema_version: str,
        attribute_names: Sequence[str],
    ) -> Tuple[str, str]:
        """
        Create a new credential schema and store it in the wallet.

        Args:
            origin_did: the DID issuing the credential definition
            schema_name: the schema name
            schema_version: the schema version
            attribute_names: a sequence of schema attribute names

        Returns:
            A tuple of the schema ID and JSON

        """
        try:
            schema = Schema.create(
                origin_did, schema_name, schema_version, attribute_names
            )
            schema_id = schema.id
            schema_json = schema.to_json()
            async with self._profile.session() as session:
                await session.handle.insert(CATEGORY_SCHEMA, schema_id, schema_json)
        except CredxError as err:
            raise IndyIssuerError("Error creating schema") from err
        except StoreError as err:
            raise IndyIssuerError("Error storing schema") from err
        return (schema_id, schema_json)

    async def credential_definition_in_wallet(
        self, credential_definition_id: str
    ) -> bool:
        """
        Check whether a given credential definition ID is present in the wallet.

        Args:
            credential_definition_id: The credential definition ID to check
        """
        try:
            async with self._profile.session() as session:
                return (
                    await session.handle.fetch(
                        CATEGORY_CRED_DEF_KEY_PROOF, credential_definition_id
                    )
                ) is not None
        except StoreError as err:
            raise IndyIssuerError("Error checking for credential definition") from err

    async def create_and_store_credential_definition(
        self,
        origin_did: str,
        schema: dict,
        signature_type: str = None,
        tag: str = None,
        support_revocation: bool = False,
    ) -> Tuple[str, str]:
        """
        Create a new credential definition and store it in the wallet.

        Args:
            origin_did: the DID issuing the credential definition
            schema_json: the schema used as a basis
            signature_type: the credential definition signature type (default 'CL')
            tag: the credential definition tag
            support_revocation: whether to enable revocation for this credential def

        Returns:
            A tuple of the credential definition ID and JSON

        """
        try:
            (
                cred_def,
                cred_def_private,
                key_proof,
            ) = await asyncio.get_event_loop().run_in_executor(
                None,
                CredentialDefinition.create,
                origin_did,
                schema,
                signature_type or DEFAULT_SIGNATURE_TYPE,
                tag or DEFAULT_CRED_DEF_TAG,
                # support_revocation=support_revocation,
            )
            cred_def_id = cred_def.id
            cred_def_json = cred_def.to_json()
        except CredxError as err:
            raise IndyIssuerError("Error creating credential definition") from err
        try:
            async with self._profile.transaction() as txn:
                await txn.handle.insert(
                    CATEGORY_CRED_DEF,
                    cred_def_id,
                    cred_def_json,
                    # Note: Indy-SDK uses a separate SchemaId record for this
                    tags={"schema_id": schema["id"]},
                )
                await txn.handle.insert(
                    CATEGORY_CRED_DEF_PRIVATE,
                    cred_def_id,
                    cred_def_private.to_json_buffer(),
                )
                await txn.handle.insert(
                    CATEGORY_CRED_DEF_KEY_PROOF, cred_def_id, key_proof.to_json_buffer()
                )
                await txn.commit()
        except StoreError as err:
            raise IndyIssuerError("Error storing credential definition") from err
        return (cred_def_id, cred_def_json)

    async def create_credential_offer(self, credential_definition_id: str) -> str:
        """
        Create a credential offer for the given credential definition id.

        Args:
            credential_definition_id: The credential definition to create an offer for

        Returns:
            The new credential offer

        """
        try:
            async with self._profile.session() as session:
                cred_def = await session.handle.fetch(
                    CATEGORY_CRED_DEF, credential_definition_id
                )
                key_proof = await session.handle.fetch(
                    CATEGORY_CRED_DEF_KEY_PROOF, credential_definition_id
                )
        except StoreError as err:
            raise IndyIssuerError("Error retrieving credential definition") from err
        if not cred_def or not key_proof:
            raise IndyIssuerError(
                "Credential definition not found for credential offer"
            )
        try:
            schema_id = cred_def.tags.get("schema_id")
            cred_def = CredentialDefinition.load(cred_def.raw_value)

            credential_offer = CredentialOffer.create(
                schema_id or cred_def.schema_id,
                cred_def,
                key_proof.raw_value,
            )
        except CredxError as err:
            raise IndyIssuerError("Error creating credential offer") from err

        return credential_offer.to_json()

    async def create_credential(
        self,
        schema: dict,
        credential_offer: dict,
        credential_request: dict,
        credential_values: dict,
        cred_ex_id: str,
        revoc_reg_id: str = None,
        tails_reader_handle: int = None,
    ) -> Tuple[str, str]:
        """
        Create a credential.

        Args
            schema: Schema to create credential for
            credential_offer: Credential Offer to create credential for
            credential_request: Credential request to create credential for
            credential_values: Values to go in credential
            cred_ex_id: credential exchange identifier to use in issuer cred rev rec
            revoc_reg_id: ID of the revocation registry
            tails_reader_handle: Handle for the tails file blob reader

        Returns:
            A tuple of created credential and revocation id

        """
        credential_definition_id = credential_offer["cred_def_id"]
        try:
            async with self._profile.session() as session:
                cred_def = await session.handle.fetch(
                    CATEGORY_CRED_DEF, credential_definition_id
                )
                cred_def_private = await session.handle.fetch(
                    CATEGORY_CRED_DEF_PRIVATE, credential_definition_id
                )
        except StoreError as err:
            raise IndyIssuerError("Error retrieving credential definition") from err
        if not cred_def or not cred_def_private:
            raise IndyIssuerError(
                "Credential definition not found for credential issuance"
            )

        raw_values = {}
        schema_attributes = schema["attrNames"]
        for attribute in schema_attributes:
            # Ensure every attribute present in schema to be set.
            # Extraneous attribute names are ignored.
            try:
                credential_value = credential_values[attribute]
            except KeyError:
                raise IndyIssuerError(
                    "Provided credential values are missing a value "
                    f"for the schema attribute '{attribute}'"
                )

            raw_values[attribute] = str(credential_value)

        if revoc_reg_id:
            (rev_reg_def, rev_reg, rev_key, rev_idx) = REV_REGS[revoc_reg_id]
            rev_idx += 1
            revoc = (rev_reg_def, rev_reg, rev_key, rev_idx, rev_reg_def.tails_location)
            credential_revocation_id = str(rev_idx)
        else:
            revoc = ()
            credential_revocation_id = None

        try:
            (
                credential,
                upd_rev_reg,
                _delta,
            ) = await asyncio.get_event_loop().run_in_executor(
                None,
                Credential.create,
                cred_def.raw_value,
                cred_def_private.raw_value,
                credential_offer,
                credential_request,
                raw_values,
                *revoc,
            )
        except CredxError as err:
            raise IndyIssuerError("Error creating credential") from err
        if revoc:
            REV_REGS[revoc_reg_id][1] = upd_rev_reg
            REV_REGS[revoc_reg_id][3] = rev_idx

        return credential.to_json(), credential_revocation_id

    async def revoke_credentials(
        self, revoc_reg_id: str, tails_file_path: str, cred_revoc_ids: Sequence[str]
    ) -> str:
        """
        Revoke a set of credentials in a revocation registry.

        Args:
            revoc_reg_id: ID of the revocation registry
            tails_file_path: path to the local tails file
            cred_revoc_ids: sequences of credential indexes in the revocation registry

        Returns:
            the combined revocation delta

        """

        if revoc_reg_id not in REV_REGS:
            raise IndyIssuerError("Unknown revocation registry")

        try:
            upd_registry, delta = await asyncio.get_event_loop().run_in_executor(
                None,
                REV_REGS[revoc_reg_id][1].update,
                REV_REGS[revoc_reg_id][0],  # definition
                None,  # issued
                [int(rev_idx) for rev_idx in cred_revoc_ids],  # revoked
                tails_file_path,
            )
        except CredxError as err:
            raise IndyIssuerError("Error updating revocation registry") from err
        REV_REGS[revoc_reg_id][1] = upd_registry
        return delta.to_json()

    async def merge_revocation_registry_deltas(
        self, fro_delta: str, to_delta: str
    ) -> str:
        """
        Merge revocation registry deltas.

        Args:
            fro_delta: original delta in JSON format
            to_delta: incoming delta in JSON format

        Returns:
            Merged delta in JSON format

        """

        def update(d1, d2):
            try:
                delta = RevocationRegistryDelta.load(d1)
                delta.update_with(d2)
                return delta.to_json()
            except CredxError as err:
                raise IndyIssuerError(
                    "Error merging revocation registry deltas"
                ) from err

        return await asyncio.get_event_loop().run_in_executor(
            None, update, fro_delta, to_delta
        )

    async def create_and_store_revocation_registry(
        self,
        origin_did: str,
        cred_def_id: str,
        revoc_def_type: str,
        tag: str,
        max_cred_num: int,
        tails_base_path: str,
    ) -> Tuple[str, str, str]:
        """
        Create a new revocation registry and store it in the wallet.

        Args:
            origin_did: the DID issuing the revocation registry
            cred_def_id: the identifier of the related credential definition
            revoc_def_type: the revocation registry type (default CL_ACCUM)
            tag: the unique revocation registry tag
            max_cred_num: the number of credentials supported in the registry
            tails_base_path: where to store the tails file
            issuance_type: optionally override the issuance type

        Returns:
            A tuple of the revocation registry ID, JSON, and entry JSON

        """
        try:
            async with self._profile.session() as session:
                cred_def = await session.handle.fetch(CATEGORY_CRED_DEF, cred_def_id)
        except StoreError as err:
            raise IndyIssuerError("Error retrieving credential definition") from err

        try:
            (
                rev_reg_def,
                rev_reg,
                rev_reg_delta,
                rev_key,
            ) = await asyncio.get_event_loop().run_in_executor(
                None,
                RevocationRegistryDefinition.create,
                origin_did,
                cred_def.raw_value,
                tag,
                revoc_def_type,
                max_cred_num,
            )
        except CredxError as err:
            raise IndyIssuerError("Error creating revocation registry") from err
        REV_REGS[rev_reg_def.id] = [rev_reg_def, rev_reg, rev_key, 0]
        return (
            rev_reg_def.id,
            rev_reg_def.to_json(),
            rev_reg_delta.to_json(),
        )
