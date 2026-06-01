import os
from pymongo import MongoClient
from pymongo.encryption import Algorithm, ClientEncryption
from pymongo.encryption_options import TextOpts, SubstringOpts, PrefixOpts, SuffixOpts

local_master_key = os.urandom(96)
kms_providers = {"local": {"key": local_master_key}}
key_vault_namespace = "keyvault.datakeys"
key_vault_db_name, key_vault_coll_name = key_vault_namespace.split(".", 1)

client = MongoClient()
key_vault = client[key_vault_db_name][key_vault_coll_name]
key_vault.drop()

client_encryption = ClientEncryption(
    kms_providers,
    key_vault_namespace,
    client,
    client.codec_options,
)

# Create a new data key for the encryptedField.
key_id = client_encryption.create_data_key("local")

contention=9223372036854775806

insert_payload = client_encryption.encrypt(
    "foobar",
    contention_factor=contention,
    algorithm="TextPreview",
    text_opts=TextOpts(
        substring=SubstringOpts(
            strMinQueryLength=2, strMaxQueryLength=10, strMaxLength=20
        ),
        case_sensitive=False,
        diacritic_sensitive=False,
    ),
    key_id=key_id,
)
print("Created substring insert payload sized: {}".format(len(insert_payload)))


find_payload = client_encryption.encrypt(
    "foobar",
    contention_factor=contention,
    algorithm="TextPreview",
    query_type="substringPreview",
    text_opts=TextOpts(
        substring=SubstringOpts(
            strMinQueryLength=2, strMaxQueryLength=10, strMaxLength=20
        ),
        case_sensitive=False,
        diacritic_sensitive=False,
    ),
    key_id=key_id,
)
print("Created substring find payload sized: {}".format(len(find_payload)))

insert_payload = client_encryption.encrypt(
    "foobar",
    contention_factor=contention,
    algorithm="TextPreview",
    text_opts=TextOpts(
        prefix=PrefixOpts(
            strMinQueryLength=2, strMaxQueryLength=10
        ),
        case_sensitive=False,
        diacritic_sensitive=False,
    ),
    key_id=key_id,
)
print("Created prefix insert payload sized: {}".format(len(insert_payload)))


find_payload = client_encryption.encrypt(
    "foobar",
    contention_factor=contention,
    algorithm="TextPreview",
    query_type="prefixPreview",
    text_opts=TextOpts(
        prefix=PrefixOpts(
            strMinQueryLength=2, strMaxQueryLength=10
        ),
        case_sensitive=False,
        diacritic_sensitive=False,
    ),
    key_id=key_id,
)
print("Created prefix find payload sized: {}".format(len(find_payload)))


insert_payload = client_encryption.encrypt(
    "foobar",
    contention_factor=contention,
    algorithm="TextPreview",
    text_opts=TextOpts(
        suffix=SuffixOpts(
            strMinQueryLength=2, strMaxQueryLength=10
        ),
        case_sensitive=False,
        diacritic_sensitive=False,
    ),
    key_id=key_id,
)
print("Created suffix insert payload sized: {}".format(len(insert_payload)))


find_payload = client_encryption.encrypt(
    "foobar",
    contention_factor=contention,
    algorithm="TextPreview",
    query_type="suffixPreview",
    text_opts=TextOpts(
        suffix=SuffixOpts(
            strMinQueryLength=2, strMaxQueryLength=10
        ),
        case_sensitive=False,
        diacritic_sensitive=False,
    ),
    key_id=key_id,
)
print("Created suffix find payload sized: {}".format(len(find_payload)))
