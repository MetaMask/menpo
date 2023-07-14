from stix2 import (AttackPattern, Identity, Indicator, Note, Relationship, Report, ThreatActor)
from stix2 import Bundle, ExternalReference
from stix2.base import STIXJSONEncoder
from stix2.properties import EnumProperty, IntegerProperty, StringProperty, TimestampProperty
from stix2.v21 import CustomExtension, CustomObservable
import json
import os

################################################################################
##
## STIX Extension definitions
##
## - x_defi_estimated_loss_usd for the report SDO
## - x_defi_taxonomy_* for the attack-pattern SDO
## - x-defi-address SCO
##
################################################################################

# We can get the UUID with
#   python3 -c "import uuid; print(str(uuid.uuid4()))"
REPORT_EXTENSION_DEFINITION_ID = "extension-definition--393acb6c-fe64-42b5-92d5-a8ec243c4876"

@CustomExtension(
    REPORT_EXTENSION_DEFINITION_ID, [
        ("x_defi_estimated_loss_usd", IntegerProperty(required=True)),
    ],
)

class ReportExtension:
    extension_type = "toplevel-property-extension"

ATTACK_PATTERN_EXTENSION_DEFINITION_ID = "extension-definition--59cde1e5-2ce1-4732-a09d-596f401ba65b"

@CustomExtension(
    ATTACK_PATTERN_EXTENSION_DEFINITION_ID, [
        ("x_defi_taxonomy_layer", EnumProperty(["NET", "CON", "SC", "PRO", "AUX"], required=True)),
        ("x_defi_taxonomy_incident_cause", StringProperty(required=True)),
        ("x_defi_taxonomy_incident_type", StringProperty(required=True)),
    ],
)

class AttackPatternExtension:
    extension_type = "toplevel-property-extension"

@CustomObservable('x-defi-address', [
    ('name', StringProperty(required=True)),
    ('description', StringProperty(required=True)),
    ('created', TimestampProperty(required=True)),
    ('modified', TimestampProperty(required=True)),
    ('blockchain', StringProperty(required=True)),
    ('value', StringProperty(required=True)),
])
class XDefiAddress():
    pass

################################################################################
##
## In this exercise we use the same ISO 8601 for created and modified in all objects
## If you feel adventurous, use
##      import datetime
##      current_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
##
################################################################################

created_date = "2023-04-19T00:00:00Z"
modified_date = "2023-04-19T00:00:00Z"

################################################################################
##
## Attacker
## threat-actor SDO, indicator SDO, relationship SRO
##
################################################################################

attacker = ThreatActor(
    created=created_date,
    modified=modified_date,
    name="Bo Shen Attacker",
    description="A total of 42M worth of crypto assets,\
    including 38M in USDC were stolen from Bo Shen's\
    personal wallet in the early morning of November 10 EST."
)

attacker_indicator = {}

attacker_indicator["00"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date, # In the future, should be valid from at least the timestamp of the attack
    name="0x66f62574ab04989737228d18c3624f7fc1edae14", # For example, the address value
    description="Bo Shen Attacker",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x66f62574ab04989737228d18c3624f7fc1edae14' AND x-defi-address:blockchain = 'ethereum']" # Example
)

attacker_indicator["01"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date, # In the future, should be valid from at least the timestamp of the attack
    name="0x24b93eed37e6ffe948a9bdf365d750b52adcbc2e", # For example, the address value
    description="Bo Shen Attacker",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x24b93eed37e6ffe948a9bdf365d750b52adcbc2e' AND x-defi-address:blockchain = 'ethereum']" # Example
)

relationship_attacker_indicator = {}

for i in range(0, 2):
    relationship_attacker_indicator[f"{i:02d}"] = Relationship(
        created=created_date,
        modified=modified_date,
        relationship_type="indicates",
        spec_version="2.1",
        source_ref=attacker_indicator[f"{i:02d}"].id,
        target_ref=attacker.id
    )

################################################################################
##
## TTP
## attack-pattern SDO, relationship SRO
##
################################################################################

attack_pattern = AttackPattern(
    created=created_date,
    modified=modified_date,
    name="Mnemonic words compromise",
    x_defi_taxonomy_layer="AUX",
    x_defi_taxonomy_incident_cause="Faulty Operation",
    x_defi_taxonomy_incident_type="Compromised private key / wallet",
    extensions={
        "extension-definition--59cde1e5-2ce1-4732-a09d-596f401ba65b" : {
            'extension_type': 'toplevel-property-extension',
        },
    }
)

# threat-actor -> attack-pattern
relationship_threat_actor_attack_pattern = Relationship(
    created=created_date,
    modified=modified_date,
    relationship_type="uses",
    spec_version="2.1",
    source_ref=attacker.id,
    target_ref=attack_pattern.id
)

################################################################################
##
## Victim
## identity SDO, x-defi-address SCO, relationship SRO
##
################################################################################

victim_identity = Identity(
    created=created_date,
    modified=modified_date,
    name="Bo Shen",
    description="Bo Shen. Fenbushi Capital @fenbushi",
    identity_class="individual",
    sectors=["financial-services"],
    external_references=[
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/boshen1011/"
        ),
    ]
)

victim_address = {}

victim_address["00"] = XDefiAddress(
    created=created_date,
    modified=modified_date,
    name="0x6be85603322df6dc66163ef5f82a9c6ffbc5e894", # Use the address as name
    description="Bo Shen address",
    blockchain="ethereum", # Not an enum
    value="0x6be85603322df6dc66163ef5f82a9c6ffbc5e894",
)

victim_address["01"] = XDefiAddress(
    created=created_date,
    modified=modified_date,
    name="TJLBmmUb5TcFFXTLzuuaKU96uTg5Sjn1yD22", # Use the address as name
    description="Bo Shen address",
    blockchain="tron", # Not an enum
    value="TJLBmmUb5TcFFXTLzuuaKU96uTg5Sjn1yD22",
)

victim_address["02"] = XDefiAddress(
    created=created_date,
    modified=modified_date,
    name="bc1qg3mnvn8saea50js7nzkhm8k054mpwqmcuq3de5", # Use the address as name
    description="Bo Shen address",
    blockchain="bitcoin", # Not an enum
    value="bc1qg3mnvn8saea50js7nzkhm8k054mpwqmcuq3de5",
)

victim_address["03"] = XDefiAddress(
    created=created_date,
    modified=modified_date,
    name="1ECNeZyiHgqJmv42i3pkWY48xiXy7KukTG", # Use the address as name
    description="Bo Shen address",
    blockchain="bitcoin", # Not an enum
    value="1ECNeZyiHgqJmv42i3pkWY48xiXy7KukTG",
)

relationship_victim = {}

# Binds addresses to the victim
for i in range(0, 4):
    relationship_victim[f"{i:02d}"] = Relationship(
        created=created_date,
        modified=modified_date,
        relationship_type="uses",
        spec_version="2.1",
        source_ref=victim_identity.id,
        target_ref=victim_address[f"{i:02d}"].id,
        allow_custom=True
    )

# threat-actor -> victim
relationship_attack_pattern_victim = Relationship(
    created=created_date,
    modified=modified_date,
    relationship_type="targets",
    spec_version="2.1",
    source_ref=attacker.id,
    target_ref=victim_identity.id
)

# attack-pattern -> victim
relationship_attacker_victim = Relationship(
    created=created_date,
    modified=modified_date,
    relationship_type="targets",
    spec_version="2.1",
    source_ref=attack_pattern.id,
    target_ref=victim_identity.id
)

victim_wallet_identity = Identity(
    created=created_date,
    modified=modified_date,
    name="Trust Wallet",
    description="Cryptocurrency Wallet",
    identity_class="system",
    sectors=["financial-services"],
    external_references=[
        ExternalReference(
            source_name="Trust Wallet",
            url="https://trustwallet.com/"
        ),
    ]
)

relationship_victim_wallet = Relationship(
    created=created_date,
    modified=modified_date,
    relationship_type="uses",
    spec_version="2.1",
    source_ref=victim_identity.id,
    target_ref=victim_wallet_identity.id
)

################################################################################
##
## The actual report
## report SDO
##
## Notice the relevant fields at the report SDO
## - published: ISO 8601 of the attack
## - external_references: Links to blog posts, tweets, etc
## - x_defi_estimated_loss_usd
##
################################################################################

incident_report = Report(
    created=created_date,
    modified=modified_date,
    name="Bo Shen 22.11.22",
    description="A total of 42M worth of crypto assets,\
    including 38M in USDC were stolen from Bo Shen's\
    personal wallet in the early morning of November 10 EST.",
    published="2022-11-22T00:00:00Z",
    report_types=["threat-actor", "attack-pattern"], # May vary based on what you have
    object_refs=[
        attacker,
        victim_identity,
    ],
    external_references=[
        ExternalReference(
            source_name="",
            url="https://twitter.com/boshen1011/status/1595266905035644929"
        ),
        ExternalReference(
            source_name="",
            url="https://twitter.com/SlowMist_Team/status/1595265080752766976"
        ),
        ExternalReference(
            source_name="Decrypt",
            url="https://decrypt.co/115420/fenbushi-founder-bo-shen-loses-42m-stablecoins-bitcoin-ethereum-hackers"
        ),
    ],
    x_defi_estimated_loss_usd=42000000,
    extensions={
        "extension-definition--393acb6c-fe64-42b5-92d5-a8ec243c4876" : {
            'extension_type': 'toplevel-property-extension',
        },
    }
)

################################################################################

BundleofAllObjects = Bundle(
    attacker,
    attacker_indicator["00"],
    attacker_indicator["01"],
    relationship_attacker_indicator["00"],
    relationship_attacker_indicator["01"],
    attack_pattern,
    relationship_threat_actor_attack_pattern,
    victim_identity,
    victim_address["00"],
    victim_address["01"],
    victim_address["02"],
    victim_address["03"],
    relationship_victim["00"],
    relationship_victim["01"],
    relationship_victim["02"],
    relationship_victim["03"],
    relationship_attack_pattern_victim,
    relationship_attacker_victim,
    victim_wallet_identity,
    relationship_victim_wallet,
    incident_report,
    allow_custom=True
)

with open('../json-stix-db/22.11.22.bo.shen.json', 'w') as f:
    f.write(json.dumps(BundleofAllObjects, indent=4, cls=STIXJSONEncoder))

# Count objects by type and print it
from collections import defaultdict
object_count = defaultdict(int)

for obj in BundleofAllObjects.objects:
    object_count[obj.type] += 1

sorted_object_count = {key: object_count[key] for key in sorted(object_count)}
print(sorted_object_count)
