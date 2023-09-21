from stix2 import AttackPattern, ExternalReference, FileSystemStore, \
    Identity, Indicator, Note, Relationship, Report, ThreatActor
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
        ("x_defi_taxonomy_layer", EnumProperty(["NET", "CON", "SC", "Pro", "AUX"], required=True)),
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
    name="FTX Drainer",
    description="On Nov 12 FTX and FTX US experienced suspicious withdrawals upwards of $450m."
)

attacker_indicator = {}

attacker_indicator["00"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date, # In the future, should be valid from at least the timestamp of the attack
    name="0x59ABf3837Fa962d6853b4Cc0a19513AA031fd32b", # For example, the address value
    description="FTX Drainer 00",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x59ABf3837Fa962d6853b4Cc0a19513AA031fd32b' AND (x-defi-address:blockchain = 'ethereum' OR x-defi-address:blockchain = 'bsc')]"
)

attacker_indicator["01"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date, # In the future, should be valid from at least the timestamp of the attack
    name="6sEk1enayZBGFyNvvJMTP7qs5S3uC7KLrQWaEk38hSHH", # For example, the address value
    description="FTX Drainer 01",
    pattern_type="stix",
    pattern="[x-defi-address:value = '6sEk1enayZBGFyNvvJMTP7qs5S3uC7KLrQWaEk38hSHH' AND x-defi-address:blockchain = 'solana']"
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
    name="Unauthorized withdrawals",
    x_defi_taxonomy_layer="AUX",
    x_defi_taxonomy_incident_cause="Greedy Operator",
    x_defi_taxonomy_incident_type="Insider trade or other activities",
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
    name="FTX",
    description="FTX is a cryptocurrency exchange founded in 2017 by Sam Bankman-Fried and Gary Wang.",
    identity_class="organization", # Example
    sectors=["financial-services"], # Example
    external_references=[
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/FTX_Official"
        )
    ]
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
    name="FTX 22.11.12",
    description=(
        "On Nov 12 FTX and FTX US experienced suspicious withdrawals upwards of $450m.",
        "The tokens were sold for DAI, ETH, BNB, & more.",
        "The tokens were consolidated into one main wallet 0x59.",
        "FTX US GC Ryne Miller clarified these were unauthorized transactions.",
        "Tether and Paxos froze assets on Ethereum, Solana, and Avalanche."
    ),
    published="2022-11-12T00:00:00Z", # Example
    report_types=["threat-actor", "attack-pattern"], # May vary based on what you have
    object_refs=[
        attacker,
        victim_identity,
    ],
    external_references=[
        ExternalReference(
            source_name="Rekt News",
            url="https://rekt.news/sbf-mask-off/"
        ),
        ExternalReference(
            source_name="CoinDesk",
            url="https://www.coindesk.com/business/2022/11/10/tether-freezes-46m-of-usdt-following-law-enforcement-request/"
        ),
        ExternalReference(
            source_name="Decrypt",
            url="https://decrypt.co/114587/paxos-freezes-paxg-crypto-ftx"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/_Ryne_Miller/status/1591495427211526146"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/zachxbt/status/1591475246250733568"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/zachxbt/status/1591276687228035074"
        )
    ],
    x_defi_estimated_loss_usd=450000000,
    extensions={
        "extension-definition--393acb6c-fe64-42b5-92d5-a8ec243c4876" : {
            'extension_type': 'toplevel-property-extension',
        },
    }
)

################################################################################

fs = FileSystemStore("../../db")
fs.add([
    attacker,
    attacker_indicator["00"],
    attacker_indicator["01"],
    relationship_attacker_indicator["00"],
    relationship_attacker_indicator["01"],
    attack_pattern,
    relationship_threat_actor_attack_pattern,
    victim_identity,
    relationship_attack_pattern_victim,
    relationship_attacker_victim,
    incident_report
])
