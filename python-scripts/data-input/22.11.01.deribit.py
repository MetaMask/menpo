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

# python3 -c "from datetime import datetime; print(datetime.utcnow().replace(microsecond=0).isoformat() + 'Z')"
created_date = "2023-05-01T01:09:29Z"
modified_date = "2023-05-01T01:09:29Z"

################################################################################
##
## Attacker
## threat-actor SDO, indicator SDO, relationship SRO
##
################################################################################

attacker = ThreatActor(
    created=created_date,
    modified=modified_date,
    name="Deribit Attacker",
    description="Deribit Exchange has lost $28M from their hot wallets on the Ethereum and Bitcoin networks."
)

attacker_indicator = {}

attacker_indicator["00"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="0xb0606f433496bf66338b8ad6b6d51fc4d84a44cd",
    description="Deribit Attacker Ethereum Address",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0xb0606f433496bf66338b8ad6b6d51fc4d84a44cd' AND x-defi-address:blockchain = 'ethereum']"
)

attacker_indicator["01"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="bc1qw5g8lw4kzltpdcraehy2dt6dqda8080xd6vhl4kg4wwsypwerg9s3x6pvk",
    description="Deribit Attacker Bitcoin Address",
    pattern_type="stix",
    pattern="[x-defi-address:value = 'bc1qw5g8lw4kzltpdcraehy2dt6dqda8080xd6vhl4kg4wwsypwerg9s3x6pvk' AND x-defi-address:blockchain = 'bitcoin']"
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
    name="Private key theft incident",
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
    name="Deribit",
    description="Cryptocurrency derivatives platform for traders of all backgrounds and trading styles",
    identity_class="organization",
    sectors=["financial-services"],
    external_references=[
        ExternalReference(
            source_name="Deribit",
            url="https://www.deribit.com/"
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
    name="Deribit 22.11.01",
    description=(
        "Deribit Exchange has lost $28M from their hot wallets on the Ethereum and Bitcoin networks."
    ),
    published="2022-11-01T00:00:00Z",
    report_types=["threat-actor", "attack-pattern"],
    object_refs=[
        attacker,
        victim_identity,
    ],
    external_references=[
        ExternalReference(
            source_name="Rekt News",
            url="https://rekt.news/deribit-rekt/"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/DeribitExchange/status/1587701883778523136"
        ),
    ],
    x_defi_estimated_loss_usd=28000000,
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
    relationship_attacker_indicator["00"],
    attacker_indicator["01"],
    relationship_attacker_indicator["01"],
    attack_pattern,
    relationship_threat_actor_attack_pattern,
    victim_identity,
    relationship_attack_pattern_victim,
    relationship_attacker_victim,
    incident_report
])
