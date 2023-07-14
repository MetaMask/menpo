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
    name="Mango Markets Attacker",
    description="Identified as Avraham Eisenberg"
)

attacker_identity = Identity(
    created=created_date,
    modified=modified_date,
    name="Avraham Eisenberg",
    description=(
        "Mango Markets Attacker"
    ),
    identity_class="individual",
    sectors=["financial-services", "technology"],
    external_references=[
        ExternalReference(
            source_name="Substack",
            url="http://deepfivalue.substack.com"
        ),
        ExternalReference(
            source_name="Substack",
            url="http://misinfounderload.substack.com"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/avi_eisen"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/avi_eisen/status/1581326197241180160"
        ),
    ]
)

relationship_attacker_identity = Relationship(
    created=created_date,
    modified=modified_date,
    relationship_type="attributed-to",
    spec_version="2.1",
    source_ref=attacker.id,
    target_ref=attacker_identity.id
)

attacker_indicator = {}

attacker_indicator["00"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date, # In the future, should be valid from at least the timestamp of the attack
    name="yUJw9a2PyoqKkH47i4yEGf4WXomSHMiK7Lp29Xs2NqM", # For example, the address value
    description="Mango Markets Attacker Address",
    pattern_type="stix",
    pattern="[x-defi-address:value = 'yUJw9a2PyoqKkH47i4yEGf4WXomSHMiK7Lp29Xs2NqM' AND x-defi-address:blockchain = 'solana']"
)

relationship_attacker_indicator = {}

for i in range(0, 1):
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
    name="Price Manipulation",
    description="Mango Markets later clarified that the incident was not\
    an oracle failure, but rather genuine price manipulation.",
    x_defi_taxonomy_layer="PRO",
    x_defi_taxonomy_incident_cause="Unsafe dependency",
    x_defi_taxonomy_incident_type="On-chain oracle manipulation",
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
    name="Mango Markets",
    description="Mango Markets is a decentralized trading platform built on the Solana blockchain.",
    identity_class="organization", # Example
    sectors=["financial-services"], # Example
    external_references=[
        ExternalReference(
            source_name="Mango Markets",
            url="https://mango.markets/"
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
    name="Mango Markets 22.10.11",
    description=(
        "On October 11, 2022 Mango Markets was exploited with a\
        price oracle manipulation attack with losses over $116M.\
        Interestingly, the attacker was soon discovered and engaged\
        in public discourse on Twitter."
    ),
    published="2022-09-01T00:00:00Z", # Example
    report_types=["threat-actor", "attack-pattern"], # May vary based on what you have
    object_refs=[
        attacker,
        victim_identity,
    ],
    external_references=[
        ExternalReference(
            source_name="Rekt News",
            url="https://rekt.news/mango-markets-rekt/"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/avi_eisen/status/1581326197241180160"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/joshua_j_lim/status/1579987648546246658"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/mangomarkets/status/1580074498174652416"
        ),
    ],
    x_defi_estimated_loss_usd=116000000,
    extensions={
        "extension-definition--393acb6c-fe64-42b5-92d5-a8ec243c4876" : {
            'extension_type': 'toplevel-property-extension',
        },
    }
)

################################################################################

BundleofAllObjects = Bundle(
    attacker,
    attacker_identity,
    relationship_attacker_identity,
    attacker_indicator["00"],
    relationship_attacker_indicator["00"],
    attack_pattern,
    relationship_threat_actor_attack_pattern,
    victim_identity,
    relationship_attack_pattern_victim,
    relationship_attacker_victim,
    incident_report,
    allow_custom=True
)

with open('../json-stix-db/22.10.11.mango.markets.json', 'w') as f:
    f.write(json.dumps(BundleofAllObjects, indent=4, cls=STIXJSONEncoder))

# Count objects by type and print it
from collections import defaultdict
object_count = defaultdict(int)

for obj in BundleofAllObjects.objects:
    object_count[obj.type] += 1

sorted_object_count = {key: object_count[key] for key in sorted(object_count)}
print(sorted_object_count)
