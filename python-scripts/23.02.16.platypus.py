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
    name="Platypus Attacker",
    description="On February 16, 2023 Platypus lost $9m due to a logic error when handling withdrawals with borrowed assets."
)

attacker_indicator = {}

attacker_indicator["00"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="0xeff003d64046a6f521ba31f39405cb720e953958",
    description="Platypus Attacker",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0xeff003d64046a6f521ba31f39405cb720e953958' AND x-defi-address:blockchain = 'avalanche']"
)

attacker_indicator["01"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="0x1266a937c2ccd970e5d7929021eed3ec593a95c68a99b4920c2efa226679b430",
    description="Platypus Flash Loan Attack Transaction",
    pattern_type="stix",
    pattern="[x-defi-transaction:value = '0x1266a937c2ccd970e5d7929021eed3ec593a95c68a99b4920c2efa226679b430' AND x-defi-address:blockchain = 'avalanche']"
)

attacker_indicator["02"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="0xeff003d64046a6f521ba31f39405cb720e953958",
    description="Platypus Attack Contract",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0xeff003d64046a6f521ba31f39405cb720e953958' AND x-defi-address:blockchain = 'avalanche']"
)

relationship_attacker_indicator = {}

for i in range(0, 3):
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
    name="Logic error vulnerability",
    x_defi_taxonomy_layer="SC",
    x_defi_taxonomy_incident_cause="Coding mistake",
    x_defi_taxonomy_incident_type="Absence of coding logic or sanity check",
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
    name="Platypus",
    description="Avalanche-based Automated market maker (AMM)",
    identity_class="organization", # Example
    sectors=["financial-services"], # Example
    external_references=[
        ExternalReference(
            source_name="Platypus",
            url="https://platypus.finance/"
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
    name="",
    description=(
        "On February 16, 2023 Platypus lost $9m due to a logic error when handling withdrawals with borrowed assets.",
        "The exploit took advantage of a faulty check mechanism when withdrawing collateral."
    ),
    published="2023-02-16T00:00:00Z", # Example
    report_types=["threat-actor", "attack-pattern"], # May vary based on what you have
    object_refs=[
        attacker,
        victim_identity,
    ],
    external_references=[
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/CertiKAlert/status/1626318821840629763"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/danielvf/status/1626641254531448833",
            description="Comments on the reverse hack"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/zachxbt/status/1626434265260118021",
            description="ZachBT doxxed the attacker "
        ),
        ExternalReference(
            source_name="Medium",
            url="https://medium.com/@omniscia.io/platypus-finance-incident-post-mortem-7b71a0a47a5e",
            description="Platypus Incident postmortem"
        ),
    ],
    x_defi_estimated_loss_usd=9000000,
    extensions={
        "extension-definition--393acb6c-fe64-42b5-92d5-a8ec243c4876" : {
            'extension_type': 'toplevel-property-extension',
        },
    }
)

################################################################################
##
## Incident Logs
## (or other relevant information you want to include in the bundle)
## note SDO
##
## Please notice that it is the note the one pointing to the report SDO
##
################################################################################

comments = [
    "On February 16, 2023 Platypus lost $9m due to a logic error\
    when handling withdrawals with borrowed assets.\
    In a series of bizarre twists attacker failed to implement\
    a withdrawal function in their exploit contract effectively\
    freezing most of the stolen assets, got hacked by the BlockSec\
     team which recovered $2.4m USDC, and also got doxxed by\
     none other than ZachXBT.\
     Overall a happy end to a very sloppy hack.",
]

incident_note_objects_comments = [
    Note(
        created=created_date,
        modified=modified_date,
        content=comment,
        object_refs=incident_report.id,
    )
    for comment in comments
]

################################################################################

BundleofAllObjects = Bundle(
    attacker,
    attacker_indicator["00"],
    attacker_indicator["01"],
    attacker_indicator["02"],
    relationship_attacker_indicator["00"],
    relationship_attacker_indicator["01"],
    relationship_attacker_indicator["02"],
    attack_pattern,
    relationship_threat_actor_attack_pattern,
    victim_identity,
    relationship_attack_pattern_victim,
    relationship_attacker_victim,
    incident_report,
    incident_note_objects_comments[0],
    allow_custom=True
)

with open('../json-stix-db/22.02.16.platypus.json', 'w') as f:
    f.write(json.dumps(BundleofAllObjects, indent=4, cls=STIXJSONEncoder))

# Count objects by type and print it
from collections import defaultdict
object_count = defaultdict(int)

for obj in BundleofAllObjects.objects:
    object_count[obj.type] += 1

sorted_object_count = {key: object_count[key] for key in sorted(object_count)}
print(sorted_object_count)
