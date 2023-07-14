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

# python3 -c "from datetime import datetime; print(datetime.utcnow().replace(microsecond=0).isoformat() + 'Z')"
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
    name="",
    description=""
)

attacker_indicator = {}

attacker_indicator["00"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date, # In the future, should be valid from at least the timestamp of the attack
    name="", # For example, the address value
    description="",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' AND x-defi-address:blockchain = 'abc']" # Example
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
    name="",
    x_defi_taxonomy_layer="AUX", # Example
    x_defi_taxonomy_incident_cause="",
    x_defi_taxonomy_incident_type="",
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
    name="",
    description="",
    identity_class="organization", # Example
    sectors=["financial-services"], # Example
    external_references=[
        ExternalReference(
            source_name="",
            url=""
        )
    ]
)

victim_address = {}

victim_address["00"] = XDefiAddress(
    created=created_date,
    modified=modified_date,
    name="", # Use the address as name
    description="",
    blockchain="", # Not an enum
    value="",
)

relationship_victim = {}

# Binds addresses to the victim
for i in range(0, 1):
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
        "" # Description will generally have several lines
    ),
    published="2022-09-01T00:00:00Z", # Example
    report_types=["threat-actor", "attack-pattern"], # May vary based on what you have
    object_refs=[
        attacker,
        victim_identity,
    ],
    external_references=[
        ExternalReference(
            source_name="",
            url=""
        ),
        ExternalReference(
            source_name="",
            url=""
        ),
    ],
    x_defi_estimated_loss_usd=0,
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

incident_logs = [
    {
        "timestamp": "",
        "event": ""
    }
]

incident_note_objects = [
    Note(
        created=created_date,
        modified=modified_date,
        content=f"{log['timestamp']} - {log['event']}",
        object_refs=incident_report.id,
    )
    for log in incident_logs
]

comments = [
    "",
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
    relationship_attacker_indicator["00"],
    attack_pattern,
    relationship_threat_actor_attack_pattern,
    victim_identity,
    victim_address["00"],
    relationship_victim["00"],
    relationship_attack_pattern_victim,
    relationship_attacker_victim,
    incident_report,
    incident_note_objects[0],
    allow_custom=True
)

# File carpentry
script_name = os.path.basename(__file__)
json_file_name = os.path.splitext(script_name)[0] + ".json"

with open('../json-stix-db/' + json_file_name, 'w') as f:
    f.write(json.dumps(BundleofAllObjects, indent=4, cls=STIXJSONEncoder))

# Count objects by type and print it
from collections import defaultdict
object_count = defaultdict(int)

for obj in BundleofAllObjects.objects:
    object_count[obj.type] += 1

sorted_object_count = {key: object_count[key] for key in sorted(object_count)}
print(sorted_object_count)
