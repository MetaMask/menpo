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
    name="MyAlgo Attacker",
    description=(
        "On February 20, 2023 and ongoing 2000+ Algorand network users and projects like ",
        "Algodex, Lofty, AlgoCasino, etc. lost $9.2M+ due to private key compromises.",
    )
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
    name="Potentially compromised CDN API key used.",
    x_defi_taxonomy_layer="AUX", # Example
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
    name="MyAlgo",
    description="Wallet of Algorand network",
    identity_class="organization",
    sectors=["financial-services"],
    external_references=[
        ExternalReference(
            source_name="Algorand Wallet",
            url="https://wallet.myalgo.com/home"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/myalgo_"
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
    name="MyAlgo 23.02.20",
    description=(
        "On February 20, 2023 and ongoing 2000+ Algorand network users and projects like ",
        "Algodex, Lofty, AlgoCasino, etc. lost $9.2M+ due to private key compromises.",
    ),
    published="2023-02-20T00:00:00Z", # Example
    report_types=["threat-actor", "attack-pattern"], # May vary based on what you have
    object_refs=[
        attacker,
        victim_identity,
    ],
    external_references=[
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/myalgo_/status/1649427788816842752"
        ),
        ExternalReference(
            source_name="Halborn",
            url="https://github.com/HalbornSecurity/PublicReports/blob/master/Incident%20Reports/RandLabs_MyAlgo_Wallet_Executive_Summary_Halborn%20.pdf"
        ),
    ],
    x_defi_estimated_loss_usd=9200000,
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
    "Attackers abused CDN for man-in-the-middle attack on http://wallet(.)myalgo(.)com webapp.",
    "Potentially compromised CDN API key used.",
    "Unclear how API key obtained.",
    "No evidence of MyAlgo codebase exploitation or vulnerability.",
    "No evidence of CDN user account compromise.",
    "CDN audit logs lack evidence of key creation for the attack.",
    "Logs cover 18 months; impacted account 19 months old, used only 6 months ago.",
    "Malicious worker uploaded on Jan 21st, attack lasted until mid-Feb with new MyAlgo version release.",
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

fs = FileSystemStore("../../db")
fs.add([
    attacker,
    attack_pattern,
    relationship_threat_actor_attack_pattern,
    victim_identity,
    relationship_attack_pattern_victim,
    relationship_attacker_victim,
    incident_report,
    incident_note_objects_comments[0],
    incident_note_objects_comments[1],
    incident_note_objects_comments[2],
    incident_note_objects_comments[3],
    incident_note_objects_comments[4],
    incident_note_objects_comments[5],
    incident_note_objects_comments[6],
    incident_note_objects_comments[7]
])
