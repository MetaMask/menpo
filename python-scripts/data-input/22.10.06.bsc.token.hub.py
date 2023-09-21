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
    name="BSC Token Hub Attacker",
    description="On October 6, 2022 BSC Token Hub lost $586M due to an exploit bypassing cross-chain transfer proofs."
)

attacker_indicator = {}

attacker_indicator["00"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="0x489a8756c18c0b8b24ec2a2b9ff3d4d447f79bec",
    description="BSC Token Hub Attacker Address",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x489a8756c18c0b8b24ec2a2b9ff3d4d447f79bec' AND x-defi-address:blockchain = 'bsc']"
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
    name="Exploit bypassing cross-chain transfer proofs",
    x_defi_taxonomy_layer="PRO",
    x_defi_taxonomy_incident_cause="Unsafe dependency",
    x_defi_taxonomy_incident_type="Other unsafe DeFi protocol dependency",
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
    name="BSC Token Hub",
    description="The BNB bridge between the old Binance Beacon Chain and BSC.",
    identity_class="organization", # Example
    sectors=["financial-services"], # Example
    external_references=[
        ExternalReference(
            source_name="BSC Token Hub",
            url="https://www.bnbchain.org/cn/bridge"
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
    name="BSC Token 22.10.06",
    description=(
        "On October 6, 2022 BSC Token Hub lost $586M due to an exploit bypassing cross-chain transfer proofs.",
        "Following the compromise, BSC shut down the network preventing attackers from transferring majority of stolen assets."
    ),
    published="2022-10-06T00:00:00Z",
    report_types=["threat-actor", "attack-pattern"], # May vary based on what you have
    object_refs=[
        attacker,
        victim_identity,
    ],
    external_references=[
        ExternalReference(
            source_name="Medium",
            url="https://drdr-zz.medium.com/bnb-bridge-hack-eli5-explained-and-visualised-1fb2837c7a7e"
        ),
        ExternalReference(
            source_name="GitHub",
            url="https://github.com/emilianobonassi/bsc-hack-analysis-2022-10-06"
        ),
        ExternalReference(
            source_name="Rekt News",
            url="https://rekt.news/bnb-bridge-rekt/"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/cz_binance/status/1578171072067031042"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/dedaub/status/1578428002701959170"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/emilianobonassi/status/1578742880662716416"
        ),
        ExternalReference(
             source_name="Twitter",
            url="https://twitter.com/samczsun/status/1578167198203289600"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/samczsun/status/1578182840751050752"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/SlowMist_Team/status/1578220472373649408"
        ),
        ExternalReference(
            source_name="Nansen",
            url="https://www.nansen.ai/research/bnb-chains-cross-chain-bridge-exploit-explained"
        ),
    ],
    x_defi_estimated_loss_usd=585000000,
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
        "timestamp": "2022-10-06T18:26:00Z",
        "event": "Attacker succeeded in delivering a 1m BNB package to its own address."
    },
    {
        "timestamp": "2022-10-06T20:43:00Z",
        "event": "Attacker succeeded in delivering the last 1m BNB package to its own address."
    }
]

incident_note_objects_logs = [
    Note(
        created=created_date,
        modified=modified_date,
        content=f"{log['timestamp']} - {log['event']}",
        object_refs=incident_report.id,
    )
    for log in incident_logs
]

comments = [
    "Bridge used vulnerable IAVL verification (block 110217401, August 2020).",
    "Vulnerability handling (1): Binance Smart Chain halted.",
    "Vulnerability handling (2): Blacklist functionality added; attacker's address hardcoded.",
    "Vulnerability handling (3): Precompiled contract for Merkle proof verification suspended, restored 5 days later.",
    "Root cause: bridge code didn't account for user-set Left and Right attributes in path nodes.",
    "Summary: Bug in Binance Bridge proof verification allowed attackers to forge arbitrary messages.",
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
    attacker_indicator["00"],
    relationship_attacker_indicator["00"],
    attack_pattern,
    relationship_threat_actor_attack_pattern,
    victim_identity,
    relationship_attack_pattern_victim,
    relationship_attacker_victim,
    incident_report,
    incident_note_objects_logs[0],
    incident_note_objects_logs[1],
    incident_note_objects_comments[0],
    incident_note_objects_comments[1],
    incident_note_objects_comments[2],
    incident_note_objects_comments[3],
    incident_note_objects_comments[4],
    incident_note_objects_comments[5]
])
