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
    name="BXH Attacker",
    description=(
        "On September 20th, 2022, Boy X Highspeed (BXH) –",
        "a financial services platform for Web3 and metaverse related assets –",
        "has suffered a loss of at least $2.4 million across its operations o",
        "BSC, Avalanche, and HECO Chain."
    )
)

attacker_indicator = {}

attacker_indicator["00"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="0xafc6e88c90334618e73eadc04b0f9dc0482f7be3",
    description=(
        "repeatedly invoked the privileged function `InCaseTokensGetStuck()`",
        "on the project’s staking pool contracts on BSC, Avalanche, and HECO Chain.",
    ),
    pattern_type="stix",
    pattern="[x-defi-address:value = '0xafc6e88c90334618e73eadc04b0f9dc0482f7be3' AND x-defi-address:blockchain = 'ethereum']"
)

attacker_indicator["01"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="0xded6b4361cb202adc9e33fc635b5f4481b2879c696d7e843793c886706306cde",
    description=(
        "The attacker bridged a total of 1,228.73 ETH from BSC to Ethereum, 267.34 ETH"
        "from Avalanche to Ethereum, and 105.49 ETH from HECO Chain to Ethereum"
        "Funds sent to Tornado Cash to be laundered."
    ),
    pattern_type="stix",
    pattern="[x-defi-transaction:value = '0xded6b4361cb202adc9e33fc635b5f4481b2879c696d7e843793c886706306cde' AND x-defi-address:blockchain = 'ethereum']"
)

attacker_indicator["02"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="0x298729e1098823beac9f83e1d1b10f25a89c50d3ed6f68738b94a09f2985b0b0",
    description=(
        "The attacker bridged a total of 1,228.73 ETH from BSC to Ethereum, 267.34 ETH"
        "from Avalanche to Ethereum, and 105.49 ETH from HECO Chain to Ethereum"
        "Funds sent to Tornado Cash to be laundered."
    ),
    pattern_type="stix",
    pattern="[x-defi-transaction:value = '0x298729e1098823beac9f83e1d1b10f25a89c50d3ed6f68738b94a09f2985b0b0' AND x-defi-address:blockchain = 'ethereum']"
)

attacker_indicator["03"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="0x9b4a9a12ad154342960d116f2b9c59539dfef47646ba0ce9557d5e3d960add88",
    description=(
        "The attacker bridged a total of 1,228.73 ETH from BSC to Ethereum, 267.34 ETH"
        "from Avalanche to Ethereum, and 105.49 ETH from HECO Chain to Ethereum"
        "Funds sent to Tornado Cash to be laundered."
    ),
    pattern_type="stix",
    pattern="[x-defi-transaction:value = '0x9b4a9a12ad154342960d116f2b9c59539dfef47646ba0ce9557d5e3d960add88' AND x-defi-address:blockchain = 'ethereum']"
)

relationship_attacker_indicator = {}

for i in range(0, 4):
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
    name="Invocation of privileged function",
    x_defi_taxonomy_layer="SC",
    x_defi_taxonomy_incident_cause="Access control mistake",
    x_defi_taxonomy_incident_type="Inconsistent access control",
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
    name="BXH",
    description=(
        "Boy X Highspeed (BXH)",
        "Financial services platform for web3 & the Metaverse"
    ),
    identity_class="organization",
    sectors=["financial-services"],
    external_references=[
        ExternalReference(
            source_name="BXH",
            url="https://bxh.com"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/BXH_Blockchain"
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
    name="BXH 22.09.20",
    description=(
        "On September 20th, 2022, Boy X Highspeed (BXH) –",
        "a financial services platform for Web3 and metaverse related assets –",
        "has suffered a loss of at least $2.4 million across its operations on",
        "BSC, Avalanche, and HECO Chain."
    ),
    published="2022-09-20T00:00:00Z", # Example
    report_types=["threat-actor", "attack-pattern"], # May vary based on what you have
    object_refs=[
        attacker,
        victim_identity,
    ],
    external_references=[
        ExternalReference(
            source_name="CertiK",
            url="https://www.certik.com/resources/blog/2eUD4Nbh0B37jw1UdxgA04-boy-x-highspeed-incident-analysis"
        ),
        ExternalReference(
            source_name="BXH - English",
            url="https://bxh.gitbook.io/english/notice/923latestnewsE"
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

comments = [
    "BXH was not audited by CertiK. The “emergency function” InCaseTokensGetStuck()\
    would have been flagged as a severe centralization risk in an audit.\
    Functions such as this are a risk on multiple levels.\
    They give privileged accounts the ability to drain affected contracts of all funds,\
    which opens the door to malicious insiders taking advantage of this power,\
    while also providing a prime target for phishers.",
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
    attacker_indicator["01"],
    attacker_indicator["02"],
    attacker_indicator["03"],
    relationship_attacker_indicator["00"],
    relationship_attacker_indicator["01"],
    relationship_attacker_indicator["02"],
    relationship_attacker_indicator["03"],
    attack_pattern,
    relationship_threat_actor_attack_pattern,
    victim_identity,
    relationship_attack_pattern_victim,
    relationship_attacker_victim,
    incident_report,
    incident_note_objects_comments[0]
])
