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
    name="Midas Capital Attacker",
    description="On January 15, 2023 Midas Capital lost $654K due to a read-only reentrancy vulnerability."
)

attacker_indicator = {}

attacker_indicator["00"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date, # In the future, should be valid from at least the timestamp of the attack
    name="0x1863b74778cf5e1c9c482a1cdc2351362bd08611", # For example, the address value
    description="Midas Capital Attacker",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x1863b74778cf5e1c9c482a1cdc2351362bd08611' AND x-defi-address:blockchain = 'polygon']" # Example
)

attacker_indicator["01"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date, # In the future, should be valid from at least the timestamp of the attack
    name="0x0053490215baf541362fc78be0de98e3147f40223238d5b12512b3e26c0a2c2f", # For example, the address value
    description="Midas Capital Attacker",
    pattern_type="stix",
    pattern="[x-defi-transaction:value = '0x0053490215baf541362fc78be0de98e3147f40223238d5b12512b3e26c0a2c2f' AND x-defi-address:blockchain = 'polygon']" # Example
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
    name="Read-only reentrancy vulnerability",
    x_defi_taxonomy_layer="SC", # Example
    x_defi_taxonomy_incident_cause="Untrusted or unsafe calls",
    x_defi_taxonomy_incident_type="Reentrancy",
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
    name="Midas Capital",
    description="Polygon-based lending protocol",
    identity_class="organization", # Example
    sectors=["financial-services"], # Example
    external_references=[
        ExternalReference(
            source_name="Midas Capital",
            url="https://midascapital.xyz/"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/MidasCapitalxyz"
        ),
    ]
)

victim_address = {}

victim_address["00"] = XDefiAddress(
    created=created_date,
    modified=modified_date,
    name="0x5bca7ddf1bcccb2ee8e46c56bfc9d3cdc77262bc", # Use the address as name
    description="Midas Capital Readonly Reentrancy Vulnerable Contract",
    blockchain="polygon", # Not an enum
    value="0x5bca7ddf1bcccb2ee8e46c56bfc9d3cdc77262bc",
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
    name="Midas Capital 23.01.15",
    description="On January 15, 2023 Midas Capital lost $654K due to a read-only reentrancy vulnerability.",
    published="2023-01-15T00:00:00Z", # Example
    report_types=["threat-actor", "attack-pattern"], # May vary based on what you have
    object_refs=[
        attacker,
        victim_identity,
    ],
    external_references=[
        ExternalReference(
            source_name="Phalcon.xyz",
            url="https://explorer.phalcon.xyz/tx/polygon/0x0053490215baf541362fc78be0de98e3147f40223238d5b12512b3e26c0a2c2f"
        ),
        ExternalReference(
            source_name="Medium",
            url="https://medium.com/@numencyberlabs/jarvis-network-flash-loan-and-re-entrancy-attack-analysis-a649748f90bb"
        ),
        ExternalReference(
            source_name="Rekt News",
            url="https://rekt.news/midas-capital-rekt/"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/BeosinAlert/status/1614905399102287872"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/BlockSecTeam/status/1614864084956254209"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/Jarvis_Network/status/1614723934519234560"
        ),
    ],
    x_defi_estimated_loss_usd=654000,
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
    "Midas recently added WMATIC-stMATIC Curve LP token for use as collateral. These tokens have a read-only reentrancy vulnerability which allows the token's virtual price to be manipulated when improperly implemented.",
    "The read-only reentrancy is a reentrancy scenario where a `view` function is reentered, which in most cases is unguarded as it does not modify the contract’s state.",
    "More on read-only reentrancy: https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/",
    "More on read-only reentrancy: https://quillaudits.medium.com/decoding-220k-read-only-reentrancy-exploit-quillaudits-30871d728ad5",
    "The attacker was able to borrow the following assets against the inflated collateral:\n\
    * jCHF: 273,973\n\
    * jEUR: 368,058\n\
    * jGBP: 45,250\n\
    * agEUR: 45,435\n\
    * Which were then swapped to ~660k MATIC ($660k) and sent on to Kucoin and Binance.\n",
    "Message from Midas to the attacker: https://polygonscan.com/tx/0x45e9e4addf8a67700fca8ab7f0fba07019e5ce5a8c630b02fc28c8b6115c66a7"
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
    attacker_indicator["01"],
    relationship_attacker_indicator["01"],
    attack_pattern,
    relationship_threat_actor_attack_pattern,
    victim_identity,
    victim_address["00"],
    relationship_victim["00"],
    relationship_attack_pattern_victim,
    relationship_attacker_victim,
    incident_report,
    incident_note_objects_comments[0],
    incident_note_objects_comments[1],
    incident_note_objects_comments[2],
    incident_note_objects_comments[3],
    incident_note_objects_comments[4],
    incident_note_objects_comments[5],
    allow_custom=True
)

with open('../json-stix-db/23.01.15.midas.capital.json', 'w') as f:
    f.write(json.dumps(BundleofAllObjects, indent=4, cls=STIXJSONEncoder))

# Count STIX objects by type and print it
from collections import defaultdict
object_count = defaultdict(int)

for obj in BundleofAllObjects.objects:
    object_count[obj.type] += 1

sorted_object_count = {key: object_count[key] for key in sorted(object_count)}
print(sorted_object_count)
