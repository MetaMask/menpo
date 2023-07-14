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
created_date = "2023-04-28T16:47:36Z"
modified_date = "2023-04-28T16:47:36Z"

################################################################################
##
## Attacker
## threat-actor SDO, indicator SDO, relationship SRO
##
################################################################################

attacker = ThreatActor(
    created=created_date,
    modified=modified_date,
    name="Transit Finance Attacker",
    description="On October 1, 2022 Transit Finance users were targeted\
        using a function parameter injection bug in the DEX’s contract."
)

attacker_indicator = {}

attacker_indicator["00"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="0x75f2aba6a44580d7be2c4e42885d4a1917bffd46",
    description="Transit Finance Attacker Address",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x75f2aba6a44580d7be2c4e42885d4a1917bffd46' \
        AND (x-defi-address:blockchain = 'ethereum' OR x-defi-address:blockchain = 'bsc')]"
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
    name="Function parameter injection bug",
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
    name="Transit Finance",
    description="Multi-chain DEX Aggregator",
    identity_class="organization", # Example
    sectors=["financial-services"], # Example
    external_references=[
        ExternalReference(
            source_name="Transit Finance",
            url="https://www.transit.finance/en/"
        ),
    ]
)

victim_address = {}

victim_address["00"] = XDefiAddress(
    created=created_date,
    modified=modified_date,
    name="0xed1afc8c4604958c2f38a3408fa63b32e737c428",
    description="Vulnerable contract in ethereum and BSC",
    blockchain="ethereum, bsc", # Maybe in the future we need a list here
    value="0xed1afc8c4604958c2f38a3408fa63b32e737c428",
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
    name="Transit Finance 22.10.01",
    description="On October 1, 2022 Transit Finance users were targeted\
        using a function parameter injection bug in the DEX’s contract.",
    published="2022-10-01T00:00:00Z",
    report_types=["threat-actor", "attack-pattern"],
    object_refs=[
        attacker,
        victim_identity,
    ],
    external_references=[
        ExternalReference(
            source_name="GitHub",
            url="https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/TransitSwap_exp.sol"
        ),
        ExternalReference(
            source_name="Medium",
            url="https://medium.com/@TransitSwap/updates-about-transitfinance-4731c38d6910"
        ),
        ExternalReference(
            source_name="Rekt News",
            url="https://rekt.news/transit-swap-rekt/"
        ),
        ExternalReference(
            source_name="Medium",
            url="https://slowmist.medium.com/cross-chain-dex-aggregator-transit-swap-hacked-analysis-74ba39c22020"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/1nf0s3cpt/status/1576511552592543745"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/peckshield/status/1576419241414524929"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/SlowMist_Team/status/1576488479357214721"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/supremacy_ca/status/1576332076277993475"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/TransitFinance/status/1576463550557483008"
        ),
    ],
    x_defi_estimated_loss_usd=28900000,
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
    "$28.9M were lost according to Transit Finance.\
        However, $18.9M were promptly returned after the discovery\
        of attacker’s multiple transactions with centralized exchanges.\
        One of the attacker’s transactions was also front-run for $1M by an MEV bot.",
    "Though the vulnerability was in the project’s code, this attack targeted\
        the users directly via a vulnerability in the use of the transferFrom()\
        function. Any tokens approved for trading on Transit Swap could be\
        transferred directly from users’ wallets to the unknown exploiter’s address.",
    "Root cause of this attack: a controllable `transferFrom()` external call",
    "20221002 Transit Swap - Incorrect owner address validation\n\
        Testing\n\
        \n\
        forge test --contracts src/test/TransitSwap_exp.sol -vv\n\
        \n\
        Contract\n\
        https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/TransitSwap_exp.sol\n\
        \n\
        Link reference\n\
        https://twitter.com/TransitFinance/status/1576463550557483008\n\
        \n\
        https://twitter.com/1nf0s3cpt/status/1576511552592543745\n\
        \n\
        https://bscscan.com/tx/0x181a7882aac0eab1036eedba25bc95a16e10f61b5df2e99d240a16c334b9b189\n",
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
    incident_note_objects_comments[0],
    incident_note_objects_comments[1],
    incident_note_objects_comments[2],
    incident_note_objects_comments[3],
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
