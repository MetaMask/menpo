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

@CustomObservable('x-defi-transaction', [
    ('name', StringProperty(required=True)),
    ('description', StringProperty(required=True)),
    ('created', TimestampProperty(required=True)),
    ('modified', TimestampProperty(required=True)),
    ('blockchain', StringProperty(required=True)),
    ('value', StringProperty(required=True)),
])
class XDefiTransaction():
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
created_date = "2023-05-04T03:02:36Z"
modified_date = "2023-05-04T03:02:36Z"

################################################################################
##
## Attacker
## threat-actor SDO, indicator SDO, relationship SRO
##
################################################################################

attacker = ThreatActor(
    created=created_date,
    modified=modified_date,
    name="Pando Rings Attacker",
    description="The attacker exploited a vulnerability in Pando Rings price oracle and manipulated the price of sBTC-WBTC"
)

attacker_indicator = {}

attacker_indicator["00"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="f059c0ee-cde3-3db9-9079-1aff956172c0",
    description="mixin wallet ID of the Pando Ring Attacker 00",
    pattern_type="stix",
    pattern="[x-defi-address:value = 'f059c0ee-cde3-3db9-9079-1aff956172c0' AND x-defi-address:blockchain = 'mixin']"
)

attacker_indicator["01"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="d3a935af-ccc4-3cca-98a0-b1b7a9cc53ca",
    description="mixin wallet ID of the Pando Ring Attacker 01",
    pattern_type="stix",
    pattern="[x-defi-address:value = 'd3a935af-ccc4-3cca-98a0-b1b7a9cc53ca' AND x-defi-address:blockchain = 'mixin']"
)

attacker_indicator["02"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="0xd3f04cE2d37b182432e2f804F9913a02071CEa54",
    description="Pando Ring Attacker address",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0xd3f04cE2d37b182432e2f804F9913a02071CEa54' AND x-defi-address:blockchain = 'ethereum']"
)

attacker_indicator["03"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="entofkdupows",
    description="Pando Ring Attacker address",
    pattern_type="stix",
    pattern="[x-defi-address:value = 'entofkdupows' AND x-defi-address:blockchain = 'eos']"
)

attacker_indicator["04"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="bc1qjnsx0sdxksh4w2azwu5ngr8sax46vcu52ljfcx",
    description="Pando Ring Attacker address",
    pattern_type="stix",
    pattern="[x-defi-address:value = 'bc1qjnsx0sdxksh4w2azwu5ngr8sax46vcu52ljfcx' AND x-defi-address:blockchain = 'bitcoin']"
)

relationship_attacker_indicator = {}

for i in range(0, 5):
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
    name="Price oracle manipulation",
    x_defi_taxonomy_layer="PRO",
    x_defi_taxonomy_incident_cause="Unsafe Dependency",
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
    name="Pando Rings",
    description="Lending Pool",
    identity_class="organization",
    sectors=["financial-services"],
    external_references=[
        ExternalReference(
            source_name="Pando Rings",
            url="https://pando.im/rings/"
        )
    ]
)

victim_address = {}

victim_address["00"] = XDefiAddress(
    created=created_date,
    modified=modified_date,
    name="0x3e99920e6c40971655e19ad0598454992210499f",
    description="ETH Message to the Pando Rings attacker",
    blockchain="ethereum",
    value="0x3e99920e6c40971655e19ad0598454992210499f",
)

victim_address["01"] = XDefiTransaction(
    created=created_date,
    modified=modified_date,
    name="0xfc453378ee7386c43f70836ded62db92b5364a4c4d2c0fe02c3aaa57c95b2241",
    description="ETH Message to the Pando Rings attacker",
    blockchain="ethereum",
    value="0xfc453378ee7386c43f70836ded62db92b5364a4c4d2c0fe02c3aaa57c95b2241",
)

relationship_victim = {}

# Binds addresses to the victim
for i in range(0, 2):
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
    name="Pando Rings 22.11.06",
    description=(
        "The attacker exploited a vulnerability in Pando Rings\
        price oracle and manipulated the price of sBTC-WBTC\
        (liquidity provider token of the trading pair BTC-WBTC on 4swap)\
        to attempt a theft of approximately $70 million worth of crypto assets.\
        $21,877,098.03 worth of crypto assets including ETH, EOS and BTC\
        were transferred out from the attacker's two perpetrating Mixin wallets\
        before measures could be taken."
    ),
    published="2022-11-06T00:00:00Z",
    report_types=["threat-actor", "attack-pattern"],
    object_refs=[
        attacker,
        victim_identity,
    ],
    external_references=[
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/pando_im/status/1589045252413100032"
        ),
        ExternalReference(
            source_name="Web3 is Going Great",
            url="https://web3isgoinggreat.com/?id=pando-exploited-for-20-million"
        ),
        ExternalReference(
            source_name="Pando Rings",
            url="https://pando.im/news/2022/2022-11-06-alert-to-pando-community-hack-of-pando-rings/"
        ),
    ],
    x_defi_estimated_loss_usd=20000000,
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
    "A message to the hacker if you are reading this:\n\
    We have sent two messages from the address 0x3e99920e6c40971655e19ad0598454992210499f.\n\
    There are consequences for your perpetrating the theft.\n\
    Even not now, it will be only a matter of time.\n\
    The communication channel is still open.\n\
    Please be in touch and we can negotiate what\n\
    can be done in exchange for the returning of the funds"
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
    attacker_indicator["04"],
    relationship_attacker_indicator["00"],
    relationship_attacker_indicator["01"],
    relationship_attacker_indicator["02"],
    relationship_attacker_indicator["03"],
    relationship_attacker_indicator["04"],
    attack_pattern,
    relationship_threat_actor_attack_pattern,
    victim_identity,
    victim_address["00"],
    victim_address["01"],
    relationship_victim["00"],
    relationship_victim["01"],
    relationship_attack_pattern_victim,
    relationship_attacker_victim,
    incident_report,
    incident_note_objects_comments[0]
])
