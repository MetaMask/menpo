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
    name="Helio Attacker",
    description="On December 2, 2022 Helio lost $19M as a result of a delayed price oracle."
)

attacker_indicator = {}

attacker_indicator["00"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="0x8d11f5b4d351396ce41813dce5a32962aa48e217",
    description="Helio Attacker Address",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x8d11f5b4d351396ce41813dce5a32962aa48e217' AND x-defi-address:blockchain = 'bsc']"
)

attacker_indicator["01"] = Indicator(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    valid_from="2023-03-01T00:00:00Z",
    name="0x391a665e8efad14cd63d5caed10f53881ebb8eab1c5ae14648db2d06cdd00cdd",
    description="Helio attacker used the $aBNBc tokens they had already deposited as collateral to borrow 16,444,740 $HAY tokens.",
    pattern_type="stix",
    pattern="[x-defi-transaction:value = '0x391a665e8efad14cd63d5caed10f53881ebb8eab1c5ae14648db2d06cdd00cdd' AND x-defi-address:blockchain = 'bsc']"
)

attacker_indicator["02"] = Indicator(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    valid_from="2023-03-01T00:00:00Z",
    name="0x9b4d0eb8df95ac6d5548c6abed0e90ceccebcf2560ef41bdc514d74746c0dd8e",
    description="Helio attacker then swapped 16,444,740 $HAY tokens to 15,504,986 BUSD.",
    pattern_type="stix",
    pattern="[x-defi-transaction:value = '0x9b4d0eb8df95ac6d5548c6abed0e90ceccebcf2560ef41bdc514d74746c0dd8e' AND x-defi-address:blockchain = 'bsc']"
)

attacker_indicator["03"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date,
    name="0xe9e7cea3dedca5984780bafc599bd69add087d56",
    description="Helio Attacker BUSD Token Address",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0xe9e7cea3dedca5984780bafc599bd69add087d56' AND x-defi-address:blockchain = 'bsc']"
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
    name="Oracle Price Manipulation",
    description="Delayed price oracle which allowed traders to borrow stablecoin with worthless aBNBc token.",
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
    name="Helio Protocol",
    description=(
        "Helio Protocol is an open-source liquidity protocol built on the BNB Chain",
        "that allows users to borrow and earn yield on the destablecoin $HAY.",
    ),
    identity_class="organization", # Example
    sectors=["financial-services"], # Example
    external_references=[
        ExternalReference(
            source_name="Helio Protocol",
            url="https://helio.money/"
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
    name="Helio 22.12.02",
    description=(
        "On December 2, 2022 Helio lost $19M as a result of a delayed price oracle,",
        "which allowed traders to borrow stablecoin with worthless aBNBc token.",
        "The root cause of the vulnerability is due to the failure of oracle",
        "in updating the price of the associated tokens after they had crashed to ",
        "a significantly lower value than they earlier trading price.",
    ),
    published="2022-12-02T00:00:00Z", # Example
    report_types=["threat-actor", "attack-pattern"], # May vary based on what you have
    object_refs=[
        attacker,
        victim_identity,
    ],
    external_references=[
        ExternalReference(
            source_name="NeptuneMutual",
            url="https://neptunemutual.com/blog/report-know-about-the-helio-protocol-hack"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/WuBlockchain/status/1598523763028799488"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/cz_binance/status/1598575867311132673"
        ),
        ExternalReference(
            source_name="Rekt News",
            url="https://rekt.news/ankr-helio-rekt/"
        ),
        ExternalReference(
            source_name="The Block",
            url="https://www.theblock.co/post/191668/attacker-pockets-20-million-in-exploits-on-ankr-and-helio"
        ),
        ExternalReference(
            source_name="Dune",
            url="https://dune.com/philosophia_ventures/helio-money-exploitation"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/WuBlockchain/status/1598523763028799488"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/Helio_Money/status/1598710454796390407?s=20&t=9Jh4Ukme6kpP39Wx68gUEg"
        )
    ],
    x_defi_estimated_loss_usd=19000000,
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
    "The Ankr protocol had suffered a governance key compromise, allowing an attacker to mint massive amount of $aBNBc tokens.",
    "After the Ankr Exploiter dumped $aBNBc tokens, another user bought 183,885 $aBNBc tokens from 1inch for just 10 $BNB, which were worth about $2,879 at the time the event took place.",
    "The price oracle of Helio was not updated during the exploit that took place with the $aBNBc tokens.",
    "The attacker used the $aBNBc tokens they had already deposited as collateral to borrow 16,444,740 $HAY tokens.",
    "The attacker then swapped 16,444,740 $HAY tokens to 15,504,986 BUSD.",
    "The swapped BUSD is then transferred to this address involving three different transactions, and then to Binance hot wallet.",
    "The stablecoin $HAY de-pegged following the incident and fell to a low of roughly $0.21.",
    "In a statement, the team explained that they were collaborating with Ankr Protocol to resolve the issue and that they had proposed a bilateral arrangement in which Ankr would pay for Helio's bad debt as a result of this exploit.",
    "Additionally, in order to aid with the re-peg of $HAY, Ankr would be purchasing any extra $HAY that is produced as a result of the discounted $aBNBc and send it to a burn address."
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
    incident_note_objects_comments[0],
    incident_note_objects_comments[1],
    incident_note_objects_comments[2],
    incident_note_objects_comments[3],
    incident_note_objects_comments[4],
    incident_note_objects_comments[5],
    incident_note_objects_comments[6],
    incident_note_objects_comments[7],
    incident_note_objects_comments[8]
])
