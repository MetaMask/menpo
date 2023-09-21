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


## Attacker
attacker = ThreatActor(
    created=created_date,
    modified=modified_date,
    name="Lodestar Attacker",
    description="On December 12th, 2022,\
    the price oracle of plvGLP collateral was manipulated,\
    allowing the attacker to drain their lending pools for a profit of ~$6.5M."
)

attacker_indicator = {}

attacker_indicator["00"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date, # In the future, should be valid from at least the timestamp of the attack
    name="0xc29d94386ff784006ff8461c170d1953cc9e2b5c", # For example, the address value
    description="",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0xc29d94386ff784006ff8461c170d1953cc9e2b5c' AND x-defi-address:blockchain = 'arbitrum']" # Example
)

attacker_indicator["01"] = Indicator(
    created=created_date,
    modified=modified_date,
    valid_from=created_date, # In the future, should be valid from at least the timestamp of the attack
    name="0xb50f58d50e30dfdaad01b1c6bcc4ccb0db55db13", # For example, the address value
    description="",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0xb50f58d50e30dfdaad01b1c6bcc4ccb0db55db13' AND x-defi-address:blockchain = 'ethereum']" # Example
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
    name="Price oracle manipulation",
    x_defi_taxonomy_layer="AUX", # Example
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
    name="Lodestar",
    description="A Compound fork on Arbitrum",
    identity_class="organization", # Example
    sectors=["financial-services"], # Example
    external_references=[
        ExternalReference(
            source_name="Lodestar",
            url="https://www.lodestarfinance.io/"
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
    name="Lodestar 22.12.10",
    description="On December 12th, 2022,\
    the price oracle of plvGLP collateral was manipulated,\
    allowing the attacker to drain their lending pools for a profit of ~$6.5M.",
    published="2022-12-10T00:00:00Z", # Example
    report_types=["threat-actor", "attack-pattern"], # May vary based on what you have
    object_refs=[
        attacker,
        victim_identity,
    ],
    external_references=[
        ExternalReference(
            source_name="Lodestar",
            url="https://blog.lodestarfinance.io/post-mortem-summary-13f5fe0bb336"
        ),
        ExternalReference(
            source_name="Rekt News",
            url="https://rekt.news/lodestar-rekt/"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/BowTiedPickle/status/1601650177369993216"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/lodestarfinance/status/1601686921566375936"
        ),
        ExternalReference(
            source_name="Twitter",
            url="https://twitter.com/SolidityFinance/status/1601684153740963840"
        ),
        ExternalReference(
            source_name="CertiK",
            url="https://www.certik.com/resources/blog/TqTyq4vYHl8JzS7zyJye9-lodestar-finance-incident-analysis"
        ),
    ],
    x_defi_estimated_loss_usd=6500000,
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
    "Using flash loans, the attacker manipulated the plvGLP price\
    reported by Lodestar’s GLPOracle contract,\
    allowing them to “borrow” all the funds supplied on the platform.",
    "The GLPOracle did not properly take into account the impact of a user\
    calling donate() on the GlpDepositor contract, which inflates the\
    assets of the GlpDepositor contract, and therefore the oracle-delivered\
    price of the plvGLP token.",
    "Attack Summary\n\
    In this case, the attack can be summarized as follows:\n\
      1. Attacker places a large amount of USDC into Lodestar\n\
      2. Attacker borrows plsGLP (longtail - high risk asset)\n\
      3. Attacker lends plsGLP and receives iplsGLP\n\
      4. Steps 2 and 3 are repeated\n\
      5. The key issue is that the oracle price of plsGLP is manipulatable - Oracles\n\
      6. The higher the value of plsGLP the higher the profit is able to be extracted.\n\
      7. Further the higher the exchange rate of plsGLP to GLP the larger the redemption is possible\n\
      8. The price of plsGLP was then pushed up by the attacker and they were able to borrow the remaining assets:\n",
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
    attacker_indicator["01"],
    relationship_attacker_indicator["01"],
    attack_pattern,
    relationship_threat_actor_attack_pattern,
    victim_identity,
    relationship_attack_pattern_victim,
    relationship_attacker_victim,
    incident_report,
    incident_note_objects_comments[0],
    incident_note_objects_comments[1],
    incident_note_objects_comments[2]
])
