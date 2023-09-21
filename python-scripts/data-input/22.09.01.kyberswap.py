from stix2 import AttackPattern, ExternalReference, FileSystemStore, \
    Identity, Indicator, Note, Relationship, Report, ThreatActor
from stix2.base import STIXJSONEncoder
from stix2.properties import EnumProperty, IntegerProperty, StringProperty, TimestampProperty
from stix2.v21 import CustomExtension, CustomObservable
import json
import os

################################################################################

# We can get the UUID with
# python3 -c "import uuid; print(str(uuid.uuid4()))"
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
        ("x_defi_taxonomy_layer", EnumProperty(["NET", "CON", "SC", "Pro", "AUX"], required=True)),
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

kyberswap_attacker = ThreatActor(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    name="KyberSwap Attacker",
    description="On September 1, 2022 KyberSwap users lost $265K in a front-end compromise."
)

kyberswap_attacker_indicator = {}

kyberswap_attacker_indicator["00"] = Indicator(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    valid_from="2023-03-01T00:00:00Z",
    name="0x57A72cE4fd69eBEdEfC1a938b690fbf11A7Dff80",
    description="KyberSwap Attacker Address",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x57A72cE4fd69eBEdEfC1a938b690fbf11A7Dff80' AND (x-defi-address:blockchain = 'ethereum' OR x-defi-address:blockchain = 'polygon')]"
)

kyberswap_attacker_indicator["01"] = Indicator(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    valid_from="2023-03-01T00:00:00Z",
    name="0xfd6f294f3c9e117dde30495770ba9b073c33b065",
    description="KyberSwap Attacker Address Receiving Tokens",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0xfd6f294f3c9e117dde30495770ba9b073c33b065' AND x-defi-address:blockchain = 'polygon']"
)

kyberswap_attacker_indicator["02"] = Indicator(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    valid_from="2023-03-01T00:00:00Z",
    name="0xb9943d5ab8b3a70925714233d938dd62e957f92e",
    description="KyberSwap Attacker Address Receiving Tokens",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0xb9943d5ab8b3a70925714233d938dd62e957f92e' AND x-defi-address:blockchain = 'ethereum']"
)

kyberswap_attacker_indicator["03"] = Indicator(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    valid_from="2023-03-01T00:00:00Z",
    name="0x9bc22f7e0234029eaf2c570588d829f07123fdd6",
    description="KyberSwap Attacker Address Receiving Tokens",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x9bc22f7e0234029eaf2c570588d829f07123fdd6' AND x-defi-address:blockchain = 'polygon']"
)

kyberswap_attacker_indicator["04"] = Indicator(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    valid_from="2023-03-01T00:00:00Z",
    name="0x6fd64b2555fa6d1bf8564f728da7eae8ad1397b1",
    description="KyberSwap Attacker Address supplying native tokens to attacker's address",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x6fd64b2555fa6d1bf8564f728da7eae8ad1397b1' AND x-defi-address:blockchain = 'polygon']"
)

kyberswap_attacker_indicator["05"] = Indicator(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    valid_from="2023-03-01T00:00:00Z",
    name="0x8152e9e1b7408b5f7c02ca54f85f245e7d013b5d",
    description="KyberSwap Attacker Address supplying native tokens to attacker's address",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x8152e9e1b7408b5f7c02ca54f85f245e7d013b5d' AND x-defi-address:blockchain = 'polygon']"
)

kyberswap_attacker_indicator["06"] = Indicator(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    valid_from="2023-03-01T00:00:00Z",
    name="0x2f5173967e1fb95f936dfcd6400bc2e533cf3708",
    description="KyberSwap Attacker Address supplying native tokens to attacker's address",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x2f5173967e1fb95f936dfcd6400bc2e533cf3708' AND x-defi-address:blockchain = 'polygon']"
)

kyberswap_attacker_indicator["07"] = Indicator(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    valid_from="2023-03-01T00:00:00Z",
    name="0x97f0df5bd8c40cbb27c2631b269d507fadc49f34",
    description="KyberSwap Attacker Address supplying native tokens to attacker's address",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x97f0df5bd8c40cbb27c2631b269d507fadc49f34' AND x-defi-address:blockchain = 'polygon']"
)

kyberswap_attacker_indicator["08"] = Indicator(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    valid_from="2023-03-01T00:00:00Z",
    name="0x60ef468b2704cfb75edc025531a03816cc69f99c",
    description="KyberSwap Attacker Address supplying native tokens to attacker's address",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x60ef468b2704cfb75edc025531a03816cc69f99c' AND x-defi-address:blockchain = 'polygon']"
)

kyberswap_attacker_indicator["09"] = Indicator(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    valid_from="2023-03-01T00:00:00Z",
    name="0x44183fd1a79704f79e0986c6380dd9bfbbc7e6d2",
    description="KyberSwap Attacker Address supplying native tokens to attacker's address",
    pattern_type="stix",
    pattern="[x-defi-address:value = '0x44183fd1a79704f79e0986c6380dd9bfbbc7e6d2' AND x-defi-address:blockchain = 'ethereum']"
)

kyberswap_attacker_indicator["10"] = Indicator(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    valid_from="2023-03-01T00:00:00Z",
    name="bc1q8gn5fuu2eva2cwmm5v5rqvqs39va44n3u7l6dp",
    description="KyberSwap Attacker moved funds to BTC",
    pattern_type="stix",
    pattern="[x-defi-address:value = 'bc1q8gn5fuu2eva2cwmm5v5rqvqs39va44n3u7l6dp' AND x-defi-address:blockchain = 'bitcoin']"
)

kyberswap_attacker_indicator["11"] = Indicator(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    valid_from="2023-03-01T00:00:00Z",
    name="7e5708652dbea1bb985ede7f810adcf33eff138f47f63c6525a0801a4235b3c5",
    description="KyberSwap Attacker sent the fund out, to a mixer/CEX",
    pattern_type="stix",
    pattern="[x-defi-transaction:value = '7e5708652dbea1bb985ede7f810adcf33eff138f47f63c6525a0801a4235b3c5' AND x-defi-address:blockchain = 'bitcoin']"
)

relationship_kyberswap_attacker_indicator = {}

for i in range(0, 12):
    relationship_kyberswap_attacker_indicator[f"{i:02d}"] = Relationship(
        relationship_type="indicates",
        spec_version="2.1",
        created="2023-03-01T00:00:00Z",
        modified="2023-03-01T00:00:00Z",
        source_ref=kyberswap_attacker_indicator[f"{i:02d}"].id,
        target_ref=kyberswap_attacker.id
    )

kyberswap_identity = Identity(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    name="KyberSwap",
    description="KyberSwap is a decentralized exchange (DEX) platform that allows users to swap tokens without an intermediary. It is built on the Ethereum blockchain and supports a wide variety of ERC-20 tokens. KyberSwap is a part of the larger Kyber Network, which is a protocol for decentralized cross-chain token swaps that supports multiple blockchains.",
    identity_class="organization",
    sectors=["financial-services"],
    external_references=[
        ExternalReference(
            source_name="KyberSwap",
            url="https://kyberswap.com/"
        )
    ]
)

victim_0_address = XDefiAddress(
    name="0x6e2ff642d60d1c99811f0a1a39e1b0250c488cce - Polygon",
    description="KyberSwap Attack Victim 0",
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    blockchain="polygon",
    value="0x6e2ff642d60d1c99811f0a1a39e1b0250c488cce",
)

victim_1_address = XDefiAddress(
    name="0x20fc9dd90ab50933537a68b9f059dbf543b107dc - Polygon",
    description="KyberSwap Attack Victim 1",
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    blockchain="polygon",
    value="0x20fc9dd90ab50933537a68b9f059dbf543b107dc",
)

bounty_address = XDefiAddress(
    name="0x2dc0ba6ba3485edd61f17ffabf4c7a9626001d50 - Polygon",
    description="KyberSwap Bounty Address for the Attacker",
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    blockchain="polygon",
    value="0x2dc0ba6ba3485edd61f17ffabf4c7a9626001d50",
)

relationship_kyberswap_victim_0 = Relationship(
    relationship_type="uses",
    spec_version="2.1",
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    source_ref=kyberswap_identity.id,
    target_ref=victim_0_address.id,
    allow_custom=True
)

relationship_kyberswap_victim_1 = Relationship(
    relationship_type="uses",
    spec_version="2.1",
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    source_ref=kyberswap_identity.id,
    target_ref=victim_1_address.id,
    allow_custom=True
)

relationship_kyberswap_bounty= Relationship(
    relationship_type="uses",
    spec_version="2.1",
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    source_ref=kyberswap_identity.id,
    target_ref=bounty_address.id,
    allow_custom=True
)

attack_pattern_front_end_exploit_gtm = AttackPattern(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    name="Front-end Exploit with Google Tag Manager",
    x_defi_taxonomy_layer="AUX",
    x_defi_taxonomy_incident_cause="Faulty Web Development",
    x_defi_taxonomy_incident_type="N/A",
    extensions={
        "extension-definition--59cde1e5-2ce1-4732-a09d-596f401ba65b" : {
            'extension_type': 'toplevel-property-extension',
        },
    }
)

relationship_attack_pattern_threat_actor = Relationship(
    relationship_type="uses",
    spec_version="2.1",
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    source_ref=kyberswap_attacker.id,
    target_ref=attack_pattern_front_end_exploit_gtm.id
)

relationship_threat_actor_kyberswap = Relationship(
    relationship_type="targets",
    spec_version="2.1",
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    source_ref=kyberswap_attacker.id,
    target_ref=kyberswap_identity.id
)

relationship_attack_pattern_kyberswap = Relationship(
    relationship_type="targets",
    spec_version="2.1",
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    source_ref=attack_pattern_front_end_exploit_gtm.id,
    target_ref=kyberswap_identity.id
)

kyberswap_incident_report = Report(
    created="2023-03-01T00:00:00Z",
    modified="2023-03-01T00:00:00Z",
    name="KyberSwap 22.09.01",
    description=(
        "On September 1, 2022 KyberSwap users lost $265K in a front-end compromise."
        "There is no smart contract vulnerability."
        "Malicious code in KyberSwap Google Tag Manager (GTM), which inserted a false approval."
    ),
    published="2022-09-01T00:00:00Z",
    report_types=["threat-actor", "attack-pattern"],
    object_refs=[
        kyberswap_attacker,
        kyberswap_identity,
    ],
    external_references=[
        ExternalReference(source_name="KyberSwap Blog",
            url="https://blog.kyber.network/interim-update-hack-is-removed-kyberswap-is-secure-next-steps-8b2d594efb33"),
        ExternalReference(source_name="KyberSwap Blog",
            url="https://blog.kyber.network/notice-of-exploit-of-kyberswap-frontend-963aa8febd6a"),
        ExternalReference(source_name="Twitter",
            url="https://twitter.com/cz_binance/status/1565976776710430721"),
        ExternalReference(source_name="Twitter",
            url="https://twitter.com/KyberNetwork/status/1565421305410686976"),
    ],
    x_defi_estimated_loss_usd=265000,
    extensions={
        "extension-definition--393acb6c-fe64-42b5-92d5-a8ec243c4876" : {
            'extension_type': 'toplevel-property-extension',
        },
    }
)

kyberswap_incident_logs = [
    {
        "timestamp": "2022-09-01T08:24:00Z",
        "event": "On 1 Sep, 3.24PM GMT+7, we identified a suspicious element on our frontend."
    },
    {
        "timestamp": "2022-09-01T09:00:00Z",
        "event": "At 4pm GMT+7 we announced to our community that we had disabled the UI, during which we investigated the cause of the frontend exploit. A malicious code in our GTM was identified upon which we disabled GTM."
    },
    {
        "timestamp": "2022-09-01T10:46:00Z",
        "event": "We announced the UI going live again at 5.46pm GMT+7."
    }
]

kyberswap_incident_note_objects = [
    Note(
        content=f"{log['timestamp']} - {log['event']}",
        object_refs=kyberswap_incident_report.id,
        created="2023-03-01T00:00:00Z",
        modified="2023-03-01T00:00:00Z",
    )
    for log in kyberswap_incident_logs
]

################################################################################

fs = FileSystemStore("../../db")
fs.add([
    kyberswap_attacker_indicator["00"],
    kyberswap_attacker_indicator["01"],
    kyberswap_attacker_indicator["02"],
    kyberswap_attacker_indicator["03"],
    kyberswap_attacker_indicator["04"],
    kyberswap_attacker_indicator["05"],
    kyberswap_attacker_indicator["06"],
    kyberswap_attacker_indicator["07"],
    kyberswap_attacker_indicator["08"],
    kyberswap_attacker_indicator["09"],
    kyberswap_attacker_indicator["10"],
    kyberswap_attacker_indicator["11"],
    relationship_kyberswap_attacker_indicator["00"],
    relationship_kyberswap_attacker_indicator["01"],
    relationship_kyberswap_attacker_indicator["02"],
    relationship_kyberswap_attacker_indicator["03"],
    relationship_kyberswap_attacker_indicator["04"],
    relationship_kyberswap_attacker_indicator["05"],
    relationship_kyberswap_attacker_indicator["06"],
    relationship_kyberswap_attacker_indicator["07"],
    relationship_kyberswap_attacker_indicator["08"],
    relationship_kyberswap_attacker_indicator["09"],
    relationship_kyberswap_attacker_indicator["10"],
    relationship_kyberswap_attacker_indicator["11"],
    kyberswap_attacker,
    kyberswap_identity,
    victim_0_address,
    victim_1_address,
    bounty_address,
    relationship_kyberswap_victim_0,
    relationship_kyberswap_victim_1,
    relationship_kyberswap_bounty,
    attack_pattern_front_end_exploit_gtm,
    relationship_attack_pattern_threat_actor,
    relationship_threat_actor_kyberswap,
    relationship_attack_pattern_kyberswap,
    kyberswap_incident_report,
    kyberswap_incident_note_objects[0],
    kyberswap_incident_note_objects[1],
    kyberswap_incident_note_objects[2]
])
