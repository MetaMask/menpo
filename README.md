# Menpo

## Overview

DeFi Incidents in STIX 2.1.

## Menpo Research Whitepaper

* [Google Docs Link](https://docs.google.com/document/d/1bmbzHYu9s5DTgSinJXHdFWjBWla43jV1G6SnX3X8OB4/edit)

## Menpo Presentation at DeFi Security Summit - 15.JUL.2023

* [Youtube Video](https://www.youtube.com/watch?v=D4qRiKpj1go)
* [Google Slides Link](https://docs.google.com/presentation/d/1Xriaat4ZoanBRS06g9wi3tRj__dTWr1_wpSg2yyqaw4/edit#slide=id.p)

## Using Python to generate STIX objects

### Installing

```bash
cd python-scripts
python3 -m venv menpo_env
source menpo_env/bin/activate
pip3 install -r requirements.txt # If first time
```

### Creating a bundle

```bash
cd python-scripts
python3 <stix2 python script>
```

Example

```bash
cd python-scripts
source menpo_env/bin/activate

python3 22.09.01.kyberswap.py
```

## Visualization of incidents

Suppose you created and wrapped the STIX objects of your incident into the file `json-stix-db/22.09.01.kyberswap.json`.

To visualize the incident, just use [Oasis' CTI STIX Visualizer](https://oasis-open.github.io/cti-stix-visualization/) this way:

https://oasis-open.github.io/cti-stix-visualization/?url=https://raw.githubusercontent.com/metamask/menpo/main/json-stix-db/22.09.01.kyberswap.json

<img width="888" alt="Visualization 00" src="https://user-images.githubusercontent.com/85324266/232174604-41c2ba3b-57dd-4c10-975d-5845b7dbf5ef.png">
