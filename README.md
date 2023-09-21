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

### Generate and store STIX objects from a script

```bash
cd python-scripts/data-input
python3 <stix2 python script>
```

Example

```bash
cd python-scripts/data-input
source menpo_env/bin/activate

python3 22.09.01.kyberswap.py
```

## Accessing the database

### Getting a list of all the reports in the DB

```python
import json

from stix2 import FileSystemSource, Filter
from stix2.base import STIXJSONEncoder

fs = FileSystemSource("../../db")

# Do the query
filt = Filter('type', '=', 'report')
reports = fs.query([filt])

# Convert the Python objects to JSON and print them
json_str = json.dumps(reports, indent=4, cls=STIXJSONEncoder)
print(json_str)

# Or, if you don't like json, we can give you a more compact one
sorted_reports = sorted(reports, key=lambda x: x["published"])

print("Reports in the DB:", len(sorted_reports), "\n")

for report in sorted_reports:
  print("-", report.name)
```

### Generate a json report and render it on the STIX visualizer

```python
# TODO
```
