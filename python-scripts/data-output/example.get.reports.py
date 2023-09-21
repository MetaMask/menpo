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
