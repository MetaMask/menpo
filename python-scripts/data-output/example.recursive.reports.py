import json, os, sys, tempfile

from stix2 import FileSystemSource, Filter
from stix2.base import STIXJSONEncoder

fs = FileSystemSource("../../db")

################################################################################
#
# No command line arguments should output the list of reports
#
################################################################################
def start_no_command_line_arguments():
  print("Please provide the uuid of a report to render it.\n")

  filt = Filter('type', '=', 'report')
  reports = fs.query([filt])
  sorted_reports = sorted(reports, key=lambda x: x["published"])

  # Define column widths
  name_width = 30  # Adjust the width as needed
  id_width = 36    # Adjust the width as needed

  # Print table header
  print(f"{'Report Name':<{name_width}}{'ID':<{id_width}}")

  # Iterate through sorted_reports and print each row
  for report in sorted_reports:
      trimmed_id = report.id.replace("report--", "")  # Trim 'report--' from the ID
      print(f"{report.name[:name_width]:<{name_width}}{trimmed_id[:id_width]:<{id_width}}")

################################################################################
#
# We take the first argument as the report id.
# The program here is to render the report visualization from there.
#
################################################################################
def start_command_line_arg_found():
  uuid_str = sys.argv[1]

  # You can see here my blatant disregard for input parameter validation...
  report = fs.get("report--" + uuid_str)

  report_stix_ids = []

  # In reports, `fs.relationships(report) will return []
  # Understandable, as the engine is looking for SROs
  # We need to take a more indirect approach by fecthing
  # the items from object_refs as they are
  for object_ref in report.object_refs:
    recurse_and_append_objects(report_stix_ids, object_ref)

  # json and the argonauts time
  json_file_name =os.path.join(
      os.getcwd(),
      "temp-json/",
      os.path.basename(tempfile.NamedTemporaryFile().name) + ".json")
  with open(json_file_name, 'w') as f:
    f.write(json.dumps([fs.get(id) for id in report_stix_ids], indent=4, cls=STIXJSONEncoder))

  # The visualizer application doesn't allow to user file:///
  # https://github.com/oasis-open/cti-stix-visualization/blob/5ce57915ef1c3e5a7472adf765d93d24dec189f5/application.js#L771
  # Throwing the idea of leveraging a temp file overboard,

  print("JSON file created at", json_file_name)

################################################################################
#
# Performs recursion to get objects, adds them into the given list
#
################################################################################
def recurse_and_append_objects(report_stix_ids, obj_id):
  if obj_id is None or obj_id in report_stix_ids:
    return

  else:
    report_stix_ids.append(obj_id)

    for relationship in fs.relationships(obj_id):
      if relationship.id not in report_stix_ids:
        report_stix_ids.append(relationship.id)

    for related_obj in fs.related_to(obj_id):
      recurse_and_append_objects(report_stix_ids, related_obj["id"])

################################################################################
#
# "main"
#
################################################################################

if len(sys.argv) < 2:
    start_no_command_line_arguments()
else:
  start_command_line_arg_found()
