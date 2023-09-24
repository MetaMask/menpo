import json, os, shutil, sys, tempfile, webbrowser

from urllib.parse import urlunparse
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
  report_id = "report--" + uuid_str
  report = fs.get(report_id)

  report_stix_ids = [report_id]

  # In reports, `fs.relationships(report) will return []
  # Understandable, as the engine is looking for SROs
  # We need to take a more indirect approach by fecthing
  # the items from object_refs as they are
  for object_ref in report.object_refs:
    recurse_and_append_objects(report_stix_ids, object_ref)

  # The visualizer application doesn't allow to use file:///
  # https://github.com/oasis-open/cti-stix-visualization/blob/5ce57915ef1c3e5a7472adf765d93d24dec189f5/application.js#L771
  #
  # So, we use out own version of the visualizer...
  #
  # To make things extremely simple, this visualizer
  # won't receive any GET parameter and only renders
  # the contents of the file `latest.js`

  # Prepare the `latest.js` file contents
  # We are producing a requireJS module
  json_content = json.dumps([fs.get(id) for id in report_stix_ids], indent=4, cls=STIXJSONEncoder)
  javascript_code = f'''var data = `
  {json_content}
`
define(function() {{
  return {{
    data
  }};
}});
'''
  filepath_latest_js = os.path.join(
      os.getcwd(),
      "viz",
      "temp-json",
      "latest.js")
  with open(filepath_latest_js, 'w') as f:
    f.write(javascript_code)

  # Now we only need to tell `webbrowser` where is the viz app and call it
  scheme = "file"
  path = os.path.join(os.getcwd(), "viz", "index.html")
  url = urlunparse((scheme, "", path, "", "", ""))

  webbrowser.open(url)

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
