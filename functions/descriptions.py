import pandas as pd
import json

# Step 1: Load the CSV into a pandas DataFrame
df = pd.read_csv('other/tshark_fields.csv', error_bad_lines=False)

# Step 2: Create a dictionary for fast lookup of field_abbr -> field_name
abbr_to_name = dict(zip(df['field_abbr'], df['field_name']))

# Step 3: Read the JSON file
with open('data.json', 'r') as jsonfile:
    data = json.load(jsonfile)

# Step 4: Replace field_abbr with field_name in each JSON entry
for entry in data:
    if 'field_abbr' in entry:
        field_abbr = entry['field_abbr']
        if field_abbr in abbr_to_name:
            entry['field_abbr'] = abbr_to_name[field_abbr]  # Replace with field_name

# Step 5: Write the updated data back to a JSON file
with open('updated_data.json', 'w') as jsonfile:
    json.dump(data, jsonfile, indent=4)
