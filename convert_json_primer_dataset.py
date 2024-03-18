import json

def convert(input_file, output_file):
    with open(input_file, 'r') as f:
        data = json.load(f)

    original_format_data = []
    for item in data:
        original_format_data.append(json.dumps(item))

    with open(output_file, 'w') as f:
        f.write('\n'.join(original_format_data))

# Example usage:
input_file = 'primer-dataset.json'
output_file = 'output_original_format.json'

convert(input_file, output_file)