# FireMon Assessment Export Tool

This script exports rule failures for a specific assessment and device from FireMon to a CSV file.

## Requirements

- Python 3.6+
- Required Python packages:
  - requests (already installed on FMOS)

Install required packages:
```
pip install requests
```

## Usage

```
python firemon_assessment_export.py -u URL -n USERNAME -p PASSWORD -d DEVICE_ID -a ASSESSMENT_UUID -o OUTPUT_FILE
```

### Arguments

- `-u`, `--url`: FireMon base URL (e.g., https://demo01.firemon.com)
- `-n`, `--username`: FireMon username
- `-p`, `--password`: FireMon password
- `-d`, `--device-id`: Device ID
- `-a`, `--assessment`: Assessment UUID
- `-o`, `--output`: Output CSV file path

### Example

```
python firemon_assessment_export.py -u https://demo01.firemon.com -n admin -p passwd -d 4 -a ddfe53ea-c146-4ffc-b199-fa5e600d3bee -o assessment_failures.csv
```

## CSV Output Format

The script will generate a CSV file with the following columns:

- Rule Name
- Rule Number
- Cumulative Rule Severity
- Policy Name
- Sources
- Destinations
- Services
- Users
- Apps
- Profiles
- URL Matchers
- Action
- Control Name
- Control Description
- Control Severity
- Control Code

Each rule-control combination will appear as a separate row in the CSV.