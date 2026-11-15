import yaml

# Load Sigma rule
with open("rules/failed_login.yml", "r") as file:
    rule = yaml.safe_load(file)

print("\n================================")
print("   CYBERION THREATSHIELD")
print("   SIGMA RULE VALIDATOR")
print("================================")

# Check important fields
required_fields = [
    "title",
    "id",
    "description",
    "logsource",
    "detection",
    "level"
]

for field in required_fields:

    if field in rule:
        print("[OK]", field, "found")

    else:
        print("[MISSING]", field)

# Display rule information
print("\nRule Title:", rule["title"])
print("Detection Condition:", rule["detection"]["condition"])
print("Severity:", rule["level"])

print("\nSigma YAML Validation Completed")