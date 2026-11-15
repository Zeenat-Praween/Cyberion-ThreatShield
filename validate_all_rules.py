import yaml
import os
import glob

print("\n======================================")
print("       CYBERION THREATSHIELD")
print("       SIGMA RULE VALIDATOR")
print("======================================")

# Step 1: Find all YAML files
rule_files = glob.glob("rules/*.yml")

if not rule_files:
    print("No Sigma rules found!")
    exit()

print("\nTotal Rules Found:", len(rule_files))

# Step 2: Validate each rule
for file_path in rule_files:

    print("\n--------------------------------")
    print("Checking:", os.path.basename(file_path))

    try:
        with open(file_path, "r") as file:
            rule = yaml.safe_load(file)

        if not isinstance(rule, dict):
            print("[FAILED] Invalid YAML structure")
            continue

        # Step 3: Check common required fields
        required_fields = [
            "title",
            "id",
            "description",
            "level"
        ]

        missing_fields = []

        for field in required_fields:
            if field not in rule:
                missing_fields.append(field)

        if missing_fields:
            print("[FAILED] Missing fields:", missing_fields)

        else:
            print("[PASSED] Required fields found")
            print("Rule Title:", rule["title"])
            print("Rule ID:", rule["id"])
            print("Severity:", rule["level"])

    except yaml.YAMLError as error:
        print("[FAILED] YAML syntax error:", error)

    except Exception as error:
        print("[ERROR]", error)

print("\n======================================")
print("Sigma Rule Checking Completed")
print("======================================")