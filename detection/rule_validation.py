import pandas as pd
import os

# ==========================================
# CYBERION THREATSHIELD
# DETECTION RULE VALIDATION
# ==========================================

print("\n========== DETECTION RULE VALIDATION ==========")

# Load security logs

data = pd.read_csv("data/sample_logs.csv")

data["timestamp"] = pd.to_datetime(
    data["timestamp"],
    errors="coerce"
)

results = []


# Function to record test results

def add_result(test_name, condition, details):

    results.append({
        "Test Name": test_name,
        "Result": "PASS" if condition else "FAIL",
        "Details": details
    })


# ==========================================
# TEST 1: REQUIRED COLUMNS
# ==========================================

required_columns = [
    "timestamp",
    "username",
    "source_ip",
    "event_type",
    "status",
    "device"
]

columns_available = all(
    column in data.columns
    for column in required_columns
)

add_result(
    "Required Columns Validation",
    columns_available,
    "All required columns are available"
    if columns_available
    else "Some required columns are missing"
)


# ==========================================
# PREPARE FAILED LOGIN EVENTS
# ==========================================

failed_logins = data[
    (data["event_type"] == "Login") &
    (data["status"] == "Failed")
].copy()


# ==========================================
# TEST 2: BRUTE FORCE DETECTION
# ==========================================

failed_counts = (
    failed_logins
    .groupby(["username", "source_ip"])
    .size()
)

admin_count = failed_counts.get(
    ("admin", "192.168.1.12"), 0
)

brute_force_detected = admin_count >= 3

add_result(
    "Brute Force Detection",
    brute_force_detected,
    f"Admin failed login attempts detected: {admin_count}"
)


# ==========================================
# TEST 3: PASSWORD SPRAYING DETECTION
# ==========================================

target_ip = "192.168.1.20"

spray_events = failed_logins[
    failed_logins["source_ip"] == target_ip
].sort_values("timestamp")

unique_users = spray_events["username"].nunique()

password_spray_detected = unique_users >= 3

add_result(
    "Password Spraying Detection",
    password_spray_detected,
    f"Unique usernames with failed logins: {unique_users}"
)


# ==========================================
# TEST 4: NORMAL ACTIVITY VALIDATION
# ==========================================

normal_user = "user1"

normal_user_failures = len(
    failed_logins[
        failed_logins["username"] == normal_user
    ]
)

normal_activity_check = normal_user_failures < 3

add_result(
    "Normal Activity Validation",
    normal_activity_check,
    f"Failed login attempts for user1: {normal_user_failures}"
)


# ==========================================
# TEST 5: TIMESTAMP VALIDATION
# ==========================================

invalid_timestamps = data["timestamp"].isna().sum()

timestamp_check = invalid_timestamps == 0

add_result(
    "Timestamp Validation",
    timestamp_check,
    f"Invalid timestamps found: {invalid_timestamps}"
)


# ==========================================
# GENERATE VALIDATION REPORT
# ==========================================

validation_report = pd.DataFrame(results)

print("\nVALIDATION RESULTS")

print(
    validation_report.to_string(index=False)
)


# ==========================================
# SUMMARY
# ==========================================

total_tests = len(validation_report)

passed_tests = (
    validation_report["Result"] == "PASS"
).sum()

failed_tests = (
    validation_report["Result"] == "FAIL"
).sum()

print("\n========== VALIDATION SUMMARY ==========")

print("Total Tests:", total_tests)

print("Passed Tests:", passed_tests)

print("Failed Tests:", failed_tests)


# ==========================================
# SAVE REPORT
# ==========================================

os.makedirs("reports", exist_ok=True)

validation_report.to_csv(
    "reports/rule_validation_report.csv",
    index=False
)

print("\nValidation report saved successfully.")

print("Location: reports/rule_validation_report.csv")