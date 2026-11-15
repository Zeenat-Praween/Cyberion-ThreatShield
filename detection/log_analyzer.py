import pandas as pd

# Load security log dataset
data = pd.read_csv("data/sample_logs.csv")

# Display first five records
print("\n--- SECURITY LOGS ---")
print(data.head())

# Display dataset information
print("\n--- DATASET INFORMATION ---")
print(data.info())

# Count successful and failed events
print("\n--- LOGIN STATUS SUMMARY ---")
print(data["status"].value_counts())

# Count events by username
print("\n--- USER ACTIVITY ---")
print(data["username"].value_counts())