import pandas as pd

# Load the CSV file into a DataFrame
df = pd.read_csv("information-sheets\protocol-numbers.csv")

# Drop the last 3 columns
df = df.iloc[:, :-3]

# Save the modified DataFrame to a new CSV (optional)
df.to_csv("modified_file.csv", index=False)

# Display the modified DataFrame (optional)
print(df.head())
