#This file was used to inspect the dataset
import pandas as pd

df = pd.read_csv("data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

print(df.head(5)) #display first 5 rows
print(df.info())
print(df.isnull().sum())

print(df[' Label'].value_counts())