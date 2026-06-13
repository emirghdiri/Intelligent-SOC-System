import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import pickle

# Charger les données
df = pd.read_csv('alerts.csv')
print(f"Total alertes: {len(df)}")
print(f"Normal: {len(df[df['label']==0])} | Attaque: {len(df[df['label']==1])}")

# Préparer les features
df['rule_id_num'] = pd.to_numeric(df['rule_id'], errors='coerce').fillna(0)
df['rule_level'] = pd.to_numeric(df['rule_level'], errors='coerce').fillna(0)
df['firedtimes'] = pd.to_numeric(df['firedtimes'], errors='coerce').fillna(0)
df['event_id_num'] = pd.to_numeric(df['event_id'], errors='coerce').fillna(0)

# Encoder l'agent_name
le = LabelEncoder()
df['agent_encoded'] = le.fit_transform(df['agent_name'].fillna('unknown'))

# Features finales
X = df[['rule_id_num', 'rule_level', 'firedtimes', 'event_id_num', 'agent_encoded']].fillna(0)
y = df['label']

# Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Random Forest
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train, y_train)
y_pred = rf.predict(X_test)
print("\n=== Random Forest ===")
print(classification_report(y_test, y_pred))

# Feature importance
print("=== Feature Importance ===")
for feat, imp in zip(X.columns, rf.feature_importances_):
    print(f"  {feat}: {imp:.3f}")

# Isolation Forest
iso = IsolationForest(contamination=0.2, random_state=42)
iso.fit(X)
print("\n=== Isolation Forest entraine ✅ ===")

# Sauvegarder
pickle.dump(rf, open('rf_model.pkl', 'wb'))
pickle.dump(iso, open('iso_model.pkl', 'wb'))
pickle.dump(le, open('label_encoder.pkl', 'wb'))
print("✅ Modeles sauvegardes !")
