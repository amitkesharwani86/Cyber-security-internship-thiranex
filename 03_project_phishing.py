import pandas as pd
import re

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report
)

import seaborn as sns
import matplotlib.pyplot as plt


# --------------------------
# Feature Extraction
# --------------------------

def extract_features(text):

    text = str(text).lower()

    url_count = len(
        re.findall(r'https?://\S+|www\.\S+', text)
    )

    suspicious_words = [
        'click',
        'verify',
        'urgent',
        'bank',
        'password',
        'login',
        'winner',
        'prize',
        'free',
        'account'
    ]

    suspicious_count = sum(
        word in text
        for word in suspicious_words
    )

    return (
        text
        + " URLCOUNT_" + str(url_count)
        + " SUSCOUNT_" + str(suspicious_count)
    )


# --------------------------
# Load Dataset
# --------------------------

df = pd.read_csv("emails.csv")

df["processed"] = df["text"].apply(extract_features)

X = df["processed"]
y = df["label"]

# --------------------------
# Train/Test Split
# --------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# --------------------------
# ML Pipeline
# --------------------------

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            stop_words="english"
        )
    ),
    (
        "classifier",
        RandomForestClassifier(
            n_estimators=100,
            random_state=42
        )
    )
])

# --------------------------
# Train Model
# --------------------------

model.fit(X_train, y_train)

# --------------------------
# Predictions
# --------------------------

y_pred = model.predict(X_test)

# --------------------------
# Accuracy
# --------------------------

accuracy = accuracy_score(
    y_test,
    y_pred
)

print("\nAccuracy:", round(accuracy * 100, 2), "%")

# --------------------------
# Classification Report
# --------------------------

print("\nClassification Report:\n")
print(
    classification_report(
        y_test,
        y_pred
    )
)

# --------------------------
# Confusion Matrix
# --------------------------

cm = confusion_matrix(
    y_test,
    y_pred
)

plt.figure(figsize=(6,4))

sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    cmap="Blues",
    xticklabels=["Safe","Phishing"],
    yticklabels=["Safe","Phishing"]
)

plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")

plt.show()

# --------------------------
# Email Testing
# --------------------------

while True:

    email = input(
        "\nEnter Email Text (or quit): "
    )

    if email.lower() == "quit":
        break

    processed = extract_features(email)

    prediction = model.predict(
        [processed]
    )[0]

    print(
        "\nPrediction:",
        prediction.upper()
    )