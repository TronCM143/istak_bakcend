# firebase.py
import os
import json
import firebase_admin
from firebase_admin import credentials, messaging

# 🔹 Load Firebase credentials from environment variable
firebase_json = os.getenv("FIREBASE_CREDENTIALS")

if not firebase_admin._apps:
    try:
        if not firebase_json:
            raise ValueError("FIREBASE_CREDENTIALS not found in environment variables")

        # 🔹 Parse the JSON string → dict
        cred_dict = json.loads(firebase_json)

        # 🔹 Initialize Firebase using the parsed dict (not a path)
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)
        print("✅ Firebase initialized successfully from FIREBASE_CREDENTIALS")
    except Exception as e:
        print(f"❌ Firebase initialization failed: {e}")

def send_push_notification(fcm_token, title, body):
    try:
        message = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=body,
            ),
            token=fcm_token,
        )
        response = messaging.send(message)
        print(f"✅ Successfully sent notification: {response}")
        return response
    except Exception as e:
        print(f"❌ Error sending notification: {str(e)}")
        return None
