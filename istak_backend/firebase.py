# firebase.py
import os
import firebase_admin
from firebase_admin import credentials, messaging

# Get the current directory of this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

cred_path = os.path.join(BASE_DIR, "serviceAccountKey.json")

if not firebase_admin._apps:
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)

def send_push_notification(fcm_token, title, body):
    try:
        # Create a message
        message = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=body,
            ),
            token=fcm_token,
        )

        # Send the message
        response = messaging.send(message)
        print(f"Successfully sent notification: {response}")
        return response
    except Exception as e:
        print(f"Error sending notification: {str(e)}")
        return None