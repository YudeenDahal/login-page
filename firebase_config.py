"""
Firebase Configuration
Instructions for setting up Firebase
"""

"""
FIREBASE SETUP INSTRUCTIONS:

1. Go to Firebase Console: https://console.firebase.google.com/

2. Create a new project or select existing project

3. Enable Firestore Database:
   - Go to "Build" > "Firestore Database"
   - Click "Create database"
   - Choose production or test mode
   - Select your region

4. Generate Service Account Key:
   - Go to Project Settings (gear icon)
   - Navigate to "Service Accounts" tab
   - Click "Generate New Private Key"
   - Download the JSON file
   - Rename it to 'firebase-credentials.json'
   - Place it in your project root directory

5. Firestore Security Rules (for production):
   
   rules_version = '2';
   service cloud.firestore {
     match /databases/{database}/documents {
       // Users collection
       match /users/{userId} {
         allow read: if request.auth != null && request.auth.uid == userId;
         allow create: if request.auth != null;
         allow update: if request.auth != null && request.auth.uid == userId;
         allow delete: if false;
       }
     }
   }

6. Environment Variables (.env file):
   
   SECRET_KEY=your-super-secret-key-here
   JWT_SECRET=your-jwt-secret-key-here
   FIREBASE_CREDENTIALS_PATH=firebase-credentials.json

"""

# Firebase credentials template
FIREBASE_CREDENTIALS_TEMPLATE = {
    "type": "service_account",
    "project_id": "your-project-id",
    "private_key_id": "your-private-key-id",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
    "client_email": "firebase-adminsdk-xxxxx@your-project-id.iam.gserviceaccount.com",
    "client_id": "123456789012345678901",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-xxxxx%40your-project-id.iam.gserviceaccount.com"
}