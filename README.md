

---


# Google One Tap SDK

Google One Tap allows users to authenticate anywhere on your site or application without a dedicated authentication page. This ensures a smooth experience, and you can offer users the chance to authenticate anywhere on their user journey.
To see which browsers are supported with One Tap, [check out](https://developers.google.com/identity/gsi/web/guides/supported-browsers)
 this page in Google’s developer documentation.
A simple JavaScript SDK to integrate **Google One Tap Login** into your web applications. The SDK includes automatic user authentication, JWT verification, and user data storage using `localStorage`. It allows for a smooth user experience with minimal configuration.



## Features

- **Google One Tap Login** integration.
- **JWT Decoding & Verification** with Google's public keys.
- **Local Storage Support** with base64 encoding for user data.
- Simple API for initializing, logging in, logging out, and retrieving user data.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Google Client ID Setup](#google-client-id-setup)
- [API Reference](#api-reference)
- [Example](#example)

---

## Installation

### Step 1: Clone or Download the SDK

You can clone this repository or download the SDK files.

```bash
git clone https://github.com/readwhere/googleonetaplogin-sdk.git
```

### Step 2: Include the SDK in Your Project

You can include the SDK file in your HTML or JavaScript project.

```html
<script src="path-to-sdk.js"></script>
```



---

## Usage

### 1. Initialize the SDK

Configure the SDK with your Google Client ID and other optional settings.

```javascript
GoogleOneTapSdk.initData({
    clientId: 'YOUR_GOOGLE_CLIENT_ID', // Required
    enableCookies: true,                // Optional (default: false)
    userCookieName: 'userToken'         // Required if enableCookies is true
});
```

### 2. Trigger Google One Tap Login

Use the `doLogin` function to display the Google One Tap login and handle login success.

```javascript
GoogleOneTapSdk.doLogin(function(userData) {
    console.log("Login successful! User data:", userData);
});
```

### 3. Log Out

To log the user out and remove their data from local storage:

```javascript
GoogleOneTapSdk.doLogout();
```

### 4. Get Logged-In User Data

Retrieve the stored user data:

```javascript
const user = GoogleOneTapSdk.getUserData();
if (user) {
    console.log("User Data:", user);
} else {
    console.log("No user is logged in.");
}
```

---

## Google Client ID Setup

To use the SDK, you need a **Google Client ID**. Follow these steps to create one:

### Step 1: Create a Google Cloud Project
- Go to the [Google Cloud Console](https://console.cloud.google.com/).
- Sign in with your Google account.
- Click Select a project ➝ New Project ➝ the Create button.
![image](https://github.com/user-attachments/assets/2eb226a3-bbeb-41af-bdc6-145590ceecc1)
![image](https://github.com/user-attachments/assets/70e77615-c719-462e-9caf-6dfc47c4100d)



### Step 2: Enable OAuth 2.0 Credentials
1. In the [Google Cloud Console](https://console.cloud.google.com/), select your newly created project.
2. On the left side, navigate to **APIs & Services > Credentials**.
3. ![image](https://github.com/user-attachments/assets/f7ac14de-31ba-4c36-903c-609c9d826460)
4. Click **Create Credentials** and choose **OAuth 2.0 Client IDs**.
5. ![image](https://github.com/user-attachments/assets/30e8f283-54a8-422c-b464-4f3f95e742a1)
6. Configure the OAuth consent screen:
   - Go to **OAuth consent screen**.
   - ![image](https://github.com/user-attachments/assets/1651b3ab-82b7-48c3-b31d-68d0ee304975)
   - Select **External** for public apps, then click **Create**.
   - Provide the required app information, like the app name and support email.
   - ![image](https://github.com/user-attachments/assets/0b911e11-f7bb-4d13-9a6b-32504d0bf4b3)
   - Under **Authorized Domains**, add any domains that will use the Google One Tap login.
   - Click **Save and Continue**.
7. Create your OAuth 2.0 Client ID:
   - Navigate back to **Credentials**.
   - Click **Create Credentials** and choose **OAuth 2.0 Client ID**.
   - Choose **Web application** as the application type.
   - Under **Authorized redirect URIs**, add `http://localhost` or your production URL (for local testing).
   - ![image](https://github.com/user-attachments/assets/62392c0e-33b3-4cca-a562-da083461f3b7)
   - Click **Create**.

### Step 3: Get Your Client ID
Once your OAuth client ID is created, you will be shown your **Client ID**. Copy this value, as you will need to pass it to the SDK.
![image](https://github.com/user-attachments/assets/8bc6ccd5-c262-4cb5-8882-fc1e4cfe5276)


---

## API Reference

- `GoogleOneTapSdk.initData(config)`:
   - Initializes the SDK with your settings.
   - Parameters:
     - `clientId`: (required) Your Google OAuth client ID.
     - `enableCookies`: (optional) Boolean to enable localStorage usage.
     - `userCookieName`: (required if `enableCookies` is true) The key name for storing user data.
  
- `GoogleOneTapSdk.doLogin(onSuccessCallback)`:
   - Initiates the Google One Tap login process.
   - Parameters:
     - `onSuccessCallback`: A function that is called when login is successful, passing the user data.

- `GoogleOneTapSdk.doLogout()`:
   - Logs the user out and clears stored data.

- `GoogleOneTapSdk.getUserData()`:
   - Retrieves the logged-in user data.

---

## Example

```html

<script src="path-to-your-sdk.js"></script>

<script>
    // Initialize the SDK
    GoogleOneTapSdk.initData({
        clientId: 'YOUR_GOOGLE_CLIENT_ID',
        enableCookies: true,
        userCookieName: 'userToken'
    });

    // Trigger Login
    GoogleOneTapSdk.doLogin(function(userData) {
        console.log('Login successful! User data:', userData);
    });

    // Get user data
    console.log( GoogleOneTapSdk.getUserData() )

    // Logout
    GoogleOneTapSdk.doLogout()
    
</script>
```

---


