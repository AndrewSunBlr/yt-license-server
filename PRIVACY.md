# Privacy Policy for YouTube Localizer

**Last updated:** May 21, 2026

---

## 1. Overview

YouTube Localizer ("the App", "we", "our", "us") is a desktop application designed to help YouTube content creators translate their video titles, descriptions, and captions into multiple languages using the YouTube Data API v3.

This Privacy Policy explains what data the App collects, how it is used, and your rights regarding your information.

---

## 2. What Data We Collect

The App collects the following types of data:

### 2.1 Information You Provide

| Data Type | Purpose |
|-----------|---------|
| **Google Account (email)** | To authenticate you and associate translations with your YouTube channel |
| **License Key** | To verify your subscription and activate the App |
| **Video ID** | To identify which YouTube video to update with translations |
| **Title and description files (title.txt, description.txt)** | To translate your video metadata into selected languages |
| **Subtitle files (.srt)** | To translate and upload caption tracks to your videos |

### 2.2 Automatically Collected Data

| Data Type | Purpose |
|-----------|---------|
| **HWID (Hardware ID)** | To bind your license to a specific device and prevent unauthorized sharing |
| **Device information (OS, machine ID)** | For license validation and anti-piracy protection |
| **App usage logs** | For debugging and technical support only — never shared with third parties |

### 2.3 Data from YouTube API

The App accesses your YouTube account **only** to:

- Read your existing video metadata (title, description, localizations)
- Update your video metadata with translated titles and descriptions
- Upload translated subtitle (.srt) files to your videos

**The App never:**  
❌ Reads your private messages or comments  
❌ Accesses your channel analytics  
❌ Modifies videos you do not own  
❌ Shares your YouTube data with any third party

---

## 3. How We Use Your Data

Your data is used **exclusively** for:

- Authenticating you via Google OAuth 2.0
- Translating your video titles, descriptions, and captions
- Uploading translations to your YouTube videos
- Validating your license and subscription status
- Improving the App and providing technical support

**We do NOT:**  
- Sell your data to anyone  
- Share your data with advertisers  
- Use your data for marketing purposes  
- Store your video content permanently (all operations are real-time)

---

## 4. Data Storage and Security

| Data | Where it's stored | Retention period |
|------|-------------------|------------------|
| **OAuth refresh token** | Encrypted on your local machine (`.youtube_localizer/accounts.bin`) | Until you sign out |
| **License information** | Encrypted on your local machine (`.youtube_localizer/license.bin`) | Until you deactivate |
| **License records** | On our secure server (Render.com + PostgreSQL) | For subscription management |
| **Translation files** | On your local machine (folder you select) | Until you delete them |
| **Logs** | On your local machine only | For debugging purposes |

**Security measures:**
- All local data is encrypted using AES-GCM + ChaCha20 (HWID-bound)
- API communications use HTTPS and Ed25519 signatures
- Your refresh token is never stored on our servers

---

## 5. Third-Party Services

The App uses the following third-party services:

| Service | Purpose | Data shared |
|---------|---------|-------------|
| **Google (YouTube Data API v3)** | Video metadata and subtitle management | Video titles, descriptions, captions |
| **Google OAuth 2.0** | User authentication | Your email address |
| **Lemon Squeezy** | Payment processing and license management | License key, email (for subscription) |
| **Render.com** | License server hosting | License records (email, license key, HWID) |

Each of these services has its own privacy policy. We recommend reviewing them:

- [Google Privacy Policy](https://policies.google.com/privacy)
- [Lemon Squeezy Privacy Policy](https://www.lemonsqueezy.com/privacy)
- [Render Privacy Policy](https://render.com/privacy)

---

## 6. Your Rights

You have the right to:

- **Access** the data we store about you
- **Delete** your license and account data by contacting us
- **Revoke** the App's access to your YouTube account via [Google Account Permissions](https://myaccount.google.com/permissions)
- **Uninstall** the App at any time (all local data will remain on your machine until manually deleted)

To exercise any of these rights, contact us at: **era2313828@gmail.com**

---

## 7. Data Retention

- **License data** (email, license key, HWID) is retained for as long as your subscription is active, plus 30 days for billing purposes.
- **You can delete your local data** by deleting the folder `C:\Users\[YourName]\.youtube_localizer\`
- **To request deletion from our server**, email us with your license key or email address.

---

## 8. Children's Privacy

The App is not intended for children under 13. We do not knowingly collect personal information from children under 13.

---

## 9. Changes to This Privacy Policy

We may update this Privacy Policy from time to time. Any changes will be posted at the URL where this document is hosted. Continued use of the App after changes constitutes acceptance of the updated policy.

---

## 10. Contact Information

For any questions, concerns, or data requests, please contact:

**Developer:** Andrew Sun  
**Email:** era2313828@gmail.com  
**Project Repository:** [https://github.com/AndrewSunBlr/yt-license-server](https://github.com/AndrewSunBlr/yt-license-server)

---

## 11. Consent

By using YouTube Localizer, you consent to this Privacy Policy and agree to its terms. You also confirm that you have read and agree to the [YouTube Terms of Service](https://www.youtube.com/t/terms) and [Google Privacy Policy](https://policies.google.com/privacy).
