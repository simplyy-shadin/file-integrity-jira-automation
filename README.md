
<div align="center">

![Project Status](https://img.shields.io/badge/Project_Status-Active-brightgreen)
![Python](https://img.shields.io/badge/Python-3.x-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

</div>

# 🛡️ File Integrity Monitor with Automated Jira Ticketing

Continuously monitors a specified folder for file changes (addition, deletion, modification), logs events, and automatically creates issues in Jira for any detected change—helping organizations track integrity and security events seamlessly.

---

## 🚀 Features

- **Monitors file changes** in any directory (modification, creation, removal)
- **SHA-256 hash computation** to detect changes reliably
- **Logs events** to `file_integrity.log`
- **Automated Jira ticket creation** for every issue found
- Configurable via `.env` for credentials and project details
- **Runs every minute** (can be adjusted)

---

## 📦 Prerequisites

- Python 3.7+
- A Jira Cloud account (free or paid)
- Python packages in `requirements.txt`:
  - `python-dotenv`
  - `requests`
  - `schedule`

---
## 🧱 Folder Structure
```
file-integrity-jira-automation/
│
├── main.py                  # Main script
├── .env.example             # Sample environment file
├── requirements.txt         # Python dependencies
└── file_hashes.json         # Auto-generated file storing hashes

```
## 🐙 How to Get Your Jira Cloud API Credentials and Project Info

### 1. **Create a Jira Account**
- Sign up at [https://www.atlassian.com/software/jira](https://www.atlassian.com/software/jira)
- Choose **Jira Software Cloud** (free tier is fine)

### 2. **Create a Jira Project**
- Once logged in, select `Projects > Create Project`
- Pick a template ("Scrum", "Kanban" or "Bug Tracking")
- Set your **Project Key** (e.g., `KAN`)

### 3. **Get Your Jira Cloud URL**
- Will look like: `https://your-domain.atlassian.net`

### 4. **Generate a Jira API Token**
- Go to [Atlassian API tokens](https://id.atlassian.com/manage-profile/security/api-tokens)
- Click **Create API token** and copy the value

### 5. **Find Your Account Email**
- The email you use to log into Jira

---

## 🔑 Setting Up Your `.env` File

Create a file named `.env` in the project root with the following content:

JIRA_EMAIL=your-jira-login-email@example.com                                                                                                                                                                       
JIRA_API_KEY=your-api-token

git clone https://github.com/yourusername/file-integrity-monitor.git                                                                                                                                          
cd file-integrity-monitor

python -m venv venv                                                                                                                                                                                              
source venv/bin/activate # Linux/Mac                                                                                                                                                                           
venv\Scripts\activate # Windows

pip install -r requirements.txt

**Example `requirements.txt`:**                                                                                                                                                                              
python-dotenv                                                                                                                                                                                                  
schedule                                                                                                                                                                                                           
requests

---

## 📁 Configuration

Open `file_integrity_monitor.py` and edit:

FOLDER_TO_MONITOR = r"/absolute/path/to/folder"                                                                                                                                                               
JIRA_URL = "https://your-domain.atlassian.net"                                                                                                                                                               
JIRA_PROJECT_KEY = "KAN" # Set to your Jira project key                                                                                                                                                       
JIRA_ISSUE_TYPE = "Bug" # Typical values: "Bug", "Task", "Story"                                                                                                                                               

---

## 🏃 Usage

python file_integrity_monitor.py


- The script will scan the folder, log changes, and create Jira issues as needed.
- It repeats every minute by default.

---

## 📋 What Gets Logged and Sent to Jira?

- **Modification**: Existing file has a changed hash
- **New File**: Found a new file
- **File Removal**: Previously known file is now missing

Each triggers a new Jira issue with summary and descriptive details.

---

## 🛠 Example Jira Issue Created

- **Summary**: `File Integrity Issue: Modification - config.yaml`
- **Description**: `A Modification was detected for the file: /home/user/config.yaml. Please investigate.`
- **Type**: Bug (or your chosen issue type)

---

## 🧑‍💻 How The Script Works

1. Loads hashes from `file_hashes.json` (or creates it)
2. Scans all files, computes SHA-256 hash per file
3. Detects new/changed/removed files
4. Logs every action to `file_integrity.log`
5. Creates Jira ticket via REST API for each event
6. Updates `file_hashes.json`
7. Repeats every minute using `schedule`

---

## 🆘 Troubleshooting

- **Jira API errors**: Check your `.env` values and project key; consult [Jira REST API docs](https://developer.atlassian.com/cloud/jira/platform/rest/v2/intro/)
- **Permissions**: Script must have read/write access to the monitored folder and log/hash files
- **No `.env`**: Script will fail if Jira email/token are unset

---

## 🚦 To Stop the Script

- Simply press `CTRL+C` in the terminal

---

## 📄 License

MIT License

---

## 🙋 Connect with Me

<p align="center">
<a href="www.linkedin.com/in/shadin-k-v-cybersecurity/" target="_blank">
  <img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn"/>
</a>
<a href="https://tryhackme.com/p/simplyy.hacker" target="_blank">
  <img src="https://img.shields.io/badge/TryHackMe-88cc14?style=for-the-badge&logo=tryhackme&logoColor=white" alt="TryHackMe"/>
</a>
<a href="https://medium.com/@shdnkval" target="_blank">
  <img src="https://img.shields.io/badge/Medium-12100E?style=for-the-badge&logo=medium&logoColor=white" alt="Medium"/>
</a>
<a href="https://x.com/simplyy_shadin" target="_blank">
  <img src="https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white" alt="Twitter"/>
</a>
</p>

---

<p align="center"><samp>~ Automated security is better security. ~</samp></p>
