import re
import base64
import requests
import urllib.parse
from bs4 import BeautifulSoup
from pathlib import Path
from email import message_from_bytes
from email.header import decode_header
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from datetime import datetime, timedelta, timezone
import pandas as pd
import time

# === CONFIG ===
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
APEX_REST_URL = 'https://apex.oracle.com/pls/apex/varunk/jobapi/addjob'
RED_FLAGS = ['security clearance', '5+ years', '7+ years', 'ts/sci', 'us citizen only']
MAX_RETRIES = 3

def authenticate_gmail():
    creds = None
    if Path('token.json').exists():
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    else:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

def clean_subject(subject):
    try:
        decoded, charset = decode_header(subject)[0]
        return decoded.decode(charset) if isinstance(decoded, bytes) else decoded
    except:
        return subject

def extract_jobs_from_html(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    jobs = []
    seen = set()

    for a_tag in soup.find_all('a', href=True):
        link = a_tag['href']
        if not re.search(r'/jobs/view/\d+', link):
            continue

        title_text = a_tag.get_text(separator=" ", strip=True)
        if not title_text or len(title_text) < 3:
            continue

        key = (title_text, link)
        if key in seen:
            continue
        seen.add(key)

        job_title = title_text.split(' · ')[0].split('$')[0].strip()
        job_title = job_title[:950]  # truncate to avoid DB errors

        company = "Unknown"
        location = "Unknown"

        parent = a_tag.find_parent()
        if parent:
            sibling_divs = parent.find_all_next(['span', 'p'], limit=4)
            for tag in sibling_divs:
                text = tag.get_text(strip=True)
                if '·' in text and len(text) > 4 and text != title_text:
                    split = text.split('·')
                    if len(split) == 2:
                        company = split[0].strip()
                        location = split[1].strip()
                    elif len(split) > 2:
                        company = split[0].strip()
                        location = '·'.join(split[1:]).strip()
                    break

        jobs.append({
            'title': job_title,
            'company': company[:450],
            'url': link[:950],
            'location': location[:450]
        })

    return jobs

def is_red_flag(job_data):
    text = f"{job_data['title']} {job_data['company']}".lower()
    return any(flag in text for flag in RED_FLAGS)

def send_to_apex(job, retries=MAX_RETRIES):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0'
    }

    payload = {
        'job_title': job['title'],
        'company_name': job['company'],
        'job_url': job['url'],
        'location': job['location']
    }

    for attempt in range(1, retries + 1):
        try:
            response = requests.post(APEX_REST_URL, json=payload, headers=headers, timeout=20)
            if response.status_code == 200:
                print("✅ Sent successfully\n")
                return True
            else:
                print(f"⚠️ Attempt {attempt} failed with status code: {response.status_code}")
                print(f"🔍 Response content: {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"❌ Attempt {attempt} failed: {e}")
        time.sleep(2)
    return False

def fetch_linkedin_emails():
    print("📬 Fetching LinkedIn job alerts and sending to APEX...\n")
    service = authenticate_gmail()
    now = datetime.now(timezone.utc)
    after = int((now - timedelta(days=1)).timestamp())
    query = f'from:jobalerts-noreply@linkedin.com after:{after}'
    result = service.users().messages().list(userId='me', q=query, maxResults=20).execute()
    messages = result.get('messages', [])
    all_jobs = []

    for msg in messages:
        msg_data = service.users().messages().get(userId='me', id=msg['id'], format='raw').execute()
        raw_msg = base64.urlsafe_b64decode(msg_data['raw'])
        mime_msg = message_from_bytes(raw_msg)
        subject = clean_subject(mime_msg.get('Subject'))
        print(f"📨 Subject: {subject}")

        html_body = ""
        if mime_msg.is_multipart():
            for part in mime_msg.walk():
                if part.get_content_type() == 'text/html':
                    html_body = part.get_payload(decode=True).decode(errors='ignore')
                    break
        elif mime_msg.get_content_type() == 'text/html':
            html_body = mime_msg.get_payload(decode=True).decode(errors='ignore')

        if not html_body:
            continue

        jobs = extract_jobs_from_html(html_body)
        print(f"🔎 Found {len(jobs)} job(s) in this email.\n")
        all_jobs.extend(jobs)

    unique_jobs_df = pd.DataFrame(all_jobs).drop_duplicates(subset='url')
    unique_jobs = unique_jobs_df.to_dict(orient='records')
    unique_jobs_df.to_csv("extracted_jobs.csv", index=False)
    print(f"📂 Saved {len(unique_jobs)} unique jobs to extracted_jobs.csv\n")

    print("🖨️ Listing all unique jobs saved:")
    for job in unique_jobs:
        print(f"\n📌 {job['title']} @ {job['company']} 📍 {job['location']}")
        print(f"🔗 {job['url']}")

    print("\n📤 Sending jobs to APEX...")
    for idx, job in enumerate(unique_jobs, 1):
        print(f"🚀 [{idx}/{len(unique_jobs)}] Uploading: {job['title']} @ {job['company']} 📍 {job['location']}")
        if not is_red_flag(job):
            success = send_to_apex(job)
            if not success:
                print("❌ Failed to send\n")
        time.sleep(1)

if __name__ == "__main__":
    fetch_linkedin_emails()
