#!/usr/bin/env python3
"""Batch-push email drafts to Gmail via Google API.

Usage:
    python3 gmail_batch_drafts.py /tmp/all_100_drafts.json

Reads JSON file with list of {to, subject, body} objects, creates a Gmail draft for each.
On first run, opens browser for OAuth consent and saves token.json for reuse.

Expected JSON format:
    [{"to": "...", "subject": "...", "body": "..."}, ...]

Token cached at: ~/.secrets/gmail_token.json
Credentials needed: ~/.secrets/gmail_credentials.json (download from Google Cloud Console)
"""

import json
import sys
import os
import base64
from email.mime.text import MIMEText
from pathlib import Path

import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ['https://www.googleapis.com/auth/gmail.compose']


def get_service():
    """Get authenticated Gmail service via Application Default Credentials.

    Requires: gcloud auth application-default login --scopes=https://www.googleapis.com/auth/gmail.compose
    """
    try:
        creds, _ = google.auth.default(scopes=SCOPES)
    except Exception as e:
        print(f"ERROR: ADC not configured: {e}", file=sys.stderr)
        print("Run: gcloud auth application-default login --scopes=https://www.googleapis.com/auth/gmail.compose", file=sys.stderr)
        sys.exit(1)
    return build('gmail', 'v1', credentials=creds)


def make_draft(service, to, subject, body):
    msg = MIMEText(body)
    msg['to'] = to
    msg['subject'] = subject
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    draft = service.users().drafts().create(userId='me', body={'message': {'raw': raw}}).execute()
    return draft['id']


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <drafts.json>", file=sys.stderr)
        sys.exit(1)

    drafts = json.load(open(sys.argv[1]))
    print(f"Loaded {len(drafts)} drafts from {sys.argv[1]}")

    service = get_service()
    print("Gmail API authenticated")

    created = 0
    failed = 0
    for i, d in enumerate(drafts, 1):
        try:
            draft_id = make_draft(service, d['to'], d['subject'], d['body'])
            created += 1
            if i % 10 == 0 or i == len(drafts):
                print(f"  [{i}/{len(drafts)}] {created} created, {failed} failed")
        except HttpError as e:
            failed += 1
            print(f"  [{i}] FAIL {d['to']}: {e}", file=sys.stderr)

    print(f"\nDone: {created} drafts created, {failed} failed")


if __name__ == '__main__':
    main()
