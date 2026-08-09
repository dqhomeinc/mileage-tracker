# Mileage Tracker

**Version 0.0.3**

A web app for logging and tracking driving mileage. Enter a start and end address to calculate the driving distance, save trips to your history, and export your logs.

## Features

- **Account system** — register, log in, and reset your password via email
- **Distance calculation** — uses OpenStreetMap (Nominatim + OSRM) to calculate real driving distances between two addresses
- **Address autocomplete** — type a partial address and select from live suggestions
- **Voice input** — speak an address into either location field; the app transcribes and resolves it to the closest matching address *(see known issues)*
- **Vehicle management** — add vehicles with a nickname and year/make/model; select which vehicle was used when logging each trip
- **Trip date & time** — optionally record the date a trip took place plus start and end times; history shows `–` when times are omitted
- **12h / 24h time toggle** — switch between 12-hour and 24-hour time display from the navbar; preference is saved across sessions
- **Trip history** — all logged trips are saved per account and displayed newest-first
- **Edit trips** — update start/end location, distance, vehicle, date, and times for any previously logged trip
- **Total mileage display** — running total and trip count shown above your history
- **Export** — download your trip history as PDF, Excel (.xlsx), or CSV; exports include vehicle, date, and time columns
- **Stay logged in** — optional persistent login so you don't have to sign in every visit
- **Install as app** — add to your home screen on iOS or Android via your browser's share menu

## Tech Stack

- **Backend:** Flask, Flask-Login, Flask-SQLAlchemy, Flask-Mail
- **Database:** PostgreSQL (production) / SQLite (local development)
- **Geocoding:** Nominatim (OpenStreetMap)
- **Routing:** OSRM public API
- **Frontend:** Bootstrap 5, vanilla JS, Web Speech API

## Known Issues

- **Voice input is not always working** — the Web Speech API is browser-dependent. It works best in Chrome and Edge on desktop. Safari support is inconsistent and Firefox does not support it at all. On some devices, microphone permission prompts may be dismissed silently with no visible error. If voice input appears to do nothing, try typing the address instead.

## Release Notes

### v0.0.3 — August 8, 2026
- Fixed password reset emails not sending: switched to Brevo's HTTPS email API (the previous Gmail SMTP approach was blocked by the hosting provider)
- Removed a temporary debug endpoint and tightened error handling on the password reset flow so internal error details are no longer shown to users
- Migrated deployment from Railway to Render, with the database moved to Neon Postgres
- Added automated PR checks: lint, build verification, and an AI code review on every pull request

### v0.0.2 — June 28, 2026
- Added vehicle management: create a personal vehicle list with nickname, year, make, and model; duplicate names are rejected
- Added vehicle selection when logging or editing a trip
- Added optional trip date, start time, and end time fields; history shows `–` when times are not entered
- Added 12h/24h time format toggle in the navbar, persisted in localStorage
- Updated exports (PDF, Excel, CSV) to include vehicle, trip date, start time, and end time columns
- PDF export switched to landscape to accommodate the additional columns

### v0.0.1 — June 26, 2026
Initial release with core mileage tracking functionality, user authentication, address autocomplete, voice input, trip history with edit/delete, export (PDF/Excel/CSV), and PWA home screen support.
