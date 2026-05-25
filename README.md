# Lab 04 - Student Management (Flask + SQL Server)

This project stores encrypted data in SQL Server and performs all crypto on the client (Python/Flask).

## Prerequisites

- Windows with SQL Server installed (local instance).
- ODBC Driver 17 for SQL Server.
- Python 3.x.

## Setup

1. Create a database named `QLSVNhom1` in SQL Server.
2. Run the SQL scripts in order:
   - `sql/01_create_db_and_tables.sql`
   - `sql/02_stored_procedures.sql`
   - `sql/03_sample_data.sql`

3. (Optional) Create a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
```

4. Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Seed data

Run the seeding script to create sample data and RSA keys:

```bash
python seed_data.py
```

This will generate private key files in the `keys/` folder and create sample accounts.

## Run the app

```bash
python app.py
```

Open the app in your browser:

```
http://localhost:5000
```

## Sample accounts

- `NV01 / abcd12` (manages LOP01, LOP02)
- `NV02 / xyz789` (manages LOP03)
- `NV03 / abcd12` (manages LOP04)

## Notes

- The app uses Windows trusted connection to SQL Server.
- Private key files (`*.pem`) are generated locally and ignored by Git.
