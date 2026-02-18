import os
import sqlite3

DB_FILE = "maintenance.db"
AUTH_CONFIG_KEY = "api_auth"


def main():
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_FILE)
    if not os.path.exists(db_path):
        print(f"Tietokantaa ei loydy: {db_path}")
        return

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("DELETE FROM config WHERE key=?", (AUTH_CONFIG_KEY,))
    deleted = c.rowcount
    conn.commit()
    conn.close()

    if deleted > 0:
        print("API-salasana poistettu.")
    else:
        print("API-salasanaa ei ollut asetettu.")


if __name__ == "__main__":
    main()
