#!/usr/bin/env python3
"""
Generate dummy report entries into maintenance.db.

Usage:
  python3 dummydata.py 100
  python3 dummydata.py 250 --db maintenance.db --days-back 60 --seed 42
"""

import argparse
import json
import random
import sqlite3
import sys
from datetime import date, timedelta


FIRST_NAMES = [
    "Mika",
    "Jari",
    "Juha",
    "Antti",
    "Timo",
    "Sami",
    "Janne",
    "Petri",
    "Marko",
    "Mikko",
    "Ville",
    "Esa",
    "Ari",
    "Risto",
    "Pekka",
    "Kari",
    "Teemu",
    "Joni",
    "Laura",
    "Anna",
    "Sari",
    "Maria",
    "Elina",
    "Katja",
    "Tiina",
    "Heidi",
    "Emilia",
    "Noora",
    "Johanna",
    "Paula",
]

LAST_NAMES = [
    "Virtanen",
    "Korhonen",
    "Makinen",
    "Nieminen",
    "Heikkinen",
    "Koskinen",
    "Jokinen",
    "Lehtonen",
    "Laine",
    "Hamalainen",
    "Aaltonen",
    "Pitkanen",
    "Manninen",
    "Salminen",
    "Niskanen",
    "Rantanen",
    "Karjalainen",
    "Lindholm",
    "Ahonen",
    "Heinonen",
]

STREETS = [
    "Keskuskatu",
    "Asemakatu",
    "Kirkkokatu",
    "Rantatie",
    "Koulutie",
    "Puistokatu",
    "Siltakatu",
    "Satamakatu",
    "Teollisuustie",
    "Lahdenkatu",
    "Myllytie",
    "Koivutie",
    "Metsatie",
    "Pellontie",
]

POSTAL_CITY = [
    ("00100", "Helsinki"),
    ("20100", "Turku"),
    ("33100", "Tampere"),
    ("40100", "Jyvaskyla"),
    ("90100", "Oulu"),
    ("65100", "Vaasa"),
    ("53100", "Lappeenranta"),
    ("70100", "Kuopio"),
    ("11100", "Riihimaki"),
    ("06100", "Porvoo"),
]

VEHICLE_MODELS = [
    "Toyota Corolla",
    "Toyota Yaris",
    "Volkswagen Golf",
    "Skoda Octavia",
    "Volvo V70",
    "Volvo V60",
    "Audi A4",
    "BMW 320",
    "Mercedes C 200",
    "Ford Focus",
    "Ford Fiesta",
    "Nissan Qashqai",
    "Kia Ceed",
    "Hyundai i30",
    "Peugeot 308",
    "Renault Clio",
]

LOREM_WORDS = """
huolto tarkastus vaihto kiristys puhdistus mittaus korjaus koeajo pesu kuivatus
asiakas autohuolto varaosa moottori jarru alusta vaihteisto sytytys suodatin neste
seuranta huomio lisatyo havainto merkitty valmis aloitettu jatkotoimi suositus arvio
talvirengas kesarengas paine laakeri anturi laturi akku remmi ketju pyora
ajoneuvo testi kytkin aani tuntu toiminta lampo kaynti savutus vikakoodi
""".split()


def parse_args():
    parser = argparse.ArgumentParser(description="Generate dummy reports into maintenance.db")
    parser.add_argument("count", type=int, help="Number of dummy reports to generate")
    parser.add_argument("--db", default="maintenance.db", help="Path to SQLite DB (default: maintenance.db)")
    parser.add_argument("--days-back", type=int, default=60, help="Random report date range back from today")
    parser.add_argument("--seed", type=int, default=None, help="Optional random seed for reproducible data")
    return parser.parse_args()


def random_words(rng, min_words=3, max_words=10):
    word_count = rng.randint(min_words, max_words)
    text = " ".join(rng.choice(LOREM_WORDS) for _ in range(word_count))
    return text.capitalize() + "."


def random_plate(rng):
    letters = "ABCDEFGHJKLMNPRSTUVWXYZ"
    return "".join(rng.choice(letters) for _ in range(3)) + "-" + str(rng.randint(1, 999)).zfill(3)


def random_vin(rng):
    alphabet = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
    return "".join(rng.choice(alphabet) for _ in range(17))


def random_engine_code(rng):
    letters = "ABCDEFGHJKLMNPRSTUVWXYZ"
    return f"{rng.choice(letters)}{rng.choice(letters)}{rng.randint(10, 99)}{rng.choice(letters)}"


def random_customer_block(rng):
    first = rng.choice(FIRST_NAMES)
    last = rng.choice(LAST_NAMES)
    street = rng.choice(STREETS)
    house = rng.randint(1, 120)
    unit = rng.choice(["", f" A {rng.randint(1, 30)}", f" B {rng.randint(1, 30)}"])
    postal, city = rng.choice(POSTAL_CITY)
    return f"{first} {last}\n{street} {house}{unit}\n{postal} {city}"


def load_maintenance_template(conn):
    cur = conn.cursor()
    cur.execute("SELECT value FROM config WHERE key='maintenance_items'")
    row = cur.fetchone()
    if not row or not row[0]:
        raise RuntimeError("Config key 'maintenance_items' not found in DB.")

    try:
        data = json.loads(row[0])
    except json.JSONDecodeError as exc:
        raise RuntimeError("Config key 'maintenance_items' contains invalid JSON.") from exc

    groups_in = data.get("groups") if isinstance(data, dict) else None
    if not isinstance(groups_in, list) or not groups_in:
        raise RuntimeError("No maintenance groups found in config.")

    groups_out = []
    for g_idx, group in enumerate(groups_in):
        if not isinstance(group, dict):
            continue
        g_id = str(group.get("id") or f"group_{g_idx+1}")
        g_title = str(group.get("title") or f"Group {g_idx+1}")
        items_in = group.get("items")
        if not isinstance(items_in, list):
            continue

        items_out = []
        for i_idx, item in enumerate(items_in):
            if not isinstance(item, dict):
                continue
            item_id = str(item.get("id") or f"{g_id}_item_{i_idx+1}")
            label = str(item.get("label") or f"Item {i_idx+1}")
            subitems_raw = item.get("subitems")
            subitems = []
            if isinstance(subitems_raw, list):
                for sub in subitems_raw:
                    if isinstance(sub, str):
                        val = sub.strip()
                        if val and val not in subitems:
                            subitems.append(val)
            items_out.append(
                {
                    "id": item_id,
                    "label": label,
                    "subitems": subitems,
                }
            )

        if items_out:
            groups_out.append({"id": g_id, "title": g_title, "items": items_out})

    if not groups_out:
        raise RuntimeError("No usable maintenance items found in config.")

    schema_version = 2
    if isinstance(data, dict):
        try:
            schema_version = int(data.get("schema_version", 2))
        except (TypeError, ValueError):
            schema_version = 2

    return schema_version, groups_out


def build_random_maintenance_v2(rng, schema_version, template_groups):
    groups = []
    all_items = []
    done_count = 0

    for group in template_groups:
        out_items = []
        for item in group["items"]:
            roll = rng.random()
            if roll < 0.40:
                status = "done"
            elif roll < 0.58:
                status = "not_done"
            else:
                status = "na"

            selected_subitems = []
            if item["subitems"] and status == "done":
                max_pick = min(2, len(item["subitems"]))
                pick_count = 1 if max_pick <= 1 else rng.randint(1, max_pick)
                selected_subitems = rng.sample(item["subitems"], pick_count)

            note = ""
            if rng.random() < 0.18:
                note = random_words(rng, min_words=3, max_words=8)

            out_item = {
                "id": item["id"],
                "label": item["label"],
                "subitems": list(item["subitems"]),
                "selected_subitems": selected_subitems,
                "note": note,
                "status": status,
            }
            out_items.append(out_item)
            all_items.append(out_item)
            if status == "done":
                done_count += 1

        groups.append(
            {
                "id": group["id"],
                "title": group["title"],
                "items": out_items,
            }
        )

    # Ensure at least one checked/done item.
    if done_count == 0 and all_items:
        chosen = rng.choice(all_items)
        chosen["status"] = "done"
        if chosen["subitems"] and not chosen["selected_subitems"]:
            chosen["selected_subitems"] = [rng.choice(chosen["subitems"])]

    return {
        "schema_version": schema_version,
        "groups": groups,
        "legacy_items": [],
    }


def flatten_maintenance_items(maintenance_v2):
    flat = {}
    for group in maintenance_v2.get("groups", []):
        for item in group.get("items", []):
            label = item.get("label")
            status = item.get("status", "na")
            if isinstance(label, str):
                flat[label] = status
    return flat


def build_report_payload(rng, schema_version, template_groups, days_back):
    report_day = date.today() - timedelta(days=rng.randint(0, max(0, days_back)))
    registered_day = date.today() - timedelta(days=rng.randint(365, 365 * 20))
    customer_name = random_customer_block(rng)
    maintenance_v2 = build_random_maintenance_v2(rng, schema_version, template_groups)

    first_name = customer_name.split("\n", 1)[0].split(" ", 1)[0]

    return {
        "customer_name": customer_name,
        "report_date": report_day.isoformat(),
        "pre_info": random_words(rng, 2, 7) if rng.random() < 0.22 else "",
        "license_plate": random_plate(rng),
        "vin": random_vin(rng),
        "vehicle_model": rng.choice(VEHICLE_MODELS),
        "engine_code": random_engine_code(rng),
        "registered_date": registered_day.isoformat(),
        "mileage": str(rng.randint(8_000, 390_000)),
        "additional_notes": random_words(rng, 4, 14) if rng.random() < 0.35 else "",
        "mechanic_signature": first_name,
        "maintenance_schema_version": schema_version,
        "maintenance_v2": maintenance_v2,
        "items": flatten_maintenance_items(maintenance_v2),
        "attachments": [],
    }


def insert_dummy_reports(db_path, count, days_back, seed):
    if count < 0:
        raise ValueError("count must be >= 0")
    if days_back < 0:
        raise ValueError("days-back must be >= 0")

    rng = random.Random(seed)

    conn = sqlite3.connect(db_path)
    try:
        schema_version, template_groups = load_maintenance_template(conn)
        cur = conn.cursor()

        inserts = []
        for _ in range(count):
            report = build_report_payload(rng, schema_version, template_groups, days_back)
            inserts.append(
                (
                    report["customer_name"],
                    report["license_plate"],
                    report["vin"],
                    report["report_date"],
                    json.dumps(report, ensure_ascii=False),
                )
            )

        if inserts:
            cur.executemany(
                """
                INSERT INTO reports (customer_name, license_plate, vin, report_date, data)
                VALUES (?, ?, ?, ?, ?)
                """,
                inserts,
            )
        conn.commit()
    finally:
        conn.close()


def main():
    args = parse_args()
    try:
        insert_dummy_reports(args.db, args.count, args.days_back, args.seed)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(
        f"Inserted {args.count} dummy reports into {args.db} "
        f"(random report_date 0..{args.days_back} days back)."
    )


if __name__ == "__main__":
    main()
