import sqlite3, os

# 1. Clear DB data (keep table structure)
db_path = ".proxies.db"
for f in [db_path, db_path + "-shm", db_path + "-wal"]:
    if os.path.exists(f):
        try:
            if f == db_path:
                conn = sqlite3.connect(f)
                conn.execute("DELETE FROM proxies")
                conn.commit()
                conn.close()
                print(f"Cleared data from {f}")
            else:
                os.remove(f)
                print(f"Removed {f}")
        except Exception as e:
            print(f"Error on {f}: {e}")

# 2. Remove scan state / proxy snapshot files
for f in [".scan_state.json", ".proxies.json"]:
    if os.path.exists(f):
        try:
            os.remove(f)
            print(f"Removed {f}")
        except Exception as e:
            print(f"Error on {f}: {e}")

print("Done. Ready for fresh run.")
