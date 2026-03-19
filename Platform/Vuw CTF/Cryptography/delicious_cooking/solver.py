#!/usr/bin/env python3
import sqlite3

def solve():
    db_file = 'users.db'
    target_user = 'meatballfan19274'
    
    try:
        # Membuka koneksi ke database SQLite
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Mengambil daftar semua tabel di dalam database
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"[*] Tabel yang ditemukan di database: {[t[0] for t in tables]}")
        
        found = False
        
        # Iterasi ke setiap tabel untuk mencari username target
        for table in tables:
            table_name = table[0]
            try:
                # Mencari baris dengan username target
                cursor.execute(f"SELECT * FROM {table_name} WHERE username=?", (target_user,))
                rows = cursor.fetchall()
                
                if rows:
                    print(f"\n[*] Target ditemukan di tabel '{table_name}'!")
                    found = True
                    
                    # Mengambil nama-nama kolom
                    col_names = [desc[0] for desc in cursor.description]
                    
                    for row in rows:
                        data = dict(zip(col_names, row))
                        print(f"[*] Data : {data}")
                        
                        # Mengekstrak password dan memformatnya menjadi flag
                        if 'password' in data:
                            password = data['password']
                            print(f"\n[*] Ekstraksi berhasil!")
                            print(f"[*] Flag : VuwCTF{{{password}}}")
                        else:
                            print("[!] Kolom 'password' tidak ditemukan pada tabel ini.")
            except sqlite3.OperationalError:
                # Mengabaikan error jika tabel tidak memiliki kolom 'username'
                pass
                
        if not found:
            print(f"\n[!] Username '{target_user}' tidak ditemukan di tabel manapun.")
            
    except sqlite3.Error as e:
        print(f"[!] Terjadi kesalahan SQLite: {e}")
    except Exception as e:
        print(f"[!] Terjadi kesalahan: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    solve()
