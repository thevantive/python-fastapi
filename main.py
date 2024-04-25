from fastapi import FastAPI, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from typing import Optional
from datetime import datetime, timedelta
import mysql.connector
import jwt
import re

app = FastAPI()

# konfigurasi koneksi database ke vps
DATABASE_HOST = ""
DATABASE_NAME = ""
DATABASE_USER = ""
DATABASE_PASSWORD = ""

# menghubungkan ke database 
try:
    db = mysql.connector.connect(
        host=DATABASE_HOST,
        user=DATABASE_USER,
        password=DATABASE_PASSWORD,
        database=DATABASE_NAME,
    )
except mysql.connector.Error as err:
    print("Error connecting to database:", err)
    raise Exception("Internal Server Error (Database connection)")

# skema autentikasi
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# untuk keperluan hashing password 
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# konfigurasi CORS
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# verifikasi password 
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# untuk autentikasi user
def authenticate_user(username: str, password: str) -> dict | None:
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM m_user WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()

        if user and verify_password(password, user["password"]):
            return user
        else:
            return None
    except mysql.connector.Error as err:
        print("Error fetching user from database:", err)
        raise Exception("Internal Server Error (Database issue)")

# membuat token
def create_access_token(id: int) -> str:
    try:
        access_token_expires = timedelta(minutes=30)
        to_encode = {"sub": id, "exp": datetime.now() + access_token_expires}
        access_token = jwt.encode(to_encode, "secret_key", algorithm="HS256")

        # Insert into t_user_activity table
        cursor = db.cursor()
        insert_query = "INSERT INTO t_user_activity (user_id, created_at) VALUES (%s, %s)"
        cursor.execute(insert_query, (id, datetime.now()))
        db.commit()

        return access_token
    except Exception as e:
        print("Error creating access token and inserting user activity:", e)
        raise e

# untuk validasi token
def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(token, "secret_key", algorithms=["HS256"])
        id: int = payload.get("sub")
        if id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return get_user_by_id(id)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# mengambil user berdasarkan username
def get_user_by_username(username: str) -> dict:
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT id, username, fullname, email, level, created_at FROM m_user WHERE username = %s", (username,))
        user_row = cursor.fetchone()
        cursor.close()

        if not user_row:
            print(user_row)
            return {
                "meta": {
                    "status": True,
                    "message": "Pengguna Tidak Ditemukan"
                }
            }

        return user_row
    except mysql.connector.Error as err:
        print("Error fetching user from database:", err)
        return {
            "meta": {
                "status": True,
                "message": "Terjadi Kesalahan Pada Server"
            }
        }

# mengambil user berdasarakan id 
def get_user_by_id(id: int) -> dict:
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT id, username, fullname, email, level, created_at FROM m_user WHERE id = %s", (id,))
        user_row = cursor.fetchone()
        cursor.close()

        if not user_row:
            print(id)
            return {
                "meta": {
                    "status": True,
                    "message": "Pengguna Tidak Ditemukan"
                }
            }

        return user_row
    except mysql.connector.Error as err:
        print("Error fetching user from database:", err)
        return {
            "meta": {
                "status": True,
                "message": "Terjadi Kesalahan Pada Server"
            }
        }

# basemodel kebutuhn pada saat login
class UserLogin(BaseModel):
    username: str
    password: str

# endpoint login
@app.post("/login", response_model=dict)
def login(user_data: UserLogin) -> dict:
    user = authenticate_user(user_data.username, user_data.password)
    if not user:
        return {
            "meta": {
                "status": False,
                "message": "ID Pengguna atau Kata Sandi tidak sesuai"
            },
        }

    # mengambil data pengguna untuk keperluan identitas
    db_user = get_user_by_username(user_data.username)
    if not db_user:
        return {
            "meta": {
                "status": False,
                "message": "Data Pengguna Tidak Ditemukan"
            },
        }

    # membuat token
    access_token = create_access_token(db_user["id"])
    
    return {
        "meta": {
            "status": True,
            "message": "Berhasil Masuk"
        },
        "identity": db_user, 
        "token": access_token
    }

# endpoint untuk mengambil semua users
@app.get("/users", response_model=dict)
def get_all_users():
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                m.id AS id,
                m.username, 
                m.fullname, 
                m.email, 
                m.level, 
                m.created_at,
                MAX(a.created_at) AS last_login_at
            FROM 
                m_user m
            LEFT JOIN 
                t_user_activity a ON m.id = a.user_id
            GROUP BY 
                m.id
        """)
        users = cursor.fetchall()
        cursor.close()

        if not users:
            return {
                "meta": {
                    "status": False,
                    "message": "No users found"
                }
            }

        # mengindex user menggunakan idnya, kebutuhan fe
        indexed_users = {user["id"]: user for user in users}

        return {
            "meta": {
                "status": True,
                "message": "Successfully retrieved users"
            },
            "rows": indexed_users
        }
    except mysql.connector.Error as e:
        print(f"Error fetching users: {e}")
        return {
            "meta": {
                "status": False,
                "message": "Server error occurred"
            }
        }

# endpoint untuk form filed berjenis select 
@app.get("/users/list", response_model=dict)
def get_all_users_list():
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                m.id AS user_id,
                CONCAT(m.fullname, ' - ', m.username) AS display_name
            FROM 
                m_user m
        """)
        users = cursor.fetchall()
        cursor.close()

        if not users:
            return {
                "meta": {
                    "status": False,
                    "message": "No users found"
                }
            }

        # menyesuaikan kebutuhan fe
        user_dict = {
            user["user_id"]: user["display_name"]
            for user in users
        }

        return {
            "meta": {
                "status": True,
                "message": "Successfully retrieved simplified user list"
            },
            "list": user_dict
        }
    except mysql.connector.Error as e:
        print(f"Error fetching users: {e}")
        return {
            "meta": {
                "status": False,
                "message": "Database error"
            }
        }

# membuat struktur kebutuhan data untuk keperluan registrasi
class UserRegistration(BaseModel):
    level: int
    username: str
    password: str
    fullname: str
    email: str

# endpoint untuk registrasi
@app.post("/user/registration")
def register_user(user_data: UserRegistration, current_user: dict = Depends(get_current_user)) -> dict:
    try:
        
        # pengguna tidak diperbolehkan membuat akun
        if current_user["level"] == '3':
            return {
                "meta": {
                    "status": False,
                    "message": "Maaf, Pengguna Tidak Dapat Membuat Akun Pengguna Lain"
                }
            }
        
        # memeriksa username yang sudah digunakan
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM m_user WHERE username = %s", (user_data.username,))
        existing_user = cursor.fetchone()
        if existing_user:
            return {
                "meta": {
                    "status": False,
                    "message": "ID Pengguna Sudah Terpakai"
                }
            }

        # memeriksa format email yang benar
        if not re.match(r"[^@]+@[^@]+\.[^@]+", user_data.email):
            return {
                "meta": {
                    "status": False,
                    "message": "Format Email Tidak Benar"
                }
            }

        # memeriksa apabila email sudah digunakan
        cursor.execute("SELECT * FROM m_user WHERE email = %s", (user_data.email,))
        existing_email = cursor.fetchone()
        if existing_email:
            return {
                "meta": {
                    "status": False,
                    "message": "Maaf, Email Sudah Terpakai"
                }
            }

        # hash kata sandi
        hashed_password = pwd_context.hash(user_data.password)
        
        # batasan seorang admin
        if current_user["level"] == '2' and user_data.level == 1:
            return {
                "meta": {
                    "status": False,
                    "message": "Maaf, Admin Tidak Dapat Memberikan Level Super Admin"
                }
            }

        # menambahkan baris ke database
        cursor.execute(
            "INSERT INTO m_user (username, password, fullname, email, level) VALUES (%s, %s, %s, %s, %s)",
            (user_data.username, hashed_password, user_data.fullname, user_data.email, user_data.level),
        )
        db.commit()

        return {
            "meta": {
                "status": True,
                "message": "Berhasil Mendaftarkan Pengguna"
            }
        }
    except mysql.connector.Error as e:
        print("Error registering user:", e)
        return {
            "meta": {
                "status": False,
                "message": "Terjadi Kesalahan Pada Server"
            }
        }
    finally:
        cursor.close()

# untuk kebutuhan update user
class UpdateUser(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    fullname: Optional[str] = None
    level: Optional[int] = None
    email: Optional[str] = None

# endpoint untuk update user
@app.patch("/user/{user_id}")
def update_user(user_id: int, user_data: UpdateUser, current_user: dict = Depends(get_current_user)) -> dict:
    try:
        cursor = db.cursor(dictionary=True)

        # mengambil data yang akan diupdate
        cursor.execute("SELECT * FROM m_user WHERE id = %s", (user_id,))
        user_to_update = cursor.fetchone()

        if not user_to_update:
            return {
                "meta": {
                    "status": False,
                    "message": "Pengguna Tidak Ditemukan"
                }
            }

        current_user_level = current_user.get("level")

        if current_user_level is None:
            print(current_user)
            return {
                "meta": {
                    "status": False,
                    "message": "Terjadi Kesalahan Pada Server"
                }
            }

        user_to_update_level = user_to_update.get("level")

        # pengguna hanya boleh memperbaharui datanya sendiri
        if current_user_level == '3' and current_user["id"] != user_id:
            return {
                "meta": {
                    "status": False,
                    "message": "Anda Hanya Boleh Memperbaharui Data Anda"
                }
            }

        if (current_user_level == '2' and (user_to_update_level == '2' or user_to_update_level == '1')) and current_user["id"] != user_id:
            return {
                "meta": {
                    "status": False,
                    "message": "Admin Tidak Boleh Memperbaharui Data Sesama Admin atau Super Admin"
                }
            }
        
        if current_user_level == '2' and user_data.level == 1:
            return {
                "meta": {
                    "status": False,
                    "message": "Admin Tidak Dapat Memberikan Level Super Admin"
                }
            }

        # update ke db
        cursor.execute(
            "UPDATE m_user SET username = %s, fullname = %s, email = %s, level = %s WHERE id = %s",
            (user_data.username, user_data.fullname, user_data.email, user_data.level, user_id)
        )
        db.commit()

        return {
            "meta": {
                "status": True,
                "message": "User information updated successfully"
            }
        }
    except mysql.connector.Error as e:
        print("Error updating user information:", e)
        return {
            "meta": {
                "status": False,
                "message": "Terjadi Kesalahan Pada Server"
            }
        }
    finally:
        cursor.close()

# endpoint untuk menghapus pengguna
@app.delete("/user/{user_id}")
def delete_user(user_id: int, current_user: dict = Depends(get_current_user)) -> dict:
    try:
        cursor = db.cursor(dictionary=True)
        current_user_level = current_user.get("level")

        # memastikan id tersedia
        cursor.execute("SELECT * FROM m_user WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            return {
                "meta": {
                    "status": True,
                    "message": "Pengguna Tidak Ditemukan"
                }
            }
        
        # pengguna tidak dapat menghapus akunnya sendiri
        if current_user_level == '3':
            return {
                "meta": {
                    "status": False,
                    "message": "Pengguna Tidak Bisa Menghapus Data"
                }
            }
        
        if (current_user_level == '2' and (user["level"] == '2' or user["level"] == '1')) and current_user["id"] != user_id:
            return {
                "meta": {
                    "status": False,
                    "message": "Admin Tidak Boleh Menghapus Data Sesama Admin atau Super Admin"
                }
            }

        # menghapus user dari database
        cursor.execute("DELETE FROM m_user WHERE id = %s", (user_id,))
        db.commit()
        return {
            "meta": {
                "status": True,
                "message": "Pengguna Berhasil Dihapus"
            }
        }

    except mysql.connector.Error as e:
        print(f"Error deleting user from database: {e}")
        return {
            "meta": {
                "status": False,
                "message": "Terjadi Kesalahan Pada Server"
            }
        }

    finally:
        cursor.close()