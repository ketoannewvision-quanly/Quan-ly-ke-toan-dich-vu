# -*- coding: utf-8 -*-
"""
NEW VISION - QUẢN LÝ CÔNG VIỆC KẾ TOÁN DỊCH VỤ HÀNG THÁNG (Streamlit + SQLite)

Chạy:
    pip install streamlit pandas
    streamlit run app.py

Đăng nhập lần đầu: admin / Admin@123 (hệ thống bắt buộc đổi mật khẩu ngay).
Có thể đặt mật khẩu ban đầu bằng biến môi trường ADMIN_INITIAL_PASSWORD
trước khi chạy lần đầu (khi database chưa tồn tại).

QUY TRÌNH HÀNG THÁNG
  B1. Hạch toán sổ sách (9 bước nhỏ)            - có Ngày hoàn thành
  B2. Kê khai thuế (theo sắc thuế, kỳ T/Q/N)     - có Ngày hoàn thành, cảnh báo hạn
  B3. Nộp tiền thuế (theo sắc thuế, kỳ T/Q/N)    - số phát sinh, đã nộp, thừa/thiếu, cảnh báo hạn
  B4. Tự kiểm tra: người phụ trách tự ghi vấn đề và đã chỉnh sửa hay chưa
  B5. Soát xét cấp 2: người kiểm tra ghi vấn đề + hướng xử lý; người phụ trách giải trình,
      chỉnh sửa và cập nhật đã sửa xong hay chưa
  B6. Lưu trữ hồ sơ: người phụ trách cập nhật; người kiểm tra cập nhật tình trạng kiểm tra

NGUYÊN TẮC KHÓA Ô: ai được phân công thì người đó mới được điền; ô của người khác bị khóa.
Quản trị viên chỉ phân công lại người phụ trách/người kiểm tra và chỉnh hạn.

BẢO MẬT: băm PBKDF2-SHA256 + salt, khóa tài khoản sau 5 lần sai, tự đăng xuất sau 30 phút,
chính sách mật khẩu, truy vấn SQL có tham số, kiểm tra quyền phía máy chủ, nhật ký hệ thống.
"""

import base64
import calendar
import hashlib
import io
import hmac
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta

import pandas as pd
import streamlit as st

# ----------------------------------------------------------------------------
# CẤU HÌNH
# ----------------------------------------------------------------------------
COMPANY = "NEW VISION"
DB_PATH = os.environ.get("KETOAN_DB", "ketoan_dichvu.db")
SESSION_TIMEOUT_MIN = 30
MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 15
PBKDF2_ITERATIONS = 200_000
WARN_DAYS = 5  # cảnh báo "sắp đến hạn" khi còn <= số ngày này

ROLES = {
    "admin": "Quản trị viên",
    "reviewer": "Người kiểm tra",
    "staff": "Nhân viên kế toán",
}

STATUSES = [
    "Chưa thực hiện",
    "Đang xử lý",
    "Chờ kiểm tra",
    "Vướng mắc",
    "Đã hoàn thành",
    "Không phát sinh",
]
DONE_STATUSES = ("Đã hoàn thành", "Không phát sinh")
SELF_STATUSES = ["Chưa chỉnh sửa", "Đã chỉnh sửa"]
REVIEW_STATUSES = ["Chưa sửa", "Đang sửa", "Đã sửa xong"]
CHECK_STATUSES = ["Chưa kiểm tra", "Đã kiểm tra - đủ hồ sơ", "Thiếu hồ sơ - cần bổ sung"]

STEPS = ["B1", "B2", "B3", "B4", "B5", "B6"]
STEP_NAMES = {
    "B1": "B1. Hạch toán sổ sách",
    "B2": "B2. Kê khai thuế",
    "B3": "B3. Nộp tiền thuế",
    "B4": "B4. Tự kiểm tra",
    "B5": "B5. Soát xét cấp 2",
    "B6": "B6. Lưu trữ hồ sơ",
}

B1_ITEMS = [
    "Hạch toán hoá đơn đầu vào",
    "Hạch toán hoá đơn đầu ra",
    "Hạch toán sao kê ngân hàng",
    "Hạch toán lương, BHXH",
    "Tính khấu hao",
    "Tính phân bổ",
    "Các nghiệp vụ khác",
    "Tính giá thành",
    "Kết chuyển lãi lỗ",
]
B4_ITEM = "Tự kiểm tra hồ sơ kỳ"
B5_ITEM = "Soát xét cấp 2 hồ sơ kỳ"
B6_ITEM = "Lưu trữ hồ sơ kỳ"

TAX_TYPES = [
    "GTGT", "TNCN", "TNDN", "Môn bài", "Thuế nhà thầu",
    "Tiêu thụ đặc biệt", "Tài nguyên", "Bảo vệ môi trường", "Thuế khác",
]
FREQUENCIES = ["Tháng", "Quý", "Năm"]
DEFAULT_FREQ = {
    "GTGT": "Tháng", "TNCN": "Tháng", "TNDN": "Quý", "Môn bài": "Năm",
    "Thuế nhà thầu": "Tháng", "Tiêu thụ đặc biệt": "Tháng", "Tài nguyên": "Tháng",
    "Bảo vệ môi trường": "Quý", "Thuế khác": "Tháng",
}

THEME_TOML = """[theme]
primaryColor = "#1B8A4B"
backgroundColor = "#F3FAF5"
secondaryBackgroundColor = "#E3F4E8"
textColor = "#1F2D24"
font = "sans serif"
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin','reviewer','staff')),
    active INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    must_change_pw INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    tax_code TEXT DEFAULT '',
    staff_id INTEGER REFERENCES users(id),
    reviewer_id INTEGER REFERENCES users(id),
    active INTEGER NOT NULL DEFAULT 1,
    note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS client_taxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    tax_type TEXT NOT NULL,
    frequency TEXT NOT NULL,
    UNIQUE (client_id, tax_type, frequency)
);
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    period TEXT NOT NULL,
    step TEXT NOT NULL,
    sub_item TEXT NOT NULL,
    tax_type TEXT NOT NULL DEFAULT '',
    tax_period TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Chưa thực hiện',
    assignee_id INTEGER REFERENCES users(id),
    checker_id INTEGER REFERENCES users(id),
    due_date TEXT DEFAULT '',
    completed_date TEXT DEFAULT '',
    tax_amount REAL,
    paid_amount REAL,
    check_status TEXT DEFAULT 'Chưa kiểm tra',
    check_note TEXT DEFAULT '',
    note TEXT DEFAULT '',
    updated_by TEXT DEFAULT '',
    updated_at TEXT DEFAULT '',
    UNIQUE (client_id, period, step, sub_item, tax_type, tax_period)
);
CREATE TABLE IF NOT EXISTS issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('self','review')),
    client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    period TEXT NOT NULL,
    issue TEXT NOT NULL,
    solution TEXT DEFAULT '',
    checker_id INTEGER REFERENCES users(id),
    handler_id INTEGER REFERENCES users(id),
    status TEXT NOT NULL,
    explanation TEXT DEFAULT '',
    handling_note TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tasks_period ON tasks(period);
CREATE INDEX IF NOT EXISTS idx_tasks_assignee ON tasks(assignee_id);
CREATE INDEX IF NOT EXISTS idx_issues2_period ON issues(period);
"""

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Be+Vietnam+Pro:wght@400;500;600;700&display=swap');
.stApp, .stApp p, .stApp label, .stApp li, .stApp h1, .stApp h2, .stApp h3, .stApp h4,
.stApp input, .stApp textarea, .stApp button, .stMarkdown {
    font-family: 'Be Vietnam Pro', 'Segoe UI', Roboto, Arial, sans-serif;
}
.stApp { background: #F3FAF5; font-size: 16px; color: #1F2D24; }
[data-testid="stHeader"] { background: transparent; }
.block-container { padding-top: 1.6rem; max-width: 1500px; }
.stApp h1 { font-size: 2rem; font-weight: 700; color: #0F5132; }
.stApp h2 { font-size: 1.55rem; font-weight: 700; color: #14713A; }
.stApp h3 { font-size: 1.25rem; font-weight: 600; color: #14713A; }
.stApp h4 { font-size: 1.1rem; font-weight: 600; color: #1B8A4B; }
.stMarkdown p { font-size: 1rem; line-height: 1.55; }

[data-testid="stSidebar"] { background: linear-gradient(180deg, #0B3D20 0%, #14713A 100%); }
[data-testid="stSidebar"] p, [data-testid="stSidebar"] label, [data-testid="stSidebar"] span,
[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3,
[data-testid="stSidebar"] .stMarkdown, [data-testid="stSidebar"] [data-testid="stCaptionContainer"] {
    color: #FFFFFF;
}
[data-testid="stSidebar"] .stRadio label { padding: 6px 10px; border-radius: 8px; font-weight: 500; font-size: 0.95rem; }
[data-testid="stSidebar"] .stRadio label:hover { background: rgba(255,255,255,0.16); }
[data-testid="stSidebar"] .stTextInput input {
    background: rgba(255, 255, 255, 0.15);
    color: #FFFFFF !important;
    border: 1px solid rgba(255, 255, 255, 0.35);
    border-radius: 8px;
    font-size: 0.9rem;
}
[data-testid="stSidebar"] .stTextInput input::placeholder {
    color: rgba(255, 255, 255, 0.7);
}
[data-testid="stSidebar"] .stButton > button {
    width: 100%; background: rgba(255,255,255,0.14); color: #FFFFFF;
    border: 1px solid rgba(255,255,255,0.4);
}
[data-testid="stSidebar"] .stButton > button:hover { background: rgba(255,255,255,0.26); }
[data-testid="stSidebar"] hr { border-color: rgba(255,255,255,0.25); }

.stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] > button {
    background: #1B8A4B; color: #FFFFFF; border: none; border-radius: 10px;
    font-weight: 600; padding: 0.5rem 1.2rem;
}
.stButton > button:hover, .stDownloadButton > button:hover,
[data-testid="stFormSubmitButton"] > button:hover { background: #14713A; color: #FFFFFF; }
.stButton > button p, .stDownloadButton > button p,
[data-testid="stFormSubmitButton"] > button p { color: #FFFFFF; }

[data-testid="stMetric"] {
    background: #FFFFFF; border: 1px solid #CFE8D8; border-left: 6px solid #1B8A4B;
    border-radius: 12px; padding: 12px 16px; box-shadow: 0 1px 3px rgba(11,61,32,0.08);
}
[data-testid="stMetricLabel"] p { color: #4B6355; font-weight: 500; }
[data-testid="stMetricValue"] { color: #0B3D20; font-weight: 700; }

.stTabs [data-baseweb="tab-list"] { gap: 6px; border-bottom: 2px solid #CFE8D8; }
.stTabs [data-baseweb="tab"] {
    font-weight: 600; color: #14713A; padding: 10px 16px; border-radius: 10px 10px 0 0;
}
.stTabs [aria-selected="true"] { background: #E3F4E8; color: #0B3D20; }
.stTabs [data-baseweb="tab-highlight"] { background-color: #1B8A4B; }

[data-testid="stExpander"] { background: #FFFFFF; border: 1px solid #CFE8D8; border-radius: 12px; }
[data-testid="stForm"] { background: #FFFFFF; border: 1px solid #CFE8D8; border-radius: 14px; padding: 1rem; }
[data-testid="stDataFrame"] { border: 1px solid #CFE8D8; border-radius: 10px; overflow: hidden; }

.nv-hero {
    display: flex; align-items: center; gap: 22px; padding: 12px 26px; margin-bottom: 18px;
    border-radius: 16px; background: #FFFFFF; border: 1px solid #CFE8D8; border-left: 8px solid #1B8A4B;
    box-shadow: 0 3px 12px rgba(11,61,32,0.10);
}
.nv-hero img { height: 112px; width: auto; flex-shrink: 0; }
.nv-title { font-size: 1.6rem; font-weight: 800; color: #0F5132; line-height: 1.2; }
.nv-sub { font-size: 1rem; color: #4B6355; margin-top: 6px; }
.nv-sub b { color: #1B8A4B; }
.nv-login { text-align: center; background: #FFFFFF; border: 1px solid #CFE8D8; border-radius: 18px;
    padding: 18px 12px 10px 12px; margin-bottom: 14px; box-shadow: 0 3px 12px rgba(11,61,32,0.10); }
.nv-login img { width: 270px; max-width: 80%; height: auto; }
.nv-login-title { font-size: 1.15rem; font-weight: 700; color: #0F5132; margin: 4px 0 8px 0; }
.nv-side-brand { background: #FFFFFF; border-radius: 14px; padding: 8px; margin: 2px 0 12px 0; text-align: center; }
.nv-side-brand img { width: 100%; height: auto; }
</style>
"""

LOGO_B64 = (
    "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"
)
ICON_B64 = (
    "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"
)
_LOGO_SRC = "data:image/jpeg;base64," + LOGO_B64
HERO_HTML = (
    '<div class="nv-hero"><img src="' + _LOGO_SRC + '" alt="NEW VISION">'
    '<div><div class="nv-title">Hệ thống quản lý công việc kế toán</div>'
    '<div class="nv-sub"><b>Kế toán - Thuế - Tư vấn</b> &middot; Đồng hành cùng doanh nghiệp</div></div></div>'
)
LOGIN_HTML = (
    '<div class="nv-login"><img src="' + _LOGO_SRC + '" alt="NEW VISION">'
    '<div class="nv-login-title">Hệ thống quản lý công việc kế toán</div></div>'
)
SIDE_BRAND_HTML = '<div class="nv-side-brand"><img src="' + _LOGO_SRC + '" alt="NEW VISION"></div>'


def load_page_icon():
    try:
        from PIL import Image
        return Image.open(io.BytesIO(base64.b64decode(ICON_B64)))
    except Exception:  # noqa: BLE001
        return "🌿"


# ----------------------------------------------------------------------------
# CƠ SỞ DỮ LIỆU
# ----------------------------------------------------------------------------
@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_action(username, action, detail=""):
    with get_db() as db:
        db.execute(
            "INSERT INTO audit_log (ts, username, action, detail) VALUES (?,?,?,?)",
            (now_str(), username, action, detail),
        )


def update_row(db, table, row_id, changes):
    """Tên bảng và tên cột chỉ lấy từ hằng số trong mã nguồn; giá trị luôn dùng tham số."""
    cols = ", ".join(f"{k}=?" for k in changes)
    db.execute(f"UPDATE {table} SET {cols} WHERE id=?", (*changes.values(), row_id))


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.close()
    with get_db() as db:
        had_tasks = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='tasks'"
        ).fetchone() is not None
        db.executescript(SCHEMA)
        if had_tasks:
            cols = [r["name"] for r in db.execute("PRAGMA table_info(tasks)").fetchall()]
            if "completed_date" not in cols:
                # Nâng cấp từ phiên bản cũ (B1-B5) lên phiên bản mới (B1-B6)
                for ddl in (
                    "ALTER TABLE tasks ADD COLUMN checker_id INTEGER REFERENCES users(id)",
                    "ALTER TABLE tasks ADD COLUMN completed_date TEXT DEFAULT ''",
                    "ALTER TABLE tasks ADD COLUMN tax_amount REAL",
                    "ALTER TABLE tasks ADD COLUMN paid_amount REAL",
                    "ALTER TABLE tasks ADD COLUMN check_status TEXT DEFAULT 'Chưa kiểm tra'",
                    "ALTER TABLE tasks ADD COLUMN check_note TEXT DEFAULT ''",
                ):
                    db.execute(ddl)
                db.execute("DELETE FROM tasks WHERE step IN ('B4','B5')")
                db.execute("DROP TABLE IF EXISTS b4_issues")
        count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            pw = os.environ.get("ADMIN_INITIAL_PASSWORD", "Admin@123")
            h, s = hash_password(pw)
            db.execute(
                "INSERT INTO users (username, full_name, password_hash, salt, role, "
                "active, must_change_pw, created_at) VALUES (?,?,?,?,?,?,?,?)",
                ("admin", "Quản trị viên", h, s, "admin", 1, 1, now_str()),
            )


def ensure_theme_config():
    path = os.path.join(".streamlit", "config.toml")
    if os.path.exists(path):
        return
    try:
        os.makedirs(".streamlit", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(THEME_TOML)
    except OSError:
        pass


@st.cache_resource
def init_once():
    init_db()
    ensure_theme_config()
    return True


# ----------------------------------------------------------------------------
# MẬT KHẨU & XÁC THỰC
# ----------------------------------------------------------------------------
def hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return digest.hex(), salt.hex()


def verify_password(password, hash_hex, salt_hex):
    calc, _ = hash_password(password, salt_hex)
    return hmac.compare_digest(calc, hash_hex)


def password_error(pw):
    if len(pw) < 8:
        return "Mật khẩu phải có ít nhất 8 ký tự."
    if not re.search(r"[A-Z]", pw):
        return "Mật khẩu phải có ít nhất một chữ hoa."
    if not re.search(r"[a-z]", pw):
        return "Mật khẩu phải có ít nhất một chữ thường."
    if not re.search(r"[0-9]", pw):
        return "Mật khẩu phải có ít nhất một chữ số."
    return None


def authenticate(username, password):
    username = username.strip().lower()
    with get_db() as db:
        u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if u is None:
            hash_password(password)  # cân bằng thời gian xử lý
            return None, "Sai tên đăng nhập hoặc mật khẩu."
        if not u["active"]:
            return None, "Tài khoản đã bị vô hiệu hóa. Vui lòng liên hệ quản trị viên."
        if u["locked_until"]:
            until = datetime.fromisoformat(u["locked_until"])
            if until > datetime.now():
                return None, f"Tài khoản tạm khóa đến {until.strftime('%H:%M %d/%m/%Y')}."
        if verify_password(password, u["password_hash"], u["salt"]):
            db.execute(
                "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (u["id"],)
            )
            return dict(u), None
        fails = u["failed_attempts"] + 1
        if fails >= MAX_FAILED_ATTEMPTS:
            until = (datetime.now() + timedelta(minutes=LOCK_MINUTES)).isoformat()
            db.execute(
                "UPDATE users SET failed_attempts=0, locked_until=? WHERE id=?", (until, u["id"])
            )
            return None, f"Sai mật khẩu quá {MAX_FAILED_ATTEMPTS} lần. Tài khoản bị khóa {LOCK_MINUTES} phút."
        db.execute("UPDATE users SET failed_attempts=? WHERE id=?", (fails, u["id"]))
        return None, f"Sai tên đăng nhập hoặc mật khẩu. (Còn {MAX_FAILED_ATTEMPTS - fails} lần thử)"


def logout(message=None):
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    if message:
        st.session_state["login_msg"] = message


def current_user():
    uid = st.session_state.get("uid")
    if uid is None:
        return None
    last = st.session_state.get("last_active")
    if last and (datetime.now() - last) > timedelta(minutes=SESSION_TIMEOUT_MIN):
        logout("Phiên làm việc đã hết hạn do không hoạt động. Vui lòng đăng nhập lại.")
        return None
    with get_db() as db:
        u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if u is None or not u["active"]:
        logout("Tài khoản không còn hiệu lực.")
        return None
    st.session_state["last_active"] = datetime.now()
    return dict(u)


# ----------------------------------------------------------------------------
# TIỆN ÍCH CHUNG
# ----------------------------------------------------------------------------
_WIDTH_MODE = {"mode": None}


def full_width_call(fn, *args, **kwargs):
    """Gọi st.dataframe / st.data_editor giãn hết chiều ngang, tương thích mọi phiên bản Streamlit."""
    options = [{"width": "stretch"}, {"use_container_width": True}]
    if _WIDTH_MODE["mode"] is not None:
        options = [options[_WIDTH_MODE["mode"]]]
    last = None
    for i, extra in enumerate(options):
        try:
            result = fn(*args, **kwargs, **extra)
            if _WIDTH_MODE["mode"] is None:
                _WIDTH_MODE["mode"] = 0 if "width" in extra else 1
            return result
        except Exception as exc:  # noqa: BLE001
            last = exc
    raise last


def flash(kind, msg):
    st.session_state["flash"] = (kind, msg)


def show_flash():
    f = st.session_state.pop("flash", None)
    if f:
        getattr(st, f[0])(f[1])


def ver():
    return st.session_state.setdefault("ver", 0)


def bump_ver():
    st.session_state["ver"] = ver() + 1


def clean_text(v):
    if v is None:
        return ""
    try:
        if pd.isna(v):
            return ""
    except (TypeError, ValueError):
        pass
    return str(v).strip()


def to_iso(v):
    if v is None:
        return ""
    try:
        if pd.isna(v):
            return ""
    except (TypeError, ValueError):
        pass
    if hasattr(v, "isoformat"):
        return v.isoformat()[:10]
    return str(v)[:10]


def to_num(v):
    try:
        if v is None or pd.isna(v):
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


def fmt_vnd(x):
    return f"{x:,.0f}".replace(",", ".")


def date_series(values):
    out = []
    for v in values:
        s = clean_text(v)[:10]
        try:
            out.append(date.fromisoformat(s) if s else None)
        except ValueError:
            out.append(None)
    return pd.Series(out, index=values.index, dtype="object")


def add_month(y, m, n):
    t = y * 12 + (m - 1) + n
    return t // 12, t % 12 + 1


def last_day(y, m):
    return calendar.monthrange(y, m)[1]


def period_str(y, m):
    return f"{y:04d}-{m:02d}"


def period_label(p):
    return f"Tháng {p[5:7]}/{p[:4]}"


def is_admin(u):
    return u["role"] == "admin"


def is_privileged(u):
    return u["role"] in ("admin", "reviewer")


def user_label(u):
    return f"{u['full_name']} ({u['username']})"


def load_users(active_only=False):
    sql = "SELECT * FROM users"
    if active_only:
        sql += " WHERE active=1"
    sql += " ORDER BY full_name"
    with get_db() as db:
        return [dict(r) for r in db.execute(sql).fetchall()]


def load_clients(active_only=False):
    sql = (
        "SELECT c.*, s.full_name AS staff_name, r.full_name AS reviewer_name "
        "FROM clients c LEFT JOIN users s ON s.id=c.staff_id "
        "LEFT JOIN users r ON r.id=c.reviewer_id"
    )
    if active_only:
        sql += " WHERE c.active=1"
    sql += " ORDER BY c.code"
    with get_db() as db:
        return [dict(r) for r in db.execute(sql).fetchall()]


def client_label(c):
    return f"{c['code']} - {c['name']}"


def period_selector(key):
    today = date.today()
    py, pm = add_month(today.year, today.month, -1)
    with get_db() as db:
        rows = db.execute("SELECT DISTINCT period FROM tasks").fetchall()
    options = {r["period"] for r in rows}
    options |= {period_str(today.year, today.month), period_str(py, pm)}
    options = sorted(options, reverse=True)
    default = period_str(py, pm)
    return st.selectbox(
        "Kỳ làm việc (tháng hạch toán)",
        options,
        index=options.index(default),
        format_func=period_label,
        key=f"period_{key}",
    )


# ----------------------------------------------------------------------------
# CẢNH BÁO HẠN & TÍNH THỪA/THIẾU THUẾ
# ----------------------------------------------------------------------------
def deadline_info(due, status):
    """Trả về (nội dung cảnh báo, mức: done/late/soon/ok/none)."""
    if status in DONE_STATUSES:
        return "✅ Đã xong", "done"
    try:
        d = date.fromisoformat(clean_text(due)[:10])
    except ValueError:
        return "—", "none"
    delta = (d - date.today()).days
    if delta < 0:
        return f"🔴 Trễ hạn {-delta} ngày", "late"
    if delta == 0:
        return "🟠 Đến hạn hôm nay", "soon"
    if delta <= WARN_DAYS:
        return f"🟠 Sắp đến hạn (còn {delta} ngày)", "soon"
    return f"🟢 Còn {delta} ngày", "ok"


def settlement(amount, paid):
    """Trả về (chênh lệch = đã nộp - phát sinh, kết luận)."""
    a, p = to_num(amount), to_num(paid)
    if a is None and p is None:
        return None, ""
    a0, p0 = a or 0.0, p or 0.0
    d = p0 - a0
    if a0 == 0 and p0 == 0:
        return 0.0, "Không phát sinh"
    if d == 0:
        return 0.0, "Đã nộp đủ"
    if d > 0:
        return d, f"Nộp thừa {fmt_vnd(d)}"
    return d, f"Nộp thiếu {fmt_vnd(-d)}"


def alert_rows(user):
    limit = (date.today() + timedelta(days=WARN_DAYS)).isoformat()
    sql = (
        "SELECT t.*, c.code AS client_code, c.name AS client_name, u.full_name AS assignee_name "
        "FROM tasks t JOIN clients c ON c.id=t.client_id "
        "LEFT JOIN users u ON u.id=t.assignee_id "
        "WHERE t.step IN ('B2','B3') AND c.active=1 "
        "AND t.status NOT IN ('Đã hoàn thành','Không phát sinh') "
        "AND t.due_date<>'' AND t.due_date<=?"
    )
    params = [limit]
    if not is_privileged(user):
        sql += " AND t.assignee_id=?"
        params.append(user["id"])
    sql += " ORDER BY t.due_date, c.code"
    with get_db() as db:
        return [dict(r) for r in db.execute(sql, params).fetchall()]


def render_alerts(user):
    rows = alert_rows(user)
    st.subheader("⏰ Cảnh báo hạn kê khai và nộp thuế (B2, B3)")
    if not rows:
        st.success(f"Không có việc B2/B3 nào trễ hạn hoặc sắp đến hạn (trong {WARN_DAYS} ngày tới).")
        return
    late = sum(1 for r in rows if deadline_info(r["due_date"], r["status"])[1] == "late")
    c1, c2 = st.columns(2)
    c1.metric("🔴 Trễ hạn", late)
    c2.metric("🟠 Sắp đến hạn", len(rows) - late)
    out = pd.DataFrame(
        {
            "Cảnh báo": [deadline_info(r["due_date"], r["status"])[0] for r in rows],
            "Khách hàng": [f"{r['client_code']} - {r['client_name']}" for r in rows],
            "Bước": [STEP_NAMES[r["step"]] for r in rows],
            "Hạng mục": [r["sub_item"] for r in rows],
            "Kỳ kê khai": [r["tax_period"] for r in rows],
            "Hạn": [r["due_date"] for r in rows],
            "Trạng thái": [r["status"] for r in rows],
            "Người phụ trách": [r["assignee_name"] or "" for r in rows],
        }
    )
    full_width_call(st.dataframe, out, hide_index=True)


def alert_banner(sdf):
    late = soon = 0
    for due, status in zip(sdf["due_date"], sdf["status"]):
        level = deadline_info(due, status)[1]
        if level == "late":
            late += 1
        elif level == "soon":
            soon += 1
    if late:
        st.error(f"🔴 Có {late} việc đã trễ hạn.")
    if soon:
        st.warning(f"🟠 Có {soon} việc sắp đến hạn (trong {WARN_DAYS} ngày tới).")
    if not late and not soon and not sdf.empty:
        st.success("🟢 Không có việc trễ hạn hoặc sắp đến hạn.")


# ----------------------------------------------------------------------------
# TỰ ĐỘNG SINH VIỆC
# ----------------------------------------------------------------------------
def freq_applies(freq, month):
    if freq == "Tháng":
        return True
    if freq == "Quý":
        return month % 3 == 0
    if freq == "Năm":
        return month == 12
    return False


def tax_period_label(freq, y, m):
    if freq == "Tháng":
        return f"Tháng {m:02d}/{y}"
    if freq == "Quý":
        return f"Quý {(m - 1) // 3 + 1}/{y}"
    return f"Năm {y}"


def due_date_for(step, tax_type, freq, y, m):
    ny, nm = add_month(y, m, 1)
    if step == "B1":
        return date(ny, nm, 10)
    if step in ("B2", "B3"):
        if freq == "Tháng":
            return date(ny, nm, 20)
        if freq == "Quý":
            return date(ny, nm, last_day(ny, nm))
        if tax_type == "Môn bài":
            return date(y + 1, 1, 30)
        return date(y + 1, 3, 31)
    if step == "B4":
        return date(ny, nm, 15)
    if step == "B5":
        return date(ny, nm, 25)
    return date(ny, nm, last_day(ny, nm))


def generate_tasks(year, month, actor):
    """Sinh việc cho mọi khách hàng đang hoạt động. Không tạo trùng. Trả về số việc mới."""
    period = period_str(year, month)
    inserted = 0
    with get_db() as db:
        clients = db.execute("SELECT * FROM clients WHERE active=1").fetchall()
        for c in clients:
            staff, reviewer = c["staff_id"], c["reviewer_id"]
            taxes = db.execute(
                "SELECT tax_type, frequency FROM client_taxes WHERE client_id=?", (c["id"],)
            ).fetchall()
            rows = []  # (step, sub_item, tax_type, tax_period, assignee, checker, due)
            d1 = due_date_for("B1", "", "", year, month).isoformat()
            for item in B1_ITEMS:
                rows.append(("B1", item, "", "", staff, None, d1))
            for t in taxes:
                if not freq_applies(t["frequency"], month):
                    continue
                label = tax_period_label(t["frequency"], year, month)
                due2 = due_date_for("B2", t["tax_type"], t["frequency"], year, month).isoformat()
                due3 = due_date_for("B3", t["tax_type"], t["frequency"], year, month).isoformat()
                rows.append(("B2", f"Kê khai thuế {t['tax_type']}", t["tax_type"], label, staff, None, due2))
                rows.append(("B3", f"Nộp tiền thuế {t['tax_type']}", t["tax_type"], label, staff, None, due3))
            rows.append(("B4", B4_ITEM, "", "", staff, None, due_date_for("B4", "", "", year, month).isoformat()))
            rows.append(("B5", B5_ITEM, "", "", reviewer, None, due_date_for("B5", "", "", year, month).isoformat()))
            rows.append(("B6", B6_ITEM, "", "", staff, reviewer, due_date_for("B6", "", "", year, month).isoformat()))
            for step, sub, tax, tperiod, assignee, checker, due in rows:
                cur = db.execute(
                    "INSERT OR IGNORE INTO tasks (client_id, period, step, sub_item, tax_type, tax_period, "
                    "status, assignee_id, checker_id, due_date, updated_by, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (c["id"], period, step, sub, tax, tperiod, "Chưa thực hiện",
                     assignee, checker, due, actor, now_str()),
                )
                inserted += cur.rowcount
    if inserted:
        log_action(actor, "SINH_VIEC", f"Kỳ {period}: thêm {inserted} đầu việc")
    return inserted


def auto_generate_recent(actor):
    today = date.today()
    py, pm = add_month(today.year, today.month, -1)
    generate_tasks(py, pm, actor)
    generate_tasks(today.year, today.month, actor)


def sync_assignees(period, actor):
    """Cập nhật người phụ trách/người kiểm tra các việc chưa hoàn thành theo cấu hình khách hàng."""
    with get_db() as db:
        cur = db.execute(
            "UPDATE tasks SET "
            "assignee_id = CASE WHEN step='B5' "
            "  THEN (SELECT reviewer_id FROM clients WHERE id=tasks.client_id) "
            "  ELSE (SELECT staff_id FROM clients WHERE id=tasks.client_id) END, "
            "checker_id = CASE WHEN step='B6' "
            "  THEN (SELECT reviewer_id FROM clients WHERE id=tasks.client_id) ELSE checker_id END, "
            "updated_by=?, updated_at=? "
            "WHERE period=? AND status NOT IN ('Đã hoàn thành','Không phát sinh')",
            (actor, now_str(), period),
        )
        n = cur.rowcount
    log_action(actor, "DONG_BO_NGUOI_PHU_TRACH", f"Kỳ {period}: {n} việc")
    return n


# ----------------------------------------------------------------------------
# CÔNG VIỆC (B1 - B6): TRUY VẤN, BẢNG NHẬP, LƯU
# ----------------------------------------------------------------------------
TASK_COLS = [
    "id", "client_id", "period", "step", "sub_item", "tax_type", "tax_period", "status",
    "assignee_id", "checker_id", "due_date", "completed_date", "tax_amount", "paid_amount",
    "check_status", "check_note", "note", "updated_by", "updated_at", "client_code", "client_name",
]


def load_tasks(user, period, client_ids=None, statuses=None, assignee_id=None):
    sql = (
        "SELECT t.*, c.code AS client_code, c.name AS client_name "
        "FROM tasks t JOIN clients c ON c.id=t.client_id WHERE t.period=?"
    )
    params = [period]
    if not is_privileged(user):
        sql += " AND (t.assignee_id=? OR t.checker_id=?)"
        params += [user["id"], user["id"]]
    elif assignee_id:
        sql += " AND t.assignee_id=?"
        params.append(assignee_id)
    if client_ids:
        sql += " AND t.client_id IN (%s)" % ",".join("?" * len(client_ids))
        params.extend(client_ids)
    if statuses:
        sql += " AND t.status IN (%s)" % ",".join("?" * len(statuses))
        params.extend(statuses)
    sql += " ORDER BY c.code, t.step, t.id"
    with get_db() as db:
        rows = [dict(r) for r in db.execute(sql, params).fetchall()]
    return pd.DataFrame(rows, columns=TASK_COLS)


def build_task_view(sdf, labels):
    amt = pd.to_numeric(sdf["tax_amount"], errors="coerce")
    paid = pd.to_numeric(sdf["paid_amount"], errors="coerce")
    diffs, concl = [], []
    for a, p in zip(amt, paid):
        d, c = settlement(a, p)
        diffs.append(d)
        concl.append(c)
    return pd.DataFrame(
        {
            "ID": sdf["id"].astype(int),
            "Khách hàng": sdf["client_code"] + " - " + sdf["client_name"],
            "Hạng mục": sdf["sub_item"],
            "Sắc thuế": sdf["tax_type"],
            "Kỳ kê khai": sdf["tax_period"],
            "Người phụ trách": sdf["assignee_id"].map(labels).fillna(""),
            "Người kiểm tra": sdf["checker_id"].map(labels).fillna(""),
            "Hạn": date_series(sdf["due_date"]),
            "Cảnh báo": [deadline_info(d, s)[0] for d, s in zip(sdf["due_date"], sdf["status"])],
            "Ngày hoàn thành": date_series(sdf["completed_date"]),
            "Số thuế phát sinh": amt,
            "Số đã nộp": paid,
            "Nộp thừa/(thiếu)": diffs,
            "Kết luận": concl,
            "Trạng thái": sdf["status"],
            "Ghi chú": sdf["note"].fillna(""),
            "Tình trạng kiểm tra": sdf["check_status"].fillna("Chưa kiểm tra"),
            "Ghi chú kiểm tra": sdf["check_note"].fillna(""),
        }
    )


def column_order(step, mode):
    base = ["ID", "Khách hàng", "Hạng mục"]
    if step in ("B2", "B3"):
        base += ["Sắc thuế", "Kỳ kê khai"]
    if mode == "admin":
        order = base + ["Người phụ trách"]
        if step == "B6":
            order += ["Người kiểm tra"]
        return order + ["Hạn", "Trạng thái"]
    if mode == "check":
        return ["ID", "Khách hàng", "Hạng mục", "Người phụ trách", "Trạng thái",
                "Tình trạng kiểm tra", "Ghi chú kiểm tra"]
    order = base + ["Người phụ trách", "Hạn"]
    if step in ("B2", "B3"):
        order += ["Cảnh báo"]
    if step in ("B1", "B2"):
        order += ["Ngày hoàn thành"]
    if step == "B3":
        order += ["Số thuế phát sinh", "Số đã nộp", "Nộp thừa/(thiếu)", "Kết luận"]
    order += ["Trạng thái", "Ghi chú"]
    if step == "B6":
        order += ["Người kiểm tra", "Tình trạng kiểm tra", "Ghi chú kiểm tra"]
    return order


def editable_cols(step, mode):
    if mode == "work":
        s = {"Trạng thái", "Ghi chú"}
        if step in ("B1", "B2"):
            s.add("Ngày hoàn thành")
        if step == "B3":
            s |= {"Số thuế phát sinh", "Số đã nộp"}
        return s
    if mode == "check":
        return {"Tình trạng kiểm tra", "Ghi chú kiểm tra"}
    if mode == "admin":
        s = {"Người phụ trách", "Hạn"}
        if step == "B6":
            s.add("Người kiểm tra")
        return s
    return set()


def task_column_config(labels):
    opts = [""] + list(labels.values())
    cc = st.column_config
    return {
        "ID": cc.NumberColumn("ID", width="small"),
        "Người phụ trách": cc.SelectboxColumn("Người phụ trách", options=opts, required=False),
        "Người kiểm tra": cc.SelectboxColumn("Người kiểm tra", options=opts, required=False),
        "Hạn": cc.DateColumn("Hạn", format="DD/MM/YYYY"),
        "Ngày hoàn thành": cc.DateColumn("Ngày hoàn thành", format="DD/MM/YYYY"),
        "Số thuế phát sinh": cc.NumberColumn("Số thuế phát sinh (VNĐ)", min_value=0, format="%.0f"),
        "Số đã nộp": cc.NumberColumn("Số đã nộp (VNĐ)", min_value=0, format="%.0f"),
        "Nộp thừa/(thiếu)": cc.NumberColumn("Nộp thừa/(thiếu) (VNĐ)", format="%.0f"),
        "Trạng thái": cc.SelectboxColumn("Trạng thái", options=STATUSES, required=True),
        "Ghi chú": cc.TextColumn("Ghi chú", max_chars=500),
        "Tình trạng kiểm tra": cc.SelectboxColumn("Tình trạng kiểm tra", options=CHECK_STATUSES, required=True),
        "Ghi chú kiểm tra": cc.TextColumn("Ghi chú kiểm tra", max_chars=500),
    }


def completion_blocker(db, t):
    """Điều kiện để một việc B4/B5 được đánh dấu 'Đã hoàn thành'."""
    if t["step"] == "B4":
        n = db.execute(
            "SELECT COUNT(*) FROM issues WHERE kind='self' AND client_id=? AND period=? AND status<>'Đã chỉnh sửa'",
            (t["client_id"], t["period"]),
        ).fetchone()[0]
        if n:
            return f"còn {n} vấn đề tự kiểm tra chưa chỉnh sửa."
    if t["step"] == "B5":
        n = db.execute(
            "SELECT COUNT(*) FROM issues WHERE kind='review' AND client_id=? AND period=? AND status<>'Đã sửa xong'",
            (t["client_id"], t["period"]),
        ).fetchone()[0]
        if n:
            return f"còn {n} vấn đề soát xét chưa được sửa xong."
        b4 = db.execute(
            "SELECT COUNT(*) FROM tasks WHERE client_id=? AND period=? AND step='B4' "
            "AND status NOT IN ('Đã hoàn thành','Không phát sinh')",
            (t["client_id"], t["period"]),
        ).fetchone()[0]
        if b4:
            return "bước B4 (Tự kiểm tra) của khách hàng này chưa hoàn thành."
    return None


def save_task_changes(user, step, mode, original, edited, label_to_id):
    ok, errors = 0, []
    with get_db() as db:
        for idx in original.index:
            o, e = original.loc[idx], edited.loc[idx]
            tid = int(o["ID"])
            t = db.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()
            if t is None:
                continue
            changes = {}
            if mode == "work":
                new = clean_text(e["Trạng thái"])
                if new != clean_text(o["Trạng thái"]):
                    changes["status"] = new
                new = clean_text(e["Ghi chú"])
                if new != clean_text(o["Ghi chú"]):
                    changes["note"] = new
                if step in ("B1", "B2"):
                    new = to_iso(e["Ngày hoàn thành"])
                    if new != to_iso(o["Ngày hoàn thành"]):
                        changes["completed_date"] = new
                if step == "B3":
                    for col, field in (("Số thuế phát sinh", "tax_amount"), ("Số đã nộp", "paid_amount")):
                        nv, ov = to_num(e[col]), to_num(o[col])
                        if nv != ov:
                            if nv is not None and nv < 0:
                                errors.append(f"Việc #{tid}: {col} không được âm.")
                                changes = {}
                                break
                            changes[field] = nv
                allowed = t["assignee_id"] == user["id"]
            elif mode == "check":
                new = clean_text(e["Tình trạng kiểm tra"])
                if new != clean_text(o["Tình trạng kiểm tra"]):
                    if new in CHECK_STATUSES:
                        changes["check_status"] = new
                new = clean_text(e["Ghi chú kiểm tra"])
                if new != clean_text(o["Ghi chú kiểm tra"]):
                    changes["check_note"] = new
                allowed = step == "B6" and t["checker_id"] == user["id"]
            elif mode == "admin":
                nl, ol = clean_text(e["Người phụ trách"]), clean_text(o["Người phụ trách"])
                if nl != ol:
                    if nl == "":
                        changes["assignee_id"] = None
                    elif nl in label_to_id:
                        changes["assignee_id"] = label_to_id[nl]
                if step == "B6":
                    nl, ol = clean_text(e["Người kiểm tra"]), clean_text(o["Người kiểm tra"])
                    if nl != ol:
                        if nl == "":
                            changes["checker_id"] = None
                        elif nl in label_to_id:
                            changes["checker_id"] = label_to_id[nl]
                nd, od = to_iso(e["Hạn"]), to_iso(o["Hạn"])
                if nd != od:
                    changes["due_date"] = nd
                allowed = is_admin(user)
            else:
                continue
            if not changes:
                continue
            if not allowed:
                errors.append(f"Việc #{tid} ({t['sub_item']}): bạn không được phân công nên không có quyền điền ô này.")
                continue
            if "status" in changes:
                if changes["status"] not in STATUSES:
                    errors.append(f"Việc #{tid}: trạng thái không hợp lệ.")
                    continue
                if changes["status"] == "Đã hoàn thành":
                    blocker = completion_blocker(db, t)
                    if blocker:
                        errors.append(f"Việc #{tid} ({STEP_NAMES[step]}): chưa thể hoàn thành vì {blocker}")
                        continue
            changes["updated_by"] = user["username"]
            changes["updated_at"] = now_str()
            update_row(db, "tasks", tid, changes)
            ok += 1
    if ok:
        log_action(user["username"], "CAP_NHAT_VIEC", f"{STEP_NAMES[step]} ({mode}): {ok} đầu việc")
    return ok, errors


def task_grid(user, df, step, mode, key):
    labels = {u["id"]: user_label(u) for u in load_users()}
    label_to_id = {v: k for k, v in labels.items()}
    view = build_task_view(df.reset_index(drop=True), labels)
    order = column_order(step, mode)
    cfg = task_column_config(labels)
    if mode == "readonly":
        full_width_call(st.dataframe, view[order], hide_index=True, column_config=cfg)
        return
    editable = editable_cols(step, mode)
    disabled = [c for c in order if c not in editable]
    edited = full_width_call(
        st.data_editor,
        view,
        key=f"ed_{key}_{mode}_{ver()}",
        hide_index=True,
        num_rows="fixed",
        disabled=disabled,
        column_order=order,
        column_config=cfg,
    )
    caption = {"work": "💾 Lưu cập nhật công việc", "check": "💾 Lưu kết quả kiểm tra",
               "admin": "💾 Lưu phân công"}[mode]
    if st.button(caption, key=f"save_{key}_{mode}_{ver()}"):
        ok, errors = save_task_changes(user, step, mode, view, edited, label_to_id)
        if errors:
            flash("warning", f"Đã lưu {ok} việc. Cần lưu ý:\n\n" + "\n\n".join(errors))
        elif ok:
            flash("success", f"Đã lưu {ok} đầu việc.")
        else:
            flash("info", "Không có thay đổi nào để lưu.")
        bump_ver()
        st.rerun()


def b3_summary(sdf):
    amt = pd.to_numeric(sdf["tax_amount"], errors="coerce").fillna(0.0)
    paid = pd.to_numeric(sdf["paid_amount"], errors="coerce").fillna(0.0)
    diff = paid - amt
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Tổng thuế phát sinh", fmt_vnd(amt.sum()))
    c2.metric("Tổng đã nộp", fmt_vnd(paid.sum()))
    c3.metric("Nộp thừa", fmt_vnd(diff[diff > 0].sum()))
    c4.metric("Nộp thiếu", fmt_vnd(-diff[diff < 0].sum()))


def render_step(user, step, sdf, period, client_ids, filt_key):
    uid = user["id"]
    if sdf.empty:
        st.info("Không có công việc nào ở bước này.")
    else:
        done = int(sdf["status"].isin(DONE_STATUSES).sum())
        st.progress(done / len(sdf), text=f"Hoàn thành {done}/{len(sdf)} việc")
        if step in ("B2", "B3"):
            alert_banner(sdf)
        if step == "B3":
            b3_summary(sdf)
    captions = {
        "B1": "Người phụ trách tự điền **Ngày hoàn thành** khi xong từng bước hạch toán.",
        "B2": "Theo dõi từng sắc thuế và kỳ kê khai (tháng/quý/năm). Người phụ trách điền ngày hoàn thành.",
        "B3": "Nhập số thuế phát sinh và số đã nộp; hệ thống tự tính nộp thừa/(thiếu).",
        "B4": "Người phụ trách tự kiểm tra, ghi vấn đề phát hiện và đánh dấu đã chỉnh sửa hay chưa.",
        "B5": "Người kiểm tra ghi vấn đề và hướng xử lý; người phụ trách giải trình, sửa và cập nhật tình trạng.",
        "B6": "Người phụ trách cập nhật việc lưu trữ; người kiểm tra cập nhật tình trạng kiểm tra hồ sơ.",
    }
    st.caption(captions[step])

    if not sdf.empty:
        st.markdown("**✏️ Việc của tôi (được phép cập nhật)**")
        mine = sdf[sdf["assignee_id"] == uid]
        if mine.empty:
            st.caption("Bạn không được phân công việc nào ở bước này.")
        else:
            task_grid(user, mine, step, "work", f"{step}_{filt_key}")
        if step == "B6":
            checks = sdf[sdf["checker_id"] == uid]
            if not checks.empty:
                st.markdown("**🔎 Kiểm tra lưu trữ (tôi là người kiểm tra)**")
                task_grid(user, checks, step, "check", f"{step}_{filt_key}")
        if is_privileged(user):
            others = sdf[sdf["assignee_id"] != uid]
            if not others.empty:
                with st.expander("👁️ Việc của người khác (chỉ xem, ô bị khóa)"):
                    task_grid(user, others, step, "readonly", f"{step}_{filt_key}")
        if is_admin(user):
            with st.expander("🛠️ Quản trị: phân công người phụ trách và chỉnh hạn"):
                task_grid(user, sdf, step, "admin", f"{step}_{filt_key}")
    if step == "B4":
        st.divider()
        render_issues(user, period, client_ids, "self")
    if step == "B5":
        st.divider()
        render_issues(user, period, client_ids, "review")


# ----------------------------------------------------------------------------
# VẤN ĐỀ KIỂM TRA: B4 (tự kiểm tra) VÀ B5 (soát xét cấp 2)
# ----------------------------------------------------------------------------
ISSUE_COLS = [
    "id", "kind", "client_id", "period", "issue", "solution", "checker_id", "handler_id",
    "status", "explanation", "handling_note", "created_at", "updated_at",
    "client_code", "client_name",
]
ISSUE_EDIT = {
    ("self", "owner"): {"Vấn đề phát hiện", "Tình trạng chỉnh sửa", "Ghi chú chỉnh sửa", "Xóa"},
    ("self", "admin"): {"Xóa"},
    ("review", "author"): {"Vấn đề phát hiện", "Hướng xử lý", "NV phụ trách", "Xóa"},
    ("review", "handler"): {"Giải trình sai sót", "Tình trạng sửa", "Kết quả chỉnh sửa"},
    ("review", "admin"): {"NV phụ trách", "Xóa"},
}


def issue_order(kind):
    if kind == "self":
        return ["ID", "Khách hàng", "Người tự kiểm tra", "Vấn đề phát hiện",
                "Tình trạng chỉnh sửa", "Ghi chú chỉnh sửa", "Xóa"]
    return ["ID", "Khách hàng", "Người kiểm tra", "Vấn đề phát hiện", "Hướng xử lý", "NV phụ trách",
            "Giải trình sai sót", "Tình trạng sửa", "Kết quả chỉnh sửa", "Xóa"]


def load_issues(user, kind, period, client_ids):
    sql = (
        "SELECT i.*, c.code AS client_code, c.name AS client_name "
        "FROM issues i JOIN clients c ON c.id=i.client_id WHERE i.kind=? AND i.period=?"
    )
    params = [kind, period]
    if client_ids:
        sql += " AND i.client_id IN (%s)" % ",".join("?" * len(client_ids))
        params.extend(client_ids)
    if not is_privileged(user):
        sql += " AND (i.handler_id=? OR i.checker_id=?)"
        params += [user["id"], user["id"]]
    sql += " ORDER BY c.code, i.id"
    with get_db() as db:
        rows = [dict(r) for r in db.execute(sql, params).fetchall()]
    return pd.DataFrame(rows, columns=ISSUE_COLS)


def issue_view(df, kind, labels):
    base = {
        "ID": df["id"].astype(int),
        "Khách hàng": df["client_code"] + " - " + df["client_name"],
        "Vấn đề phát hiện": df["issue"],
        "Xóa": False,
    }
    if kind == "self":
        base.update(
            {
                "Người tự kiểm tra": df["checker_id"].map(labels).fillna(""),
                "Tình trạng chỉnh sửa": df["status"],
                "Ghi chú chỉnh sửa": df["handling_note"].fillna(""),
            }
        )
    else:
        base.update(
            {
                "Người kiểm tra": df["checker_id"].map(labels).fillna(""),
                "Hướng xử lý": df["solution"].fillna(""),
                "NV phụ trách": df["handler_id"].map(labels).fillna(""),
                "Giải trình sai sót": df["explanation"].fillna(""),
                "Tình trạng sửa": df["status"],
                "Kết quả chỉnh sửa": df["handling_note"].fillna(""),
            }
        )
    return pd.DataFrame(base)


def issue_config(labels):
    cc = st.column_config
    return {
        "ID": cc.NumberColumn("ID", width="small"),
        "Vấn đề phát hiện": cc.TextColumn("Vấn đề phát hiện", max_chars=1000),
        "Tình trạng chỉnh sửa": cc.SelectboxColumn("Tình trạng chỉnh sửa", options=SELF_STATUSES, required=True),
        "Ghi chú chỉnh sửa": cc.TextColumn("Ghi chú chỉnh sửa", max_chars=1000),
        "Hướng xử lý": cc.TextColumn("Hướng xử lý", max_chars=1000),
        "NV phụ trách": cc.SelectboxColumn("NV phụ trách", options=[""] + list(labels.values()), required=False),
        "Giải trình sai sót": cc.TextColumn("Giải trình sai sót", max_chars=1000),
        "Tình trạng sửa": cc.SelectboxColumn("Tình trạng sửa", options=REVIEW_STATUSES, required=True),
        "Kết quả chỉnh sửa": cc.TextColumn("Kết quả chỉnh sửa", max_chars=1000),
        "Xóa": cc.CheckboxColumn("Xóa"),
    }


def save_issue_changes(user, kind, mode, original, edited, label_to_id):
    ok, errors = 0, []
    uid = user["id"]
    status_col = "Tình trạng chỉnh sửa" if kind == "self" else "Tình trạng sửa"
    note_col = "Ghi chú chỉnh sửa" if kind == "self" else "Kết quả chỉnh sửa"
    valid_status = SELF_STATUSES if kind == "self" else REVIEW_STATUSES
    with get_db() as db:
        for idx in original.index:
            o, e = original.loc[idx], edited.loc[idx]
            iid = int(o["ID"])
            row = db.execute("SELECT * FROM issues WHERE id=?", (iid,)).fetchone()
            if row is None:
                continue
            perm = {
                "owner": row["handler_id"] == uid,
                "author": row["checker_id"] == uid,
                "handler": row["handler_id"] == uid,
                "admin": is_admin(user),
            }[mode]
            if "Xóa" in ISSUE_EDIT[(kind, mode)] and bool(e["Xóa"]):
                if perm:
                    db.execute("DELETE FROM issues WHERE id=?", (iid,))
                    ok += 1
                else:
                    errors.append(f"Vấn đề #{iid}: bạn không có quyền xóa.")
                continue
            changes = {}

            def diff_text(col, field, target=changes):
                nv = clean_text(e[col])
                if nv != clean_text(o[col]):
                    target[field] = nv

            if mode == "owner":
                diff_text("Vấn đề phát hiện", "issue")
                diff_text(status_col, "status")
                diff_text(note_col, "handling_note")
            elif mode == "author":
                diff_text("Vấn đề phát hiện", "issue")
                diff_text("Hướng xử lý", "solution")
            elif mode == "handler":
                diff_text("Giải trình sai sót", "explanation")
                diff_text(status_col, "status")
                diff_text(note_col, "handling_note")
            if mode in ("author", "admin") and kind == "review":
                nh, oh = clean_text(e["NV phụ trách"]), clean_text(o["NV phụ trách"])
                if nh != oh:
                    if nh == "":
                        changes["handler_id"] = None
                    elif nh in label_to_id:
                        changes["handler_id"] = label_to_id[nh]
            if not changes:
                continue
            if not perm:
                errors.append(f"Vấn đề #{iid}: bạn không được phân công nên không có quyền điền ô này.")
                continue
            if "issue" in changes and not changes["issue"]:
                errors.append(f"Vấn đề #{iid}: nội dung vấn đề không được để trống.")
                continue
            if "status" in changes and changes["status"] not in valid_status:
                errors.append(f"Vấn đề #{iid}: tình trạng không hợp lệ.")
                continue
            if kind == "review" and mode == "handler" and changes.get("status") == "Đã sửa xong":
                expl = changes.get("explanation", clean_text(row["explanation"]))
                if not expl:
                    errors.append(f"Vấn đề #{iid}: vui lòng nhập giải trình sai sót trước khi chọn 'Đã sửa xong'.")
                    continue
            changes["updated_at"] = now_str()
            update_row(db, "issues", iid, changes)
            ok += 1
    if ok:
        log_action(user["username"], "CAP_NHAT_VAN_DE", f"{kind}/{mode}: {ok} mục")
    return ok, errors


def issue_grid(user, df, kind, mode, key):
    labels = {u["id"]: user_label(u) for u in load_users()}
    label_to_id = {v: k for k, v in labels.items()}
    view = issue_view(df.reset_index(drop=True), kind, labels)
    order = issue_order(kind)
    cfg = issue_config(labels)
    if mode == "readonly":
        cols = [c for c in order if c != "Xóa"]
        full_width_call(st.dataframe, view[cols], hide_index=True, column_config=cfg)
        return
    editable = ISSUE_EDIT[(kind, mode)]
    disabled = [c for c in order if c not in editable]
    edited = full_width_call(
        st.data_editor,
        view,
        key=f"iss_{key}_{kind}_{mode}_{ver()}",
        hide_index=True,
        num_rows="fixed",
        disabled=disabled,
        column_order=order,
        column_config=cfg,
    )
    if st.button("💾 Lưu", key=f"isave_{key}_{kind}_{mode}_{ver()}"):
        ok, errors = save_issue_changes(user, kind, mode, view, edited, label_to_id)
        if errors:
            flash("warning", f"Đã lưu {ok} mục. Cần lưu ý:\n\n" + "\n\n".join(errors))
        elif ok:
            flash("success", f"Đã lưu {ok} mục.")
        else:
            flash("info", "Không có thay đổi nào để lưu.")
        bump_ver()
        st.rerun()


def render_issues(user, period, client_ids, kind):
    uid = user["id"]
    step = "B4" if kind == "self" else "B5"
    if kind == "self":
        st.markdown("#### Vấn đề tự kiểm tra và tình trạng chỉnh sửa")
    else:
        st.markdown("#### Vấn đề soát xét cấp 2, giải trình và tình trạng sửa")
    labels = {u["id"]: user_label(u) for u in load_users()}

    # Chỉ người được phân công bước này (B4/B5) của khách hàng đó mới được thêm vấn đề
    with get_db() as db:
        eligible = [
            dict(r) for r in db.execute(
                "SELECT DISTINCT c.id, c.code, c.name, c.staff_id FROM tasks t "
                "JOIN clients c ON c.id=t.client_id WHERE t.period=? AND t.step=? "
                "AND t.assignee_id=? AND c.active=1 ORDER BY c.code",
                (period, step, uid),
            ).fetchall()
        ]
    if eligible:
        title = "➕ Ghi nhận vấn đề tự kiểm tra" if kind == "self" else "➕ Ghi nhận vấn đề soát xét cấp 2"
        with st.expander(title):
            with st.form(f"add_{kind}_{period}_{ver()}", clear_on_submit=True):
                cmap = {c["id"]: c for c in eligible}
                cid = st.selectbox("Khách hàng", list(cmap.keys()), format_func=lambda i: client_label(cmap[i]))
                issue = st.text_area("Vấn đề phát hiện *")
                if kind == "self":
                    note = st.text_area("Ghi chú chỉnh sửa (đã chỉnh sửa như thế nào)")
                    solution, handler = "", 0
                else:
                    solution = st.text_area("Hướng xử lý")
                    umap = {u["id"]: u for u in load_users(active_only=True)}
                    handler = st.selectbox(
                        "Nhân viên phụ trách giải trình và sửa",
                        [0] + list(umap.keys()),
                        format_func=lambda i: "Mặc định theo khách hàng" if i == 0 else user_label(umap[i]),
                    )
                    note = ""
                submitted = st.form_submit_button("Thêm vấn đề")
            if submitted:
                if not issue.strip():
                    st.error("Vui lòng nhập vấn đề phát hiện.")
                else:
                    if kind == "self":
                        hid, status = uid, SELF_STATUSES[0]
                    else:
                        hid, status = (handler or cmap[cid]["staff_id"]), REVIEW_STATUSES[0]
                    with get_db() as db:
                        db.execute(
                            "INSERT INTO issues (kind, client_id, period, issue, solution, checker_id, "
                            "handler_id, status, explanation, handling_note, created_at, updated_at) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                            (kind, cid, period, issue.strip(), solution.strip(), uid, hid, status,
                             "", note.strip(), now_str(), now_str()),
                        )
                    log_action(user["username"], "THEM_VAN_DE", f"{kind} {cmap[cid]['code']} kỳ {period}")
                    flash("success", "Đã ghi nhận vấn đề.")
                    bump_ver()
                    st.rerun()
    else:
        who = "tự kiểm tra" if kind == "self" else "soát xét cấp 2"
        st.caption(f"Bạn chỉ thêm được vấn đề {who} cho khách hàng mà bạn được phân công ở bước {step} trong kỳ này.")

    df = load_issues(user, kind, period, client_ids)
    if df.empty:
        st.info("Chưa có vấn đề nào trong kỳ này.")
        return
    key = f"{period}_{'-'.join(map(str, client_ids))}"
    if kind == "self":
        mine = df[df["handler_id"] == uid]
        others = df[df["handler_id"] != uid]
        if not mine.empty:
            st.markdown("**✏️ Vấn đề tự kiểm tra của tôi**")
            issue_grid(user, mine, "self", "owner", key)
        if is_privileged(user) and not others.empty:
            with st.expander("👁️ Tự kiểm tra của người khác (chỉ xem, ô bị khóa)"):
                issue_grid(user, others, "self", "readonly", key)
        if is_admin(user):
            with st.expander("🛠️ Quản trị: xóa vấn đề"):
                issue_grid(user, df, "self", "admin", key)
    else:
        author = df[df["checker_id"] == uid]
        handler = df[df["handler_id"] == uid]
        others = df[(df["checker_id"] != uid) & (df["handler_id"] != uid)]
        if not author.empty:
            st.markdown("**🔎 Vấn đề do tôi ghi nhận (người kiểm tra)**")
            issue_grid(user, author, "review", "author", key)
        if not handler.empty:
            st.markdown("**✏️ Vấn đề cần tôi giải trình và sửa**")
            issue_grid(user, handler, "review", "handler", key)
        if is_privileged(user) and not others.empty:
            with st.expander("👁️ Vấn đề của người khác (chỉ xem, ô bị khóa)"):
                issue_grid(user, others, "review", "readonly", key)
        if is_admin(user):
            with st.expander("🛠️ Quản trị: phân công lại người sửa / xóa vấn đề"):
                issue_grid(user, df, "review", "admin", key)


# ----------------------------------------------------------------------------
# TRANG: ĐĂNG NHẬP / ĐỔI MẬT KHẨU
# ----------------------------------------------------------------------------
def page_login():
    _, mid, _ = st.columns([1, 1.6, 1])
    with mid:
        st.markdown(LOGIN_HTML, unsafe_allow_html=True)
        msg = st.session_state.pop("login_msg", None)
        if msg:
            st.warning(msg)
        with get_db() as db:
            adm = db.execute("SELECT must_change_pw FROM users WHERE username='admin'").fetchone()
        if adm and adm["must_change_pw"] and not os.environ.get("ADMIN_INITIAL_PASSWORD"):
            st.info("Lần đầu sử dụng: tài khoản **admin**, mật khẩu **Admin@123**. Hệ thống sẽ yêu cầu đổi mật khẩu ngay.")
        with st.form("login_form"):
            st.subheader("Đăng nhập hệ thống")
            username = st.text_input("Tên đăng nhập")
            password = st.text_input("Mật khẩu", type="password")
            submitted = st.form_submit_button("Đăng nhập")
        if submitted:
            if not username or not password:
                st.error("Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu.")
                return
            u, err = authenticate(username, password)
            if err:
                log_action(username.strip().lower() or "?", "DANG_NHAP_THAT_BAI", err)
                st.error(err)
                return
            st.session_state["uid"] = u["id"]
            st.session_state["last_active"] = datetime.now()
            log_action(u["username"], "DANG_NHAP", "")
            st.rerun()


def page_change_password(user, forced=False):
    st.header("🔑 Đổi mật khẩu")
    if forced:
        st.warning("Bạn cần đổi mật khẩu trước khi sử dụng hệ thống.")
    st.caption("Mật khẩu tối thiểu 8 ký tự, gồm chữ hoa, chữ thường và chữ số.")
    with st.form("pw_form", clear_on_submit=True):
        old = st.text_input("Mật khẩu hiện tại", type="password")
        new1 = st.text_input("Mật khẩu mới", type="password")
        new2 = st.text_input("Nhập lại mật khẩu mới", type="password")
        submitted = st.form_submit_button("Đổi mật khẩu")
    if submitted:
        if not verify_password(old, user["password_hash"], user["salt"]):
            st.error("Mật khẩu hiện tại không đúng.")
        elif new1 != new2:
            st.error("Hai mật khẩu mới không khớp.")
        elif new1 == old:
            st.error("Mật khẩu mới phải khác mật khẩu hiện tại.")
        elif password_error(new1):
            st.error(password_error(new1))
        else:
            h, s = hash_password(new1)
            with get_db() as db:
                db.execute(
                    "UPDATE users SET password_hash=?, salt=?, must_change_pw=0 WHERE id=?",
                    (h, s, user["id"]),
                )
            log_action(user["username"], "DOI_MAT_KHAU", "")
            flash("success", "Đổi mật khẩu thành công.")
            st.rerun()


# ----------------------------------------------------------------------------
# TRANG: TỔNG QUAN
# ----------------------------------------------------------------------------
def page_dashboard(user):
    st.header("📊 Tổng quan tiến độ")
    render_alerts(user)
    st.divider()
    period = period_selector("dash")
    df = load_tasks(user, period)
    if df.empty:
        st.info("Chưa có công việc trong kỳ này. Quản trị viên có thể sinh việc ở mục 'Sinh việc tự động'.")
        return
    df["done"] = df["status"].isin(DONE_STATUSES)
    df["client"] = df["client_code"] + " - " + df["client_name"]
    total = len(df)
    n_done = int(df["done"].sum())
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Tổng số việc", total)
    c2.metric("Hoàn thành", f"{n_done} ({n_done * 100 // total}%)")
    c3.metric("Đang xử lý", int((df["status"] == "Đang xử lý").sum()))
    c4.metric("Chưa thực hiện", int((df["status"] == "Chưa thực hiện").sum()))
    c5.metric("Vướng mắc", int((df["status"] == "Vướng mắc").sum()))
    st.progress(n_done / total)

    st.subheader("Tỷ lệ hoàn thành theo bước")
    by_step = df.groupby("step").agg(Tong=("id", "count"), Xong=("done", "sum"))
    by_step["Tỷ lệ (%)"] = (by_step["Xong"] / by_step["Tong"] * 100).round(1)
    by_step.index = [STEP_NAMES.get(s, s) for s in by_step.index]
    by_step = by_step.rename(columns={"Tong": "Tổng", "Xong": "Hoàn thành"})
    left, right = st.columns(2)
    with left:
        full_width_call(st.dataframe, by_step)
    with right:
        st.bar_chart(by_step["Tỷ lệ (%)"])

    b3 = df[df["step"] == "B3"]
    if not b3.empty:
        st.subheader("Tình hình nộp thuế trong kỳ (B3)")
        b3_summary(b3)

    st.subheader("Tình trạng theo khách hàng")
    pt = df.pivot_table(index="client", columns="status", values="id", aggfunc="count", fill_value=0)
    pt = pt.reindex(columns=STATUSES, fill_value=0)
    pt["% hoàn thành"] = (df.groupby("client")["done"].mean().reindex(pt.index) * 100).round(1)
    full_width_call(st.dataframe, pt)

    st.subheader("Việc quá hạn chưa hoàn thành trong kỳ")
    flags = [deadline_info(d, s)[1] for d, s in zip(df["due_date"], df["status"])]
    late = df[[f == "late" for f in flags]]
    if late.empty:
        st.success("Không có việc quá hạn.")
    else:
        out = pd.DataFrame(
            {
                "Cảnh báo": [deadline_info(d, s)[0] for d, s in zip(late["due_date"], late["status"])],
                "Khách hàng": late["client"],
                "Bước": late["step"].map(STEP_NAMES),
                "Hạng mục": late["sub_item"],
                "Kỳ kê khai": late["tax_period"],
                "Hạn": late["due_date"],
                "Trạng thái": late["status"],
            }
        )
        full_width_call(st.dataframe, out, hide_index=True)


# ----------------------------------------------------------------------------
# TRANG: CÔNG VIỆC HÀNG THÁNG
# ----------------------------------------------------------------------------
def page_tasks(user, selected_client_id=None):
    clients = load_clients(active_only=True)
    cmap = {c["id"]: c for c in clients}

    if selected_client_id and selected_client_id in cmap:
        sel_client = cmap[selected_client_id]

        top_c1, top_c2 = st.columns([4, 1])
        with top_c1:
            st.header(f"🏢 {client_label(sel_client)}")
        with top_c2:
            if st.button("📋 Tất cả KH", help="Chuyển sang xem toàn bộ khách hàng"):
                st.session_state["active_nav_choice"] = "\u00a0\u00a0├─ 📋 Tất cả khách hàng"
                st.rerun()

        info_items = []
        if sel_client.get("tax_code"):
            info_items.append(f"**MST:** `{sel_client['tax_code']}`")
        if sel_client.get("staff_name"):
            info_items.append(f"**Phụ trách:** {sel_client['staff_name']}")
        if sel_client.get("reviewer_name"):
            info_items.append(f"**Kiểm tra:** {sel_client['reviewer_name']}")
        if info_items:
            st.caption(" · ".join(info_items))

        f1, f2 = st.columns([2, 1])
        with f1:
            period = period_selector("tasks")
        with f2:
            statuses = st.multiselect(
                "Lọc trạng thái (tùy chọn)",
                STATUSES,
                key=f"status_filt_{selected_client_id}",
            )

        client_ids = [selected_client_id]
        assignee_id = 0
    else:
        st.header("✅ Công việc kế toán dịch vụ hàng tháng")
        period = period_selector("tasks")
        f1, f2, f3 = st.columns(3)
        client_ids = f1.multiselect("Khách hàng", list(cmap.keys()), format_func=lambda i: client_label(cmap[i]))
        statuses = f2.multiselect("Trạng thái", STATUSES)
        assignee_id = 0
        if is_privileged(user):
            umap = {u["id"]: u for u in load_users(active_only=True)}
            assignee_id = f3.selectbox(
                "Người phụ trách",
                [0] + list(umap.keys()),
                format_func=lambda i: "Tất cả" if i == 0 else user_label(umap[i]),
            )

    df = load_tasks(user, period, client_ids, statuses, assignee_id)
    if df.empty:
        if selected_client_id and selected_client_id in cmap:
            st.info(f"Khách hàng **{cmap[selected_client_id]['code']}** chưa có công việc nào trong kỳ **{period_label(period)}**.")
        else:
            st.info("Không có công việc phù hợp. Quản trị viên có thể sinh việc ở mục 'Sinh việc tự động'.")
        return

    export = pd.DataFrame(
        {
            "Khách hàng": df["client_code"] + " - " + df["client_name"],
            "Bước": df["step"].map(STEP_NAMES),
            "Hạng mục": df["sub_item"],
            "Sắc thuế": df["tax_type"],
            "Kỳ kê khai": df["tax_period"],
            "Hạn": df["due_date"],
            "Ngày hoàn thành": df["completed_date"],
            "Số thuế phát sinh": df["tax_amount"],
            "Số đã nộp": df["paid_amount"],
            "Trạng thái": df["status"],
            "Ghi chú": df["note"],
            "Tình trạng kiểm tra lưu trữ": df["check_status"],
            "Ghi chú kiểm tra": df["check_note"],
        }
    )
    csv_file = f"cong_viec_{cmap[selected_client_id]['code']}_{period}.csv" if (selected_client_id and selected_client_id in cmap) else f"cong_viec_{period}.csv"
    st.download_button(
        "⬇️ Xuất CSV (mở được bằng Excel)",
        data=export.to_csv(index=False).encode("utf-8-sig"),
        file_name=csv_file,
        mime="text/csv",
    )
    filt_key = f"{period}_{'-'.join(map(str, client_ids))}_{'-'.join(statuses)}_{assignee_id}"
    tabs = st.tabs([STEP_NAMES[s] for s in STEPS])
    for tab, step in zip(tabs, STEPS):
        with tab:
            sdf = df[df["step"] == step].reset_index(drop=True)
            render_step(user, step, sdf, period, client_ids, filt_key)


# ----------------------------------------------------------------------------
# TRANG: KHÁCH HÀNG (ADMIN)
# ----------------------------------------------------------------------------
def page_clients(user):
    st.header("🏢 Quản lý khách hàng")
    users = load_users(active_only=True)
    umap = {u["id"]: u for u in users}
    reviewer_ids = [u["id"] for u in users if u["role"] in ("reviewer", "admin")]

    def ulabel(i):
        return "— Chưa chọn —" if i == 0 else user_label(umap[i])

    with st.expander("➕ Thêm khách hàng mới", expanded=False):
        with st.form("add_client", clear_on_submit=True):
            c1, c2 = st.columns(2)
            code = c1.text_input("Mã khách hàng *")
            name = c2.text_input("Tên khách hàng *")
            mst = c1.text_input("Mã số thuế")
            staff = c2.selectbox("Nhân viên phụ trách", [0] + list(umap.keys()), format_func=ulabel)
            reviewer = c1.selectbox("Người kiểm tra (soát xét cấp 2, kiểm tra lưu trữ)", [0] + reviewer_ids, format_func=ulabel)
            taxes = st.multiselect(
                "Sắc thuế phải kê khai (tần suất mặc định, chỉnh sau ở bảng bên dưới)",
                TAX_TYPES, default=["GTGT", "TNCN", "TNDN"],
            )
            submitted = st.form_submit_button("Thêm khách hàng")
        if submitted:
            if not code.strip() or not name.strip():
                st.error("Mã và tên khách hàng là bắt buộc.")
            else:
                try:
                    with get_db() as db:
                        cur = db.execute(
                            "INSERT INTO clients (code, name, tax_code, staff_id, reviewer_id, active) "
                            "VALUES (?,?,?,?,?,1)",
                            (code.strip(), name.strip(), mst.strip(), staff or None, reviewer or None),
                        )
                        cid = cur.lastrowid
                        for t in taxes:
                            db.execute(
                                "INSERT OR IGNORE INTO client_taxes (client_id, tax_type, frequency) VALUES (?,?,?)",
                                (cid, t, DEFAULT_FREQ.get(t, "Tháng")),
                            )
                    log_action(user["username"], "THEM_KHACH_HANG", code.strip())
                    flash("success", f"Đã thêm khách hàng {code.strip()}.")
                    st.rerun()
                except sqlite3.IntegrityError:
                    st.error("Mã khách hàng đã tồn tại.")

    clients = load_clients()
    if not clients:
        st.info("Chưa có khách hàng nào.")
        return
    st.subheader("Danh sách khách hàng")
    full_width_call(
        st.dataframe,
        pd.DataFrame(
            {
                "Mã": [c["code"] for c in clients],
                "Tên": [c["name"] for c in clients],
                "MST": [c["tax_code"] for c in clients],
                "NV phụ trách": [c["staff_name"] or "" for c in clients],
                "Người kiểm tra": [c["reviewer_name"] or "" for c in clients],
                "Hoạt động": ["Có" if c["active"] else "Không" for c in clients],
            }
        ),
        hide_index=True,
    )

    st.subheader("Chỉnh sửa khách hàng")
    cmap = {c["id"]: c for c in clients}
    sel = st.selectbox("Chọn khách hàng", list(cmap.keys()), format_func=lambda i: client_label(cmap[i]))
    c = cmap[sel]
    all_users = {u["id"]: u for u in load_users()}
    staff_opts = [0] + list(umap.keys())
    rev_opts = [0] + reviewer_ids
    for uid_, opts in ((c["staff_id"], staff_opts), (c["reviewer_id"], rev_opts)):
        if uid_ and uid_ not in opts:
            opts.append(uid_)
            umap[uid_] = all_users[uid_]
    with st.form(f"edit_client_{sel}_{ver()}"):
        e1, e2 = st.columns(2)
        name = e1.text_input("Tên khách hàng", value=c["name"])
        mst = e2.text_input("Mã số thuế", value=c["tax_code"] or "")
        staff = e1.selectbox("Nhân viên phụ trách", staff_opts,
                             index=staff_opts.index(c["staff_id"] or 0), format_func=ulabel)
        reviewer = e2.selectbox("Người kiểm tra", rev_opts,
                                index=rev_opts.index(c["reviewer_id"] or 0), format_func=ulabel)
        active = st.checkbox("Đang hoạt động (được sinh việc hàng tháng)", value=bool(c["active"]))
        note = st.text_area("Ghi chú", value=c["note"] or "")
        saved = st.form_submit_button("Lưu thông tin khách hàng")
    if saved:
        if not name.strip():
            st.error("Tên khách hàng không được để trống.")
        else:
            with get_db() as db:
                db.execute(
                    "UPDATE clients SET name=?, tax_code=?, staff_id=?, reviewer_id=?, active=?, note=? WHERE id=?",
                    (name.strip(), mst.strip(), staff or None, reviewer or None,
                     1 if active else 0, note.strip(), sel),
                )
            log_action(user["username"], "SUA_KHACH_HANG", c["code"])
            flash("success", "Đã cập nhật khách hàng. Dùng 'Đồng bộ người phụ trách' ở mục Sinh việc nếu cần áp dụng cho việc đã sinh.")
            bump_ver()
            st.rerun()

    st.subheader(f"Sắc thuế và tần suất kê khai của {c['code']}")
    st.caption("Tháng: sinh việc mọi tháng. Quý: sinh việc tại tháng 3, 6, 9, 12. Năm: sinh việc tại tháng 12. "
               "Một sắc thuế có thể có nhiều dòng (ví dụ TNDN: Quý và Năm).")
    with get_db() as db:
        trows = db.execute(
            "SELECT tax_type, frequency FROM client_taxes WHERE client_id=? ORDER BY id", (sel,)
        ).fetchall()
    tdf = pd.DataFrame(
        [{"Sắc thuế": r["tax_type"], "Tần suất": r["frequency"]} for r in trows],
        columns=["Sắc thuế", "Tần suất"],
    )
    tedit = full_width_call(
        st.data_editor,
        tdf,
        key=f"taxes_{sel}_{ver()}",
        num_rows="dynamic",
        hide_index=True,
        column_config={
            "Sắc thuế": st.column_config.SelectboxColumn("Sắc thuế", options=TAX_TYPES, required=True),
            "Tần suất": st.column_config.SelectboxColumn("Tần suất", options=FREQUENCIES, required=True),
        },
    )
    if st.button("💾 Lưu cấu hình sắc thuế", key=f"save_tax_{sel}_{ver()}"):
        pairs = []
        for _, r in tedit.iterrows():
            tt, fq = clean_text(r["Sắc thuế"]), clean_text(r["Tần suất"])
            if tt in TAX_TYPES and fq in FREQUENCIES and (tt, fq) not in pairs:
                pairs.append((tt, fq))
        with get_db() as db:
            db.execute("DELETE FROM client_taxes WHERE client_id=?", (sel,))
            for tt, fq in pairs:
                db.execute(
                    "INSERT INTO client_taxes (client_id, tax_type, frequency) VALUES (?,?,?)",
                    (sel, tt, fq),
                )
        log_action(user["username"], "SUA_SAC_THUE", f"{c['code']}: {len(pairs)} dòng")
        flash("success", "Đã lưu cấu hình sắc thuế (áp dụng cho các kỳ sinh việc sau này).")
        bump_ver()
        st.rerun()


# ----------------------------------------------------------------------------
# TRANG: NGƯỜI DÙNG (ADMIN)
# ----------------------------------------------------------------------------
def page_users(user):
    st.header("👥 Quản lý người dùng và phân quyền")
    with st.expander("➕ Tạo tài khoản mới"):
        with st.form("add_user", clear_on_submit=True):
            c1, c2 = st.columns(2)
            username = c1.text_input("Tên đăng nhập * (chữ thường, số, _ . ; 3-32 ký tự)")
            full_name = c2.text_input("Họ và tên *")
            role = c1.selectbox("Vai trò", list(ROLES.keys()), format_func=lambda r: ROLES[r], index=2)
            pw = c2.text_input("Mật khẩu tạm thời *", type="password")
            submitted = st.form_submit_button("Tạo tài khoản")
        if submitted:
            uname = username.strip().lower()
            if not re.fullmatch(r"[a-z0-9_.]{3,32}", uname):
                st.error("Tên đăng nhập chỉ gồm chữ thường, số, dấu _ và dấu chấm (3-32 ký tự).")
            elif not full_name.strip():
                st.error("Vui lòng nhập họ và tên.")
            elif password_error(pw):
                st.error(password_error(pw))
            else:
                h, s = hash_password(pw)
                try:
                    with get_db() as db:
                        db.execute(
                            "INSERT INTO users (username, full_name, password_hash, salt, role, active, "
                            "must_change_pw, created_at) VALUES (?,?,?,?,?,1,1,?)",
                            (uname, full_name.strip(), h, s, role, now_str()),
                        )
                    log_action(user["username"], "TAO_TAI_KHOAN", f"{uname} ({role})")
                    flash("success", f"Đã tạo tài khoản {uname}. Người dùng phải đổi mật khẩu khi đăng nhập lần đầu.")
                    st.rerun()
                except sqlite3.IntegrityError:
                    st.error("Tên đăng nhập đã tồn tại.")

    users = load_users()
    st.subheader("Danh sách tài khoản")
    full_width_call(
        st.dataframe,
        pd.DataFrame(
            {
                "Tên đăng nhập": [u["username"] for u in users],
                "Họ tên": [u["full_name"] for u in users],
                "Vai trò": [ROLES[u["role"]] for u in users],
                "Trạng thái": ["Hoạt động" if u["active"] else "Vô hiệu hóa" for u in users],
                "Đang bị khóa đến": [u["locked_until"] or "" for u in users],
            }
        ),
        hide_index=True,
    )

    st.subheader("Chỉnh sửa tài khoản")
    umap = {u["id"]: u for u in users}
    sel = st.selectbox("Chọn tài khoản", list(umap.keys()), format_func=lambda i: user_label(umap[i]))
    u = umap[sel]
    is_self = sel == user["id"]
    if is_self:
        st.info("Bạn không thể đổi vai trò hoặc vô hiệu hóa chính mình.")
    with st.form(f"edit_user_{sel}_{ver()}"):
        fname = st.text_input("Họ và tên", value=u["full_name"])
        roles = list(ROLES.keys())
        role = st.selectbox("Vai trò", roles, index=roles.index(u["role"]),
                            format_func=lambda r: ROLES[r], disabled=is_self)
        active = st.checkbox("Tài khoản hoạt động", value=bool(u["active"]), disabled=is_self)
        unlock = st.checkbox("Mở khóa tài khoản (xóa số lần đăng nhập sai)")
        saved = st.form_submit_button("Lưu")
    if saved:
        if not fname.strip():
            st.error("Họ và tên không được để trống.")
        else:
            with get_db() as db:
                if is_self:
                    db.execute("UPDATE users SET full_name=? WHERE id=?", (fname.strip(), sel))
                else:
                    db.execute(
                        "UPDATE users SET full_name=?, role=?, active=? WHERE id=?",
                        (fname.strip(), role, 1 if active else 0, sel),
                    )
                if unlock:
                    db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (sel,))
            log_action(user["username"], "SUA_TAI_KHOAN", u["username"])
            flash("success", "Đã cập nhật tài khoản.")
            bump_ver()
            st.rerun()

    with st.form(f"reset_pw_{sel}_{ver()}", clear_on_submit=True):
        st.markdown("**Đặt lại mật khẩu** (người dùng phải đổi mật khẩu ở lần đăng nhập kế tiếp)")
        newpw = st.text_input("Mật khẩu tạm thời mới", type="password")
        reset = st.form_submit_button("Đặt lại mật khẩu")
    if reset:
        if password_error(newpw):
            st.error(password_error(newpw))
        else:
            h, s = hash_password(newpw)
            with get_db() as db:
                db.execute(
                    "UPDATE users SET password_hash=?, salt=?, must_change_pw=1, failed_attempts=0, "
                    "locked_until=NULL WHERE id=?",
                    (h, s, sel),
                )
            log_action(user["username"], "DAT_LAI_MAT_KHAU", u["username"])
            flash("success", f"Đã đặt lại mật khẩu cho {u['username']}.")
            st.rerun()


# ----------------------------------------------------------------------------
# TRANG: SINH VIỆC TỰ ĐỘNG (ADMIN)
# ----------------------------------------------------------------------------
def page_generate(user):
    st.header("⚙️ Sinh việc tự động")
    st.write(
        "Hệ thống tự sinh việc cho **tháng hiện tại và tháng trước** mỗi khi có người đăng nhập. "
        "Tại đây bạn có thể sinh thủ công cho bất kỳ tháng/năm nào. Việc đã tồn tại sẽ không bị tạo trùng."
    )
    today = date.today()
    c1, c2 = st.columns(2)
    year = c1.number_input("Năm", min_value=2020, max_value=2100, value=today.year, step=1)
    month = c2.selectbox("Tháng", list(range(1, 13)), index=today.month - 1)
    b1, b2, b3 = st.columns(3)
    if b1.button("Sinh việc cho tháng đã chọn"):
        n = generate_tasks(int(year), int(month), user["username"])
        flash("success", f"Đã sinh thêm {n} đầu việc cho {month:02d}/{int(year)}.")
        st.rerun()
    if b2.button("Sinh việc cho cả năm"):
        total = sum(generate_tasks(int(year), m, user["username"]) for m in range(1, 13))
        flash("success", f"Đã sinh thêm {total} đầu việc cho năm {int(year)}.")
        st.rerun()
    if b3.button("Đồng bộ người phụ trách",
                 help="Cập nhật người phụ trách/người kiểm tra các việc chưa hoàn thành của tháng đã chọn theo cấu hình khách hàng hiện tại."):
        n = sync_assignees(period_str(int(year), int(month)), user["username"])
        flash("success", f"Đã đồng bộ người phụ trách cho {n} việc chưa hoàn thành.")
        st.rerun()
    st.subheader("Quy tắc sinh việc")
    st.markdown(
        "- **B1**: 9 bước hạch toán, hạn ngày 10 tháng sau.\n"
        "- **B2/B3**: theo sắc thuế và tần suất đã cấu hình cho từng khách hàng. "
        "Kỳ tháng: hạn ngày 20 tháng sau; kỳ quý: hạn cuối tháng sau quý; kỳ năm: "
        "Môn bài 30/01, các thuế khác 31/03 năm sau.\n"
        f"- Cảnh báo **sắp đến hạn** khi còn từ 0 đến {WARN_DAYS} ngày; **trễ hạn** khi quá hạn mà chưa hoàn thành.\n"
        "- **B4 Tự kiểm tra** (nhân viên phụ trách), hạn ngày 15 tháng sau.\n"
        "- **B5 Soát xét cấp 2** (người kiểm tra), hạn ngày 25 tháng sau.\n"
        "- **B6 Lưu trữ hồ sơ** (nhân viên lưu trữ, người kiểm tra kiểm tra lại), hạn cuối tháng sau.\n"
        "- Hạn và người phụ trách có thể được quản trị viên chỉnh trực tiếp ở mục Công việc."
    )


# ----------------------------------------------------------------------------
# TRANG: NHẬT KÝ (ADMIN)
# ----------------------------------------------------------------------------
def page_audit(user):
    st.header("📜 Nhật ký hệ thống")
    limit = st.selectbox("Số dòng hiển thị", [100, 500, 1000, 5000], index=1)
    with get_db() as db:
        rows = db.execute(
            "SELECT ts, username, action, detail FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    df = pd.DataFrame(
        [dict(r) for r in rows], columns=["ts", "username", "action", "detail"]
    ).rename(columns={"ts": "Thời gian", "username": "Người dùng", "action": "Hành động", "detail": "Chi tiết"})
    full_width_call(st.dataframe, df, hide_index=True)
    st.download_button(
        "⬇️ Xuất CSV",
        data=df.to_csv(index=False).encode("utf-8-sig"),
        file_name="nhat_ky_he_thong.csv",
        mime="text/csv",
    )


# ----------------------------------------------------------------------------
# ĐIỀU HƯỚNG CHÍNH
# ----------------------------------------------------------------------------
def main():
    st.set_page_config(
        page_title="NEW VISION - Quản lý công việc kế toán", page_icon=load_page_icon(), layout="wide"
    )
    st.markdown(CSS, unsafe_allow_html=True)
    init_once()
    user = current_user()
    if user is None:
        page_login()
        return

    if user["must_change_pw"]:
        with st.sidebar:
            st.markdown(SIDE_BRAND_HTML, unsafe_allow_html=True)
            st.write(f"👤 **{user['full_name']}**")
            if st.button("Đăng xuất"):
                log_action(user["username"], "DANG_XUAT", "")
                logout()
                st.rerun()
        st.markdown(HERO_HTML, unsafe_allow_html=True)
        show_flash()
        page_change_password(user, forced=True)
        return

    if not st.session_state.get("auto_generated"):
        auto_generate_recent(user["username"])
        st.session_state["auto_generated"] = True

    clients = load_clients(active_only=True)
    alerts = alert_rows(user)
    n_late = sum(1 for r in alerts if deadline_info(r["due_date"], r["status"])[1] == "late")
    n_soon = len(alerts) - n_late

    with st.sidebar:
        st.markdown(SIDE_BRAND_HTML, unsafe_allow_html=True)
        st.write(f"👤 **{user['full_name']}**")
        st.caption(f"Vai trò: {ROLES[user['role']]}")
        if alerts:
            st.write(f"🔴 {n_late} trễ hạn · 🟠 {n_soon} sắp đến hạn (B2/B3)")

        # Tìm kiếm nhanh khách hàng nếu danh sách từ 6 khách hàng trở lên
        filtered_clients = clients
        if len(clients) >= 6:
            c_kw = st.text_input(
                "Tìm khách hàng",
                value="",
                placeholder="🔍 Tìm mã hoặc tên KH...",
                key="sidebar_search_client",
                label_visibility="collapsed",
            ).strip().lower()
            if c_kw:
                filtered_clients = [c for c in clients if c_kw in c["code"].lower() or c_kw in c["name"].lower()]

        menu_items = {}
        menu_items["📊 Tổng quan"] = page_dashboard
        menu_items["✅ Công việc hàng tháng"] = lambda u: page_tasks(u, None)
        menu_items["\u00a0\u00a0├─ 📋 Tất cả khách hàng"] = lambda u: page_tasks(u, None)

        for i, c in enumerate(filtered_clients):
            is_last = (i == len(filtered_clients) - 1)
            prefix = "\u00a0\u00a0└─ " if is_last else "\u00a0\u00a0├─ "
            c_name = c["name"]
            if len(c_name) > 28:
                c_name = c_name[:26] + "…"
            label = f"{prefix}🏢 {c['code']} - {c_name}"
            cid = c["id"]
            menu_items[label] = (lambda client_id=cid: lambda u: page_tasks(u, client_id))()

        if is_admin(user):
            menu_items["🏢 Khách hàng"] = page_clients
            menu_items["👥 Người dùng"] = page_users
            menu_items["⚙️ Sinh việc tự động"] = page_generate
            menu_items["📜 Nhật ký hệ thống"] = page_audit
        menu_items["🔑 Đổi mật khẩu"] = lambda u: page_change_password(u)

        options = list(menu_items.keys())
        prev_choice = st.session_state.get("active_nav_choice", options[0])
        if prev_choice not in options:
            prev_choice = options[1] if len(options) > 1 else options[0]

        choice = st.radio(
            "Chức năng",
            options,
            index=options.index(prev_choice),
            label_visibility="collapsed",
        )
        st.session_state["active_nav_choice"] = choice

        st.divider()
        if st.button("Đăng xuất"):
            log_action(user["username"], "DANG_XUAT", "")
            logout()
            st.rerun()
        st.caption(f"Tự đăng xuất sau {SESSION_TIMEOUT_MIN} phút không hoạt động.")

    st.markdown(HERO_HTML, unsafe_allow_html=True)
    show_flash()
    menu_items[choice](user)


main()
