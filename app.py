# -*- coding: utf-8 -*-
"""
QUẢN LÝ CÔNG VIỆC KẾ TOÁN DỊCH VỤ HÀNG THÁNG (Streamlit + SQLite)

Chạy:
    pip install streamlit pandas
    streamlit run app.py

Đăng nhập lần đầu: admin / Admin@123  (hệ thống bắt buộc đổi mật khẩu ngay).
Có thể đặt mật khẩu ban đầu bằng biến môi trường ADMIN_INITIAL_PASSWORD
trước khi chạy lần đầu (khi database chưa tồn tại).

BẢO MẬT
- Mật khẩu băm PBKDF2-HMAC-SHA256 (200.000 vòng) + salt ngẫu nhiên, không lưu mật khẩu gốc.
- Khóa tài khoản 15 phút sau 5 lần đăng nhập sai; tự đăng xuất sau 30 phút không hoạt động.
- Chính sách mật khẩu: tối thiểu 8 ký tự, có chữ hoa, chữ thường, chữ số.
- Mọi truy vấn SQL dùng tham số (chống SQL injection); kiểm tra quyền phía máy chủ.
- Nhật ký hệ thống ghi lại đăng nhập, thay đổi dữ liệu, sinh việc, quản trị.

PHÂN QUYỀN
- Quản trị viên: toàn quyền (khách hàng, người dùng, sinh việc, nhật ký, sửa mọi công việc).
- Người kiểm tra: xem toàn bộ, sửa việc được giao (B4, kiểm tra lại B5), ghi nhận
  và theo dõi vấn đề kiểm tra.
- Nhân viên kế toán: chỉ thấy và sửa việc được giao; cập nhật kết quả xử lý vấn đề
  kiểm tra được giao cho mình.

TỰ ĐỘNG SINH VIỆC (theo kỳ làm việc = tháng hạch toán)
- B1: 9 bước hạch toán nhỏ.
- B2/B3: theo từng sắc thuế đã cấu hình cho khách hàng: Tháng (mọi tháng),
  Quý (tháng 3, 6, 9, 12), Năm (tháng 12).
- B4: kiểm tra tổng thể + danh sách vấn đề phát hiện.
- B5: lưu trữ (nhân viên) và kiểm tra lại (người kiểm tra).
- Tự sinh cho tháng hiện tại và tháng trước khi có người đăng nhập; quản trị viên
  có thể sinh cho bất kỳ tháng/năm nào (không tạo trùng).
"""

import calendar
import hashlib
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
DB_PATH = os.environ.get("KETOAN_DB", "ketoan_dichvu.db")
SESSION_TIMEOUT_MIN = 30
MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 15
PBKDF2_ITERATIONS = 200_000

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
ISSUE_STATUSES = ["Chưa xử lý", "Đang xử lý", "Đã xử lý"]

STEPS = ["B1", "B2", "B3", "B4", "B5"]
STEP_NAMES = {
    "B1": "B1. Hạch toán sổ sách",
    "B2": "B2. Kê khai thuế",
    "B3": "B3. Nộp tiền thuế",
    "B4": "B4. Kiểm tra",
    "B5": "B5. Lưu trữ hồ sơ",
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
B4_ITEM = "Kiểm tra tổng thể hồ sơ kỳ"
B5_STAFF_ITEM = "Lưu trữ hồ sơ (nhân viên phụ trách)"
B5_REVIEW_ITEM = "Kiểm tra lại hồ sơ lưu trữ (người kiểm tra)"

TAX_TYPES = [
    "GTGT",
    "TNCN",
    "TNDN",
    "Môn bài",
    "Thuế nhà thầu",
    "Tiêu thụ đặc biệt",
    "Tài nguyên",
    "Bảo vệ môi trường",
    "Thuế khác",
]
FREQUENCIES = ["Tháng", "Quý", "Năm"]
DEFAULT_FREQ = {
    "GTGT": "Tháng",
    "TNCN": "Tháng",
    "TNDN": "Quý",
    "Môn bài": "Năm",
    "Thuế nhà thầu": "Tháng",
    "Tiêu thụ đặc biệt": "Tháng",
    "Tài nguyên": "Tháng",
    "Bảo vệ môi trường": "Quý",
    "Thuế khác": "Tháng",
}

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
    due_date TEXT DEFAULT '',
    note TEXT DEFAULT '',
    updated_by TEXT DEFAULT '',
    updated_at TEXT DEFAULT '',
    UNIQUE (client_id, period, step, sub_item, tax_type, tax_period)
);
CREATE TABLE IF NOT EXISTS b4_issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    period TEXT NOT NULL,
    issue TEXT NOT NULL,
    solution TEXT DEFAULT '',
    checker_id INTEGER REFERENCES users(id),
    handler_id INTEGER REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'Chưa xử lý',
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
CREATE INDEX IF NOT EXISTS idx_issues_period ON b4_issues(period);
"""


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
    """Tên bảng và tên cột chỉ lấy từ hằng số trong mã nguồn, giá trị luôn dùng tham số."""
    cols = ", ".join(f"{k}=?" for k in changes)
    db.execute(f"UPDATE {table} SET {cols} WHERE id=?", (*changes.values(), row_id))


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.close()
    with get_db() as db:
        db.executescript(SCHEMA)
        count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            pw = os.environ.get("ADMIN_INITIAL_PASSWORD", "Admin@123")
            h, s = hash_password(pw)
            db.execute(
                "INSERT INTO users (username, full_name, password_hash, salt, role, "
                "active, must_change_pw, created_at) VALUES (?,?,?,?,?,?,?,?)",
                ("admin", "Quản trị viên", h, s, "admin", 1, 1, now_str()),
            )


@st.cache_resource
def init_once():
    init_db()
    return True


# ----------------------------------------------------------------------------
# MẬT KHẨU & XÁC THỰC
# ----------------------------------------------------------------------------
def hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
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
                "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?",
                (u["id"],),
            )
            return dict(u), None
        fails = u["failed_attempts"] + 1
        if fails >= MAX_FAILED_ATTEMPTS:
            until = (datetime.now() + timedelta(minutes=LOCK_MINUTES)).isoformat()
            db.execute(
                "UPDATE users SET failed_attempts=0, locked_until=? WHERE id=?",
                (until, u["id"]),
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
# TIỆN ÍCH
# ----------------------------------------------------------------------------
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


def can_edit_task(u, task):
    if is_admin(u):
        return True
    return task["assignee_id"] is not None and task["assignee_id"] == u["id"]


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
        return date(ny, nm, 25)
    return date(ny, nm, last_day(ny, nm))


def generate_tasks(year, month, actor):
    """Sinh việc cho tất cả khách hàng đang hoạt động. Không tạo trùng. Trả về số việc mới."""
    period = period_str(year, month)
    inserted = 0
    with get_db() as db:
        clients = db.execute("SELECT * FROM clients WHERE active=1").fetchall()
        for c in clients:
            staff, reviewer = c["staff_id"], c["reviewer_id"]
            taxes = db.execute(
                "SELECT tax_type, frequency FROM client_taxes WHERE client_id=?",
                (c["id"],),
            ).fetchall()
            rows = []
            d1 = due_date_for("B1", "", "", year, month).isoformat()
            for item in B1_ITEMS:
                rows.append(("B1", item, "", "", staff, d1))
            for t in taxes:
                if not freq_applies(t["frequency"], month):
                    continue
                label = tax_period_label(t["frequency"], year, month)
                due2 = due_date_for("B2", t["tax_type"], t["frequency"], year, month).isoformat()
                due3 = due_date_for("B3", t["tax_type"], t["frequency"], year, month).isoformat()
                rows.append(("B2", f"Kê khai thuế {t['tax_type']}", t["tax_type"], label, staff, due2))
                rows.append(("B3", f"Nộp tiền thuế {t['tax_type']}", t["tax_type"], label, staff, due3))
            rows.append(("B4", B4_ITEM, "", "", reviewer, due_date_for("B4", "", "", year, month).isoformat()))
            d5 = due_date_for("B5", "", "", year, month).isoformat()
            rows.append(("B5", B5_STAFF_ITEM, "", "", staff, d5))
            rows.append(("B5", B5_REVIEW_ITEM, "", "", reviewer, d5))
            for step, sub, tax, tperiod, assignee, due in rows:
                cur = db.execute(
                    "INSERT OR IGNORE INTO tasks (client_id, period, step, sub_item, tax_type, "
                    "tax_period, status, assignee_id, due_date, note, updated_by, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (c["id"], period, step, sub, tax, tperiod, "Chưa thực hiện",
                     assignee, due, "", actor, now_str()),
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
    """Cập nhật người phụ trách các việc chưa hoàn thành theo cấu hình khách hàng hiện tại."""
    with get_db() as db:
        cur = db.execute(
            "UPDATE tasks SET assignee_id = CASE "
            " WHEN step IN ('B1','B2','B3') THEN (SELECT staff_id FROM clients WHERE id=tasks.client_id) "
            " WHEN step='B4' THEN (SELECT reviewer_id FROM clients WHERE id=tasks.client_id) "
            " WHEN step='B5' AND sub_item=? THEN (SELECT staff_id FROM clients WHERE id=tasks.client_id) "
            " ELSE (SELECT reviewer_id FROM clients WHERE id=tasks.client_id) END, "
            "updated_by=?, updated_at=? "
            "WHERE period=? AND status NOT IN ('Đã hoàn thành','Không phát sinh')",
            (B5_STAFF_ITEM, actor, now_str(), period),
        )
        n = cur.rowcount
    log_action(actor, "DONG_BO_NGUOI_PHU_TRACH", f"Kỳ {period}: {n} việc")
    return n


# ----------------------------------------------------------------------------
# TRUY VẤN CÔNG VIỆC
# ----------------------------------------------------------------------------
def load_tasks(user, period, client_ids=None, statuses=None, assignee_id=None):
    sql = (
        "SELECT t.*, c.code AS client_code, c.name AS client_name "
        "FROM tasks t JOIN clients c ON c.id=t.client_id WHERE t.period=?"
    )
    params = [period]
    if user["role"] == "staff":
        sql += " AND t.assignee_id=?"
        params.append(user["id"])
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
    cols = [
        "id", "client_id", "period", "step", "sub_item", "tax_type", "tax_period",
        "status", "assignee_id", "due_date", "note", "updated_by", "updated_at",
        "client_code", "client_name",
    ]
    return pd.DataFrame(rows, columns=cols)


def save_task_changes(user, original, edited, label_to_id):
    ok, errors = 0, []
    with get_db() as db:
        for idx in original.index:
            o, e = original.loc[idx], edited.loc[idx]
            tid = int(o["ID"])
            changes = {}
            new_status = clean_text(e["Trạng thái"])
            new_note = clean_text(e["Ghi chú"])
            if new_status != clean_text(o["Trạng thái"]):
                changes["status"] = new_status
            if new_note != clean_text(o["Ghi chú"]):
                changes["note"] = new_note
            if is_admin(user):
                nl, ol = clean_text(e["Người phụ trách"]), clean_text(o["Người phụ trách"])
                if nl != ol:
                    if nl == "":
                        changes["assignee_id"] = None
                    elif nl in label_to_id:
                        changes["assignee_id"] = label_to_id[nl]
                nd, od = to_iso(e["Hạn"]), to_iso(o["Hạn"])
                if nd != od:
                    changes["due_date"] = nd
            if not changes:
                continue
            t = db.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()
            if t is None:
                continue
            if not can_edit_task(user, t):
                errors.append(f"Việc #{tid} ({t['sub_item']}): bạn không có quyền sửa.")
                continue
            if "status" in changes:
                if changes["status"] not in STATUSES:
                    errors.append(f"Việc #{tid}: trạng thái không hợp lệ.")
                    continue
                if changes["status"] == "Đã hoàn thành":
                    if t["step"] == "B4":
                        pending = db.execute(
                            "SELECT COUNT(*) FROM b4_issues WHERE client_id=? AND period=? "
                            "AND status<>'Đã xử lý'",
                            (t["client_id"], t["period"]),
                        ).fetchone()[0]
                        if pending > 0:
                            errors.append(
                                f"Việc #{tid} (B4): còn {pending} vấn đề kiểm tra chưa xử lý xong, "
                                "chưa thể đánh dấu hoàn thành."
                            )
                            continue
                    if t["step"] == "B5" and t["sub_item"] == B5_REVIEW_ITEM:
                        pending = db.execute(
                            "SELECT COUNT(*) FROM tasks WHERE client_id=? AND period=? AND step='B5' "
                            "AND sub_item=? AND status NOT IN ('Đã hoàn thành','Không phát sinh')",
                            (t["client_id"], t["period"], B5_STAFF_ITEM),
                        ).fetchone()[0]
                        if pending > 0:
                            errors.append(
                                f"Việc #{tid} (B5): nhân viên phụ trách chưa lưu trữ xong hồ sơ, "
                                "chưa thể kiểm tra lại."
                            )
                            continue
            changes["updated_by"] = user["username"]
            changes["updated_at"] = now_str()
            update_row(db, "tasks", tid, changes)
            ok += 1
    if ok:
        log_action(user["username"], "CAP_NHAT_VIEC", f"{ok} đầu việc")
    return ok, errors


def render_task_editor(user, sdf, key):
    if sdf.empty:
        st.info("Không có công việc nào trong bước này (hoặc bạn chưa được giao việc).")
        return
    users = load_users()
    labels = {u["id"]: user_label(u) for u in users}
    label_to_id = {v: k for k, v in labels.items()}
    view = pd.DataFrame(
        {
            "ID": sdf["id"].astype(int),
            "Khách hàng": sdf["client_code"] + " - " + sdf["client_name"],
            "Hạng mục": sdf["sub_item"],
            "Sắc thuế": sdf["tax_type"],
            "Kỳ kê khai": sdf["tax_period"],
            "Người phụ trách": sdf["assignee_id"].map(labels).fillna(""),
            "Hạn": pd.to_datetime(sdf["due_date"], errors="coerce").dt.date,
            "Trạng thái": sdf["status"],
            "Ghi chú": sdf["note"].fillna(""),
        }
    )
    disabled = ["ID", "Khách hàng", "Hạng mục", "Sắc thuế", "Kỳ kê khai"]
    if not is_admin(user):
        disabled += ["Người phụ trách", "Hạn"]
    order = ["ID", "Khách hàng", "Hạng mục"]
    if sdf["step"].iloc[0] in ("B2", "B3"):
        order += ["Sắc thuế", "Kỳ kê khai"]
    order += ["Người phụ trách", "Hạn", "Trạng thái", "Ghi chú"]
    edited = st.data_editor(
        view,
        key=f"ed_{key}_{ver()}",
        hide_index=True,
        num_rows="fixed",
        use_container_width=True,
        disabled=disabled,
        column_order=order,
        column_config={
            "ID": st.column_config.NumberColumn("ID", width="small"),
            "Người phụ trách": st.column_config.SelectboxColumn(
                "Người phụ trách", options=[""] + list(labels.values()), required=False
            ),
            "Hạn": st.column_config.DateColumn("Hạn", format="DD/MM/YYYY"),
            "Trạng thái": st.column_config.SelectboxColumn(
                "Trạng thái", options=STATUSES, required=True
            ),
            "Ghi chú": st.column_config.TextColumn("Ghi chú", max_chars=500),
        },
    )
    if st.button("💾 Lưu thay đổi", key=f"save_{key}_{ver()}"):
        ok, errors = save_task_changes(user, view, edited, label_to_id)
        if errors:
            flash("warning", f"Đã lưu {ok} việc. Lỗi:\n\n" + "\n\n".join(errors))
        elif ok:
            flash("success", f"Đã lưu {ok} đầu việc.")
        else:
            flash("info", "Không có thay đổi nào để lưu.")
        bump_ver()
        st.rerun()


# ----------------------------------------------------------------------------
# B4 - VẤN ĐỀ KIỂM TRA
# ----------------------------------------------------------------------------
def render_issues(user, period, client_ids):
    st.markdown("#### Vấn đề phát hiện khi kiểm tra và tình trạng xử lý")
    users = load_users()
    labels = {u["id"]: user_label(u) for u in users}
    label_to_id = {v: k for k, v in labels.items()}
    privileged = is_privileged(user)

    if privileged:
        clients = load_clients(active_only=True)
        if clients:
            with st.expander("➕ Ghi nhận vấn đề kiểm tra mới"):
                with st.form(f"add_issue_{period}_{ver()}", clear_on_submit=True):
                    cmap = {c["id"]: c for c in clients}
                    cid = st.selectbox(
                        "Khách hàng", list(cmap.keys()),
                        format_func=lambda i: client_label(cmap[i]),
                    )
                    issue = st.text_area("Vấn đề phát hiện *")
                    solution = st.text_area("Hướng xử lý")
                    active_users = load_users(active_only=True)
                    umap = {u["id"]: u for u in active_users}
                    handler = st.selectbox(
                        "Nhân viên phụ trách xử lý",
                        [0] + list(umap.keys()),
                        format_func=lambda i: "Mặc định theo khách hàng" if i == 0 else user_label(umap[i]),
                    )
                    submitted = st.form_submit_button("Thêm vấn đề")
                if submitted:
                    if not issue.strip():
                        st.error("Vui lòng nhập vấn đề phát hiện.")
                    else:
                        hid = handler if handler else cmap[cid]["staff_id"]
                        with get_db() as db:
                            db.execute(
                                "INSERT INTO b4_issues (client_id, period, issue, solution, checker_id, "
                                "handler_id, status, handling_note, created_at, updated_at) "
                                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                                (cid, period, issue.strip(), solution.strip(), user["id"], hid,
                                 "Chưa xử lý", "", now_str(), now_str()),
                            )
                        log_action(user["username"], "THEM_VAN_DE_B4", f"{cmap[cid]['code']} kỳ {period}")
                        flash("success", "Đã ghi nhận vấn đề kiểm tra.")
                        bump_ver()
                        st.rerun()

    sql = (
        "SELECT i.*, c.code AS client_code, c.name AS client_name "
        "FROM b4_issues i JOIN clients c ON c.id=i.client_id WHERE i.period=?"
    )
    params = [period]
    if client_ids:
        sql += " AND i.client_id IN (%s)" % ",".join("?" * len(client_ids))
        params.extend(client_ids)
    if not privileged:
        sql += " AND i.handler_id=?"
        params.append(user["id"])
    sql += " ORDER BY c.code, i.id"
    with get_db() as db:
        rows = [dict(r) for r in db.execute(sql, params).fetchall()]
    if not rows:
        st.info("Chưa có vấn đề kiểm tra nào trong kỳ này.")
        return
    df = pd.DataFrame(rows)
    view = pd.DataFrame(
        {
            "ID": df["id"].astype(int),
            "Khách hàng": df["client_code"] + " - " + df["client_name"],
            "Người kiểm tra": df["checker_id"].map(labels).fillna(""),
            "Vấn đề phát hiện": df["issue"],
            "Hướng xử lý": df["solution"].fillna(""),
            "NV phụ trách xử lý": df["handler_id"].map(labels).fillna(""),
            "Tình trạng xử lý": df["status"],
            "Kết quả xử lý": df["handling_note"].fillna(""),
            "Xóa": False,
        }
    )
    disabled = ["ID", "Khách hàng", "Người kiểm tra"]
    if not privileged:
        disabled += ["Vấn đề phát hiện", "Hướng xử lý", "NV phụ trách xử lý", "Xóa"]
    edited = st.data_editor(
        view,
        key=f"issues_{period}_{ver()}",
        hide_index=True,
        num_rows="fixed",
        use_container_width=True,
        disabled=disabled,
        column_config={
            "ID": st.column_config.NumberColumn("ID", width="small"),
            "Vấn đề phát hiện": st.column_config.TextColumn("Vấn đề phát hiện", max_chars=1000),
            "Hướng xử lý": st.column_config.TextColumn("Hướng xử lý", max_chars=1000),
            "NV phụ trách xử lý": st.column_config.SelectboxColumn(
                "NV phụ trách xử lý", options=[""] + list(labels.values()), required=False
            ),
            "Tình trạng xử lý": st.column_config.SelectboxColumn(
                "Tình trạng xử lý", options=ISSUE_STATUSES, required=True
            ),
            "Kết quả xử lý": st.column_config.TextColumn("Kết quả xử lý", max_chars=1000),
            "Xóa": st.column_config.CheckboxColumn("Xóa"),
        },
    )
    if st.button("💾 Lưu vấn đề kiểm tra", key=f"save_issues_{period}_{ver()}"):
        ok, errors = 0, []
        with get_db() as db:
            for idx in view.index:
                o, e = view.loc[idx], edited.loc[idx]
                iid = int(o["ID"])
                row = db.execute("SELECT * FROM b4_issues WHERE id=?", (iid,)).fetchone()
                if row is None:
                    continue
                is_handler = row["handler_id"] == user["id"]
                if not (privileged or is_handler):
                    continue
                if privileged and bool(e["Xóa"]):
                    if is_admin(user) or row["checker_id"] == user["id"]:
                        db.execute("DELETE FROM b4_issues WHERE id=?", (iid,))
                        ok += 1
                    else:
                        errors.append(f"Vấn đề #{iid}: chỉ quản trị viên hoặc người ghi nhận mới được xóa.")
                    continue
                changes = {}
                st_new = clean_text(e["Tình trạng xử lý"])
                if st_new != clean_text(o["Tình trạng xử lý"]) and st_new in ISSUE_STATUSES:
                    changes["status"] = st_new
                hn = clean_text(e["Kết quả xử lý"])
                if hn != clean_text(o["Kết quả xử lý"]):
                    changes["handling_note"] = hn
                if privileged:
                    iss = clean_text(e["Vấn đề phát hiện"])
                    if iss != clean_text(o["Vấn đề phát hiện"]):
                        if iss:
                            changes["issue"] = iss
                        else:
                            errors.append(f"Vấn đề #{iid}: nội dung không được để trống.")
                    sol = clean_text(e["Hướng xử lý"])
                    if sol != clean_text(o["Hướng xử lý"]):
                        changes["solution"] = sol
                    nh, oh = clean_text(e["NV phụ trách xử lý"]), clean_text(o["NV phụ trách xử lý"])
                    if nh != oh:
                        if nh == "":
                            changes["handler_id"] = None
                        elif nh in label_to_id:
                            changes["handler_id"] = label_to_id[nh]
                if changes:
                    changes["updated_at"] = now_str()
                    update_row(db, "b4_issues", iid, changes)
                    ok += 1
        if ok:
            log_action(user["username"], "CAP_NHAT_VAN_DE_B4", f"{ok} vấn đề kỳ {period}")
        if errors:
            flash("warning", f"Đã lưu {ok} mục. Lỗi:\n\n" + "\n\n".join(errors))
        elif ok:
            flash("success", f"Đã lưu {ok} mục.")
        else:
            flash("info", "Không có thay đổi nào để lưu.")
        bump_ver()
        st.rerun()


# ----------------------------------------------------------------------------
# TRANG: ĐĂNG NHẬP / ĐỔI MẬT KHẨU
# ----------------------------------------------------------------------------
def page_login():
    _, mid, _ = st.columns([1, 1.2, 1])
    with mid:
        st.title("📒 Quản lý kế toán dịch vụ")
        st.caption("Vui lòng đăng nhập để tiếp tục.")
        msg = st.session_state.pop("login_msg", None)
        if msg:
            st.warning(msg)
        with get_db() as db:
            adm = db.execute(
                "SELECT must_change_pw FROM users WHERE username='admin'"
            ).fetchone()
        if adm and adm["must_change_pw"] and not os.environ.get("ADMIN_INITIAL_PASSWORD"):
            st.info("Lần đầu sử dụng: tài khoản **admin**, mật khẩu **Admin@123**. Hệ thống sẽ yêu cầu đổi mật khẩu ngay.")
        with st.form("login_form"):
            username = st.text_input("Tên đăng nhập")
            password = st.text_input("Mật khẩu", type="password")
            submitted = st.form_submit_button("Đăng nhập", use_container_width=True)
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
    left, right = st.columns([1, 1])
    left.dataframe(by_step, use_container_width=True)
    right.bar_chart(by_step["Tỷ lệ (%)"])

    st.subheader("Tình trạng theo khách hàng")
    pt = df.pivot_table(index="client", columns="status", values="id", aggfunc="count", fill_value=0)
    pt = pt.reindex(columns=STATUSES, fill_value=0)
    pt["% hoàn thành"] = (
        df.groupby("client")["done"].mean().reindex(pt.index) * 100
    ).round(1)
    st.dataframe(pt, use_container_width=True)

    st.subheader("⚠️ Việc quá hạn chưa hoàn thành")
    today = date.today()
    due = pd.to_datetime(df["due_date"], errors="coerce").dt.date
    mask = (~df["done"]) & due.notna() & (due < today)
    late = df[mask]
    if late.empty:
        st.success("Không có việc quá hạn.")
    else:
        out = pd.DataFrame(
            {
                "Khách hàng": late["client"],
                "Bước": late["step"].map(STEP_NAMES),
                "Hạng mục": late["sub_item"],
                "Kỳ kê khai": late["tax_period"],
                "Hạn": due[mask],
                "Trạng thái": late["status"],
            }
        )
        st.dataframe(out, use_container_width=True, hide_index=True)


# ----------------------------------------------------------------------------
# TRANG: CÔNG VIỆC HÀNG THÁNG
# ----------------------------------------------------------------------------
def page_tasks(user):
    st.header("✅ Công việc kế toán dịch vụ hàng tháng")
    period = period_selector("tasks")
    clients = load_clients(active_only=True)
    cmap = {c["id"]: c for c in clients}
    f1, f2, f3 = st.columns(3)
    client_ids = f1.multiselect(
        "Khách hàng", list(cmap.keys()), format_func=lambda i: client_label(cmap[i])
    )
    statuses = f2.multiselect("Trạng thái", STATUSES)
    assignee_id = 0
    if is_privileged(user):
        active_users = load_users(active_only=True)
        umap = {u["id"]: u for u in active_users}
        assignee_id = f3.selectbox(
            "Người phụ trách",
            [0] + list(umap.keys()),
            format_func=lambda i: "Tất cả" if i == 0 else user_label(umap[i]),
        )
    df = load_tasks(user, period, client_ids, statuses, assignee_id)
    if df.empty:
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
            "Trạng thái": df["status"],
            "Ghi chú": df["note"],
        }
    )
    st.download_button(
        "⬇️ Xuất CSV (mở được bằng Excel)",
        data=export.to_csv(index=False).encode("utf-8-sig"),
        file_name=f"cong_viec_{period}.csv",
        mime="text/csv",
    )
    filt_key = f"{period}_{'-'.join(map(str, client_ids))}_{'-'.join(statuses)}_{assignee_id}"
    tabs = st.tabs([STEP_NAMES[s] for s in STEPS])
    for tab, step in zip(tabs, STEPS):
        with tab:
            sdf = df[df["step"] == step].reset_index(drop=True)
            if not sdf.empty:
                done = int(sdf["status"].isin(DONE_STATUSES).sum())
                st.progress(done / len(sdf), text=f"Hoàn thành {done}/{len(sdf)} việc")
            if step == "B4":
                st.caption("Người kiểm tra cập nhật trạng thái kiểm tra tổng thể; chỉ hoàn thành khi mọi vấn đề phát hiện đã được xử lý.")
            if step == "B5":
                st.caption("Nhân viên lưu trữ xong thì người kiểm tra mới kiểm tra lại và hoàn thành.")
            render_task_editor(user, sdf, f"{step}_{filt_key}")
            if step == "B4":
                st.divider()
                render_issues(user, period, client_ids)


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
            reviewer = c1.selectbox("Người kiểm tra", [0] + reviewer_ids, format_func=ulabel)
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
                            (code.strip(), name.strip(), mst.strip(),
                             staff or None, reviewer or None),
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
    st.dataframe(
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
        use_container_width=True, hide_index=True,
    )

    st.subheader("Chỉnh sửa khách hàng")
    cmap = {c["id"]: c for c in clients}
    sel = st.selectbox("Chọn khách hàng", list(cmap.keys()), format_func=lambda i: client_label(cmap[i]))
    c = cmap[sel]
    with st.form(f"edit_client_{sel}_{ver()}"):
        e1, e2 = st.columns(2)
        name = e1.text_input("Tên khách hàng", value=c["name"])
        mst = e2.text_input("Mã số thuế", value=c["tax_code"] or "")
        staff_opts = [0] + list(umap.keys())
        rev_opts = [0] + reviewer_ids
        # giữ nguyên người đã gán dù người đó đã bị vô hiệu hóa
        if c["staff_id"] and c["staff_id"] not in staff_opts:
            staff_opts.append(c["staff_id"])
            umap[c["staff_id"]] = next(u for u in load_users() if u["id"] == c["staff_id"])
        if c["reviewer_id"] and c["reviewer_id"] not in rev_opts:
            rev_opts.append(c["reviewer_id"])
            umap[c["reviewer_id"]] = next(u for u in load_users() if u["id"] == c["reviewer_id"])
        staff = e1.selectbox(
            "Nhân viên phụ trách", staff_opts,
            index=staff_opts.index(c["staff_id"] or 0), format_func=ulabel,
        )
        reviewer = e2.selectbox(
            "Người kiểm tra", rev_opts,
            index=rev_opts.index(c["reviewer_id"] or 0), format_func=ulabel,
        )
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

    st.subheader(f"Sắc thuế & tần suất kê khai của {c['code']}")
    st.caption("Tháng: kê khai mọi tháng. Quý: sinh việc tại tháng 3, 6, 9, 12. Năm: sinh việc tại tháng 12. "
               "Một sắc thuế có thể có nhiều dòng (ví dụ TNDN: Quý và Năm).")
    with get_db() as db:
        trows = db.execute(
            "SELECT tax_type, frequency FROM client_taxes WHERE client_id=? ORDER BY id", (sel,)
        ).fetchall()
    tdf = pd.DataFrame(
        [{"Sắc thuế": r["tax_type"], "Tần suất": r["frequency"]} for r in trows],
        columns=["Sắc thuế", "Tần suất"],
    )
    tedit = st.data_editor(
        tdf,
        key=f"taxes_{sel}_{ver()}",
        num_rows="dynamic",
        use_container_width=True,
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
    st.header("👥 Quản lý người dùng & phân quyền")
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
    st.dataframe(
        pd.DataFrame(
            {
                "Tên đăng nhập": [u["username"] for u in users],
                "Họ tên": [u["full_name"] for u in users],
                "Vai trò": [ROLES[u["role"]] for u in users],
                "Trạng thái": ["Hoạt động" if u["active"] else "Vô hiệu hóa" for u in users],
                "Đang bị khóa đến": [u["locked_until"] or "" for u in users],
            }
        ),
        use_container_width=True, hide_index=True,
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
    if b1.button("Sinh việc cho tháng đã chọn", use_container_width=True):
        n = generate_tasks(int(year), int(month), user["username"])
        flash("success", f"Đã sinh thêm {n} đầu việc cho {month:02d}/{int(year)}.")
        st.rerun()
    if b2.button("Sinh việc cho cả năm", use_container_width=True):
        total = sum(generate_tasks(int(year), m, user["username"]) for m in range(1, 13))
        flash("success", f"Đã sinh thêm {total} đầu việc cho năm {int(year)}.")
        st.rerun()
    if b3.button("Đồng bộ người phụ trách", use_container_width=True,
                 help="Cập nhật người phụ trách các việc chưa hoàn thành của tháng đã chọn theo cấu hình khách hàng hiện tại."):
        n = sync_assignees(period_str(int(year), int(month)), user["username"])
        flash("success", f"Đã đồng bộ người phụ trách cho {n} việc chưa hoàn thành.")
        st.rerun()
    st.subheader("Quy tắc sinh việc")
    st.markdown(
        "- **B1**: 9 bước hạch toán, hạn ngày 10 tháng sau.\n"
        "- **B2/B3**: theo sắc thuế và tần suất đã cấu hình cho từng khách hàng. "
        "Kỳ tháng: hạn ngày 20 tháng sau; kỳ quý: hạn cuối tháng sau quý; kỳ năm: "
        "Môn bài 30/01, các thuế khác 31/03 năm sau.\n"
        "- **B4**: kiểm tra tổng thể (người kiểm tra), hạn ngày 25 tháng sau.\n"
        "- **B5**: lưu trữ (nhân viên) và kiểm tra lại (người kiểm tra), hạn cuối tháng sau.\n"
        "- Hạn có thể được quản trị viên chỉnh trực tiếp ở mục Công việc."
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
    st.dataframe(df, use_container_width=True, hide_index=True)
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
        page_title="Quản lý công việc kế toán dịch vụ", page_icon="📒", layout="wide"
    )
    init_once()
    user = current_user()
    if user is None:
        page_login()
        return

    if user["must_change_pw"]:
        with st.sidebar:
            st.write(f"👤 **{user['full_name']}**")
            if st.button("Đăng xuất"):
                log_action(user["username"], "DANG_XUAT", "")
                logout()
                st.rerun()
        show_flash()
        page_change_password(user, forced=True)
        return

    if not st.session_state.get("auto_generated"):
        auto_generate_recent(user["username"])
        st.session_state["auto_generated"] = True

    menu = {
        "📊 Tổng quan": page_dashboard,
        "✅ Công việc hàng tháng": page_tasks,
    }
    if is_admin(user):
        menu["🏢 Khách hàng"] = page_clients
        menu["👥 Người dùng"] = page_users
        menu["⚙️ Sinh việc tự động"] = page_generate
        menu["📜 Nhật ký hệ thống"] = page_audit
    menu["🔑 Đổi mật khẩu"] = lambda u: page_change_password(u)

    with st.sidebar:
        st.title("📒 Kế toán dịch vụ")
        st.write(f"👤 **{user['full_name']}**")
        st.caption(f"Vai trò: {ROLES[user['role']]}")
        choice = st.radio("Chức năng", list(menu.keys()), label_visibility="collapsed")
        st.divider()
        if st.button("Đăng xuất", use_container_width=True):
            log_action(user["username"], "DANG_XUAT", "")
            logout()
            st.rerun()
        st.caption(f"Tự đăng xuất sau {SESSION_TIMEOUT_MIN} phút không hoạt động.")

    show_flash()
    menu[choice](user)


main()
