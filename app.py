"""
Lab 04 — Student Management Web Application
All encryption/decryption is performed on the CLIENT (Python/Flask).
The database only stores and retrieves encrypted data.
"""

import pyodbc
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
from datetime import datetime
from crypto_utils import (
    sha256_hash, generate_rsa_keypair, serialize_public_key,
    load_public_key_from_pem, save_private_key_file, load_private_key_file,
    rsa_encrypt, rsa_decrypt,
)

app = Flask(__name__)
app.secret_key = 'lab04_dbsec_secret_key_2025'

# ============================================================
# Database Connection
# ============================================================
CONN_STR = (
    'DRIVER={ODBC Driver 17 for SQL Server};'
    'SERVER=localhost;'
    'DATABASE=QLSVNhom1;'
    'Trusted_Connection=yes;'
)


def get_db():
    """Tạo kết nối database mới."""
    return pyodbc.connect(CONN_STR)


# ============================================================
# Login Required Decorator
# ============================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'manv' not in session:
            flash('Vui lòng đăng nhập!', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# ============================================================
# Routes
# ============================================================

@app.route('/')
def index():
    return redirect(url_for('login'))


# ---------- LOGIN / LOGOUT ----------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        manv = request.form.get('manv', '').strip()
        mk = request.form.get('mk', '').strip()

        if not manv or not mk:
            flash('Vui lòng nhập đầy đủ thông tin!', 'error')
            return render_template('login.html')

        try:
            # Client-side: hash password with SHA2_256
            mk_hash = sha256_hash(mk, manv)

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('EXEC SP_LOGIN ?, ?', manv, mk_hash)
            row = cursor.fetchone()
            conn.close()

            if row:
                # Only store basic info — NO password, NO keys in session
                session['manv'] = row.MANV
                session['hoten'] = row.HOTEN
                session['email'] = row.EMAIL
                flash(f'Đăng nhập thành công! Xin chào {row.HOTEN}', 'success')
                return redirect(url_for('classes'))
            else:
                flash('Mã nhân viên hoặc mật khẩu không đúng!', 'error')
        except Exception as e:
            flash(f'Lỗi kết nối database: {str(e)}', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Đã đăng xuất!', 'info')
    return redirect(url_for('login'))


# ---------- EMPLOYEES ----------

@app.route('/employees', methods=['GET', 'POST'])
@login_required
def employees():
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add':
            manv_new = request.form.get('manv', '').strip()
            hoten = request.form.get('hoten', '').strip()
            email = request.form.get('email', '').strip()
            luong_str = request.form.get('luong', '').strip()
            tendn = request.form.get('tendn', '').strip()
            mk_new = request.form.get('mk', '').strip()

            if manv_new and hoten and tendn and mk_new and luong_str:
                try:
                    # Client-side: generate RSA key pair
                    private_key, public_key = generate_rsa_keypair()
                    pub_pem = serialize_public_key(public_key)

                    # Client-side: hash password
                    mk_hash = sha256_hash(mk_new, manv_new)

                    # Client-side: encrypt salary with public key
                    luong_encrypted = rsa_encrypt(public_key, luong_str)

                    # Save private key file (encrypted with password)
                    save_private_key_file(manv_new, private_key, mk_new)

                    # Send pre-encrypted data to DB
                    cursor.execute(
                        'EXEC SP_INS_PUBLIC_ENCRYPT_NHANVIEN ?, ?, ?, ?, ?, ?, ?',
                        manv_new, hoten, email, luong_encrypted, tendn, mk_hash, pub_pem,
                    )
                    conn.commit()
                    flash(f'Thêm nhân viên {manv_new} thành công!', 'success')
                except Exception as e:
                    error_msg = str(e)
                    if 'PRIMARY KEY' in error_msg or 'duplicate key' in error_msg.lower():
                        flash('Mã nhân viên đã tồn tại!', 'error')
                    elif 'UNIQUE' in error_msg:
                        flash('Tên đăng nhập đã tồn tại!', 'error')
                    else:
                        flash(f'Lỗi: {error_msg}', 'error')
            else:
                flash('Vui lòng nhập đầy đủ thông tin!', 'error')

        conn.close()
        return redirect(url_for('employees'))

    # Get all employees (basic info only) via SP
    cursor.execute('EXEC SP_SEL_ALL_NHANVIEN_BASIC')
    all_employees = cursor.fetchall()

    conn.close()
    return render_template('employees.html', employees=all_employees)


# ---------- SALARY DECRYPT (AJAX) ----------

@app.route('/employees/decrypt', methods=['POST'])
@login_required
def decrypt_salary():
    """AJAX endpoint: decrypt own salary and return JSON. No page reload."""
    mk_input = request.form.get('mk_decrypt', '').strip()
    if not mk_input:
        return jsonify({'error': 'Vui lòng nhập mật khẩu!'}), 400

    try:
        # Load private key from file using password
        private_key = load_private_key_file(session['manv'], mk_input)

        # Hash password for SP authentication
        mk_hash = sha256_hash(mk_input, session['manv'])

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('EXEC SP_SEL_PUBLIC_ENCRYPT_NHANVIEN ?, ?', session['manv'], mk_hash)
        row = cursor.fetchone()
        conn.close()

        if row and row.LUONG:
            # Client-side: decrypt salary
            luong = rsa_decrypt(private_key, bytes(row.LUONG))
            # private_key discarded here — not stored
            return jsonify({'luong': luong})
        else:
            return jsonify({'error': 'Mật khẩu không đúng hoặc không có dữ liệu lương!'}), 400

    except FileNotFoundError:
        return jsonify({'error': 'Không tìm thấy file khóa bí mật!'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Mật khẩu không đúng!'}), 400
    except Exception as e:
        return jsonify({'error': f'Lỗi giải mã: {str(e)}'}), 400


# ---------- SALARY UPDATE (AJAX) ----------

@app.route('/employees/update-salary', methods=['POST'])
@login_required
def update_salary():
    """AJAX endpoint: verify password, re-encrypt new salary, update DB."""
    mk_input = request.form.get('mk_update', '').strip()
    luong_new = request.form.get('luong_new', '').strip()

    if not mk_input or not luong_new:
        return jsonify({'error': 'Vui lòng nhập đầy đủ thông tin!'}), 400

    try:
        # Verify password by loading private key
        private_key = load_private_key_file(session['manv'], mk_input)

        # Derive public key from private key
        pub_key = private_key.public_key()

        # Encrypt new salary with public key
        luong_encrypted = rsa_encrypt(pub_key, luong_new)

        # Hash password for SP authentication
        mk_hash = sha256_hash(mk_input, session['manv'])

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('EXEC SP_UPDATE_LUONG ?, ?, ?',
                       session['manv'], mk_hash, luong_encrypted)
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': 'Cập nhật lương thành công!'})

    except FileNotFoundError:
        return jsonify({'error': 'Không tìm thấy file khóa bí mật!'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Mật khẩu không đúng!'}), 400
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 400


# ---------- CLASSES ----------

@app.route('/classes', methods=['GET', 'POST'])
@login_required
def classes():
    conn = get_db()
    cursor = conn.cursor()

    # Thêm / Xóa lớp
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add':
            malop = request.form.get('malop', '').strip()
            tenlop = request.form.get('tenlop', '').strip()

            if malop and tenlop:
                try:
                    cursor.execute('EXEC SP_INS_LOP ?, ?, ?', malop, tenlop, session['manv'])
                    conn.commit()
                    flash(f'Thêm lớp {malop} thành công!', 'success')
                except Exception as e:
                    error_msg = str(e)
                    if 'PRIMARY KEY' in error_msg or 'duplicate key' in error_msg:
                        flash('Mã lớp này đã tồn tại trong hệ thống! Vui lòng nhập mã khác.', 'error')
                    elif 'RAISERROR' in error_msg:
                        flash('Bạn không có quyền thực hiện thao tác này!', 'error')
                    else:
                        flash('Đã xảy ra lỗi khi thao tác với cơ sở dữ liệu!', 'error')
            else:
                flash('Vui lòng nhập đầy đủ mã lớp và tên lớp!', 'error')

        elif action == 'delete':
            malop = request.form.get('malop', '').strip()
            try:
                cursor.execute('EXEC SP_DEL_LOP ?, ?', malop, session['manv'])
                conn.commit()
                flash(f'Xóa lớp {malop} thành công!', 'success')
            except Exception as e:
                flash(f'Lỗi: {str(e)}', 'error')

        conn.close()
        return redirect(url_for('classes'))

    # Lấy lớp do nhân viên quản lý
    cursor.execute('EXEC SP_SEL_LOP_BY_NV ?', session['manv'])
    my_classes = cursor.fetchall()
    my_class_ids = [c.MALOP for c in my_classes]

    # Lấy tất cả lớp
    cursor.execute('EXEC SP_SEL_ALL_LOP')
    all_classes = cursor.fetchall()

    # Phân tách: lớp khác
    other_classes = [c for c in all_classes if c.MALOP not in my_class_ids]

    conn.close()
    return render_template('classes.html',
                           my_classes=my_classes,
                           other_classes=other_classes)


# ---------- STUDENTS ----------

@app.route('/classes/<malop>/students', methods=['GET', 'POST'])
@login_required
def students(malop):
    conn = get_db()
    cursor = conn.cursor()

    # Kiểm tra lớp có thuộc quyền quản lý không
    cursor.execute('EXEC SP_CHECK_LOP_MANAGER ?, ?', malop, session['manv'])
    is_manager = cursor.fetchone() is not None

    # Lấy thông tin lớp
    cursor.execute('EXEC SP_SEL_LOP_BY_ID ?', malop)
    lop_info = cursor.fetchone()

    if not lop_info:
        flash('Không tìm thấy lớp!', 'error')
        conn.close()
        return redirect(url_for('classes'))

    # Thêm / Sửa / Xóa sinh viên (chỉ cho manager)
    if request.method == 'POST' and is_manager:
        action = request.form.get('action')

        if action == 'add':
            masv = request.form.get('masv', '').strip()
            hoten = request.form.get('hoten', '').strip()
            ngaysinh_str = request.form.get('ngaysinh', '').strip()
            diachi = request.form.get('diachi', '').strip()
            tendn = request.form.get('tendn', '').strip()
            mk_sv = request.form.get('mk_sv', '').strip()

            if masv and hoten and tendn and mk_sv:
                try:
                    ngaysinh = datetime.strptime(ngaysinh_str, '%Y-%m-%d') if ngaysinh_str else None

                    # Client-side: hash password with SHA2_256
                    mk_hash = sha256_hash(mk_sv, masv)

                    cursor.execute('EXEC SP_INS_SINHVIEN ?, ?, ?, ?, ?, ?, ?',
                                   masv, hoten, ngaysinh, diachi, malop, tendn, mk_hash)
                    conn.commit()
                    flash(f'Thêm sinh viên {masv} thành công!', 'success')
                except Exception as e:
                    error_msg = str(e)
                    if 'PRIMARY KEY' in error_msg or 'duplicate key' in error_msg:
                        flash('Mã sinh viên này đã tồn tại trong hệ thống! Vui lòng nhập mã khác.', 'error')
                    elif 'RAISERROR' in error_msg:
                        flash('Bạn không có quyền thực hiện thao tác này!', 'error')
                    else:
                        flash('Đã xảy ra lỗi khi thao tác với cơ sở dữ liệu!', 'error')
            else:
                flash('Vui lòng nhập đầy đủ thông tin bắt buộc!', 'error')

        elif action == 'edit':
            masv = request.form.get('masv', '').strip()
            hoten = request.form.get('hoten', '').strip()
            ngaysinh_str = request.form.get('ngaysinh', '').strip()
            diachi = request.form.get('diachi', '').strip()

            try:
                ngaysinh = datetime.strptime(ngaysinh_str, '%Y-%m-%d') if ngaysinh_str else None
                cursor.execute('EXEC SP_UPDATE_SINHVIEN ?, ?, ?, ?, ?',
                               masv, hoten, ngaysinh, diachi, session['manv'])
                conn.commit()
                flash(f'Cập nhật sinh viên {masv} thành công!', 'success')
            except Exception as e:
                error_msg = str(e)
                if 'RAISERROR' in error_msg:
                    flash('Bạn không có quyền thực hiện thao tác này!', 'error')
                else:
                    flash('Đã xảy ra lỗi khi thao tác với cơ sở dữ liệu!', 'error')

        elif action == 'delete':
            masv = request.form.get('masv', '').strip()
            try:
                cursor.execute('EXEC SP_DEL_SINHVIEN ?, ?', masv, session['manv'])
                conn.commit()
                flash(f'Xóa sinh viên {masv} thành công!', 'success')
            except Exception as e:
                flash(f'Lỗi: {str(e)}', 'error')

        elif action == 'add_grade':
            masv = request.form.get('masv', '').strip()
            mahp = request.form.get('mahp', '').strip()
            diemthi_str = request.form.get('diemthi', '').strip()

            if masv and mahp and diemthi_str:
                try:
                    # Get employee's public key from DB
                    cursor.execute('EXEC SP_SEL_NHANVIEN_PUBKEY ?', session['manv'])
                    nv_row = cursor.fetchone()
                    if nv_row and nv_row.PUBKEY:
                        public_key = load_public_key_from_pem(nv_row.PUBKEY)

                        # Client-side: encrypt grade with public key
                        diemthi_encrypted = rsa_encrypt(public_key, diemthi_str)

                        cursor.execute('EXEC SP_INS_BANGDIEM ?, ?, ?, ?',
                                       masv, mahp, diemthi_encrypted, session['manv'])
                        conn.commit()
                        flash(f'Nhập điểm cho {masv} thành công!', 'success')
                    else:
                        flash('Không tìm thấy khóa công khai!', 'error')
                except Exception as e:
                    flash(f'Lỗi: {str(e)}', 'error')
            else:
                flash('Vui lòng nhập đầy đủ thông tin!', 'error')

        conn.close()
        return redirect(url_for('students', malop=malop))

    # Lấy danh sách sinh viên
    cursor.execute('EXEC SP_SEL_SINHVIEN_BY_LOP ?', malop)
    student_list = cursor.fetchall()

    # Lấy danh sách học phần (cho modal nhập điểm)
    hocphan_list = []
    if is_manager:
        cursor.execute('EXEC SP_SEL_ALL_HOCPHAN')
        hocphan_list = cursor.fetchall()

    conn.close()
    return render_template('students.html',
                           lop=lop_info,
                           students=student_list,
                           is_manager=is_manager,
                           malop=malop,
                           hocphan_list=hocphan_list)


# ---------- GRADES ----------

@app.route('/classes/<malop>/students/<masv>/grades')
@login_required
def grades(malop, masv):
    conn = get_db()
    cursor = conn.cursor()

    # Kiểm tra quyền quản lý
    cursor.execute('EXEC SP_CHECK_LOP_MANAGER ?, ?', malop, session['manv'])
    is_manager = cursor.fetchone() is not None

    if not is_manager:
        flash('Bạn không có quyền truy cập bảng điểm của lớp này!', 'error')
        conn.close()
        return redirect(url_for('students', malop=malop))

    # Lấy thông tin sinh viên
    cursor.execute('EXEC SP_SEL_SINHVIEN_BY_ID ?, ?', masv, malop)
    sv_info = cursor.fetchone()

    if not sv_info:
        flash('Không tìm thấy sinh viên!', 'error')
        conn.close()
        return redirect(url_for('students', malop=malop))

    # Always show encrypted grades (decryption happens via AJAX)
    cursor.execute('EXEC SP_SEL_BANGDIEM ?, ?', masv, session['manv'])
    raw_grades = cursor.fetchall()
    grade_list = []
    for g in raw_grades:
        grade_list.append({
            'MASV': g.MASV,
            'MAHP': g.MAHP,
            'TENHP': g.TENHP,
            'DIEMTHI': None,  # Encrypted — decrypted via AJAX
        })

    conn.close()
    return render_template('grades.html',
                           sv=sv_info,
                           grades=grade_list,
                           malop=malop)


# ---------- GRADES DECRYPT (AJAX) ----------

@app.route('/classes/<malop>/students/<masv>/grades/decrypt', methods=['POST'])
@login_required
def decrypt_grades(malop, masv):
    """AJAX endpoint: decrypt grades and return JSON. No page reload."""
    mk_input = request.form.get('mk_decrypt', '').strip()
    if not mk_input:
        return jsonify({'error': 'Vui lòng nhập mật khẩu!'}), 400

    try:
        # Load private key from file using password
        private_key = load_private_key_file(session['manv'], mk_input)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('EXEC SP_SEL_BANGDIEM ?, ?', masv, session['manv'])
        raw_grades = cursor.fetchall()
        conn.close()

        # Client-side: decrypt each grade
        grades = []
        for g in raw_grades:
            diem = None
            if g.DIEMTHI:
                try:
                    diem = rsa_decrypt(private_key, bytes(g.DIEMTHI))
                except Exception:
                    diem = None  # Không giải mã được
            grades.append({'MAHP': g.MAHP, 'DIEMTHI': diem})
        # private_key discarded here — not stored

        return jsonify({'grades': grades})

    except FileNotFoundError:
        return jsonify({'error': 'Không tìm thấy file khóa bí mật!'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Mật khẩu không đúng!'}), 400
    except Exception as e:
        return jsonify({'error': f'Lỗi giải mã: {str(e)}'}), 400


# ============================================================
# Run
# ============================================================
if __name__ == '__main__':
    app.run(debug=True, port=5000)
