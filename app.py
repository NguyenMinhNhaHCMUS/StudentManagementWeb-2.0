import pyodbc
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'lab03_dbsec_secret_key_2025'

# ============================================================
# Database Connection
# ============================================================
# Sửa connection string nếu cần (server name, authentication)
CONN_STR = (
    'DRIVER={ODBC Driver 17 for SQL Server};'
    'SERVER=localhost;'
    'DATABASE=QLSVNhom;'
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
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('EXEC SP_LOGIN ?, ?', manv, mk)
            row = cursor.fetchone()
            conn.close()

            if row:
                session['manv'] = row.MANV
                session['hoten'] = row.HOTEN
                session['email'] = row.EMAIL
                session['pubkey'] = row.PUBKEY
                session['mk'] = mk  # Cần để giải mã sau
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


# ---------- CLASSES ----------

@app.route('/classes', methods=['GET', 'POST'])
@login_required
def classes():
    conn = get_db()
    cursor = conn.cursor()

    # Thêm lớp mới
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
    cursor.execute('SELECT 1 FROM LOP WHERE MALOP = ? AND MANV = ?', malop, session['manv'])
    is_manager = cursor.fetchone() is not None

    # Lấy thông tin lớp
    cursor.execute('SELECT MALOP, TENLOP, MANV FROM LOP WHERE MALOP = ?', malop)
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
                    cursor.execute('EXEC SP_INS_SINHVIEN ?, ?, ?, ?, ?, ?, ?',
                                   masv, hoten, ngaysinh, diachi, malop, tendn, mk_sv)
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

        conn.close()
        return redirect(url_for('students', malop=malop))

    # Lấy danh sách sinh viên
    cursor.execute('EXEC SP_SEL_SINHVIEN_BY_LOP ?', malop)
    student_list = cursor.fetchall()

    conn.close()
    return render_template('students.html',
                           lop=lop_info,
                           students=student_list,
                           is_manager=is_manager,
                           malop=malop)


# ---------- GRADES ----------

@app.route('/classes/<malop>/students/<masv>/grades', methods=['GET', 'POST'])
@login_required
def grades(malop, masv):
    conn = get_db()
    cursor = conn.cursor()

    # Kiểm tra quyền quản lý
    cursor.execute('SELECT 1 FROM LOP WHERE MALOP = ? AND MANV = ?', malop, session['manv'])
    is_manager = cursor.fetchone() is not None

    if not is_manager:
        flash('Bạn không có quyền truy cập bảng điểm của lớp này!', 'error')
        conn.close()
        return redirect(url_for('students', malop=malop))

    # Lấy thông tin sinh viên
    cursor.execute('SELECT MASV, HOTEN, MALOP FROM SINHVIEN WHERE MASV = ? AND MALOP = ?', masv, malop)
    sv_info = cursor.fetchone()

    if not sv_info:
        flash('Không tìm thấy sinh viên!', 'error')
        conn.close()
        return redirect(url_for('students', malop=malop))

    # Thêm điểm
    if request.method == 'POST':
        mahp = request.form.get('mahp', '').strip()
        diemthi_str = request.form.get('diemthi', '').strip()

        if mahp and diemthi_str:
            try:
                diemthi = float(diemthi_str)
                cursor.execute('EXEC SP_INS_BANGDIEM ?, ?, ?, ?',
                               masv, mahp, diemthi, session['manv'])
                conn.commit()
                flash('Nhập điểm thành công!', 'success')
            except ValueError:
                flash('Điểm thi phải là số!', 'error')
            except Exception as e:
                flash(f'Lỗi: {str(e)}', 'error')
        else:
            flash('Vui lòng nhập đầy đủ thông tin!', 'error')

        conn.close()
        return redirect(url_for('grades', malop=malop, masv=masv))

    # Lấy bảng điểm (giải mã)
    cursor.execute('EXEC SP_SEL_BANGDIEM ?, ?, ?', masv, session['manv'], session['mk'])
    grade_list = cursor.fetchall()

    # Lấy danh sách học phần
    cursor.execute('EXEC SP_SEL_ALL_HOCPHAN')
    hocphan_list = cursor.fetchall()

    conn.close()
    return render_template('grades.html',
                           sv=sv_info,
                           grades=grade_list,
                           hocphan_list=hocphan_list,
                           malop=malop)


# ============================================================
# Run
# ============================================================
if __name__ == '__main__':
    app.run(debug=True, port=5000)
