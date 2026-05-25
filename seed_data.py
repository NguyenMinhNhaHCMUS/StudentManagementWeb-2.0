"""
Lab 04 — Seed sample data with client-side encryption.
Run this AFTER executing:
  1. sql/01_create_db_and_tables.sql
  2. sql/02_stored_procedures.sql
  3. sql/03_sample_data.sql  (học phần)
"""

import pyodbc
from crypto_utils import (
    sha256_hash, generate_rsa_keypair, serialize_public_key,
    save_private_key_file, rsa_encrypt,
)

CONN_STR = (
    'DRIVER={ODBC Driver 17 for SQL Server};'
    'SERVER=localhost;'
    'DATABASE=QLSVNhom1;'
    'Trusted_Connection=yes;'
)


def seed():
    conn = pyodbc.connect(CONN_STR)
    cursor = conn.cursor()

    # ----------------------------------------------------------
    # Thêm nhân viên (mã hóa tại client)
    # ----------------------------------------------------------
    employees = [
        ('NV01', 'Nguyễn Văn A',   'NVA@fit.edu.vn', 3000000, 'NVA', 'abcd12'),
        ('NV02', 'Trần Thị B',     'TTB@fit.edu.vn', 5000000, 'TTB', 'xyz789'),
        ('NV03', 'Nguyễn Minh C',  'NMC@fit.edu.vn', 4000000, 'NMC', 'abcd12'),
    ]

    employee_keys = {}  # Lưu public key để mã hóa điểm

    for manv, hoten, email, luongcb, tendn, mk in employees:
        # Client-side crypto
        private_key, public_key = generate_rsa_keypair()
        pub_pem = serialize_public_key(public_key)
        mk_hash = sha256_hash(mk, manv)
        luong_encrypted = rsa_encrypt(public_key, str(luongcb))

        # Lưu private key vào file (encrypted bởi password)
        save_private_key_file(manv, private_key, mk)

        # Gọi SP — chỉ lưu dữ liệu đã mã hóa
        cursor.execute(
            'EXEC SP_INS_PUBLIC_ENCRYPT_NHANVIEN ?, ?, ?, ?, ?, ?, ?',
            manv, hoten, email, luong_encrypted, tendn, mk_hash, pub_pem,
        )
        employee_keys[manv] = public_key
        print(f'  + Nhân viên {manv}: {hoten}')

    # ----------------------------------------------------------
    # Thêm lớp
    # ----------------------------------------------------------
    classes = [
        ('LOP01', 'CNTT K20 - Nhóm 1', 'NV01'),
        ('LOP02', 'CNTT K20 - Nhóm 2', 'NV01'),
        ('LOP03', 'CNTT K21 - Nhóm 1', 'NV02'),
        ('LOP04', 'CNTT K21 - Nhóm 2', 'NV03'),
    ]
    for malop, tenlop, manv in classes:
        cursor.execute('EXEC SP_INS_LOP ?, ?, ?', malop, tenlop, manv)
        print(f'  + Lớp {malop}: {tenlop}')

    # ----------------------------------------------------------
    # Thêm sinh viên (mật khẩu hash SHA2_256 tại client)
    # ----------------------------------------------------------
    students = [
        ('SV01', 'Lê Văn C',       '2002-05-15', '123 Nguyễn Trãi, Q5',    'LOP01', 'LVC', 'sv1234'),
        ('SV02', 'Phạm Thị D',     '2002-08-20', '456 Lê Lợi, Q1',         'LOP01', 'PTD', 'sv5678'),
        ('SV03', 'Hoàng Văn E',    '2003-01-10', '789 Cách Mạng, Q3',      'LOP02', 'HVE', 'sv9012'),
        ('SV04', 'Ngô Thị F',      '2003-03-25', '321 Hai Bà Trưng, Q1',   'LOP03', 'NTF', 'sv3456'),
        ('SV05', 'Đỗ Văn G',       '2003-07-12', '654 Pasteur, Q3',        'LOP03', 'DVG', 'sv7890'),
        ('SV06', 'Nguyễn Minh H',  '2003-04-12', '420 Bùi Thị Xuân, Q1',  'LOP04', 'NMH', 'sv7890'),
        ('SV07', 'Trần Thị I',     '2003-07-01', '13 Lê Văn Khương, Q12', 'LOP04', 'TTI', 'sv7891'),
    ]
    for masv, hoten, ns, dc, malop, tendn, mk in students:
        mk_hash = sha256_hash(mk, masv)
        cursor.execute(
            'EXEC SP_INS_SINHVIEN ?, ?, ?, ?, ?, ?, ?',
            masv, hoten, ns, dc, malop, tendn, mk_hash,
        )
        print(f'  + Sinh viên {masv}: {hoten}')

    # ----------------------------------------------------------
    # Thêm điểm (mã hóa RSA bằng public key của nhân viên quản lý)
    # ----------------------------------------------------------
    grades = [
        ('SV01', 'HP01', 8.5, 'NV01'),
        ('SV01', 'HP02', 7.0, 'NV01'),
        ('SV02', 'HP01', 9.0, 'NV01'),
        ('SV03', 'HP03', 6.5, 'NV01'),
        ('SV04', 'HP01', 7.5, 'NV02'),
        ('SV05', 'HP04', 8.0, 'NV02'),
        ('SV06', 'HP01', 7.5, 'NV03'),
        ('SV07', 'HP03', 8.0, 'NV03'),
    ]
    for masv, mahp, diem, manv in grades:
        diem_encrypted = rsa_encrypt(employee_keys[manv], str(diem))
        cursor.execute(
            'EXEC SP_INS_BANGDIEM ?, ?, ?, ?',
            masv, mahp, diem_encrypted, manv,
        )
        print(f'  + Điểm {masv}/{mahp}: {diem}')

    conn.commit()
    conn.close()

    print()
    print('=' * 50)
    print('Seed dữ liệu thành công!')
    print('=' * 50)
    print()
    print('Tài khoản đăng nhập:')
    print('  NV01 / abcd12  (quản lý LOP01, LOP02)')
    print('  NV02 / xyz789  (quản lý LOP03)')
    print('  NV03 / abcd12  (quản lý LOP04)')


if __name__ == '__main__':
    seed()
