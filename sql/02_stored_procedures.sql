USE QLSVNhom1;
GO

-- ============================================================
-- Lab 04: Stored Procedures
-- Tất cả mã hóa/giải mã được thực hiện ở phía CLIENT
-- Stored procedures chỉ lưu trữ và truy vấn dữ liệu đã mã hóa
-- ============================================================

-- ============================================================
-- SP_INS_PUBLIC_ENCRYPT_NHANVIEN
-- Thêm mới nhân viên với dữ liệu đã được mã hóa từ client:
--   MATKHAU → đã hash SHA2_256 từ client
--   LUONG   → đã mã hóa RSA 2048 từ client
--   PUBKEY  → khóa công khai PEM từ client
-- ============================================================
CREATE OR ALTER PROCEDURE SP_INS_PUBLIC_ENCRYPT_NHANVIEN
    @MANV       VARCHAR(20),
    @HOTEN      NVARCHAR(100),
    @EMAIL      VARCHAR(20),
    @LUONG      VARBINARY(MAX),     -- Đã mã hóa RSA từ client
    @TENDN      NVARCHAR(100),
    @MK         VARBINARY(MAX),     -- Đã hash SHA2_256 từ client
    @PUB        NVARCHAR(MAX)       -- Khóa công khai PEM từ client
AS
BEGIN
    SET NOCOUNT ON;

    -- Chỉ lưu trữ dữ liệu đã mã hóa, không mã hóa tại server
    INSERT INTO NHANVIEN (MANV, HOTEN, EMAIL, LUONG, TENDN, MATKHAU, PUBKEY)
    VALUES (@MANV, @HOTEN, @EMAIL, @LUONG, @TENDN, @MK, @PUB);

    PRINT N'Thêm nhân viên thành công: ' + @MANV;
END
GO

-- ============================================================
-- SP_SEL_PUBLIC_ENCRYPT_NHANVIEN
-- Truy vấn nhân viên: xác thực và trả về lương đã mã hóa
-- Client sẽ tự giải mã lương bằng private key
-- ============================================================
CREATE OR ALTER PROCEDURE SP_SEL_PUBLIC_ENCRYPT_NHANVIEN
    @MANV       VARCHAR(20),
    @MK         VARBINARY(MAX)      -- Hash SHA2_256 để xác thực
AS
BEGIN
    SET NOCOUNT ON;

    SELECT
        NV.MANV,
        NV.HOTEN,
        NV.EMAIL,
        NV.LUONG            -- Trả về lương đã mã hóa (client tự giải mã)
    FROM NHANVIEN NV
    WHERE NV.MANV = @MANV AND NV.MATKHAU = @MK;
END
GO

-- ============================================================
-- SP_LOGIN
-- Xác thực đăng nhập: so sánh hash đã tạo từ client
-- Trả về thông tin nhân viên (không gồm PUBKEY)
-- ============================================================
CREATE OR ALTER PROCEDURE SP_LOGIN
    @MANV       VARCHAR(20),
    @MK         VARBINARY(MAX)      -- Đã hash SHA2_256 từ client
AS
BEGIN
    SET NOCOUNT ON;

    -- So sánh trực tiếp hash đã tạo từ client
    SELECT MANV, HOTEN, EMAIL
    FROM NHANVIEN
    WHERE MANV = @MANV AND MATKHAU = @MK;
END
GO

-- ============================================================
-- SP_INS_SINHVIEN
-- Thêm sinh viên: mật khẩu đã hash SHA2_256 từ client
-- ============================================================
CREATE OR ALTER PROCEDURE SP_INS_SINHVIEN
    @MASV       VARCHAR(20),
    @HOTEN      NVARCHAR(100),
    @NGAYSINH   DATETIME,
    @DIACHI     NVARCHAR(200),
    @MALOP      VARCHAR(20),
    @TENDN      NVARCHAR(100),
    @MK         VARBINARY(MAX)      -- Đã hash SHA2_256 từ client
AS
BEGIN
    SET NOCOUNT ON;

    -- Lưu trực tiếp hash từ client, không hash lại
    INSERT INTO SINHVIEN (MASV, HOTEN, NGAYSINH, DIACHI, MALOP, TENDN, MATKHAU)
    VALUES (@MASV, @HOTEN, @NGAYSINH, @DIACHI, @MALOP, @TENDN, @MK);

    PRINT N'Thêm sinh viên thành công: ' + @MASV;
END
GO

-- ============================================================
-- SP_INS_LOP
-- Thêm lớp mới
-- ============================================================
CREATE OR ALTER PROCEDURE SP_INS_LOP
    @MALOP      VARCHAR(20),
    @TENLOP     NVARCHAR(100),
    @MANV       VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    INSERT INTO LOP (MALOP, TENLOP, MANV)
    VALUES (@MALOP, @TENLOP, @MANV);

    PRINT N'Thêm lớp thành công: ' + @MALOP;
END
GO

-- ============================================================
-- SP_DEL_LOP
-- Xóa lớp (chỉ được xóa nếu nhân viên quản lý lớp đó)
-- ============================================================
CREATE OR ALTER PROCEDURE SP_DEL_LOP
    @MALOP      VARCHAR(20),
    @MANV       VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    -- Kiểm tra quyền quản lý
    IF NOT EXISTS (SELECT 1 FROM LOP WHERE MALOP = @MALOP AND MANV = @MANV)
    BEGIN
        RAISERROR(N'Bạn không có quyền xóa lớp này!', 16, 1);
        RETURN;
    END

    -- Xóa điểm của sinh viên thuộc lớp
    DELETE BD FROM BANGDIEM BD
    INNER JOIN SINHVIEN SV ON BD.MASV = SV.MASV
    WHERE SV.MALOP = @MALOP;

    -- Xóa sinh viên thuộc lớp
    DELETE FROM SINHVIEN WHERE MALOP = @MALOP;

    -- Xóa lớp
    DELETE FROM LOP WHERE MALOP = @MALOP AND MANV = @MANV;

    PRINT N'Xóa lớp thành công: ' + @MALOP;
END
GO

-- ============================================================
-- SP_SEL_LOP_BY_NV
-- Lấy danh sách lớp do nhân viên quản lý
-- ============================================================
CREATE OR ALTER PROCEDURE SP_SEL_LOP_BY_NV
    @MANV       VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT MALOP, TENLOP, MANV
    FROM LOP
    WHERE MANV = @MANV;
END
GO

-- ============================================================
-- SP_SEL_ALL_LOP
-- Lấy tất cả các lớp
-- ============================================================
CREATE OR ALTER PROCEDURE SP_SEL_ALL_LOP
AS
BEGIN
    SET NOCOUNT ON;

    SELECT L.MALOP, L.TENLOP, L.MANV, NV.HOTEN AS TENNV
    FROM LOP L
    LEFT JOIN NHANVIEN NV ON L.MANV = NV.MANV;
END
GO

-- ============================================================
-- SP_SEL_SINHVIEN_BY_LOP
-- Lấy danh sách sinh viên theo lớp
-- ============================================================
CREATE OR ALTER PROCEDURE SP_SEL_SINHVIEN_BY_LOP
    @MALOP      VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT MASV, HOTEN, NGAYSINH, DIACHI, MALOP
    FROM SINHVIEN
    WHERE MALOP = @MALOP;
END
GO

-- ============================================================
-- SP_DEL_SINHVIEN
-- Xóa sinh viên (cùng điểm liên quan)
-- ============================================================
CREATE OR ALTER PROCEDURE SP_DEL_SINHVIEN
    @MASV       VARCHAR(20),
    @MANV       VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    -- Kiểm tra sinh viên thuộc lớp do nhân viên quản lý
    IF NOT EXISTS (
        SELECT 1 FROM SINHVIEN SV
        INNER JOIN LOP L ON SV.MALOP = L.MALOP AND L.MANV = @MANV
        WHERE SV.MASV = @MASV
    )
    BEGIN
        RAISERROR(N'Bạn không có quyền xóa sinh viên này!', 16, 1);
        RETURN;
    END

    DELETE FROM BANGDIEM WHERE MASV = @MASV;
    DELETE FROM SINHVIEN WHERE MASV = @MASV;

    PRINT N'Xóa sinh viên thành công: ' + @MASV;
END
GO

-- ============================================================
-- SP_UPDATE_SINHVIEN
-- Cập nhật thông tin sinh viên
-- ============================================================
CREATE OR ALTER PROCEDURE SP_UPDATE_SINHVIEN
    @MASV       VARCHAR(20),
    @HOTEN      NVARCHAR(100),
    @NGAYSINH   DATETIME,
    @DIACHI     NVARCHAR(200),
    @MANV       VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    -- Kiểm tra sinh viên thuộc lớp do nhân viên quản lý
    IF NOT EXISTS (
        SELECT 1 FROM SINHVIEN SV
        INNER JOIN LOP L ON SV.MALOP = L.MALOP AND L.MANV = @MANV
        WHERE SV.MASV = @MASV
    )
    BEGIN
        RAISERROR(N'Bạn không có quyền sửa sinh viên này!', 16, 1);
        RETURN;
    END

    UPDATE SINHVIEN
    SET HOTEN = @HOTEN, NGAYSINH = @NGAYSINH, DIACHI = @DIACHI
    WHERE MASV = @MASV;

    PRINT N'Cập nhật sinh viên thành công: ' + @MASV;
END
GO

-- ============================================================
-- SP_INS_BANGDIEM
-- Thêm/Cập nhật điểm: DIEMTHI đã được mã hóa RSA từ client
-- ============================================================
CREATE OR ALTER PROCEDURE SP_INS_BANGDIEM
    @MASV       VARCHAR(20),
    @MAHP       VARCHAR(20),
    @DIEMTHI    VARBINARY(MAX),     -- Đã mã hóa RSA từ client
    @MANV       VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    -- Kiểm tra sinh viên thuộc lớp do nhân viên quản lý
    IF NOT EXISTS (
        SELECT 1 FROM SINHVIEN SV
        INNER JOIN LOP L ON SV.MALOP = L.MALOP AND L.MANV = @MANV
        WHERE SV.MASV = @MASV
    )
    BEGIN
        RAISERROR(N'Bạn không có quyền nhập điểm cho sinh viên này!', 16, 1);
        RETURN;
    END

    -- Lưu trực tiếp dữ liệu đã mã hóa từ client
    IF EXISTS (SELECT 1 FROM BANGDIEM WHERE MASV = @MASV AND MAHP = @MAHP)
    BEGIN
        UPDATE BANGDIEM
        SET DIEMTHI = @DIEMTHI
        WHERE MASV = @MASV AND MAHP = @MAHP;
    END
    ELSE
    BEGIN
        INSERT INTO BANGDIEM (MASV, MAHP, DIEMTHI)
        VALUES (@MASV, @MAHP, @DIEMTHI);
    END

    PRINT N'Nhập điểm thành công!';
END
GO

-- ============================================================
-- SP_SEL_BANGDIEM
-- Truy vấn bảng điểm: trả về DIEMTHI đã mã hóa
-- Client sẽ tự giải mã bằng private key
-- ============================================================
CREATE OR ALTER PROCEDURE SP_SEL_BANGDIEM
    @MASV       VARCHAR(20),
    @MANV       VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    -- Kiểm tra quyền quản lý
    IF NOT EXISTS (
        SELECT 1 FROM SINHVIEN SV
        INNER JOIN LOP L ON SV.MALOP = L.MALOP AND L.MANV = @MANV
        WHERE SV.MASV = @MASV
    )
    BEGIN
        RAISERROR(N'Bạn không có quyền xem bảng điểm của sinh viên này!', 16, 1);
        RETURN;
    END

    SELECT
        BD.MASV,
        BD.MAHP,
        HP.TENHP,
        BD.DIEMTHI      -- Trả về dữ liệu đã mã hóa (client tự giải mã)
    FROM BANGDIEM BD
    INNER JOIN HOCPHAN HP ON BD.MAHP = HP.MAHP
    WHERE BD.MASV = @MASV;
END
GO


-- ============================================================
-- SP_SEL_ALL_HOCPHAN
-- Lấy tất cả học phần
-- ============================================================
CREATE OR ALTER PROCEDURE SP_SEL_ALL_HOCPHAN
AS
BEGIN
    SET NOCOUNT ON;

    SELECT MAHP, TENHP, SOTC
    FROM HOCPHAN;
END
GO

-- ============================================================
-- SP_SEL_ALL_NHANVIEN_BASIC
-- Lấy danh sách nhân viên (thông tin cơ bản)
-- ============================================================
CREATE OR ALTER PROCEDURE SP_SEL_ALL_NHANVIEN_BASIC
AS
BEGIN
    SET NOCOUNT ON;

    SELECT MANV, HOTEN, EMAIL
    FROM NHANVIEN;
END
GO

-- ============================================================
-- SP_SEL_NHANVIEN_PUBKEY
-- Lấy khóa công khai của nhân viên
-- ============================================================
CREATE OR ALTER PROCEDURE SP_SEL_NHANVIEN_PUBKEY
    @MANV       VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT PUBKEY
    FROM NHANVIEN
    WHERE MANV = @MANV;
END
GO

-- ============================================================
-- SP_SEL_LOP_BY_ID
-- Lấy thông tin lớp theo mã lớp
-- ============================================================
CREATE OR ALTER PROCEDURE SP_SEL_LOP_BY_ID
    @MALOP      VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT MALOP, TENLOP, MANV
    FROM LOP
    WHERE MALOP = @MALOP;
END
GO

-- ============================================================
-- SP_CHECK_LOP_MANAGER
-- Kiểm tra nhân viên có quản lý lớp không
-- ============================================================
CREATE OR ALTER PROCEDURE SP_CHECK_LOP_MANAGER
    @MALOP      VARCHAR(20),
    @MANV       VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT 1 AS IS_MANAGER
    FROM LOP
    WHERE MALOP = @MALOP AND MANV = @MANV;
END
GO

-- ============================================================
-- SP_SEL_SINHVIEN_BY_ID
-- Lấy thông tin sinh viên theo mã sinh viên và lớp
-- ============================================================
CREATE OR ALTER PROCEDURE SP_SEL_SINHVIEN_BY_ID
    @MASV       VARCHAR(20),
    @MALOP      VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT MASV, HOTEN, MALOP
    FROM SINHVIEN
    WHERE MASV = @MASV AND MALOP = @MALOP;
END
GO

-- ============================================================
-- SP_INS_HOCPHAN
-- Thêm học phần mới
-- ============================================================
CREATE OR ALTER PROCEDURE SP_INS_HOCPHAN
    @MAHP       VARCHAR(20),
    @TENHP      NVARCHAR(100),
    @SOTC       INT
AS
BEGIN
    SET NOCOUNT ON;

    INSERT INTO HOCPHAN (MAHP, TENHP, SOTC)
    VALUES (@MAHP, @TENHP, @SOTC);

    PRINT N'Thêm học phần thành công: ' + @MAHP;
END
GO

PRINT N'Tạo tất cả Stored Procedures thành công!';
GO
