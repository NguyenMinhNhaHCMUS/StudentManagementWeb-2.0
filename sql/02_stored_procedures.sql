USE QLSVNhom;
GO

-- SP_INS_PUBLIC_NHANVIEN
-- Thêm mới nhân viên:
--   MATKHAU → SHA2_256
--   LUONG   → RSA_2048 (tạo asymmetric key với tên = MANV)
--   PUBKEY  = MANV
CREATE OR ALTER PROCEDURE SP_INS_PUBLIC_NHANVIEN
    @MANV       VARCHAR(20),
    @HOTEN      NVARCHAR(100),
    @EMAIL      VARCHAR(20),
    @LUONGCB    INT,
    @TENDN      NVARCHAR(100),
    @MK         NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

    -- Mã hóa mật khẩu bằng SHA2_256
    DECLARE @MATKHAU_HASH VARBINARY(MAX);
    SET @MATKHAU_HASH = HASHBYTES('SHA2_256', @MK + @MANV);

    -- Tạo asymmetric key với tên = MANV, được bảo vệ bởi mật khẩu MK
    DECLARE @SQL NVARCHAR(MAX);
    SET @SQL = 'CREATE ASYMMETRIC KEY ' + QUOTENAME(@MANV) +
               ' WITH ALGORITHM = RSA_2048 ' +
               'ENCRYPTION BY PASSWORD = ''' + @MK + '''';
    EXEC sp_executesql @SQL;

    -- Mã hóa lương bằng public key
    DECLARE @LUONG_ENCRYPTED VARBINARY(MAX);
    SET @LUONG_ENCRYPTED = ENCRYPTBYASYMKEY(
        ASYMKEY_ID(@MANV),
        CAST(@LUONGCB AS VARCHAR(20))
    );

    -- Thêm nhân viên vào bảng
    INSERT INTO NHANVIEN (MANV, HOTEN, EMAIL, LUONG, TENDN, MATKHAU, PUBKEY)
    VALUES (@MANV, @HOTEN, @EMAIL, @LUONG_ENCRYPTED, @TENDN, @MATKHAU_HASH, @MANV);

    PRINT N'Thêm nhân viên thành công: ' + @MANV;
END
GO

-- ============================================================
-- SP_SEL_PUBLIC_NHANVIEN
-- Truy vấn nhân viên và giải mã lương
-- ============================================================
CREATE OR ALTER PROCEDURE SP_SEL_PUBLIC_NHANVIEN
    @MANV       VARCHAR(20),
    @MK         NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT
        NV.MANV,
        NV.HOTEN,
        NV.EMAIL,
        CAST(
            DECRYPTBYASYMKEY(
                ASYMKEY_ID(NV.PUBKEY),
                NV.LUONG,
                @MK
            ) AS VARCHAR(20)
        ) AS LUONGCB
    FROM NHANVIEN NV
    WHERE NV.MANV = @MANV;
END
GO

-- ============================================================
-- SP_LOGIN
-- Xác thực đăng nhập: so sánh mật khẩu đã hash
-- Trả về thông tin nhân viên nếu đúng
-- ============================================================
CREATE OR ALTER PROCEDURE SP_LOGIN
    @MANV       VARCHAR(20),
    @MK         NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @MATKHAU_HASH VARBINARY(MAX);
    SET @MATKHAU_HASH = HASHBYTES('SHA2_256', @MK + @MANV);

    SELECT MANV, HOTEN, EMAIL, PUBKEY
    FROM NHANVIEN
    WHERE MANV = @MANV AND MATKHAU = @MATKHAU_HASH;
END
GO

-- ============================================================
-- SP_INS_SINHVIEN
-- Thêm sinh viên với mật khẩu được hash SHA2_256
-- ============================================================
CREATE OR ALTER PROCEDURE SP_INS_SINHVIEN
    @MASV       VARCHAR(20),
    @HOTEN      NVARCHAR(100),
    @NGAYSINH   DATETIME,
    @DIACHI     NVARCHAR(200),
    @MALOP      VARCHAR(20),
    @TENDN      NVARCHAR(100),
    @MK         NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @MATKHAU_HASH VARBINARY(MAX);
    SET @MATKHAU_HASH = HASHBYTES('SHA2_256', @MK + @MASV);

    INSERT INTO SINHVIEN (MASV, HOTEN, NGAYSINH, DIACHI, MALOP, TENDN, MATKHAU)
    VALUES (@MASV, @HOTEN, @NGAYSINH, @DIACHI, @MALOP, @TENDN, @MATKHAU_HASH);

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
-- Lấy danh sách sinh viên theo lớp (thông tin cơ bản, không có điểm)
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
-- Thêm điểm: mã hóa DIEMTHI bằng public key của nhân viên đã đăng nhập
-- ============================================================
CREATE OR ALTER PROCEDURE SP_INS_BANGDIEM
    @MASV       VARCHAR(20),
    @MAHP       VARCHAR(20),
    @DIEMTHI    FLOAT,
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

    -- Lấy tên public key của nhân viên
    DECLARE @PUBKEY VARCHAR(20);
    SELECT @PUBKEY = PUBKEY FROM NHANVIEN WHERE MANV = @MANV;

    -- Mã hóa điểm bằng public key
    DECLARE @DIEM_ENCRYPTED VARBINARY(MAX);
    SET @DIEM_ENCRYPTED = ENCRYPTBYASYMKEY(
        ASYMKEY_ID(@PUBKEY),
        CAST(@DIEMTHI AS VARCHAR(10))
    );

    -- Kiểm tra nếu đã có điểm thì cập nhật, nếu chưa thì thêm mới
    IF EXISTS (SELECT 1 FROM BANGDIEM WHERE MASV = @MASV AND MAHP = @MAHP)
    BEGIN
        UPDATE BANGDIEM
        SET DIEMTHI = @DIEM_ENCRYPTED
        WHERE MASV = @MASV AND MAHP = @MAHP;
    END
    ELSE
    BEGIN
        INSERT INTO BANGDIEM (MASV, MAHP, DIEMTHI)
        VALUES (@MASV, @MAHP, @DIEM_ENCRYPTED);
    END

    PRINT N'Nhập điểm thành công!';
END
GO

-- ============================================================
-- SP_SEL_BANGDIEM
-- Truy vấn bảng điểm: giải mã DIEMTHI bằng private key + mật khẩu
-- ============================================================
CREATE OR ALTER PROCEDURE SP_SEL_BANGDIEM
    @MASV       VARCHAR(20),
    @MANV       VARCHAR(20),
    @MK         NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @PUBKEY VARCHAR(20);
    SELECT @PUBKEY = PUBKEY FROM NHANVIEN WHERE MANV = @MANV;

    SELECT
        BD.MASV,
        BD.MAHP,
        HP.TENHP,
        CAST(
            DECRYPTBYASYMKEY(
                ASYMKEY_ID(@PUBKEY),
                BD.DIEMTHI,
                @MK
            ) AS VARCHAR(10)
        ) AS DIEMTHI
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
