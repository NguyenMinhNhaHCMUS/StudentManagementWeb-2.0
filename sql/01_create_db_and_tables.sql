-- ============================================================
-- Lab 04: Tạo Database và các bảng cho hệ thống Quản lý Sinh viên
-- Mã hóa/giải mã được thực hiện ở phía CLIENT (Python)
-- DB chỉ lưu trữ dữ liệu đã được mã hóa sẵn
-- ============================================================

-- Tạo Database
USE master;
GO

IF EXISTS (SELECT name FROM sys.databases WHERE name = N'QLSVNhom1')
BEGIN
    ALTER DATABASE QLSVNhom1 SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE QLSVNhom1;
END
GO

CREATE DATABASE QLSVNhom1;
GO

USE QLSVNhom1;
GO

CREATE TABLE SINHVIEN (
    MASV        VARCHAR(20)     PRIMARY KEY,
    HOTEN       NVARCHAR(100)   NOT NULL,
    NGAYSINH    DATETIME,
    DIACHI      NVARCHAR(200),
    MALOP       VARCHAR(20),
    TENDN       NVARCHAR(100)   NOT NULL UNIQUE,
    MATKHAU     VARBINARY(MAX)  NOT NULL        -- SHA2_256 hash (from client)
);
GO

CREATE TABLE NHANVIEN (
    MANV        VARCHAR(20)     PRIMARY KEY,
    HOTEN       NVARCHAR(100)   NOT NULL,
    EMAIL       VARCHAR(20),
    LUONG       VARBINARY(MAX),                 -- RSA encrypted (from client)
    TENDN       NVARCHAR(100)   NOT NULL UNIQUE,
    MATKHAU     VARBINARY(MAX)  NOT NULL,       -- SHA2_256 hash (from client)
    PUBKEY      NVARCHAR(MAX),                  -- PEM public key (from client)
    ROLE        INT             NOT NULL DEFAULT 0
);
GO

CREATE TABLE LOP (
    MALOP       VARCHAR(20)     PRIMARY KEY,
    TENLOP      NVARCHAR(100)   NOT NULL,
    MANV        VARCHAR(20)
);
GO

CREATE TABLE HOCPHAN (
    MAHP        VARCHAR(20)     PRIMARY KEY,
    TENHP       NVARCHAR(100)   NOT NULL,
    SOTC        INT
);
GO

CREATE TABLE BANGDIEM (
    MASV        VARCHAR(20),
    MAHP        VARCHAR(20),
    DIEMTHI     VARBINARY(MAX),                 -- RSA encrypted (from client)
    PRIMARY KEY (MASV, MAHP)
);
GO

-- Thêm khóa ngoại
ALTER TABLE SINHVIEN
    ADD CONSTRAINT FK_SINHVIEN_LOP FOREIGN KEY (MALOP) REFERENCES LOP(MALOP);
GO

ALTER TABLE LOP
    ADD CONSTRAINT FK_LOP_NHANVIEN FOREIGN KEY (MANV) REFERENCES NHANVIEN(MANV);
GO

ALTER TABLE BANGDIEM
    ADD CONSTRAINT FK_BANGDIEM_SINHVIEN FOREIGN KEY (MASV) REFERENCES SINHVIEN(MASV);
GO

ALTER TABLE BANGDIEM
    ADD CONSTRAINT FK_BANGDIEM_HOCPHAN FOREIGN KEY (MAHP) REFERENCES HOCPHAN(MAHP);
GO

PRINT N'Tạo Database và các bảng thành công!';
GO
