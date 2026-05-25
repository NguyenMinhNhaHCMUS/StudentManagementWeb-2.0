USE QLSVNhom1;
GO

-- Xóa dữ liệu theo thứ tự FK
DELETE FROM BANGDIEM;
DELETE FROM SINHVIEN;
DELETE FROM LOP;
DELETE FROM NHANVIEN;
DELETE FROM HOCPHAN;

PRINT N'Đã xóa toàn bộ dữ liệu!';
PRINT N'Lưu ý: Xóa thủ công các file khóa trong thư mục keys/ nếu cần.';
GO
