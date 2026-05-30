USE QLSVNhom1;
GO
--Sau khi chạy xong file này thì chạy file seed_data.py
-- Thêm học phần
EXEC SP_INS_HOCPHAN 'HP01', N'Cơ sở dữ liệu', 4;
EXEC SP_INS_HOCPHAN 'HP02', N'Lập trình web', 3;
EXEC SP_INS_HOCPHAN 'HP03', N'An toàn thông tin', 3;
EXEC SP_INS_HOCPHAN 'HP04', N'Mạng máy tính', 3;
GO

PRINT N'Thêm học phần thành công!';
PRINT N'';
PRINT N'Tiếp theo, chạy "python seed_data.py" để thêm nhân viên, lớp, sinh viên, và điểm.';
GO
