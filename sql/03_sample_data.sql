USE QLSVNhom;
GO

-- Thêm học phần
EXEC SP_INS_HOCPHAN 'HP01', N'Cơ sở dữ liệu', 4;
EXEC SP_INS_HOCPHAN 'HP02', N'Lập trình web', 3;
EXEC SP_INS_HOCPHAN 'HP03', N'An toàn thông tin', 3;
EXEC SP_INS_HOCPHAN 'HP04', N'Mạng máy tính', 3;
GO

-- Thêm nhân viên (mật khẩu sẽ được hash SHA2_256, lương mã hóa RSA_2048)
EXEC SP_INS_PUBLIC_NHANVIEN 'NV01', N'Nguyễn Văn A', 'NVA@fit.edu.vn', 3000000, 'NVA', 'abcd12';
EXEC SP_INS_PUBLIC_NHANVIEN 'NV02', N'Trần Thị B', 'TTB@fit.edu.vn', 5000000, 'TTB', 'xyz789';
EXEC SP_INS_PUBLIC_NHANVIEN 'NV03', N'Nguyễn Minh C', 'NMC@fit.edu.vn', 4000000, 'NMC', 'abcd12';
GO

-- Thêm lớp (NV01 quản lý LOP01, LOP02; NV02 quản lý LOP03)
EXEC SP_INS_LOP 'LOP01', N'CNTT K20 - Nhóm 1', 'NV01';
EXEC SP_INS_LOP 'LOP02', N'CNTT K20 - Nhóm 2', 'NV01';
EXEC SP_INS_LOP 'LOP03', N'CNTT K21 - Nhóm 1', 'NV02';
EXEC SP_INS_LOP 'LOP04', N'CNTT K21 - Nhóm 2', 'NV03';
GO

-- Thêm sinh viên
EXEC SP_INS_SINHVIEN 'SV01', N'Lê Văn C', '2002-05-15', N'123 Nguyễn Trãi, Q5', 'LOP01', 'LVC', 'sv1234';
EXEC SP_INS_SINHVIEN 'SV02', N'Phạm Thị D', '2002-08-20', N'456 Lê Lợi, Q1', 'LOP01', 'PTD', 'sv5678';
EXEC SP_INS_SINHVIEN 'SV03', N'Hoàng Văn E', '2003-01-10', N'789 Cách Mạng, Q3', 'LOP02', 'HVE', 'sv9012';
EXEC SP_INS_SINHVIEN 'SV04', N'Ngô Thị F', '2003-03-25', N'321 Hai Bà Trưng, Q1', 'LOP03', 'NTF', 'sv3456';
EXEC SP_INS_SINHVIEN 'SV05', N'Đỗ Văn G', '2003-07-12', N'654 Pasteur, Q3', 'LOP03', 'DVG', 'sv7890';
EXEC SP_INS_SINHVIEN 'SV06', N'Nguyễn Minh H', '2003-04-12', N'420 Bùi Thị Xuân, Q1', 'LOP04', 'NMH', 'sv7890';
EXEC SP_INS_SINHVIEN 'SV07', N'Trần Thị I', '2003-07-01', N'13 Lê Văn Khương, Q12', 'LOP04', 'TTI', 'sv7891';

GO

-- Thêm điểm (mã hóa bằng public key của nhân viên quản lý)
-- NV01 nhập điểm cho SV01, SV02 (LOP01) và SV03 (LOP02)
EXEC SP_INS_BANGDIEM 'SV01', 'HP01', 8.5, 'NV01';
EXEC SP_INS_BANGDIEM 'SV01', 'HP02', 7.0, 'NV01';
EXEC SP_INS_BANGDIEM 'SV02', 'HP01', 9.0, 'NV01';
EXEC SP_INS_BANGDIEM 'SV03', 'HP03', 6.5, 'NV01';

-- NV02 nhập điểm cho SV04, SV05 (LOP03)
EXEC SP_INS_BANGDIEM 'SV04', 'HP01', 7.5, 'NV02';
EXEC SP_INS_BANGDIEM 'SV05', 'HP04', 8.0, 'NV02';

-- NV03 nhập điểm cho SV06, SV07 (LOP04)
EXEC SP_INS_BANGDIEM 'SV06', 'HP01', 7.5, 'NV03';
EXEC SP_INS_BANGDIEM 'SV07', 'HP03', 8.0, 'NV03';
GO

PRINT N'Thêm dữ liệu mẫu thành công!';
PRINT N'';
PRINT N'Tài khoản đăng nhập:';
PRINT N'  NV01 / abcd12  (quản lý LOP01, LOP02)';
PRINT N'  NV02 / xyz789  (quản lý LOP03)';
PRINT N'  NV03 / abcd12  (quản lý LOP04)';
GO
