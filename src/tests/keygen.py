from sealium.scripts.generate_activation_codes import generate_activation_codes

# 生成 10 个永久激活码
codes = generate_activation_codes(10)
print(codes)

# 生成带有效期的激活码
codes = generate_activation_codes(
    count=5,
    expires_at="2026-12-31",
    features=["premium", "enterprise"]
)

# 使用自定义数据库路径
codes = generate_activation_codes(
    count=3,
    expires_at="2027-12-31",
    db_path="../../../data/database.db"
)