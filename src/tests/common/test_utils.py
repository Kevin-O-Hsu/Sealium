from sealium.common.utils import *

# 生成机器码
machine_code = Utils.generate_machine_code()
print(machine_code)

# 生成随机 nonce
nonce = Utils.generate_nonce(16)
print(nonce)

# 获取权威时间戳
try:
    ts = Utils.get_timestamp_from_api()
    print(ts)
except Exception as e:
    print(f"获取时间戳失败: {e}")

# 校验激活码
is_valid = Utils.validate_activation_code("ABC123")
print(is_valid)

# 检查时间戳偏差
valid = Utils.is_timestamp_valid(ts, tolerance=300)
print(valid)