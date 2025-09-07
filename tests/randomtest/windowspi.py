import winreg

def get_windows_product_id():
    try:
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"

        # 👇 关键：添加 winreg.KEY_WOW64_64KEY 强制访问 64 位注册表
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            key_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY  # ← 这行是关键！
        )

        product_id, regtype = winreg.QueryValueEx(key, "ProductId")
        winreg.CloseKey(key)

        if isinstance(product_id, str) and product_id.strip():
            return product_id.strip()
        else:
            print("⚠️ ProductId 为空或无效")
            return None

    except FileNotFoundError:
        print("❌ 注册表路径不存在（请检查是否加了 KEY_WOW64_64KEY）")
        return None
    except PermissionError:
        print("❌ 权限不足")
        return None
    except Exception as e:
        print(f"❌ 读取注册表时出错: {e}")
        return None

# 调用
pid = get_windows_product_id()
if pid:
    print(f"✅ Windows Product ID (via winreg 64-bit): {pid}")
else:
    print("❌ 未能获取 Product ID")