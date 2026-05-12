import http.server
import socket
import socketserver
import sys
import os
from random import randint

# 1. 获取并显示所有启用的网卡 IPv4 地址
def show_ip_addresses():
    hostname = socket.gethostname()
    try:
        # 获取本机所有 IP 地址
        ip_list = socket.gethostbyname_ex(hostname)[2]
        # 过滤掉本地回环地址(127.x.x.x)，只保留实际可用的局域网 IPv4 地址
        valid_ips = [ip for ip in ip_list if not ip.startswith("127.")]

        print("\n" + "="*30)
        if valid_ips:
            print("本机可用的 IPv4 地址：")
            for ip in valid_ips:
                print(f"  -> {ip}")
        else:
            print("未找到可用的局域网 IPv4 地址")
        print("="*30 + "\n")
    except Exception as e:
        print(f"获取 IP 地址失败: {e}\n")

# 2. 解析命令行参数（端口和路径）
PORT = 8000
DIRECTORY = "."

if len(sys.argv) > 1:
    # 如果第一个参数是数字，则视为端口
    if sys.argv[1].isdigit():
        PORT = int(sys.argv[1])
    else:
        # 否则视为路径
        DIRECTORY = sys.argv[1]

if len(sys.argv) > 2:
    # 如果有两个参数，则分别为端口和路径（或路径和端口）
    if sys.argv[2].isdigit():
        PORT = int(sys.argv[2])
    else:
        DIRECTORY = sys.argv[2]

# 3. 切换到指定的共享目录
try:
    os.chdir(DIRECTORY)
    print(f"已指定共享目录: {os.getcwd()}")
except FileNotFoundError:
    print(f"错误：找不到指定的目录 '{DIRECTORY}'")
    sys.exit(1)

# 4. 启动 Web 服务器
if __name__ == "__main__":
    for i in range(10):  # 最多尝试30个端口
        try:
            with socketserver.TCPServer(("", PORT), http.server.SimpleHTTPRequestHandler) as httpd:
                show_ip_addresses()

                print(f"-> 轻量化 Python Web 服务器已启动！")
                print(f"-> 工作目录：{os.getcwd()}")
                print(f"-> 本地访问地址: http://localhost:{PORT}")
                print("按 Ctrl+C 可停止服务器\n")
                try:
                    httpd.serve_forever()
                except KeyboardInterrupt:
                    print("\n服务器已手动停止。")
                    httpd.server_close()
            break  # 成功启动服务器后退出循环
        except OSError as e:
            if i > 2:
                PORT = randint(10000, 65535)  # 在10000-65535范围内随机选择一个端口
            else:
                PORT += 1
            print(f"启动服务器失败, 尝试新端口{PORT}")
    else:
        print("错误：无法启动服务器，所有尝试的端口都被占用。请尝试手动指定一个未被占用的端口。")