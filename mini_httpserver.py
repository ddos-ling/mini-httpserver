import http.server
import argparse
import html
import hashlib
import io
import socket
import socketserver
import sys
import os
import shutil
import time
from collections import defaultdict, deque
from email.parser import BytesParser
from email.policy import default
from random import randint, choices
from string import ascii_lowercase
from urllib.parse import parse_qs, urlencode, urlsplit

VERSION = "1.2.1"
BUILD_TIMESTAMP = ""
BUILDBY = ""

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

# 2. 默认配置与状态
# 基础运行参数
PORT = 8000  # HTTP 服务监听端口
DIRECTORY = "."  # 共享目录路径（启动后会切换到该目录）
UPLOAD_AUTH_CODE = f"{randint(100000, 999999)}"  # 上传时需要校验的授权码
AUTH_CODE_FROM_CLI = False  # 授权码是否由命令行显式指定

# 上传与文件名安全
MAX_UPLOAD_SIZE = 500 * 1024 * 1024  # 单次上传大小上限（500MB，<=0 表示禁用）
INVALID_FILENAME_CHARS = set('<>:"/\\|?*\x00')  # 禁止出现在文件名中的非法字符集合

# 风控开关
ENABLE_PATH_SAFETY = True  # 启用路径安全校验（防止越权路径写入）
ENABLE_DISK_SPACE_CHECK = True  # 启用磁盘剩余空间校验
ENABLE_IP_RATE_LIMIT = True  # 启用单 IP 上传频率限制
ENABLE_VIOLATION_LIMIT = True  # 启用单 IP 违规次数封禁
ENABLE_DUPLICATE_LARGE_CHECK = True  # 启用大文件短时重复上传检测
ENABLE_FREQUENT_SMALL_CHECK = True  # 启用小文件短时频繁重复上传检测
ENABLE_REJECT_LOCKOUT = True  # 启用拒绝次数触发的临时锁定

# 风控阈值
IP_RATE_WINDOW_SECONDS = 30  # 频率限制统计窗口时长（秒）
IP_RATE_MAX_REQUESTS = 60  # 统计窗口内单 IP 最大上传请求数
VIOLATION_LIMIT_PER_IP = 10  # 单 IP 允许的最大违规次数

LARGE_FILE_THRESHOLD = 100 * 1024 * 1024  # 判定“大文件”的体积阈值（字节）
LARGE_REPEAT_WINDOW_SECONDS = 120  # 大文件重复上传统计窗口（秒）
LARGE_REPEAT_MAX_TIMES = 2  # 窗口内同一大文件允许重复次数

SMALL_FILE_THRESHOLD = 1024 * 1024  # 判定“小文件”的体积阈值（字节）
SMALL_REPEAT_WINDOW_SECONDS = 60  # 小文件频繁上传统计窗口（秒）
SMALL_REPEAT_MAX_TIMES = 16  # 窗口内同一小文件允许重复次数

REJECT_COUNT_WINDOW_SECONDS = 120  # 拒绝次数统计窗口（秒）
REJECT_COUNT_THRESHOLD = 6  # 触发临时锁定前的拒绝次数阈值
REJECT_LOCKOUT_SECONDS = 60  # 触发后 IP 被临时锁定的时长（秒）

# 运行时内存状态（按 IP 追踪）
IP_UPLOAD_TIMES = defaultdict(deque)  # 记录每个 IP 的上传时间戳队列（用于频率限制）
IP_VIOLATIONS = defaultdict(int)  # 记录每个 IP 的累计违规次数
IP_LARGE_EVENTS = defaultdict(deque)  # 记录每个 IP 的大文件上传事件（时间戳+哈希）
IP_SMALL_EVENTS = defaultdict(deque)  # 记录每个 IP 的小文件上传事件（时间戳+哈希）
IP_REJECT_TIMES = defaultdict(deque)  # 记录每个 IP 的被拒绝时间戳（用于临时锁定判断）
IP_LOCKED_UNTIL = defaultdict(float)  # 记录每个 IP 的临时锁定截止时间戳


def mask_auth_code(code):
    if len(code) <= 3:
        return code
    return code[:3] + "*" * (len(code) - 3)


def bi(zh_text, en_text):
    return f"{zh_text} / {en_text}"


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="轻量化 Python Web 服务器（支持上传与安全风控）"
    )
    parser.add_argument("legacy", nargs="*", help="兼容旧参数：端口和路径")

    parser.add_argument("--port", type=int, help="监听端口")
    parser.add_argument("--directory", type=str, help="共享目录")
    parser.add_argument("--auth-code", type=str, help="手动指定上传授权码")
    parser.add_argument("--max-upload-size", type=int, help="最大上传大小（字节），<=0 禁用")

    parser.add_argument("--disable-path-safety", action="store_true", help="禁用路径安全校验")
    parser.add_argument("--disable-disk-space-check", action="store_true", help="禁用磁盘剩余空间校验")
    parser.add_argument("--disable-ip-rate-limit", action="store_true", help="禁用单 IP 上传频率限制")
    parser.add_argument("--disable-violation-limit", action="store_true", help="禁用单 IP 违规次数限制")
    parser.add_argument("--disable-duplicate-large-check", action="store_true", help="禁用大文件短时重复上传限制")
    parser.add_argument("--disable-frequent-small-check", action="store_true", help="禁用小文件短时频繁上传限制")
    parser.add_argument("--disable-reject-lockout", action="store_true", help="禁用拒绝次数触发的临时 IP 封禁")

    parser.add_argument("--ip-rate-window", type=int, help="单 IP 频率统计窗口（秒）")
    parser.add_argument("--ip-rate-max", type=int, help="单 IP 窗口内最大上传次数")
    parser.add_argument("--violation-limit", type=int, help="单 IP 最大违规次数（超过后封禁）")

    parser.add_argument("--large-file-threshold", type=int, help="判定大文件阈值（字节）")
    parser.add_argument("--large-repeat-window", type=int, help="大文件重复统计窗口（秒）")
    parser.add_argument("--large-repeat-max", type=int, help="大文件重复允许次数")

    parser.add_argument("--small-file-threshold", type=int, help="判定小文件阈值（字节）")
    parser.add_argument("--small-repeat-window", type=int, help="小文件频繁统计窗口（秒）")
    parser.add_argument("--small-repeat-max", type=int, help="小文件重复允许次数")

    parser.add_argument("--reject-count-window", type=int, help="拒绝次数统计窗口（秒）")
    parser.add_argument("--reject-count-threshold", type=int, help="窗口内触发封禁的拒绝次数")
    parser.add_argument("--reject-lockout-seconds", type=int, help="触发后 IP 封禁时长（秒）")
    return parser


def apply_runtime_config():
    global PORT, DIRECTORY, UPLOAD_AUTH_CODE, AUTH_CODE_FROM_CLI, MAX_UPLOAD_SIZE
    global ENABLE_PATH_SAFETY, ENABLE_DISK_SPACE_CHECK, ENABLE_IP_RATE_LIMIT
    global ENABLE_VIOLATION_LIMIT, ENABLE_DUPLICATE_LARGE_CHECK, ENABLE_FREQUENT_SMALL_CHECK
    global ENABLE_REJECT_LOCKOUT
    global IP_RATE_WINDOW_SECONDS, IP_RATE_MAX_REQUESTS, VIOLATION_LIMIT_PER_IP
    global LARGE_FILE_THRESHOLD, LARGE_REPEAT_WINDOW_SECONDS, LARGE_REPEAT_MAX_TIMES
    global SMALL_FILE_THRESHOLD, SMALL_REPEAT_WINDOW_SECONDS, SMALL_REPEAT_MAX_TIMES
    global REJECT_COUNT_WINDOW_SECONDS, REJECT_COUNT_THRESHOLD, REJECT_LOCKOUT_SECONDS

    # 统一读取命令行参数并覆盖默认配置
    args = build_arg_parser().parse_args()

    # 兼容旧参数顺序：script.py [port|directory] [port|directory]
    if len(args.legacy) > 0:
        if args.legacy[0].isdigit():
            PORT = int(args.legacy[0])
        else:
            DIRECTORY = args.legacy[0]

    if len(args.legacy) > 1:
        if args.legacy[1].isdigit():
            PORT = int(args.legacy[1])
        else:
            DIRECTORY = args.legacy[1]

    # 显式参数优先级高于旧式位置参数
    if args.port is not None:
        PORT = args.port
    if args.directory:
        DIRECTORY = args.directory

    if args.auth_code is not None:
        UPLOAD_AUTH_CODE = args.auth_code
        AUTH_CODE_FROM_CLI = True

    if args.max_upload_size is not None:
        MAX_UPLOAD_SIZE = args.max_upload_size

    # 安全开关：按需禁用对应能力
    if args.disable_path_safety:
        ENABLE_PATH_SAFETY = False
    if args.disable_disk_space_check:
        ENABLE_DISK_SPACE_CHECK = False
    if args.disable_ip_rate_limit:
        ENABLE_IP_RATE_LIMIT = False
    if args.disable_violation_limit:
        ENABLE_VIOLATION_LIMIT = False
    if args.disable_duplicate_large_check:
        ENABLE_DUPLICATE_LARGE_CHECK = False
    if args.disable_frequent_small_check:
        ENABLE_FREQUENT_SMALL_CHECK = False
    if args.disable_reject_lockout:
        ENABLE_REJECT_LOCKOUT = False

    # 数值阈值：尽量做最小值保护，避免 0 秒窗口等无意义配置
    if args.ip_rate_window is not None:
        IP_RATE_WINDOW_SECONDS = max(1, args.ip_rate_window)
    if args.ip_rate_max is not None:
        IP_RATE_MAX_REQUESTS = args.ip_rate_max
    if args.violation_limit is not None:
        VIOLATION_LIMIT_PER_IP = args.violation_limit

    if args.large_file_threshold is not None:
        LARGE_FILE_THRESHOLD = args.large_file_threshold
    if args.large_repeat_window is not None:
        LARGE_REPEAT_WINDOW_SECONDS = max(1, args.large_repeat_window)
    if args.large_repeat_max is not None:
        LARGE_REPEAT_MAX_TIMES = args.large_repeat_max

    if args.small_file_threshold is not None:
        SMALL_FILE_THRESHOLD = args.small_file_threshold
    if args.small_repeat_window is not None:
        SMALL_REPEAT_WINDOW_SECONDS = max(1, args.small_repeat_window)
    if args.small_repeat_max is not None:
        SMALL_REPEAT_MAX_TIMES = args.small_repeat_max

    if args.reject_count_window is not None:
        REJECT_COUNT_WINDOW_SECONDS = max(1, args.reject_count_window)
    if args.reject_count_threshold is not None:
        REJECT_COUNT_THRESHOLD = args.reject_count_threshold
    if args.reject_lockout_seconds is not None:
        REJECT_LOCKOUT_SECONDS = max(0, args.reject_lockout_seconds)


class UploadHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """在目录浏览页中增加上传功能，并校验控制台授权码。"""

    def _get_lockout_remaining_seconds(self, now):
        if not ENABLE_REJECT_LOCKOUT or REJECT_COUNT_THRESHOLD <= 0 or REJECT_LOCKOUT_SECONDS <= 0:
            return 0
        ip = self._client_ip()
        remain = int(IP_LOCKED_UNTIL[ip] - now)
        return remain if remain > 0 else 0

    def _record_reject_and_maybe_lock(self, now):
        if not ENABLE_REJECT_LOCKOUT or REJECT_COUNT_THRESHOLD <= 0 or REJECT_LOCKOUT_SECONDS <= 0:
            return

        ip = self._client_ip()
        bucket = IP_REJECT_TIMES[ip]
        self._prune_timestamps(bucket, REJECT_COUNT_WINDOW_SECONDS, now)
        bucket.append(now)

        # 超过阈值时进入临时封禁
        if len(bucket) > REJECT_COUNT_THRESHOLD:
            IP_LOCKED_UNTIL[ip] = now + REJECT_LOCKOUT_SECONDS
            # 触发临时封禁时同时重置该 IP 的长期违规计数，避免封禁过期后仍被长期封禁
            IP_VIOLATIONS[ip] = 0
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print(f"[SECURITY][{timestamp}] ip={ip} temporary lockout for {REJECT_LOCKOUT_SECONDS} seconds due to repeated rejects")
            bucket.clear()

    def _client_ip(self):
        return self.client_address[0] if self.client_address else "unknown"

    def _is_ip_blocked(self):
        if not ENABLE_VIOLATION_LIMIT or VIOLATION_LIMIT_PER_IP < 0:
            return False
        ip = self._client_ip()
        return IP_VIOLATIONS[ip] > VIOLATION_LIMIT_PER_IP

    def _send_utf8_error(self, status_code, message):
        body = (message + "\n").encode("utf-8", errors="replace")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # 拦截场景下主动关闭连接，避免未读取完的请求体影响后续请求。
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _redirect_with_error_banner(self, status_code, message):
        base_path = urlsplit(self.path).path or "/"
        location = f"{base_path}?{urlencode({'upload_error': message, 'error_code': status_code})}"
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _log_intercept(self, status_code, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        ip = self._client_ip()
        path = self.path if self.path else "/"
        print(f"[SECURITY][{timestamp}] ip={ip} method={self.command} path={path} status={status_code} reason={message}")

    def _reject(self, status_code, message, mark_violation=False):
        now = time.time()

        if mark_violation:
            self._record_reject_and_maybe_lock(now)

        lock_remaining = self._get_lockout_remaining_seconds(now)
        if lock_remaining > 0:
            lock_msg = bi(
                f"拒绝次数过多，当前 IP 已被限制上传 {lock_remaining} 秒",
                f"Too many rejected requests, this IP is blocked for {lock_remaining} seconds",
            )
            self._log_intercept(429, lock_msg)
            if self.command == "POST":
                self._redirect_with_error_banner(429, lock_msg)
            else:
                self._send_utf8_error(429, lock_msg)
            return

        # 记录违规并在超阈值后直接封禁该 IP
        if mark_violation:
            ip = self._client_ip()
            IP_VIOLATIONS[ip] += 1
            if ENABLE_VIOLATION_LIMIT and VIOLATION_LIMIT_PER_IP >= 0 and IP_VIOLATIONS[ip] > VIOLATION_LIMIT_PER_IP:
                violation_msg = bi(
                    f"该 IP 违规次数超过限制（{VIOLATION_LIMIT_PER_IP}），已拒绝上传",
                    f"IP violations exceeded limit ({VIOLATION_LIMIT_PER_IP}), upload denied",
                )
                self._log_intercept(429, violation_msg)
                if self.command == "POST":
                    self._redirect_with_error_banner(429, violation_msg)
                else:
                    self._send_utf8_error(429, violation_msg)
                return
        self._log_intercept(status_code, message)
        if self.command == "POST":
            self._redirect_with_error_banner(status_code, message)
        else:
            self._send_utf8_error(status_code, message)

    @staticmethod
    def _prune_timestamps(bucket, window_seconds, now):
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()

    @staticmethod
    def _prune_events(bucket, window_seconds, now):
        while bucket and now - bucket[0][0] > window_seconds:
            bucket.popleft()

    def _check_rate_limit(self, now):
        # 单 IP 上传频率控制
        if not ENABLE_IP_RATE_LIMIT or IP_RATE_MAX_REQUESTS <= 0:
            return True

        ip = self._client_ip()
        bucket = IP_UPLOAD_TIMES[ip]
        self._prune_timestamps(bucket, IP_RATE_WINDOW_SECONDS, now)

        if len(bucket) >= IP_RATE_MAX_REQUESTS:
            self._reject(429, bi("上传请求过于频繁，请稍后再试", "Too many upload requests, please try again later"), mark_violation=True)
            return False

        bucket.append(now)
        return True

    def _check_duplicate_risk(self, file_bytes, now):
        # 通过文件哈希识别“相同文件”，分别执行大文件/小文件风控
        ip = self._client_ip()
        file_size = len(file_bytes)
        digest = hashlib.sha256(file_bytes).hexdigest()

        if ENABLE_DUPLICATE_LARGE_CHECK and LARGE_REPEAT_MAX_TIMES > 0 and LARGE_FILE_THRESHOLD > 0 and file_size >= LARGE_FILE_THRESHOLD:
            large_bucket = IP_LARGE_EVENTS[ip]
            self._prune_events(large_bucket, LARGE_REPEAT_WINDOW_SECONDS, now)
            same_count = sum(1 for _, saved_digest in large_bucket if saved_digest == digest)
            if same_count >= LARGE_REPEAT_MAX_TIMES:
                self._reject(
                    429,
                    bi("检测到短时间内重复上传大文件，已触发风控", "Repeated large file uploads detected in a short time, risk control triggered"),
                    mark_violation=True,
                )
                return False
            large_bucket.append((now, digest))

        if ENABLE_FREQUENT_SMALL_CHECK and SMALL_REPEAT_MAX_TIMES > 0 and SMALL_FILE_THRESHOLD >= 0 and file_size <= SMALL_FILE_THRESHOLD:
            small_bucket = IP_SMALL_EVENTS[ip]
            self._prune_events(small_bucket, SMALL_REPEAT_WINDOW_SECONDS, now)
            same_count = sum(1 for _, saved_digest in small_bucket if saved_digest == digest)
            if same_count >= SMALL_REPEAT_MAX_TIMES:
                self._reject(
                    429,
                    bi("检测到短时间内频繁上传相同小文件，已触发风控", "Frequent uploads of identical small files detected, risk control triggered"),
                    mark_violation=True,
                )
                return False
            small_bucket.append((now, digest))

        return True

    def list_directory(self, path):
        try:
            entries = sorted(os.listdir(path), key=lambda x: x.lower())
        except OSError:
            self.send_error(404, "No permission to list directory")
            return None

        def format_size(num_bytes):
            if num_bytes < 0:
                return "-"
            units = ["B", "KB", "MB", "GB", "TB"]
            size = float(num_bytes)
            unit_index = 0
            while size >= 1024 and unit_index < len(units) - 1:
                size /= 1024
                unit_index += 1
            if unit_index == 0:
                return f"{int(size)} {units[unit_index]}"
            return f"{size:.2f} {units[unit_index]}"

        def format_mtime(timestamp):
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

        parsed_request = urlsplit(self.path)
        request_path = parsed_request.path or "/"
        request_query = parse_qs(parsed_request.query)
        display_path = html.escape(request_path, quote=False)
        encoded_path = html.escape(os.path.abspath(path), quote=False)

        error_message = request_query.get("upload_error", [""])[0]
        error_code = request_query.get("error_code", [""])[0]

        page = io.StringIO()
        page.write("<!DOCTYPE html>\n")
        page.write(f"<html><head><meta charset='utf-8'><title>目录浏览 - {display_path}</title></head><body>")
        page.write(f"<h2>目录浏览 - {display_path}</h2>")
        page.write(f"<p>当前共享目录: {encoded_path}</p>")
        if error_message:
            safe_error_msg = html.escape(error_message, quote=False)
            safe_error_code = html.escape(str(error_code), quote=False)
            page.write(
                "<div style='background:#ffe5e5;border:1px solid #d60000;color:#8b0000;padding:10px 12px;border-radius:6px;margin:10px 0;'>"
                f"<strong>上传被拦截 / Upload Blocked</strong>（{safe_error_code}）：{safe_error_msg}</div>"
            )
        page.write("<p><button type='button' onclick='toggleUploadArea()' id='uploadToggleBtn'>上传文件到当前目录</button></p>")
        page.write("<div id='uploadArea' style='display:none;'>")
        page.write("<form method='post' enctype='multipart/form-data'>")
        page.write("<p><label>控制台授权码: <input type='password' name='auth_code' required></label></p>")
        page.write("<p><label>选择文件: <input type='file' name='file' required></label></p>")
        page.write("<p><button type='submit'>上传到当前目录</button></p>")
        page.write("</form>")
        page.write("</div><hr>")
        page.write("<table style='border-collapse:collapse;min-width:720px;'>")
        page.write("<thead><tr>")
        page.write("<th style='text-align:left;border-bottom:1px solid #ccc;padding:6px 10px;'>名称</th>")
        page.write("<th style='text-align:left;border-bottom:1px solid #ccc;padding:6px 10px;'>修改时间</th>")
        page.write("<th style='text-align:right;border-bottom:1px solid #ccc;padding:6px 10px;'>大小</th>")
        page.write("</tr></thead><tbody>")

        if request_path not in ("/", ""):
            parent = os.path.dirname(request_path.rstrip("/"))
            if not parent:
                parent = "/"
            page.write(
                "<tr>"
                f"<td style='padding:6px 10px;'><a href='{html.escape(parent, quote=True)}'>.. (上级目录)</a></td>"
                "<td style='padding:6px 10px;'>-</td>"
                "<td style='padding:6px 10px;text-align:right;'>-</td>"
                "</tr>"
            )

        for name in entries:
            full_name = os.path.join(path, name)
            display_name = link_name = name
            if os.path.isdir(full_name):
                display_name = name + "/"
                link_name = name + "/"
            elif os.path.islink(full_name):
                display_name = name + "@"

            try:
                stat_result = os.stat(full_name)
                modified_time = format_mtime(stat_result.st_mtime)
                if os.path.isdir(full_name):
                    size_text = "-"
                else:
                    size_text = format_size(stat_result.st_size)
            except OSError:
                modified_time = "-"
                size_text = "-"

            page.write(
                "<tr>"
                "<td style='padding:6px 10px;'><a href='%s'>%s</a></td>"
                "<td style='padding:6px 10px;'>%s</td>"
                "<td style='padding:6px 10px;text-align:right;'>%s</td>"
                "</tr>"
                % (
                    html.escape(link_name, quote=True),
                    html.escape(display_name, quote=False),
                    html.escape(modified_time, quote=False),
                    html.escape(size_text, quote=False),
                )
            )

        page.write("</tbody></table>")
        page.write("<script>")
        page.write("function toggleUploadArea(){")
        page.write("var area=document.getElementById('uploadArea');")
        page.write("var btn=document.getElementById('uploadToggleBtn');")
        page.write("var hidden=area.style.display==='none';")
        page.write("area.style.display=hidden?'block':'none';")
        page.write("btn.textContent=hidden?'收起上传区':'上传文件到当前目录';")
        page.write("}")
        page.write("</script></body></html>")
        encoded = page.getvalue().encode("utf-8", "surrogateescape")
        response = io.BytesIO(encoded)

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return response

    def do_POST(self):
        # 上传主流程：先校验请求合法性，再做风控，最后安全落盘
        now = time.time()

        lock_remaining = self._get_lockout_remaining_seconds(now)
        if lock_remaining > 0:
            self._reject(
                429,
                bi(
                    f"拒绝次数过多，当前 IP 已被限制上传 {lock_remaining} 秒",
                    f"Too many rejected requests, this IP is blocked for {lock_remaining} seconds",
                ),
            )
            return

        if self._is_ip_blocked():
            self._reject(
                429,
                bi(
                    f"该 IP 违规次数超过限制（{VIOLATION_LIMIT_PER_IP}），已拒绝上传",
                    f"IP violations exceeded limit ({VIOLATION_LIMIT_PER_IP}), upload denied",
                ),
            )
            return

        if ENABLE_PATH_SAFETY and self.path not in ("", "/"):
            self._reject(403, bi("仅允许上传到共享根目录", "Uploads are only allowed to the shared root directory"), mark_violation=True)
            return

        content_type = self.headers.get("Content-Type", "")
        if not content_type.startswith("multipart/form-data"):
            self._reject(400, bi("仅支持 multipart/form-data 上传", "Only multipart/form-data uploads are supported"), mark_violation=True)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._reject(400, bi("无效的 Content-Length", "Invalid Content-Length"), mark_violation=True)
            return

        if content_length <= 0:
            self._reject(400, bi("空请求体", "Empty request body"), mark_violation=True)
            return

        if MAX_UPLOAD_SIZE > 0 and content_length > MAX_UPLOAD_SIZE:
            self._reject(
                413,
                bi(
                    f"上传文件过大，限制为 {MAX_UPLOAD_SIZE // (1024 * 1024)}MB",
                    f"Uploaded file is too large, limit is {MAX_UPLOAD_SIZE // (1024 * 1024)}MB",
                ),
                mark_violation=True,
            )
            return

        if not self._check_rate_limit(now):
            return

        # 请求体读取后再解析 multipart 内容
        body = self.rfile.read(content_length)
        msg = BytesParser(policy=default).parsebytes(
            f"Content-Type: {content_type}\r\n\r\n".encode("utf-8") + body
        )

        if not msg.is_multipart():
            self._reject(400, bi("上传内容格式错误", "Invalid upload payload format"), mark_violation=True)
            return

        auth_code = ""
        filename = ""
        file_bytes = b""

        for part in msg.iter_parts():
            if part.get_content_disposition() != "form-data":
                continue

            field_name = part.get_param("name", header="content-disposition")
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload_bytes = payload
            elif isinstance(payload, str):
                payload_bytes = payload.encode("utf-8", errors="ignore")
            else:
                payload_bytes = b""

            if field_name == "auth_code":
                auth_code = payload_bytes.decode("utf-8", errors="ignore").strip()
            elif field_name == "file":
                raw_name = part.get_filename() or ""
                filename = os.path.basename(raw_name)
                file_bytes = payload_bytes

        if auth_code != UPLOAD_AUTH_CODE:
            self._reject(403, bi("授权码错误，拒绝上传", "Invalid authorization code, upload denied"), mark_violation=True)
            return

        if not filename:
            self._reject(400, bi("未检测到上传文件", "No uploaded file detected"), mark_violation=True)
            return

        # 文件名标准化与基础安全检查（防止特殊名称与路径注入）
        filename = filename.strip().rstrip(". ")
        if (
            not filename
            or filename in {".", ".."}
            or any(ch in INVALID_FILENAME_CHARS for ch in filename)
            or os.path.sep in filename
            or (os.path.altsep and os.path.altsep in filename)
        ):
            self._reject(400, bi("非法文件名", "Invalid file name"), mark_violation=True)
            return

        if len(filename) > 255:
            self._reject(400, bi("文件名过长", "File name is too long"), mark_violation=True)
            return

        shared_root = os.path.realpath(os.getcwd())

        # 目标路径规范化，并校验必须位于共享目录内
        target_path = os.path.realpath(os.path.join(shared_root, filename))
        if ENABLE_PATH_SAFETY and os.path.commonpath([shared_root, target_path]) != shared_root:
            self._reject(400, bi("非法路径，禁止越级写入", "Illegal path, path traversal write is blocked"), mark_violation=True)
            return

        if ENABLE_DISK_SPACE_CHECK:
            free_bytes = shutil.disk_usage(shared_root).free
            if len(file_bytes) > free_bytes:
                self._reject(
                    507,
                    bi("上传文件大小超过当前目录所在磁盘剩余空间", "Uploaded file size exceeds remaining disk space for current directory"),
                    mark_violation=True,
                )
                return

        if not self._check_duplicate_risk(file_bytes, now):
            return

        # 防覆盖：重名时追加 -xxxxxx 随机后缀
        if os.path.exists(target_path):
            base_name, ext = os.path.splitext(filename)
            while True:
                suffix = "".join(choices(ascii_lowercase, k=6))
                new_name = f"{base_name}-{suffix}{ext}"
                new_path = os.path.realpath(os.path.join(shared_root, new_name))
                if ENABLE_PATH_SAFETY and os.path.commonpath([shared_root, new_path]) != shared_root:
                    continue
                if not os.path.exists(new_path):
                    target_path = new_path
                    break

        try:
            with open(target_path, "wb") as f:
                f.write(file_bytes)
        except OSError as exc:
            self._reject(500, bi(f"保存文件失败: {exc}", f"Failed to save file: {exc}"), mark_violation=True)
            return

        self.send_response(303)
        self.send_header("Location", self.path if self.path else "/")
        self.end_headers()

apply_runtime_config()

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
            with socketserver.TCPServer(("", PORT), UploadHTTPRequestHandler) as httpd:
                show_ip_addresses()

                print(f"-> 轻量化 Web 服务器已启动！")
                print(f"-> 版本: {VERSION} by DDoS_LING")
                if BUILD_TIMESTAMP and BUILDBY:
                    print(f"-> Build by {BUILDBY} at {BUILD_TIMESTAMP}")
                print(f"-> 工作目录：{os.getcwd()}")
                print(f"-> 本地访问地址: http://localhost:{PORT}")
                if AUTH_CODE_FROM_CLI:
                    print(f"-> 上传授权码（已遮掩）: {mask_auth_code(UPLOAD_AUTH_CODE)}")
                else:
                    print(f"-> 上传授权码（控制台查看）: {UPLOAD_AUTH_CODE}")
                if MAX_UPLOAD_SIZE > 0:
                    print(f"-> 最大上传大小: {MAX_UPLOAD_SIZE} 字节")
                else:
                    print("-> 最大上传大小: 已禁用")
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









