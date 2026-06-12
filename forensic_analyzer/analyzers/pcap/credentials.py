import re
import base64

_FTP_USER = re.compile(rb'USER\s+(\S+)', re.IGNORECASE)
_FTP_PASS = re.compile(rb'PASS\s+(\S+)', re.IGNORECASE)
_HTTP_AUTH = re.compile(rb'Authorization:\s*Basic\s+(\S+)', re.IGNORECASE)
_HTTP_HOST = re.compile(rb'Host:\s*(\S+)', re.IGNORECASE)
_TELNET_LOGIN = re.compile(rb'login:\s*(\S+)', re.IGNORECASE)

def extract_credentials(streams: dict[str, bytes]) -> list[dict]:
    creds = []
    for stream_id, data in streams.items():
        is_ftp_port = ":21-" in stream_id or stream_id.endswith(":21") or b"220 " in data[:50]
        if is_ftp_port:
            users = _FTP_USER.findall(data)
            passwords = _FTP_PASS.findall(data)
            if users:
                for i, user in enumerate(users):
                    cred = {"protocol": "FTP", "stream": stream_id, "username": user.decode('utf-8', 'replace')}
                    if i < len(passwords): cred["password"] = passwords[i].decode('utf-8', 'replace')
                    creds.append(cred)
        auths = _HTTP_AUTH.findall(data)
        hosts = _HTTP_HOST.findall(data)
        host = hosts[0].decode('utf-8', 'replace') if hosts else "unknown"
        for auth in auths:
            try:
                decoded = base64.b64decode(auth).decode('utf-8', 'replace')
                parts = decoded.split(':', 1)
                creds.append({"protocol": "HTTP Basic", "stream": stream_id, "host": host, "username": parts[0], "password": parts[1] if len(parts) > 1 else ""})
            except Exception:
                pass  # TODO: log.debug(exc)
        logins = _TELNET_LOGIN.findall(data)
        for login in logins:
            creds.append({"protocol": "Telnet", "stream": stream_id, "username": login.decode('utf-8', 'replace')})
    return creds
