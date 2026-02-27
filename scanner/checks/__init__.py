from .ftp_check import check_ftp
from .telnet_check import check_telnet
from .http_check import check_http
from .http_headers_check import check_weak_http_headers
from .smb_check import check_smb

ALL_CHECKS = [
    check_ftp,
    check_telnet,
    check_http,
    check_weak_http_headers,
    check_smb,
]
