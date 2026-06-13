import time
from typing import Literal, SupportsIndex
from datetime import datetime

class CookieItem:
    def __init__(self, name: str, value: str, secure: bool = False, httponly: bool = False, partitioned: bool = False, path: str | None = None, domain: str | None = None, expires: datetime | None = None, max_age: int | None = None, samesite: Literal["Strict", "Lax", "None"] | None = None):
        self.name = name
        self.value = value
        self.secure = secure
        self.httponly = httponly
        self.partitioned = partitioned
        self.path = path
        self.domain = domain
        self.expires = expires
        self.max_age = max_age
        self.samesite = samesite

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CookieItem):
            return NotImplemented
        return self.name == other.name and self.value == other.value

    def __repr__(self) -> str:
        return f"CookieItem(name={self.name!r}, value={self.value!r})"

    def part(self) -> str:
        parts = [f"{self.name}={self.value}"]
        if self.path is not None:
            parts.append(f"Path={self.path}")
        if self.domain is not None:
            parts.append(f"Domain={self.domain}")
        if self.expires is not None:
            parts.append(f"Expires={self.expires.strftime('%a, %d %b %Y %H:%M:%S GMT')}")
        if self.max_age is not None:
            parts.append(f"Max-Age={self.max_age}")
        if self.secure:
            parts.append("Secure")
        if self.httponly:
            parts.append("HttpOnly")
        if self.samesite is not None:
            parts.append(f"SameSite={self.samesite}")
        if self.partitioned:
            parts.append("Partitioned")
        return "; ".join(parts)

class Cookie:
    def __init__(self, cookies: str | list[CookieItem] | None = None):
        self.initial: list[CookieItem] = []
        if isinstance(cookies, str):
            self.initial = Cookie.from_header(cookies)
        elif isinstance(cookies, list):
            self.initial = cookies
        self.cookies: list[CookieItem] = self.initial.copy()

    def append(self, item: CookieItem):
        if any(c.name == item.name for c in self.cookies):
            raise ValueError(f"Cookie '{item.name}' already exists")
        self.cookies.append(item)

    def set(self, item: CookieItem):
        for i, c in enumerate(self.cookies):
            if c.name == item.name:
                self.cookies[i] = item
                return
        self.cookies.append(item)

    def pop(self, index: SupportsIndex = -1):
        self.cookies.pop(index)

    def remove(self, item: CookieItem):
        self.cookies.remove(item)

    def clear(self):
        self.cookies.clear()

    def copy(self) -> Cookie:
        return Cookie(self.cookies.copy())

    def headers(self) -> list[str]:
        result: list[str] = []
        initial_map = {c.name: c for c in self.initial}
        current_map = {c.name: c for c in self.cookies}

        for name, item in current_map.items():
            if name not in initial_map or initial_map[name] != item:
                result.append(item.part())

        for name in initial_map:
            if name not in current_map:
                result.append(CookieItem(name, "", max_age=0).part())

        return result

    @staticmethod
    def from_header(header: str) -> "Cookie":
        items: list[CookieItem] = []
        for part in header.split(";"):
            part = part.strip()
            if not part:
                continue
            name, _, value = part.partition("=")
            items.append(CookieItem(name.strip(), value.strip()))

        cookie: Cookie = object.__new__(Cookie)
        cookie.initial = items
        cookie.cookies = items.copy()
        return cookie

class CSP:
    def __init__(self):
        self.default = True
        self.directives: dict[str, list[str] | bool] = {"default-src": ["'self'"]}

    def set(self, key: str, value: list[str] | bool, override: bool = True):
        if override or key not in self.directives:
            self.default = False
            self.directives[key] = value

    def append(self, key: str, *values: str):
        self.default = False
        if key not in self.directives:
            self.directives[key] = list(values)
        else:
            self.directives[key] += list(values)

    def remove(self, key: str):
        self.default = False
        self.directives.pop(key, None)

    @property
    def header(self) -> str:
        parts = []
        for key, value in self.directives.items():
            if isinstance(value, bool) and value:
                parts.append(key)
            elif isinstance(value, str) and value:
                parts.append(f"{key} {value}")
            else:
                parts.append(f"{key} {' '.join(value)}")
        return "; ".join(parts).strip()

class PermissionsPolicy:
    def __init__(self):
        self.default = True
        self.directives: dict[str, list[str]] = {
            "camera": [],
            "microphone": [],
            "geolocation": [],
            "payment": [],
            "usb": [],
            "accelerometer": [],
            "gyroscope": [],
            "magnetometer": [],
            "display-capture": []
        }

    def set(self, key: str, value: list[str], override: bool = True):
        if override or key not in self.directives:
            self.default = False
            self.directives[key] = value

    def append(self, key: str, *values: str):
        self.default = False
        if key not in self.directives:
            self.directives[key] = list(values)
        else:
            self.directives[key] += list(values)

    def remove(self, key: str):
        self.default = False
        self.directives.pop(key, None)

    @property
    def header(self) -> str:
        parts = []
        for key, value in self.directives.items():
            if value == ["*"]:
                parts.append(f"{key}=*")
            elif value:
                parts.append(f"{key}=({' '.join(value)})")
            else:
                parts.append(f"{key}=()")
        return ", ".join(parts)

class CacheControl:
    def __init__(self):
        self.default = True
        self.directives: dict[str, int | bool] = {}

    def set(self, key: str, value: int | bool = True, override: bool = True):
        if override or key not in self.directives:
            self.default = False
            self.directives[key] = value

    def remove(self, key: str):
        self.default = False
        self.directives.pop(key, None)

    @property
    def header(self) -> str:
        parts = []
        for key, value in self.directives.items():
            if value is True:
                parts.append(key)
            elif isinstance(value, int):
                parts.append(f"{key}={value}")
        return ", ".join(parts)

class ServerTiming:
    def __init__(self):
        self.timings: dict[str, list[float, float | None, str | None]] = {}

    def start(self, key: str, description: str | None = None) -> float:
        if key in self.timings:
            n = 1
            while f"{key}-{n}" in self.timings:
                n += 1
            key = f"{key}-{n}"
        now = time.perf_counter()
        self.timings[key] = [now, None, description]
        return now

    def stop(self, key: str, description: str | None = None) -> float:
        candidates = [k for k in self.timings if k == key or (k.startswith(f"{key}-") and k[len(key) + 1:].isdigit())]
        assert candidates
        key = max(candidates, key=lambda k: self.timings[k][0])
        now = time.perf_counter()
        self.timings[key] = [self.timings[key][0], now, description or self.timings[key][2]]
        return now

    @property
    def header(self) -> str:
        headers = []
        sorted_timings = sorted(((key, value) for key, value in self.timings.items() if value[1] is not None), key=lambda item: item[1][1])
        for key, value in sorted_timings:
            duration = round((value[1] - value[0]) * 1000, 3)
            headers.append(f"{key}{f';desc=\"{value[2]}\"' if value[2] is not None else ''};dur={duration}")
        return ", ".join(headers)
