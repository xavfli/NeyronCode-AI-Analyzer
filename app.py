from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
STORE_PATH = DATA_DIR / "store.json"
PORT = int(os.environ.get("NEYRON_PORT", "8000"))
APP_ROUTES = {"/", "/login", "/dashboard", "/code-analysis", "/security", "/optimization", "/reports"}
SESSION_COOKIE = "neyron_session"
SESSION_TTL_SECONDS = 60 * 60 * 24
DEFAULT_USERNAME = os.environ.get("NEYRON_USERNAME", "admin")
DEFAULT_PASSWORD = os.environ.get("NEYRON_PASSWORD", "admin123")
OLLAMA_TIMEOUT_SECONDS = float(os.environ.get("OLLAMA_TIMEOUT", "20"))
GENERATED_TEST_ARTIFACTS = {
    ("secret.py", 'password="123"'),
    ("broken.py", "if x==0\n    print\nelse\n    print(5)"),
    ("quality.py", "from math import *\n\ndef f(list=[]):\n    print\n    assert len(list) > 0\n    return list"),
}
DEFAULT_DEMO_CODES = [
    {
        "id": "demo-clean-code",
        "filename": "sample.py",
        "code": """def calculate_total(items):
    total = 0
    for item in items:
        total = total + item["price"]
    return total


cart = [{"price": 12000}, {"price": 8000}, {"price": 5000}]
print(calculate_total(cart))
""",
    },
    {
        "id": "demo-security-audit",
        "filename": "security_demo.py",
        "code": """import sqlite3


password = "admin123"


def find_user(username):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    return cursor.execute(f"SELECT * FROM users WHERE name = '{username}'").fetchone()
""",
    },
    {
        "id": "demo-optimization",
        "filename": "optimization_demo.py",
        "code": """def count_matches(users, orders):
    matches = []
    for user in users:
        for order in orders:
            if user["id"] == order["user_id"]:
                matches.append((user["name"], order["total"]))
    return matches
""",
    },
]


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    fix: str
    line: int | None = None


@dataclass
class ImportedName:
    visible_name: str
    source: str
    line: int


class AnalyzerVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.imports: list[ImportedName] = []
        self.used_names: set[str] = set()
        self.functions: list[dict[str, Any]] = []
        self.classes: list[dict[str, Any]] = []
        self.loop_depth = 0
        self.max_loop_depth = 0

    def visit_Name(self, node: ast.Name) -> Any:
        self.used_names.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        chain = full_name(node)
        if chain:
            self.used_names.add(chain.split(".")[0])
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            visible = alias.asname or alias.name.split(".")[0]
            self.imports.append(ImportedName(visible, alias.name, node.lineno))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        module = "." * node.level + (node.module or "")
        for alias in node.names:
            visible = alias.asname or alias.name
            self.imports.append(ImportedName(visible, f"{module}.{alias.name}".strip("."), node.lineno))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._record_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._record_function(node)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.classes.append(
            {
                "name": node.name,
                "line": node.lineno,
                "methods": len([item for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))]),
            }
        )
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        self._enter_loop(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self._enter_loop(node)

    def visit_While(self, node: ast.While) -> Any:
        self._enter_loop(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> Any:
        if node.type is None:
            self.findings.append(
                Finding(
                    "medium",
                    "Xatolik boshqaruvi",
                    "Juda keng except bloki",
                    "Bare except barcha xatolarni yashiradi va debug qilishni qiyinlashtiradi.",
                    "Aniq exception turlarini tuting va xatoni logga yozing.",
                    node.lineno,
                )
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        self._check_secret_assignment(node.targets, node.value, getattr(node, "lineno", None))
        self._check_debug_assignment(node.targets, node.value, getattr(node, "lineno", None))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._check_secret_assignment([node.target], node.value, getattr(node, "lineno", None))
            self._check_debug_assignment([node.target], node.value, getattr(node, "lineno", None))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        call_name = full_name(node.func)
        self._check_dangerous_call(node, call_name)
        self._check_sql_call(node, call_name)
        self._check_crypto_call(node, call_name)
        self._check_requests_call(node, call_name)
        self._check_yaml_call(node, call_name)
        self._check_open_call(node, call_name)
        self._check_debug_call(node, call_name)
        self.generic_visit(node)

    def _record_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        end_line = getattr(node, "end_lineno", node.lineno)
        args_count = (
            len(node.args.args)
            + len(node.args.kwonlyargs)
            + len(node.args.posonlyargs)
            + (1 if node.args.vararg else 0)
            + (1 if node.args.kwarg else 0)
        )
        complexity = cyclomatic_complexity(node)
        has_docstring = ast.get_docstring(node) is not None
        item = {
            "name": node.name,
            "line": node.lineno,
            "length": max(1, end_line - node.lineno + 1),
            "args": args_count,
            "complexity": complexity,
            "has_docstring": has_docstring,
        }
        self.functions.append(item)

        if item["length"] > 45:
            self.findings.append(
                Finding(
                    "medium",
                    "Murakkablik",
                    f"`{node.name}` funksiyasi juda uzun",
                    f"Funksiya {item['length']} qatordan iborat; bu testlash va tushunishni qiyinlashtiradi.",
                    "Funksiyani kichikroq yordamchi funksiyalarga ajrating.",
                    node.lineno,
                )
            )
        if complexity > 10:
            self.findings.append(
                Finding(
                    "high",
                    "Murakkablik",
                    f"`{node.name}` funksiyasida yuqori shartli murakkablik",
                    f"Cyclomatic complexity taxminan {complexity}; xatolik xavfi oshadi.",
                    "Erta return, jadvalga asoslangan yechim yoki alohida strategiya funksiyalaridan foydalaning.",
                    node.lineno,
                )
            )
        if args_count > 6:
            self.findings.append(
                Finding(
                    "medium",
                    "Dizayn",
                    f"`{node.name}` juda ko'p parametr qabul qiladi",
                    f"{args_count} ta parametr funksiyani noto'g'ri chaqirish ehtimolini oshiradi.",
                    "Bog'liq qiymatlarni dataclass yoki konfiguratsiya obyektiga birlashtiring.",
                    node.lineno,
                )
            )

    def _enter_loop(self, node: ast.For | ast.AsyncFor | ast.While) -> None:
        self.loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self.loop_depth)
        if self.loop_depth >= 3:
            self.findings.append(
                Finding(
                    "medium",
                    "Optimallashtirish",
                    "Chuqur ichma-ich sikl",
                    "Uch yoki undan ortiq ichma-ich sikl katta ma'lumotlarda sekinlashishi mumkin.",
                    "Ma'lumotni oldindan indekslang, set/dict ishlating yoki algoritmni soddalashtiring.",
                    getattr(node, "lineno", None),
                )
            )
        self.generic_visit(node)
        self.loop_depth -= 1

    def _check_secret_assignment(self, targets: list[ast.expr], value: ast.expr, line: int | None) -> None:
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str) or not value.value.strip():
            return
        secret_markers = ("password", "passwd", "secret", "token", "api_key", "apikey", "private_key", "auth")
        for target in targets:
            target_name = full_name(target).lower()
            if any(marker in target_name for marker in secret_markers):
                self.findings.append(
                    Finding(
                        "critical",
                        "Xavfsizlik",
                        "Hardcoded maxfiy qiymat",
                        f"`{target_name}` qiymati kod ichida matn sifatida saqlangan.",
                        "Maxfiy qiymatlarni environment variable yoki secret manager orqali o'qing.",
                        line,
                    )
                )

    def _check_debug_assignment(self, targets: list[ast.expr], value: ast.expr, line: int | None) -> None:
        if not (isinstance(value, ast.Constant) and value.value is True):
            return
        for target in targets:
            target_name = full_name(target).lower()
            if target_name.endswith("debug") or target_name == "debug":
                self.findings.append(
                    Finding(
                        "high",
                        "Xavfsizlik",
                        "Debug rejimi yoqilgan",
                        "Production muhitida debug rejimi stack trace va ichki ma'lumotlarni ko'rsatishi mumkin.",
                        "Debug qiymatini konfiguratsiyadan o'qing va productionda `False` qiling.",
                        line,
                    )
                )

    def _check_dangerous_call(self, node: ast.Call, call_name: str) -> None:
        dangerous = {
            "eval": ("critical", "Dinamik kod bajarish `eval` orqali amalga oshirilmoqda."),
            "exec": ("critical", "Dinamik kod bajarish `exec` orqali amalga oshirilmoqda."),
            "compile": ("medium", "`compile` noto'g'ri manba bilan ishlatilsa xavf tug'diradi."),
            "os.system": ("high", "Shell buyrug'i to'g'ridan-to'g'ri bajarilmoqda."),
            "subprocess.Popen": ("high", "Subprocess chaqiruvida buyruq injeksiyasi xavfi bo'lishi mumkin."),
            "subprocess.call": ("high", "Subprocess chaqiruvida buyruq injeksiyasi xavfi bo'lishi mumkin."),
            "subprocess.run": ("medium", "Subprocess ishlatilgan, argumentlar xavfsiz uzatilganini tekshiring."),
            "pickle.load": ("high", "Ishonchsiz pickle faylni ochish kod bajarilishiga olib kelishi mumkin."),
            "pickle.loads": ("high", "Ishonchsiz pickle ma'lumot kod bajarilishiga olib kelishi mumkin."),
        }
        if call_name in dangerous:
            severity, detail = dangerous[call_name]
            fix = "Xavfsiz parser/API ishlating va foydalanuvchi kiritgan qiymatni kod sifatida bajarmang."
            if call_name.startswith("subprocess"):
                fix = "Buyruqni ro'yxat argumentlari bilan uzating, `shell=True`dan qoching va inputni validatsiya qiling."
            self.findings.append(
                Finding(
                    severity,
                    "Xavfsizlik",
                    f"`{call_name}` chaqiruvi tekshirilsin",
                    detail,
                    fix,
                    getattr(node, "lineno", None),
                )
            )

        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                self.findings.append(
                    Finding(
                        "high",
                        "Xavfsizlik",
                        "`shell=True` ishlatilgan",
                        "Shell orqali buyruq bajarish command injection xavfini oshiradi.",
                        "Subprocess argumentlarini ro'yxat shaklida uzating va shellni o'chiring.",
                        getattr(node, "lineno", None),
                    )
                )

    def _check_sql_call(self, node: ast.Call, call_name: str) -> None:
        if not call_name.endswith(".execute") and call_name != "execute":
            return
        if not node.args:
            return
        query = node.args[0]
        unsafe = isinstance(query, (ast.JoinedStr, ast.BinOp)) or (
            isinstance(query, ast.Call) and full_name(query.func).endswith(".format")
        )
        if unsafe:
            self.findings.append(
                Finding(
                    "critical",
                    "Xavfsizlik",
                    "SQL so'rovida string interpolation",
                    "SQL matnini f-string, `%` yoki `.format()` bilan yig'ish injection xavfini oshiradi.",
                    "Parameterized query ishlating: `cursor.execute(sql, params)`.",
                    getattr(node, "lineno", None),
                )
            )

    def _check_crypto_call(self, node: ast.Call, call_name: str) -> None:
        if call_name in {"hashlib.md5", "hashlib.sha1"}:
            self.findings.append(
                Finding(
                    "medium",
                    "Xavfsizlik",
                    "Zaif hash algoritmi",
                    f"`{call_name}` kolliziya hujumlariga chidamsiz.",
                    "Parol uchun `bcrypt`/`argon2`, checksum uchun `sha256` yoki kuchliroq algoritm ishlating.",
                    getattr(node, "lineno", None),
                )
            )

    def _check_requests_call(self, node: ast.Call, call_name: str) -> None:
        request_methods = {
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.patch",
            "requests.delete",
            "requests.request",
        }
        if call_name not in request_methods:
            return
        has_timeout = any(keyword.arg == "timeout" for keyword in node.keywords)
        verify_false = any(
            keyword.arg == "verify" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False
            for keyword in node.keywords
        )
        if not has_timeout:
            self.findings.append(
                Finding(
                    "low",
                    "Barqarorlik",
                    "HTTP so'rovda timeout yo'q",
                    "Timeout belgilanmasa, tarmoq muammosida jarayon uzoq kutib qolishi mumkin.",
                    "`timeout=` parametrini qo'shing.",
                    getattr(node, "lineno", None),
                )
            )
        if verify_false:
            self.findings.append(
                Finding(
                    "high",
                    "Xavfsizlik",
                    "TLS tekshiruvi o'chirilgan",
                    "`verify=False` man-in-the-middle xavfini oshiradi.",
                    "Sertifikatni to'g'ri sozlang va TLS tekshiruvini yoqilgan holda qoldiring.",
                    getattr(node, "lineno", None),
                )
            )

    def _check_yaml_call(self, node: ast.Call, call_name: str) -> None:
        if call_name != "yaml.load":
            return
        uses_safe_loader = any(
            keyword.arg in {"Loader", "loader"}
            and ("SafeLoader" in full_name(keyword.value) or "CSafeLoader" in full_name(keyword.value))
            for keyword in node.keywords
        )
        if not uses_safe_loader:
            self.findings.append(
                Finding(
                    "high",
                    "Xavfsizlik",
                    "YAML xavfsiz loader bilan o'qilmagan",
                    "`yaml.load` ishonchsiz obyektlarni yaratishi mumkin.",
                    "`yaml.safe_load` yoki `SafeLoader` ishlating.",
                    getattr(node, "lineno", None),
                )
            )

    def _check_open_call(self, node: ast.Call, call_name: str) -> None:
        if call_name != "open":
            return
        mode = ""
        if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
            mode = str(node.args[1].value)
        for keyword in node.keywords:
            if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                mode = str(keyword.value.value)
        binary_mode = "b" in mode
        has_encoding = any(keyword.arg == "encoding" for keyword in node.keywords)
        if not binary_mode and not has_encoding:
            self.findings.append(
                Finding(
                    "low",
                    "Sifat",
                    "Fayl encoding ko'rsatilmagan",
                    "Platformaga bog'liq default encoding turli muhitda muammo berishi mumkin.",
                    "`open(..., encoding='utf-8')` shaklida yozing.",
                    getattr(node, "lineno", None),
                )
            )

    def _check_debug_call(self, node: ast.Call, call_name: str) -> None:
        if call_name.endswith(".run"):
            debug_true = any(
                keyword.arg == "debug" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                for keyword in node.keywords
            )
            if debug_true:
                self.findings.append(
                    Finding(
                        "high",
                        "Xavfsizlik",
                        "Ilova debug rejimida ishga tushmoqda",
                        "Debug server production uchun mos emas.",
                        "Productionda WSGI/ASGI server ishlating va `debug=False` qiling.",
                        getattr(node, "lineno", None),
                    )
                )


class CodeAnalyzer:
    def analyze(self, code: str, filename: str = "main.py", use_model: bool = True) -> dict[str, Any]:
        started = time.perf_counter()
        code = code.replace("\r\n", "\n")
        base_metrics = basic_metrics(code)

        if not code.strip():
            return {
                "filename": filename,
                "score": 0,
                "status": "empty",
                "summary": "Kod kiritilmagan. Tahlil uchun Python kodini joylang yoki `.py` fayl yuklang.",
                "model_summary": None,
                "model_status": "Kutilmoqda",
                "metrics": base_metrics,
                "findings": [],
                "suggestions": [],
                "optimized_code": "",
                "elapsed_ms": elapsed_ms(started),
            }

        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError as exc:
            syntax_findings = collect_syntax_findings(code, exc)
            metrics = base_metrics | {"syntax_ok": False, "complexity": 0}
            model_summary, model_status = maybe_ollama_summary(code, syntax_findings, metrics, use_model)
            suggestions = unique_list([finding.fix for finding in syntax_findings])
            return {
                "filename": filename,
                "score": max(0, 25 - len(syntax_findings) * 5),
                "status": "syntax_error",
                "summary": (
                    f"Kod hozircha bajariladigan Python sifatida parse bo'lmadi. "
                    f"{len(syntax_findings)} ta sintaksis yoki ehtimoliy yozilish xatosi topildi."
                ),
                "model_summary": model_summary,
                "model_status": model_status,
                "metrics": metrics,
                "findings": [asdict(finding) for finding in syntax_findings],
                "suggestions": suggestions,
                "optimized_code": "",
                "elapsed_ms": elapsed_ms(started),
            }

        visitor = AnalyzerVisitor()
        visitor.visit(tree)
        findings = visitor.findings
        findings.extend(unused_import_findings(visitor))
        findings.extend(duplication_findings(code))
        findings.extend(naming_findings(tree))
        findings.extend(tree_quality_findings(tree))
        findings.extend(text_quality_findings(code))
        findings = dedupe_findings(findings)
        findings.sort(key=lambda item: (severity_rank(item.severity), item.line or 10**8, item.title))

        metrics = base_metrics | {
            "syntax_ok": True,
            "functions": len(visitor.functions),
            "classes": len(visitor.classes),
            "imports": len(visitor.imports),
            "complexity": sum(item["complexity"] for item in visitor.functions) or cyclomatic_complexity(tree),
            "max_function_complexity": max([item["complexity"] for item in visitor.functions] or [0]),
            "max_function_length": max([item["length"] for item in visitor.functions] or [0]),
            "max_loop_depth": visitor.max_loop_depth,
        }
        score = calculate_score(findings, metrics)
        suggestions = build_suggestions(findings, metrics, visitor.functions)
        optimized_code = suggest_optimized_code(code)
        summary = build_summary(score, findings, metrics)
        model_summary, model_status = maybe_ollama_summary(code, findings, metrics, use_model)

        return {
            "filename": filename,
            "score": score,
            "status": "ok",
            "summary": summary,
            "model_summary": model_summary,
            "model_status": model_status,
            "metrics": metrics,
            "findings": [asdict(finding) for finding in findings],
            "suggestions": suggestions,
            "optimized_code": optimized_code,
            "elapsed_ms": elapsed_ms(started),
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def new_user(password: str) -> dict[str, Any]:
    salt = secrets.token_urlsafe(18)
    return {
        "password_hash": hash_password(password, salt),
        "salt": salt,
        "created_at": utc_now(),
        "state": {},
        "history": [],
    }


def hash_password(password: str, salt: str) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 160_000)
    return base64.b64encode(digest).decode("ascii")


def verify_password(password: str, expected_hash: str, salt: str) -> bool:
    if not expected_hash or not salt:
        return False
    actual_hash = hash_password(password, salt)
    return hmac.compare_digest(actual_hash, expected_hash)


def is_generated_test_artifact(filename: Any, code: Any) -> bool:
    return (str(filename), str(code)) in GENERATED_TEST_ARTIFACTS


class AuthStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_store()

    def authenticate(self, username: str, password: str) -> bool:
        user = self._load().get("users", {}).get(username)
        if not user:
            return False
        return verify_password(password, user.get("password_hash", ""), user.get("salt", ""))

    def create_session(self, username: str) -> str:
        data = self._load()
        token = secrets.token_urlsafe(32)
        data.setdefault("sessions", {})[token] = {
            "username": username,
            "expires_at": int(time.time()) + SESSION_TTL_SECONDS,
        }
        self._save(data)
        return token

    def session_user(self, token: str | None) -> str | None:
        if not token:
            return None
        data = self._load()
        sessions = data.setdefault("sessions", {})
        session = sessions.get(token)
        if not session:
            return None
        if int(session.get("expires_at", 0)) < int(time.time()):
            sessions.pop(token, None)
            self._save(data)
            return None
        return str(session.get("username", "")) or None

    def delete_session(self, token: str | None) -> None:
        if not token:
            return
        data = self._load()
        if data.setdefault("sessions", {}).pop(token, None) is not None:
            self._save(data)

    def snapshot(self, username: str) -> dict[str, Any]:
        user = self._get_user(username)
        return {
            "username": username,
            "state": user.get("state", {}),
            "history": user.get("history", []),
        }

    def save_work(self, username: str, payload: dict[str, Any]) -> dict[str, Any]:
        data = self._load()
        user = self._ensure_user(data, username)
        state = user.setdefault("state", {})
        state["code"] = str(payload.get("code", state.get("code", "")))
        state["filename"] = str(payload.get("filename", state.get("filename", "sample.py"))) or "sample.py"
        state["use_model"] = bool(payload.get("use_model", state.get("use_model", True)))
        state["last_route"] = str(payload.get("last_route", state.get("last_route", "/dashboard")))
        state["updated_at"] = utc_now()
        if "last_result" in payload:
            state["last_result"] = payload["last_result"]
        self._save(data)
        return self.snapshot(username)

    def save_analysis(
        self,
        username: str,
        code: str,
        filename: str,
        use_model: bool,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        data = self._load()
        user = self._ensure_user(data, username)
        item = {
            "id": secrets.token_hex(6),
            "created_at": utc_now(),
            "filename": filename,
            "code": code,
            "score": result.get("score", 0),
            "issue_count": len(result.get("findings", [])),
            "summary": result.get("summary", ""),
            "result": result,
        }
        history = user.setdefault("history", [])
        history.insert(0, item)
        del history[25:]
        user["state"] = {
            "code": code,
            "filename": filename,
            "use_model": use_model,
            "last_route": "/reports",
            "last_result": result,
            "updated_at": item["created_at"],
        }
        self._save(data)
        return item

    def delete_history_item(self, username: str, history_id: str) -> dict[str, Any]:
        data = self._load()
        user = self._ensure_user(data, username)
        user["history"] = [item for item in user.get("history", []) if str(item.get("id")) != history_id]
        state = user.get("state", {})
        saved_id = state.get("last_result", {}).get("saved", {}).get("id") if isinstance(state.get("last_result"), dict) else None
        if saved_id == history_id:
            state.pop("last_result", None)
        self._save(data)
        return self.snapshot(username)

    def clear_history(self, username: str) -> dict[str, Any]:
        data = self._load()
        user = self._ensure_user(data, username)
        user["history"] = []
        user.setdefault("state", {}).pop("last_result", None)
        self._save(data)
        return self.snapshot(username)

    def seed_demo_data(self, username: str = DEFAULT_USERNAME, replace_state: bool = True) -> dict[str, Any]:
        data = self._load()
        self._seed_demo_data(data, username, replace_state=replace_state)
        self._save(data)
        return self.snapshot(username)

    def _ensure_store(self) -> None:
        if self.path.exists():
            data = self._load()
        else:
            data = {"users": {}, "sessions": {}}
        users = data.setdefault("users", {})
        if DEFAULT_USERNAME not in users:
            users[DEFAULT_USERNAME] = new_user(DEFAULT_PASSWORD)
        data.setdefault("sessions", {})
        self._save(data)

    def _get_user(self, username: str) -> dict[str, Any]:
        data = self._load()
        return self._ensure_user(data, username)

    def _ensure_user(self, data: dict[str, Any], username: str) -> dict[str, Any]:
        users = data.setdefault("users", {})
        if username not in users:
            users[username] = new_user(secrets.token_urlsafe(18))
        users[username].setdefault("state", {})
        users[username].setdefault("history", [])
        return users[username]

    def _seed_demo_data(self, data: dict[str, Any], username: str, replace_state: bool) -> None:
        user = self._ensure_user(data, username)
        analyzer = CodeAnalyzer()
        demo_ids = {demo["id"] for demo in DEFAULT_DEMO_CODES}
        demo_code_keys = {(demo["filename"], demo["code"]) for demo in DEFAULT_DEMO_CODES}
        history = [
            item
            for item in user.get("history", [])
            if not is_generated_test_artifact(item.get("filename"), item.get("code"))
            and not (str(item.get("id", "")) not in demo_ids and (item.get("filename"), item.get("code")) in demo_code_keys)
        ]
        demo_items: list[dict[str, Any]] = []

        for index, demo in enumerate(DEFAULT_DEMO_CODES):
            result = analyzer.analyze(demo["code"], filename=demo["filename"], use_model=False)
            created_at = f"2026-05-21T09:0{index + 1}:00Z"
            result["saved"] = {"id": demo["id"], "created_at": created_at}
            item = {
                "id": demo["id"],
                "created_at": created_at,
                "filename": demo["filename"],
                "code": demo["code"],
                "score": result.get("score", 0),
                "issue_count": len(result.get("findings", [])),
                "summary": result.get("summary", ""),
                "result": result,
            }
            demo_items.append(item)

        history = [item for item in history if str(item.get("id", "")) not in demo_ids]
        for item in reversed(demo_items):
            history.insert(0, item)
        user["history"] = history[:25]

        state = user.get("state", {})
        state_is_empty = not state or not state.get("code")
        state_is_test_artifact = is_generated_test_artifact(state.get("filename"), state.get("code"))
        if replace_state or state_is_empty or state_is_test_artifact:
            primary = demo_items[0]
            user["state"] = {
                "code": primary["code"],
                "filename": primary["filename"],
                "use_model": False,
                "last_route": "/dashboard",
                "last_result": primary["result"],
                "updated_at": utc_now(),
            }

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"users": {}, "sessions": {}}
        try:
            with self.path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except (json.JSONDecodeError, OSError):
            data = {"users": {}, "sessions": {}}
        data.setdefault("users", {})
        data.setdefault("sessions", {})
        return data

    def _save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=2)
        temp_path.replace(self.path)


class NeyronHandler(SimpleHTTPRequestHandler):
    analyzer = CodeAnalyzer()
    auth = AuthStore(STORE_PATH)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/me":
            username = self._current_user()
            if not username:
                self._json_response({"authenticated": False})
                return
            self._json_response({"authenticated": True, **self.auth.snapshot(username)})
            return
        if path == "/api/history":
            username = self._require_user()
            if not username:
                return
            self._json_response(self.auth.snapshot(username))
            return
        if path == "/api/ollama/status":
            username = self._require_user()
            if not username:
                return
            self._json_response(ollama_status())
            return
        if path in APP_ROUTES or path == "/index.html":
            self._serve_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            return
        if path.startswith("/static/"):
            requested = (BASE_DIR / path.lstrip("/")).resolve()
            if not requested.is_relative_to(STATIC_DIR):
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            content_type = self.guess_type(str(requested))
            self._serve_file(requested, content_type)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/login":
            self._handle_login()
            return
        if path == "/api/logout":
            self._handle_logout()
            return
        if path == "/api/save-work":
            username = self._require_user()
            if not username:
                return
            payload = self._json_body()
            self._json_response({"ok": True, **self.auth.save_work(username, payload)})
            return
        if path == "/api/history/delete":
            username = self._require_user()
            if not username:
                return
            payload = self._json_body()
            self._json_response({"ok": True, **self.auth.delete_history_item(username, str(payload.get("id", "")))})
            return
        if path == "/api/history/clear":
            username = self._require_user()
            if not username:
                return
            self._json_response({"ok": True, **self.auth.clear_history(username)})
            return
        if path != "/api/analyze":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        username = self._require_user()
        if not username:
            return
        try:
            payload = self._json_body()
            code = str(payload.get("code", ""))
            filename = str(payload.get("filename", "main.py")) or "main.py"
            use_model = bool(payload.get("use_model", True))
            result = self.analyzer.analyze(code, filename=filename, use_model=use_model)
            saved_item = self.auth.save_analysis(username, code, filename, use_model, result)
            result["saved"] = {
                "id": saved_item["id"],
                "created_at": saved_item["created_at"],
            }
            self._json_response(result)
        except Exception as exc:  # noqa: BLE001 - API must return structured failure.
            self._json_response(
                {
                    "status": "error",
                    "score": 0,
                    "summary": "Server tahlil vaqtida xatoga duch keldi.",
                    "error": str(exc),
                },
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    def _handle_login(self) -> None:
        try:
            payload = self._json_body()
            username = str(payload.get("username", "")).strip()
            password = str(payload.get("password", ""))
            if not self.auth.authenticate(username, password):
                self._json_response({"ok": False, "error": "Login yoki parol noto'g'ri."}, HTTPStatus.UNAUTHORIZED)
                return
            token = self.auth.create_session(username)
            headers = [
                (
                    "Set-Cookie",
                    f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_TTL_SECONDS}",
                )
            ]
            self._json_response(
                {"ok": True, "authenticated": True, **self.auth.snapshot(username)},
                extra_headers=headers,
            )
        except Exception as exc:  # noqa: BLE001 - login must answer JSON.
            self._json_response({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_logout(self) -> None:
        token = self._session_token()
        self.auth.delete_session(token)
        self._json_response(
            {"ok": True, "authenticated": False},
            extra_headers=[("Set-Cookie", f"{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")],
        )

    def log_message(self, format: str, *args: Any) -> None:
        sys.stdout.write("[%s] %s\n" % (self.log_date_time_string(), format % args))

    def _serve_file(self, path: Path, content_type: str) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _json_body(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _json_response(
        self,
        data: dict[str, Any],
        status: HTTPStatus = HTTPStatus.OK,
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> None:
        content = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        for header, value in extra_headers or []:
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(content)

    def _session_token(self) -> str | None:
        cookie_header = self.headers.get("Cookie", "")
        if not cookie_header:
            return None
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def _current_user(self) -> str | None:
        return self.auth.session_user(self._session_token())

    def _require_user(self) -> str | None:
        username = self._current_user()
        if username:
            return username
        self._json_response({"authenticated": False, "error": "Avval login qiling."}, HTTPStatus.UNAUTHORIZED)
        return None


def full_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = full_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return full_name(node.func)
    if isinstance(node, ast.Subscript):
        return full_name(node.value)
    return ""


def basic_metrics(code: str) -> dict[str, Any]:
    lines = code.splitlines()
    non_empty = [line for line in lines if line.strip()]
    comments = [line for line in lines if line.strip().startswith("#")]
    return {
        "total_lines": len(lines),
        "code_lines": len([line for line in non_empty if not line.strip().startswith("#")]),
        "comment_lines": len(comments),
        "blank_lines": len(lines) - len(non_empty),
        "avg_line_length": round(sum(len(line) for line in lines) / max(1, len(lines)), 1),
        "long_lines": len([line for line in lines if len(line) > 100]),
    }


def collect_syntax_findings(code: str, exc: SyntaxError) -> list[Finding]:
    findings = [
        Finding(
            "critical",
            "Sintaksis",
            "Python sintaksis xatosi",
            exc.msg,
            "Ko'rsatilgan qator atrofidagi qavs, ikki nuqta, indent yoki string yopilishini tekshiring.",
            exc.lineno,
        )
    ]
    block_pattern = re.compile(
        r"^(if|elif|else|for|while|def|class|try|except|finally|with|match|case)\b|^(async\s+(def|for|with))\b"
    )
    bracket_balance = {"(": 0, "[": 0, "{": 0}

    for line_no, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        for char in stripped:
            if char in bracket_balance:
                bracket_balance[char] += 1
            elif char == ")":
                bracket_balance["("] -= 1
            elif char == "]":
                bracket_balance["["] -= 1
            elif char == "}":
                bracket_balance["{"] -= 1

        if block_pattern.search(stripped) and not stripped.endswith(":"):
            keyword = stripped.split()[0]
            findings.append(
                Finding(
                    "critical",
                    "Sintaksis",
                    "Block oxirida ikki nuqta yo'q",
                    f"`{keyword}` bilan boshlangan qatorda `:` belgisi yetishmaydi.",
                    f"{line_no}-qatorda shart yoki block oxiriga `:` qo'shing.",
                    line_no,
                )
            )

        if stripped == "print" or re.match(r"^print\s+[^(\s]", stripped):
            findings.append(
                Finding(
                    "medium",
                    "Yozilish",
                    "`print` chaqiruvi to'liq emas",
                    "`print` funksiyasi argument bilan chaqirilmagan yoki Python 2 uslubida yozilgan.",
                    "`print(...)` shaklida yozing, masalan `print(x)`.",
                    line_no,
                )
            )

        if stripped.endswith("="):
            findings.append(
                Finding(
                    "critical",
                    "Sintaksis",
                    "Assign qiymati yo'q",
                    "Tenglik belgisidan keyin qiymat yozilmagan.",
                    "O'zgaruvchiga qiymat bering yoki ortiqcha `=` belgisini olib tashlang.",
                    line_no,
                )
            )

    for bracket, balance in bracket_balance.items():
        if balance > 0:
            findings.append(
                Finding(
                    "critical",
                    "Sintaksis",
                    "Yopilmagan qavs",
                    f"`{bracket}` qavsi ochilgan, lekin mos yopuvchi qavs topilmadi.",
                    "Qavslar juftligini tekshiring va yopuvchi qavsni qo'shing.",
                    None,
                )
            )
        elif balance < 0:
            findings.append(
                Finding(
                    "critical",
                    "Sintaksis",
                    "Ortiqcha yopuvchi qavs",
                    "Kodda yopuvchi qavs ochuvchi qavsdan ko'p.",
                    "Ortiqcha yopuvchi qavsni olib tashlang yoki ochuvchi qavsni qo'shing.",
                    None,
                )
            )

    return dedupe_findings(findings)


def cyclomatic_complexity(node: ast.AST) -> int:
    complexity = 1
    decision_nodes = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.ExceptHandler,
        ast.IfExp,
        ast.comprehension,
        ast.Assert,
        ast.Match,
    )
    for child in ast.walk(node):
        if isinstance(child, decision_nodes):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            complexity += max(1, len(child.values) - 1)
    return complexity


def unused_import_findings(visitor: AnalyzerVisitor) -> list[Finding]:
    findings: list[Finding] = []
    ignored = {"annotations"}
    for item in visitor.imports:
        if item.visible_name in ignored or item.visible_name == "*":
            continue
        if item.visible_name not in visitor.used_names:
            findings.append(
                Finding(
                    "low",
                    "Sifat",
                    "Ishlatilmagan import",
                    f"`{item.source}` import qilingan, lekin kodda ishlatilmagan ko'rinadi.",
                    "Keraksiz importni olib tashlang yoki haqiqatan ham kerak bo'lsa ishlatilishini tekshiring.",
                    item.line,
                )
            )
    return findings


def duplication_findings(code: str) -> list[Finding]:
    normalized: dict[tuple[str, ...], int] = {}
    lines = [line.strip() for line in code.splitlines()]
    candidates = [line for line in lines if line and not line.startswith("#")]
    for index in range(max(0, len(candidates) - 4)):
        block = tuple(candidates[index : index + 5])
        if sum(len(line) for line in block) < 60:
            continue
        normalized[block] = normalized.get(block, 0) + 1
    repeated = [count for count in normalized.values() if count > 1]
    if not repeated:
        return []
    return [
        Finding(
            "medium",
            "Takrorlanish",
            "Takrorlangan kod bloklari",
            f"{len(repeated)} ta o'xshash kod bo'lagi qayta uchradi.",
            "Takrorlangan qismni funksiya yoki helper modulga ajrating.",
            None,
        )
    ]


def naming_findings(tree: ast.AST) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and not re.match(r"^[a-z_][a-z0-9_]*$", node.name):
            findings.append(
                Finding(
                    "low",
                    "Standart",
                    "Funksiya nomi PEP 8 formatida emas",
                    f"`{node.name}` uchun snake_case tavsiya etiladi.",
                    "Funksiya nomini `snake_case` formatiga keltiring.",
                    node.lineno,
                )
            )
        if isinstance(node, ast.ClassDef) and not re.match(r"^[A-Z][A-Za-z0-9]+$", node.name):
            findings.append(
                Finding(
                    "low",
                    "Standart",
                    "Class nomi PEP 8 formatida emas",
                    f"`{node.name}` uchun PascalCase tavsiya etiladi.",
                    "Class nomini `PascalCase` formatiga keltiring.",
                    node.lineno,
                )
            )
    return findings


def tree_quality_findings(tree: ast.AST) -> list[Finding]:
    findings: list[Finding] = []
    builtin_names = {"list", "dict", "set", "str", "int", "float", "type", "id", "input", "file", "sum", "max", "min"}

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defaults = list(node.args.defaults) + [item for item in node.args.kw_defaults if item is not None]
            for default in defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    findings.append(
                        Finding(
                            "high",
                            "Sifat",
                            "Mutable default argument",
                            f"`{node.name}` funksiyasida list/dict/set default qiymat sifatida ishlatilgan.",
                            "Default qiymatni `None` qiling va funksiya ichida yangi list/dict/set yarating.",
                            node.lineno,
                        )
                    )

            public_function = not node.name.startswith("_") and node.name != "__init__"
            if public_function and node.returns is None:
                findings.append(
                    Finding(
                        "low",
                        "Standart",
                        "Return type hint yo'q",
                        f"`{node.name}` funksiyasida qaytish turi ko'rsatilmagan.",
                        "Funksiya imzosiga return annotation qo'shing, masalan `-> int` yoki `-> None`.",
                        node.lineno,
                    )
                )

            for argument in list(node.args.args) + list(node.args.kwonlyargs):
                if argument.arg in builtin_names:
                    findings.append(
                        Finding(
                            "low",
                            "Standart",
                            "Built-in nom soya qilinmoqda",
                            f"`{argument.arg}` Python built-in nomi bilan bir xil.",
                            "Argument yoki o'zgaruvchi nomini aniqroq qiling, masalan `items`, `user_id`, `values`.",
                            argument.lineno,
                        )
                    )

        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                name = full_name(target)
                if name in builtin_names:
                    findings.append(
                        Finding(
                            "low",
                            "Standart",
                            "Built-in nom qayta ishlatilgan",
                            f"`{name}` Python built-in nomini soya qilmoqda.",
                            "O'zgaruvchi nomini aniqroq va xavfsizroq nomga almashtiring.",
                            getattr(node, "lineno", None),
                        )
                    )

        if isinstance(node, ast.Assert):
            findings.append(
                Finding(
                    "medium",
                    "Barqarorlik",
                    "`assert` production tekshiruv sifatida ishlatilgan",
                    "Python optimallashtirilgan rejimda assert operatorlarini olib tashlashi mumkin.",
                    "Runtime validatsiya uchun aniq `if ...: raise ValueError(...)` ishlating.",
                    node.lineno,
                )
            )

        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
            findings.append(
                Finding(
                    "medium",
                    "Sifat",
                    "Wildcard import",
                    "`from module import *` kodni noaniq qiladi va nomlar to'qnashuviga olib keladi.",
                    "Faqat kerakli nomlarni aniq import qiling.",
                    node.lineno,
                )
            )

        if isinstance(node, ast.Call) and full_name(node.func) == "print":
            findings.append(
                Finding(
                    "low",
                    "Sifat",
                    "Debug `print` chaqiruvi",
                    "`print` production kodda nazorat qilinmaydigan chiqish hosil qiladi.",
                    "Monitoring uchun `logging` modulidan foydalaning yoki debug printni olib tashlang.",
                    node.lineno,
                )
            )

    return findings


def text_quality_findings(code: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        upper = stripped.upper()
        if len(line) > 100:
            findings.append(
                Finding(
                    "low",
                    "Standart",
                    "Qator juda uzun",
                    f"{line_no}-qator {len(line)} belgidan iborat.",
                    "Qatorni kichikroq ifodalarga ajrating yoki helper o'zgaruvchi ishlating.",
                    line_no,
                )
            )
        if line.rstrip() != line:
            findings.append(
                Finding(
                    "low",
                    "Standart",
                    "Qator oxirida bo'sh joy bor",
                    "Trailing whitespace diff va formatlashda keraksiz shovqin beradi.",
                    "Qator oxiridagi ortiqcha bo'sh joylarni olib tashlang.",
                    line_no,
                )
            )
        if "\t" in line[: len(line) - len(line.lstrip())]:
            findings.append(
                Finding(
                    "low",
                    "Standart",
                    "Tab indent ishlatilgan",
                    "Tab va space aralashishi Python indent xatolariga olib kelishi mumkin.",
                    "PEP 8 bo'yicha 4 ta space ishlating.",
                    line_no,
                )
            )
        if "TODO" in upper or "FIXME" in upper:
            findings.append(
                Finding(
                    "low",
                    "Texnik qarz",
                    "TODO/FIXME izohi qolgan",
                    "Kodda keyin bajarilishi kerak bo'lgan ish belgisi bor.",
                    "TODO/FIXME uchun aniq issue oching yoki kodni yakunlang.",
                    line_no,
                )
            )
    return findings


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[Any, ...]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.severity, finding.category, finding.title, finding.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def unique_list(items: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(severity, 4)


def calculate_score(findings: list[Finding], metrics: dict[str, Any]) -> int:
    penalty_by_severity = {"critical": 22, "high": 13, "medium": 7, "low": 3}
    score = 100
    for finding in findings:
        score -= penalty_by_severity.get(finding.severity, 2)
    if metrics.get("long_lines", 0) > 3:
        score -= min(10, metrics["long_lines"] * 2)
    if metrics.get("max_function_complexity", 0) > 10:
        score -= min(14, metrics["max_function_complexity"] - 8)
    if metrics.get("code_lines", 0) > 250 and metrics.get("functions", 0) < 3:
        score -= 8
    return max(0, min(100, score))


def build_suggestions(findings: list[Finding], metrics: dict[str, Any], functions: list[dict[str, Any]]) -> list[str]:
    suggestions: list[str] = []
    for finding in findings:
        if finding.fix not in suggestions:
            suggestions.append(finding.fix)
    if metrics.get("max_loop_depth", 0) >= 2:
        suggestions.append("Katta kolleksiyalar uchun `dict`, `set` yoki generator expression orqali qidiruvni tezlashtiring.")
    complex_functions = [item for item in functions if item["complexity"] > 8]
    if complex_functions:
        names = ", ".join(f"`{item['name']}`" for item in complex_functions[:3])
        suggestions.append(f"{names} funksiyalarida shartlarni kichik funksiyalarga ajratish foydali bo'ladi.")
    if not suggestions:
        suggestions.append("Kod umumiy ko'rinishda toza. Testlar va type hintlar bilan barqarorlikni yanada oshirish mumkin.")
    return suggestions


def build_summary(score: int, findings: list[Finding], metrics: dict[str, Any]) -> str:
    critical = len([item for item in findings if item.severity == "critical"])
    high = len([item for item in findings if item.severity == "high"])
    medium = len([item for item in findings if item.severity == "medium"])
    if score >= 86:
        tone = "Kod sifati yuqori, faqat mayda uslubiy yaxshilashlar bor."
    elif score >= 70:
        tone = "Kod ishlashga yaqin, lekin ayrim xavfsizlik va sifat nuqtalari bor."
    elif score >= 45:
        tone = "Kodda sezilarli risklar bor; asosiy muammolarni tuzatish tavsiya qilinadi."
    else:
        tone = "Kod hozir yuqori xavfli holatda; avval critical va high muammolarni yoping."
    return (
        f"{tone} {metrics.get('code_lines', 0)} qator kod, "
        f"{metrics.get('functions', 0)} funksiya, {critical} critical, {high} high, {medium} medium topilma aniqlandi."
    )


def suggest_optimized_code(code: str) -> str:
    optimized = code
    optimized = re.sub(r"if\s+(.+?)\s*==\s*True\s*:", r"if \1:", optimized)
    optimized = re.sub(r"if\s+(.+?)\s*==\s*False\s*:", r"if not \1:", optimized)
    optimized = re.sub(r"(\b\w+\b)\s*=\s*\1\s*\+\s*1", r"\1 += 1", optimized)
    optimized = re.sub(r"(\b\w+\b)\s*=\s*\1\s*-\s*1", r"\1 -= 1", optimized)

    sum_loop_pattern = re.compile(
        r"(?P<indent>[ \t]*)total\s*=\s*0\s*\n"
        r"(?P=indent)for\s+(?P<item>\w+)\s+in\s+(?P<items>[\w.]+)\s*:\s*\n"
        r"(?P=indent)[ \t]+total\s*=\s*total\s*\+\s*(?P<expr>[^\n]+)\n"
        r"(?P=indent)return\s+total",
        re.MULTILINE,
    )

    def replace_sum(match: re.Match[str]) -> str:
        indent = match.group("indent")
        item = match.group("item")
        items = match.group("items")
        expr = match.group("expr").strip()
        return f"{indent}return sum({expr} for {item} in {items})"

    optimized = sum_loop_pattern.sub(replace_sum, optimized)
    return optimized if optimized != code else ""


def maybe_ollama_summary(
    code: str,
    findings: list[Finding],
    metrics: dict[str, Any],
    use_model: bool,
) -> tuple[str | None, str]:
    if not use_model:
        return None, "O'chirilgan"
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    model = os.environ.get("NEYRON_MODEL", "qwen2.5-coder")
    prompt = (
        "Sen Python kod tahlilchisisen. Uzbek tilida AI tavsiya ber. "
        "Barcha topilgan xatolarni qator raqami bilan sanab chiq, har biriga aniq yechim yoz. "
        "Agar sintaksis xatosi bo'lsa, kodni ishga tushadigan holatga keltirish tartibini ko'rsat. "
        "Javobni qisqa, amaliy va bandlar ko'rinishida yoz.\n\n"
        f"Metriclar: {json.dumps(metrics, ensure_ascii=False)}\n"
        f"Topilmalar: {json.dumps([asdict(item) for item in findings], ensure_ascii=False)}\n"
        f"Kod:\n{code[:5000]}"
    )
    body = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 320},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{host}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=OLLAMA_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
            text = str(payload.get("response", "")).strip()
            if text:
                return text, f"{model} orqali"
            return None, "Model bo'sh javob qaytardi"
    except (urllib.error.URLError, TimeoutError, socket.timeout, ConnectionError):
        return None, "Ollama topilmadi, qoidaviy tahlil ishladi"
    except Exception as exc:  # noqa: BLE001 - optional model must not break analyzer.
        return None, f"Model xatosi: {exc}"


def ollama_status() -> dict[str, Any]:
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    selected_model = os.environ.get("NEYRON_MODEL", "qwen2.5-coder")
    request = urllib.request.Request(f"{host}/api/tags", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
            models = [item.get("name", "") for item in payload.get("models", []) if item.get("name")]
            return {
                "ok": True,
                "host": host,
                "selected_model": selected_model,
                "models": models,
                "model_ready": any(name.split(":")[0] == selected_model.split(":")[0] for name in models),
                "message": "Ollama ishlayapti.",
            }
    except (urllib.error.URLError, TimeoutError, socket.timeout, ConnectionError):
        return {
            "ok": False,
            "host": host,
            "selected_model": selected_model,
            "models": [],
            "model_ready": False,
            "message": "Ollama topilmadi. `ollama serve` ishga tushiring.",
        }
    except Exception as exc:  # noqa: BLE001 - status endpoint should stay JSON.
        return {
            "ok": False,
            "host": host,
            "selected_model": selected_model,
            "models": [],
            "model_ready": False,
            "message": f"Ollama tekshiruvida xato: {exc}",
        }


def elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def main() -> None:
    if not (STATIC_DIR / "index.html").exists():
        raise SystemExit("static/index.html topilmadi")
    NeyronHandler.auth.seed_demo_data(DEFAULT_USERNAME, replace_state=False)
    server = ThreadingHTTPServer(("127.0.0.1", PORT), NeyronHandler)
    print(f"Neyron Code Analyzer ishga tushdi: http://127.0.0.1:{PORT}")
    print("To'xtatish uchun Ctrl+C bosing.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer to'xtatildi.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
