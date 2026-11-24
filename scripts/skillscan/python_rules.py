"""Resolve common imported call names without importing or executing scanned code."""
from __future__ import annotations

import ast
from collections import ChainMap
import re
import shlex

from .model import MAX_LINE
from .text_rules import ENCODING, HOST, SENSITIVE, SHELL_SINK, UPLOAD, line_rules

PROCESS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
           "subprocess.Popen", "os.system", "os.popen"}
SEND = {"socket.socket.send", "socket.socket.sendall", "socket.socket.sendto",
        "ftplib.FTP.storbinary", "ftplib.FTP.storlines", "smtplib.SMTP.sendmail", "smtplib.SMTP.send_message"}
HTTP = {"requests", "requests.Session", "httpx", "httpx.Client", "httpx.AsyncClient"}
PATH_TYPES = {"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath"}
ENCODERS = {"binascii.hexlify", "binascii.b2a_base64", "codecs.encode", "bytes.hex"}
MUTATING_METHODS = {"write_text", "write_bytes", "touch", "mkdir", "unlink", "chmod", "rmdir"}
CREDENTIAL = re.compile(r"(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY|API_KEY)", re.I)


class Calls(ast.NodeVisitor):
    def __init__(self, emit):
        self.emit = emit
        self.names = ChainMap({})
        self.values = ChainMap({})
        self.stages: dict[str, int] = {}

    def stage(self, name, line):
        self.stages.setdefault(name, line)

    def finish_scope(self):
        if self.stages.keys() >= {"source", "encoding", "sink"}:
            self.emit("S2-SENSITIVE-CHAIN", max(self.stages.values()))

    def visit_scope(self, node):
        for decorator in node.decorator_list:
            self.visit(decorator)
        if isinstance(node, ast.ClassDef):
            for expression in [*node.bases, *node.keywords]:
                self.visit(expression)
        else:
            self.visit(node.args)
        self.names[node.name], self.values[node.name] = "", ""
        outer_names, outer_values, outer_stages = self.names, self.values, self.stages
        self.names, self.values, self.stages = self.names.new_child(), self.values.new_child(), {}
        if hasattr(node, "args"):
            for arg in ast.walk(node.args):
                if isinstance(arg, ast.arg):
                    self.names[arg.arg] = ""
                    self.values[arg.arg] = ""
        for statement in node.body:
            self.visit(statement)
        self.finish_scope()
        self.names, self.values, self.stages = outer_names, outer_values, outer_stages

    visit_FunctionDef = visit_scope
    visit_AsyncFunctionDef = visit_scope
    visit_ClassDef = visit_scope

    def visit_Import(self, node):
        for item in node.names:
            root = item.name.split(".")[0]
            self.names[item.asname or root] = item.name if item.asname else root

    def visit_ImportFrom(self, node):
        for item in node.names:
            self.names[item.asname or item.name] = f"{node.module}.{item.name}"

    def name(self, node):
        if isinstance(node, ast.Name):
            return self.names.get(node.id, node.id if node.id in {"open", "eval", "exec", "bytes"} else "")
        if isinstance(node, ast.Attribute):
            return self.name(node.value) + "." + node.attr
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and self.name(node.left) in PATH_TYPES:
            return "pathlib.Path"
        if isinstance(node, ast.Call):
            cls = self.name(node.func)
            owner, _, method = cls.rpartition(".")
            if owner in PATH_TYPES and method in {"home", "cwd", "resolve", "expanduser", "joinpath"}:
                return owner
            if cls == "socket.create_connection":
                return "socket.socket"
            if cls == "urllib.request.Request" and self.has_body(node):
                return "urllib.request.RequestWithData"
            return cls
        return ""

    def value(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self.values.get(node.id, "")
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
            join = "/" if isinstance(node.op, ast.Div) else ""
            return (self.value(node.left) + join + self.value(node.right))[:MAX_LINE]
        if isinstance(node, ast.Call):
            fn = self.name(node.func)
            if fn in PATH_TYPES or fn in {"os.path.join", "os.path.expanduser"}:
                return "/".join(self.value(arg) for arg in node.args)[:MAX_LINE]
            if fn in {f"{cls}.home" for cls in PATH_TYPES}:
                return "~"
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"expanduser", "resolve", "joinpath"}:
                return "/".join([self.value(node.func.value), *(self.value(arg) for arg in node.args)])
        return ""

    def bind(self, target, value):
        if isinstance(target, ast.Name):
            label, literal = self.name(value), self.value(value)
            self.names[target.id], self.values[target.id] = label, literal

    def visit_Assign(self, node):
        self.visit(node.value)
        for target in node.targets:
            self.bind(target, node.value)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
            self.bind(node.target, node.value)

    def visit_withitem(self, node):
        self.visit(node.context_expr)
        self.bind(node.optional_vars, node.context_expr)

    def source(self, line):
        self.emit("S2-SENSITIVE-READ", line)
        self.stage("source", line)

    def visit_Subscript(self, node):
        if self.name(node.value) == "os.environ" and CREDENTIAL.search(self.value(node.slice)):
            self.source(node.lineno)
        self.generic_visit(node)

    @staticmethod
    def argument(node, position, keyword):
        if len(node.args) > position:
            return node.args[position]
        return next((arg.value for arg in node.keywords if arg.arg == keyword), None)

    @staticmethod
    def has_body(node):
        data = Calls.argument(node, 1, "data")
        return data is not None and not (isinstance(data, ast.Constant) and data.value is None)

    def visit_Call(self, node):
        fn = self.name(node.func)
        owner, _, method = fn.rpartition(".")
        first = self.argument(node, 0, "file")
        path = self.value(first)
        receiver = self.value(node.func.value) if isinstance(node.func, ast.Attribute) else ""
        line = node.lineno
        if fn in {"open", "builtins.open", "io.open"} or (owner in PATH_TYPES and method == "open"):
            is_method = owner in PATH_TYPES
            mode = self.value(self.argument(node, 0 if is_method else 1, "mode")) or "r"
            filename = receiver if is_method else path
            if ("r" in mode or "+" in mode) and SENSITIVE.search(filename):
                self.source(line)
            if any(flag in mode for flag in "wax+") and HOST.search(filename):
                self.emit("M4-HOST-CONFIG-WRITE", line)
        elif owner in PATH_TYPES:
            if method in {"read_bytes", "read_text"} and SENSITIVE.search(receiver):
                self.source(line)
            if method in MUTATING_METHODS and HOST.search(receiver):
                self.emit("M4-HOST-CONFIG-WRITE", line)
            if method in {"rename", "replace"} and HOST.search(path):
                self.emit("M4-HOST-CONFIG-WRITE", line)
        elif fn in {"shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move", "os.replace", "os.rename"}:
            if HOST.search(self.value(self.argument(node, 1, "dst"))):
                self.emit("M4-HOST-CONFIG-WRITE", line)
        elif fn in {"os.getenv", "os.environ.get"} and CREDENTIAL.search(path):
            self.source(line)

        if fn in ENCODERS or (owner == "base64" and method.endswith(("encode", "decode"))):
            self.stage("encoding", line)
        if fn in SEND or (owner in HTTP and method in {"post", "put", "patch"}) or (
            fn == "urllib.request.urlopen" and (
                self.has_body(node) or self.name(self.argument(node, 0, "url")) == "urllib.request.RequestWithData")
        ):
            self.emit("S2-NETWORK-SINK", line)
            self.stage("sink", line)

        if fn in {"eval", "exec", "builtins.eval", "builtins.exec", "os.system", "os.popen"}:
            self.emit("M4-DYNAMIC-EXECUTION", line)
            self.stage("sink", line)
        if fn in PROCESS:
            self.process_call(node, fn)
        self.generic_visit(node)

    def process_call(self, node, fn):
        first = self.argument(node, 0, "args")
        shell_arg = next((arg.value for arg in node.keywords if arg.arg == "shell"), None)
        shell = fn in {"os.system", "os.popen"} or (isinstance(shell_arg, ast.Constant) and shell_arg.value is True)
        if isinstance(first, (ast.Tuple, ast.List)):
            argv = [self.value(item) for item in first.elts]
            if len(argv) > 2 and argv[0] in {"sh", "bash", "/bin/sh", "/bin/bash"} and argv[1] == "-c":
                shell, command = True, argv[2]
            else:
                command = shlex.join(argv)
        else:
            command = self.value(first)
        if shell:
            self.emit("M4-DYNAMIC-EXECUTION", node.lineno)
            self.stage("sink", node.lineno)
        for rule in line_rules(command[:MAX_LINE]):
            if rule == "M4-REMOTE-SCRIPT-EXEC" and not shell:
                continue
            self.emit(rule, node.lineno)
            if rule == "S2-SENSITIVE-READ":
                self.stage("source", node.lineno)
        if ENCODING.search(command):
            self.stage("encoding", node.lineno)
        if UPLOAD.search(command) or (shell and SHELL_SINK.search(command)):
            self.stage("sink", node.lineno)


def python_rules(lines: list[str], emit) -> None:
    try:
        tree = ast.parse("\n".join(lines).removeprefix("\ufeff"))
        calls = Calls(emit)
        calls.visit(tree)
        calls.finish_scope()
    except (SyntaxError, ValueError, RecursionError) as exc:
        emit("M4-PYTHON-PARSE", min(len(lines), getattr(exc, "lineno", 1) or 1))
