"""Parse source only. Never import or execute code from the inspected project."""
import ast
import json
import sys


def name(node):
    if isinstance(node, ast.Call):
        return name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return name(node.value) + "." + node.attr
    return ""


def matches(value, configured):
    return any(value == item or ("." not in item and value.rsplit(".", 1)[-1] == item)
               for item in configured)


def snapshot(tree, policy):
    def resolved(node, aliases):
        value = name(node)
        first, sep, rest = value.partition(".")
        return aliases.get(first, first) + (sep + rest if sep else "")

    found = []

    def visit(node, path, aliases, enclosing):
        # Follow imports in source order, without leaking bindings out of a
        # function or class. Decorators execute in the defining scope, before
        # entering the decorated function's body.
        if isinstance(node, ast.ImportFrom):
            for item in node.names:
                aliases[item.asname or item.name] = (node.module or "") + "." + item.name
            return
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = (
                    item.name if item.asname else item.name.split(".")[0])
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            path = path + [node.name]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decorators = node.decorator_list
            route = any(matches(name(d), policy["route_decorators"]) or
                        matches(resolved(d, aliases), policy["route_decorators"]) for d in decorators)
            security = any(matches(name(d), policy["security_decorators"]) or
                           matches(resolved(d, aliases), policy["security_decorators"]) for d in decorators)
            if route and security:
                # Preserve the complete stack, route identity, and import binding.
                found.append([path, [ast.dump(d, include_attributes=False) for d in decorators],
                              [resolved(d, aliases) for d in decorators]])
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Class namespaces are visible to method decorators, but are not
            # enclosing lexical scopes for method bodies or nested classes.
            local = enclosing.copy()
            child_enclosing = enclosing if isinstance(node, ast.ClassDef) else local
            for child in node.body:
                visit(child, path, local, child_enclosing)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, path, aliases, enclosing)

    aliases = {}
    visit(tree, [], aliases, aliases)
    return found


payload = json.load(sys.stdin)
before = ast.parse(payload["before"])
after = ast.parse(payload["after"])
reason = ""
for policy in payload["policies"]:
    if snapshot(before, policy) != snapshot(after, policy):
        reason = "Policy " + policy["id"] + ": route security decorator stack cannot be changed"
        break
json.dump({"denied": reason}, sys.stdout)
