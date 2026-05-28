#!/usr/bin/env python3
"""Generate Bruno .bru files from Okta's OpenAPI specs.

Reads two YAML specs (management + oauth) from Okta's public GitHub repo
and emits one .bru file per operation into bruno/Management/<Tag>/ and
bruno/OIDC-OAuth/<Tag>/. The _Curated/ and environments/ folders are
never read or modified.

Run: python3 scripts/generate.py
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

import requests
import yaml

OKTA_SPEC_VERSION = "current"  # use "current" for latest, or pin like "2026.05.1"
SPEC_BASE_URL = (
    "https://raw.githubusercontent.com/okta/okta-management-openapi-spec/master/dist"
)
SPEC_FILES = {
    "management": "management-minimal.yaml",
    "oauth": "oauth-minimal.yaml",
}

REPO_ROOT = Path(__file__).resolve().parent.parent
SPECS_DIR = REPO_ROOT / "specs"
BRUNO_ROOT = REPO_ROOT / "bruno"
TARGET_DIRS = {
    "management": BRUNO_ROOT / "Management",
    "oauth": BRUNO_ROOT / "OIDC-OAuth",
}


# ----- Spec loading -------------------------------------------------------

def download_specs() -> dict[str, Path]:
    """Download spec files into specs/ and return paths keyed by spec name."""
    SPECS_DIR.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for name, filename in SPEC_FILES.items():
        url = f"{SPEC_BASE_URL}/{OKTA_SPEC_VERSION}/{filename}"
        version_tag = OKTA_SPEC_VERSION
        local_name = f"{name}-{version_tag}.yaml"
        local_path = SPECS_DIR / local_name
        print(f"Downloading {url}")
        resp = requests.get(url, timeout=120)
        resp.raise_for_status()
        local_path.write_bytes(resp.content)
        paths[name] = local_path
        print(f"  -> saved to {local_path.relative_to(REPO_ROOT)} ({len(resp.content):,} bytes)")
    return paths


def load_spec(path: Path) -> dict[str, Any]:
    with open(path) as f:
        return yaml.safe_load(f)


# ----- Sanitization -------------------------------------------------------

_FS_INVALID = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

def sanitize_filename(name: str, max_len: int = 120) -> str:
    """Make a string safe for use as a filename."""
    s = _FS_INVALID.sub("", name).strip()
    s = re.sub(r"\s+", " ", s)
    s = s.rstrip(". ")
    if not s:
        s = "untitled"
    return s[:max_len]


def sanitize_dirname(name: str) -> str:
    return sanitize_filename(name, max_len=80)


# ----- URL + parameter handling ------------------------------------------

def template_path(spec_path: str) -> str:
    """Convert /api/v1/users/{userId} to /api/v1/users/{{userId}}.

    Bruno uses double braces for variables. OpenAPI uses single.
    """
    return re.sub(r"\{([^}]+)\}", r"{{\1}}", spec_path)


def split_params(operation: dict, path_item: dict) -> tuple[list[dict], list[dict]]:
    """Return (path_params, query_params) for an operation.

    Merges path-level and operation-level parameters per OpenAPI spec.
    """
    combined: list[dict] = []
    seen: set[str] = set()
    # operation-level parameters override path-level
    for source in (operation.get("parameters", []), path_item.get("parameters", [])):
        for p in source:
            key = (p.get("name"), p.get("in"))
            if key in seen:
                continue
            seen.add(key)
            combined.append(p)
    path_params = [p for p in combined if p.get("in") == "path"]
    query_params = [p for p in combined if p.get("in") == "query"]
    return path_params, query_params


# ----- Auth resolution ----------------------------------------------------

def resolve_auth(spec_kind: str, security_schemes: dict, operation: dict) -> dict:
    """Pick an auth strategy for the operation.

    Returns a dict: {"header_lines": [...], "auth_block": "..." or None,
                     "url_auth_marker": "none"|"basic"|"bearer"|"apikey"}.

    Strategy:
      - If operation has explicit security: [], the request is unauthenticated.
      - For management spec: default to SSWS apiKey header.
      - For oauth spec: pick basic auth, bearer, or none based on declared schemes.
    """
    op_security = operation.get("security")
    # Explicit empty security means no auth on this endpoint.
    if op_security == []:
        return {"header_lines": [], "auth_block": None, "url_auth_marker": "none"}

    if spec_kind == "management":
        return {
            "header_lines": ["Authorization: SSWS {{apiKey}}"],
            "auth_block": None,
            "url_auth_marker": "none",
        }

    # OAuth/OIDC: read declared schemes
    if not op_security:
        return {"header_lines": [], "auth_block": None, "url_auth_marker": "none"}

    requirement = op_security[0] if isinstance(op_security, list) else {}
    chosen_scheme: str | None = None
    for scheme_name in requirement.keys():
        scheme_def = security_schemes.get(scheme_name, {})
        scheme_type = scheme_def.get("type", "")
        if scheme_type == "http" and scheme_def.get("scheme") == "basic":
            chosen_scheme = "basic"
            break
        if scheme_type == "http" and scheme_def.get("scheme") == "bearer":
            chosen_scheme = "bearer"
            break
        if scheme_type == "oauth2":
            chosen_scheme = "bearer"
            break
        if scheme_type == "apiKey":
            chosen_scheme = "apikey"
            break

    if chosen_scheme == "basic":
        block = (
            "auth:basic {\n"
            "  username: {{oauthClientId}}\n"
            "  password: {{oauthClientSecret}}\n"
            "}"
        )
        return {"header_lines": [], "auth_block": block, "url_auth_marker": "basic"}
    if chosen_scheme == "bearer":
        block = (
            "auth:bearer {\n"
            "  token: {{bearerToken}}\n"
            "}"
        )
        return {"header_lines": [], "auth_block": block, "url_auth_marker": "bearer"}

    return {"header_lines": [], "auth_block": None, "url_auth_marker": "none"}


# ----- Body builder -------------------------------------------------------

def schema_to_skeleton(schema: dict, spec: dict, depth: int = 0) -> Any:
    """Build a minimal example value from an OpenAPI schema.

    Resolves $ref references against the full spec. Bounded recursion to
    avoid infinite loops on circular schemas.
    """
    if depth > 4 or not isinstance(schema, dict):
        return None

    if "$ref" in schema:
        ref = schema["$ref"]
        # only handle local refs like #/components/schemas/Foo
        if ref.startswith("#/"):
            parts = ref.lstrip("#/").split("/")
            target: Any = spec
            for part in parts:
                if isinstance(target, dict) and part in target:
                    target = target[part]
                else:
                    return None
            return schema_to_skeleton(target, spec, depth + 1)
        return None

    if "example" in schema:
        return schema["example"]

    if "default" in schema:
        return schema["default"]

    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]

    type_ = schema.get("type")

    if type_ == "object" or "properties" in schema:
        out: dict[str, Any] = {}
        props = schema.get("properties", {})
        required = set(schema.get("required", []))
        for prop_name, prop_schema in props.items():
            if required and prop_name not in required:
                continue  # skeleton only includes required fields
            value = schema_to_skeleton(prop_schema, spec, depth + 1)
            if value is not None or prop_name in required:
                out[prop_name] = value if value is not None else ""
        if not out and not required:
            # fallback: include first property even if not required
            for prop_name, prop_schema in list(props.items())[:1]:
                out[prop_name] = schema_to_skeleton(prop_schema, spec, depth + 1) or ""
        return out

    if type_ == "array":
        item_schema = schema.get("items", {})
        item = schema_to_skeleton(item_schema, spec, depth + 1)
        return [item] if item is not None else []

    if type_ == "string":
        format_ = schema.get("format", "")
        if format_ == "date-time":
            return "2026-01-01T00:00:00Z"
        if format_ == "date":
            return "2026-01-01"
        if format_ == "uuid":
            return "00000000-0000-0000-0000-000000000000"
        if format_ == "email":
            return "user@example.com"
        if format_ == "uri":
            return "https://example.com"
        return ""

    if type_ == "integer":
        return 0
    if type_ == "number":
        return 0.0
    if type_ == "boolean":
        return False

    # oneOf/anyOf/allOf — pick first
    for key in ("oneOf", "anyOf", "allOf"):
        variants = schema.get(key, [])
        if variants:
            if key == "allOf":
                merged: dict[str, Any] = {}
                for v in variants:
                    val = schema_to_skeleton(v, spec, depth + 1)
                    if isinstance(val, dict):
                        merged.update(val)
                return merged or None
            return schema_to_skeleton(variants[0], spec, depth + 1)

    return None


def build_request_body(operation: dict, spec: dict) -> tuple[str, str | None]:
    """Return (body_marker, body_block_text).

    body_marker is the value for the http method's `body:` field
    ("none", "json", "formUrlEncoded", "multipartForm", "text").
    body_block_text is the full Bruno body block, or None for body:none.
    """
    request_body = operation.get("requestBody")
    if not request_body:
        return "none", None

    content = request_body.get("content", {})
    if not content:
        return "none", None

    # Prefer JSON
    if "application/json" in content:
        media = content["application/json"]
        example = media.get("example")
        if example is None:
            schema = media.get("schema", {})
            example = schema_to_skeleton(schema, spec)
        if example is None:
            example = {}
        body_text = json.dumps(example, indent=2)
        # Indent each line two spaces inside the bruno block
        indented = "\n".join("  " + line for line in body_text.splitlines())
        return "json", "body:json {\n" + indented + "\n}"

    if "application/x-www-form-urlencoded" in content:
        media = content["application/x-www-form-urlencoded"]
        schema = media.get("schema", {})
        skeleton = schema_to_skeleton(schema, spec) or {}
        if not isinstance(skeleton, dict):
            skeleton = {}
        lines = [f"  {k}: {v if v not in (None, '') else ''}" for k, v in skeleton.items()]
        body = "body:form-urlencoded {\n" + "\n".join(lines) + ("\n" if lines else "") + "}"
        return "formUrlEncoded", body

    if "multipart/form-data" in content:
        return "multipartForm", "body:multipart-form {\n  # populate fields here\n}"

    if "text/plain" in content:
        return "text", "body:text {\n  \n}"

    # Unknown content type — fall back to none
    return "none", None


# ----- .bru file emission -------------------------------------------------

def emit_bru_file(
    target_path: Path,
    seq: int,
    method: str,
    name: str,
    url: str,
    headers: list[str],
    query_params: list[dict],
    body_marker: str,
    body_block: str | None,
    auth_marker: str,
    auth_block: str | None,
    docs: str,
) -> None:
    """Write a single .bru file with all blocks."""
    parts: list[str] = []

    # meta
    parts.append(
        "meta {\n"
        f"  name: {name}\n"
        "  type: http\n"
        f"  seq: {seq}\n"
        "}"
    )

    # http method
    parts.append(
        f"{method.lower()} {{\n"
        f"  url: {url}\n"
        f"  body: {body_marker}\n"
        f"  auth: {auth_marker}\n"
        "}"
    )

    # query params
    if query_params:
        param_lines = []
        for p in query_params:
            pname = p.get("name", "")
            required = p.get("required", False)
            schema = p.get("schema", {})
            default_val = schema.get("default", "")
            prefix = "" if required else "~"
            param_lines.append(f"  {prefix}{pname}: {default_val}")
        parts.append("params:query {\n" + "\n".join(param_lines) + "\n}")

    # headers
    header_lines = ["  Accept: application/json"]
    if body_marker == "json":
        header_lines.append("  Content-Type: application/json")
    for h in headers:
        header_lines.append(f"  {h}")
    parts.append("headers {\n" + "\n".join(header_lines) + "\n}")

    # auth
    if auth_block:
        parts.append(auth_block)

    # body
    if body_block:
        parts.append(body_block)

    # docs
    safe_docs = docs.strip().replace("\r", "")
    if safe_docs:
        parts.append("docs {\n" + safe_docs + "\n}")

    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text("\n\n".join(parts) + "\n", encoding="utf-8")


# ----- Operation processor -----------------------------------------------

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def process_spec(spec_kind: str, spec: dict) -> int:
    """Walk every operation in a spec and emit .bru files. Returns count."""
    target_root = TARGET_DIRS[spec_kind]
    security_schemes = spec.get("components", {}).get("securitySchemes", {})

    # Build seq counters per folder so each folder has 1..N
    folder_seq: dict[Path, int] = {}
    written = 0
    skipped = 0

    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            tags = operation.get("tags", ["Untagged"])
            tag = tags[0] if tags else "Untagged"
            folder = target_root / sanitize_dirname(tag)

            summary = operation.get("summary") or operation.get("operationId") or f"{method.upper()} {path}"
            base_filename = sanitize_filename(summary) + ".bru"
            target_path = folder / base_filename

            # If a sibling already exists for this summary, both files get the
            # HTTP method prefixed so the user sees "GET foo.bru" and
            # "POST foo.bru" instead of "foo.bru" and "foo (operationId).bru".
            if target_path.exists():
                method_upper = method.upper()
                target_path = folder / (sanitize_filename(f"{method_upper} {summary}") + ".bru")
                # Rename the pre-existing colliding file too, if it doesn't already have a method prefix.
                existing = folder / base_filename
                if existing.exists():
                    existing_text = existing.read_text(encoding="utf-8")
                    existing_method_match = re.search(
                        r"^\s*(get|post|put|patch|delete|head|options)\s*\{",
                        existing_text,
                        re.MULTILINE,
                    )
                    if existing_method_match:
                        existing_method = existing_method_match.group(1).upper()
                        renamed = folder / (
                            sanitize_filename(f"{existing_method} {summary}") + ".bru"
                        )
                        if not renamed.exists():
                            existing.rename(renamed)
                # Final safety net: if even the method-prefixed name collides, append a counter.
                if target_path.exists():
                    n = 2
                    base = target_path.stem
                    while target_path.exists():
                        target_path = folder / f"{base} ({n}).bru"
                        n += 1

            seq = folder_seq.get(folder, 0) + 1
            folder_seq[folder] = seq

            url = "{{orgUrl}}" + template_path(path)
            path_params, query_params = split_params(operation, path_item)
            auth = resolve_auth(spec_kind, security_schemes, operation)
            body_marker, body_block = build_request_body(operation, spec)

            description = operation.get("description") or operation.get("summary") or ""
            responses = operation.get("responses", {})
            response_lines = []
            for code, resp in sorted(responses.items()):
                if not isinstance(resp, dict):
                    continue
                desc = resp.get("description", "").strip().split("\n")[0]
                response_lines.append(f"- `{code}`: {desc}")
            docs = description.strip()
            if response_lines:
                docs = (docs + "\n\n**Responses:**\n" + "\n".join(response_lines)).strip()
            if path_params:
                pp_lines = ["\n**Path parameters:**"]
                for p in path_params:
                    pname = p.get("name", "")
                    pdesc = (p.get("description") or "").strip().split("\n")[0]
                    pp_lines.append(f"- `{{{{{pname}}}}}` — {pdesc}".rstrip(" —"))
                docs = (docs + "\n" + "\n".join(pp_lines)).strip()

            try:
                emit_bru_file(
                    target_path=target_path,
                    seq=seq,
                    method=method,
                    name=summary,
                    url=url,
                    headers=auth["header_lines"],
                    query_params=query_params,
                    body_marker=body_marker,
                    body_block=body_block,
                    auth_marker=auth["url_auth_marker"],
                    auth_block=auth["auth_block"],
                    docs=docs,
                )
                written += 1
            except Exception as e:
                print(f"  SKIP {method.upper()} {path} ({summary}): {e}", file=sys.stderr)
                skipped += 1

    print(f"  {spec_kind}: wrote {written} files, skipped {skipped}")
    return written


# ----- Main ---------------------------------------------------------------

def wipe_generated_dirs() -> None:
    for path in TARGET_DIRS.values():
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True, exist_ok=True)


def write_manifest(counts: dict[str, int]) -> None:
    manifest = {
        "spec_version": OKTA_SPEC_VERSION,
        "counts": counts,
        "generated_dirs": [str(p.relative_to(REPO_ROOT)) for p in TARGET_DIRS.values()],
    }
    BRUNO_ROOT.mkdir(parents=True, exist_ok=True)
    (BRUNO_ROOT / ".generated-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


def main() -> int:
    print(f"Okta Bruno generator — spec version: {OKTA_SPEC_VERSION}")
    print(f"Repo root: {REPO_ROOT}")

    spec_paths = download_specs()

    print("\nWiping previously generated folders…")
    wipe_generated_dirs()

    counts: dict[str, int] = {}
    for kind, path in spec_paths.items():
        print(f"\nLoading {kind} spec: {path.name}")
        spec = load_spec(path)
        print(f"  paths: {len(spec.get('paths', {}))}")
        counts[kind] = process_spec(kind, spec)

    write_manifest(counts)
    total = sum(counts.values())
    print(f"\nDone. {total} .bru files written across {len(counts)} specs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
