import os
import re
import json
import tempfile
from ai_helper import classify_vulnerability_pattern, generate_template_params

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "vuln_templates")
BUILD_DIR = os.path.join(tempfile.gettempdir(), "cve_builds")

DEFAULT_PARAMS = {
    "table_name": "users",
    "column_names": ["id", "username", "secret"],
    "app_title": "Vulnerable App",
    "sample_row_1": "1, admin, secretpass",
    "sample_row_2": "2, john, doe123"
}

LABEL_KEY = "cyber_range_pattern"

LAB_KEY = "cyber_range_lab"

LAB_FIELDS = ("app_title", "endpoint", "param_name", "public_file",
              "secret_file", "table_name", "base_command","flag_token", "flag_reason" )


def get_image_tag(cve_id: str) -> str:
    safe = re.sub(r'[^a-z0-9\-]', '-', cve_id.lower())
    return f"cve-vuln-{safe}"


def _template_dir(pattern: str) -> str:
    return os.path.join(TEMPLATES_DIR, pattern)


def _resolve_pattern(cve_id: str, description: str, log) -> str:
    """Classify, then verify a usable template actually exists on disk."""
    log("classify", "Classifying vulnerability pattern…")
    pattern = classify_vulnerability_pattern(cve_id, description)
    log("classify", f"Pattern: {pattern}")

    if pattern != "unsupported":
        if not os.path.exists(os.path.join(_template_dir(pattern), "app.py.template")):
            log("classify", f"No template files for '{pattern}' — falling back to unsupported")
            pattern = "unsupported"

    if pattern == "unsupported" and not os.path.exists(
            os.path.join(_template_dir("unsupported"), "app.py.template")):
        raise FileNotFoundError(
            "No 'unsupported' fallback template found in vuln_templates/. "
            "Create vuln_templates/unsupported/{app.py.template,Dockerfile.template}."
        )
    return pattern


def _build_params(pattern: str, cve_id: str, description: str, log) -> dict:
    if pattern == "unsupported":
        return {
            "cve_id": cve_id,
            "description": description[:300].replace("{", "(").replace("}", ")"),
        }
    log("params", "Generating CVE-specific lab parameters…")
    params = generate_template_params(pattern, cve_id, description)
    log("params", f"endpoint=/{params.get('endpoint')} param={params.get('param_name')}")
    return params


def build_cve_image(docker_client, cve_id: str, description: str, emit=None):
    """
    Returns (image_tag, pattern). Raises on genuine failure.
    `emit(stage, message)` is optional — used to stream progress to the frontend.
    """
    def log(stage, msg):
        print(f"[BUILD:{stage}] {msg}")
        if emit:
            try:
                emit(stage, msg)
            except Exception:
                pass  # never let a broken SSE stream kill the build

    tag = get_image_tag(cve_id)

    # ---- 1. cached image, but only if it came from the current template ----
    try:
        image = docker_client.images.get(tag)
        labels = image.labels or {}
        cached_pattern = labels.get(LABEL_KEY)
        cached_fp = labels.get(FINGERPRINT_KEY)
        if cached_pattern and cached_fp == _template_fingerprint(cached_pattern):
            try:
                lab = json.loads(labels.get(LAB_KEY) or "{}")
            except Exception:
                lab = {}
            log("image", f"Cached image found ({cached_pattern}) — skipping build")
            return tag, cached_pattern, lab
        log("image", "Template changed since this image was built — rebuilding")
        try:
            docker_client.images.remove(tag, force=True)
        except Exception as e:
            log("image", f"Could not remove stale image: {e}")
    except Exception:
        log("image", "No cached image — building from template")

    

    # ---- 2. classify + fill template ----
    pattern = _resolve_pattern(cve_id, description, log)
    template_path = _template_dir(pattern)
    params = _build_params(pattern, cve_id, description, log)

    build_path = os.path.join(BUILD_DIR, tag)
    os.makedirs(build_path, exist_ok=True)

    app_tpl = os.path.join(template_path, "app.py.template")
    docker_tpl = os.path.join(template_path, "Dockerfile.template")
    for p in (app_tpl, docker_tpl):
        if not os.path.exists(p):
            raise FileNotFoundError(f"Missing template file: {p}")

    with open(app_tpl, encoding="utf-8") as f:
        raw = f.read()
    try:
        app_code = raw.format(**params)
    except KeyError as e:
        raise KeyError(
            f"Template '{pattern}/app.py.template' uses placeholder {e} "
            f"that wasn't provided. Available: {sorted(params)}"
        ) from e
    except (IndexError, ValueError) as e:
        raise ValueError(
            f"Template '{pattern}/app.py.template' has an unescaped brace. "
            f"Literal {{ and }} must be doubled as {{{{ and }}}}. Original error: {e}"
        ) from e

    with open(os.path.join(build_path, "app.py"), "w", encoding="utf-8") as f:
        f.write(app_code)

    with open(docker_tpl, encoding="utf-8") as f:
        dockerfile = f.read()
    with open(os.path.join(build_path, "Dockerfile"), "w", encoding="utf-8") as f:
        f.write(dockerfile)

    # ---- 3. build, streaming docker's own output ----
    lab = {k: params[k] for k in LAB_FIELDS if k in params}

    log("build", f"Building image {tag} from pattern '{pattern}'…")
    last_step = None
    try:
        for chunk in docker_client.api.build(
            path=build_path, tag=tag, rm=True,
            labels={
                LABEL_KEY: pattern,
                FINGERPRINT_KEY: _template_fingerprint(pattern),
                LAB_KEY: json.dumps(lab),
            },
            decode=True
        ):
            if "stream" in chunk:
                line = chunk["stream"].strip()
                if line.startswith("Step ") and line != last_step:
                    last_step = line
                    log("build", line)
            elif "error" in chunk:
                raise RuntimeError(chunk["error"].strip())
    except Exception as e:
        raise RuntimeError(f"Docker build failed for {tag}: {e}") from e

    docker_client.images.get(tag)
    log("build", f"Image {tag} ready")
    return tag, pattern, lab


import hashlib

TEMPLATE_VERSION = "2"      # bump manually for a forced global rebuild
FINGERPRINT_KEY = "cyber_range_fingerprint"


def _template_fingerprint(pattern: str) -> str:
    """Hash the template files so edits automatically invalidate cached images."""
    h = hashlib.sha256()
    h.update(TEMPLATE_VERSION.encode())
    h.update(pattern.encode())
    for name in ("app.py.template", "Dockerfile.template"):
        path = os.path.join(_template_dir(pattern), name)
        try:
            with open(path, "rb") as f:
                h.update(f.read())
        except FileNotFoundError:
            pass
    return h.hexdigest()[:16]