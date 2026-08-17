import os
import re
from ai_helper import classify_vulnerability_pattern, generate_template_params

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "vuln_templates")
BUILD_DIR = "/tmp/cve_builds"

DEFAULT_PARAMS = {
    "table_name": "users",
    "column_names": ["id", "username", "secret"],
    "app_title": "Vulnerable App",
    "sample_row_1": "1, admin, secretpass",
    "sample_row_2": "2, john, doe123"
}

def get_image_tag(cve_id: str) -> str:
    safe = re.sub(r'[^a-z0-9\-]', '-', cve_id.lower())
    return f"cve-vuln-{safe}"

def build_cve_image(docker_client, cve_id: str, description: str):
    """Returns (image_tag, pattern). Builds only if not already cached."""
    tag = get_image_tag(cve_id)

    try:
        docker_client.images.get(tag)
        # already built — we still need to know which pattern it used,
        # so store it in a sidecar label lookup instead of re-classifying.
        image = docker_client.images.get(tag)
        pattern = image.labels.get("cyber_range_pattern", "unknown")
        return tag, pattern
    except Exception:
        pass

    pattern = classify_vulnerability_pattern(cve_id, description)
    template_path = os.path.join(TEMPLATES_DIR, pattern)

    # genuine dev bug: classifier picked a real pattern name but its files are missing
    if pattern != "unsupported" and not os.path.exists(os.path.join(template_path, "app.py.template")):
        print(f"[WARN] Pattern '{pattern}' has no template files — treating as unsupported")
        pattern = "unsupported"
        template_path = os.path.join(TEMPLATES_DIR, "unsupported")

    if pattern == "unsupported":
        template_path = os.path.join(TEMPLATES_DIR, "unsupported")
        params = {"cve_id": cve_id, "description": description[:300]}
    else:
        params = generate_template_params(pattern, cve_id, description)
        for key, default in DEFAULT_PARAMS.items():
            params.setdefault(key, default)

    build_path = os.path.join(BUILD_DIR, tag)
    os.makedirs(build_path, exist_ok=True)

    with open(os.path.join(template_path, "app.py.template")) as f:
        app_code = f.read().format(**params)
    with open(os.path.join(build_path, "app.py"), "w") as f:
        f.write(app_code)

    with open(os.path.join(template_path, "Dockerfile.template")) as f:
        dockerfile = f.read()
    with open(os.path.join(build_path, "Dockerfile"), "w") as f:
        f.write(dockerfile)

    print(f"[BUILD] Building image {tag} from pattern '{pattern}'...")
    docker_client.images.build(path=build_path, tag=tag, rm=True, labels={"cyber_range_pattern": pattern})
    return tag, pattern