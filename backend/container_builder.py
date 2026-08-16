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

def build_cve_image(docker_client, cve_id: str, description: str) -> str:
    """Returns the image tag, building it only if it doesn't already exist."""
    tag = get_image_tag(cve_id)

    try:
        docker_client.images.get(tag)
        return tag  # already built — reuse
    except Exception:
        pass

    pattern = classify_vulnerability_pattern(cve_id, description)
    template_path = os.path.join(TEMPLATES_DIR, pattern)

    if not os.path.exists(os.path.join(template_path, "app.py.template")):
        print(f"[WARN] No template for pattern '{pattern}', falling back to sql_injection")
        pattern = "sql_injection"
        template_path = os.path.join(TEMPLATES_DIR, pattern)

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
    docker_client.images.build(path=build_path, tag=tag, rm=True)
    return tag