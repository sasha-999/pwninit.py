import os


def get_templates_folder():
    return os.path.join(os.path.dirname(__file__), "templates/")


def get_available_templates():
    templates = []
    for file in os.listdir(get_templates_folder()):
        if not file.endswith(".py"):
            continue
        templates.append(file.rsplit(".py", 1)[0])
    return templates


def get_template(name):
    path = os.path.join(get_templates_folder(), f"{name}.py")
    try:
        f = open(path, "r")
    except OSError:
        return None

    with f:
        return f.read()
