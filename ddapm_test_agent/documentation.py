from pathlib import Path

tag_filter = set(["traceparent", "tracestate", "runtime-id", "_sampling_priority_v1", "language", "component", "process_id", "env"])

class ApmPackageDocumentation:
    def __init__(self, span):
        meta = span.get("meta", {})
        metrics = span.get("meta", {})
        self.component = meta.get("component", "")
        self.name = span["name"]
        self.span_type = span.get("type", None)
        self.tags = {}
        for tag, value in {**meta, **metrics}.items():
            if tag not in tag_filter and tag[0] != "_" and tag[0:5] != "error":
                self.tags[tag] = {
                    "required": True,
                    "value": value
                }


    def update(self, span):
        updated_tags = {}
        meta = span.get("meta", {})
        metrics = span.get("metrics", {})
        for tag, value in {**meta, **metrics}.items():
            if tag not in tag_filter and tag[0] != "_" and tag[0:5] != "error":
                if tag in self.tags:
                    updated_tags[tag] = {
                        "value": value if self.tags[tag]["value"] == value else None,
                        "required": self.tags[tag]["required"],
                    }
                    self.tags[tag] = updated_tags[tag]
                else:
                    updated_tags[tag] = {
                        "required": False,
                        "value": value
                    }
                    self.tags[tag] = updated_tags[tag]

        for tag_name in self.tags:
            if tag_name not in updated_tags:
                self.tags[tag_name]["required"] = False

    def to_markdown(self):
        markdown = f"## {self.component}\n"
        markdown += "### Span properties\n"
        markdown += "Name | Value |\n---------|----------------|\n"
        markdown += f"Name | `{self.name}`\n"
        if self.span_type:
            markdown += f"Type | `{self.span_type}`\n"

        markdown += "### Tags\n"
        markdown += "Name | Required |\n---------|----------------|\n"
        for tag in self.tags.keys().sort():
            required = "Yes" if self.tags[tag]["required"] else "No"
            value = self.tags[tag]["value"] if self.tags[tag]["value"] is not None else required
            markdown += f"{tag} | `{value}`\n"

        return markdown

def create_documentation(documentation, span, component, schema_version):
    if schema_version not in documentation:
        documentation[schema_version] = {}
    documentation_hash = component + ";" + span["name"]
    if documentation_hash in documentation[schema_version]:
        documentation[schema_version][documentation_hash].update(span)
    else:
        documentation[schema_version][documentation_hash] = ApmPackageDocumentation(span)

    return documentation


def documentation_to_markdown(documentation, schema_version):
    for component in documentation[schema_version].keys().sort():
        markdown = "This file is intended for development purposes only.\n"
        markdown += documentation[schema_version][component].to_markdown()
        markdown += "\n"

        dir = Path(f'documentation/generated/{schema_version}')
        dir.mkdir(parents=True, exist_ok=True)
        file1 = dir.joinpath(f"{component}.md")
        file1.touch(exist_ok=True)

        with open(file1, 'w+') as file:
            file.write(markdown)
            file.close()


if __name__ == "__main__":
    documentation_to_markdown({}, "v1")
