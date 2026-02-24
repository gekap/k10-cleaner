# k10-cleaner — thin kubectl subprocess wrapper
# Copyright (c) 2026 Georgios Kapellakis
# Licensed under AGPL-3.0 — see LICENSE for details.

from __future__ import annotations

import json
import subprocess


class Kubectl:
    """Thin wrapper around kubectl. All methods return safe defaults on failure."""

    def __init__(self, timeout: int = 30):
        self._timeout = timeout

    def run(self, args: list[str], timeout: int | None = None) -> tuple[int, str, str]:
        """Run kubectl with args. Returns (returncode, stdout, stderr)."""
        timeout = timeout if timeout is not None else self._timeout
        try:
            proc = subprocess.run(
                ["kubectl"] + args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return 1, "", "timeout"
        except FileNotFoundError:
            return 1, "", "kubectl not found"

    def get_json(self, args: list[str], timeout: int | None = None) -> dict | list | None:
        """Run kubectl with -o json and parse output. Returns None on failure."""
        rc, out, _ = self.run(args + ["-o", "json"], timeout=timeout)
        if rc != 0 or not out.strip():
            return None
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return None

    def get_lines(self, args: list[str], timeout: int | None = None) -> list[str]:
        """Run kubectl and return non-empty stdout lines."""
        rc, out, _ = self.run(args, timeout=timeout)
        if rc != 0:
            return []
        return [l for l in out.splitlines() if l.strip()]

    def get_namespace_uid(self, namespace: str = "kube-system") -> str:
        """Get the UID of a namespace. Returns empty string on failure."""
        rc, out, _ = self.run(
            ["get", "namespace", namespace, "-o", "jsonpath={.metadata.uid}"]
        )
        if rc != 0:
            return ""
        return out.strip()

    def get_current_context(self) -> str:
        rc, out, _ = self.run(["config", "current-context"])
        if rc != 0:
            return ""
        return out.strip()

    def get_cluster_name(self) -> str:
        rc, out, _ = self.run(
            ["config", "view", "--minify", "-o", "jsonpath={.clusters[0].name}"]
        )
        if rc != 0:
            return ""
        return out.strip()

    def get_server_url(self) -> str:
        rc, out, _ = self.run(
            ["config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}"]
        )
        if rc != 0:
            return ""
        return out.strip()

    def get_node_labels_json(self) -> str:
        """Get first node's labels as JSON string."""
        rc, out, _ = self.run(
            ["get", "nodes", "-o", "jsonpath={.items[0].metadata.labels}"]
        )
        if rc != 0:
            return ""
        return out.strip()

    def get_server_version(self) -> str:
        rc, out, _ = self.run(["version"])
        if rc != 0:
            # Try --short for older kubectl
            rc, out, _ = self.run(["version", "--short"])
            if rc != 0:
                return ""
        return out.strip()

    def get_ns_env_labels(self) -> str:
        """Get env/environment labels from all namespaces as space-separated string."""
        rc, out, _ = self.run(
            [
                "get", "namespaces", "-o",
                "jsonpath={range .items[*]}{.metadata.labels.env}{\" \"}{.metadata.labels.environment}{\" \"}{end}",
            ]
        )
        if rc != 0:
            return ""
        return out.strip()

    def get_node_env_labels(self) -> str:
        """Get env/environment labels from all nodes as space-separated string."""
        rc, out, _ = self.run(
            [
                "get", "nodes", "-o",
                "jsonpath={range .items[*]}{.metadata.labels.env}{\" \"}{.metadata.labels.environment}{\" \"}{end}",
            ]
        )
        if rc != 0:
            return ""
        return out.strip()

    def count_resources(self, resource: str, extra_args: list[str] | None = None) -> int:
        """Count resources by running get --no-headers and counting lines."""
        args = ["get", resource, "--no-headers"]
        if extra_args:
            args.extend(extra_args)
        lines = self.get_lines(args)
        return len(lines)

    def create_from_yaml(self, yaml_str: str, namespace: str) -> tuple[bool, str]:
        """kubectl create -n <ns> -f - from yaml string. Returns (success, output)."""
        try:
            proc = subprocess.run(
                ["kubectl", "create", "-n", namespace, "-f", "-"],
                input=yaml_str,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            output = (proc.stdout + proc.stderr).strip()
            return proc.returncode == 0, output
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return False, str(e)

    def delete_resource(self, resource: str, name: str, namespace: str) -> tuple[bool, str]:
        """kubectl delete <resource> <name> -n <ns>. Returns (success, output)."""
        rc, out, err = self.run(["delete", resource, name, "-n", namespace])
        return rc == 0, (out + err).strip()

    def namespace_exists(self, namespace: str) -> bool:
        rc, _, _ = self.run(["get", "namespace", namespace])
        return rc == 0
