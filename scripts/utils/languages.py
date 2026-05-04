"""Language and framework detection utilities."""

import re
from pathlib import Path

EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".java": "java",
    ".kt": "kotlin",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".rs": "rust",
    ".swift": "swift",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "bash",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".html": "html",
    ".htm": "html",
    ".jinja": "jinja2",
    ".jinja2": "jinja2",
    ".j2": "jinja2",
    ".twig": "twig",
    ".erb": "erb",
    ".ejs": "ejs",
    ".hbs": "handlebars",
    ".mustache": "mustache",
    ".dockerfile": "dockerfile",
    ".env": "dotenv",
    ".ini": "ini",
    ".toml": "toml",
    ".properties": "properties",
}

FRAMEWORK_SIGNALS = {
    "python": {
        "flask": ["from flask import", "import flask", "Flask(__name__)", "@app.route"],
        "django": ["from django", "import django", "django.db", "INSTALLED_APPS"],
        "fastapi": ["from fastapi", "import fastapi", "FastAPI()", "@app.get", "@router.get"],
        "tornado": ["import tornado", "tornado.web"],
        "aiohttp": ["from aiohttp", "import aiohttp", "web.Application()"],
        "pyramid": ["from pyramid", "import pyramid"],
    },
    "javascript": {
        "express": ["require('express')", "from 'express'", "express()", "app.get(", "router.get("],
        "nextjs": ["from 'next'", "require('next')", "getServerSideProps", "getStaticProps"],
        "nestjs": ["@Module", "@Controller", "@Injectable", "from '@nestjs"],
        "koa": ["require('koa')", "from 'koa'", "new Koa()"],
        "hapi": ["require('@hapi/hapi')", "Hapi.server("],
        "react": ["from 'react'", "require('react')", "React.createElement", "useState", "useEffect"],
        "vue": ["from 'vue'", "createApp(", "Vue.component("],
    },
    "java": {
        "spring": ["@SpringBootApplication", "@RestController", "@Controller", "@Service", "@Repository",
                   "import org.springframework"],
        "struts": ["import org.apache.struts", "ActionSupport"],
        "jersey": ["import javax.ws.rs", "import jakarta.ws.rs"],
        "dropwizard": ["io.dropwizard"],
        "servlet": ["HttpServlet", "HttpServletRequest", "doGet", "doPost"],
    },
    "php": {
        "laravel": ["use Illuminate", "App\\", "artisan", "Eloquent"],
        "symfony": ["use Symfony", "Symfony\\Component"],
        "wordpress": ["wp_query", "get_post", "add_action", "WP_"],
        "codeigniter": ["CI_Controller", "$this->load->model"],
    },
    "ruby": {
        "rails": ["Rails.application", "ActiveRecord::Base", "ActionController", "has_many", "belongs_to"],
        "sinatra": ["require 'sinatra'", "Sinatra::Base"],
    },
    "go": {
        "gin": ['"github.com/gin-gonic/gin"', "gin.Default()", "gin.New()"],
        "echo": ['"github.com/labstack/echo"', "echo.New()"],
        "fiber": ['"github.com/gofiber/fiber"', "fiber.New()"],
        "chi": ['"github.com/go-chi/chi"'],
        "gorilla": ['"github.com/gorilla/mux"'],
        "stdlib": ["net/http", "http.HandleFunc", "http.ServeMux"],
    },
}

SKIP_DIRS = {
    "node_modules", ".git", "vendor", "__pycache__", ".tox", "venv", ".venv",
    "env", ".env", "dist", "build", "target", ".gradle", ".mvn",
    "coverage", ".coverage", "htmlcov", ".pytest_cache", ".mypy_cache",
    "site-packages", "eggs", ".eggs", "migrations", "static", "assets",
    "public", "media", "uploads", ".idea", ".vscode", ".DS_Store",
}

SOURCE_EXTENSIONS = set(
    ext for ext, lang in EXTENSION_MAP.items()
    if lang in {"python", "javascript", "typescript", "java", "kotlin", "go",
                "php", "ruby", "c", "cpp", "csharp", "rust", "swift", "bash"}
)

CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".xml", ".env", ".ini", ".toml",
                     ".properties", ".tf", ".tfvars", ".dockerfile"}


def detect_language(file_path: Path) -> str:
    name = file_path.name.lower()
    if name == "dockerfile":
        return "dockerfile"
    if name == ".env" or name.startswith(".env."):
        return "dotenv"
    if name == "gemfile" or name == "gemfile.lock":
        return "ruby"
    if name in ("makefile", "gnumakefile"):
        return "make"
    ext = file_path.suffix.lower()
    return EXTENSION_MAP.get(ext, "unknown")


def detect_frameworks(file_path: Path, content: str, language: str) -> list:
    found = []
    signals = FRAMEWORK_SIGNALS.get(language, {})
    for framework, patterns in signals.items():
        if any(p in content for p in patterns):
            found.append(framework)
    return found


def is_test_file(file_path: Path) -> bool:
    parts = {p.lower() for p in file_path.parts}
    if "test" in parts or "tests" in parts or "spec" in parts or "__tests__" in parts:
        return True
    name = file_path.stem.lower()
    return (name.startswith("test_") or name.endswith("_test") or
            name.startswith("spec_") or name.endswith("_spec") or
            name.endswith(".test") or name.endswith(".spec"))


def is_generated_file(file_path: Path) -> bool:
    name = file_path.name.lower()
    generated_indicators = [
        "bundle.js", "bundle.min.js", ".min.js", ".min.css",
        "package-lock.json", "yarn.lock", "poetry.lock", "pipfile.lock",
        ".pb.go", "_pb2.py", "_pb2_grpc.py", "*.generated.",
    ]
    return any(name.endswith(ind.lstrip("*")) for ind in generated_indicators)


def should_skip_dir(dir_path: Path) -> bool:
    return dir_path.name.lower() in SKIP_DIRS or dir_path.name.startswith(".")


def get_manifest_files(base_path: Path) -> list:
    manifests = []
    manifest_names = {
        "requirements.txt", "requirements-dev.txt", "requirements-prod.txt",
        "Pipfile", "Pipfile.lock", "pyproject.toml", "setup.py", "setup.cfg",
        "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
        "go.mod", "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
        "Cargo.toml", "Cargo.lock", ".csproj", "packages.config", "paket.dependencies",
    }
    for p in base_path.rglob("*"):
        if p.is_file() and p.name in manifest_names:
            if not any(skip in p.parts for skip in SKIP_DIRS):
                manifests.append(p)
    return manifests
