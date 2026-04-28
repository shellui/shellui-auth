from django.http import HttpResponse
from django.urls import reverse


def root(request):
    swagger_url = reverse("swagger-ui")
    redoc_url = reverse("redoc")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ShellUI Auth</title>
  <style>
    body {{
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      line-height: 1.6;
      max-width: 40rem;
      margin: 4rem auto;
      padding: 0 1.5rem;
      color: #1a1a1a;
    }}
    h1 {{ font-size: 1.75rem; font-weight: 600; margin-bottom: 0.5rem; }}
    p {{ color: #444; margin-bottom: 1.5rem; }}
    ul {{ padding-left: 1.25rem; }}
    li {{ margin: 0.5rem 0; }}
    a {{ color: #0b57d0; }}
    a:visited {{ color: #5c2d91; }}
  </style>
</head>
<body>
  <h1>Welcome to ShellUI Auth</h1>
  <p>This service exposes authentication and related APIs. Explore the OpenAPI documentation using Swagger UI or ReDoc.</p>
  <ul>
    <li><a href="{swagger_url}">Swagger UI</a></li>
    <li><a href="{redoc_url}">ReDoc</a></li>
  </ul>
</body>
</html>"""
    return HttpResponse(html)
