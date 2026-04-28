"""DRF renderers for non-JSON responses."""

from rest_framework.renderers import BaseRenderer, JSONRenderer
from rest_framework.utils import json


class PrometheusTextRenderer(BaseRenderer):
    """
    Registers `text/plain` so content negotiation succeeds when clients send
    `Accept: text/plain` (e.g. Prometheus scrapers, admin UI).

    Successful metrics responses are plain `HttpResponse` bytes from the view; this
    renderer is only used when the handler returns a `Response` — we encode
    errors as JSON bytes so staff still get structured 401/403 bodies.
    """

    media_type = 'text/plain'
    format = 'txt'
    charset = 'utf-8'

    def render(self, data, accepted_media_type=None, renderer_context=None):
        if data is None:
            return b''
        if isinstance(data, (bytes, bytearray, memoryview)):
            return bytes(data)
        if isinstance(data, str):
            return data.encode(self.charset)
        return json.dumps(data).encode(self.charset)


DEFAULT_METRICS_RENDERERS = [JSONRenderer, PrometheusTextRenderer]
