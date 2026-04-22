import os
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
from channels.auth import AuthMiddlewareStack
import threat_detection.routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'insider_threat.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter(
            threat_detection.routing.websocket_urlpatterns
        )
    ),
})