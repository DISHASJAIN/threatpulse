from rest_framework.routers import DefaultRouter
from .views import NetworkLogViewSet, AlertViewSet

router = DefaultRouter()
router.register('logs', NetworkLogViewSet)
router.register('alerts', AlertViewSet)
urlpatterns = router.urls