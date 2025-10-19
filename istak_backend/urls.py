from django.contrib import admin
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from django.conf.urls.static import static
from istak_backend import settings
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

router = DefaultRouter()
router.register(r'requests', views.RegistrationRequestViewSet, basename='requests')

urlpatterns = [
   path("healthz/", views.healthz, name="healthz"),
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/register_mobile/', views.register_mobile, name='register_mobile'),
    path('api/login_manager/', views.login_manager, name='login_manager'),
    path('api/login_mobile/', views.login_mobile, name='login_mobile'),
    path('api/register_manager/', views.register_manager, name='register_manager'),
    path('api/approve_registration/', views.approve_registration, name='approve_registration'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/items/', views.ItemListCreateAPIView.as_view(), name='item-list-create'),
    path('api/items/<int:pk>/', views.ItemRetrieveUpdateDestroyAPIView.as_view(), name='item-detail'),
    path('api/items/by-id/<int:item_id>/', views.item_by_id, name='item-by-id'),
    path('api/managers/', views.manager_list, name='manager-list'),
    path('api/borrowing/create/', views.borrowing_create, name='borrowing-create'),
    path('api/user/', views.UserAPIView.as_view(), name='user-detail'),
    path('api/transactions/', views.TransactionListAPIView.as_view(), name='transaction-list'),
    path('api/update_fcm_token/', views.update_fcm_token, name='update_fcm_token'),
    path('api/top-borrowed-items/', views.top_borrowed_items, name='top_borrowed_items'),
    path('api/analytics/transactions/', views.AnalyticsTransactionsView.as_view(), name='analytics-transactions'),
    path('api/analytics/monthly-transactions/', views.MonthlyTransactionsView.as_view(), name='monthly-transactions'),
    path('api/update_overdue_transactions/', views.update_overdue_transactions, name='update_overdue_transactions'),
    path('api/item-status-count/', views.ItemStatusCountView.as_view(), name='item-status-count'),
    path('api/borrowers/', views.BorrowerListView.as_view(), name='borrower-list'),
    path('api/borrowers/<int:borrower_id>/transactions/', views.BorrowerTransactionsView.as_view(), name='borrower-transactions'),
    path('api/items/<str:itemId>/borrower/', views.item_borrower_view, name='item_borrower'),
    path('api/return_item/', views.return_item, name='return_item'),
    path('api/inventory/', views.InventorySummaryView.as_view(), name='inventory'),
    path('api/process_image/', views.ProcessImageView.as_view(), name='process_image'),
     path('api/forecast/top-items/', views.forecast_top_items_excel, name='forecast_top_items'),
     path('api/analytics/borrowed-stats/', views.borrowed_stats, name='total_borrow_ng_nakaraan'),
     path('api/transactions/<int:pk>/', views.TransactionRetrieveUpdateDestroyAPIView.as_view(), name='transaction-detail'),
   path('api/reports/damaged-lost-items/', views.DamagedOverdueReportView.as_view(), name='damaged-overdue-report'),
    path('api/current-user/', views.CurrentUserView.as_view(), name='current-user'),
    path('api/transactions/<str:pk>/', views.TransactionDeleteAPIView.as_view(), name='transaction-delete'),
    path('api/mobile-users/', views.MobileUsersList.as_view(), name='mobile-users-list'),
    path('api/change-password/<int:user_id>/', views.change_mobile_password, name='change-mobile-password'),
   path('api/predictive/insights/', views.PredictiveDamageInsightView.as_view(), name='predictive-insights'),
  path('api/reports/transactions/', views.TransactionReportView.as_view(), name='transaction-report'),
   path('api/items/simple/', views.SimpleItemListCreateAPIView.as_view(), name='simple_item_list_create'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)