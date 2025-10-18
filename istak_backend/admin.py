from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group

from .models import (
    CustomUser,
    Borrower,
    Item,
    RegistrationRequest,
    StudentOrgOfficer,   # proxy for user_web
    StudentOrgModerator, # proxy for user_mobile
    Transaction,
)

# --- SITE TITLES ---
admin.site.site_header = "ISTAK Administration Panel"
admin.site.site_title = "ISTAK Admin Portal"
admin.site.index_title = "Welcome to ISTAK Management System"

# --- (Optional) hide Groups tab safely --- 
try:
    admin.site.unregister(Group)
except admin.sites.NotRegistered:
    pass


# ==========================================================
# Hidden CustomUser admin (required by autocomplete_fields)
#   - stays registered so admin.E039 is satisfied
#   - hidden from the admin index/sidebar
# ==========================================================
# @admin.register(CustomUser)
# class HiddenCustomUserAdmin(UserAdmin):
#     list_display = ("username", "email", "role", "manager", "is_staff", "is_active")
#     list_filter = ("role", "is_staff", "is_active", "manager")
#     search_fields = ("username", "email", "manager__username")  # REQUIRED for autocomplete
#     ordering = ("username",)

#     fieldsets = (
#         (None, {"fields": ("username", "email", "password")}),
#         ("Role & Manager", {"fields": ("role", "manager")}),
#         ("Permissions", {"fields": ("is_staff", "is_active", "groups", "user_permissions")}),
#         ("Important dates", {"fields": ("last_login", "date_joined")}),
#     )

#     add_fieldsets = (
#         (None, {"classes": ("wide",),
#                 "fields": ("username", "email", "password1", "password2",
#                            "role", "manager", "is_staff", "is_active")}),
#     )

#     # Hide from sidebar & index, but keep registered
#     def get_model_perms(self, request):
#         return {}


# ==========================================================
# VISIBLE PANELS
#   Officer (user_web) — managers; MUST NOT have manager set
#   Moderator (user_mobile) — mobile users; MUST HAVE manager set
# ==========================================================
@admin.register(StudentOrgModerator)
class StudentOrgOfficerAdmin(UserAdmin):
    # user_web (managers) — do NOT include 'manager' in forms
    list_display = ("username", "email", "role")
    fieldsets = ((None, {"fields": ("username", "email", "password", "role")}),)
    add_fieldsets = ((None, {"classes": ("wide",),
                             "fields": ("username", "email", "password1", "password2", "role")}),)
    search_fields = ("username", "email")
    ordering = ("username",)

    def get_queryset(self, request):
        return super().get_queryset(request).filter(role="user_web")

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        for f in ["is_staff", "is_active"]:
            form.base_fields.pop(f, None)
        return form


@admin.register(StudentOrgOfficer)
class StudentOrgModeratorAdmin(UserAdmin):
    # user_mobile — INCLUDE 'manager' in forms
    list_display = ("username", "email", "role", "manager")
    fieldsets = ((None, {"fields": ("username", "email", "password", "role", "manager")}),)
    add_fieldsets = ((None, {"classes": ("wide",),
                             "fields": ("username", "email", "password1", "password2", "role", "manager")}),)
    search_fields = ("username", "email")
    ordering = ("username",)

    def get_queryset(self, request):
        return super().get_queryset(request).filter(role="user_mobile")

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        for f in ["is_staff", "is_active"]:
            form.base_fields.pop(f, None)
        return form


# ==========================================================
# Borrower admin (required for Transaction.autocomplete_fields)
# ==========================================================
# @admin.register(Borrower)
# class BorrowerAdmin(admin.ModelAdmin):
#     list_display = ("name", "school_id", "status")
#     list_filter = ("status",)
#     search_fields = ("name", "school_id")  # REQUIRED for autocomplete
#     fields = ("name", "school_id", "status", "image")


# # ==========================================================
# # Transaction admin
# # ==========================================================
# # in admin.py
# from .models import Item, Transaction  # make sure Transaction is imported

# @admin.register(Transaction)
# class TransactionAdmin(admin.ModelAdmin):
#     ...
#     # OPTIONAL: nicer dual-list UI for M2M
#     filter_horizontal = ("items",)

#     def formfield_for_manytomany(self, db_field, request, **kwargs):
#         if db_field.name == "items":
#             obj_id = getattr(getattr(request, "resolver_match", None), "kwargs", {}).get("object_id")

#             if obj_id:
#                 # Edit view: limit items to the same manager as this transaction (if present)
#                 tx = Transaction.objects.filter(pk=obj_id).only("manager").first()
#                 if tx and tx.manager_id:
#                     kwargs["queryset"] = Item.objects.filter(manager=tx.manager)
#                 else:
#                     kwargs["queryset"] = Item.objects.all()
#             else:
#                 # Add view: show items (choose how strict you want this)
#                 if getattr(request.user, "is_superuser", False):
#                     kwargs["queryset"] = Item.objects.all()
#                 elif getattr(request.user, "role", None) == "user_web":
#                     kwargs["queryset"] = Item.objects.filter(manager=request.user)
#                 else:
#                     kwargs["queryset"] = Item.objects.all()  # fallback

#         return super().formfield_for_manytomany(db_field, request, **kwargs)
