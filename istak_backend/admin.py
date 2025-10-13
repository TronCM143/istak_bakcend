from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group
from .models import CustomUser, StudentOrgOfficer, StudentOrgModerator

# --- SITE TITLES ---
admin.site.site_header = "ISTAK Administration Panel"
admin.site.site_title = "ISTAK Admin Portal"
admin.site.index_title = "Welcome to ISTAK Management System"

# --- REMOVE GROUPS TAB ---
#admin.site.unregister(Group)


# 🔹 Admin for Student Org Officers
@admin.register(StudentOrgOfficer)
class StudentOrgOfficerAdmin(UserAdmin):
    list_display = ('username', 'email', 'role', 'manager')
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password', 'role', 'manager')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'role', 'manager')}
        ),
    )
    search_fields = ('username', 'email')
    ordering = ('username',)

    def get_queryset(self, request):
        """Show only Student Org Officers."""
        qs = super().get_queryset(request)
        return qs.filter(role='user_mobile')

    def get_form(self, request, obj=None, **kwargs):
        """Remove is_staff and is_active fields."""
        form = super().get_form(request, obj, **kwargs)
        for field in ['is_staff', 'is_active']:
            form.base_fields.pop(field, None)
        return form


# 🔹 Admin for Student Org Moderators
@admin.register(StudentOrgModerator)
class StudentOrgModeratorAdmin(UserAdmin):
    list_display = ('username', 'email', 'role')
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password', 'role')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'role')}
        ),
    )
    search_fields = ('username', 'email')
    ordering = ('username',)

    def get_queryset(self, request):
        """Show only Student Org Moderators."""
        qs = super().get_queryset(request)
        return qs.filter(role='user_web')

    def get_form(self, request, obj=None, **kwargs):
        """Remove is_staff and is_active fields."""
        form = super().get_form(request, obj, **kwargs)
        for field in ['is_staff', 'is_active']:
            form.base_fields.pop(field, None)
        return form



# Custom filter for Borrower.status
# class BorrowerStatusFilter(SimpleListFilter):
#     title = 'borrower status'
#     parameter_name = 'status'

#     def lookups(self, request, model_admin):
#         return (
#             ('active', 'Active'),
#             ('inactive', 'Inactive'),
#         )

#     def queryset(self, request, queryset):
#         value = self.value()
#         if value in ['active', 'inactive']:
#             return queryset.filter(status=value)
#         return queryset



# @admin.register(Item)
# class ItemAdmin(admin.ModelAdmin):
#     list_display = ('item_name', 'get_status_display', 'condition', 'manager_username')
#     list_filter = ('condition', 'manager')
#     search_fields = ('item_name',)
#     fields = ('item_name', 'condition', 'user', 'manager', 'image')
#     raw_id_fields = ('user', 'manager')
#     autocomplete_fields = ['user', 'manager']

#     def get_status_display(self, obj):
#         """Display computed status based on transactions."""
#         if obj.transactions.filter(status='borrowed').exists():
#             return 'Borrowed'
#         return 'Available'
#     get_status_display.short_description = 'Status'

#     def manager_username(self, obj):
#         """Safely display manager username."""
#         if obj.manager:
#             return obj.manager.username or "No Username"
#         return "No Manager"
#     manager_username.short_description = "Manager"
#     manager_username.admin_order_field = 'manager__username'

# @admin.register(Borrower)
# class BorrowerAdmin(admin.ModelAdmin):
#     list_display = ('name', 'school_id', 'get_status_display')
#     list_filter = ('status', BorrowerStatusFilter)
#     search_fields = ('name', 'school_id')
#     fields = ('name', 'school_id', 'status', 'image')

#     def get_status_display(self, obj):
#         """Display Borrower.status."""
#         return obj.status.capitalize()
#     get_status_display.short_description = "Status"
# @admin.register(Transaction)
# class TransactionAdmin(admin.ModelAdmin):
#     list_display = (
#         'borrow_date',
#         'return_date',
#         'status',
#         'manager',
#         'mobile_user',
#         'get_borrowed_items',
#         'borrower',
#     )
#     list_filter = ('status', 'borrow_date', 'return_date', 'manager', 'mobile_user')
#     search_fields = ('borrower__name', 'items__item_name')
#     raw_id_fields = ('manager', 'mobile_user', 'borrower')
#     autocomplete_fields = ['manager', 'mobile_user', 'borrower']

#     def formfield_for_manytomany(self, db_field, request, **kwargs):
#         """
#         Restrict items to only those already linked to the transaction being edited.
#         """
#         if db_field.name == "items":
#             obj_id = request.resolver_match.kwargs.get("object_id")
#             if obj_id:  # editing existing transaction
#                 kwargs["queryset"] = Item.objects.filter(transactions__id=obj_id)
#             else:  # creating new transaction, show nothing
#                 kwargs["queryset"] = Item.objects.none()
#         return super().formfield_for_manytomany(db_field, request, **kwargs)

#     def get_borrowed_items(self, obj):
#         borrowed_items = obj.items.filter(transactions__status='borrowed').distinct()
#         return ', '.join(item.item_name for item in borrowed_items) or "None"
#     get_borrowed_items.short_description = 'Borrowed Items'



# @admin.register(RegistrationRequest)
# class RegistrationRequestAdmin(admin.ModelAdmin):
#     list_display = ['username', 'email', 'status', 'requested_manager']
#     list_filter = ['status']
#     search_fields = ['username', 'email']
#     raw_id_fields = ['requested_manager']
#     autocomplete_fields = ['requested_manager']

from django.contrib.auth.models import Group
admin.site.unregister(Group)