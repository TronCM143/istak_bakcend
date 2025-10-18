import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password
import random

class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('user_mobile', 'Mobile App User'),
        ('user_web', 'Manager User'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user_mobile')
    manager = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='mobile_users',
        limit_choices_to={'role': 'user_web'},
        db_index=True
    )
    fcm_token = models.CharField(max_length=255, null=True, blank=True, db_index=True)

    def clean(self):
        if self.role == 'user_mobile' and not self.manager:
            raise ValidationError("Mobile users must have a manager assigned.")
        if self.role == 'user_web' and self.manager is not None:
            raise ValidationError("Managers cannot have a manager assigned.")

    def __str__(self):
        username = self.username if self.username else "Unknown User"
        role = self.role if self.role else "Unknown Role"
        return f"{username} ({role})"

def generate_12_digit_id():
    return str(random.randint(10**11, (10**12)-1))  # ensures 12 digits

class Item(models.Model):
    id = models.CharField(
        primary_key=True,
        max_length=12,
        default=generate_12_digit_id,
        editable=False,
        unique=True
    )
    item_name = models.CharField(max_length=50)
    condition = models.CharField(max_length=20, null=True, blank=True)
    user = models.ForeignKey(
        CustomUser,
        limit_choices_to={'role': 'user_mobile'},
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='items',
        db_index=True
    )
    manager = models.ForeignKey(
        CustomUser,
        limit_choices_to={'role': 'user_web'},
        null=False,
        blank=False,
        on_delete=models.PROTECT,
        related_name='managed_items',
        db_index=True
    )
    image = models.ImageField(upload_to='item_images/', null=True, blank=True)

    class Meta:
        unique_together = ('item_name', 'manager')

    def __str__(self):
        return f"{self.item_name} (ID: {self.id})"

class Borrower(models.Model):
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    ]
    name = models.CharField(max_length=255)
    school_id = models.CharField(max_length=10, unique=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    image = models.ImageField(upload_to='borrower_images/', null=True, blank=True)
    return_image = models.ImageField(upload_to='borrower_return_images/', null=True, blank=True)

    def __str__(self):
        return f"{self.name} (School ID: {self.school_id})"


from django.utils.timezone import localdate
class Transaction(models.Model):
    STATUS_CHOICES = [
        ('borrowed', 'Borrowed'),
        ('returned', 'Returned'),
        ('overdue', 'Overdue'),
    ]
    borrow_date = models.DateField(default=localdate)
    return_date = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='borrowed', db_index=True)
    manager = models.ForeignKey(
        CustomUser,
        limit_choices_to={'role': 'user_web'},
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name='transactions_managed'
    )
    mobile_user = models.ForeignKey(
        CustomUser,
        limit_choices_to={'role': 'user_mobile'},
        null=True,          # ← ADDED: Allows NULL in DB for user_web cases
        blank=True,         # ← ADDED: Allows empty in forms/serializers
        on_delete=models.PROTECT,
        related_name='transactions_made'
    )
    items = models.ManyToManyField(Item, related_name='transactions')
    borrower = models.ForeignKey(Borrower, on_delete=models.CASCADE, related_name='transactions')

    class Meta:
        indexes = [
            models.Index(fields=['status', 'manager']),
            models.Index(fields=['return_date'])
        ]

    def clean(self):
        if self.return_date and self.return_date < self.borrow_date:
            raise ValidationError("Return date cannot be before borrow date.")

    def __str__(self):
        borrower_name = self.borrower.name if self.borrower else "Unknown Borrower"
        return f"Transaction for {borrower_name} on {self.borrow_date}"

class RegistrationRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField()
    password = models.CharField(max_length=128)
    requested_manager = models.ForeignKey(
        CustomUser,
        limit_choices_to={'role': 'user_web'},
        on_delete=models.CASCADE,
        related_name='registration_requests',
        db_index=True
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if self.password and not self.password.startswith('pbkdf2_'):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Request for {self.username} to {self.requested_manager}"
    


class StudentOrgOfficer(CustomUser):
    class Meta:
        proxy = True
        verbose_name = "Student Org Officer"
        verbose_name_plural = "Student Org Officers"


class StudentOrgModerator(CustomUser):
    class Meta:
        proxy = True
        verbose_name = "Student Org Moderator"
        verbose_name_plural = "Student Org Moderators"
        
        
from django.utils import timezone
from datetime import timedelta

class PredictiveItemCondition(models.Model):
    item = models.OneToOneField(Item, on_delete=models.CASCADE, related_name='prediction')
    predicted_risk = models.FloatField(default=0.0)
    reason = models.TextField(blank=True, null=True)
    last_checked = models.DateTimeField(auto_now=True)

    def update_prediction(self):
        """
        Rule-based predictive model for future damage risk.
        """
        from .models import Transaction  # avoid circular import
        now = timezone.now().date()
        transactions = Transaction.objects.filter(items=self.item)

        total_borrows = transactions.count()
        recent_borrows = transactions.filter(borrow_date__gte=now - timedelta(days=90)).count()
        overdue_count = transactions.filter(status='overdue').count()
        damaged_returns = transactions.filter(items__condition__icontains='damaged').count()

        # Weighted risk computation (simple heuristic)
        risk = 0.0
        if recent_borrows > 3:
            risk += 0.3
        if overdue_count > 1:
            risk += 0.2
        if damaged_returns > 0:
            risk += 0.4
        if total_borrows > 10:
            risk += 0.1

        self.predicted_risk = min(risk, 1.0)
        self.reason = (
            f"Total borrows: {total_borrows}, Recent borrows: {recent_borrows}, "
            f"Overdue: {overdue_count}, Damaged returns: {damaged_returns}"
        )
        self.save()

    def __str__(self):
        return f"{self.item.item_name} - Risk: {self.predicted_risk:.2f}"
