# istak_backend/tasks.py
from celery import shared_task
from django.utils import timezone
from django.db.models import Q
from istak_backend.models import Transaction
from istak_backend.firebase import send_push_notification

@shared_task
def notify_due_items():
    """
    Check all transactions daily (or every few minutes for testing)
    and send FCM notifications for:
      - Due Today (status='borrowed' and return_date=today)
      - Overdue (status='borrowed' and return_date<today, or status='overdue')
    """
    today = timezone.now().date()

    # --- 1️⃣ DUE TODAY ---
    due_qs = (
        Transaction.objects
        .filter(
            status='borrowed',
            return_date=today,
            items__isnull=False
        )
        .select_related('mobile_user', 'borrower')
        .prefetch_related('items')
        .distinct()
    )

    # --- 2️⃣ OVERDUE ---
    overdue_qs = (
        Transaction.objects
        .filter(items__isnull=False)
        .filter(
            Q(status='overdue') |
            (Q(status='borrowed') & Q(return_date__lt=today))
        )
        .select_related('mobile_user', 'borrower')
        .prefetch_related('items')
        .distinct()
    )

    print(f"[notify_due_items] {timezone.now()} | due_today={due_qs.count()} | overdue={overdue_qs.count()}")

    sent_count = 0

    # --- 🔔 DUE TODAY NOTIFICATIONS ---
    for tx in due_qs:
        token = getattr(tx.mobile_user, 'fcm_token', None)
        if not token:
            continue

        item_names = ", ".join(i.item_name for i in tx.items.all())
        borrower_id = getattr(tx.borrower, 'school_id', 'Unknown')

        send_push_notification(
            token,
            "Item(s) Due Today",
            f"School ID: {borrower_id} must return '{item_names}' today."
        )
        sent_count += 1

    # --- 🔔 OVERDUE NOTIFICATIONS ---
    for tx in overdue_qs:
        token = getattr(tx.mobile_user, 'fcm_token', None)
        if not token:
            continue

        days_overdue = max((today - tx.return_date).days, 0) if tx.return_date else 0
        item_names = ", ".join(i.item_name for i in tx.items.all())
        borrower_id = getattr(tx.borrower, 'school_id', 'Unknown')

        send_push_notification(
            token,
            "Overdue Item(s)",
            f"School ID: {borrower_id} hasn’t returned '{item_names}' "
            f"for {days_overdue} day(s)."
        )
        sent_count += 1

    print(f"[notify_due_items] Finished | total_sent={sent_count}")
    return f"Sent {sent_count} notifications (due={due_qs.count()}, overdue={overdue_qs.count()})"
