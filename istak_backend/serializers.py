from datetime import datetime
from io import BytesIO

import requests
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.utils import timezone as dj_timezone
from rest_framework import serializers

from istak_backend.models import (
    Borrower,
    CustomUser,
    PredictiveItemCondition,
    RegistrationRequest,
    Transaction,
    Item,
)

User = get_user_model()


# ---------- Helpers ----------

def _abs_url(request, f):
    """Build an absolute URL for a FileField/ImageField if possible."""
    if not f or not hasattr(f, "url"):
        return None
    if request:
        try:
            return request.build_absolute_uri(f.url)
        except Exception:
            return f.url  # fallback
    return f.url


# ---------- Serializers ----------

class RegistrationRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = RegistrationRequest
        fields = ["id", "username", "email", "status"]


class BorrowerSerializer(serializers.ModelSerializer):
    borrowed_items = serializers.SerializerMethodField()
    transaction_count = serializers.SerializerMethodField()
    image = serializers.SerializerMethodField()
    total_borrowed_items = serializers.SerializerMethodField()
    last_borrowed_date = serializers.DateField(read_only=True, allow_null=True)
    current_borrow_date = serializers.SerializerMethodField()
    return_image_url = serializers.SerializerMethodField()

    class Meta:
        model = Borrower
        fields = [
            "id",
            "name",
            "school_id",
            "status",
            "image",
            "borrowed_items",
            "transaction_count",
            "total_borrowed_items",
            "last_borrowed_date",
            "current_borrow_date",
            "return_image_url",
        ]

    def get_borrowed_items(self, obj):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        qs = (
            Transaction.objects.filter(borrower=obj, status="borrowed", mobile_user=user)
            .prefetch_related("items")
        )
        # avoid extra exists() per transaction
        names = []
        for t in qs:
            first = next(iter(t.items.all()), None)
            if first:
                names.append(first.item_name)
        return names

    def get_transaction_count(self, obj):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        return Transaction.objects.filter(borrower=obj, mobile_user=user).count()

    def get_image(self, obj):
        return _abs_url(self.context.get("request"), obj.image)

    def get_return_image_url(self, obj):
        return _abs_url(self.context.get("request"), obj.return_image)

    def get_total_borrowed_items(self, obj):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        qs = (
            Transaction.objects.filter(borrower=obj, status="borrowed", mobile_user=user)
            .prefetch_related("items")
        )
        return sum(t.items.count() for t in qs)

    def get_current_borrow_date(self, obj):
        transaction = (
            Transaction.objects.filter(borrower=obj, status="borrowed")
            .order_by("-borrow_date")
            .first()
        )
        return transaction.borrow_date if transaction else None


class TransactionSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ["id", "borrow_date", "return_date", "status"]


class TransactionSerializer(serializers.ModelSerializer):
    items = serializers.SerializerMethodField()
    borrower = BorrowerSerializer(read_only=True)
    school_id = serializers.CharField(source="borrower.school_id", read_only=True)
    borrower_name = serializers.CharField(source="borrower.name", read_only=True)

    class Meta:
        model = Transaction
        fields = [
            "id",
            "borrow_date",
            "return_date",
            "status",
            "items",
            "borrower",
            "school_id",
            "borrower_name",
        ]

    def get_items(self, obj):
        request = self.context.get("request")
        out = []
        for item in obj.items.all():
            out.append(
                {
                    "id": item.id,
                    "item_name": item.item_name,
                    "condition": item.condition,
                    "image": _abs_url(request, item.image),
                }
            )
        return out


class TopBorrowedItemsSerializer(serializers.ModelSerializer):
    borrow_count = serializers.IntegerField()
    image = serializers.SerializerMethodField()

    class Meta:
        model = Item
        fields = ["id", "item_name", "borrow_count", "image"]

    def get_image(self, obj):
        return _abs_url(self.context.get("request"), obj.image)


class CreateBorrowingSerializer(serializers.Serializer):
    school_id = serializers.CharField(max_length=10)
    name = serializers.CharField(max_length=255)
    status = serializers.ChoiceField(choices=["active", "inactive"], default="active")
    image = serializers.ImageField(required=False, allow_null=True)
    return_date = serializers.DateField()
    item_ids = serializers.ListField(child=serializers.CharField(), allow_empty=False)

    def validate_item_ids(self, value):
        invalid = [iid for iid in value if not Item.objects.filter(id=iid).exists()]
        if invalid:
            raise serializers.ValidationError(
                f"Invalid or non-existent item IDs: {invalid}"
            )
        return value

    def validate(self, data):
        # allow multipart image upload from request.FILES
        req = self.context.get("request")
        if req and "image" in req.FILES:
            data["image"] = req.FILES["image"]
        return data


class DamagedOverdueReportSerializer(serializers.ModelSerializer):
    borrowerName = serializers.CharField(source="borrower.name")
    school_id = serializers.CharField(source="borrower.school_id")
    borrowerImage = serializers.ImageField(source="borrower.image", allow_null=True)
    itemName = serializers.SerializerMethodField()
    issue = serializers.SerializerMethodField()
    daysPastDue = serializers.SerializerMethodField()

    class Meta:
        model = Transaction
        fields = [
            "id",
            "borrowerName",
            "school_id",
            "borrowerImage",
            "itemName",
            "issue",
            "daysPastDue",
        ]

    def get_itemName(self, obj):
        return ", ".join(i.item_name for i in obj.items.all())

    def get_issue(self, obj):
        if obj.status == "returned" and any(
            (i.condition or "").lower() in {"damaged", "broken"} for i in obj.items.all()
        ):
            return "Damaged"
        if (
            obj.status == "borrowed"
            and obj.return_date
            and obj.return_date < dj_timezone.now().date()
        ):
            return "Overdue"
        return "Unknown"

    def get_daysPastDue(self, obj):
        if (
            obj.status == "borrowed"
            and obj.return_date
            and obj.return_date < dj_timezone.now().date()
        ):
            return (dj_timezone.now().date() - obj.return_date).days
        return None


class ItemSerializer(serializers.ModelSerializer):
    image = serializers.SerializerMethodField()
    last_transaction_return_date = serializers.SerializerMethodField()
    transactions = TransactionSummarySerializer(many=True, read_only=True)
    current_transaction = serializers.SerializerMethodField()

    class Meta:
        model = Item
        fields = [
            "id",
            "item_name",
            "condition",
            "image",
            "last_transaction_return_date",
            "transactions",
            "current_transaction",
        ]
        extra_kwargs = {"manager": {"read_only": True}}

    def get_image(self, obj):
        return _abs_url(self.context.get("request"), obj.image)

    def get_last_transaction_return_date(self, obj):
        last_transaction = (
            obj.transactions.filter(status="returned").order_by("-return_date").first()
        )
        return last_transaction.return_date if last_transaction else None

    def get_current_transaction(self, obj):
        t = obj.transactions.filter(status="borrowed").first()
        return t.id if t else None


class CreateBorrowingSerializerWithURL(serializers.Serializer):
    school_id = serializers.CharField(max_length=10)
    name = serializers.CharField(max_length=255)
    status = serializers.ChoiceField(choices=["active", "inactive"], default="active")
    image_url = serializers.URLField(required=False, allow_null=True)
    return_date = serializers.DateField()
    item_ids = serializers.ListField(child=serializers.CharField(), allow_empty=False)

    def validate_item_ids(self, value):
        invalid = [iid for iid in value if not Item.objects.filter(id=iid).exists()]
        if invalid:
            raise serializers.ValidationError(
                f"Invalid or non-existent item IDs: {invalid}"
            )
        return value

    def validate(self, data):
        url = data.get("image_url")
        if url:
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200 and resp.content:
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    name = f"borrower_image_{ts}.png"
                    data["image"] = ContentFile(resp.content, name=name)
                else:
                    raise serializers.ValidationError("Failed to download image from URL")
            except Exception as e:
                raise serializers.ValidationError(f"Invalid image URL: {e}")
        return data

    def create(self, validated_data):
        image = validated_data.pop("image", None)
        borrower_defaults = {
            "name": validated_data["name"],
            "status": validated_data["status"],
        }
        if image:
            borrower_defaults["image"] = image

        borrower, _ = Borrower.objects.get_or_create(
            school_id=validated_data["school_id"], defaults=borrower_defaults
        )

        tx = Transaction.objects.create(
            borrower=borrower,
            mobile_user=getattr(self.context.get("request"), "user", None),
            status="borrowed",
            borrow_date=dj_timezone.now().date(),
            return_date=validated_data["return_date"],
        )
        tx.items.set(validated_data["item_ids"])
        return tx


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["id", "username", "email", "date_joined"]


class PredictiveItemSerializer(serializers.ModelSerializer):
    item_name = serializers.CharField(source="item.item_name", read_only=True)
    condition = serializers.CharField(source="item.condition", read_only=True)

    class Meta:
        model = PredictiveItemCondition
        fields = ["item_name", "condition", "predicted_risk", "reason", "last_checked"]


class TransactionReportSerializer(serializers.ModelSerializer):
    borrowerName = serializers.CharField(source="borrower.name")
    schoolId = serializers.CharField(source="borrower.school_id")
    borrowerImage = serializers.SerializerMethodField()
    borrowDate = serializers.DateField(source="borrow_date")
    returnDate = serializers.DateField(source="return_date", allow_null=True)
    items = serializers.SerializerMethodField()
    daysPastDue = serializers.SerializerMethodField()

    class Meta:
        model = Transaction
        fields = [
            "id",
            "borrowerName",
            "schoolId",
            "borrowerImage",
            "borrowDate",
            "returnDate",
            "status",
            "items",
            "daysPastDue",
        ]

    def get_borrowerImage(self, obj):
        return _abs_url(self.context.get("request"), getattr(obj.borrower, "image", None))

    def get_items(self, obj):
        return [{"itemName": i.item_name, "condition": i.condition or "Good"} for i in obj.items.all()]

    def get_daysPastDue(self, obj):
        if obj.status == "borrowed" and obj.return_date:
            today = dj_timezone.now().date()
            if obj.return_date < today:
                return (today - obj.return_date).days
        return None


from .models import Item

class SimpleItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = Item
        fields = ['id', 'item_name', 'image']