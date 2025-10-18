from datetime import datetime, timezone as dt_timezone
from django.utils import timezone as dj_timezone
from io import BytesIO
from msilib.schema import File
import requests
from rest_framework import serializers
from istak_backend.models import Borrower, CustomUser, PredictiveItemCondition, RegistrationRequest, Transaction, Item
from django.contrib.auth import get_user_model

User = get_user_model()

class RegistrationRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = RegistrationRequest
        fields = ['id', 'username', 'email', 'status']

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
        fields = ['id', 'name', 'school_id', 'status', 'image', 'borrowed_items', 'transaction_count', 'total_borrowed_items', 'last_borrowed_date', 'current_borrow_date', 'return_image_url']

    def get_borrowed_items(self, obj):
        transactions = Transaction.objects.filter(
            borrower=obj,
            status='borrowed',
            mobile_user=self.context['request'].user
        ).prefetch_related('items')
        return [t.items.first().item_name for t in transactions if t.items.exists()]

    def get_transaction_count(self, obj):
        return Transaction.objects.filter(
            borrower=obj,
            mobile_user=self.context['request'].user
        ).count()

    def get_image(self, obj):
        request = self.context.get('request')
        if obj.image and hasattr(obj.image, 'url'):
            return request.build_absolute_uri(obj.image.url) if request else obj.image.url
        return None
    
    def get_return_image_url(self, obj):
        request = self.context.get('request')
        if obj.return_image and hasattr(obj.return_image, 'url'):
            return request.build_absolute_uri(obj.return_image.url) if request else obj.return_image.url
        return None

    def get_total_borrowed_items(self, obj):
        transactions = Transaction.objects.filter(
            borrower=obj,
            status='borrowed',
            mobile_user=self.context['request'].user
        ).prefetch_related('items')
        total = sum(len(t.items.all()) for t in transactions)
        return total

    def get_current_borrow_date(self, obj):
        transaction = Transaction.objects.filter(
            borrower=obj,
            status='borrowed'
        ).order_by('-borrow_date').first()
        return transaction.borrow_date if transaction else None

class TransactionSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ['id', 'borrow_date', 'return_date', 'status']

class TransactionSerializer(serializers.ModelSerializer):
    items = serializers.SerializerMethodField()
    borrower = BorrowerSerializer(read_only=True)
    school_id = serializers.CharField(source='borrower.school_id', read_only=True)
    borrower_name = serializers.CharField(source='borrower.name', read_only=True)

    class Meta:
        model = Transaction
        fields = ['id', 'borrow_date', 'return_date', 'status', 'items', 'borrower', 'school_id', 'borrower_name']

    def get_items(self, obj):
        items = obj.items.all()
        return [{
            'id': item.id,
            'item_name': item.item_name,
            'condition': item.condition,
            'image': self.context['request'].build_absolute_uri(item.image.url) if item.image and hasattr(item.image, 'url') and self.context.get('request') else None
        } for item in items]

class TopBorrowedItemsSerializer(serializers.ModelSerializer):
    borrow_count = serializers.IntegerField()
    image = serializers.SerializerMethodField()

    class Meta:
        model = Item
        fields = ['id', 'item_name', 'borrow_count', 'image']

    def get_image(self, obj):
        request = self.context.get('request')
        if obj.image and hasattr(obj.image, 'url'):
            return request.build_absolute_uri(obj.image.url) if request else obj.image.url
        return None

class CreateBorrowingSerializer(serializers.Serializer):
    school_id = serializers.CharField(max_length=10)
    name = serializers.CharField(max_length=255)
    status = serializers.ChoiceField(choices=['active', 'inactive'], default='active')
    image = serializers.ImageField(required=False, allow_null=True)
    return_date = serializers.DateField()
    item_ids = serializers.ListField(
        child=serializers.CharField(),
        allow_empty=False
    )

    def validate_item_ids(self, value):
        invalid_ids = []
        for item_id in value:
            if not item_id or not isinstance(item_id, str):
                invalid_ids.append(item_id)
            elif not Item.objects.filter(id=item_id).exists():
                invalid_ids.append(item_id)
        if invalid_ids:
            raise serializers.ValidationError(f"Invalid or non-existent item IDs: {invalid_ids}")
        return value

    def validate(self, data):
        if 'image' in self.context['request'].FILES:
            data['image'] = self.context['request'].FILES['image']
        return data

class DamagedOverdueReportSerializer(serializers.ModelSerializer):
    borrowerName = serializers.CharField(source='borrower.name')
    school_id = serializers.CharField(source='borrower.school_id')
    borrowerImage = serializers.ImageField(source='borrower.image', allow_null=True)
    itemName = serializers.SerializerMethodField()
    issue = serializers.SerializerMethodField()
    daysPastDue = serializers.SerializerMethodField()

    class Meta:
        model = Transaction
        fields = ['id', 'borrowerName', 'school_id', 'borrowerImage', 'itemName', 'issue', 'daysPastDue']

    def get_itemName(self, obj):
        return ", ".join(item.item_name for item in obj.items.all())

    def get_issue(self, obj):
        if obj.status == 'returned' and any(item.condition and item.condition.lower() in ['damaged', 'broken'] for item in obj.items.all()):
            return 'Damaged'
        elif obj.status == 'borrowed' and obj.return_date and obj.return_date < dj_timezone.now().date():
            return 'Overdue'
        return 'Unknown'

    def get_daysPastDue(self, obj):
        if obj.status == 'borrowed' and obj.return_date and obj.return_date < dj_timezone.now().date():
            return (dj_timezone.now().date() - obj.return_date).days
        return None

class ItemSerializer(serializers.ModelSerializer):
    image = serializers.SerializerMethodField()
    last_transaction_return_date = serializers.SerializerMethodField()
    transactions = TransactionSummarySerializer(many=True, read_only=True)
    current_transaction = serializers.SerializerMethodField()

    class Meta:
        model = Item
        fields = ['id', 'item_name', 'condition', 'image', 'last_transaction_return_date', 'transactions', 'current_transaction']
        extra_kwargs = {'manager': {'read_only': True}}

    def get_image(self, obj):
        request = self.context.get('request')
        if obj.image and hasattr(obj.image, 'url'):
            return request.build_absolute_uri(obj.image.url) if request else obj.image.url
        return None

    def get_last_transaction_return_date(self, obj):
        last_transaction = obj.transactions.filter(status='returned').order_by('-return_date').first()
        return last_transaction.return_date if last_transaction else None

    def get_current_transaction(self, obj):
        transaction = obj.transactions.filter(status='borrowed').first()
        return transaction.id if transaction else None

class CreateBorrowingSerializerWithURL(serializers.Serializer):
    school_id = serializers.CharField(max_length=10)
    name = serializers.CharField(max_length=255)
    status = serializers.ChoiceField(choices=['active', 'inactive'], default='active')
    image_url = serializers.URLField(required=False, allow_null=True)
    return_date = serializers.DateField()
    item_ids = serializers.ListField(child=serializers.CharField(), allow_empty=False)

    def validate_item_ids(self, value):
        invalid_ids = []
        for item_id in value:
            if not item_id or not isinstance(item_id, str):
                invalid_ids.append(item_id)
            elif not Item.objects.filter(id=item_id).exists():
                invalid_ids.append(item_id)
        if invalid_ids:
            raise serializers.ValidationError(f"Invalid or non-existent item IDs: {invalid_ids}")
        return value

    def validate(self, data):
        if 'image_url' in data and data['image_url']:
            try:
                response = requests.get(data['image_url'])
                if response.status_code == 200:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"borrower_image_{timestamp}.png"
                    data['image'] = File(BytesIO(response.content), name=filename)
                else:
                    raise serializers.ValidationError("Failed to download image from URL")
            except Exception as e:
                raise serializers.ValidationError(f"Invalid image URL: {str(e)}")
        return data

    def create(self, validated_data):
        image = validated_data.pop('image', None)
        borrower_data = {
            'name': validated_data['name'],
            'school_id': validated_data['school_id'],
            'status': validated_data['status'],
        }
        if image:
            borrower_data['image'] = image
        borrower, _ = Borrower.objects.get_or_create(
            school_id=validated_data['school_id'], defaults=borrower_data
        )
        transaction = Transaction.objects.create(
            borrower=borrower,
            mobile_user=self.context['request'].user,
            status='borrowed',
            borrow_date=dj_timezone.now().date(),
            return_date=validated_data['return_date'],
        )
        transaction.items.set(validated_data['item_ids'])
        return transaction

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'date_joined']

class PredictiveItemSerializer(serializers.ModelSerializer):
    item_name = serializers.CharField(source='item.item_name', read_only=True)
    condition = serializers.CharField(source='item.condition', read_only=True)

    class Meta:
        model = PredictiveItemCondition
        fields = ['item_name', 'condition', 'predicted_risk', 'reason', 'last_checked']

class TransactionReportSerializer(serializers.ModelSerializer):
    borrowerName = serializers.CharField(source='borrower.name')
    schoolId = serializers.CharField(source='borrower.school_id')
    borrowerImage = serializers.SerializerMethodField()
    borrowDate = serializers.DateField(source='borrow_date')
    returnDate = serializers.DateField(source='return_date', allow_null=True)
    items = serializers.SerializerMethodField()
    daysPastDue = serializers.SerializerMethodField()

    class Meta:
        model = Transaction
        fields = ['id', 'borrowerName', 'schoolId', 'borrowerImage', 'borrowDate', 'returnDate', 'status', 'items', 'daysPastDue']

    def get_borrowerImage(self, obj):
        request = self.context.get('request')
        if obj.borrower and obj.borrower.image:
            if request:
                return request.build_absolute_uri(obj.borrower.image.url)
            return obj.borrower.image.url
        return None

    def get_items(self, obj):
        return [{'itemName': item.item_name, 'condition': item.condition or 'Good'} for item in obj.items.all()]

    def get_daysPastDue(self, obj):
        if obj.status == 'borrowed' and obj.return_date:
            today = dj_timezone.now().date()
            if obj.return_date < today:
                return (today - obj.return_date).days
        return None