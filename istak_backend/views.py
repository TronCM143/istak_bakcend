import logging
import json
from django.utils import timezone as dj_timezone
from django.contrib.auth import get_user_model, authenticate, login
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

from rest_framework import generics, permissions, status, viewsets
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from django.contrib import messages
from io import BytesIO
from PIL import Image
from rembg import remove
from django.core.files.base import ContentFile
from datetime import date
from django.db.models import Count
from sympy import Q

from .models import Transaction, Item, CustomUser, RegistrationRequest, Borrower
from .serializers import CreateBorrowingSerializer, TransactionSerializer, ItemSerializer, RegistrationRequestSerializer, TopBorrowedItemsSerializer
from istak_backend import models

logger = logging.getLogger(__name__)

@csrf_exempt
def register_manager(request):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid method"}, status=405)
    try:
        data = json.loads(request.body)
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        if not username or not email or not password:
            return JsonResponse({"error": "Missing fields"}, status=400)
        user = CustomUser.objects.create_user(
            username=username,
            email=email,
            password=password,
            role="user_web"
        )
        return JsonResponse({"status": "success"}, status=201)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def login_mobile(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body.decode("utf-8"))
            username = data.get("username")
            password = data.get("password")
            user = authenticate(username=username, password=password)
            if user is not None:
                refresh = RefreshToken.for_user(user)
                return JsonResponse({
                    "success": True,
                    "message": "Login successful",
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                    }
                }, status=200)
            else:
                return JsonResponse({
                    "success": False,
                    "error": "Invalid username or password"
                }, status=401)
        except Exception as e:
            return JsonResponse({
                "success": False,
                "error": f"Invalid request: {str(e)}"
            }, status=400)
    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def login_manager(request):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid method"}, status=405)
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return JsonResponse({"error": "Missing credentials"}, status=400)
    user = authenticate(username=username, password=password)
    if user and user.role == "user_web":
        refresh = RefreshToken.for_user(user)
        return JsonResponse({
            "status": "success",
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role
            }
        })
    return JsonResponse({"error": "Invalid credentials"}, status=400)

User = get_user_model()

@csrf_exempt
def register_mobile(request):
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)
    try:
        data = json.loads(request.body)
        username = data.get("username")
        password = data.get("password")
        email = data.get("email")
        manager_id = data.get("manager_id")
        if not username or not password or not email or not manager_id:
            return JsonResponse({"error": "All fields are required, including manager_id"}, status=400)
        if User.objects.filter(username=username).exists():
            return JsonResponse({"error": "Username already exists"}, status=400)
        manager = User.objects.filter(id=manager_id, role='user_web').first()
        if not manager:
            return JsonResponse({"error": "Invalid manager ID"}, status=400)
        RegistrationRequest.objects.create(
            username=username,
            email=email,
            password=make_password(password),
            requested_manager=manager
        )
        return JsonResponse({"status": "success", "message": "Registration pending approval"}, status=201)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

def manager_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user and user.role == "user_web":
            login(request, user)
            return redirect("home")
        else:
            messages.error(request, "Invalid credentials or not a manager.")
    return render(request, "login.html")

def home(request):
    if request.user.is_authenticated:
        return render(request, "home.html", {"username": request.user.username})
    else:
        return redirect("manager_login")

@api_view(['GET'])
@permission_classes([AllowAny])
def manager_list(request):
    managers = CustomUser.objects.filter(role='user_web')
    return Response([{"id": m.id, "username": m.username} for m in managers])

@api_view(['GET', 'POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def item_list(request):
    if request.method == 'GET':
        item_id = request.query_params.get('id')
        if item_id:
            try:
                item_id = str(item_id).strip()
                item_id_int = int(item_id)
                if request.user.role == 'user_web':
                    items = Item.objects.filter(id=item_id_int, manager=request.user)
                else:
                    if request.user.manager:
                        items = Item.objects.filter(id=item_id_int, manager=request.user.manager)
                    else:
                        items = Item.objects.none()
                if not items.exists():
                    return Response({"error": "Item not found"}, status=status.HTTP_404_NOT_FOUND)
                serializer = ItemSerializer(items.first())
                return Response(serializer.data)
            except (ValueError, TypeError):
                return Response({"error": "Invalid item ID"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            if request.user.role == 'user_web':
                items = Item.objects.filter(manager=request.user)
            else:
                if request.user.manager:
                    items = Item.objects.filter(manager=request.user.manager)
                else:
                    items = Item.objects.none()
            serializer = ItemSerializer(items, many=True)
            return Response(serializer.data)
    elif request.method == 'POST':
        serializer = ItemSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(manager=request.user if request.user.role == 'user_web' else request.user.manager)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

from django.db.models import Prefetch

class ItemListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = ItemSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = Item.objects.filter(manager=self.request.user) if self.request.user.role == 'user_web' else \
                   Item.objects.filter(manager=self.request.user.manager) if self.request.user.manager else \
                   Item.objects.none()
        return queryset.prefetch_related(
            Prefetch('transactions', queryset=Transaction.objects.filter(status='borrowed'), to_attr='borrowed_transactions')
        )

    def perform_create(self, serializer):
        image_file = self.request.FILES.get('image')
        new_image = None
        if image_file:
            try:
                input_img = Image.open(image_file).convert("RGBA")
                output_img = remove(input_img)
                temp_buffer = BytesIO()
                output_img.save(temp_buffer, format="PNG")
                temp_buffer.seek(0)
                new_image = ContentFile(
                    temp_buffer.read(),
                    name=f"{image_file.name.rsplit('.', 1)[0]}.png"
                )
            except Exception as e:
                logger.error(f"Error removing background for new item: {str(e)}")
                print(f"❌ Error removing background for new item: {str(e)}")
                raise

        if self.request.user.role == 'user_web':
            manager = self.request.user
        else:
            manager = self.request.user.manager

        kwargs = {'manager': manager}
        if new_image:
            kwargs['image'] = new_image

        instance = serializer.save(**kwargs)

        if new_image:
            logger.info(f"Background removed for item {instance.id}")
            print(f"✅ Background removed successfully for item {instance.id}")



from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import ValidationError
class ItemRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ItemSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        if self.request.user.role == 'user_web':
            return Item.objects.filter(manager=self.request.user)
        elif self.request.user.manager:
            return Item.objects.filter(manager=self.request.user.manager)
        return Item.objects.none()

    def perform_update(self, serializer):
        instance = serializer.instance
        image_file = self.request.FILES.get('image')

        if image_file:
            try:
                input_img = Image.open(image_file).convert("RGBA")
                output_img = remove(input_img)
                temp_buffer = BytesIO()
                output_img.save(temp_buffer, format="PNG")
                temp_buffer.seek(0)
                new_image = ContentFile(
                    temp_buffer.read(),
                    name=f"{image_file.name.rsplit('.', 1)[0]}.png"
                )
                serializer.save(image=new_image)
                logger.info(f"Background removed for item {instance.id}")
                print(f"✅ Background removed successfully for item {instance.id}")
            except Exception as e:
                logger.error(f"Error removing background for item {instance.id}: {str(e)}")
                print(f"❌ Error removing background for item {instance.id}: {str(e)}")
                raise
        else:
            serializer.save()

    def perform_destroy(self, instance):
        if instance.transactions.exists():
            # Better: Return Response directly (avoids exception handling altogether)
            return Response(
                {"detail": "Cannot delete an item that has associated transactions."},
                status=status.HTTP_400_BAD_REQUEST
            )
        # Or, if raising: raise ValidationError(...)  # Now with correct import
        instance.delete()

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def approve_registration(request):
    if request.user.role != 'user_web':
        return Response({"error": "Only managers can approve registrations"}, status=status.HTTP_403_FORBIDDEN)
    try:
        data = json.loads(request.body)
        request_id = data.get("request_id")
        is_approved = data.get("is_approved")
        if not request_id or is_approved is None:
            return Response({"error": "request_id and is_approved are required"}, status=400)
        reg_request = RegistrationRequest.objects.filter(
            id=request_id,
            requested_manager=request.user
        ).first()
        if not reg_request:
            return Response({"error": "Invalid or unauthorized request ID"}, status=400)
        if is_approved:
            user = CustomUser.objects.create_user(
                username=reg_request.username,
                email=reg_request.email,
                password=None,
                role='user_mobile',
                manager=request.user
            )
            user.password = reg_request.password
            user.save()
            reg_request.delete()
            return Response({"status": "success", "user_id": user.id}, status=200)
        else:
            reg_request.delete()
            return Response({"status": "success", "message": "Request denied"}, status=200)
    except json.JSONDecodeError:
        return Response({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

class RegistrationRequestViewSet(viewsets.ModelViewSet):
    serializer_class = RegistrationRequestSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_queryset(self):
        if self.request.user.role == 'user_web':
            return RegistrationRequest.objects.filter(requested_manager=self.request.user)
        return RegistrationRequest.objects.none()

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        status_value = request.data.get('status')
        if status_value not in ['approved', 'rejected']:
            return Response(
                {"error": "Invalid status. Use 'approved' or 'rejected'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if status_value == 'approved':
            if instance.status == 'approved':
                return Response(
                    {"error": "Request is already approved."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            user = CustomUser.objects.create_user(
                username=instance.username,
                email=instance.email,
                password=None,
                role='user_mobile',
                manager=instance.requested_manager
            )
            user.password = instance.password
            user.save()
            instance.status = 'approved'
            instance.save()
        elif status_value == 'rejected':
            if instance.status == 'approved':
                return Response(
                    {"error": "Cannot reject an already approved request."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            instance.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)

        serializer = self.get_serializer(instance)
        return Response(serializer.data)
    
import logging
import json

from django.core.files.base import ContentFile
from datetime import date
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django.db import transaction as db_transaction
from django.db.models import Count
from uuid import UUID
from istak_backend.models import Item, Borrower, Transaction
from .serializers import CreateBorrowingSerializer, TransactionSerializer

logger = logging.getLogger(__name__)
# views.py
@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def borrowing_create(request):
    try:
        if not request.user.is_authenticated:
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)

        # Construct data dictionary
        data = {
            'school_id': request.POST.get('school_id'),
            'name': request.POST.get('name'),
            'status': request.POST.get('status'),
            'return_date': request.POST.get('return_date'),
            'item_ids': request.POST.getlist('item_ids[]')
        }

        # Fallback to item_ids as JSON string
        if not data['item_ids'] and request.POST.get('item_ids'):
            try:
                data['item_ids'] = json.loads(request.POST.get('item_ids'))
            except json.JSONDecodeError:
                logger.error(f"Invalid item_ids format: {request.POST.get('item_ids')}")
                return Response({"error": "Invalid item_ids format"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate required fields
        if not all([data['school_id'], data['name'], data['status'], data['return_date']]):
            logger.error(f"Missing required fields: {data}")
            return Response({"error": "All fields (school_id, name, status, return_date) are required"}, 
                           status=status.HTTP_400_BAD_REQUEST)

        # Pass data and files to serializer
        serializer = CreateBorrowingSerializer(data=data, context={'request': request})
        if not serializer.is_valid():
            logger.error(f"Validation errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        validated = serializer.validated_data
        school_id = validated['school_id']
        name = validated['name']
        status_choice = validated['status']
        image_file = request.FILES.get('image')
        return_date = validated['return_date']
        item_ids = validated['item_ids']

        # Role check - already allows both user_mobile and user_web
        if request.user.role not in ['user_mobile', 'user_web']:
            return Response({"error": "Invalid user role"}, status=status.HTTP_403_FORBIDDEN)

        # Resolve manager context
        manager = request.user if request.user.role == 'user_web' else request.user.manager

        # Fetch items
        items = Item.objects.filter(id__in=item_ids, manager=manager)
        found_ids = list(items.values_list('id', flat=True))

        if len(found_ids) != len(item_ids):
            missing = set(item_ids) - set(found_ids)
            logger.error(f"Items not found: {missing}")
            return Response({"error": f"Items not found: {missing}"}, status=status.HTTP_400_BAD_REQUEST)

        unavailable = [item.id for item in items if item.transactions.filter(status='borrowed').exists()]
        if unavailable:
            return Response({"error": f"Items already borrowed: {unavailable}"}, status=status.HTTP_400_BAD_REQUEST)

        # Create borrower + transaction
        with db_transaction.atomic():
            borrower, created = Borrower.objects.get_or_create(
                school_id=school_id,
                defaults={'name': name, 'status': status_choice}
            )
            borrower.name = name
            borrower.status = status_choice
            if image_file:
                timestamp = dj_timezone.now().strftime("%Y%m%d%H%M%S")
                orig_name = getattr(image_file, 'name', 'upload')
                filename = f"{school_id}_{timestamp}_{orig_name}"
                borrower.image.save(filename, ContentFile(image_file.read()), save=False)
            borrower.save()

            # Check for duplicate transaction
            existing_transaction = Transaction.objects.filter(
                borrower=borrower,
                borrow_date=date.today(),
                return_date=return_date,
                status='borrowed',
                manager=manager,
            ).select_related('borrower').prefetch_related('items').first()

            if existing_transaction:
                existing_item_ids = set(existing_transaction.items.values_list('id', flat=True))
                if existing_item_ids == set(item_ids):
                    # Duplicate found - return existing transaction data
                    response_serializer = TransactionSerializer(existing_transaction, context={'request': request})
                    logger.info(f"Duplicate transaction detected and skipped: {existing_transaction.id}")
                    return Response(response_serializer.data, status=status.HTTP_201_CREATED)

            # No duplicate - create new transaction
            transaction = Transaction.objects.create(
                borrower=borrower,
                borrow_date=date.today(),
                return_date=return_date,
                status='borrowed',
                manager=manager,
                mobile_user=request.user if request.user.role == 'user_mobile' else None,
            )
            transaction.items.set(items)

            response_serializer = TransactionSerializer(transaction, context={'request': request})  # Pass context
            logger.info(f"Transaction created: {transaction.id}")
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    except Exception as e:
        logger.exception("Error creating borrowing")
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def item_by_id(request, item_id):
    try:
        if not request.user.is_authenticated:
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)
        item = Item.objects.filter(id=item_id, manager=request.user if request.user.role == 'user_web' else request.user.manager).first()
        if not item:
            logger.error(f"Item with ID {item_id} not found")
            return Response({"error": "Item not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = ItemSerializer(item)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error fetching item by ID: {str(e)}")
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    
class UserAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        manager_id = request.user.manager_id if hasattr(request.user, 'manager_id') else None
        return Response({
            "role": request.user.role,
            "username": request.user.username,
            "manager_id": manager_id,
        })
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import PermissionDenied
from istak_backend.models import Transaction
from istak_backend.serializers import TransactionSerializer
import logging

logger = logging.getLogger(__name__)

class TransactionListAPIView(generics.ListAPIView):
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_queryset(self):
        user = self.request.user
        logger.info(f"Fetching transactions for user {user.username} with role {user.role}")
        if user.role == 'user_web':
            return Transaction.objects.filter(manager=user)
        elif user.role == 'user_mobile':
            return Transaction.objects.filter(mobile_user=user)
        logger.warning(f"No transactions returned for user {user.username} with role {user.role}")
        return Transaction.objects.none()

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request
        return context

class TransactionDeleteAPIView(generics.DestroyAPIView):
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_queryset(self):
        user = self.request.user
        logger.info(f"Attempting to delete transaction for user {user.username} with role {user.role}")
        if user.role == 'user_web':
            return Transaction.objects.filter(manager=user)
        elif user.role == 'user_mobile':
            return Transaction.objects.filter(mobile_user=user)
        logger.warning(f"No transactions accessible for deletion by user {user.username} with role {user.role}")
        return Transaction.objects.none()

    def perform_destroy(self, instance):
        logger.info(f"Deleting transaction {instance.id} by user {self.request.user.username}")
        instance.delete()

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def update_fcm_token(request):
    try:
        data = json.loads(request.body)
        fcm_token = data.get('fcm_token')
        
        if not fcm_token:
            return Response({"error": "fcm_token is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        request.user.fcm_token = fcm_token
        request.user.save()
        
        return Response({
            "status": "success",
            "message": "FCM token updated successfully"
        }, status=status.HTTP_200_OK)
    
    except json.JSONDecodeError:
        return Response({"error": "Invalid JSON"}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@authentication_classes([JWTAuthentication])
def top_borrowed_items(request):
    top_items = Item.objects.annotate(
        borrow_count=Count('transactions')
    ).order_by('-borrow_count')[:5]
    serializer = TopBorrowedItemsSerializer(top_items, many=True, context={'request': request})
    return Response(serializer.data)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Transaction

from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from rest_framework.permissions import AllowAny
import logging  # FIXED: Added for debugging

logger = logging.getLogger(__name__)

class MonthlyTransactionsView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny] 
    def get(self, request):
        try:
            # Calculate the date range: last 6 months + current = 7 months
            today = dj_timezone.now().date()
            start_date = today - relativedelta(months=6)  # Starts from 7 months ago
            transactions = Transaction.objects.filter(borrow_date__gte=start_date)

            logger.info(f"Fetching transactions from {start_date} to {today}. Found {transactions.count()} total.")

            # Initialize monthly data for exactly 7 months (with zeros for empty)
            monthly_data = {}
            current_date = start_date
            while current_date <= today:
                month_key = current_date.strftime('%Y-%m')
                monthly_data[month_key] = {'borrowed': 0, 'returned': 0}
                current_date += relativedelta(months=1)

            # Aggregate transactions - FIXED: Ensure borrow_date is used correctly
            for t in transactions:
                month_key = t.borrow_date.strftime('%Y-%m')
                if month_key in monthly_data:
                    if t.status.lower() == 'borrowed':
                        monthly_data[month_key]['borrowed'] += 1
                    elif t.status.lower() == 'returned':
                        monthly_data[month_key]['returned'] += 1

            logger.info(f"Aggregated data: {monthly_data}")  # FIXED: Added logging to debug empty months

            # Format response - FIXED: Sort ascending (oldest first) for chart flow; ensure 7 items
            monthly_result = [
                {
                    'month': datetime.strptime(month_key, '%Y-%m').strftime('%B'),  # e.g., "April"
                    'borrowed': data['borrowed'],
                    'returned': data['returned']
                }
                for month_key, data in sorted(monthly_data.items())  # Ensures oldest to newest
            ]

            # FIXED: Trim to exactly 7 if more (edge case), but loop ensures 7
            if len(monthly_result) > 7:
                monthly_result = monthly_result[-7:]  # Last 7 (safeguard)

            logger.info(f"Returning {len(monthly_result)} months: {monthly_result}")
            return Response(monthly_result, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error in MonthlyTransactionsView: {str(e)}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def update_overdue_transactions(request):
    try:
        today = date.today()
        # Find borrowed transactions with past due return dates
        overdue_transactions = Transaction.objects.filter(
            status='borrowed',
            return_date__lt=today
        )
        count = overdue_transactions.count()
        overdue_transactions.update(status='overdue')
        return Response({
            "status": "success",
            "message": f"Updated {count} transactions to overdue status"
        }, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Item, Transaction

class ItemStatusCountView(APIView):
    def get(self, request):
        try:
            # Count items based on current_transaction status
            total_items = Item.objects.count()
            borrowed_items = Item.objects.filter(
                current_transaction__status='borrowed'
            ).count()
            available_items = total_items - borrowed_items

            return Response({
                'available': available_items,
                'borrowed': borrowed_items
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django.db.models import Count, Max, Q
from .models import Borrower
from .serializers import BorrowerSerializer
import logging

logger = logging.getLogger(__name__)

from django.db.models import Max, Q

class BorrowerListView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        try:
            if request.user.role not in ['user_mobile', 'user_web']:
                logger.error(
                    f"User {request.user.username} with role {request.user.role} "
                    f"attempted to access BorrowerListView"
                )
                return Response(
                    {'error': 'Only mobile or web users can access this endpoint'},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Scope queryset based on role
            if request.user.role == 'user_mobile':
                borrowers = Borrower.objects.filter(
                    transactions__mobile_user=request.user
                )
            else:  # user_web
                borrowers = Borrower.objects.filter(
                    transactions__manager=request.user
                )

            # Annotate with total borrowed items and current borrow date
            borrowers = borrowers.distinct().annotate(
                total_borrowed_items=Count(
                    'transactions__items',
                    filter=Q(transactions__status='borrowed')
                ),
                current_borrow_date=Max(
                    'transactions__borrow_date',
                    filter=Q(transactions__status='borrowed')
                )
            )

            logger.info(
                f"User: {request.user.username}, Role: {request.user.role}, "
                f"Borrowers found: {borrowers.count()}"
            )

            serializer = BorrowerSerializer(borrowers, many=True, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception(f"Error fetching borrowers for user {request.user.username}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# Other views remain unchanged
# ... (Include other views like borrowing_create, item_by_id, etc., as they are not modified)
            
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from istak_backend.models import Transaction, Borrower
from istak_backend.serializers import TransactionSerializer

class BorrowerTransactionsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, borrower_id):
        try:
            transactions = Transaction.objects.filter(
                borrower_id=borrower_id,
                mobile_user=request.user
            ).select_related('borrower').prefetch_related('items').order_by('-borrow_date')
            
            serializer = TransactionSerializer(transactions, many=True, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Borrower.DoesNotExist:
            return Response({"error": "Borrower not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"Failed to fetch transactions: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django.db import transaction as db_transaction
from istak_backend.models import Item, Borrower, Transaction
from istak_backend.serializers import BorrowerSerializer
import logging

logger = logging.getLogger(__name__)

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def item_borrower_view(request, itemId):
    try:
        if not request.user.is_authenticated:
            logger.error("Unauthenticated request to item_borrower_view")
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)

        manager = request.user if request.user.role == 'user_web' else request.user.manager
        if not manager:
            logger.error(f"No manager assigned for user {request.user.username}")
            return Response({"error": "No manager assigned for mobile user"}, status=status.HTTP_403_FORBIDDEN)

        # Find the item with id explicitly selected
        try:
            item = Item.objects.only('id', 'manager').get(id=itemId, manager=manager)
            logger.info(f"Found item {itemId} managed by {manager.username}")
        except Item.DoesNotExist:
            logger.error(f"Item {itemId} not found or not managed by {manager.username}")
            return Response({"error": f"Item {itemId} not found or not managed by your manager"}, status=status.HTTP_404_NOT_FOUND)

        # Find the active transaction for this item with borrower fields loaded
        transaction = Transaction.objects.select_related('borrower').prefetch_related('items').filter(
            items=item,
            status='borrowed',
            manager=manager
        ).first()
        if not transaction:
            logger.error(f"No active borrowed transaction for item {itemId}")
            return Response({"error": f"Item {itemId} is not currently borrowed"}, status=status.HTTP_400_BAD_REQUEST)

        # Get all items in this transaction
        borrowed_items = [
            {
                'id': item.id,
                'item_name': item.item_name,
                'condition': item.condition
            }
            for item in transaction.items.all()
        ]

        # Serialize the borrower instance with all necessary fields
        borrower_data = BorrowerSerializer(transaction.borrower, context={'request': request}).data

        response_data = {
            'transaction_id': str(transaction.id),
            'borrower': borrower_data,
            'borrowed_items': borrowed_items
        }
        logger.info(
            f"Fetched transaction {transaction.id} for borrower {transaction.borrower.school_id} "
            f"with {len(borrowed_items)} items for item {itemId}"
        )
        return Response(response_data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception(f"Error fetching borrower for item {itemId}")
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.db.models import Count

from .models import Item, Transaction, Borrower
from PIL import Image, ImageDraw, ImageFont
from django.core.files.base import ContentFile
from io import BytesIO
import os
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def return_item(request):
    try:
        # Parse request data
        school_id = request.data.get('school_id')
        items_data = []
        for i in range(len(request.data) // 2):  # Parse items array
            item_id = request.data.get(f'items[{i}][itemId]') or request.data.get(f'items[{i}][item_id]')
            condition = request.data.get(f'items[{i}][condition]')
            if item_id and condition:
                items_data.append({'item_id': item_id, 'condition': condition})

        return_image = request.FILES.get('return_image')
        if not items_data:
            return Response({"error": "No items provided"}, status=status.HTTP_400_BAD_REQUEST)

        # Find transaction
        item_ids = [item['item_id'] for item in items_data]
        transactions = Transaction.objects.filter(
            status='borrowed',
            items__id__in=item_ids,
        ).annotate(num_matches=Count('items__id')).filter(num_matches=len(item_ids))

        if school_id:
            transactions = transactions.filter(borrower__school_id=school_id)

        transaction = transactions.first()
        if not transaction:
            return Response({"error": "No matching borrowed transaction found"}, status=status.HTTP_400_BAD_REQUEST)

        # Get borrower details
        borrower = transaction.borrower
        name = borrower.name
        school_id = borrower.school_id

        # Process return_image if provided
        processed_image = None
        if return_image:
            # Validate image size (max 5MB)
            if return_image.size > 5 * 1024 * 1024:
                return Response({"error": "Return image size exceeds 5MB"}, status=status.HTTP_400_BAD_REQUEST)

            # Open and process image
            image = Image.open(return_image).convert('RGB')
            draw = ImageDraw.Draw(image)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            text = f"Name: {name}\nSchool ID: {school_id}\nReturned: {timestamp}"

            try:
                font = ImageFont.truetype(os.path.join(settings.BASE_DIR, 'fonts', 'arial.ttf'), 24)
            except IOError:
                font = ImageFont.load_default(size=24)

            text_position = (10, 10)
            draw.multiline_text(
                text_position,
                text,
                font=font,
                fill=(255, 255, 255, 255),
                stroke_width=2,
                stroke_fill=(0, 0, 0, 255)
            )

            # Save processed image to buffer
            buffer = BytesIO()
            image.save(buffer, format="PNG")
            buffer.seek(0)
            timestamp_clean = timestamp.replace(":", "-").replace(" ", "_")
            filename = f"borrower_return_image_{school_id}_{timestamp_clean}.png"
            processed_image = ContentFile(buffer.read(), name=filename)

        # Update transaction
        transaction.status = 'returned'
        transaction.return_date = dj_timezone.now().date()
        transaction.save()

        # Update item conditions
        for item_data in items_data:
            try:
                item = Item.objects.get(id=item_data['item_id'])
                item.condition = item_data['condition']
                item.save()
            except Item.DoesNotExist:
                logger.warning(f"Item {item_data['item_id']} not found")

        # Update borrower's return_image
        if processed_image:
            borrower.return_image = processed_image
            borrower.save()

        logger.info(f"Return processed for transaction {transaction.id}, borrower {borrower.school_id}")
        return Response(
            {
                "status": "success",
                "message": "Items returned successfully",
                "image_url": request.build_absolute_uri(borrower.return_image.url) if processed_image else None
            },
            status=status.HTTP_200_OK
        )

    except Exception as e:
        logger.error(f"Error in return_item: {str(e)}")
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
# views.py
# views.py (Revised: Now returns transaction counts, not item counts)
from django.db.models import Q
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated

from .models import Item, Transaction
import logging

logger = logging.getLogger(__name__)

class InventorySummaryView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            today = dj_timezone.now().date()

            # Scope by role
            if user.role == 'user_web':
                queryset = Transaction.objects.filter(manager=user)
                items = Item.objects.filter(manager=user)
            elif user.role == 'user_mobile':
                queryset = Transaction.objects.filter(mobile_user=user)
                items = Item.objects.filter(manager=user.manager) if user.manager else Item.objects.none()
            else:
                return Response({"error": "Invalid user role"}, status=status.HTTP_403_FORBIDDEN)

            # Counts
            returned_transactions = queryset.filter(status='returned').count()
            overdue_transactions = queryset.filter(
                Q(status='overdue') | (Q(status='borrowed') & Q(return_date__lt=today))
            ).count()
            non_overdue_borrowed = queryset.filter(
                status='borrowed',
                return_date__gte=today
            ).count()
            borrowed_active = non_overdue_borrowed + overdue_transactions
            returning_today_transactions = queryset.filter(
                status='borrowed',
                return_date=today
            ).count()
            total_transactions = returned_transactions + borrowed_active

            # Log counts for debugging
            logger.debug(f"InventorySummaryView: returned={returned_transactions}, "
                        f"borrowed_active={borrowed_active}, non_overdue_borrowed={non_overdue_borrowed}, "
                        f"overdue={overdue_transactions}, returning_today={returning_today_transactions}")

            return Response({
                'totalTransactions': total_transactions,
                'borrowedTransactions': borrowed_active,  # For percentage (yellow + red)
                'returnedTransactions': returned_transactions,  # Available (green)
                'overdueTransactions': overdue_transactions,  # Red
                'returningTodayTransactions': returning_today_transactions,  # For UI text
                'nonOverdueBorrowedTransactions': non_overdue_borrowed,  # Yellow
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error in InventorySummaryView: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from PIL import Image, ImageDraw, ImageFont
from django.core.files.base import ContentFile
from io import BytesIO
import os
from datetime import datetime
from django.conf import settings
from istak_backend.models import Borrower

class ProcessImageView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            if 'image' not in request.FILES or 'name' not in request.data or 'school_id' not in request.data:
                return Response({"error": "Image, name, and school_id are required"}, status=status.HTTP_400_BAD_REQUEST)

            image_file = request.FILES['image']
            if image_file.size > 5 * 1024 * 1024:
                return Response({"error": "Image size exceeds 5MB"}, status=status.HTTP_400_BAD_REQUEST)

            name = request.data['name']
            school_id = request.data['school_id']
            if not isinstance(name, str) or not isinstance(school_id, str):
                return Response({"error": "Name and school_id must be strings"}, status=status.HTTP_400_BAD_REQUEST)
            if len(name) > 255 or len(school_id) > 10:
                return Response({"error": "Name or school_id exceeds maximum length"}, status=status.HTTP_400_BAD_REQUEST)

            image = Image.open(image_file).convert('RGB')
            draw = ImageDraw.Draw(image)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            text = f"Name: {name}\nSchool ID: {school_id}\nCaptured: {timestamp}"

            try:
                font = ImageFont.truetype(os.path.join(settings.BASE_DIR, 'fonts', 'arial.ttf'), 24)
            except IOError:
                font = ImageFont.load_default(size=24)

            text_position = (10, 10)
            draw.multiline_text(text_position, text, font=font, fill=(255, 255, 255, 255), stroke_width=2, stroke_fill=(0, 0, 0, 255))

            buffer = BytesIO()
            image.save(buffer, format="PNG")
            buffer.seek(0)

            timestamp_clean = timestamp.replace(":", "-").replace(" ", "_")
            filename = f"borrower_image_{school_id}_{timestamp_clean}.png"
            processed_image = ContentFile(buffer.read(), name=filename)

            # Create or update Borrower
            borrower, created = Borrower.objects.get_or_create(
                school_id=school_id,
                defaults={'name': name, 'status': 'active', 'image': processed_image}
            )
            if not created:
                borrower.name = name
                borrower.image = processed_image
                borrower.status = 'active'
                borrower.save()

            image_url = request.build_absolute_uri(borrower.image.url)
            return Response({"image_url": image_url}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"Failed to process image: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
import logging
import traceback
from django.core.cache import cache
from datetime import date
from dateutil.relativedelta import relativedelta

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

from .forcastingModel import forecast_next_month_from_excel as forecast_excel_helper

# Setup logging (this writes to Django's console/logs)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

EXCEL_PATH = "dataset.xlsx"  # your local file in same folder as manage.py

def _next_forecast_month_str():
    try:
        return (timezone.localdate() + relativedelta(months=1)).strftime("%Y-%m")
    except Exception:
        return (date.today() + relativedelta(months=1)).strftime("%Y-%m")


@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def forecast_top_items_excel(request):
    """
    Debug version of the forecast API — adds verbose logs at every step
    to locate the exact cause of '502 Bad Gateway' errors.
    """
    logger.info("===== /api/forecast-top-items/ called =====")

    try:
        # Step 1: Parse params
        force = str(request.query_params.get("force", "0")).lower() in ("1", "true", "yes")
        try:
            top_k = int(request.query_params.get("k", "5"))
        except ValueError:
            top_k = 5

        forecast_month = _next_forecast_month_str()
        cache_key = f"forecast_excel:{forecast_month}:k{top_k}"

        logger.info(f"[PARAMS] top_k={top_k}, force={force}, forecast_month={forecast_month}")
        logger.info(f"[CACHE_KEY] {cache_key}")

        # Step 2: Try cache first
        if not force:
            cached = cache.get(cache_key)
            if cached is not None:
                logger.info("[CACHE HIT] Returning cached forecast")
                return Response(cached, status=200)
        logger.info("[CACHE MISS] No cached data found or force recompute")

        # Step 3: Try loading Excel file
        import os
        abs_path = os.path.abspath(EXCEL_PATH)
        logger.info(f"[EXCEL LOAD] Attempting to read file: {abs_path}")
        if not os.path.exists(abs_path):
            logger.error(f"[ERROR] Excel file not found at {abs_path}")
            return Response({"error": f"Excel file not found at {abs_path}"}, status=500)

        # Step 4: Run the Prophet forecast helper
        logger.info("[FORECAST] Starting Prophet model computation...")
        results = forecast_excel_helper(EXCEL_PATH, top_k=top_k)
        logger.info(f"[FORECAST] Completed successfully — results count: {len(results)}")

        # Step 5: Prepare payload and cache
        payload = {
            "month": results[0]["month"] if results else forecast_month,
            "top_k": top_k,
            "results": results,
            "cached_for_month": forecast_month,
        }
        cache.set(cache_key, payload, 35 * 24 * 60 * 60)
        logger.info("[CACHE SET] Cached new forecast for one month")
        logger.info("===== /api/forecast-top-items/ finished OK =====")

        return Response(payload, status=200)

    except Exception as e:
        tb = traceback.format_exc()
        logger.error("===== /api/forecast-top-items/ FAILED =====")
        logger.error(f"[EXCEPTION] {str(e)}")
        logger.error(f"[TRACEBACK]\n{tb}")
        return Response({
            "error": str(e),
            "traceback": tb.splitlines()[-10:],
        }, status=500)


# views.py
from datetime import timedelta
from django.utils.timezone import localdate
from django.db.models import Q
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import Transaction

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def borrowed_stats(request):
    """
    Unified endpoint for borrowed items.
    Use ?range=yesterday|today|week|month
    """
    range_type = request.query_params.get("range", "yesterday")  # default = yesterday
    today = localdate()
    qs = Transaction.objects.filter(status="borrowed")

    if range_type == "today":
        qs = qs.filter(borrow_date=today)

    elif range_type == "yesterday":
        qs = qs.filter(borrow_date=today - timedelta(days=1))

    elif range_type == "week":
        start_of_week = today - timedelta(days=today.weekday())  # Monday
        qs = qs.filter(borrow_date__gte=start_of_week, borrow_date__lte=today)

    elif range_type == "month":
        start_of_month = today.replace(day=1)
        qs = qs.filter(borrow_date__gte=start_of_month, borrow_date__lte=today)

    count = qs.count()
    return Response({
        "range": range_type,
        "count": count,
    })


from rest_framework import generics
from .models import Transaction
from .serializers import TransactionSerializer

class TransactionRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Transaction.objects.all()
    serializer_class = TransactionSerializer
    lookup_field = "pk"
    
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from datetime import timedelta, datetime
from django.db.models import Count
from .models import Transaction
from .serializers import TransactionSerializer
import logging

logger = logging.getLogger(__name__)

class AnalyticsTransactionsView(APIView):
    def get(self, request):
        try:
            # Get all relevant transactions (no filter here, filter in aggregations)
            transactions = Transaction.objects.all()

            # Calculate date ranges
            today = dj_timezone.now().date()

            # Daily aggregation: Last 7 days
            start_daily = today - timedelta(days=6)
            daily_data = {}
            daily_transactions = [t for t in transactions if start_daily <= t.borrow_date <= today]
            for t in daily_transactions:
                day_key = t.borrow_date.strftime('%Y-%m-%d')
                if day_key not in daily_data:
                    daily_data[day_key] = {'count': 0, 'items': {}}
                daily_data[day_key]['count'] += 1
                for item in t.items.all():
                    item_name = item.item_name
                    daily_data[day_key]['items'][item_name] = daily_data[day_key]['items'].get(item_name, 0) + 1

            daily_7_result = [
                {
                    'date': day_key,
                    'count': data['count'],
                    'top_items': [
                        {'item': item, 'count': count}
                        for item, count in sorted(
                            data['items'].items(), key=lambda x: x[1], reverse=True
                        )[:5]
                    ]
                }
                for day_key, data in sorted(daily_data.items())  # Ascending: past to present
            ]

            # Weekly aggregation: Last 8 weeks
            start_weekly = today - timedelta(weeks=7)  # 8 weeks including current
            weekly_data = {}
            weekly_transactions = [t for t in transactions if t.borrow_date >= start_weekly]
            for t in weekly_transactions:
                borrow_date = t.borrow_date
                day = borrow_date.weekday()
                week_start = borrow_date - timedelta(days=day)
                week_key = week_start.strftime('%Y-%m-%d')

                if week_key not in weekly_data:
                    weekly_data[week_key] = {'count': 0, 'items': {}}
                weekly_data[week_key]['count'] += 1
                for item in t.items.all():
                    item_name = item.item_name
                    weekly_data[week_key]['items'][item_name] = weekly_data[week_key]['items'].get(item_name, 0) + 1

            weekly_8_result = [
                {
                    'week_start': week_key,
                    'count': data['count'],
                    'top_items': [
                        {'item': item, 'count': count}
                        for item, count in sorted(
                            data['items'].items(), key=lambda x: x[1], reverse=True
                        )[:5]
                    ]
                }
                for week_key, data in sorted(weekly_data.items())  # Ascending
                if datetime.strptime(week_key, '%Y-%m-%d').date() >= start_weekly
            ][:8]  # Ensure max 8

            # Monthly aggregation: Last 12 months
            start_monthly = today - relativedelta(months=11)  # 12 months including current
            monthly_data = {}
            monthly_transactions = [t for t in transactions if t.borrow_date >= start_monthly]
            for t in monthly_transactions:
                month_key = t.borrow_date.strftime('%Y-%m')
                if month_key not in monthly_data:
                    monthly_data[month_key] = {'count': 0, 'items': {}}
                monthly_data[month_key]['count'] += 1
                for item in t.items.all():
                    item_name = item.item_name
                    monthly_data[month_key]['items'][item_name] = monthly_data[month_key]['items'].get(item_name, 0) + 1

            monthly_12_result = [
                {
                    'month': month_key,
                    'count': data['count'],
                    'top_items': [
                        {'item': item, 'count': count}
                        for item, count in sorted(
                            data['items'].items(), key=lambda x: x[1], reverse=True
                        )[:5]
                    ]
                }
                for month_key, data in sorted(monthly_data.items())  # Ascending
                if datetime.strptime(month_key, '%Y-%m').date() >= start_monthly.replace(day=1)
            ][:12]  # Ensure max 12

            return Response({
                'daily_7': daily_7_result,
                'weekly_8': weekly_8_result,
                'monthly_12': monthly_12_result
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error in AnalyticsTransactionsView: {str(e)}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
# serializers.py (Revised DamagedOverdueReportSerializer)
# serializers.py (Fixed: Proper ModelSerializer)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from datetime import timedelta
from django.db.models import Q, Prefetch
from .models import Transaction, Item
from .serializers import DamagedOverdueReportSerializer  # FIXED: Import the serializer
import logging

logger = logging.getLogger(__name__)

class DamagedOverdueReportView(APIView):  # FIXED: Proper APIView
    def post(self, request):
        try:
            # Get filters from request body
            search = request.data.get('search', '')
            status_filter = request.data.get('status', '').lower()
            date_from = request.data.get('dateFrom')
            date_to = request.data.get('dateTo')

            today = dj_timezone.now().date()

            # Base queryset
            queryset = Transaction.objects.filter(
                Q(status='returned', items__condition__iexact='damaged') |
                Q(status='borrowed', return_date__lt=today)
            ).distinct().prefetch_related(
                Prefetch('items', queryset=Item.objects.only('item_name', 'condition')),
                'borrower'
            )

            # Apply search
            if search:
                queryset = queryset.filter(
                    Q(borrower__name__icontains=search) |
                    Q(borrower__school_id__icontains=search) |
                    Q(items__item_name__icontains=search)
                )

            # Apply status filter
            if status_filter and status_filter != 'all':
                if status_filter == 'damaged':
                    queryset = queryset.filter(status='returned', items__condition__iexact='damaged')
                elif status_filter == 'overdue':
                    queryset = queryset.filter(status='borrowed', return_date__lt=today)

            # Apply date range
            from datetime import datetime, timedelta

# ...
            if date_from:
                try:
                    date_from = datetime.strptime(date_from, "%Y-%m-%d").date()
                    queryset = queryset.filter(borrow_date__gte=date_from)
                except ValueError:
                    return Response({"error": "Invalid dateFrom format"}, status=status.HTTP_400_BAD_REQUEST)

            if date_to:
                try:
                    # include the full end day by adding +1 day and using < instead of <=
                    date_to = datetime.strptime(date_to, "%Y-%m-%d").date() + timedelta(days=1)
                    queryset = queryset.filter(borrow_date__lt=date_to)
                except ValueError:
                    return Response({"error": "Invalid dateTo format"}, status=status.HTTP_400_BAD_REQUEST)


            logger.info(f"Queried {queryset.count()} transactions")

            # FIXED: Use the serializer
            serializer = DamagedOverdueReportSerializer(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error in DamagedOverdueReportView: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
class CurrentUserView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        data = {
            'username': user.username,
            'name': user.username,  # Use username as name if no first_name/last_name
            'email': user.email,
            # 'avatar': '/avatars/shadcn.jpg'  # Default avatar, adjust as needed
        }
        return Response(data)
    
    
from rest_framework import generics
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.hashers import make_password
from .models import CustomUser, RegistrationRequest
from .serializers import RegistrationRequestSerializer  # Assume you have one for users too

# New ViewSet for listing mobile users under manager
# views.py (Fixed MobileUsersList)
from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from .models import CustomUser

class MobileUsersList(generics.ListAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        # FIXED: Return None to skip serialization (use manual response in list())
        return None

    def get_queryset(self):
        if self.request.user.role != 'user_web':
            return CustomUser.objects.none()
        return CustomUser.objects.filter(role='user_mobile', manager=self.request.user)

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        # FIXED: Manual response (no serializer needed)
        users_data = [
            {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'date_joined': user.date_joined.isoformat() if user.date_joined else None,
            }
            for user in queryset
        ]
        return Response({'users': users_data}, status=status.HTTP_200_OK)

# New endpoint for changing password (manager only)
@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def change_mobile_password(request, user_id):
    if request.user.role != 'user_web':
        return Response({"error": "Only managers can change passwords"}, status=status.HTTP_403_FORBIDDEN)
    
    try:
        target_user = CustomUser.objects.filter(id=user_id, role='user_mobile', manager=request.user).first()
        if not target_user:
            return Response({"error": "User not found or unauthorized"}, status=404)
        
        new_password = request.data.get('password')
        if not new_password:
            return Response({"error": "Password is required"}, status=400)
        
        target_user.set_password(new_password)
        target_user.save()
        
        return Response({"status": "success", "message": "Password updated successfully"}, status=200)
    
    except Exception as e:
        return Response({"error": str(e)}, status=500)
    
    


# --- add/ensure imports ---
from datetime import timedelta

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from .models import Item, Transaction

# If you see this anywhere in views.py, fix it:
# from sympy import Q   <-- WRONG
# use:
# from django.db.models import Q  # <-- RIGHT (only if you actually use Q)

class PredictiveDamageInsightView(APIView):
    """
    Rule-based prediction: estimates which items are at risk of damage soon.
    Computes per-item risk using recent borrows, overdue history, and current condition.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Scope items by role
            if getattr(request.user, "role", None) == "user_web":
                items_qs = Item.objects.filter(manager=request.user)
            elif getattr(request.user, "role", None) == "user_mobile" and request.user.manager:
                items_qs = Item.objects.filter(manager=request.user.manager)
            else:
                return Response({"error": "Unauthorized role or missing manager."},
                                status=status.HTTP_403_FORBIDDEN)

            today = dj_timezone.now().date()
            ninety_days_ago = today - timedelta(days=90)
            now_iso = dj_timezone.now().isoformat()

            results = []
            for item in items_qs:
                tx_qs = Transaction.objects.filter(items=item)

                total_borrows = tx_qs.count()
                recent_borrows = tx_qs.filter(borrow_date__gte=ninety_days_ago).count()
                overdue_count  = tx_qs.filter(status="overdue").count()

                # Use current item condition as a damage signal
                cond_text = (item.condition or "").lower()
                damage_flag = any(k in cond_text for k in ["damaged", "damage", "broken", "crack", "dent", "loose"])

                # Heuristic scoring
                risk = 0.0
                if recent_borrows > 3:  # heavy recent usage
                    risk += 0.30
                if overdue_count > 1:   # mishandling risk
                    risk += 0.20
                if damage_flag:         # already showing issues
                    risk += 0.40
                if total_borrows > 10:  # wear/tear
                    risk += 0.10
                risk = min(1.0, risk)

                reason = (
                    f"Total borrows: {total_borrows}, "
                    f"Recent(90d): {recent_borrows}, "
                    f"Overdue: {overdue_count}, "
                    f"Current condition: {item.condition or 'N/A'}"
                )

                results.append({
                    "item_name": item.item_name,
                    "condition": item.condition,
                    "predicted_risk": risk,
                    "reason": reason,
                    "last_checked": now_iso,
                })

            results.sort(key=lambda x: x["predicted_risk"], reverse=True)
            return Response(results, status=status.HTTP_200_OK)

        except Exception as e:
            # Print full traceback to your Django console for quick diagnosis
            import traceback
            traceback.print_exc()
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




from datetime import datetime, timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone as dj_timezone
from django.db.models import Q, Prefetch
from .models import Transaction, Item, Borrower
from .serializers import TransactionReportSerializer
import logging

logger = logging.getLogger(__name__)

class TransactionReportView(APIView):
    def post(self, request):
        try:
            # --- Get filters from request body ---
            search = request.data.get('search', '')
            condition_filter = request.data.get('condition', '').lower()
            date_from = request.data.get('dateFrom')
            date_to = request.data.get('dateTo')
            date_type = request.data.get('dateType', 'borrow').lower()  
            # 👆 new field: 'borrow' | 'return' | 'both'

            today = dj_timezone.now().date()

            queryset = Transaction.objects.select_related('borrower').prefetch_related(
                Prefetch('items', queryset=Item.objects.only('item_name', 'condition')),
            ).distinct()

            # --- Condition filter ---
            if condition_filter and condition_filter != 'all':
                if condition_filter == 'overdue':
                    queryset = queryset.filter(status='borrowed', return_date__lt=today)
                else:
                    queryset = queryset.filter(
                        status='returned',
                        items__condition__iexact=condition_filter
                    )

            # --- Search filter ---
            if search:
                queryset = queryset.filter(
                    Q(borrower__name__icontains=search) |
                    Q(borrower__school_id__icontains=search) |
                    Q(items__item_name__icontains=search)
                )

            # --- Date parsing ---
            parsed_from = None
            parsed_to = None
            if date_from:
                parsed_from = datetime.strptime(date_from, "%Y-%m-%d").date()
            if date_to:
                parsed_to = datetime.strptime(date_to, "%Y-%m-%d").date() + timedelta(days=1)

            # --- Date filter logic ---
            if parsed_from and parsed_to:
                if date_type == "borrow":
                    queryset = queryset.filter(borrow_date__gte=parsed_from, borrow_date__lt=parsed_to)
                elif date_type == "return":
                    queryset = queryset.filter(return_date__isnull=False,
                                               return_date__gte=parsed_from,
                                               return_date__lt=parsed_to)
                elif date_type == "both":
                    queryset = queryset.filter(
                        borrow_date__gte=parsed_from, borrow_date__lt=parsed_to,
                        return_date__isnull=False,
                        return_date__gte=parsed_from, return_date__lt=parsed_to
                    )
            elif parsed_from:
                # fallback if only start given
                if date_type == "borrow":
                    queryset = queryset.filter(borrow_date__gte=parsed_from)
                elif date_type == "return":
                    queryset = queryset.filter(return_date__isnull=False, return_date__gte=parsed_from)
            elif parsed_to:
                if date_type == "borrow":
                    queryset = queryset.filter(borrow_date__lt=parsed_to)
                elif date_type == "return":
                    queryset = queryset.filter(return_date__isnull=False, return_date__lt=parsed_to)

            # --- Serialize + extra overdue info ---
            today = dj_timezone.now().date()
            processed_data = []
            for tx in queryset:
                serializer = TransactionReportSerializer(tx, context={'request': request})
                data = serializer.data
                if tx.status == 'borrowed' and tx.return_date and tx.return_date < today:
                    data['daysPastDue'] = (today - tx.return_date).days
                processed_data.append(data)

            logger.info(f"Queried {len(processed_data)} transactions (dateType={date_type})")

            return Response(processed_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error in TransactionReportView: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from django.http import JsonResponse


def healthz(_):
    # simple OK; fast and safe
    return JsonResponse({"status": "ok"}, status=200)



from .models import Item
from .serializers import SimpleItemSerializer
import logging

logger = logging.getLogger(__name__)

class SimpleItemListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = SimpleItemSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = None  # Disable pagination for simplicity

    def get_queryset(self):
        user = self.request.user
        cache_key = f"simple_items_{user.id}_{user.role}"
        cached_data = cache.get(cache_key)
        if cached_data is not None:
            logger.info(f"Cache hit for simple items: user={user.username}")
            return Item.objects.filter(id__in=[item['id'] for item in cached_data])

        if user.role == 'user_web':
            queryset = Item.objects.filter(manager=user).only('id', 'item_name')
        elif user.manager:
            queryset = Item.objects.filter(manager=user.manager).only('id', 'item_name')
        else:
            queryset = Item.objects.none()

        serializer = SimpleItemSerializer(queryset, many=True)
        cache.set(cache_key, serializer.data, 60 * 60)  # Cache for 1 hour
        logger.info(f"Cached simple items for user={user.username}, count={len(serializer.data)}")

        return queryset

    def perform_create(self, serializer):
        from PIL import Image
        from rembg import remove
        from io import BytesIO

        image_file = self.request.FILES.get('image')
        new_image = None
        if image_file:
            try:
                if image_file.size > 5 * 1024 * 1024:
                    logger.error("Image size exceeds 5MB")
                    return Response(
                        {"error": "Image size exceeds 5MB"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                input_img = Image.open(image_file).convert("RGBA")
                input_img.thumbnail((800, 800), Image.Resampling.LANCZOS)
                output_img = remove(input_img)
                temp_buffer = BytesIO()
                output_img.save(temp_buffer, format="PNG")
                temp_buffer.seek(0)
                new_image = ContentFile(
                    temp_buffer.read(),
                    name=f"{image_file.name.rsplit('.', 1)[0]}.png"
                )
            except Exception as e:
                logger.error(f"Error removing background for new item: {str(e)}")
                return Response(
                    {"error": f"Failed to process image: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        manager = self.request.user if self.request.user.role == 'user_web' else self.request.user.manager
        if not manager:
            logger.error(f"No manager assigned for user {self.request.user.username}")
            return Response(
                {"error": "No manager assigned for mobile user"},
                status=status.HTTP_403_FORBIDDEN
            )

        instance = serializer.save(manager=manager, image=new_image if new_image else None)

        cache_key = f"simple_items_{self.request.user.id}_{self.request.user.role}"
        cache.delete(cache_key)
        logger.info(f"Invalidated cache for user={self.request.user.username}")

        if new_image:
            logger.info(f"Background removed for item {instance.id}")

        return Response(serializer.data, status=status.HTTP_201_CREATED)