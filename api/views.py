import hashlib
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
# from django.utils.timezone import now
# from django.core import cache
from django.db import transaction
from django.db.models import Q
# from django.contrib.auth.models import User
from ecdsa import SigningKey, SECP256k1
from .models import CustomUser, LuluCoinBlock, Transaction, GlobalVariables
from .serializers import LuluCoinBlockSerializer, TransactionSerializer, CustomUserSerializer, GlobalVariablesSerializer
# from decouple import config


class Block:
    def __init__(self, previous_block_hash: str, transactions: list[str]):
        self.previous_block_hash = previous_block_hash
        self.transactions = transactions
    
        self.block_data = "-".join(transactions) + "-" + previous_block_hash
        self.block_hash = hashlib.sha256(self.block_data.encode()).hexdigest()


class GlobalVariablesView(APIView):
    def get(self, request):
        global_variables = GlobalVariables.objects.all()

        if global_variables:
            return Response({
                "difficulty": global_variables.first().difficulty,
                "mining_reward": global_variables.first().mining_reward,
                "fees": global_variables.first().fees
            })
        
        return Response({
            "error": "Data not available!"
        }, status=status.HTTP_404_NOT_FOUND)

    def post(self, request):
        if not request.user.is_staff:
            return Response({
                "error": "Unauthorized access!."
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        serializer = GlobalVariablesSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)  
    
    def put(self, request):
        if not request.user.is_staff:
            return Response({
                "error": "Unauthorized access!."
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        serializer = GlobalVariablesSerializer(data=request.data)

        if serializer.is_valid():
            serializer.update(GlobalVariables.objects.first(), serializer.validated_data)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)        


class InfoView(APIView):
    def get(self, request):
        return Response({"data": "LULUCOIN, the threat to Culprits of CSE Club"})


class CustomRegister(APIView):
    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        
        if serializer.is_valid():
            first_name = request.data.get("first_name")
            last_name = request.data.get("last_name")
            username = request.data.get("username")
            email = request.data.get("email")
            city = request.data.get("city")
            password = request.data.get("password")

            if CustomUser.objects.filter(email=email).exists():
                return Response({"message": "Eamil already exists!"}, status=status.HTTP_400_BAD_REQUEST)
            
            if CustomUser.objects.filter(username=username).exists():
                return Response({"message": "Username already exists!"}, status=status.HTTP_400_BAD_REQUEST)      

            signing_key = SigningKey.generate(curve=SECP256k1)
            private_key = signing_key.to_string().hex()
            public_key = signing_key.verifying_key.to_string().hex()

            user = CustomUser.objects.create_user(first_name=first_name, last_name=last_name, email=email, city=city, username=username, password=password, private_key=private_key, public_key=public_key)
            refresh = RefreshToken.for_user(user)
            
            return Response({
                "message": "User registered successfully!",
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors)

# class WalletView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         user = request.user
#         cache_key = f"wallet_creation_{user.id}"
#         cooldown_key = f"wallet_cooldown_{user.id}"

#         cooldown_time = cache.get(cooldown_key)

#         if cooldown_time:
#             return Response({
#                 "error": "You have exceeded the limit. Try again after 1 hour."
#             }, status=403)

#         request_count = cache.get(cache_key, 0)

#         if request_count >= 2:
#             cache.set(cooldown_key, now().timestamp(), timeout=3600)
#             cache.delete(cache_key)
#             return Response({
#                 "error": "You have exceeded the limit. Try again after 1 hour."
#             }, status=403)

#         cache.set(cache_key, request_count + 1, timeout=3600)

#         wallet = Wallet(user=user)
#         wallet.generate_keys()
#         wallet.save()

#         return Response({
#             "private_key": wallet.private_key,
#             "public_key": wallet.public_key
#         })



class TransactionView(APIView):
    def get(self, request):

        option = request.GET.get("type")

        if option == "mempool":
            txs = Transaction.objects.filter(is_pending=True)
            serializer = TransactionSerializer(txs, many=True)
            return Response(serializer.data)
        
        txs = Transaction.objects.all()
        serializer = TransactionSerializer(txs, many=True)
        return Response(serializer.data)
        
    def post(self, request):
        sender = CustomUser.objects.filter(username=request.user.username).first()
        receiver = CustomUser.objects.filter(username=request.data.get("receiver")).first()
        amount = float(request.data.get("amount"))
        fees = GlobalVariables.objects.first().fees * amount
        
        if CustomUser.objects.filter(id=request.user.id).first().balance - (amount + fees) < 0:
            return Response({
                "error": "Insufficient amount of LULUCOINs!"
            }, status=status.HTTP_400_BAD_REQUEST)

        private_key = CustomUser.objects.filter(username=request.user).first().private_key

        transaction = Transaction(sender=sender, receiver=receiver, amount=amount, fees=fees)
        transaction.sign_transaction(private_key)
        transaction.save()

        self.balance_adjustment(sender.id, amount + fees)

        return Response({
            "message": "LULUCOIN Transaction successfull!"
        }, status=status.HTTP_200_OK)


    def balance_adjustment(self, sender_id, amount):
        with transaction.atomic():
            user = CustomUser.objects.select_for_update().get(id=sender_id)
            user.balance -= amount
            user.save()


class AddBlockView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = LuluCoinBlockSerializer(data=request.data)

        if serializer.is_valid():
            # previous_block_hash = LuluCoinBlock.objects.order_by("-created_at")[0].block_hash
            # transactions = Block(previous_block_hash, serializer.validated_data.get('transactions').split(","))
            # block_hash = transactions.block_hash
            # serializer.save(previous_block_hash=previous_block_hash, block_hash=block_hash)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ValidateView(APIView):
    def get(self, request):
        blocks = LuluCoinBlock.objects.filter(is_pending=True).order_by("-submission_time")

        for block in blocks:
            if block.difficulty != GlobalVariables.objects.first().difficulty:
                LuluCoinBlock.objects.filter(id=block.id).get(is_pending=False)
                return Response({
                    "error": "Difficulty level is not same!"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            is_valid = True
            trxns = block.transactions.split(",")
            for trxn in trxns:
                if not Transaction.objects.filter(Q(signature=trxn) & Q(is_pending=True)).exists():
                    is_valid = False
                    break
                    
            if is_valid == False:
                with transaction.atomic():
                    LuluCoinBlock.objects.filter(id=block.id).get(is_pending=False)
                
                return Response({"error": "Invalid Block"}, status=status.HTTP_403_FORBIDDEN)
            
            passed = block.validate()

            if passed:
                with transaction.atomic():
                    
                    total_fees = 0
                    
                    for trxn in trxns:
                        adjust_trxn = Transaction.objects.filter(signature=trxn)
                        self.balance_adjustment(adjust_trxn.first().receiver.id, adjust_trxn.first().amount) # Adjusting the balance of the receiver
                        total_fees += adjust_trxn.first().fees # Calculating the total fees for the miner
                        adjust_trxn.update(is_pending=False)

                    self.balance_adjustment(CustomUser.objects.filter(username="anti_cse_club_treasury").first().id, -GlobalVariables.objects.first().mining_reward)
                    self.balance_adjustment(block.created_by.id, GlobalVariables.objects.first().mining_reward) # Adjusting the block_reward for the miner
                    self.balance_adjustment(block.created_by.id, total_fees) # Adjusting the bonus balance of the miner

                    LuluCoinBlock.objects.filter(id=block.id).update(is_pending=False, is_valid=True, block_reward=total_fees, index=GlobalVariables.objects.first().num_blocks)
                    GlobalVariables.objects.update(num_blocks=GlobalVariables.objects.first().num_blocks + 1)

                    return Response({
                        "message": "Block is valid"
                    }, status=status.HTTP_200_OK)
            
            LuluCoinBlock.objects.filter(id=block.id).update(is_pending=False)

            return Response({
                "error": "Block is invalid!"
            }, status=status.HTTP_403_FORBIDDEN)
        

        return Response({
            "error": "Mempool is empty"
        }, status=status.HTTP_404_NOT_FOUND)
        
    # Increases the balance of the receiver
    def balance_adjustment(self, receiver_id, amount):
        with transaction.atomic():
            user = CustomUser.objects.select_for_update().get(id=receiver_id)
            user.balance += amount
            user.save()
            
        # all_blocks = LuluCoinBlock.objects.all()
        # is_valid = True

        # # Generating Hash for the Genesis block
        # previous_block_hash = hashlib.sha256(config("GENESIS_HASH").encode()).hexdigest() + "....0000000001101"

        # for block in all_blocks:
        #     if previous_block_hash != block.previous_block_hash:
        #         is_valid = False
        #         break
            
        #     block = Block(previous_block_hash, block.transactions.split(','))
        #     previous_block_hash = block.block_hash
            
        # if is_valid:
        #     return Response({"data": "Block Chain Data Integrity is valid"}, status=status.HTTP_200_OK)
        # else:
        #     return Response({"data": "Block Chain Data Integrity is invalid!"}, status=status.HTTP_409_CONFLICT)
