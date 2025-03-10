import hashlib
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from .models import LuluCoinBlock
from .serializers import LuluCoinBlockSerializer
from decouple import config


class Block:
    def __init__(self, previous_block_hash: str, transactions: list[str]):
        self.previous_block_hash = previous_block_hash
        self.transactions = transactions
    
        self.block_data = "-".join(transactions) + "-" + previous_block_hash
        self.block_hash = hashlib.sha256(self.block_data.encode()).hexdigest()


class InfoView(APIView):
    def get(self, request):
        return Response({"data": "LULUCOIN, the threat to Culprits of CSE Club"})


class AddBlockView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    def post(self, request):
        serializer = LuluCoinBlockSerializer(data=request.data)

        if serializer.is_valid():
            previous_block_hash = LuluCoinBlock.objects.order_by("-created_at")[0].block_hash
            transactions = Block(previous_block_hash, serializer.validated_data.get('transactions').split(","))
            block_hash = transactions.block_hash
            serializer.save(previous_block_hash=previous_block_hash, block_hash=block_hash)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ValidateView(APIView):
    def get(self, request):
        all_blocks = LuluCoinBlock.objects.all()
        is_valid = True

        # Generating Hash for the Genesis block
        previous_block_hash = hashlib.sha256(config("GENESIS_HASH").encode()).hexdigest() + "....0000000001101"

        for block in all_blocks:
            if previous_block_hash != block.previous_block_hash:
                is_valid = False
                break
            
            block = Block(previous_block_hash, block.transactions.split(','))
            previous_block_hash = block.block_hash
            
        if is_valid:
            return Response({"data": "Block Chain Data Integrity is valid"}, status=status.HTTP_200_OK)
        else:
            return Response({"data": "Block Chain Data Integrity is invalid!"}, status=status.HTTP_409_CONFLICT)
