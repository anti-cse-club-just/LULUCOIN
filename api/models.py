import hashlib
import json
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from ecdsa import SigningKey, SECP256k1



class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, username, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(unique=True)
    city = models.CharField(max_length=50)
    private_key = models.TextField()
    public_key = models.TextField()
    balance = models.IntegerField(default=0)
    # role = models.ForeignKey(Role, null=True, blank=True, on_delete=models.CASCADE)
    # profile_pic = models.TextField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)  # Regular user, not staff by default
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']


    def __str__(self):
        return self.username


# class Wallet(models.Model):
#     user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
#     private_key = models.TextField()
#     public_key = models.TextField()

#     def generate_keys(self):
#         private_key = SigningKey.generate(curve=SECP256k1)
#         self.private_key = private_key.to_string().hex()
#         self.public_key = private_key.verifying_key.to_string().hex()

#     def __str__(self):
#         return self.user


class GlobalVariables(models.Model):
    difficulty = models.IntegerField(default=6)
    mining_reward = models.FloatField(default=25)
    fees = models.FloatField(default=0.02)
    # max_block_size = models.IntegerField(default=10)

    def __str__(self):
        return f"Difficulty: {self.difficulty}"


class LuluCoinBlock(models.Model):
    block_hash = models.TextField()
    previous_block_hash = models.TextField()
    transactions = models.TextField()
    timestamp = models.IntegerField(default=0)
    nonce = models.IntegerField(default=0)
    difficulty = models.IntegerField(default=4)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    block_reward = models.FloatField()
    submission_time = models.DateTimeField(auto_now=True)
    is_pending = models.BooleanField(default=True)
    is_valid = models.BooleanField(default=False)


    def generate_hash(self):
        self.merkle_hash = hashlib.sha256(self.transactions.replace(",", "-").encode()).hexdigest()
        self.header = self.previous_block_hash + self.merkle_hash + str(self.timestamp) + str(self.nonce)
        self.block_hash = hashlib.sha256(self.header.encode()).hexdigest()

    def validate(self):
        self.generate_hash()
        if self.block_hash == self.block_hash:
            return True
        


    def __str__(self):
        return self.block_hash


class Transaction(models.Model):
    sender = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="sender")
    receiver = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="receiver")
    amount = models.FloatField()
    fees = models.FloatField()
    signature = models.TextField()
    timestamp = models.DateTimeField(auto_now=True)
    is_pending = models.BooleanField(default=True)

    def sign_transaction(self, private_key):
            transaction_dict = {
                "sender": self.sender.username,
                "receiver": self.receiver.username,
                "amount": self.amount + self.fees
            }
            transaction_string = json.dumps(transaction_dict, sort_keys=True).encode()
            private_key = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
            self.signature = private_key.sign(transaction_string).hex()


    def is_valid(self):
        if self.sender == "Genesis":
            return True
        try:
            public_key = SigningKey.from_string(bytes.fromhex(self.sender), curve=SECP256k1).verifying_key
            transaction_dict = {
                "sender": self.sender,
                "receiver": self.receiver,
                "amount": self.amount
            }
            transaction_string = json.dumps(transaction_dict, sort_keys=True).encode()
            return public_key.verify(bytes.fromhex(self.signature), transaction_string)
        except:
            return False


    def __str__(self):
        return self.signature