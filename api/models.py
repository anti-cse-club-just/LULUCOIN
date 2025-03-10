from django.db import models
from django.contrib.auth.models import User


class LuluCoinBlock(models.Model):
    block_hash = models.TextField()
    previous_block_hash = models.TextField()
    transactions = models.TextField()
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.block_hash
