# import jwt
import uuid
# from datetime import datetime, timedelta
# from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin
)
# from rest_framework_simplejwt.tokens import RefreshToken
from django.db import models

class UserManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        """ Create and return a `User`. """

        if email is None:
            raise TypeError('Users must have an email address.')
        
        if not password:
            raise ValueError('The password must be set.')

        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save()

        return user

    def create_superuser(self, email, password, **extra_fields):
      """ Create and return a `User` with Admin role. """
      extra_fields.setdefault('role', 1)

      return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    ADMIN = 1
    TEACHER = 2
    STUDENT = 3

    ROLE_CHOICES = (
        (ADMIN, 'Admin'),
        (TEACHER, 'Teacher'),
        (STUDENT, 'Student')
    )
    
    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'

    uid = models.UUIDField(unique=True, editable=False, default=uuid.uuid4, verbose_name='Public identifier')
    email = models.EmailField(db_index=True, unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    role = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, blank=True, null=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email

    # @property
    # def token(self):
    #     return self._generate_jwt_token()

    def get_full_name(self):
      return f'{self.first_name} {self.last_name}'

    def get_short_name(self):
        return self.first_name

    # def _generate_jwt_token(self):
        """
        Generates a JSON Web Token that stores this user's ID and has an expiry
        date set to 60 days into the future.
        """
        # dt = datetime.now() + timedelta(days=60)

        # token = jwt.encode({
        #     'id': self.pk,
        #     'exp': int(dt.strftime('%s'))
        # }, settings.SECRET_KEY, algorithm='HS256')

        # return token.decode('utf-8')
        # refresh = RefreshToken.for_user(self)

        # return str(refresh.access_token)

