from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken


from django.contrib.auth.models import User
from rest_framework import serializers
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.conf import settings

class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'password',
        ]

    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    token = serializers.CharField(read_only=True)

    def validate(self, data):
        username = data.get("username")
        password = data.get("password")

        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                if user.is_active:
                    data['user'] = user
                    return data
                else:
                    raise serializers.ValidationError("User is inactive.")

    def create(self, validated_data):
        user = validated_data['user']
        refresh = RefreshToken.for_user(user)
        return {
            'username': user.username,
            'token': str(refresh.access_token),
        }


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "email"]


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
        except Exception:
            raise serializers.ValidationError(
                "No user is associated with this email address.")
        return value

    def save(self):
        """
        token is used for generating random token which is also valid for limited time django inbuilt feature.
        encoding user id for security purpose.
        i dont have a mail server but i tried to fire this from my personal mail using app password but did not work so its not tested but on paper it works.
        """
        request = self.context.get('request')
        email = self.validated_data['email']
        user = User.objects.get(email=email)
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = request.build_absolute_uri(
            f'/password-reset-confirm/{uid}/{token}/')

        subject = "Password Reset"
        message = f"Hello {user.username},\n\nYou requested a password reset. Click the link below to reset your password:\n\n{reset_link}"
        send_mail(subject, message, settings.EMAIL_HOST_USER,
                [user.email], fail_silently=False)


class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField()
    token = serializers.CharField()

    def validate(self, values):
        try:
            uid = urlsafe_base64_decode(values['uidb64']).decode()
            user = User.objects.get(pk=uid)
        except (ValueError):
            raise serializers.ValidationError("Invalid token or ID.")

        if not default_token_generator.check_token(user, values['token']):
            raise serializers.ValidationError("Invalid token or user ID.")

        values['user'] = user
        return values

    def save(self):
        password = self.validated_data['new_password']
        user = self.validated_data['user']
        user.set_password(password)
        user.save()
