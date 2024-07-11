from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model


class EmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        try:
            user = UserModel.objects.get(email=username)
            print(f"User found: {user.email}")
        except UserModel.DoesNotExist:
            print("User does not exist.")
            return None
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                print("Password check passed.")
                return user
            print("Password check failed.")
        return None

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
