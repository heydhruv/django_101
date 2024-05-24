from rest_framework.permissions import BasePermission
from rest_framework.request import Request


class IsAuthenticatedUser(BasePermission):
    """
    Allows access only to authenticated users.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated

# not used as of now