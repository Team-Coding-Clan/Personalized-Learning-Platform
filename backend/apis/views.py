from django.shortcuts import render
from .forms import connect, FeedbackForm
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView


from .serializers import MyTokenObtainPairSerializer, RegisterSerializer, UserSerializer, ProfileSerializer, \
    ConnectSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView

from django.contrib.auth.models import User
from rest_framework import generics, status

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAdminUser

from django.views.decorators.csrf import csrf_protect
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.http import JsonResponse
from rest_framework.status import (HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND,
                                   HTTP_409_CONFLICT, HTTP_511_NETWORK_AUTHENTICATION_REQUIRED)

from .helpers import youtube_api, google_books_api


# login
class MyObtainTokenPairView(TokenObtainPairView):
    permission_classes = (AllowAny,)
    serializer_class = MyTokenObtainPairSerializer


# register
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer


# logout
class APILogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        if self.request.data.get('all'):
            token: OutstandingToken
            for token in OutstandingToken.objects.filter(user = request.user):
                _, _ = BlacklistedToken.objects.get_or_create(token = token)
            return Response({"status": "OK, goodbye, all refresh tokens blacklisted"})
        refresh_token = self.request.data.get('refresh_token')
        token = RefreshToken(token = refresh_token)
        token.blacklist()
        return Response({"status": "OK, goodbye"})


# homepage
def home(request):
    return render(request, "homepage.html")


# recommendations : depricated
# def recommend(request):
#     return render(request, "recommendation.html")


class CreateConnectView(generics.CreateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ConnectSerializer

    # todo : serializer also has create and update
    # def post(self, request, format=None):
    #     serializer = ConnectSerializer(data=request.data)
    #     if serializer.is_valid():
    #         serializer.save()
    #         return Response(serializer.data, status=status.HTTP_201_CREATED)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateConnectView(generics.UpdateAPIView):
    queryset = connect.objects.all()
    serializer_class = ConnectSerializer
    permission_classes = (IsAuthenticated,)
    lookup_field = 'user_id_id'


class IsSuperUser(IsAdminUser):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_superuser)


class ListUsers(APIView):
    """
    View to list all users in the system.

    * Requires authentication.
    """
    permission_classes = (IsSuperUser,)

    def get(self, request, format = None):
        """
        Return particular user
        """
        data = User.objects.all()
        serializer_data = UserSerializer(data = data, many = True)
        serializer_data.is_valid()
        return Response(serializer_data.data)


class ProfileView(APIView):
    """
    View to list all users in the system.

    * Requires token authentication.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, format = None):
        """
        Return particular user
        """
        # print(request.user.pk)
        data = connect.objects.filter(user_id_id = request.user.pk)
        # print(data)
        serializer_data = ProfileSerializer(data = data, many = True)
        serializer_data.is_valid()
        return Response(serializer_data.data)


@csrf_protect
@api_view(['GET', ])
@permission_classes((IsAuthenticated,))
def get_recommendations(request):
    if request.method == 'GET':
        # try:
        print(request.user.id)
        user_profile = connect.objects.filter(user_id_id = request.user.id).get()
        print(user_profile)
        skills_to_learn = user_profile.skills_to_learn  # returns csvs
        print(skills_to_learn, type(skills_to_learn))
        print(list(map(str.strip, skills_to_learn.split(','))))
        skills_to_learn = list(map(str.strip, skills_to_learn.split(',')))
        known_skills = user_profile.known_skills  # returns a python list
        print(known_skills, type(known_skills))
        search_keys = ''

        for skill in skills_to_learn:
            youtube_api(skill)
            google_books_api(skill)
            # append in search key the returned url
        # for skill in known_skills:
        # youtube_api(skill)

        if not search_keys:
            return JsonResponse({'Status': 'No skills to learn'}, status = HTTP_200_OK)

        # call the APIs, this will go into the Task Scheduler
        result = []
        return JsonResponse({"Recommendations": result})

        # except Exception as e:
        #     return JsonResponse({'Status': 'Error Occurred'}, status = HTTP_400_BAD_REQUEST, safe = False)


class FeedbackFormView(FormView):
    template_name = "feedback/feedback.html"
    form_class = FeedbackForm
    success_url = "/success/"

    def form_valid(self, form):
        form.send_email()
        return super().form_valid(form)


class SuccessView(TemplateView):
    template_name = "feedback/success.html"
