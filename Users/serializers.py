from rest_framework import serializers


class MALLoginResponseSerializer(serializers.Serializer):
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()
    token_expiry = serializers.DateTimeField()
