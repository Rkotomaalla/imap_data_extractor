from rest_framework import serializers

class TaskSerializer(serializers.Serializer):
    task_id =serializers.IntegerField(read_only = True)  
    id = serializers.CharField(read_only=True)
    bot_id = serializers.IntegerField(required = True)
    started_by = serializers.IntegerField(required=False, allow_null=True)
    ended_by = serializers.IntegerField(required=False, allow_null=True)
    started_at = serializers.DateTimeField(required=False, allow_null=True)
    ended_at = serializers.DateTimeField(required=False, allow_null=True)
