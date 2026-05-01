from rest_framework import serializers
class ActionSerializer(serializers.Serializer):
    action_id = serializers.IntegerField(required=True)
    id = serializers.CharField(read_only=True)
    action_label = serializers.CharField(required=True)
    need_attachment = serializers.BooleanField(required=True)
    child_action = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        allow_empty = True
    )
    
class BotActionSerializers(serializers.Serializer):
    action_id = serializers.IntegerField(required=True)
    value = serializers.JSONField(required=False)

    def __init__(self, *args, **kwargs):
        # ✅ Flag pour éviter la récursion infinie
        is_child = kwargs.pop('_is_child', False)
        super().__init__(*args, **kwargs)
        
        if not is_child:
            self.fields['sub_action'] = BotActionSerializers(
                many=True, 
                required=False, 
                _is_child=True  # ✅ Le child ne recrée pas sub_action
            )