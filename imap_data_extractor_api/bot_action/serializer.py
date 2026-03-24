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
    sub_action = serializers.JSONField(required=False)  # Accepte n'importe quel JSON valide

    def validate(self, attrs):

        sub_act = attrs.get("sub_action")

        if sub_act:

            if not isinstance(sub_act, dict):
                raise serializers.ValidationError({
                    "sub_action": "sub_action doit être un objet JSON."
                })

            ser = BotActionSerializers(data=sub_act)
            ser.is_valid(raise_exception=True)

        return attrs
        
