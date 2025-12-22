import requests
class ImapDataExtractorApiServices:
    def __init__(self):
        pass
    def send_into_api(self, api_url ,method = "POST",headers = None , body = None):
        try:
            response = requests.request(
                method=method,
                url=api_url,
                headers=headers,
                json=body,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Erreur API : {str(e)}")
imap_data_extractor_api_services = ImapDataExtractorApiServices()