import requests
import time

def generate_traffic(url, interval_seconds=1):
    while True:
        try:
            response = requests.get(url)
            # Vous pouvez traiter la réponse ici si nécessaire
            print(f"Requête envoyée. Code de réponse : {response.status_code}")
        except Exception as e:
            print(f"Erreur lors de l'envoi de la requête : {str(e)}")

        time.sleep(interval_seconds)

# Utilisation : Remplacez 'http://example.com' par l'URL de votre choix
generate_traffic('http://facebook.com')
