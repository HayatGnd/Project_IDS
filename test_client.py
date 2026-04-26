"""
Interactive Console Client for SecureCorp API
"""

import requests
import json
import secrets

BASE_URL = "http://localhost:5000"

# Session globale
session = {
    "username": None,
    "tgt": None,
    "service_ticket": None
}


def print_header(title):
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)


def print_response(response):
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))


def login():
    print_header("LOGIN")
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    response = requests.post(f"{BASE_URL}/login", json={
        "username": username,
        "password": password
    })
    print_response(response)

    if response.status_code == 200:
        session["username"] = username
        session["tgt"] = response.json().get("tgt")
        print(" Login réussi ! TGT obtenu.")
    else:
        print(" Login échoué.")


def request_ticket():
    if not session["tgt"]:
        print(" Tu dois te connecter d'abord (option 1).")
        return

    print_header("DEMANDE DE TICKET")
    service = input("Service (défaut: resource-server): ").strip() or "resource-server"
    nonce = secrets.token_hex(16)

    response = requests.post(f"{BASE_URL}/request-ticket", json={
        "username": session["username"],
        "tgt": session["tgt"],
        "service": service,
        "nonce": nonce
    })
    print_response(response)

    if response.status_code == 200:
        session["service_ticket"] = response.json().get("service_ticket")
        print(" Service ticket obtenu.")
    else:
        print(" Demande de ticket échouée.")


def get_resource():
    if not session["service_ticket"]:
        print(" Tu dois obtenir un ticket d'abord (option 2).")
        return

    print_header("ACCÈS RESSOURCE")
    resource_id = input("ID de la ressource: ").strip()

    response = requests.get(
        f"{BASE_URL}/resource/{resource_id}",
        headers={"Authorization": f"Bearer {session['service_ticket']}"}
    )
    print_response(response)

    if response.status_code == 200:
        print(" Ressource accédée avec succès.")
    else:
        print(" Accès refusé.")


def create_resource():
    if not session["service_ticket"]:
        print(" Tu dois obtenir un ticket d'abord (option 2).")
        return

    print_header("CRÉER UNE RESSOURCE")
    name = input("Nom: ").strip()
    department = input("Département (IT, HR, Finance...): ").strip()
    classification = input("Classification (public, confidential, secret, top-secret): ").strip() or "public"
    access_location = input("Accès (any, internal_only): ").strip() or "any"
    content = input("Contenu: ").strip()

    response = requests.post(
        f"{BASE_URL}/resource",
        json={
            "name": name,
            "department": department,
            "classification": classification,
            "access_location": access_location,
            "content": content
        },
        headers={"Authorization": f"Bearer {session['service_ticket']}"}
    )
    print_response(response)

    if response.status_code == 201:
        print(" Ressource créée avec succès.")
    else:
        print(" Création échouée.")


def list_resources():
    if not session["service_ticket"]:
        print(" Tu dois obtenir un ticket d'abord (option 2).")
        return

    print_header("LISTE DES RESSOURCES")
    response = requests.get(
        f"{BASE_URL}/resources",
        headers={"Authorization": f"Bearer {session['service_ticket']}"}
    )
    print_response(response)

    if response.status_code == 200:
        resources = response.json().get("resources", [])
        print(f" {len(resources)} ressource(s) accessible(s).")
    else:
        print(" Impossible de lister les ressources.")


def delete_resource():
    if not session["service_ticket"]:
        print(" Tu dois obtenir un ticket d'abord (option 2).")
        return

    print_header("SUPPRIMER UNE RESSOURCE")
    resource_id = input("ID de la ressource à supprimer: ").strip()
    confirm = input(f"Confirmer la suppression de la ressource {resource_id} ? (oui/non): ").strip().lower()

    if confirm != "oui":
        print("Annulé.")
        return

    response = requests.delete(
        f"{BASE_URL}/resource/{resource_id}",
        headers={"Authorization": f"Bearer {session['service_ticket']}"}
    )
    print_response(response)

    if response.status_code == 200:
        print(" Ressource supprimée.")
    else:
        print(" Suppression échouée.")


def audit_report():
    print_header("RAPPORT D'AUDIT")
    response = requests.get(f"{BASE_URL}/audit-report")
    print_response(response)


def health_check():
    print_header("HEALTH CHECK")
    response = requests.get(f"{BASE_URL}/health")
    print_response(response)


def print_menu():
    print("\n" + "█"*60)
    print("  SecureCorp Zero-Trust — Menu Principal")
    print("█"*60)

    # Afficher l'état de la session
    if session["username"]:
        print(f"  👤 Connecté en tant que : {session['username']}")
        print(f"  🎫 Ticket : {'✅ Obtenu' if session['service_ticket'] else '❌ Non obtenu'}")
    else:
        print("  👤 Non connecté")

    print()
    print("  1. Login")
    print("  2. Demander un service ticket")
    print("  3. Accéder à une ressource")
    print("  4. Créer une ressource")
    print("  5. Lister les ressources")
    print("  6. Supprimer une ressource")
    print("  7. Rapport d'audit")
    print("  8. Health check")
    print("  0. Quitter")
    print()


def main():
    print("\n" + "█"*60)
    print("  Bienvenue dans SecureCorp Zero-Trust System")
    print("█"*60)

    actions = {
        "1": login,
        "2": request_ticket,
        "3": get_resource,
        "4": create_resource,
        "5": list_resources,
        "6": delete_resource,
        "7": audit_report,
        "8": health_check,
    }

    while True:
        print_menu()
        choix = input("Votre choix: ").strip()

        if choix == "0":
            print("\nAu revoir ! 👋")
            break
        elif choix in actions:
            try:
                actions[choix]()
            except requests.exceptions.ConnectionError:
                print(" Impossible de se connecter au serveur. Vérifiez que Flask tourne.")
            except Exception as e:
                print(f" Erreur inattendue: {str(e)}")
        else:
            print(" Choix invalide. Entrez un nombre entre 0 et 8.")


if __name__ == "__main__":
    main()