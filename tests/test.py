import requests

def check_juiceshop():
    try:
        response = requests.get("http://localhost:3000")
        if response.status_code == 200:
            print("✅ Juice Shop is running!")
        else:
            print(f"⚠️ Juice Shop responded with status code: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("❌ Juice Shop is not running or not reachable.")

if __name__ == "__main__":
    check_juiceshop()