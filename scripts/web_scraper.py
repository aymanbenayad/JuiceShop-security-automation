import requests
from bs4 import BeautifulSoup
import re

url = "http://localhost:3000"

response = requests.get(url)

soup = BeautifulSoup(response.content, 'html.parser')

print(soup.prettify()[:1000])

scripts = soup.find_all('script')
for script in scripts:
    if script.string:
        print(script.string[:200])

hidden_inputs = soup.find_all('input', {'type': 'hidden'})
for inp in hidden_inputs:
    print(inp)

links = soup.find_all('a', href=True)
for link in links:
    if "javascript" in link['href'] or "#" in link['href']:
        print(link['href'])

emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", response.text)
print("Emails trouvés:", emails)

keys = re.findall(r"[a-f0-9]{32,64}", response.text)
print("Clés potentiellement exposées:", keys)