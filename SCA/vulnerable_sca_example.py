import requests  # 2.19.0 – CVE-2018-18074
import yaml  # PyYAML 4.1 – CVE-2017-18342
import jwt  # PyJWT 1.7.1 – CVE-2022-29217

def get_data():
    r = requests.get("http://example.com")
    return yaml.load(r.text) 

# סתם להריץ שלא יהיה unused
if __name__ == "__main__":
    print(get_data())