# BENCHMARK: secrets - github_personal_access_token
# WARNING: This file contains a fake token for benchmark testing only

import requests

token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
GITHUB_API = "https://api.github.com"


def list_repos(org):
    headers = {"Authorization": f"token {token}"}
    resp = requests.get(f"{GITHUB_API}/orgs/{org}/repos", headers=headers)
    return resp.json()
