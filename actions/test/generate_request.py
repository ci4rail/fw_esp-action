#!/usr/bin/python3
import sys
import json

if len(sys.argv) != 8:
    print(f"Usage: {sys.argv[0]} pipeline repo_owner repo artifact_id artifact_name artifact_revision")
    sys.exit(1)

pipeline,repo_owner,repo,artifact_id,artifact_name,artifact_revision = sys.argv[1:8]

req = {
  "type": "Run Test",
  "user": pipeline,
  "github_artifact": {
    "owner": repo_owner,
    "repo": repo,
    "artifact_id": artifact_id,
    "name": artifact_name,
    "revision": artifact_revision
  }
}

print(json.dumps(req))


