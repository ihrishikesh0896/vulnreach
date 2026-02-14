# PyYAML 5.3 + yaml.load FullLoader (CVE-2020-1747 pattern)

## Docker

This repository includes a Dockerfile to build a container image for the vulnerable test app.

Build the image:

```bash
# from the project root (where Dockerfile lives)
docker build -t python_vuln_app:latest .
```

Run the container (maps container port 8000 -> host port 5000):

```bash
# if port 5000 is already in use, change the left side (host port) to an available port
docker run --rm -p 5000:8000 python_vuln_app:latest
```

Then open http://127.0.0.1:5000/ in your browser or curl the /health endpoint:

```bash
curl http://127.0.0.1:5000/health
```
