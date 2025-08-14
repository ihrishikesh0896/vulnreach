import sys, yaml
def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.load(f, Loader=yaml.FullLoader)
if __name__ == "__main__":
    infile = sys.argv[1] if len(sys.argv) > 1 else "data.yaml"
    data = load_config(infile)
    print("Loaded:", type(data).__name__)
