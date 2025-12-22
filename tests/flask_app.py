from flask import Flask, Blueprint

app = Flask(__name__)

@app.route('/health')
def health():
    return 'ok'

@app.route('/items/<item_id>', methods=['GET', 'POST'])
def item(item_id):
    return item_id

bp = Blueprint('api', __name__, url_prefix='/api')

@bp.route('/status', methods=['GET'])
def status():
    return 'status'

app.register_blueprint(bp)

