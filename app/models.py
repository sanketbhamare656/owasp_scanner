from . import db
from datetime import datetime

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    results = db.Column(db.Text, nullable=False)
    vulnerable = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<ScanResult {self.url} - {self.scan_date}>'