from datetime import datetime
from pytz import timezone

def get_indian_time():
    india = timezone('Asia/Kolkata')
    return datetime.now(india)
