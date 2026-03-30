from datetime import datetime
import os

class Logger:
    def __init__(self, filename="attacks.log"):
        # Garante que a pasta 'logs' existe
        self.log_dir = "logs"
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
        self.filepath = os.path.join(self.log_dir, filename)

    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        
        with open(self.filepath, "a") as f:
            f.write(entry + "\n")