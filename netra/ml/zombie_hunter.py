import pickle
import io
import re
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

class ZombieHunter:
    _model = None
    _heuristic_mode = False

    @classmethod
    def load_model(cls, minio_client):
        """
        Loads the zombie_model_v1.pkl from MinIO into memory.
        """
        if not minio_client:
            print("ZombieHunter: No MinIO client. Running in Heuristic Mode.")
            cls._heuristic_mode = True
            return

        try:
            if minio_client.bucket_exists("ml-models"):
                response = minio_client.get_object("ml-models", "zombie_model_v1.pkl")
                model_bytes = io.BytesIO(response.read())
                response.close()
                response.release_conn()
                
                cls._model = pickle.load(model_bytes)
                cls._heuristic_mode = False
                print("ZombieHunter: Loaded Neural Brain (zombie_model_v1.pkl).")
            else:
                print("ZombieHunter: Model bucket missing. Training needed.")
                cls._heuristic_mode = True
        except Exception as e:
            print(f"ZombieHunter Init Failed: {e}")
            cls._heuristic_mode = True

    @classmethod
    def predict_is_api(cls, text: str) -> bool:
        """
        Determines if a string looks like a hidden API endpoint.
        """
        # 1. Pre-filter: Must look remotely like a path
        if not text or len(text) < 4: return False
        if " " in text: return False # Paths usually don't have spaces
        if not "/" in text: return False # Must have a slash
        
        # 2. Heuristic Check (Fast Path or Fallback)
        # If Heuristic Mode or Model Missing, use classic Regex-ish logic
        if cls._heuristic_mode or cls._model is None:
            # Fallback to smart heuristics
            return cls._heuristic_check(text)

        # 3. Neural Check
        try:
            # Model expects a list of strings
            prediction = cls._model.predict([text])[0]
            if prediction == 1:
                return True
        except Exception:
            # If inference fails, fallback
            return cls._heuristic_check(text)
            
        return False

    @staticmethod
    def _heuristic_check(text: str) -> bool:
        """
        Classic Heuristics (Regex/Keyword)
        """
        common_api = re.search(r"(/api/|/v[0-9]/|/graphql|/internal/)", text, re.IGNORECASE)
        if common_api: return True
        return False
