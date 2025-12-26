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
    def consult_oracle(text: str, is_hit: bool) -> str:
        """
        Generates sarcastic AI commentary based on the finding.
        """
        import random
        
        if not is_hit:
            safe_quips = [
                "Boring. Just a normal string.",
                "Nothing to see here. Move along.",
                "Clean. Disappointingly clean.",
                "Not an API. Just random noise.",
                "Yawn. 0% threat detected."
            ]
            return random.choice(safe_quips)
            
        common_api = re.search(r"(/api/|/v[0-9]/|/graphql|/internal/)", text, re.IGNORECASE)
        if common_api:
            standard_quips = [
                "Classic API pattern. Detecting... incompetency.",
                "Standard endpoint found. Too easy.",
                "I see /api/, I eat /api/.",
                "Boringly predictable API structure.",
                "Found it. It wasn't even hiding."
            ]
            return random.choice(standard_quips)
            
        # If it's a hit but not standard -> Shadow API!
        shadow_quips = [
            f"Ooh, '{text}'? That looks sneaky.",
            "Trying to hide this endpoint? Cute.",
            "Shadow API detected. Deploying sarcasm.",
            "This doesn't look like a public route. I like it.",
            "High entropy, weird path... definitely suspicious.",
            "Who names an endpoint like that? A hacker, that's who.",
            "I smell a hidden admin route. Delicious."
        ]
        return random.choice(shadow_quips)

    @staticmethod
    def _heuristic_check(text: str) -> bool:
        """
        Classic Heuristics (Regex/Keyword)
        """
        common_api = re.search(r"(/api/|/v[0-9]/|/graphql|/internal/)", text, re.IGNORECASE)
        if common_api: return True
        return False
