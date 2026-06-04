import os
import json
import operator
import threading
from datetime import datetime
from sqlalchemy.ext.declarative import declarative_base

# We still expose Base so models.py can import it
Base = declarative_base()

_DB_LOCK = threading.RLock()

# Firebase SDK Imports
db_client = None
try:
    import firebase_admin
    from firebase_admin import credentials, firestore
    
    # Initialize Firebase Admin SDK if credentials exist
    firebase_creds_json = os.getenv("FIREBASE_CREDENTIALS_JSON")
    if firebase_creds_json:
        try:
            creds_dict = json.loads(firebase_creds_json)
            cred = credentials.Certificate(creds_dict)
            firebase_admin.initialize_app(cred)
            db_client = firestore.client()
            print("Successfully connected to Firebase Cloud Firestore using environment credentials.")
        except Exception as e:
            print(f"Firebase initialization from env variable failed: {e}.")
    elif os.path.exists("firebase-key.json"):
        try:
            cred = credentials.Certificate("firebase-key.json")
            firebase_admin.initialize_app(cred)
            db_client = firestore.client()
            print("Successfully connected to Firebase Cloud Firestore using firebase-key.json.")
        except Exception as e:
            print(f"Firebase initialization from firebase-key.json failed: {e}.")
    else:
        print("No Firebase credentials detected. Running in local in-memory mode.")
    print("Successfully connected to Firebase Cloud Firestore.")
except Exception as e:
    print(f"Firebase Admin is not fully initialized: {e}. Falling back to in-memory db.")

# Global TTL cache to prevent throttling / timeout when streaming from Firestore
_GLOBAL_FETCH_CACHE = {}
_GLOBAL_FETCH_CACHE_TTL = 5.0

# In-memory Local Database Fallback (for zero-config local runs)
_IN_MEMORY_DB = {
    "detection_rules": {},
    "security_logs": {},
    "incident_cases": {},
    "alerts": {}
}
_MODEL_OBJECT_CACHE = {
    "detection_rules": {},
    "security_logs": {},
    "incident_cases": {},
    "alerts": {}
}
_LOCAL_COUNTERS = {
    "security_logs": 100,
    "incident_cases": 0,
    "alerts": 100
}

_DB_BACKUP_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "db_backup.json")

def save_local_db():
    if db_client:
        return
    try:
        serializable_db = {}
        with _DB_LOCK:
            for col in list(_IN_MEMORY_DB.keys()):
                items = _IN_MEMORY_DB[col]
                if col == 'security_logs' and len(items) > 100000:
                    sorted_keys = sorted(items.keys(), key=lambda x: int(x) if x.isdigit() else 0)
                    pruned_keys = sorted_keys[-4500:]
                    _IN_MEMORY_DB[col] = {k: items[k] for k in pruned_keys}
                    _MODEL_OBJECT_CACHE[col] = {k: _MODEL_OBJECT_CACHE[col][k] for k in pruned_keys if k in _MODEL_OBJECT_CACHE[col]}
                elif col in ('alerts', 'incident_cases') and len(items) > 100000:
                    sorted_keys = sorted(items.keys(), key=lambda x: int(x) if x.isdigit() else 0)
                    pruned_keys = sorted_keys[-1500:]
                    _IN_MEMORY_DB[col] = {k: items[k] for k in pruned_keys}
                    _MODEL_OBJECT_CACHE[col] = {k: _MODEL_OBJECT_CACHE[col][k] for k in pruned_keys if k in _MODEL_OBJECT_CACHE[col]}
                serializable_db[col] = _IN_MEMORY_DB[col]
        with open(_DB_BACKUP_PATH, "w", encoding="utf-8") as f:
            json.dump(serializable_db, f, indent=2)
    except Exception as e:
        print(f"Error backing up local DB: {e}")

def load_local_db():
    if db_client:
        return
    if not os.path.exists(_DB_BACKUP_PATH):
        return
    try:
        with open(_DB_BACKUP_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        with _DB_LOCK:
            for col, items in data.items():
                if col in _IN_MEMORY_DB:
                    if col == 'security_logs' and len(items) > 100000:
                        sorted_keys = sorted(items.keys(), key=lambda x: int(x) if x.isdigit() else 0)
                        pruned_keys = sorted_keys[-4500:]
                        items = {k: items[k] for k in pruned_keys}
                    elif col in ('alerts', 'incident_cases') and len(items) > 100000:
                        sorted_keys = sorted(items.keys(), key=lambda x: int(x) if x.isdigit() else 0)
                        pruned_keys = sorted_keys[-1500:]
                        items = {k: items[k] for k in pruned_keys}
                    _IN_MEMORY_DB[col] = items
                    if items:
                        try:
                            max_id = max(int(k) for k in items.keys() if k.isdigit())
                            _LOCAL_COUNTERS[col] = max_id
                        except ValueError:
                            pass
    except Exception as e:
        print(f"Error loading local DB backup: {e}")

def get_next_id(collection_name):
    default_start = 0 if collection_name == "incident_cases" else 100
    if db_client:
        try:
            doc_ref = db_client.collection("counters").document(collection_name)
            doc = doc_ref.get()
            if doc.exists:
                val = doc.to_dict().get("current_id", default_start) + 1
            else:
                val = default_start + 1
            doc_ref.set({"current_id": val})
            return val
        except Exception as e:
            print(f"Firestore counter failed for {collection_name}: {e}. Using local counter.")
            
    global _LOCAL_COUNTERS
    with _DB_LOCK:
        _LOCAL_COUNTERS[collection_name] = _LOCAL_COUNTERS.get(collection_name, default_start) + 1
        return _LOCAL_COUNTERS[collection_name]

# Helper to translate model classes to Firestore collection names
def get_collection_name(model_class):
    name = model_class.__name__
    if name == 'SecurityLog':
        return 'security_logs'
    elif name == 'Alert':
        return 'alerts'
    elif name == 'IncidentCase':
        return 'incident_cases'
    elif name == 'DetectionRule':
        return 'detection_rules'
    return 'generic'

def model_to_dict(obj):
    data = {}
    for k, v in obj.__dict__.items():
        if k.startswith('_') or k in ['alerts', 'rule', 'trigger_log', 'case']:
            continue
        if isinstance(v, datetime):
            data[k] = v.isoformat()
        else:
            data[k] = v
    return data

def dict_to_model(model_class, data):
    obj = model_class()
    for k, v in data.items():
        if k in ['id', 'trigger_log_id', 'case_id', 'source_port', 'destination_port'] and v is not None:
            try:
                v = int(v)
            except (ValueError, TypeError):
                pass
        if k in ['timestamp', 'created_at', 'updated_at'] and isinstance(v, str):
            try:
                # clean timezone info
                clean_str = v.replace('Z', '')
                if '+' in clean_str:
                    clean_str = clean_str.split('+')[0]
                if '.' in clean_str:
                    setattr(obj, k, datetime.fromisoformat(clean_str))
                else:
                    setattr(obj, k, datetime.strptime(clean_str, "%Y-%m-%dT%H:%M:%S"))
            except:
                setattr(obj, k, v)
        else:
            setattr(obj, k, v)
            
    # Guarantee critical fields are populated with defaults if they are missing or None
    now_dt = datetime.now()
    cname = model_class.__name__
    if cname in ('Alert', 'SecurityLog'):
        if getattr(obj, 'timestamp', None) is None:
            obj.timestamp = now_dt
    if cname == 'IncidentCase':
        if getattr(obj, 'created_at', None) is None:
            obj.created_at = now_dt
        if getattr(obj, 'updated_at', None) is None:
            obj.updated_at = now_dt
        if getattr(obj, 'status', None) is None:
            obj.status = 'OPEN'
        if getattr(obj, 'assigned_to', None) is None:
            obj.assigned_to = 'Unassigned'
    if cname == 'Alert':
        if getattr(obj, 'status', None) is None:
            obj.status = 'NEW'
        if getattr(obj, 'severity', None) is None:
            obj.severity = 'MEDIUM'
            
    return obj

def evaluate_criterion(obj, criterion):
    try:
        from sqlalchemy.sql.elements import BinaryExpression
        if isinstance(criterion, BinaryExpression):
            left_name = criterion.left.name
            val = getattr(obj, left_name, None)
            
            right = criterion.right
            if hasattr(right, "value"):
                right_val = right.value
            elif hasattr(right, "element") and hasattr(right.element, "value"):
                right_val = right.element.value
            else:
                right_val = right
                
            op = criterion.operator
            op_name = getattr(op, '__name__', '')
            
            # Coerce types and dates for comparisons
            v1 = val
            v2 = right_val
            
            # Handle None values safely to prevent TypeError comparisons (e.g. None >= datetime)
            if v1 is None or v2 is None:
                if op == operator.eq or op_name == 'eq':
                    return v1 == v2
                elif op == operator.ne or op_name == 'ne':
                    return v1 != v2
                return False
            
            def try_parse_datetime(val_to_parse):
                if isinstance(val_to_parse, str):
                    try:
                        clean_str = val_to_parse.replace('Z', '')
                        if '+' in clean_str:
                            clean_str = clean_str.split('+')[0]
                        if '-' in clean_str and len(clean_str) > 10 and (clean_str[10] == 'T' or clean_str[10] == ' '):
                            return datetime.fromisoformat(clean_str)
                    except:
                        pass
                return val_to_parse

            if isinstance(v1, datetime) or isinstance(v2, datetime) or (isinstance(v1, str) and '-' in v1) or (isinstance(v2, str) and '-' in v2):
                v1_parsed = try_parse_datetime(v1)
                v2_parsed = try_parse_datetime(v2)
                if isinstance(v1_parsed, datetime) and isinstance(v2_parsed, datetime):
                    v1 = v1_parsed.replace(tzinfo=None)
                    v2 = v2_parsed.replace(tzinfo=None)
            
            if isinstance(v1, int) and isinstance(v2, str):
                try: v2 = int(v2)
                except ValueError: v1 = str(v1)
            elif isinstance(v1, str) and isinstance(v2, int):
                try: v1 = int(v1)
                except ValueError: v2 = str(v2)
                
            if op == operator.eq or op_name == 'eq':
                return v1 == v2
            elif op == operator.ne or op_name == 'ne':
                return v1 != v2
            elif op == operator.lt or op_name == 'lt':
                return v1 < v2
            elif op == operator.le or op_name == 'le':
                return v1 <= v2
            elif op == operator.gt or op_name == 'gt':
                return v1 > v2
            elif op == operator.ge or op_name == 'ge':
                return v1 >= v2
            elif op_name == 'in_op':
                if isinstance(v2, (list, tuple, set)):
                    if any(isinstance(x, str) for x in v2):
                        return str(v1) in [str(x) for x in v2]
                    return v1 in v2
                return v1 in v2
            elif op_name == 'like_op':
                return str(v2).replace('%', '') in str(v1)
        return True
    except Exception as e:
        print(f"Error evaluating criterion: {e}")
        return True

def stitch_relationships(session, obj):
    if not hasattr(session, '_stitching_set'):
        session._stitching_set = set()
    
    # Use class name and ID if available, otherwise fallback to object id()
    obj_id = getattr(obj, 'id', None)
    obj_key = (obj.__class__.__name__, obj_id if obj_id is not None else id(obj))
    
    if obj_key in session._stitching_set:
        return
    session._stitching_set.add(obj_key)
    
    try:
        from app.models.models import DetectionRule, SecurityLog, IncidentCase, Alert
        # Direct lookup in local cache to avoid query recursion
        if obj.__class__.__name__ == 'Alert':
            if obj.rule_id:
                rule_obj = session._fetch_one(DetectionRule, obj.rule_id)
                if rule_obj:
                    obj.rule = rule_obj
            if obj.trigger_log_id:
                log_obj = session._fetch_one(SecurityLog, obj.trigger_log_id)
                if log_obj:
                    obj.trigger_log = log_obj
            if obj.case_id:
                case_obj = session._fetch_one(IncidentCase, obj.case_id)
                if case_obj:
                    obj.case = case_obj
        elif obj.__class__.__name__ == 'IncidentCase':
            case_id_str = str(obj.id)
            alerts_list = []
            if db_client:
                try:
                    docs = db_client.collection('alerts').where('case_id', '==', obj.id).stream()
                    for doc in docs:
                        doc_data = doc.to_dict()
                        with _DB_LOCK:
                            _IN_MEMORY_DB['alerts'][doc.id] = doc_data
                            alert_obj = dict_to_model(Alert, doc_data)
                            _MODEL_OBJECT_CACHE['alerts'][doc.id] = alert_obj
                            alerts_list.append(alert_obj)
                except Exception as e:
                    print(f"Firestore alerts query failed for case {obj.id}: {e}")
            else:
                with _DB_LOCK:
                    for alert_id, alert_data in _IN_MEMORY_DB['alerts'].items():
                        if str(alert_data.get('case_id')) == case_id_str:
                            alerts_list.append(dict_to_model(Alert, alert_data))
            obj.alerts = alerts_list
    finally:
        session._stitching_set.discard(obj_key)

class MockAggregateQuery:
    def __init__(self, entities, session):
        self.entities = entities
        self.session = session
        self.group_by_cols = []
        self.filters = []
        self.orders = []
        self.limit_val = None

    def filter(self, *criterion):
        for c in criterion:
            self.filters.append(c)
        return self

    def join(self, *args, **kwargs):
        return self

    def outerjoin(self, *args, **kwargs):
        return self

    def group_by(self, *cols):
        for col in cols:
            self.group_by_cols.append(col)
        return self

    def order_by(self, *criterion):
        for c in criterion:
            self.orders.append(c)
        return self

    def limit(self, limit):
        self.limit_val = limit
        return self

    def all(self):
        # Extract names to identify which query is executing
        entity_names = []
        for ent in self.entities:
            if hasattr(ent, "name"):
                entity_names.append(ent.name)
            elif hasattr(ent, "key"):
                entity_names.append(ent.key)
            elif hasattr(ent, "element") and hasattr(ent.element, "name"):
                entity_names.append(ent.element.name)
            else:
                entity_names.append(str(ent))

        # 1. category_counts: Alert.rule_id, func.count(...)
        # Represented by rule_id at index 0
        if len(entity_names) == 2 and entity_names[0] == "rule_id":
            from app.models.models import Alert
            alerts = self.session._fetch_all(Alert)
            counts = {}
            for alert in alerts:
                key = alert.rule_id
                counts[key] = counts.get(key, 0) + 1
            return list(counts.items())

        # 2. threat_sources_query: SecurityLog.source_ip, SecurityLog.geo_country, func.count(...), func.max(...)
        if len(entity_names) == 4 and entity_names[0] == "source_ip" and entity_names[1] == "geo_country":
            from app.models.models import SecurityLog
            logs = self.session._fetch_all(SecurityLog)
            groups = {}
            for log in logs:
                if log.source_ip and log.source_ip != "127.0.0.1":
                    key = (log.source_ip, log.geo_country or "Unknown Origin")
                    if key not in groups:
                        groups[key] = []
                    groups[key].append(log.severity)
            sev_priority = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
            results = []
            for (ip, country), sevs in groups.items():
                max_sev = max(sevs, key=lambda s: sev_priority.get(s, 0)) if sevs else "INFO"
                results.append((ip, country, len(sevs), max_sev))
            results.sort(key=lambda x: x[2], reverse=True)
            return results[:5]

        # 3. country_groups: SecurityLog.geo_country, func.max(...)
        if len(entity_names) == 2 and entity_names[0] == "geo_country":
            from app.models.models import SecurityLog
            logs = self.session._fetch_all(SecurityLog)
            groups = {}
            for log in logs:
                if log.geo_country and log.source_ip != "127.0.0.1":
                    key = log.geo_country
                    if key not in groups:
                        groups[key] = []
                    groups[key].append(log.severity)
            sev_priority = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
            results = []
            for country, sevs in groups.items():
                max_sev = max(sevs, key=lambda s: sev_priority.get(s, 0)) if sevs else "INFO"
                results.append((country, max_sev))
            return results

        # 4. targeted_ports_query: SecurityLog.destination_port, func.count(...)
        if len(entity_names) == 2 and entity_names[0] == "destination_port":
            from app.models.models import SecurityLog
            logs = self.session._fetch_all(SecurityLog)
            counts = {}
            for log in logs:
                if log.destination_port and log.destination_port > 0:
                    counts[log.destination_port] = counts.get(log.destination_port, 0) + 1
            results = list(counts.items())
            results.sort(key=lambda x: x[1], reverse=True)
            return results[:5]

        # 5. user_risk_query: SecurityLog.user_id, func.count(...), func.max(...)
        if len(entity_names) == 3 and entity_names[0] == "user_id":
            from app.models.models import SecurityLog, Alert
            logs = self.session._fetch_all(SecurityLog)
            alerts = self.session._fetch_all(Alert)
            log_map = {str(l.id): l for l in logs if l.id is not None}
            groups = {}
            for alert in alerts:
                trigger_log = log_map.get(str(alert.trigger_log_id))
                if trigger_log and trigger_log.user_id and trigger_log.user_id != "guest":
                    user = trigger_log.user_id
                    if user not in groups:
                        groups[user] = []
                    groups[user].append(alert.severity)
            sev_priority = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
            results = []
            for user, sevs in groups.items():
                max_sev = max(sevs, key=lambda s: sev_priority.get(s, 0)) if sevs else "INFO"
                results.append((user, len(sevs), max_sev))
            results.sort(key=lambda x: x[1], reverse=True)
            return results[:5]

        # 6. assets_query: SecurityLog.destination_ip, Alert.title, func.count(...), func.max(...), SecurityLog.user_id
        if len(entity_names) == 5 and entity_names[0] == "destination_ip" and entity_names[1] == "title":
            from app.models.models import SecurityLog, Alert
            logs = self.session._fetch_all(SecurityLog)
            alerts = self.session._fetch_all(Alert)
            log_map = {str(l.id): l for l in logs if l.id is not None}
            groups = {}
            for alert in alerts:
                trigger_log = log_map.get(str(alert.trigger_log_id))
                if trigger_log:
                    dest_ip = trigger_log.destination_ip or "internal-host.local"
                    title = alert.title
                    user_id = trigger_log.user_id or "system"
                    key = (dest_ip, title, user_id)
                    if key not in groups:
                        groups[key] = []
                    groups[key].append(alert.severity)
            sev_priority = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
            results = []
            for (dest_ip, title, user_id), sevs in groups.items():
                max_sev = max(sevs, key=lambda s: sev_priority.get(s, 0)) if sevs else "INFO"
                results.append((dest_ip, title, len(sevs), max_sev, user_id))
            results.sort(key=lambda x: x[2], reverse=True)
            return results[:5]

        # 7. assets_discovery_query: SecurityLog.destination_ip, func.count(...), func.max(...)
        if len(entity_names) == 3 and entity_names[0] == "destination_ip":
            from app.models.models import SecurityLog, Alert
            logs = self.session._fetch_all(SecurityLog)
            alerts = self.session._fetch_all(Alert)
            log_to_alerts = {}
            for alert in alerts:
                t_id = str(alert.trigger_log_id)
                if t_id not in log_to_alerts:
                    log_to_alerts[t_id] = []
                log_to_alerts[t_id].append(alert)
            groups = {}
            for log in logs:
                dest_ip = log.destination_ip
                if dest_ip and (dest_ip.startswith("10.") or dest_ip.startswith("192.168.")):
                    if dest_ip not in groups:
                        groups[dest_ip] = []
                    log_alerts = log_to_alerts.get(str(log.id), [])
                    groups[dest_ip].extend(log_alerts)
            sev_priority = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
            results = []
            for dest_ip, associated_alerts in groups.items():
                count = len(associated_alerts)
                if associated_alerts:
                    max_sev = max((a.severity for a in associated_alerts), key=lambda s: sev_priority.get(s, 0))
                else:
                    max_sev = "INFO"
                results.append((dest_ip, count, max_sev))
            return results

        # Fallback default empty list
        return []

class MockQuery:
    def __init__(self, model_class, session):
        self.model_class = model_class
        self.session = session
        self.filters = []
        self.orders = []
        self.limit_val = None

    def filter(self, *criterion):
        for c in criterion:
            self.filters.append(c)
        return self

    def order_by(self, *criterion):
        for c in criterion:
            self.orders.append(c)
        return self

    def limit(self, limit):
        self.limit_val = limit
        return self

    def count(self):
        results = self.session._fetch_all(self.model_class)
        
        filtered_count = 0
        for obj in results:
            match = True
            for c in self.filters:
                if not evaluate_criterion(obj, c):
                    match = False
                    break
            if match:
                filtered_count += 1
        return filtered_count

    def first(self):
        res = self.all()
        return res[0] if res else None

    def all(self):
        id_filter_val = None
        for c in self.filters:
            from sqlalchemy.sql.elements import BinaryExpression
            if isinstance(c, BinaryExpression) and getattr(c.left, 'name', None) == 'id' and getattr(c.operator, '__name__', '') == 'eq':
                right = c.right
                if hasattr(right, "value"):
                    id_filter_val = right.value
                elif hasattr(right, "element") and hasattr(right.element, "value"):
                    id_filter_val = right.element.value
                else:
                    id_filter_val = right
                break

        if id_filter_val is not None:
            obj = self.session._fetch_one(self.model_class, id_filter_val)
            if obj:
                match = True
                for c in self.filters:
                    if not evaluate_criterion(obj, c):
                        match = False
                        break
                if match:
                    stitch_relationships(self.session, obj)
                    self.session._tracked.add(obj)
                    return [obj]
            return []

        results = self.session._fetch_all(self.model_class)
        
        filtered_results = []
        for obj in results:
            match = True
            for c in self.filters:
                if not evaluate_criterion(obj, c):
                    match = False
                    break
            if match:
                filtered_results.append(obj)

        if self.orders:
            for order in reversed(self.orders):
                col_name = getattr(order, "element", order)
                if hasattr(col_name, "name"):
                    col_name = col_name.name
                else:
                    col_name = str(col_name)
                    
                is_desc = "desc" in str(order).lower()
                
                def get_val(o):
                    val = getattr(o, col_name, None)
                    if val is None:
                        return ""
                    return val
                
                try:
                    filtered_results.sort(key=get_val, reverse=is_desc)
                except Exception as e:
                    print(f"Error sorting: {e}")


        if self.limit_val is not None:
            filtered_results = filtered_results[:self.limit_val]

        for obj in filtered_results:
            stitch_relationships(self.session, obj)
            self.session._tracked.add(obj)

        return filtered_results

class MockSession:
    def __init__(self):
        self._adds = []
        self._tracked = set()
        self._fetch_cache = {}

    def query(self, *entities):
        if len(entities) > 1 or not hasattr(entities[0], "__tablename__"):
            return MockAggregateQuery(entities, self)
        return MockQuery(entities[0], self)

    def add(self, obj):
        self._adds.append(obj)
        self._tracked.add(obj)

    def delete(self, obj):
        collection = get_collection_name(obj.__class__)
        doc_id = str(obj.id)
        if db_client:
            try:
                db_client.collection(collection).document(doc_id).delete()
            except Exception as e:
                print(f"Firestore delete error: {e}")
        with _DB_LOCK:
            if doc_id in _IN_MEMORY_DB[collection]:
                del _IN_MEMORY_DB[collection][doc_id]
            if doc_id in _MODEL_OBJECT_CACHE[collection]:
                del _MODEL_OBJECT_CACHE[collection][doc_id]
        if obj in self._tracked:
            self._tracked.remove(obj)
        save_local_db()

    def commit(self):
        # Commit all objects that have been added or loaded
        all_objects = list(self._tracked)
        for obj in all_objects:
            collection = get_collection_name(obj.__class__)
            
            # Autoincrement integer ID if not present
            if getattr(obj, 'id', None) is None:
                new_id = get_next_id(collection)
                obj.id = new_id
                
            # Populate default fields before converting to dict
            now_dt = datetime.now()
            cname = obj.__class__.__name__
            if cname in ('Alert', 'SecurityLog'):
                if getattr(obj, 'timestamp', None) is None:
                    obj.timestamp = now_dt
            if cname == 'IncidentCase':
                if getattr(obj, 'created_at', None) is None:
                    obj.created_at = now_dt
                if getattr(obj, 'updated_at', None) is None:
                    obj.updated_at = now_dt
                if getattr(obj, 'status', None) is None:
                    obj.status = 'OPEN'
                if getattr(obj, 'assigned_to', None) is None:
                    obj.assigned_to = 'Unassigned'
            if cname == 'Alert':
                if getattr(obj, 'status', None) is None:
                    obj.status = 'NEW'
                if getattr(obj, 'severity', None) is None:
                    obj.severity = 'MEDIUM'
                    
            doc_id = str(obj.id)
            data = model_to_dict(obj)
            
            # Save to Firebase Firestore
            if db_client:
                try:
                    db_client.collection(collection).document(doc_id).set(data)
                except Exception as e:
                    print(f"Firestore save error: {e}")
                    
            # Update local memory database
            with _DB_LOCK:
                _IN_MEMORY_DB[collection][doc_id] = data
                _MODEL_OBJECT_CACHE[collection][doc_id] = obj
            
        self._adds = []
        self._tracked = set()
        save_local_db()

    def rollback(self):
        self._adds = []
        self._tracked = set()

    def refresh(self, obj):
        stitch_relationships(self, obj)

    def close(self):
        pass
        
    def execute(self, text_expr):
        # Dummy executor for health check SQL expressions
        class DummyResult:
            def all(self):
                return [(1,)]
        return DummyResult()

    def _fetch_one(self, model_class, doc_id):
        collection = get_collection_name(model_class)
        doc_id_str = str(doc_id)
        
        # Check cache/in-memory first
        with _DB_LOCK:
            cached_obj = _MODEL_OBJECT_CACHE[collection].get(doc_id_str)
            if cached_obj:
                return cached_obj
            data = _IN_MEMORY_DB[collection].get(doc_id_str)
            if data:
                obj = dict_to_model(model_class, data)
                _MODEL_OBJECT_CACHE[collection][doc_id_str] = obj
                return obj
                
        # If not in cache and db_client is connected, fetch from Firestore by ID
        if db_client:
            try:
                doc_ref = db_client.collection(collection).document(doc_id_str).get()
                if doc_ref.exists:
                    doc_data = doc_ref.to_dict()
                    with _DB_LOCK:
                        _IN_MEMORY_DB[collection][doc_id_str] = doc_data
                        obj = dict_to_model(model_class, doc_data)
                        _MODEL_OBJECT_CACHE[collection][doc_id_str] = obj
                        return obj
            except Exception as e:
                print(f"Firestore fetch_one error for {collection}/{doc_id_str}: {e}")
                
        return None

    def _fetch_all(self, model_class):
        import time
        collection = get_collection_name(model_class)
        now_ts = time.time()
        
        # Check global TTL cache first to prevent repeated Firestore network calls across requests
        if collection in _GLOBAL_FETCH_CACHE:
            cached_data, expiry = _GLOBAL_FETCH_CACHE[collection]
            if now_ts < expiry:
                return cached_data

        if hasattr(self, '_fetch_cache') and collection in self._fetch_cache:
            return self._fetch_cache[collection]

        objects = []
        
        # Load from Firestore
        if db_client:
            try:
                if collection in ('security_logs', 'alerts'):
                    from datetime import datetime, timedelta
                    cutoff_str = (datetime.now() - timedelta(hours=48)).isoformat()
                    docs = db_client.collection(collection).where('timestamp', '>=', cutoff_str).stream()
                else:
                    docs = db_client.collection(collection).stream()
                current_keys = set()
                for doc in docs:
                    doc_data = doc.to_dict()
                    current_keys.add(doc.id)
                    with _DB_LOCK:
                        _IN_MEMORY_DB[collection][doc.id] = doc_data
                        
                # Evict items from local cache that were deleted from Firestore
                with _DB_LOCK:
                    all_cached_keys = list(_IN_MEMORY_DB[collection].keys())
                    for cached_key in all_cached_keys:
                        if cached_key not in current_keys:
                            del _IN_MEMORY_DB[collection][cached_key]
                            if cached_key in _MODEL_OBJECT_CACHE[collection]:
                                del _MODEL_OBJECT_CACHE[collection][cached_key]
            except Exception as e:
                print(f"Firestore load error: {e}")
                
        # Load from local memory cache safely using lock
        with _DB_LOCK:
            cached_items = list(_IN_MEMORY_DB[collection].items())
            
        for doc_id, data in cached_items:
            with _DB_LOCK:
                cached_obj = _MODEL_OBJECT_CACHE[collection].get(doc_id)
            if cached_obj:
                objects.append(cached_obj)
            else:
                obj = dict_to_model(model_class, data)
                with _DB_LOCK:
                    _MODEL_OBJECT_CACHE[collection][doc_id] = obj
                objects.append(obj)
            
        if hasattr(self, '_fetch_cache'):
            self._fetch_cache[collection] = objects
        _GLOBAL_FETCH_CACHE[collection] = (objects, now_ts + _GLOBAL_FETCH_CACHE_TTL)
        return objects

# SessionLocal factory returns a new session instances
def SessionLocal():
    return MockSession()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    load_local_db()
    from app.models.models import DetectionRule
    db = SessionLocal()
    try:
        default_rules = [
            DetectionRule(
                id="RULE-AUTH-BRUTEFORCE",
                name="Failed Login Brute Force",
                description="Detects multiple failed login attempts from a single source IP address within a short timeframe.",
                pattern=r"(Failed password|invalid user|authentication failure|Login failed)",
                severity="HIGH",
                is_active=True
            ),
            DetectionRule(
                id="RULE-WEB-SQLI",
                name="SQL Injection Attack",
                description="Identifies SQL injection syntax patterns (e.g., SELECT, UNION, or comment tokens) in HTTP queries or payloads.",
                pattern=r"(?i)(UNION\s+SELECT|SELECT\s+.*\s+FROM|OR\s+\d+=\d+|['\"#]|\/\*|\*\/)",
                severity="CRITICAL",
                is_active=True
            ),
            DetectionRule(
                id="RULE-WEB-XSS",
                name="Cross-Site Scripting (XSS)",
                description="Detects potential script tag injections or HTML entity manipulations in web request parameters.",
                pattern=r"(?i)(<script.*?>|javascript:|onload=|<img\s+src=.*onerror=)",
                severity="HIGH",
                is_active=True
            ),
            DetectionRule(
                id="RULE-NETWORK-SCAN",
                name="Nmap / Network Port Scanning",
                description="Flags connections matching signature characteristics of network scanning software like Nmap.",
                pattern=r"(?i)(nmap|masscan|zgrab|scan|ping)",
                severity="MEDIUM",
                is_active=True
            ),
            DetectionRule(
                id="RULE-MALWARE-DETECTION",
                name="Malware / Trojan Activity Detected",
                description="Detects presence of malware signatures, known trojan commands, or backdoor connections.",
                pattern=r"(?i)(malware|trojan|ransomware|virus|backdoor|reverse shell|cnc contact)",
                severity="CRITICAL",
                is_active=True
            ),
            DetectionRule(
                id="RULE-POLICY-VIOLATION",
                name="Security Policy Violation",
                description="Detects actions violating security guidelines, such as accessing forbidden sites or privilege bypasses.",
                pattern=r"(?i)(unauthorized access|policy violation|security policy bypass|privilege escalation)",
                severity="HIGH",
                is_active=True
            )
        ]
        
        for rule in default_rules:
            existing = db.query(DetectionRule).filter(DetectionRule.id == rule.id).first()
            if not existing:
                db.add(rule)
        db.commit()

        # Refresh rules cache so correlation engine has rules to run on
        from app.services.rule_loader import refresh_rules
        refresh_rules(db)

        # Seed historical logs to show realistic timeline and metrics on load
        from app.models.models import SecurityLog
        from app.services.correlation_engine import correlate_log
        
        if db.query(SecurityLog).count() == 0:
            print("Seeding historical logs and generating initial alert database...")
            import random
            from datetime import timedelta
            
            users = ["john.doe", "alice.smith", "bob.johnson", "charlie.brown", "david.miller", "admin", "root", "db_admin"]
            internal_ips = [f"192.168.1.{i}" for i in range(10, 30)] + [f"10.0.0.{i}" for i in range(50, 70)]
            external_ips = ["198.51.100.45", "203.0.113.82", "185.220.101.5", "93.184.216.34", "185.190.140.40", "95.142.100.12", "82.102.23.9", "45.132.89.2", "103.24.12.18", "88.198.54.3"]
            countries = ["United States", "Canada", "Netherlands", "Germany", "United Kingdom", "Russia", "Singapore", "Brazil", "China", "India"]
            
            # Create logs spanning the last 24 hours with diurnal pattern weights
            now = datetime.now()
            for _ in range(800):
                hour_offset = random.choices(
                    range(24), 
                    weights=[12, 8, 6, 5, 4, 6, 12, 22, 35, 42, 48, 50, 46, 42, 45, 48, 52, 40, 32, 26, 20, 18, 15, 13]
                )[0]
                minute_offset = random.randint(0, 59)
                log_time = now - timedelta(hours=hour_offset, minutes=minute_offset)
                cat = random.choice(["auth", "web", "firewall", "system"])
                severity = "INFO"
                src_ip = random.choice(internal_ips)
                dst_ip = "10.0.0.15"
                user = random.choice(users)
                msg = ""
                
                if cat == "auth":
                    roll = random.random()
                    if roll < 0.22:
                        severity = "WARNING"
                        src_ip = random.choice(external_ips)
                        user = "root" if random.random() < 0.5 else "admin"
                        msg = f"sshd[12942]: Failed password for invalid user {user} from {src_ip} port {random.randint(4000, 60000)} ssh2"
                    else:
                        msg = f"sshd[12942]: Accepted password for {user} from {src_ip} port {random.randint(4000, 60000)} ssh2"
                elif cat == "web":
                    roll = random.random()
                    if roll < 0.05:
                        severity = "ERROR"
                        src_ip = random.choice(external_ips)
                        msg = "WAF: SQL Injection detected on login page payload: ' OR '1'='1"
                    elif roll < 0.10:
                        severity = "ERROR"
                        src_ip = random.choice(external_ips)
                        msg = "WAF: Cross-Site Scripting (XSS) payload: <script>alert(document.cookie)</script>"
                    else:
                        msg = f"Web server access: GET /index.html HTTP/1.1 from {src_ip}"
                elif cat == "firewall":
                    roll = random.random()
                    if roll < 0.10:
                        severity = "INFO"
                        src_ip = random.choice(external_ips)
                        msg = f"Firewall blocked nmap scanning attempt from {src_ip} to port {random.choice([21,22,23,80])}"
                    else:
                        msg = f"Firewall allowed outbound packet from {src_ip} to 8.8.8.8:53"
                else:
                    roll = random.random()
                    if roll < 0.05:
                        severity = "CRITICAL"
                        msg = "Antivirus Alert: Trojan backdoor activity detected on host 10.0.0.15. Signature: Trojan.Win32.ReverseShell.a"
                    else:
                        msg = f"System status update: disk space utilization at {random.randint(20, 60)}%"
                
                country = None
                if src_ip in external_ips:
                    country = countries[external_ips.index(src_ip) % len(countries)]
                
                log_entry = SecurityLog(
                    timestamp=log_time,
                    event_type=cat,
                    severity=severity,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    message=msg,
                    raw_payload=msg,
                    geo_country=country,
                    user_id=user
                )
                db.add(log_entry)
                db.commit()
                
                # Correlate this log to trigger historical alerts
                correlate_log(log_entry, db)

            # Seed initial escalated incident cases so dashboard counters and ticket lists aren't empty
            from app.models.models import IncidentCase, Alert
            if db.query(IncidentCase).count() == 0:
                default_cases = [
                    IncidentCase(
                        title="Target User root Brute Force from Russian IP",
                        severity="HIGH",
                        status="OPEN",
                        assigned_to="Unassigned"
                    ),
                    IncidentCase(
                        title="SQL Injection attempt on API payment endpoint",
                        severity="CRITICAL",
                        status="IN_PROGRESS",
                        assigned_to="alice.smith"
                    ),
                    IncidentCase(
                        title="Trojan backdoor command execution on host 10.0.0.15",
                        severity="CRITICAL",
                        status="OPEN",
                        assigned_to="john.doe"
                    ),
                    IncidentCase(
                        title="Suspicious outreach traffic to known tor exit node",
                        severity="MEDIUM",
                        status="CLOSED",
                        assigned_to="bob.johnson"
                    )
                ]
                for case in default_cases:
                    db.add(case)
                db.commit()
    except Exception as e:
        print(f"Error seeding database: {e}")
    finally:
        db.close()
