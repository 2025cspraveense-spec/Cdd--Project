"""
MongoDB Database Interface and Data Access Layer
Supports direct MongoDB cluster connection with transparent in-memory fallback
for standalone/offline environments.
"""

from datetime import datetime, timezone
import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from scanner.config import ScannerConfig

logger = logging.getLogger("scanner.db")


class InMemoryCollection:
    """Thread-safe in-memory replica of a PyMongo Collection for offline fallback."""

    def __init__(self, name: str):
        self.name = name
        self._docs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def create_index(self, keys, **kwargs):
        pass

    def insert_one(self, doc: Dict[str, Any]):
        with self._lock:
            d = dict(doc)
            _id = str(d.get("_id") or d.get("scan_id") or d.get("finding_id") or d.get("username") or len(self._docs) + 1)
            d["_id"] = _id
            self._docs[_id] = d
            return type("InsertResult", (), {"inserted_id": _id})()

    def insert_many(self, docs: List[Dict[str, Any]]):
        ids = []
        with self._lock:
            for doc in docs:
                res = self.insert_one(doc)
                ids.append(res.inserted_id)
            return type("InsertManyResult", (), {"inserted_ids": ids})()

    def find_one(self, filter_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            for doc in self._docs.values():
                if self._matches(doc, filter_dict):
                    return dict(doc)
            return None

    def find(self, filter_dict: Optional[Dict[str, Any]] = None):
        filter_dict = filter_dict or {}
        with self._lock:
            matched = [dict(d) for d in self._docs.values() if self._matches(d, filter_dict)]
            return InMemoryCursor(matched)

    def update_one(self, filter_dict: Dict[str, Any], update_dict: Dict[str, Any], upsert: bool = False):
        with self._lock:
            for key, doc in self._docs.items():
                if self._matches(doc, filter_dict):
                    if "$set" in update_dict:
                        doc.update(update_dict["$set"])
                    else:
                        doc.update(update_dict)
                    return type("UpdateResult", (), {"matched_count": 1, "modified_count": 1})()
            if upsert:
                new_doc = dict(filter_dict)
                if "$set" in update_dict:
                    new_doc.update(update_dict["$set"])
                else:
                    new_doc.update(update_dict)
                self.insert_one(new_doc)
                return type("UpdateResult", (), {"matched_count": 0, "modified_count": 1, "upserted_id": new_doc.get("_id")})()
            return type("UpdateResult", (), {"matched_count": 0, "modified_count": 0})()

    def count_documents(self, filter_dict: Optional[Dict[str, Any]] = None) -> int:
        filter_dict = filter_dict or {}
        with self._lock:
            return sum(1 for d in self._docs.values() if self._matches(d, filter_dict))

    def delete_many(self, filter_dict: Dict[str, Any]):
        with self._lock:
            to_del = [k for k, d in self._docs.items() if self._matches(d, filter_dict)]
            for k in to_del:
                del self._docs[k]
            return type("DeleteResult", (), {"deleted_count": len(to_del)})()

    def distinct(self, key: str, filter_dict: Optional[Dict[str, Any]] = None) -> List[Any]:
        filter_dict = filter_dict or {}
        with self._lock:
            vals = set()
            for doc in self._docs.values():
                if self._matches(doc, filter_dict) and key in doc:
                    vals.add(doc[key])
            return list(vals)

    @staticmethod
    def _matches(doc: Dict[str, Any], filter_dict: Dict[str, Any]) -> bool:
        for k, v in filter_dict.items():
            if isinstance(v, dict):
                # Simple handling for $in operator
                if "$in" in v:
                    if doc.get(k) not in v["$in"]:
                        return False
                elif "$regex" in v:
                    pattern = v["$regex"]
                    if pattern.lower() not in str(doc.get(k, "")).lower():
                        return False
            elif doc.get(k) != v:
                return False
        return True


class InMemoryCursor:
    """Cursor simulation for in-memory collections."""

    def __init__(self, docs: List[Dict[str, Any]]):
        self._docs = docs

    def sort(self, key_or_list, direction=1):
        key = key_or_list if isinstance(key_or_list, str) else key_or_list[0][0]
        reverse = (direction == -1) if isinstance(key_or_list, str) else (key_or_list[0][1] == -1)
        self._docs.sort(key=lambda d: d.get(key) or "", reverse=reverse)
        return self

    def skip(self, n: int):
        self._docs = self._docs[n:]
        return self

    def limit(self, n: int):
        self._docs = self._docs[:n]
        return self

    def __iter__(self):
        return iter(self._docs)

    def __list__(self):
        return self._docs


class DatabaseManager:
    """
    Unified MongoDB Database Manager.
    Tries connecting to the configured MongoDB URI. If offline, initializes an
    in-memory database instance to keep scans uninterrupted.
    """

    def __init__(self, uri: str = ScannerConfig.MONGO_URI, db_name: str = ScannerConfig.MONGO_DB_NAME):
        self.uri = uri
        self.db_name = db_name
        self.client: Optional[MongoClient] = None
        self.db = None
        self.is_connected = False
        self._in_memory_collections: Dict[str, InMemoryCollection] = {}
        self._init_connection()

    def _init_connection(self):
        try:
            logger.info("Connecting to MongoDB at %s ...", self.uri)
            self.client = MongoClient(
                self.uri,
                serverSelectionTimeoutMS=ScannerConfig.MONGO_TIMEOUT_MS,
                connectTimeoutMS=ScannerConfig.MONGO_TIMEOUT_MS,
            )
            # Ping database to confirm live connection
            self.client.admin.command("ping")
            self.db = self.client[self.db_name]
            self.is_connected = True
            logger.info("Successfully connected to live MongoDB database: '%s'", self.db_name)
            self._ensure_indexes()
        except (ConnectionFailure, ServerSelectionTimeoutError, Exception) as exc:
            logger.warning("MongoDB not reachable (%s). Falling back to resilient in-memory storage.", exc)
            self.is_connected = False
            self.client = None
            self.db = None

    def _get_collection(self, name: str):
        if self.is_connected and self.db is not None:
            return self.db[name]
        if name not in self._in_memory_collections:
            self._in_memory_collections[name] = InMemoryCollection(name)
        return self._in_memory_collections[name]

    def _ensure_indexes(self):
        if not self.is_connected or self.db is None:
            return
        try:
            self.db.scans.create_index([("scan_id", ASCENDING)], unique=True)
            self.db.scans.create_index([("project_name", ASCENDING)])
            self.db.scans.create_index([("created_at", DESCENDING)])
            self.db.findings.create_index([("finding_id", ASCENDING)], unique=True)
            self.db.findings.create_index([("scan_id", ASCENDING)])
            self.db.findings.create_index([("severity", ASCENDING)])
            self.db.projects.create_index([("project_name", ASCENDING)], unique=True)
            self.db.users.create_index([("username", ASCENDING)], unique=True)
        except Exception as e:
            logger.warning("Error creating MongoDB indexes: %s", e)

    # -------------------------------------------------------------
    # Scan Records
    # -------------------------------------------------------------
    def save_scan(self, scan_data: Dict[str, Any]) -> str:
        scans_col = self._get_collection("scans")
        d = dict(scan_data)
        d["_id"] = d.get("scan_id")
        scans_col.update_one({"scan_id": d["scan_id"]}, {"$set": d}, upsert=True)
        # Also update projects collection
        self.upsert_project_from_scan(d)
        return d["scan_id"]

    def update_scan(self, scan_id: str, updates: Dict[str, Any]) -> bool:
        scans_col = self._get_collection("scans")
        res = scans_col.update_one({"scan_id": scan_id}, {"$set": updates})
        return (res.modified_count > 0 or getattr(res, "matched_count", 0) > 0)

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        scans_col = self._get_collection("scans")
        doc = scans_col.find_one({"scan_id": scan_id})
        if doc and "_id" in doc and not isinstance(doc["_id"], str):
            doc["_id"] = str(doc["_id"])
        return doc

    def list_scans(self, limit: int = 50, skip: int = 0) -> List[Dict[str, Any]]:
        scans_col = self._get_collection("scans")
        cursor = scans_col.find({}).sort("created_at", DESCENDING).skip(skip).limit(limit)
        results = []
        for doc in cursor:
            if "_id" in doc and not isinstance(doc["_id"], str):
                doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results

    def delete_scan(self, scan_id: str) -> bool:
        scans_col = self._get_collection("scans")
        findings_col = self._get_collection("findings")
        scans_col.delete_many({"scan_id": scan_id})
        findings_col.delete_many({"scan_id": scan_id})
        return True

    # -------------------------------------------------------------
    # Findings Records
    # -------------------------------------------------------------
    def save_findings(self, findings: List[Dict[str, Any]]) -> int:
        if not findings:
            return 0
        findings_col = self._get_collection("findings")
        prepared = []
        for f in findings:
            d = dict(f)
            d["_id"] = d.get("finding_id")
            prepared.append(d)
        findings_col.insert_many(prepared)
        return len(prepared)

    def get_findings(
        self,
        scan_id: str,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        engine: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        skip: int = 0,
    ) -> List[Dict[str, Any]]:
        findings_col = self._get_collection("findings")
        query: Dict[str, Any] = {"scan_id": scan_id}
        if severity:
            query["severity"] = severity
        if category:
            query["category"] = category
        if engine:
            query["engine"] = engine
        if search:
            query["title"] = {"$regex": search}

        cursor = findings_col.find(query).skip(skip).limit(limit)
        results = []
        for doc in cursor:
            if "_id" in doc and not isinstance(doc["_id"], str):
                doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results

    def count_findings(self, scan_id: str, severity: Optional[str] = None) -> int:
        findings_col = self._get_collection("findings")
        query: Dict[str, Any] = {"scan_id": scan_id}
        if severity:
            query["severity"] = severity
        return findings_col.count_documents(query)

    # -------------------------------------------------------------
    # Projects & Analytics
    # -------------------------------------------------------------
    def upsert_project_from_scan(self, scan_data: Dict[str, Any]):
        projects_col = self._get_collection("projects")
        proj_name = scan_data.get("project_name", "Untrusted-Project")
        now = datetime.now(timezone.utc).isoformat()

        existing = projects_col.find_one({"project_name": proj_name})
        scan_count = (existing.get("total_scans", 0) + 1) if existing else 1

        update = {
            "project_name": proj_name,
            "last_scan_id": scan_data.get("scan_id"),
            "last_scan_date": scan_data.get("completed_at") or now,
            "latest_risk_score": scan_data.get("risk_score", 0.0),
            "latest_security_grade": scan_data.get("security_grade", "A"),
            "total_scans": scan_count,
            "latest_critical_count": scan_data.get("summary", {}).get("critical", 0),
            "latest_high_count": scan_data.get("summary", {}).get("high", 0),
        }
        projects_col.update_one({"project_name": proj_name}, {"$set": update}, upsert=True)

    def list_projects(self) -> List[Dict[str, Any]]:
        projects_col = self._get_collection("projects")
        cursor = projects_col.find({}).sort("last_scan_date", DESCENDING)
        results = []
        for doc in cursor:
            if "_id" in doc and not isinstance(doc["_id"], str):
                doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        scans_col = self._get_collection("scans")
        findings_col = self._get_collection("findings")
        projects_col = self._get_collection("projects")

        total_scans = scans_col.count_documents({})
        total_projects = projects_col.count_documents({})
        total_findings = findings_col.count_documents({})

        critical = findings_col.count_documents({"severity": "CRITICAL"})
        high = findings_col.count_documents({"severity": "HIGH"})
        medium = findings_col.count_documents({"severity": "MEDIUM"})
        low = findings_col.count_documents({"severity": "LOW"})

        secrets_count = findings_col.count_documents({"category": "SECRET_LEAK"})
        dep_count = findings_col.count_documents({"category": "DEPENDENCY"})
        sast_count = findings_col.count_documents({"category": "SAST_VULNERABILITY"})
        docker_count = findings_col.count_documents({"category": "DOCKER_SECURITY"})

        recent_scans = self.list_scans(limit=10)

        # Average security score across completed scans
        all_completed = list(scans_col.find({"status": "COMPLETED"}))
        avg_score = (
            round(sum(s.get("risk_score", 0) for s in all_completed) / len(all_completed), 1)
            if all_completed
            else 0.0
        )

        return {
            "total_scans": total_scans,
            "total_projects": total_projects,
            "total_findings": total_findings,
            "severity_distribution": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
            "category_distribution": {
                "secrets": secrets_count,
                "sast": sast_count,
                "dependencies": dep_count,
                "docker": docker_count,
            },
            "average_risk_score": avg_score,
            "recent_scans": recent_scans,
            "db_mode": "MongoDB (Connected)" if self.is_connected else "MongoDB (In-Memory Fallback)",
        }


# Singleton Global Database Instance
db = DatabaseManager()
