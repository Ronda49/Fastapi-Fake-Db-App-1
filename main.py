"""
FastAPI Backend (single-file)

Requirements (put in requirements.txt):
fastapi==0.95.2
uvicorn[standard]==0.22.0
pydantic==1.10.9
python-multipart==0.0.6  # if you need file uploads
email-validator==1.3.1    # for pydantic EmailStr

Run:
1. python -m pip install -r requirements.txt
2. uvicorn fastapi_fake_db_app:app --reload --port 8000

This single-file app demonstrates:
- FastAPI application
- Pydantic models (+ validation)
- A fake in-memory DB (dict) with optional JSON persistence
- CRUD endpoints for Users and Items
- Pagination, filtering, and search
- Simple token-based auth (fake tokens)
- Middleware for logging + CORS setup
- Background task example
- OpenAPI/Swagger docs available at /docs and /redoc

"""
from fastapi import FastAPI, HTTPException, Path, Query, Body, Depends, status, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, List, Dict, Any
from uuid import uuid4, UUID
from datetime import datetime
import secrets
import json
import os
import logging

# ----- Configuration -----
PERSIST_DB_FILE = "fake_db.json"  # Optional persistence between runs (in same folder)
API_TITLE = "Example FastAPI with FakeDB"
API_VERSION = "0.1.0"

# ----- Logging -----
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ----- Fake DB Implementation -----
class FakeDB:
    """Simple thread-unsafe in-memory DB with optional JSON persistence."""
    def __init__(self):
        self.users: Dict[str, Dict[str, Any]] = {}
        self.items: Dict[str, Dict[str, Any]] = {}
        # try to load persisted data
        if os.path.exists(PERSIST_DB_FILE):
            try:
                with open(PERSIST_DB_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.users = {k: v for k, v in data.get("users", {}).items()}
                self.items = {k: v for k, v in data.get("items", {}).items()}
                logger.info("Loaded fake DB from %s", PERSIST_DB_FILE)
            except Exception as e:
                logger.warning("Could not load DB file: %s", e)

    def persist(self):
        try:
            with open(PERSIST_DB_FILE, "w", encoding="utf-8") as f:
                json.dump({"users": self.users, "items": self.items}, f, default=str, indent=2)
            logger.info("Persisted fake DB to %s", PERSIST_DB_FILE)
        except Exception as e:
            logger.error("Failed to persist DB: %s", e)

# single instance
db = FakeDB()

# ----- Pydantic Models -----
class UserCreate(BaseModel):
    email: EmailStr
    full_name: Optional[str] = Field(None, max_length=100)
    password: str = Field(..., min_length=6)

    @validator("password")
    def password_strength(cls, v):
        if len(v) < 6:
            raise ValueError("Password too short")
        return v

class User(BaseModel):
    id: UUID
    email: EmailStr
    full_name: Optional[str]
    created_at: datetime

class UserInDB(User):
    hashed_password: str

class ItemCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    price: float = Field(..., ge=0)

class Item(ItemCreate):
    id: UUID
    owner_id: UUID
    created_at: datetime

# ----- Auth (fake) -----
bearer_scheme = HTTPBearer(auto_error=False)

# For demonstration only: insecure simple "auth"
API_TOKENS = {}  # token -> user_id

def fake_hash_password(password: str) -> str:
    # DO NOT USE in prod. Use bcrypt/argon2
    return "fakehashed:" + secrets.token_hex(8)


async def get_current_user(token: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> User:
    if token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing auth token")
    token_value = token.credentials
    user_id = API_TOKENS.get(token_value)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid auth token")
    user_data = db.users.get(str(user_id))
    if not user_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return User(**user_data)

# ----- Application Setup -----
app = FastAPI(title=API_TITLE, version=API_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Example middleware for request logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"{request.method} {request.url}")
    start = datetime.utcnow()
    response = await call_next(request)
    duration = (datetime.utcnow() - start).total_seconds()
    logger.info(f"Completed in {duration:.3f}s - status {response.status_code}")
    return response

# ----- Utility functions -----
def make_user_response(user_record: Dict[str, Any]) -> Dict[str, Any]:
    # convert stored record (which contains hashed_password) into exposed user
    return {
        "id": user_record["id"],
        "email": user_record["email"],
        "full_name": user_record.get("full_name"),
        "created_at": user_record["created_at"],
    }

# Background task example
def background_persist_db():
    db.persist()

# ----- Routes: Health -----
@app.get("/health", tags=["health"])
async def health_check():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}

# ----- Routes: Auth / Users -----
@app.post("/signup", response_model=User, status_code=status.HTTP_201_CREATED, tags=["auth"])
async def signup(user: UserCreate, background_tasks: BackgroundTasks):
    # ensure unique email
    for u in db.users.values():
        if u["email"].lower() == user.email.lower():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    user_id = uuid4()
    now = datetime.utcnow().isoformat()
    hashed = fake_hash_password(user.password)
    record = {
        "id": str(user_id),
        "email": user.email,
        "full_name": user.full_name,
        "created_at": now,
        "hashed_password": hashed,
    }
    db.users[str(user_id)] = record
    # persist async
    background_tasks.add_task(background_persist_db)
    logger.info("Created user %s", user.email)
    return User(**make_user_response(record))

@app.post("/login", tags=["auth"])
async def login(credentials: UserCreate = Body(...)):
    # insecure: we use email/password in body (not recommended)
    found = None
    for u in db.users.values():
        if u["email"].lower() == credentials.email.lower():
            found = u
            break
    if not found:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    # we skip real password check; produce token
    token = secrets.token_urlsafe(24)
    API_TOKENS[token] = found["id"]
    return {"access_token": token, "token_type": "bearer"}

@app.get("/users/me", response_model=User, tags=["users"])
async def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/users/{user_id}", response_model=User, tags=["users"])
async def read_user(user_id: UUID = Path(...)):
    rec = db.users.get(str(user_id))
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return User(**make_user_response(rec))

# ----- Routes: Items -----
@app.post("/items", response_model=Item, status_code=status.HTTP_201_CREATED, tags=["items"])
async def create_item(item: ItemCreate, current_user: User = Depends(get_current_user), background_tasks: BackgroundTasks = None):
    item_id = uuid4()
    now = datetime.utcnow().isoformat()
    record = {
        "id": str(item_id),
        "title": item.title,
        "description": item.description,
        "price": item.price,
        "owner_id": str(current_user.id),
        "created_at": now,
    }
    db.items[str(item_id)] = record
    if background_tasks:
        background_tasks.add_task(background_persist_db)
    return Item(**record)

@app.get("/items/{item_id}", response_model=Item, tags=["items"])
async def get_item(item_id: UUID = Path(...)):
    rec = db.items.get(str(item_id))
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    return Item(**rec)

@app.get("/items", response_model=List[Item], tags=["items"])
async def list_items(q: Optional[str] = Query(None, min_length=1), skip: int = 0, limit: int = 10):
    # naive filtering
    results = list(db.items.values())
    if q:
        lowerq = q.lower()
        results = [r for r in results if lowerq in r.get("title", "").lower() or (r.get("description") or "").lower().find(lowerq) >= 0]
    # simple pagination
    return [Item(**r) for r in results[skip: skip + limit]]

@app.put("/items/{item_id}", response_model=Item, tags=["items"])
async def update_item(item_id: UUID, item: ItemCreate, current_user: User = Depends(get_current_user), background_tasks: BackgroundTasks = None):
    rec = db.items.get(str(item_id))
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    if rec["owner_id"] != str(current_user.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not owner")
    rec.update({"title": item.title, "description": item.description, "price": item.price})
    if background_tasks:
        background_tasks.add_task(background_persist_db)
    return Item(**rec)

@app.delete("/items/{item_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["items"])
async def delete_item(item_id: UUID, current_user: User = Depends(get_current_user), background_tasks: BackgroundTasks = None):
    rec = db.items.get(str(item_id))
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    if rec["owner_id"] != str(current_user.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not owner")
    del db.items[str(item_id)]
    if background_tasks:
        background_tasks.add_task(background_persist_db)
    return None

# ----- Admin / Debug endpoints (example) -----
@app.get("/debug/db", tags=["debug"])
async def debug_db_dump(api_key: Optional[str] = Query(None)):
    # small safety gate
    if api_key != "letmein-debug":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid debug key")
    return {"users": db.users, "items": db.items}

# ----- Startup / Shutdown Events -----
@app.on_event("shutdown")
async def on_shutdown():
    logger.info("Shutting down app - persisting DB")
    db.persist()

@app.on_event("startup")
async def on_startup():
    logger.info("Starting app %s v%s", API_TITLE, API_VERSION)

# ----- Example data seeding (optional) -----
def seed_example_data():
    if db.users or db.items:
        return
    # create a demo user
    demo_id = uuid4()
    demo_user = {
        "id": str(demo_id),
        "email": "demo@example.com",
        "full_name": "Demo User",
        "created_at": datetime.utcnow().isoformat(),
        "hashed_password": fake_hash_password("password123"),
    }
    db.users[str(demo_id)] = demo_user
    # create a token for demo
    demo_token = "demo-token-123"
    API_TOKENS[demo_token] = str(demo_id)
    # create a sample item
    item_id = uuid4()
    db.items[str(item_id)] = {
        "id": str(item_id),
        "title": "Demo Item",
        "description": "A sample item from the demo user",
        "price": 9.99,
        "owner_id": str(demo_id),
        "created_at": datetime.utcnow().isoformat(),
    }
    logger.info("Seeded example data. Demo token: %s", demo_token)

seed_example_data()

# End of file
