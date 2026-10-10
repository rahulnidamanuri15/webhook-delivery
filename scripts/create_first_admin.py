import asyncio
from app.db.session import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash

async def main():
    db = SessionLocal()
    try:
        admin = User(
            email="adminyournr@gmail.com",
            hashed_password=get_password_hash("1w3r5y7i9p"),
            is_active=True,
            is_superuser=True
        )
        db.add(admin)
        db.commit()
        print(" First admin created successfully.")
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(main())