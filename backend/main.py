import uvicorn
from fastapi import FastAPI
from core.config import settings
from auth.router import router as auth_router

app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG,
)

app.include_router(auth_router)


@app.get("/")
def read_root():
    return {"message": f"Welcome to {settings.APP_NAME}"}


def main():
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)


if __name__ == "__main__":
    main()
